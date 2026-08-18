//! Shadowsocks AEAD protocol layer.
//!
//! This module implements the stream and packet wire formats used by the
//! current yuhaiin Go client.  It intentionally only owns protocol state:
//! connecting to the configured parent proxy remains the responsibility of
//! [`ShadowsocksProxy`]'s `AsyncProxy` parent.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::yuubinsya::{decode_endpoint, encode_endpoint};
use aes_gcm::{
    Aes128Gcm, Aes256Gcm,
    aead::{Aead, KeyInit},
};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};

pub const MAX_PAYLOAD_SIZE: usize = 0x3fff;
pub const AEAD_TAG_SIZE: usize = 16;
const HKDF_INFO: &[u8] = b"ss-subkey";

/// Cipher names accepted by yuhaiin's Go implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Dummy,
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl Method {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "DUMMY" => Ok(Self::Dummy),
            "AES-128-GCM" | "AEAD_AES_128_GCM" => Ok(Self::Aes128Gcm),
            "AES-256-GCM" | "AEAD_AES_256_GCM" => Ok(Self::Aes256Gcm),
            "CHACHA20-IETF-POLY1305" | "AEAD_CHACHA20_POLY1305" => Ok(Self::Chacha20Poly1305),
            _ => Err(Error::new(
                ErrorKind::Unsupported,
                format!("unsupported Shadowsocks method {value:?}"),
            )),
        }
    }

    pub const fn key_size(self) -> usize {
        match self {
            Self::Dummy => 0,
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::Chacha20Poly1305 => 32,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Dummy => "DUMMY",
            Self::Aes128Gcm => "AEAD_AES_128_GCM",
            Self::Aes256Gcm => "AEAD_AES_256_GCM",
            Self::Chacha20Poly1305 => "AEAD_CHACHA20_POLY1305",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShadowsocksConfig {
    method: Method,
    key: Vec<u8>,
}

impl ShadowsocksConfig {
    pub fn from_password(method: Method, password: &str) -> Result<Self> {
        let key = md5_password_kdf(password.as_bytes(), method.key_size());
        Self::from_key(method, key)
    }

    fn from_key(method: Method, key: Vec<u8>) -> Result<Self> {
        if key.len() != method.key_size() {
            return Err(Error::invalid(format!(
                "Shadowsocks {} key must contain {} bytes",
                method.name(),
                method.key_size()
            )));
        }
        Ok(Self { method, key })
    }

    fn salt_size(&self) -> usize {
        self.method.key_size()
    }

    fn state_for_salt(&self, salt: &[u8]) -> io::Result<CipherState> {
        if self.method == Method::Dummy {
            return Ok(CipherState {
                cipher: self.clone(),
                nonce: 0,
            });
        }
        if salt.len() != self.salt_size() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Shadowsocks salt length",
            ));
        }
        let mut subkey = vec![0u8; self.method.key_size()];
        Hkdf::<Sha1>::new(Some(salt), &self.key)
            .expand(HKDF_INFO, &mut subkey)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Shadowsocks HKDF failed"))?;
        Ok(CipherState {
            cipher: Self {
                method: self.method,
                key: subkey,
            },
            nonce: 0,
        })
    }
}

#[derive(Debug, Clone)]
struct CipherState {
    cipher: ShadowsocksConfig,
    nonce: u64,
}

impl CipherState {
    fn nonce_bytes(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.nonce.to_le_bytes());
        nonce
    }

    fn seal(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let result = match self.cipher.method {
            Method::Dummy => plaintext.to_vec(),
            Method::Aes128Gcm => Aes128Gcm::new_from_slice(&self.cipher.key)
                .map_err(|_| invalid_cipher())?
                .encrypt(aes_gcm::Nonce::from_slice(&self.nonce_bytes()), plaintext)
                .map_err(|_| invalid_cipher())?,
            Method::Aes256Gcm => Aes256Gcm::new_from_slice(&self.cipher.key)
                .map_err(|_| invalid_cipher())?
                .encrypt(aes_gcm::Nonce::from_slice(&self.nonce_bytes()), plaintext)
                .map_err(|_| invalid_cipher())?,
            Method::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&self.cipher.key)
                .map_err(|_| invalid_cipher())?
                .encrypt(
                    chacha20poly1305::Nonce::from_slice(&self.nonce_bytes()),
                    plaintext,
                )
                .map_err(|_| invalid_cipher())?,
        };
        self.nonce = self.nonce.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Shadowsocks nonce overflow")
        })?;
        Ok(result)
    }

    fn open(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let result = match self.cipher.method {
            Method::Dummy => ciphertext.to_vec(),
            Method::Aes128Gcm => Aes128Gcm::new_from_slice(&self.cipher.key)
                .map_err(|_| invalid_cipher())?
                .decrypt(aes_gcm::Nonce::from_slice(&self.nonce_bytes()), ciphertext)
                .map_err(|_| invalid_cipher())?,
            Method::Aes256Gcm => Aes256Gcm::new_from_slice(&self.cipher.key)
                .map_err(|_| invalid_cipher())?
                .decrypt(aes_gcm::Nonce::from_slice(&self.nonce_bytes()), ciphertext)
                .map_err(|_| invalid_cipher())?,
            Method::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&self.cipher.key)
                .map_err(|_| invalid_cipher())?
                .decrypt(
                    chacha20poly1305::Nonce::from_slice(&self.nonce_bytes()),
                    ciphertext,
                )
                .map_err(|_| invalid_cipher())?,
        };
        self.nonce = self.nonce.checked_add(1).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "Shadowsocks nonce overflow")
        })?;
        Ok(result)
    }
}

fn invalid_cipher() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Shadowsocks AEAD operation failed",
    )
}

/// Go-compatible EVP_BytesToKey-style MD5 password derivation.
pub fn md5_password_kdf(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while result.len() < key_len {
        let mut digest = Md5::new();
        digest.update(&previous);
        digest.update(password);
        previous = digest.finalize().to_vec();
        result.extend_from_slice(&previous);
    }
    result.truncate(key_len);
    result
}

/// Encrypt a Shadowsocks UDP packet: salt followed by one AEAD message.
pub fn encrypt_udp_packet(
    config: &ShadowsocksConfig,
    destination: &Endpoint,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if config.method == Method::Dummy {
        let mut packet = Vec::new();
        encode_endpoint(destination, &mut packet)?;
        packet.extend_from_slice(payload);
        return Ok(packet);
    }
    let mut salt = vec![0u8; config.salt_size()];
    rand::RngExt::fill(&mut rand::rng(), &mut salt);
    let mut state = config.state_for_salt(&salt).map_err(io_to_error)?;
    let mut plaintext = Vec::with_capacity(260 + payload.len());
    encode_endpoint(destination, &mut plaintext)?;
    plaintext.extend_from_slice(payload);
    let encrypted = state.seal(&plaintext).map_err(io_to_error)?;
    salt.extend_from_slice(&encrypted);
    Ok(salt)
}

/// Decrypt a Shadowsocks UDP packet and return `(payload length, destination)`.
pub fn decrypt_udp_packet(
    config: &ShadowsocksConfig,
    packet: &[u8],
    payload: &mut [u8],
) -> Result<(usize, Endpoint)> {
    if config.method == Method::Dummy {
        let mut cursor = 0;
        let destination = decode_endpoint(packet, &mut cursor, Network::Udp)?;
        let bytes = packet.get(cursor..).ok_or_else(|| {
            Error::new(ErrorKind::Protocol, "Shadowsocks UDP packet is truncated")
        })?;
        let copied = bytes.len().min(payload.len());
        payload[..copied].copy_from_slice(&bytes[..copied]);
        return Ok((copied, destination));
    }
    let salt_len = config.salt_size();
    if packet.len() < salt_len + AEAD_TAG_SIZE {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Shadowsocks UDP packet is truncated",
        ));
    }
    let mut state = config
        .state_for_salt(&packet[..salt_len])
        .map_err(io_to_error)?;
    let plaintext = state.open(&packet[salt_len..]).map_err(io_to_error)?;
    let mut cursor = 0;
    let destination = decode_endpoint(&plaintext, &mut cursor, Network::Udp)?;
    let bytes = plaintext
        .get(cursor..)
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "Shadowsocks UDP target is truncated"))?;
    let copied = bytes.len().min(payload.len());
    payload[..copied].copy_from_slice(&bytes[..copied]);
    Ok((copied, destination))
}

/// Shadowsocks protocol layer around an already configured parent proxy.
pub struct ShadowsocksProxy {
    upstream: Arc<dyn AsyncProxy>,
    config: ShadowsocksConfig,
}

impl ShadowsocksProxy {
    pub fn new(upstream: Arc<dyn AsyncProxy>, method: &str, password: &str) -> Result<Self> {
        let method = Method::parse(method)?;
        Ok(Self {
            upstream,
            config: ShadowsocksConfig::from_password(method, password)?,
        })
    }

    pub fn method(&self) -> Method {
        self.config.method
    }
}

impl AsyncProxy for ShadowsocksProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let stream = self.upstream.connect(context).await?;
            if self.config.method == Method::Dummy {
                let mut stream = stream;
                let mut endpoint = Vec::new();
                encode_endpoint(&context.effective_destination(), &mut endpoint)?;
                stream.write_all(&endpoint).await.map_err(io_to_error)?;
                return Ok(stream);
            }
            Ok(Box::new(
                ShadowsocksStream::connect(
                    stream,
                    self.config.clone(),
                    &context.effective_destination(),
                )
                .await
                .map_err(io_to_error)?,
            ) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            let upstream = self.upstream.open_datagram(context).await?;
            Ok(Box::new(ShadowsocksDatagram {
                upstream,
                config: self.config.clone(),
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

struct ShadowsocksDatagram {
    upstream: Box<dyn AsyncDatagram>,
    config: ShadowsocksConfig,
}

impl AsyncDatagram for ShadowsocksDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let packet = encrypt_udp_packet(&self.config, &target, payload)?;
            self.upstream.send_to(&packet, target).await?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let mut packet =
                vec![0u8; self.config.salt_size() + MAX_PAYLOAD_SIZE + 260 + AEAD_TAG_SIZE];
            let (length, _) = self.upstream.recv_from(&mut packet).await?;
            let (copied, destination) =
                decrypt_udp_packet(&self.config, &packet[..length], buffer)?;
            Ok((copied, destination))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.upstream.local_addr()
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

struct PendingWrite {
    encrypted: Vec<u8>,
    offset: usize,
    accepted: usize,
}

struct ShadowsocksStream {
    inner: BoxAsyncStream,
    write_state: CipherState,
    pending_write: Option<PendingWrite>,
    read_salt: Vec<u8>,
    read_salt_filled: usize,
    read_config: ShadowsocksConfig,
    read_state: Option<CipherState>,
    read_length: Vec<u8>,
    read_length_filled: usize,
    read_payload: Vec<u8>,
    read_payload_filled: usize,
    plaintext: Vec<u8>,
    plaintext_offset: usize,
}

impl ShadowsocksStream {
    async fn connect(
        mut inner: BoxAsyncStream,
        config: ShadowsocksConfig,
        destination: &Endpoint,
    ) -> io::Result<Self> {
        let mut salt = vec![0u8; config.salt_size()];
        rand::RngExt::fill(&mut rand::rng(), &mut salt);
        let mut write_state = config.state_for_salt(&salt)?;
        inner.write_all(&salt).await?;
        let mut endpoint = Vec::new();
        encode_endpoint(destination, &mut endpoint).map_err(core_to_io)?;
        write_record(&mut inner, &mut write_state, &endpoint).await?;
        Ok(Self {
            inner,
            write_state,
            pending_write: None,
            read_salt: vec![0u8; config.salt_size()],
            read_salt_filled: 0,
            read_config: config,
            read_state: None,
            read_length: Vec::new(),
            read_length_filled: 0,
            read_payload: Vec::new(),
            read_payload_filled: 0,
            plaintext: Vec::new(),
            plaintext_offset: 0,
        })
    }

    fn encrypt_records(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        for chunk in plaintext.chunks(MAX_PAYLOAD_SIZE) {
            let length = u16::try_from(chunk.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Shadowsocks payload is too large",
                )
            })?;
            let encrypted_length = self.write_state.seal(&length.to_be_bytes())?;
            let encrypted_payload = self.write_state.seal(chunk)?;
            output.extend_from_slice(&encrypted_length);
            output.extend_from_slice(&encrypted_payload);
        }
        Ok(output)
    }

    fn poll_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let Some(pending) = self.pending_write.as_mut() else {
            return Poll::Ready(Ok(0));
        };
        while pending.offset < pending.encrypted.len() {
            let count = match Pin::new(&mut *self.inner)
                .poll_write(cx, &pending.encrypted[pending.offset..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Shadowsocks parent wrote zero bytes",
                    )));
                }
                Poll::Ready(Ok(count)) => count,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            };
            pending.offset += count;
        }
        let accepted = pending.accepted;
        self.pending_write = None;
        Poll::Ready(Ok(accepted))
    }

    fn poll_fill(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
        filled: &mut usize,
        allow_clean_eof: bool,
    ) -> Poll<io::Result<bool>> {
        while *filled < buffer.len() {
            let mut read_buf = ReadBuf::new(&mut buffer[*filled..]);
            let before = read_buf.filled().len();
            match Pin::new(&mut *self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let count = read_buf.filled().len() - before;
                    if count == 0 {
                        if allow_clean_eof && *filled == 0 {
                            return Poll::Ready(Ok(false));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated Shadowsocks frame",
                        )));
                    }
                    *filled += count;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(true))
    }
}

impl AsyncRead for ShadowsocksStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.plaintext_offset < self.plaintext.len() {
                let available = &self.plaintext[self.plaintext_offset..];
                let copied = available.len().min(output.remaining());
                output.put_slice(&available[..copied]);
                self.plaintext_offset += copied;
                if self.plaintext_offset == self.plaintext.len() {
                    self.plaintext.clear();
                    self.plaintext_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            if self.read_state.is_none() {
                let mut salt = std::mem::take(&mut self.read_salt);
                let mut filled = self.read_salt_filled;
                let result = self.poll_fill(cx, &mut salt, &mut filled, false);
                self.read_salt = salt;
                self.read_salt_filled = filled;
                match result {
                    Poll::Ready(Ok(_)) => {
                        let state = match self.read_state_for_salt() {
                            Ok(state) => state,
                            Err(error) => return Poll::Ready(Err(error)),
                        };
                        self.read_state = Some(state);
                        self.read_length = vec![0u8; 2 + AEAD_TAG_SIZE];
                        self.read_length_filled = 0;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if self.read_length_filled < self.read_length.len() {
                let mut buffer = std::mem::take(&mut self.read_length);
                let mut filled = self.read_length_filled;
                let result = self.poll_fill(cx, &mut buffer, &mut filled, true);
                self.read_length = buffer;
                self.read_length_filled = filled;
                match result {
                    Poll::Ready(Ok(true)) => {
                        let encrypted_length = self.read_length.clone();
                        let state = self.read_state.as_mut().expect("read state initialized");
                        let decrypted = match state.open(&encrypted_length) {
                            Ok(value) if value.len() == 2 => value,
                            Ok(_) => {
                                return Poll::Ready(Err(invalid_frame(
                                    "invalid Shadowsocks length frame",
                                )));
                            }
                            Err(error) => return Poll::Ready(Err(error)),
                        };
                        let length = usize::from(u16::from_be_bytes([decrypted[0], decrypted[1]]));
                        self.read_payload = vec![0u8; length + AEAD_TAG_SIZE];
                        self.read_payload_filled = 0;
                        self.read_length_filled = 0;
                    }
                    Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            let mut buffer = std::mem::take(&mut self.read_payload);
            let mut filled = self.read_payload_filled;
            let result = self.poll_fill(cx, &mut buffer, &mut filled, false);
            self.read_payload = buffer;
            self.read_payload_filled = filled;
            match result {
                Poll::Ready(Ok(_)) => {
                    let encrypted_payload = self.read_payload.clone();
                    let state = self.read_state.as_mut().expect("read state initialized");
                    self.plaintext = match state.open(&encrypted_payload) {
                        Ok(value) => value,
                        Err(error) => return Poll::Ready(Err(error)),
                    };
                    self.read_payload.clear();
                    self.read_payload_filled = 0;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl ShadowsocksStream {
    fn read_state_for_salt(&self) -> io::Result<CipherState> {
        self.read_config.state_for_salt(&self.read_salt)
    }
}

impl AsyncWrite for ShadowsocksStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending_write.is_none() {
            if buffer.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let accepted = buffer.len().min(MAX_PAYLOAD_SIZE);
            let encrypted = match self.encrypt_records(&buffer[..accepted]) {
                Ok(encrypted) => encrypted,
                Err(error) => return Poll::Ready(Err(error)),
            };
            self.pending_write = Some(PendingWrite {
                encrypted,
                offset: 0,
                accepted,
            });
        }
        self.poll_pending_write(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_write.is_some() {
            match self.poll_pending_write(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut *self.inner).poll_shutdown(cx),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn write_record<W: AsyncWrite + Unpin>(
    writer: &mut W,
    state: &mut CipherState,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Shadowsocks record is too large",
        ));
    }
    let length = u16::try_from(payload.len()).unwrap().to_be_bytes();
    writer.write_all(&state.seal(&length)?).await?;
    writer.write_all(&state.seal(payload)?).await
}

fn invalid_frame(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn io_to_error(error: io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

fn core_to_io(error: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use yuhaiin_core::{DomainName, Endpoint, Network};

    fn target() -> Endpoint {
        Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443)
    }

    #[test]
    fn method_aliases_and_md5_kdf_match_go_shape() {
        assert_eq!(Method::parse("aes-128-gcm").unwrap(), Method::Aes128Gcm);
        assert_eq!(
            Method::parse("AEAD_CHACHA20_POLY1305").unwrap(),
            Method::Chacha20Poly1305
        );
        assert_eq!(md5_password_kdf(b"password", 16).len(), 16);
        assert_eq!(md5_password_kdf(b"password", 32).len(), 32);
        assert!(Method::parse("rc4-md5").is_err());
    }

    #[test]
    fn udp_packets_round_trip_for_all_aead_methods() {
        let destination = Endpoint::ip(Network::Udp, "192.0.2.1:53".parse().unwrap());
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            let config = ShadowsocksConfig::from_password(method, "secret").unwrap();
            let packet = encrypt_udp_packet(&config, &destination, b"dns payload").unwrap();
            let mut output = [0u8; 64];
            let (length, actual) = decrypt_udp_packet(&config, &packet, &mut output).unwrap();
            assert_eq!(length, 11);
            assert_eq!(&output[..length], b"dns payload");
            assert_eq!(actual, destination);
        }
    }

    #[tokio::test]
    async fn stream_records_preserve_target_and_payload() {
        let config = ShadowsocksConfig::from_password(Method::Aes256Gcm, "secret").unwrap();
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let server_config = config.clone();
        let server_task = tokio::spawn(async move {
            let mut salt = vec![0u8; server_config.salt_size()];
            server.read_exact(&mut salt).await.unwrap();
            let mut state = server_config.state_for_salt(&salt).unwrap();
            let encrypted_length = server.read_u8().await.unwrap();
            let mut rest = vec![0u8; 2 + AEAD_TAG_SIZE];
            rest[0] = encrypted_length;
            server.read_exact(&mut rest[1..]).await.unwrap();
            let length = state.open(&rest).unwrap();
            let size = usize::from(u16::from_be_bytes([length[0], length[1]]));
            let mut ciphertext = vec![0u8; size + AEAD_TAG_SIZE];
            server.read_exact(&mut ciphertext).await.unwrap();
            let endpoint = state.open(&ciphertext).unwrap();
            let mut cursor = 0;
            assert_eq!(
                decode_endpoint(&endpoint, &mut cursor, Network::Tcp).unwrap(),
                target()
            );

            let mut response_state = server_config.state_for_salt(&[7u8; 32]).unwrap();
            server.write_all(&[7u8; 32]).await.unwrap();
            write_record(&mut server, &mut response_state, b"reply")
                .await
                .unwrap();
        });
        let mut stream = ShadowsocksStream::connect(Box::new(client), config, &target())
            .await
            .unwrap();
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"reply");
        server_task.await.unwrap();
    }

    #[test]
    fn malformed_udp_packet_is_rejected() {
        let config = ShadowsocksConfig::from_password(Method::Aes128Gcm, "secret").unwrap();
        let error =
            decrypt_udp_packet(&config, &vec![0u8; config.salt_size() + 15], &mut [0u8; 32])
                .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Protocol);
    }
}
