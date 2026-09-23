//! Outbound ShadowsocksR compatibility.
//!
//! The first supported surface is the commonly deployed auth_aes128_md5
//! protocol with origin/plain obfuscation and the legacy AES/ChaCha stream
//! ciphers. Other SSR protocols and obfuscators fail explicitly.

use std::io;
use std::sync::Arc;

use crate::yuubinsya::{decode_endpoint, encode_endpoint};
use doradus_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use doradus_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};
use md5::{Digest, Md5};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};

const MAX_FRAME_SIZE: usize = 8192;
const MAX_PACKET_SIZE: usize = 64 * 1024 - 1;

#[path = "shadowsocksr/cipher.rs"]
mod cipher;
#[path = "shadowsocksr/protocol.rs"]
mod protocol;

use cipher::StreamCipher;
use protocol::ProtocolState;
#[cfg(test)]
use protocol::decode_auth_header;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMethod {
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    Aes128Ctr,
    Aes192Ctr,
    Aes256Ctr,
    Aes128Ofb,
    Aes192Ofb,
    Aes256Ofb,
    Chacha20,
    Chacha20Ietf,
    None,
}

impl CipherMethod {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "chacha20-ietf" => Ok(Self::Chacha20Ietf),
            "aes-128-cfb" => Ok(Self::Aes128Cfb),
            "aes-192-cfb" => Ok(Self::Aes192Cfb),
            "aes-256-cfb" => Ok(Self::Aes256Cfb),
            "aes-128-ctr" => Ok(Self::Aes128Ctr),
            "aes-192-ctr" => Ok(Self::Aes192Ctr),
            "aes-256-ctr" => Ok(Self::Aes256Ctr),
            "aes-128-ofb" => Ok(Self::Aes128Ofb),
            "aes-192-ofb" => Ok(Self::Aes192Ofb),
            "aes-256-ofb" => Ok(Self::Aes256Ofb),
            "chacha20" => Ok(Self::Chacha20),
            "none" | "dummy" => Ok(Self::None),
            other => Err(Error::new(
                ErrorKind::Unsupported,
                format!("unsupported ShadowsocksR cipher {other:?}"),
            )),
        }
    }

    const fn key_len(self) -> usize {
        match self {
            Self::Aes128Cfb | Self::Aes128Ctr | Self::Aes128Ofb => 16,
            Self::Aes192Cfb | Self::Aes192Ctr | Self::Aes192Ofb => 24,
            Self::Aes256Cfb
            | Self::Aes256Ctr
            | Self::Aes256Ofb
            | Self::Chacha20
            | Self::Chacha20Ietf => 32,
            Self::None => 0,
        }
    }

    const fn iv_len(self) -> usize {
        match self {
            Self::Chacha20 => 8,
            Self::None => 0,
            _ => 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    Origin,
    AuthAes128Md5,
}

impl ProtocolKind {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "origin" => Ok(Self::Origin),
            "auth_aes128_md5" => Ok(Self::AuthAes128Md5),
            other => Err(Error::new(
                ErrorKind::Unsupported,
                format!("unsupported ShadowsocksR protocol {other:?}"),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfsKind {
    Plain,
}

impl ObfsKind {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "plain" => Ok(Self::Plain),
            other => Err(Error::new(
                ErrorKind::Unsupported,
                format!("unsupported ShadowsocksR obfs {other:?}"),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShadowsocksrConfig {
    pub method: CipherMethod,
    pub password: String,
    pub protocol: ProtocolKind,
    pub protocol_param: String,
    pub obfs: ObfsKind,
    pub obfs_param: String,
}

impl ShadowsocksrConfig {
    pub fn new(
        method: &str,
        password: &str,
        protocol: &str,
        protocol_param: &str,
        obfs: &str,
        obfs_param: &str,
    ) -> Result<Self> {
        let method = CipherMethod::parse(method)?;
        let protocol = ProtocolKind::parse(protocol)?;
        let obfs = ObfsKind::parse(obfs)?;
        if method != CipherMethod::None && password.is_empty() {
            return Err(Error::invalid("ShadowsocksR password is empty"));
        }
        Ok(Self {
            method,
            password: password.to_owned(),
            protocol,
            protocol_param: protocol_param.to_owned(),
            obfs,
            obfs_param: obfs_param.to_owned(),
        })
    }

    fn cipher_key(&self) -> Vec<u8> {
        md5_password_kdf(self.password.as_bytes(), self.method.key_len())
    }
}

pub struct ShadowsocksrProxy {
    upstream: Arc<dyn AsyncProxy>,
    config: ShadowsocksrConfig,
}

impl ShadowsocksrProxy {
    pub fn new(
        upstream: Arc<dyn AsyncProxy>,
        method: &str,
        password: &str,
        protocol: &str,
        protocol_param: &str,
        obfs: &str,
        obfs_param: &str,
    ) -> Result<Self> {
        Ok(Self {
            upstream,
            config: ShadowsocksrConfig::new(
                method,
                password,
                protocol,
                protocol_param,
                obfs,
                obfs_param,
            )?,
        })
    }

    pub fn config(&self) -> &ShadowsocksrConfig {
        &self.config
    }
}

impl AsyncProxy for ShadowsocksrProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let mut upstream = self.upstream.connect(context).await?;
            let key = self.config.cipher_key();
            let mut write_iv = vec![0u8; self.config.method.iv_len()];
            fill_random(&mut write_iv);
            upstream.write_all(&write_iv).await.map_err(io_error)?;
            let mut cipher =
                StreamCipher::new(self.config.method, &key, &write_iv, false).map_err(io_error)?;
            let mut protocol =
                ProtocolState::new(self.config.protocol, &key, &self.config.protocol_param);
            protocol.set_stream_iv(&write_iv);
            let mut target = Vec::new();
            encode_endpoint(&context.effective_destination(), &mut target)?;
            let mut encoded = protocol.encode_stream(&target).map_err(io_error)?;
            cipher.apply(&mut encoded).map_err(io_error)?;
            upstream.write_all(&encoded).await.map_err(io_error)?;

            let (client, relay) = tokio::io::duplex(64 * 1024);
            let (local_reader, local_writer) = split(relay);
            let (remote_reader, remote_writer) = split(upstream);
            tokio::spawn(upload_loop(
                local_reader,
                remote_writer,
                self.config.clone(),
                key.clone(),
                cipher,
                protocol,
            ));
            tokio::spawn(download_loop(
                remote_reader,
                local_writer,
                self.config.clone(),
                key,
            ));
            Ok(Box::new(client) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            let upstream = self.upstream.open_datagram(context).await?;
            let key = self.config.cipher_key();
            Ok(Box::new(ShadowsocksrDatagram {
                upstream,
                key: key.clone(),
                method: self.config.method,
                protocol: ProtocolState::new(
                    self.config.protocol,
                    &key,
                    &self.config.protocol_param,
                ),
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

async fn upload_loop<R, W>(
    mut local: R,
    mut remote: W,
    config: ShadowsocksrConfig,
    key: Vec<u8>,
    mut cipher: StreamCipher,
    mut protocol: ProtocolState,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let _ = (&config, &key);
    let mut input = vec![0u8; 16 * 1024];
    loop {
        let count = match local.read(&mut input).await {
            Ok(0) => {
                let _ = remote.shutdown().await;
                return;
            }
            Ok(count) => count,
            Err(_) => return,
        };
        let mut encoded = match protocol.encode_stream(&input[..count]) {
            Ok(value) => value,
            Err(_) => return,
        };
        if cipher.apply(&mut encoded).is_err() || remote.write_all(&encoded).await.is_err() {
            return;
        }
    }
}

async fn download_loop<R, W>(mut remote: R, mut local: W, config: ShadowsocksrConfig, key: Vec<u8>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut read_iv = vec![0u8; config.method.iv_len()];
    if remote.read_exact(&mut read_iv).await.is_err() {
        return;
    }
    let mut cipher = match StreamCipher::new(config.method, &key, &read_iv, true) {
        Ok(value) => value,
        Err(_) => return,
    };
    let mut protocol = ProtocolState::new(config.protocol, &key, &config.protocol_param);
    let mut encrypted = [0u8; 16 * 1024];
    let mut pending = Vec::new();
    loop {
        let count = match remote.read(&mut encrypted).await {
            Ok(0) | Err(_) => return,
            Ok(count) => count,
        };
        if cipher.apply(&mut encrypted[..count]).is_err() {
            return;
        }
        pending.extend_from_slice(&encrypted[..count]);
        let mut plaintext = Vec::new();
        match protocol.decode_stream(&mut pending, &mut plaintext) {
            Ok(()) if !plaintext.is_empty() => {
                if local.write_all(&plaintext).await.is_err() {
                    return;
                }
            }
            Ok(()) => {}
            Err(_) => return,
        }
    }
}

struct ShadowsocksrDatagram {
    upstream: Box<dyn AsyncDatagram>,
    key: Vec<u8>,
    method: CipherMethod,
    protocol: ProtocolState,
}

impl AsyncDatagram for ShadowsocksrDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let mut plain = Vec::with_capacity(260 + payload.len());
            encode_endpoint(&target, &mut plain)?;
            plain.extend_from_slice(payload);
            let mut packet = self.protocol.encode_packet(&plain).map_err(io_error)?;
            let mut iv = vec![0u8; self.method.iv_len()];
            fill_random(&mut iv);
            let mut cipher =
                StreamCipher::new(self.method, &self.key, &iv, false).map_err(io_error)?;
            cipher.apply(&mut packet).map_err(io_error)?;
            iv.extend_from_slice(&packet);
            if iv.len() > MAX_PACKET_SIZE {
                return Err(Error::invalid("ShadowsocksR UDP packet is too large"));
            }
            self.upstream.send_to(&iv, target).await?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let mut packet = vec![0u8; MAX_PACKET_SIZE];
            let (length, _) = self.upstream.recv_from(&mut packet).await?;
            let iv_len = self.method.iv_len();
            if length < iv_len {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "truncated ShadowsocksR UDP IV",
                ));
            }
            let mut cipher = StreamCipher::new(self.method, &self.key, &packet[..iv_len], true)
                .map_err(io_error)?;
            let mut plain = packet[iv_len..length].to_vec();
            cipher.apply(&mut plain).map_err(io_error)?;
            let plain = self.protocol.decode_packet(&plain).map_err(io_error)?;
            let mut cursor = 0;
            let destination = decode_endpoint(&plain, &mut cursor, Network::Udp)?;
            let mut payload = &plain[cursor..];
            if let Some(stripped) = payload.strip_suffix(&self.protocol.uid()[..]) {
                payload = stripped;
            }
            if payload.len() > buffer.len() {
                return Err(Error::invalid(
                    "ShadowsocksR UDP receive buffer is too small",
                ));
            }
            buffer[..payload.len()].copy_from_slice(payload);
            Ok((payload.len(), destination))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.upstream.local_addr()
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

fn md5_password_kdf(password: &[u8], key_len: usize) -> Vec<u8> {
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

fn fill_random(bytes: &mut [u8]) {
    if !bytes.is_empty() {
        rand::RngExt::fill(&mut rand::rng(), bytes);
    }
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn io_error(error: io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(test)]
#[path = "shadowsocksr_tests.rs"]
mod tests;
