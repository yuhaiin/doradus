//! Outbound ShadowsocksR compatibility.
//!
//! The first supported surface is the commonly deployed auth_aes128_md5
//! protocol with origin/plain obfuscation and the legacy AES/ChaCha stream
//! ciphers. Other SSR protocols and obfuscators fail explicitly.

use std::io;
use std::sync::Arc;

use crate::yuubinsya::{decode_endpoint, encode_endpoint};
use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit, generic_array::GenericArray};
use aes::{Aes128, Aes192, Aes256};
use base64::Engine;
use chacha20::{ChaCha20, ChaCha20Legacy};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};

const MAX_FRAME_SIZE: usize = 8192;
const MAX_PACKET_SIZE: usize = 64 * 1024 - 1;
type HmacMd5 = Hmac<Md5>;

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

#[derive(Debug, Clone)]
struct ProtocolState {
    kind: ProtocolKind,
    user_key: Vec<u8>,
    cipher_key: Vec<u8>,
    auth_key: Vec<u8>,
    uid: [u8; 4],
    client_id: [u8; 4],
    connection_id: u32,
    pack_id: u32,
    recv_id: u32,
    sent_header: bool,
}

impl ProtocolState {
    fn new(kind: ProtocolKind, cipher_key: &[u8], parameter: &str) -> Self {
        let mut uid = [0u8; 4];
        let mut user_key = cipher_key.to_vec();
        let mut parts = parameter.splitn(2, ':');
        if let (Some(uid_text), Some(user_password)) = (parts.next(), parts.next()) {
            if let Ok(value) = uid_text.parse::<u32>() {
                uid = value.to_le_bytes();
                user_key = md5_digest(user_password.as_bytes()).to_vec();
            }
        } else {
            fill_random(&mut uid);
        }
        let mut client_id = [0u8; 4];
        fill_random(&mut client_id);
        let mut connection = [0u8; 4];
        fill_random(&mut connection);
        Self {
            kind,
            user_key,
            cipher_key: cipher_key.to_vec(),
            auth_key: cipher_key.to_vec(),
            uid,
            client_id,
            connection_id: u32::from_le_bytes(connection) & 0x00ff_ffff,
            pack_id: 1,
            recv_id: 1,
            sent_header: false,
        }
    }

    fn set_stream_iv(&mut self, iv: &[u8]) {
        self.auth_key.clear();
        self.auth_key.extend_from_slice(iv);
        self.auth_key.extend_from_slice(&self.cipher_key);
    }

    fn uid(&self) -> &[u8; 4] {
        &self.uid
    }

    fn encode_stream(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        match self.kind {
            ProtocolKind::Origin => Ok(data.to_vec()),
            ProtocolKind::AuthAes128Md5 => {
                let mut output = Vec::new();
                if !self.sent_header {
                    self.sent_header = true;
                    self.pack_auth_data(data, &mut output)?;
                } else {
                    for chunk in data.chunks(8100) {
                        self.pack_data(chunk, &mut output)?;
                    }
                }
                Ok(output)
            }
        }
    }

    fn decode_stream(&mut self, pending: &mut Vec<u8>, output: &mut Vec<u8>) -> io::Result<()> {
        if self.kind == ProtocolKind::Origin {
            output.extend_from_slice(pending);
            pending.clear();
            return Ok(());
        }
        loop {
            if pending.len() < 4 {
                return Ok(());
            }
            let mut id_key = self.user_key.clone();
            id_key.extend_from_slice(&self.recv_id.to_le_bytes());
            if hmac_md5(&id_key, &pending[..2])[..2] != pending[2..4] {
                return Err(invalid_data("ShadowsocksR frame length HMAC mismatch"));
            }
            let length = usize::from(u16::from_le_bytes([pending[0], pending[1]]));
            if !(7..MAX_FRAME_SIZE).contains(&length) {
                return Err(invalid_data("invalid ShadowsocksR frame length"));
            }
            if pending.len() < length {
                return Ok(());
            }
            if hmac_md5(&id_key, &pending[..length - 4])[..4] != pending[length - 4..length] {
                return Err(invalid_data("ShadowsocksR frame checksum mismatch"));
            }
            let mut position = usize::from(pending[4]);
            if position >= 255 {
                position = usize::from(u16::from_le_bytes([pending[5], pending[6]]));
            }
            position = position
                .checked_add(4)
                .ok_or_else(|| invalid_data("ShadowsocksR padding overflow"))?;
            if position > length - 4 {
                return Err(invalid_data("ShadowsocksR padding exceeds frame"));
            }
            output.extend_from_slice(&pending[position..length - 4]);
            pending.drain(..length);
            self.recv_id = self.recv_id.wrapping_add(1);
        }
    }

    fn encode_packet(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        match self.kind {
            ProtocolKind::Origin => Ok(data.to_vec()),
            ProtocolKind::AuthAes128Md5 => {
                let mut output = data.to_vec();
                output.extend_from_slice(&self.uid);
                output.extend_from_slice(&hmac_md5(&self.user_key, &output)[..4]);
                Ok(output)
            }
        }
    }

    fn decode_packet(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        match self.kind {
            ProtocolKind::Origin => Ok(data.to_vec()),
            ProtocolKind::AuthAes128Md5 => {
                if data.len() < 4
                    || hmac_md5(&self.user_key, &data[..data.len() - 4])[..4]
                        != data[data.len() - 4..]
                {
                    return Err(invalid_data("ShadowsocksR UDP checksum mismatch"));
                }
                Ok(data[..data.len() - 4].to_vec())
            }
        }
    }

    fn pack_auth_data(&mut self, data: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        let mut random_length = [0u8; 2];
        fill_random(&mut random_length);
        let random_length = usize::from(u16::from_le_bytes(random_length) % 1024);
        let output_length = 35usize
            .checked_add(random_length)
            .and_then(|value| value.checked_add(data.len()))
            .ok_or_else(|| invalid_data("ShadowsocksR auth header overflow"))?;
        if output_length > u16::MAX as usize {
            return Err(invalid_data("ShadowsocksR auth header is too large"));
        }

        let encoded_key = base64::engine::general_purpose::STANDARD.encode(&self.user_key);
        let aes_key = md5_password_kdf(format!("{encoded_key}auth_aes128_md5").as_bytes(), 16);
        let mut metadata = [0u8; 16];
        metadata[..4].copy_from_slice(&(unix_seconds() as u32).to_le_bytes());
        metadata[4..8].copy_from_slice(&self.client_id);
        metadata[8..12].copy_from_slice(&self.connection_id.to_le_bytes());
        metadata[12..14].copy_from_slice(&(output_length as u16).to_le_bytes());
        metadata[14..16].copy_from_slice(&(random_length as u16).to_le_bytes());
        aes128_cbc_encrypt(&aes_key, &mut metadata)?;

        let mut head = [0u8; 1];
        fill_random(&mut head);
        output.extend_from_slice(&head);
        output.extend_from_slice(&hmac_md5(&self.auth_key, &head)[..6]);
        output.extend_from_slice(&self.uid);
        output.extend_from_slice(&metadata);
        output.extend_from_slice(&hmac_md5(&self.auth_key, &output[7..27])[..4]);
        let old_len = output.len();
        output.resize(old_len + random_length, 0);
        fill_random(&mut output[old_len..]);
        output.extend_from_slice(data);
        output.extend_from_slice(&hmac_md5(&self.user_key, output.as_slice())[..4]);
        Ok(())
    }

    fn pack_data(&mut self, data: &[u8], output: &mut Vec<u8>) -> io::Result<()> {
        let length = data
            .len()
            .checked_add(9)
            .ok_or_else(|| invalid_data("ShadowsocksR frame overflow"))?;
        if length >= MAX_FRAME_SIZE || length > u16::MAX as usize {
            return Err(invalid_data("ShadowsocksR frame is too large"));
        }
        let mut id_key = self.user_key.clone();
        id_key.extend_from_slice(&self.pack_id.to_le_bytes());
        let length_bytes = (length as u16).to_le_bytes();
        let frame_start = output.len();
        output.extend_from_slice(&length_bytes);
        output.extend_from_slice(&hmac_md5(&id_key, &length_bytes)[..2]);
        output.push(1);
        output.extend_from_slice(data);
        output.extend_from_slice(&hmac_md5(&id_key, &output[frame_start..])[..4]);
        self.pack_id = self.pack_id.wrapping_add(1);
        Ok(())
    }
}

#[allow(clippy::large_enum_variant)]
enum StreamCipher {
    None,
    Aes(AesStream),
    Chacha20(ChaCha20),
    Chacha20Legacy(ChaCha20Legacy),
}

impl StreamCipher {
    fn new(method: CipherMethod, key: &[u8], iv: &[u8], decrypt: bool) -> io::Result<Self> {
        if iv.len() != method.iv_len() || key.len() != method.key_len() {
            return Err(invalid_data("invalid ShadowsocksR key or IV length"));
        }
        match method {
            CipherMethod::None => Ok(Self::None),
            CipherMethod::Chacha20Ietf => Ok(Self::Chacha20(
                chacha20::cipher::KeyIvInit::new_from_slices(key, iv)
                    .map_err(|_| invalid_data("invalid ChaCha20 key or IV"))?,
            )),
            CipherMethod::Chacha20 => Ok(Self::Chacha20Legacy(
                chacha20::cipher::KeyIvInit::new_from_slices(key, iv)
                    .map_err(|_| invalid_data("invalid legacy ChaCha20 key or IV"))?,
            )),
            _ => Ok(Self::Aes(AesStream::new(method, key, iv, decrypt)?)),
        }
    }

    fn apply(&mut self, data: &mut [u8]) -> io::Result<()> {
        match self {
            Self::None => Ok(()),
            Self::Aes(cipher) => cipher.apply(data),
            Self::Chacha20(cipher) => {
                chacha20::cipher::StreamCipher::apply_keystream(cipher, data);
                Ok(())
            }
            Self::Chacha20Legacy(cipher) => {
                chacha20::cipher::StreamCipher::apply_keystream(cipher, data);
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum AesMode {
    Cfb,
    Ctr,
    Ofb,
}

#[derive(Debug)]
enum AesBlockCipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

impl AesBlockCipher {
    fn encrypt(&self, block: &mut [u8; 16]) {
        let mut encrypted = GenericArray::clone_from_slice(block);
        match self {
            Self::Aes128(cipher) => cipher.encrypt_block(&mut encrypted),
            Self::Aes192(cipher) => cipher.encrypt_block(&mut encrypted),
            Self::Aes256(cipher) => cipher.encrypt_block(&mut encrypted),
        }
        block.copy_from_slice(&encrypted);
    }
}

#[derive(Debug)]
struct AesStream {
    mode: AesMode,
    decrypt: bool,
    cipher: AesBlockCipher,
    feedback: [u8; 16],
    keystream: [u8; 16],
    offset: usize,
}

impl AesStream {
    fn new(method: CipherMethod, key: &[u8], iv: &[u8], decrypt: bool) -> io::Result<Self> {
        let cipher = match key.len() {
            16 => AesBlockCipher::Aes128(
                Aes128::new_from_slice(key).map_err(|_| invalid_data("invalid AES-128 key"))?,
            ),
            24 => AesBlockCipher::Aes192(
                Aes192::new_from_slice(key).map_err(|_| invalid_data("invalid AES-192 key"))?,
            ),
            32 => AesBlockCipher::Aes256(
                Aes256::new_from_slice(key).map_err(|_| invalid_data("invalid AES-256 key"))?,
            ),
            _ => return Err(invalid_data("invalid AES key length")),
        };
        let mode = match method {
            CipherMethod::Aes128Cfb | CipherMethod::Aes192Cfb | CipherMethod::Aes256Cfb => {
                AesMode::Cfb
            }
            CipherMethod::Aes128Ctr | CipherMethod::Aes192Ctr | CipherMethod::Aes256Ctr => {
                AesMode::Ctr
            }
            _ => AesMode::Ofb,
        };
        Ok(Self {
            mode,
            decrypt,
            cipher,
            feedback: iv.try_into().unwrap(),
            keystream: [0; 16],
            offset: 16,
        })
    }

    fn apply(&mut self, data: &mut [u8]) -> io::Result<()> {
        for byte in data {
            if self.offset == 16 {
                self.keystream = self.feedback;
                self.cipher.encrypt(&mut self.keystream);
                if matches!(self.mode, AesMode::Ofb) {
                    self.feedback = self.keystream;
                }
                if matches!(self.mode, AesMode::Ctr) {
                    for index in (0..16).rev() {
                        self.feedback[index] = self.feedback[index].wrapping_add(1);
                        if self.feedback[index] != 0 {
                            break;
                        }
                    }
                }
                self.offset = 0;
            }
            let input = *byte;
            *byte ^= self.keystream[self.offset];
            if matches!(self.mode, AesMode::Cfb) {
                self.feedback[self.offset] = if self.decrypt { input } else { *byte };
            }
            self.offset += 1;
        }
        Ok(())
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

#[cfg(test)]
fn decode_auth_header(
    pending: &mut Vec<u8>,
    cipher_key: &[u8],
    stream_iv: &[u8],
) -> io::Result<Option<Vec<u8>>> {
    if pending.len() < 31 {
        return Ok(None);
    }
    let mut auth_key = stream_iv.to_vec();
    auth_key.extend_from_slice(cipher_key);
    if hmac_md5(&auth_key, &pending[..1])[..6] != pending[1..7] {
        return Err(invalid_data("ShadowsocksR auth header HMAC mismatch"));
    }
    let encoded_key = base64::engine::general_purpose::STANDARD.encode(cipher_key);
    let aes_key = md5_password_kdf(format!("{encoded_key}auth_aes128_md5").as_bytes(), 16);
    let mut metadata = [0u8; 16];
    metadata.copy_from_slice(&pending[11..27]);
    aes128_cbc_decrypt(&aes_key, &mut metadata)?;
    let total = usize::from(u16::from_le_bytes([metadata[12], metadata[13]]));
    let random_length = usize::from(u16::from_le_bytes([metadata[14], metadata[15]]));
    if total < 35 + random_length || total > MAX_PACKET_SIZE {
        return Err(invalid_data("invalid ShadowsocksR auth header length"));
    }
    if pending.len() < total {
        return Ok(None);
    }
    if hmac_md5(&auth_key, &pending[7..27])[..4] != pending[27..31] {
        return Err(invalid_data("ShadowsocksR auth metadata checksum mismatch"));
    }
    if hmac_md5(cipher_key, &pending[..total - 4])[..4] != pending[total - 4..total] {
        return Err(invalid_data("ShadowsocksR auth header checksum mismatch"));
    }
    let start = 31 + random_length;
    let data = pending[start..total - 4].to_vec();
    pending.drain(..total);
    Ok(Some(data))
}

fn md5_digest(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac =
        <HmacMd5 as Mac>::new_from_slice(key).expect("HMAC accepts arbitrary key lengths");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn aes128_cbc_encrypt(key: &[u8], block: &mut [u8; 16]) -> io::Result<()> {
    let cipher = Aes128::new_from_slice(key).map_err(|_| invalid_data("invalid auth AES key"))?;
    let mut encrypted = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut encrypted);
    block.copy_from_slice(&encrypted);
    Ok(())
}

#[cfg(test)]
fn aes128_cbc_decrypt(key: &[u8], block: &mut [u8; 16]) -> io::Result<()> {
    use aes::cipher::BlockDecrypt;
    let cipher = Aes128::new_from_slice(key).map_err(|_| invalid_data("invalid auth AES key"))?;
    let mut decrypted = GenericArray::clone_from_slice(block);
    cipher.decrypt_block(&mut decrypted);
    block.copy_from_slice(&decrypted);
    Ok(())
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
