//! VMess v2 (AEAD header) TCP client and wire codec.
//!
//! The Go implementation used by yuhaiin exposes VMess as an outbound-only
//! protocol.  This module deliberately implements the modern `alter_id=0`
//! path: the authenticated AEAD request header, AES-128-GCM/ChaCha20-Poly1305
//! (or plaintext) chunk stream, and the encrypted response header.  Legacy
//! alter-id/CFB users and VMess UDP packet mode remain explicit unsupported
//! features instead of being silently treated as TCP.

use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit, generic_array::GenericArray};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use crc32fast::Hasher as Crc32;
use md5::{Digest as Md5Digest, Md5};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};

const VERSION: u8 = 1;
const OPT_CHUNK_STREAM: u8 = 1;
const CMD_TCP: u8 = 1;
const CMD_UDP: u8 = 2;
const MAX_CHUNK_SIZE: usize = 8192;
const MAX_HEADER_SIZE: usize = 8192;
const AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
const AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const AEAD_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
const VMESS_HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const VMESS_HEADER_PAYLOAD_IV: &[u8] = b"VMess Header AEAD Nonce";
const VMESS_HEADER_PAYLOAD_LENGTH_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const VMESS_HEADER_PAYLOAD_LENGTH_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const UUID_SUFFIX: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Security {
    Aes128Gcm = 3,
    Chacha20Poly1305 = 4,
    None = 5,
}

impl Security {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "chacha20-poly1305" => Ok(Self::Chacha20Poly1305),
            "none" => Ok(Self::None),
            "" | "auto" => Ok(Self::Aes128Gcm),
            other => Err(Error::invalid(format!(
                "unsupported VMess security {other:?}"
            ))),
        }
    }

    fn from_byte(value: u8) -> Result<Self> {
        match value {
            3 => Ok(Self::Aes128Gcm),
            4 => Ok(Self::Chacha20Poly1305),
            5 => Ok(Self::None),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unsupported VMess body security",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub body_iv: [u8; 16],
    pub body_key: [u8; 16],
    pub response_v: u8,
    pub option: u8,
    pub security: Security,
    pub command: u8,
    pub destination: Endpoint,
}

/// Derive the VMess command key from the user's UUID.
pub fn command_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut md5 = Md5::new();
    md5.update(uuid);
    md5.update(UUID_SUFFIX);
    md5.finalize().into()
}

/// Build a modern VMess request and return the request state needed for the
/// encrypted response/body stream.
pub fn encode_request(
    uuid: &[u8; 16],
    security: Security,
    command: u8,
    destination: &Endpoint,
) -> Result<(Vec<u8>, Request)> {
    if command == CMD_TCP && destination.network() != Network::Tcp {
        return Err(Error::invalid(
            "VMess TCP command has a non-TCP destination",
        ));
    }
    if command == CMD_UDP && destination.network() != Network::Udp {
        return Err(Error::invalid(
            "VMess UDP command has a non-UDP destination",
        ));
    }
    if !matches!(command, CMD_TCP | CMD_UDP) {
        return Err(Error::invalid("unsupported VMess command"));
    }

    let random: [u8; 33] = rand::random();
    let body_iv: [u8; 16] = random[..16].try_into().unwrap();
    let body_key: [u8; 16] = random[16..32].try_into().unwrap();
    let response_v = random[32];
    let mut plaintext = Vec::with_capacity(128);
    plaintext.push(VERSION);
    plaintext.extend_from_slice(&body_iv);
    plaintext.extend_from_slice(&body_key);
    plaintext.push(response_v);
    plaintext.push(OPT_CHUNK_STREAM);
    plaintext.push(security as u8);
    plaintext.push(0); // reserved
    plaintext.push(command);
    let port = destination
        .port()
        .ok_or_else(|| Error::invalid("VMess destination has no port"))?;
    plaintext.extend_from_slice(&port.to_be_bytes());
    encode_address(destination, &mut plaintext)?;
    let padding_len = (random[0] & 0x0f) as usize;
    plaintext[35] = (padding_len as u8) << 4 | security as u8;
    let mut padding = vec![0u8; padding_len];
    if !padding.is_empty() {
        padding.copy_from_slice(&random[..padding_len]);
        plaintext.extend_from_slice(&padding);
    }
    let checksum = fnv1a(&plaintext);
    plaintext.extend_from_slice(&checksum.to_be_bytes());

    let header = seal_header(&command_key(uuid), &plaintext)?;
    Ok((
        header,
        Request {
            body_iv,
            body_key,
            response_v,
            option: OPT_CHUNK_STREAM,
            security,
            command,
            destination: destination.clone(),
        },
    ))
}

/// Decode the AEAD request header sent by a VMess client.
pub fn decode_request(packet: &[u8], uuid: &[u8; 16]) -> Result<Request> {
    let plaintext = open_header(&command_key(uuid), packet)?;
    if plaintext.len() < 42 || plaintext[0] != VERSION {
        return Err(Error::new(
            ErrorKind::Protocol,
            "invalid VMess request header",
        ));
    }
    let checksum_offset = plaintext.len() - 4;
    if fnv1a(&plaintext[..checksum_offset])
        != u32::from_be_bytes(
            plaintext[checksum_offset..]
                .try_into()
                .map_err(|_| Error::new(ErrorKind::Protocol, "invalid VMess checksum"))?,
        )
    {
        return Err(Error::new(
            ErrorKind::Protocol,
            "invalid VMess request checksum",
        ));
    }
    let body_iv = plaintext[1..17].try_into().unwrap();
    let body_key = plaintext[17..33].try_into().unwrap();
    let response_v = plaintext[33];
    let option = plaintext[34];
    let security = Security::from_byte(plaintext[35] & 0x0f)?;
    if plaintext[36] != 0 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "invalid VMess reserved byte",
        ));
    }
    let command = plaintext[37];
    let port = u16::from_be_bytes([plaintext[38], plaintext[39]]);
    let mut cursor = 40;
    let destination = decode_address(&plaintext, &mut cursor, command, port)?;
    let padding_len = usize::from(plaintext[35] >> 4);
    if cursor + padding_len + 4 != plaintext.len() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "invalid VMess padding length",
        ));
    }
    Ok(Request {
        body_iv,
        body_key,
        response_v,
        option,
        security,
        command,
        destination,
    })
}

pub fn encode_response_header(
    response_v: u8,
    body_key: &[u8; 16],
    body_iv: &[u8; 16],
) -> Result<Vec<u8>> {
    let plaintext = [response_v, 0, 0, 0];
    let length = [0u8, plaintext.len() as u8];
    let length_key = kdf16(body_key, &[AEAD_RESP_HEADER_LEN_KEY]);
    let length_iv = kdf(body_iv, &[AEAD_RESP_HEADER_LEN_IV]);
    let payload_key = kdf16(body_key, &[AEAD_RESP_HEADER_PAYLOAD_KEY]);
    let payload_iv = kdf(body_iv, &[AEAD_RESP_HEADER_PAYLOAD_IV]);
    let mut output = aead_seal(&length_key, &length_iv[..12], &length, &[])?;
    output.extend_from_slice(&aead_seal(
        &payload_key,
        &payload_iv[..12],
        &plaintext,
        &[],
    )?);
    Ok(output)
}

/// Decode a VMess AEAD response header from a complete byte slice.
pub fn decode_response_header(
    packet: &[u8],
    body_key: &[u8; 16],
    body_iv: &[u8; 16],
) -> Result<()> {
    let mut cursor = 0;
    let length_packet = take(packet, &mut cursor, 18)?;
    let length_key = kdf16(body_key, &[AEAD_RESP_HEADER_LEN_KEY]);
    let length_iv = kdf(body_iv, &[AEAD_RESP_HEADER_LEN_IV]);
    let length = aead_open(&length_key, &length_iv[..12], length_packet, &[])?;
    let length = u16::from_be_bytes(
        length
            .as_slice()
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Protocol, "invalid VMess response length"))?,
    ) as usize;
    let payload = take(packet, &mut cursor, length + 16)?;
    let payload_key = kdf16(body_key, &[AEAD_RESP_HEADER_PAYLOAD_KEY]);
    let payload_iv = kdf(body_iv, &[AEAD_RESP_HEADER_PAYLOAD_IV]);
    let plaintext = aead_open(&payload_key, &payload_iv[..12], payload, &[])?;
    if plaintext.len() < 4 || plaintext[0] == 0xff {
        return Err(Error::new(
            ErrorKind::Protocol,
            "invalid VMess response header",
        ));
    }
    Ok(())
}

pub struct VmessProxy {
    upstream: Arc<dyn AsyncProxy>,
    uuid: [u8; 16],
    security: Security,
}

impl VmessProxy {
    pub fn new(
        upstream: Arc<dyn AsyncProxy>,
        uuid: &str,
        security: &str,
        alter_id: u32,
    ) -> Result<Self> {
        if alter_id != 0 {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "VMess alter_id is not supported; use modern alter_id=0",
            ));
        }
        Ok(Self {
            upstream,
            uuid: crate::vless::parse_uuid(uuid)?,
            security: Security::parse(security)?,
        })
    }

    pub fn from_uuid(upstream: Arc<dyn AsyncProxy>, uuid: [u8; 16], security: Security) -> Self {
        Self {
            upstream,
            uuid,
            security,
        }
    }
}

impl AsyncProxy for VmessProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let mut upstream = self.upstream.connect(context).await?;
            let destination = context.effective_destination();
            let (request, state) =
                encode_request(&self.uuid, self.security, CMD_TCP, &destination)?;
            upstream.write_all(&request).await.map_err(io_error)?;

            let (client, relay) = tokio::io::duplex(64 * 1024);
            let (local_reader, local_writer) = split(relay);
            let (remote_reader, remote_writer) = split(upstream);
            tokio::spawn(relay_remote_to_local(
                remote_reader,
                local_writer,
                state.body_key,
                state.body_iv,
                state.response_v,
                state.security,
            ));
            tokio::spawn(relay_local_to_remote(
                local_reader,
                remote_writer,
                state.body_key,
                state.body_iv,
                state.security,
            ));
            Ok(Box::new(client) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "VMess UDP packet mode is not implemented yet",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

async fn relay_remote_to_local<R, W>(
    mut remote: R,
    mut local: W,
    body_key: [u8; 16],
    body_iv: [u8; 16],
    response_v: u8,
    security: Security,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if read_response_header(&mut remote, &body_key, &body_iv, response_v)
        .await
        .is_err()
    {
        let _ = local.shutdown().await;
        return;
    }
    let mut count = 0u16;
    loop {
        match read_body_frame(&mut remote, &body_key, &body_iv, security, count).await {
            Ok(Some(payload)) => {
                count = count.wrapping_add(1);
                if local.write_all(&payload).await.is_err() {
                    return;
                }
            }
            Ok(None) | Err(_) => {
                let _ = local.shutdown().await;
                return;
            }
        }
    }
}

async fn relay_local_to_remote<R, W>(
    mut local: R,
    mut remote: W,
    body_key: [u8; 16],
    body_iv: [u8; 16],
    security: Security,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let max_payload = body_payload_size(security);
    let mut payload = vec![0u8; max_payload];
    let mut count = 0u16;
    loop {
        match local.read(&mut payload).await {
            Ok(0) => {
                let _ = remote.shutdown().await;
                return;
            }
            Ok(length) => {
                if write_body_frame(
                    &mut remote,
                    &body_key,
                    &body_iv,
                    security,
                    count,
                    &payload[..length],
                )
                .await
                .is_err()
                {
                    return;
                }
                count = count.wrapping_add(1);
            }
            Err(_) => return,
        }
    }
}

async fn read_response_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    body_key: &[u8; 16],
    body_iv: &[u8; 16],
    response_v: u8,
) -> io::Result<()> {
    let mut length_packet = [0u8; 18];
    reader.read_exact(&mut length_packet).await?;
    let length_key = kdf16(body_key, &[AEAD_RESP_HEADER_LEN_KEY]);
    let length_iv = kdf(body_iv, &[AEAD_RESP_HEADER_LEN_IV]);
    let length = aead_open_io(&length_key, &length_iv[..12], &length_packet, &[])?;
    let length = u16::from_be_bytes(
        length
            .as_slice()
            .try_into()
            .map_err(|_| invalid_io("invalid VMess response header length"))?,
    ) as usize;
    if length > MAX_HEADER_SIZE {
        return Err(invalid_io("VMess response header is too large"));
    }
    let mut payload = vec![0u8; length + 16];
    reader.read_exact(&mut payload).await?;
    let payload_key = kdf16(body_key, &[AEAD_RESP_HEADER_PAYLOAD_KEY]);
    let payload_iv = kdf(body_iv, &[AEAD_RESP_HEADER_PAYLOAD_IV]);
    let plaintext = aead_open_io(&payload_key, &payload_iv[..12], &payload, &[])?;
    if plaintext.len() < 4 || plaintext[0] != response_v || plaintext[2] != 0 {
        return Err(invalid_io("invalid VMess response header"));
    }
    Ok(())
}

async fn read_body_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    key: &[u8; 16],
    iv: &[u8; 16],
    security: Security,
    count: u16,
) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 2];
    reader.read_exact(&mut length).await?;
    let length = usize::from(u16::from_be_bytes(length));
    if length == 0 {
        return Ok(None);
    }
    let overhead = body_overhead(security);
    if length < overhead || length > MAX_CHUNK_SIZE {
        return Err(invalid_io("VMess body frame exceeds the configured bound"));
    }
    let mut encrypted = vec![0u8; length];
    reader.read_exact(&mut encrypted).await?;
    let nonce = body_nonce(iv, count);
    let payload = match security {
        Security::None => encrypted,
        Security::Aes128Gcm => Aes128Gcm::new_from_slice(key)
            .map_err(|_| invalid_io("invalid VMess AES key"))?
            .decrypt(Nonce::from_slice(&nonce), encrypted.as_ref())
            .map_err(|_| invalid_io("VMess AES body authentication failed"))?,
        Security::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&chacha_key(key))
            .map_err(|_| invalid_io("invalid VMess ChaCha key"))?
            .decrypt(
                chacha20poly1305::Nonce::from_slice(&nonce),
                encrypted.as_ref(),
            )
            .map_err(|_| invalid_io("VMess ChaCha body authentication failed"))?,
    };
    Ok(Some(payload))
}

async fn write_body_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    key: &[u8; 16],
    iv: &[u8; 16],
    security: Security,
    count: u16,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > body_payload_size(security) {
        return Err(invalid_io("VMess body payload is too large"));
    }
    let nonce = body_nonce(iv, count);
    let encrypted = match security {
        Security::None => payload.to_vec(),
        Security::Aes128Gcm => Aes128Gcm::new_from_slice(key)
            .map_err(|_| invalid_io("invalid VMess AES key"))?
            .encrypt(Nonce::from_slice(&nonce), payload)
            .map_err(|_| invalid_io("VMess AES body encryption failed"))?,
        Security::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&chacha_key(key))
            .map_err(|_| invalid_io("invalid VMess ChaCha key"))?
            .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), payload)
            .map_err(|_| invalid_io("VMess ChaCha body encryption failed"))?,
    };
    let length = u16::try_from(encrypted.len()).map_err(|_| invalid_io("VMess frame overflow"))?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&encrypted).await
}

fn body_payload_size(security: Security) -> usize {
    MAX_CHUNK_SIZE - body_overhead(security)
}

fn body_overhead(security: Security) -> usize {
    match security {
        Security::None => 0,
        Security::Aes128Gcm | Security::Chacha20Poly1305 => 16,
    }
}

fn body_nonce(iv: &[u8; 16], count: u16) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..2].copy_from_slice(&count.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    let first = md5_digest(key);
    let second = md5_digest(&first);
    let mut output = [0u8; 32];
    output[..16].copy_from_slice(&first);
    output[16..].copy_from_slice(&second);
    output
}

fn seal_header(key: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.len() > u16::MAX as usize {
        return Err(Error::invalid("VMess request header is too large"));
    }
    let auth_id = create_auth_id(key)?;
    let nonce: [u8; 8] = rand::random();
    let mut output = Vec::with_capacity(16 + 18 + 8 + plaintext.len() + 16);
    output.extend_from_slice(&auth_id);
    let mut length = [0u8; 2];
    length.copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
    let length_key = kdf16(key, &[VMESS_HEADER_PAYLOAD_LENGTH_KEY, &auth_id, &nonce]);
    let length_iv = kdf(key, &[VMESS_HEADER_PAYLOAD_LENGTH_IV, &auth_id, &nonce]);
    output.extend_from_slice(&aead_seal(
        &length_key,
        &length_iv[..12],
        &length,
        &auth_id,
    )?);
    output.extend_from_slice(&nonce);
    let payload_key = kdf16(key, &[VMESS_HEADER_PAYLOAD_KEY, &auth_id, &nonce]);
    let payload_iv = kdf(key, &[VMESS_HEADER_PAYLOAD_IV, &auth_id, &nonce]);
    output.extend_from_slice(&aead_seal(
        &payload_key,
        &payload_iv[..12],
        plaintext,
        &auth_id,
    )?);
    Ok(output)
}

fn open_header(key: &[u8; 16], packet: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = 0;
    let auth_id = take(packet, &mut cursor, 16)?;
    let length_packet = take(packet, &mut cursor, 18)?;
    let nonce = take(packet, &mut cursor, 8)?;
    let length_key = kdf16(key, &[VMESS_HEADER_PAYLOAD_LENGTH_KEY, auth_id, nonce]);
    let length_iv = kdf(key, &[VMESS_HEADER_PAYLOAD_LENGTH_IV, auth_id, nonce]);
    let length = aead_open(&length_key, &length_iv[..12], length_packet, auth_id)?;
    let length = u16::from_be_bytes(
        length
            .as_slice()
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Protocol, "invalid VMess header length"))?,
    ) as usize;
    if length > MAX_HEADER_SIZE {
        return Err(Error::new(
            ErrorKind::Protocol,
            "VMess request header is too large",
        ));
    }
    let payload = take(packet, &mut cursor, length + 16)?;
    if cursor != packet.len() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "VMess request has trailing bytes",
        ));
    }
    let payload_key = kdf16(key, &[VMESS_HEADER_PAYLOAD_KEY, auth_id, nonce]);
    let payload_iv = kdf(key, &[VMESS_HEADER_PAYLOAD_IV, auth_id, nonce]);
    aead_open(&payload_key, &payload_iv[..12], payload, auth_id)
}

fn create_auth_id(key: &[u8; 16]) -> Result<[u8; 16]> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new(ErrorKind::Protocol, "system clock is before Unix epoch"))?
        .as_secs();
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&timestamp.to_be_bytes());
    let random: [u8; 4] = rand::random();
    plain[8..12].copy_from_slice(&random);
    let mut crc = Crc32::new();
    crc.update(&plain[..12]);
    plain[12..].copy_from_slice(&crc.finalize().to_be_bytes());
    let auth_key = kdf16(key, &[AUTH_ID_ENCRYPTION_KEY]);
    let cipher = Aes128::new_from_slice(&auth_key)
        .map_err(|_| Error::new(ErrorKind::Protocol, "invalid VMess auth key"))?;
    let mut block = GenericArray::clone_from_slice(&plain);
    cipher.encrypt_block(&mut block);
    Ok(block.into())
}

fn kdf16(key: &[u8; 16], path: &[&[u8]]) -> [u8; 16] {
    kdf(key, path)[..16].try_into().unwrap()
}

fn kdf(key: &[u8; 16], path: &[&[u8]]) -> [u8; 32] {
    nested_hmac(path, key)
}

fn nested_hmac(path: &[&[u8]], data: &[u8]) -> [u8; 32] {
    if path.is_empty() {
        return hmac_sha256(VMESS_AEAD_KDF, data);
    }
    let parent = |input: &[u8]| nested_hmac(&path[..path.len() - 1], input);
    hmac_over_hash(parent, path[path.len() - 1], data)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 64];
    if key.len() > padded.len() {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0u8; 64];
    let mut outer = [0u8; 64];
    for (index, byte) in padded.iter().enumerate() {
        inner[index] = *byte ^ 0x36;
        outer[index] = *byte ^ 0x5c;
    }
    let mut inner_input = Vec::with_capacity(64 + data.len());
    inner_input.extend_from_slice(&inner);
    inner_input.extend_from_slice(data);
    let inner_hash = Sha256::digest(&inner_input);
    let mut outer_input = Vec::with_capacity(64 + inner_hash.len());
    outer_input.extend_from_slice(&outer);
    outer_input.extend_from_slice(&inner_hash);
    Sha256::digest(&outer_input).into()
}

fn md5_digest(data: &[u8]) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(data);
    digest.finalize().into()
}

fn hmac_over_hash<F>(parent: F, key: &[u8], data: &[u8]) -> [u8; 32]
where
    F: Fn(&[u8]) -> [u8; 32],
{
    let mut padded = [0u8; 64];
    if key.len() > padded.len() {
        padded[..32].copy_from_slice(&parent(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    for byte in padded {
        inner.push(byte ^ 0x36);
    }
    inner.extend_from_slice(data);
    let inner = parent(&inner);
    let mut outer = Vec::with_capacity(64 + inner.len());
    for byte in padded {
        outer.push(byte ^ 0x5c);
    }
    outer.extend_from_slice(&inner);
    parent(&outer)
}

fn aead_seal(key: &[u8; 16], nonce: &[u8], data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(key)
        .map_err(|_| Error::new(ErrorKind::Protocol, "invalid VMess AEAD key"))?
        .encrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload { msg: data, aad },
        )
        .map_err(|_| Error::new(ErrorKind::Protocol, "VMess AEAD encryption failed"))
}

fn aead_open(key: &[u8; 16], nonce: &[u8], data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(key)
        .map_err(|_| Error::new(ErrorKind::Protocol, "invalid VMess AEAD key"))?
        .decrypt(
            Nonce::from_slice(nonce),
            aes_gcm::aead::Payload { msg: data, aad },
        )
        .map_err(|_| Error::new(ErrorKind::Protocol, "VMess AEAD authentication failed"))
}

fn aead_open_io(key: &[u8; 16], nonce: &[u8], data: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    aead_open(key, nonce, data, aad).map_err(|error| invalid_io(error.to_string()))
}

fn fnv1a(data: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for byte in data {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn encode_address(endpoint: &Endpoint, output: &mut Vec<u8>) -> Result<()> {
    match endpoint {
        Endpoint::Ip { addr, .. } if addr.ip().is_ipv4() => {
            output.push(1);
            output.extend_from_slice(
                &addr
                    .ip()
                    .to_string()
                    .parse::<std::net::Ipv4Addr>()
                    .unwrap()
                    .octets(),
            );
        }
        Endpoint::Ip { addr, .. } => {
            output.push(3);
            output.extend_from_slice(
                &addr
                    .ip()
                    .to_string()
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
            );
        }
        Endpoint::Domain { host, .. } => {
            if host.as_str().len() > 255 {
                return Err(Error::invalid("VMess domain is too long"));
            }
            output.push(2);
            output.push(host.as_str().len() as u8);
            output.extend_from_slice(host.as_str().as_bytes());
        }
    }
    Ok(())
}

fn decode_address(packet: &[u8], cursor: &mut usize, command: u8, port: u16) -> Result<Endpoint> {
    let network = match command {
        CMD_TCP => Network::Tcp,
        CMD_UDP => Network::Udp,
        _ => return Err(Error::new(ErrorKind::Protocol, "unknown VMess command")),
    };
    match take(packet, cursor, 1)?[0] {
        1 => Ok(Endpoint::ip(
            network,
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                    <[u8; 4]>::try_from(take(packet, cursor, 4)?).unwrap(),
                )),
                port,
            ),
        )),
        2 => {
            let length = usize::from(take(packet, cursor, 1)?[0]);
            let host = std::str::from_utf8(take(packet, cursor, length)?)
                .map_err(|_| Error::new(ErrorKind::Protocol, "VMess domain is not UTF-8"))?;
            Ok(Endpoint::domain(
                network,
                yuhaiin_core::DomainName::new(host)?,
                port,
            ))
        }
        3 => Ok(Endpoint::ip(
            network,
            std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(take(packet, cursor, 16)?).unwrap(),
                )),
                port,
            ),
        )),
        _ => Err(Error::new(
            ErrorKind::Protocol,
            "unknown VMess address type",
        )),
    }
}

fn take<'a>(packet: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "VMess length overflow"))?;
    if end > packet.len() {
        return Err(Error::new(ErrorKind::Protocol, "VMess packet is truncated"));
    }
    let value = &packet[*cursor..end];
    *cursor = end;
    Ok(value)
}

fn invalid_io(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn io_error(error: io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use yuhaiin_core::{DomainName, Endpoint};

    const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";

    #[test]
    fn modern_request_round_trips_all_address_families() {
        let uuid = crate::vless::parse_uuid(UUID).unwrap();
        for destination in [
            Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443),
            Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap()),
            Endpoint::ip(Network::Tcp, "[2001:db8::1]:443".parse().unwrap()),
        ] {
            let (encoded, expected) =
                encode_request(&uuid, Security::Aes128Gcm, CMD_TCP, &destination).unwrap();
            let decoded = decode_request(&encoded, &uuid).unwrap();
            assert_eq!(decoded.destination, expected.destination);
            assert_eq!(decoded.body_iv, expected.body_iv);
            assert_eq!(decoded.body_key, expected.body_key);
            assert_eq!(decoded.response_v, expected.response_v);
        }
    }

    #[test]
    fn nested_kdf_is_deterministic_and_chacha_key_matches_go_shape() {
        let uuid = crate::vless::parse_uuid(UUID).unwrap();
        assert_eq!(command_key(&uuid).len(), 16);
        assert_eq!(
            kdf(&command_key(&uuid), &[VMESS_HEADER_PAYLOAD_KEY]).len(),
            32
        );
        assert_eq!(chacha_key(&command_key(&uuid)).len(), 32);
    }

    #[test]
    fn malformed_headers_fail_closed() {
        let uuid = crate::vless::parse_uuid(UUID).unwrap();
        let destination =
            Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
        let (mut encoded, _) =
            encode_request(&uuid, Security::Aes128Gcm, CMD_TCP, &destination).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        assert!(decode_request(&encoded, &uuid).is_err());
        assert!(decode_request(&encoded[..10], &uuid).is_err());
    }
}
