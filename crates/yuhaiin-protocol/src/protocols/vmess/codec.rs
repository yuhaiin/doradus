//! VMess request/response headers and cryptographic wire codec.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit, generic_array::GenericArray};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Nonce};
use crc32fast::Hasher as Crc32;
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use yuhaiin_core::{Endpoint, Error, ErrorKind, Network, Result};

pub(crate) const VERSION: u8 = 1;
pub(crate) const OPT_CHUNK_STREAM: u8 = 1;
pub(crate) const CMD_TCP: u8 = 1;
pub(crate) const CMD_UDP: u8 = 2;
pub(crate) const MAX_CHUNK_SIZE: usize = 8192;
pub(crate) const MAX_HEADER_SIZE: usize = 8192;
pub(crate) const AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
pub(crate) const AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
pub(crate) const AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
pub(crate) const AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
pub(crate) const AEAD_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
pub(crate) const VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
pub(crate) const VMESS_HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
pub(crate) const VMESS_HEADER_PAYLOAD_IV: &[u8] = b"VMess Header AEAD Nonce";
pub(crate) const VMESS_HEADER_PAYLOAD_LENGTH_KEY: &[u8] = b"VMess Header AEAD Key_Length";
pub(crate) const VMESS_HEADER_PAYLOAD_LENGTH_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
pub(crate) const UUID_SUFFIX: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
pub(crate) const ALTER_ID_SUFFIX: &[u8] = b"16167dc8-16b6-4e6d-b8bb-65dd68113a81";
pub(crate) const ALTER_ID_COLLISION_SUFFIX: &[u8] = b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2";
pub(crate) const MAX_ALTER_ID: u32 = 4096;

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
    /// True when the legacy timestamp-HMAC/CFB header format is in use.
    pub legacy: bool,
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
    encode_request_inner(uuid, uuid, security, command, destination, false)
}

/// Build a legacy VMess request for one randomly selectable alter-id user.
///
/// The command key is derived from the primary UUID, just like the Go client;
/// the selected alter-id UUID is used only for the timestamp HMAC prefix.
pub fn encode_legacy_request(
    primary_uuid: &[u8; 16],
    user_uuid: &[u8; 16],
    security: Security,
    command: u8,
    destination: &Endpoint,
) -> Result<(Vec<u8>, Request)> {
    encode_request_inner(
        primary_uuid,
        user_uuid,
        security,
        command,
        destination,
        true,
    )
}

fn encode_request_inner(
    primary_uuid: &[u8; 16],
    user_uuid: &[u8; 16],
    security: Security,
    command: u8,
    destination: &Endpoint,
    legacy: bool,
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

    let header = if legacy {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::new(ErrorKind::Protocol, "system clock is before Unix epoch"))?
            .as_secs();
        let timestamp_bytes = timestamp.to_be_bytes();
        let auth_id = legacy_auth_id(user_uuid, &timestamp_bytes)?;
        let encrypted = aes_cfb_xor(
            &command_key(primary_uuid),
            &legacy_timestamp_iv(timestamp),
            &plaintext,
            false,
        )?;
        let mut header = Vec::with_capacity(auth_id.len() + encrypted.len());
        header.extend_from_slice(&auth_id);
        header.extend_from_slice(&encrypted);
        header
    } else {
        seal_header(&command_key(primary_uuid), &plaintext)?
    };
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
            legacy,
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
        legacy: false,
    })
}

/// Read and decode one modern VMess request header from a stream.
pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    uuid: &[u8; 16],
) -> Result<Request> {
    let mut prefix = [0u8; 42];
    reader.read_exact(&mut prefix).await.map_err(io_error)?;
    let auth_id: [u8; 16] = prefix[..16]
        .try_into()
        .map_err(|_| Error::new(ErrorKind::Protocol, "invalid VMess auth id"))?;
    let nonce: [u8; 8] = prefix[34..42]
        .try_into()
        .map_err(|_| Error::new(ErrorKind::Protocol, "invalid VMess header nonce"))?;
    let key = command_key(uuid);
    let length_key = kdf16(&key, &[VMESS_HEADER_PAYLOAD_LENGTH_KEY, &auth_id, &nonce]);
    let length_iv = kdf(&key, &[VMESS_HEADER_PAYLOAD_LENGTH_IV, &auth_id, &nonce]);
    let length = aead_open(&length_key, &length_iv[..12], &prefix[16..34], &auth_id)?;
    let payload_length =
        usize::from(u16::from_be_bytes(length.as_slice().try_into().map_err(
            |_| Error::new(ErrorKind::Protocol, "invalid VMess header length"),
        )?));
    if payload_length > MAX_HEADER_SIZE {
        return Err(Error::new(
            ErrorKind::Protocol,
            "VMess request header is too large",
        ));
    }
    let mut payload = vec![0u8; payload_length + 16];
    reader.read_exact(&mut payload).await.map_err(io_error)?;
    let mut packet = prefix.to_vec();
    packet.extend_from_slice(&payload);
    decode_request(&packet, uuid)
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

/// Build the four-byte legacy VMess response header using AES-128-CFB.
pub fn encode_legacy_response_header(
    response_v: u8,
    body_key: &[u8; 16],
    body_iv: &[u8; 16],
) -> Result<Vec<u8>> {
    aes_cfb_xor(
        &md5_digest(body_key),
        &md5_digest(body_iv),
        &[response_v, 0, 0, 0],
        false,
    )
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

pub(crate) fn alter_id_users(primary: [u8; 16], alter_id: u32) -> Result<Vec<[u8; 16]>> {
    if alter_id > MAX_ALTER_ID {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("VMess alter_id exceeds the safety limit of {MAX_ALTER_ID}"),
        ));
    }
    let capacity = usize::try_from(alter_id)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "VMess alter_id is too large"))?;
    let mut users = Vec::with_capacity(capacity);
    users.push(primary);
    let mut previous = primary;
    for _ in 0..alter_id {
        let next = next_alter_id_uuid(&previous);
        users.push(next);
        previous = next;
    }
    Ok(users)
}

fn next_alter_id_uuid(previous: &[u8; 16]) -> [u8; 16] {
    let mut digest = Md5::new();
    digest.update(previous);
    digest.update(ALTER_ID_SUFFIX);
    let mut next: [u8; 16] = digest.clone().finalize().into();
    if &next == previous {
        digest.update(ALTER_ID_COLLISION_SUFFIX);
        next = digest.finalize().into();
    }
    next
}

pub(crate) fn legacy_auth_id(user_uuid: &[u8; 16], timestamp: &[u8; 8]) -> Result<[u8; 16]> {
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(user_uuid)
        .map_err(|_| Error::new(ErrorKind::Protocol, "invalid legacy VMess user UUID"))?;
    mac.update(timestamp);
    Ok(mac.finalize().into_bytes().into())
}

pub(crate) fn legacy_timestamp_iv(timestamp: u64) -> [u8; 16] {
    let timestamp = timestamp.to_be_bytes();
    let mut input = [0u8; 32];
    input[..8].copy_from_slice(&timestamp);
    input[8..16].copy_from_slice(&timestamp);
    input[16..24].copy_from_slice(&timestamp);
    input[24..].copy_from_slice(&timestamp);
    md5_digest(&input)
}

/// AES-128-CFB with a full-block feedback register.
///
/// VMess legacy headers are short, so keeping this small implementation here
/// avoids pulling a mode crate into the protocol surface. CFB encryption and
/// decryption both use AES encryption; only the feedback source differs.
pub(crate) fn aes_cfb_xor(
    key: &[u8; 16],
    iv: &[u8; 16],
    input: &[u8],
    decrypt: bool,
) -> Result<Vec<u8>> {
    let cipher = Aes128::new_from_slice(key)
        .map_err(|_| Error::new(ErrorKind::Protocol, "invalid legacy VMess AES key"))?;
    let mut feedback = *iv;
    let mut output = Vec::with_capacity(input.len());
    for chunk in input.chunks(16) {
        let mut stream = GenericArray::clone_from_slice(&feedback);
        cipher.encrypt_block(&mut stream);
        let mut result = vec![0u8; chunk.len()];
        for (index, byte) in chunk.iter().enumerate() {
            result[index] = *byte ^ stream[index];
        }
        if decrypt {
            feedback[..chunk.len()].copy_from_slice(chunk);
        } else {
            feedback[..chunk.len()].copy_from_slice(&result);
        }
        output.extend_from_slice(&result);
    }
    Ok(output)
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

pub(crate) fn kdf16(key: &[u8; 16], path: &[&[u8]]) -> [u8; 16] {
    kdf(key, path)[..16].try_into().unwrap()
}

pub(crate) fn kdf(key: &[u8; 16], path: &[&[u8]]) -> [u8; 32] {
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

pub(crate) fn md5_digest(data: &[u8]) -> [u8; 16] {
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

pub(crate) fn aead_open_io(
    key: &[u8; 16],
    nonce: &[u8],
    data: &[u8],
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    aead_open(key, nonce, data, aad).map_err(|error| invalid_io(error.to_string()))
}

pub(crate) fn fnv1a(data: &[u8]) -> u32 {
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

pub(crate) fn invalid_io(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub(crate) fn io_error(error: io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}
