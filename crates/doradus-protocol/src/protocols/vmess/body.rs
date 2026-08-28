//! VMess response headers and encrypted body frames.

use std::io;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::codec::Security;
use super::codec::{
    AEAD_RESP_HEADER_LEN_IV, AEAD_RESP_HEADER_LEN_KEY, AEAD_RESP_HEADER_PAYLOAD_IV,
    AEAD_RESP_HEADER_PAYLOAD_KEY, MAX_CHUNK_SIZE, MAX_HEADER_SIZE, aead_open_io, aes_cfb_xor,
    invalid_io, kdf, kdf16, md5_digest,
};

pub(crate) async fn read_response_header<R: AsyncRead + Unpin>(
    reader: &mut R,
    body_key: &[u8; 16],
    body_iv: &[u8; 16],
    response_v: u8,
    legacy: bool,
) -> io::Result<()> {
    if legacy {
        let mut encrypted = [0u8; 4];
        reader.read_exact(&mut encrypted).await?;
        let decrypted = aes_cfb_xor(
            &md5_digest(body_key),
            &md5_digest(body_iv),
            &encrypted,
            true,
        )
        .map_err(|error| invalid_io(error.to_string()))?;
        if decrypted.len() < 4 || decrypted[0] != response_v || decrypted[2] != 0 {
            return Err(invalid_io("invalid legacy VMess response header"));
        }
        return Ok(());
    }
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

pub async fn read_body_frame<R: AsyncRead + Unpin>(
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

pub async fn write_body_frame<W: AsyncWrite + Unpin>(
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

pub(crate) fn body_payload_size(security: Security) -> usize {
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

pub(crate) fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    let first = md5_digest(key);
    let second = md5_digest(&first);
    let mut output = [0u8; 32];
    output[..16].copy_from_slice(&first);
    output[16..].copy_from_slice(&second);
    output
}

pub(crate) fn response_key_for(key: &[u8; 16], legacy: bool) -> [u8; 16] {
    if legacy {
        md5_digest(key)
    } else {
        Sha256::digest(key)[..16].try_into().unwrap()
    }
}
