//! ShadowsocksR authentication and frame protocol state.

use std::io;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit, generic_array::GenericArray};
use base64::Engine;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};

#[cfg(test)]
use super::MAX_PACKET_SIZE;
use super::{
    MAX_FRAME_SIZE, ProtocolKind, fill_random, invalid_data, md5_password_kdf, unix_seconds,
};

type HmacMd5 = Hmac<Md5>;

#[derive(Debug, Clone)]
pub(super) struct ProtocolState {
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
    pub(super) fn new(kind: ProtocolKind, cipher_key: &[u8], parameter: &str) -> Self {
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

    pub(super) fn set_stream_iv(&mut self, iv: &[u8]) {
        self.auth_key.clear();
        self.auth_key.extend_from_slice(iv);
        self.auth_key.extend_from_slice(&self.cipher_key);
    }

    #[cfg(test)]
    pub(super) fn mark_stream_header_sent(&mut self) {
        self.sent_header = true;
    }

    pub(super) fn uid(&self) -> &[u8; 4] {
        &self.uid
    }

    pub(super) fn encode_stream(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
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

    pub(super) fn decode_stream(
        &mut self,
        pending: &mut Vec<u8>,
        output: &mut Vec<u8>,
    ) -> io::Result<()> {
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

    pub(super) fn encode_packet(&self, data: &[u8]) -> io::Result<Vec<u8>> {
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

    pub(super) fn decode_packet(&self, data: &[u8]) -> io::Result<Vec<u8>> {
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

#[cfg(test)]
pub(super) fn decode_auth_header(
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
