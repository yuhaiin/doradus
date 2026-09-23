//! ShadowsocksR stream ciphers and AES mode implementation.

use std::io;

use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit, generic_array::GenericArray};
use aes::{Aes128, Aes192, Aes256};
use chacha20::{ChaCha20, ChaCha20Legacy};

use super::{CipherMethod, invalid_data};

#[allow(clippy::large_enum_variant)]
pub(super) enum StreamCipher {
    None,
    Aes(AesStream),
    Chacha20(ChaCha20),
    Chacha20Legacy(ChaCha20Legacy),
}

impl StreamCipher {
    pub(super) fn new(
        method: CipherMethod,
        key: &[u8],
        iv: &[u8],
        decrypt: bool,
    ) -> io::Result<Self> {
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

    pub(super) fn apply(&mut self, data: &mut [u8]) -> io::Result<()> {
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
pub(super) struct AesStream {
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
