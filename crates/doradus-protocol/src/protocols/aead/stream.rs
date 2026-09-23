//! Authenticated record framing for established AEAD streams.

use super::*;

#[derive(Clone)]
pub(super) struct DirectionCipher {
    pub(super) method: CryptoMethod,
    pub(super) key: Vec<u8>,
    pub(super) nonce: Vec<u8>,
}

impl DirectionCipher {
    fn seal(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let result = match self.method {
            CryptoMethod::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| invalid_cipher())?
                .encrypt(Nonce::from_slice(&self.nonce), plaintext),
            CryptoMethod::XChacha20Poly1305 => XChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| invalid_cipher())?
                .encrypt(XNonce::from_slice(&self.nonce), plaintext),
        }
        .map_err(|_| invalid_cipher())?;
        increment_nonce(&mut self.nonce);
        Ok(result)
    }

    fn open(&mut self, ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let result = match self.method {
            CryptoMethod::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| invalid_cipher())?
                .decrypt(Nonce::from_slice(&self.nonce), ciphertext),
            CryptoMethod::XChacha20Poly1305 => XChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| invalid_cipher())?
                .decrypt(XNonce::from_slice(&self.nonce), ciphertext),
        }
        .map_err(|_| invalid_cipher())?;
        increment_nonce(&mut self.nonce);
        Ok(result)
    }
}

fn increment_nonce(nonce: &mut [u8]) {
    for byte in nonce {
        let (value, carry) = byte.overflowing_add(1);
        *byte = value;
        if !carry {
            break;
        }
    }
}

struct PendingWrite {
    encrypted: Vec<u8>,
    offset: usize,
    accepted: usize,
}

pub(super) struct AeadStream {
    inner: BoxAsyncStream,
    read_cipher: DirectionCipher,
    write_cipher: DirectionCipher,
    pending_write: Option<PendingWrite>,
    read_length: Vec<u8>,
    read_length_filled: usize,
    read_payload: Vec<u8>,
    read_payload_filled: usize,
    plaintext: Vec<u8>,
    plaintext_offset: usize,
}

impl AeadStream {
    pub(super) fn new(
        inner: BoxAsyncStream,
        read_cipher: DirectionCipher,
        write_cipher: DirectionCipher,
    ) -> Self {
        Self {
            inner,
            read_cipher,
            write_cipher,
            pending_write: None,
            read_length: vec![0; 2 + FRAME_TAG_SIZE],
            read_length_filled: 0,
            read_payload: Vec::new(),
            read_payload_filled: 0,
            plaintext: Vec::new(),
            plaintext_offset: 0,
        }
    }

    fn encrypt_records(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        for chunk in plaintext.chunks(MAX_PAYLOAD_SIZE) {
            let length = u16::try_from(chunk.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "AEAD payload is too large")
            })?;
            output.extend_from_slice(&self.write_cipher.seal(&length.to_be_bytes())?);
            output.extend_from_slice(&self.write_cipher.seal(chunk)?);
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
                        "AEAD parent wrote zero bytes",
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
                            "truncated AEAD frame",
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

impl AsyncRead for AeadStream {
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

            if self.read_length_filled < self.read_length.len() {
                let mut buffer = std::mem::take(&mut self.read_length);
                let mut filled = self.read_length_filled;
                let result = self.poll_fill(cx, &mut buffer, &mut filled, true);
                self.read_length = buffer;
                self.read_length_filled = filled;
                match result {
                    Poll::Ready(Ok(true)) => {
                        let encrypted = self.read_length.clone();
                        let length = match self.read_cipher.open(&encrypted) {
                            Ok(value) if value.len() == 2 => {
                                usize::from(u16::from_be_bytes([value[0], value[1]]))
                            }
                            Ok(_) => {
                                return Poll::Ready(Err(invalid_frame(
                                    "invalid AEAD length frame",
                                )));
                            }
                            Err(error) => return Poll::Ready(Err(error)),
                        };
                        self.read_payload = vec![0u8; length + FRAME_TAG_SIZE];
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
                    let encrypted = self.read_payload.clone();
                    self.plaintext = match self.read_cipher.open(&encrypted) {
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

impl AsyncWrite for AeadStream {
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

fn invalid_cipher() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "AEAD cipher initialization failed",
    )
}

fn invalid_frame(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
