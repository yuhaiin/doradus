//! Go-compatible `aead` transport used by contract inbounds and nodes.
//!
//! This is intentionally separate from Shadowsocks AEAD.  Go's `aead`
//! transport performs a P-256/Ed25519 authenticated handshake and then wraps
//! the byte stream in ChaCha20-Poly1305 records; it is not the Shadowsocks
//! salt/HKDF framing implemented in [`crate::shadowsocks`].

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, XChaCha20Poly1305, XNonce};
use doradus_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use doradus_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2_10::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;

const HASH_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;
const PUBLIC_KEY_SIZE: usize = 65;
const TIME_SIZE: usize = 8;
const HEADER_SIZE: usize = HASH_SIZE + TIME_SIZE + SIGNATURE_SIZE + PUBLIC_KEY_SIZE;
const MAX_PAYLOAD_SIZE: usize = u16::MAX as usize;
const FRAME_TAG_SIZE: usize = 16;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Cipher selected by the Go `aead` transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoMethod {
    Chacha20Poly1305,
    XChacha20Poly1305,
}

impl CryptoMethod {
    pub fn parse(value: &str) -> Self {
        match value.trim() {
            "AeadCryptoMethod_XChacha20Poly1305" | "XChacha20Poly1305" | "xchacha20poly1305" => {
                Self::XChacha20Poly1305
            }
            _ => Self::Chacha20Poly1305,
        }
    }

    fn name(self) -> &'static [u8] {
        match self {
            Self::Chacha20Poly1305 => b"chacha20poly1305-key",
            Self::XChacha20Poly1305 => b"xchacha20poly1305-key",
        }
    }

    fn nonce_size(self) -> usize {
        match self {
            Self::Chacha20Poly1305 => 12,
            Self::XChacha20Poly1305 => 24,
        }
    }
}

/// SHA-256 password salt used by the Go implementation.
pub fn password_salt(password: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update(b"+s@1t");
    hasher.finalize().into()
}

/// Perform the Go-compatible client handshake and return the protected stream.
pub async fn client(
    stream: BoxAsyncStream,
    password: &[u8],
    method: CryptoMethod,
) -> Result<BoxAsyncStream> {
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake::handshake_client(stream, password, method),
    )
    .await
    .map_err(|_| Error::new(ErrorKind::Timeout, "AEAD handshake timed out"))?
}

/// Perform the Go-compatible server handshake and return the protected stream.
pub async fn server(
    stream: BoxAsyncStream,
    password: &[u8],
    method: CryptoMethod,
) -> Result<BoxAsyncStream> {
    server_with_passwords(stream, &[password.to_vec()], method).await
}

/// Perform the server handshake against a bounded set of central-user
/// passwords. The candidate is selected from the signed/timestamped client
/// header before any protected stream bytes are accepted.
pub async fn server_with_passwords(
    stream: BoxAsyncStream,
    passwords: &[Vec<u8>],
    method: CryptoMethod,
) -> Result<BoxAsyncStream> {
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake::handshake_server(stream, passwords, method),
    )
    .await
    .map_err(|_| Error::new(ErrorKind::Timeout, "AEAD handshake timed out"))?
}

/// AEAD transport around an already constructed outbound proxy.
///
/// The stream path performs the Go handshake lazily on `connect`. The UDP
/// path uses the Go packet format (`nonce || ciphertext`) and, when a fixed
/// server address is supplied, bypasses the stream-only parent proxy just as
/// Go's fixed `PacketConn` does.
pub struct AeadProxy {
    upstream: Arc<dyn AsyncProxy>,
    password: Vec<u8>,
    method: CryptoMethod,
    udp_server: Option<std::net::SocketAddr>,
}

impl AeadProxy {
    pub fn new(
        upstream: Arc<dyn AsyncProxy>,
        password: impl AsRef<[u8]>,
        method: CryptoMethod,
        udp_server: Option<std::net::SocketAddr>,
    ) -> Self {
        Self {
            upstream,
            password: password.as_ref().to_vec(),
            method,
            udp_server,
        }
    }
}

impl AsyncProxy for AeadProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let stream = self.upstream.connect(context).await?;
            client(stream, &self.password, self.method).await
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            if let Some(server) = self.udp_server {
                let bind_address: std::net::SocketAddr = match server {
                    std::net::SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                    std::net::SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
                };
                let socket = tokio::net::UdpSocket::bind(bind_address)
                    .await
                    .map_err(|error| {
                        Error::new(ErrorKind::Io, format!("bind AEAD UDP client: {error}"))
                    })?;
                return Ok(Box::new(AeadUdpDatagram {
                    socket,
                    server,
                    password: self.password.clone(),
                    method: self.method,
                    receive_buffer: AsyncMutex::new(Vec::new()),
                }) as Box<dyn AsyncDatagram>);
            }
            let upstream = self.upstream.open_datagram(context).await?;
            Ok(Box::new(AeadDatagram {
                upstream,
                password: self.password.clone(),
                method: self.method,
                receive_buffer: AsyncMutex::new(Vec::new()),
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

#[path = "aead/handshake.rs"]
mod handshake;
#[path = "aead/stream.rs"]
mod stream;
/// Encrypt one Go AEAD UDP packet. `password` is the configured plaintext
/// password; the compatibility password salt is derived internally.
#[path = "aead/udp.rs"]
mod udp;

use udp::{AeadDatagram, AeadUdpDatagram};
pub use udp::{AeadUdpServer, decrypt_packet, encrypt_packet};

fn fill_random(bytes: &mut [u8]) {
    rand::RngExt::fill(&mut rand::rng(), bytes);
}

#[cfg(test)]
#[path = "aead_tests.rs"]
mod tests;
