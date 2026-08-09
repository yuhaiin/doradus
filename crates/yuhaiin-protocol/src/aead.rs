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
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2_10::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};

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
        handshake_client(stream, password, method),
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
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake_server(stream, password, method),
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
                }) as Box<dyn AsyncDatagram>);
            }
            let upstream = self.upstream.open_datagram(context).await?;
            Ok(Box::new(AeadDatagram {
                upstream,
                password: self.password.clone(),
                method: self.method,
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

/// Encrypt one Go AEAD UDP packet. `password` is the configured plaintext
/// password; the compatibility password salt is derived internally.
pub fn encrypt_packet(payload: &[u8], password: &[u8], method: CryptoMethod) -> Result<Vec<u8>> {
    let key = packet_key(password);
    let mut nonce = vec![0u8; method.nonce_size()];
    fill_random(&mut nonce);
    let ciphertext = match method {
        CryptoMethod::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| Error::new(ErrorKind::Protocol, "invalid AEAD packet key"))?
            .encrypt(Nonce::from_slice(&nonce), payload),
        CryptoMethod::XChacha20Poly1305 => XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| Error::new(ErrorKind::Protocol, "invalid AEAD packet key"))?
            .encrypt(XNonce::from_slice(&nonce), payload),
    }
    .map_err(|_| Error::new(ErrorKind::Protocol, "AEAD UDP encryption failed"))?;
    nonce.extend_from_slice(&ciphertext);
    Ok(nonce)
}

/// Decrypt one Go AEAD UDP packet (`nonce || ciphertext`).
pub fn decrypt_packet(packet: &[u8], password: &[u8], method: CryptoMethod) -> Result<Vec<u8>> {
    let nonce_size = method.nonce_size();
    if packet.len() < nonce_size + FRAME_TAG_SIZE {
        return Err(Error::new(
            ErrorKind::Protocol,
            "AEAD UDP packet is truncated",
        ));
    }
    let key = packet_key(password);
    let nonce = &packet[..nonce_size];
    let ciphertext = &packet[nonce_size..];
    match method {
        CryptoMethod::Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| Error::new(ErrorKind::Protocol, "invalid AEAD packet key"))?
            .decrypt(Nonce::from_slice(nonce), ciphertext),
        CryptoMethod::XChacha20Poly1305 => XChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| Error::new(ErrorKind::Protocol, "invalid AEAD packet key"))?
            .decrypt(XNonce::from_slice(nonce), ciphertext),
    }
    .map_err(|_| Error::new(ErrorKind::Protocol, "AEAD UDP authentication failed"))
}

fn packet_key(password: &[u8]) -> [u8; HASH_SIZE] {
    let password_hash = password_salt(password);
    let mut hasher = Sha256::new();
    hasher.update(password_hash);
    hasher.update(b"yuubinsya-salt-");
    hasher.finalize().into()
}

struct AeadUdpDatagram {
    socket: tokio::net::UdpSocket,
    server: std::net::SocketAddr,
    password: Vec<u8>,
    method: CryptoMethod,
}

/// Server-side authenticated UDP socket for an outer Go AEAD transport.
/// Unlike [`AeadUdpDatagram`], replies are sent to the peer returned by the
/// receive operation; this is the boundary needed by inbound protocols such as
/// Yuubinsya that carry their own target address inside the decrypted payload.
pub struct AeadUdpServer {
    socket: tokio::net::UdpSocket,
    password: Vec<u8>,
    method: CryptoMethod,
}

impl AeadUdpServer {
    pub fn new(
        socket: tokio::net::UdpSocket,
        password: impl AsRef<[u8]>,
        method: CryptoMethod,
    ) -> Self {
        Self {
            socket,
            password: password.as_ref().to_vec(),
            method,
        }
    }
}

impl AsyncDatagram for AeadUdpServer {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let address = target.addr().ok_or_else(|| {
                Error::new(
                    ErrorKind::Unsupported,
                    "AEAD UDP peer must be an IP endpoint",
                )
            })?;
            let packet = encrypt_packet(payload, &self.password, self.method)?;
            self.socket
                .send_to(&packet, address)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, format!("AEAD UDP send: {error}")))?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let mut packet = vec![0u8; 65_535];
            let (length, peer) =
                self.socket.recv_from(&mut packet).await.map_err(|error| {
                    Error::new(ErrorKind::Io, format!("AEAD UDP receive: {error}"))
                })?;
            let plaintext = decrypt_packet(&packet[..length], &self.password, self.method)?;
            if buffer.len() < plaintext.len() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "AEAD UDP payload exceeds receive buffer",
                ));
            }
            buffer[..plaintext.len()].copy_from_slice(&plaintext);
            Ok((plaintext.len(), Endpoint::ip(Network::Udp, peer)))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.socket
            .local_addr()
            .map(|address| Endpoint::ip(Network::Udp, address))
            .map_err(|error| Error::new(ErrorKind::Io, format!("AEAD UDP local address: {error}")))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl AsyncDatagram for AeadUdpDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], _target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let packet = encrypt_packet(payload, &self.password, self.method)?;
            self.socket
                .send_to(&packet, self.server)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, format!("AEAD UDP send: {error}")))?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let mut packet = vec![0u8; 65_535];
            let (length, peer) =
                self.socket.recv_from(&mut packet).await.map_err(|error| {
                    Error::new(ErrorKind::Io, format!("AEAD UDP receive: {error}"))
                })?;
            let plaintext = decrypt_packet(&packet[..length], &self.password, self.method)?;
            if buffer.len() < plaintext.len() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "AEAD UDP payload exceeds receive buffer",
                ));
            }
            buffer[..plaintext.len()].copy_from_slice(&plaintext);
            Ok((plaintext.len(), Endpoint::ip(Network::Udp, peer)))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.socket
            .local_addr()
            .map(|address| Endpoint::ip(Network::Udp, address))
            .map_err(|error| Error::new(ErrorKind::Io, format!("AEAD UDP local address: {error}")))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

struct AeadDatagram {
    upstream: Box<dyn AsyncDatagram>,
    password: Vec<u8>,
    method: CryptoMethod,
}

impl AsyncDatagram for AeadDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let packet = encrypt_packet(payload, &self.password, self.method)?;
            self.upstream.send_to(&packet, target).await?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let mut packet = vec![0u8; 65_535];
            let (length, target) = self.upstream.recv_from(&mut packet).await?;
            let plaintext = decrypt_packet(&packet[..length], &self.password, self.method)?;
            if buffer.len() < plaintext.len() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "AEAD UDP payload exceeds receive buffer",
                ));
            }
            buffer[..plaintext.len()].copy_from_slice(&plaintext);
            Ok((plaintext.len(), target))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.upstream.local_addr()
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

async fn handshake_client(
    mut stream: BoxAsyncStream,
    password: &[u8],
    method: CryptoMethod,
) -> Result<BoxAsyncStream> {
    let signing_key = signing_key(&password_salt(password))?;
    let (secret, public_key) = generate_keypair();
    let mut client_header = [0u8; HEADER_SIZE];
    fill_random(&mut client_header[SIGNATURE_SIZE..SIGNATURE_SIZE + HASH_SIZE]);
    let (client_time, encrypted_client_time) = timestamp_pair(
        password,
        &client_header[SIGNATURE_SIZE..SIGNATURE_SIZE + HASH_SIZE],
    )?;
    client_header[SIGNATURE_SIZE + HASH_SIZE..SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE]
        .copy_from_slice(&encrypted_client_time);
    client_header[SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE..].copy_from_slice(public_key.as_slice());
    sign_header(&mut client_header, &signing_key);
    stream.write_all(&client_header).await.map_err(io_error)?;

    let client_salt = client_header[SIGNATURE_SIZE..SIGNATURE_SIZE + HASH_SIZE].to_vec();
    let mut server_header = [0u8; HEADER_SIZE];
    stream
        .read_exact(&mut server_header)
        .await
        .map_err(io_error)?;
    server_header[SIGNATURE_SIZE..SIGNATURE_SIZE + HASH_SIZE].copy_from_slice(&client_salt);
    verify_header(&server_header, &signing_key)?;
    let server_public =
        PublicKey::from_sec1_bytes(&server_header[SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE..])
            .map_err(|_| Error::new(ErrorKind::Protocol, "invalid AEAD server public key"))?;
    if server_public.to_encoded_point(false).as_bytes() == public_key.as_slice() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "AEAD handshake replayed the public key",
        ));
    }
    let server_time = decrypt_timestamp(
        password,
        &client_salt,
        &server_header[SIGNATURE_SIZE + HASH_SIZE..SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE],
    )?;
    validate_timestamp(&server_time)?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), server_public.as_affine());
    let read = derive_cipher(
        method,
        shared.raw_secret_bytes().as_slice(),
        &client_salt,
        &client_time,
    )?;
    let write = derive_cipher(
        method,
        shared.raw_secret_bytes().as_slice(),
        &client_salt,
        &server_time,
    )?;
    Ok(Box::new(AeadStream::new(stream, read, write)) as BoxAsyncStream)
}

async fn handshake_server(
    mut stream: BoxAsyncStream,
    password: &[u8],
    method: CryptoMethod,
) -> Result<BoxAsyncStream> {
    let signing_key = signing_key(&password_salt(password))?;
    let mut client_header = [0u8; HEADER_SIZE];
    stream
        .read_exact(&mut client_header)
        .await
        .map_err(io_error)?;
    verify_header(&client_header, &signing_key)?;
    let client_salt = client_header[SIGNATURE_SIZE..SIGNATURE_SIZE + HASH_SIZE].to_vec();
    let client_time = decrypt_timestamp(
        password,
        &client_salt,
        &client_header[SIGNATURE_SIZE + HASH_SIZE..SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE],
    )?;
    validate_timestamp(&client_time)?;
    let client_public =
        PublicKey::from_sec1_bytes(&client_header[SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE..])
            .map_err(|_| Error::new(ErrorKind::Protocol, "invalid AEAD client public key"))?;

    let (secret, public_key) = generate_keypair();
    let (server_time, encrypted_server_time) = timestamp_pair(password, &client_salt)?;
    let mut server_header = [0u8; HEADER_SIZE];
    server_header[SIGNATURE_SIZE..SIGNATURE_SIZE + HASH_SIZE].copy_from_slice(&client_salt);
    server_header[SIGNATURE_SIZE + HASH_SIZE..SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE]
        .copy_from_slice(&encrypted_server_time);
    server_header[SIGNATURE_SIZE + HASH_SIZE + TIME_SIZE..].copy_from_slice(public_key.as_slice());
    sign_header(&mut server_header, &signing_key);
    // Go randomizes this field after signing.  The client replaces it with
    // the original client salt before signature verification.
    fill_random(&mut server_header[SIGNATURE_SIZE..SIGNATURE_SIZE + HASH_SIZE]);
    stream.write_all(&server_header).await.map_err(io_error)?;

    let shared = diffie_hellman(secret.to_nonzero_scalar(), client_public.as_affine());
    // Go's server NewConn swaps its read/write arguments: it reads with the
    // cipher derived from the server timestamp and writes with the client one.
    let read = derive_cipher(
        method,
        shared.raw_secret_bytes().as_slice(),
        &client_salt,
        &server_time,
    )?;
    let write = derive_cipher(
        method,
        shared.raw_secret_bytes().as_slice(),
        &client_salt,
        &client_time,
    )?;
    Ok(Box::new(AeadStream::new(stream, read, write)) as BoxAsyncStream)
}

fn generate_keypair() -> (SecretKey, Vec<u8>) {
    let secret = SecretKey::random(&mut OsRng);
    let public = secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    (secret, public)
}

fn signing_key(password_hash: &[u8; HASH_SIZE]) -> Result<SigningKey> {
    let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; HASH_SIZE]), password_hash);
    let mut seed = [0u8; 32];
    hkdf.expand(b"ed25519-signature", &mut seed)
        .map_err(|_| Error::new(ErrorKind::Protocol, "AEAD Ed25519 key derivation failed"))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn sign_header(header: &mut [u8; HEADER_SIZE], key: &SigningKey) {
    let signature = key.sign(&header[SIGNATURE_SIZE..]);
    header[..SIGNATURE_SIZE].copy_from_slice(&signature.to_bytes());
}

fn verify_header(header: &[u8; HEADER_SIZE], key: &SigningKey) -> Result<()> {
    let verifying: VerifyingKey = key.verifying_key();
    let signature = Signature::from_bytes(header[..SIGNATURE_SIZE].try_into().unwrap());
    verifying
        .verify(&header[SIGNATURE_SIZE..], &signature)
        .map_err(|_| Error::new(ErrorKind::Protocol, "AEAD handshake signature mismatch"))
}

fn timestamp_pair(password: &[u8], salt: &[u8]) -> Result<([u8; TIME_SIZE], [u8; TIME_SIZE])> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new(ErrorKind::Protocol, "system clock is before Unix epoch"))?
        .as_secs();
    let plain = now.to_be_bytes();
    let mut encrypted = plain;
    crypt_timestamp(password, salt, &mut encrypted)?;
    Ok((plain, encrypted))
}

fn decrypt_timestamp(password: &[u8], salt: &[u8], encrypted: &[u8]) -> Result<[u8; TIME_SIZE]> {
    if encrypted.len() != TIME_SIZE {
        return Err(Error::new(
            ErrorKind::Protocol,
            "invalid AEAD timestamp length",
        ));
    }
    let mut plain = [0u8; TIME_SIZE];
    plain.copy_from_slice(encrypted);
    crypt_timestamp(password, salt, &mut plain)?;
    Ok(plain)
}

fn crypt_timestamp(password: &[u8], salt: &[u8], data: &mut [u8; TIME_SIZE]) -> Result<()> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), password);
    let mut key_nonce = [0u8; 44];
    hkdf.expand(b"time", &mut key_nonce)
        .map_err(|_| Error::new(ErrorKind::Protocol, "AEAD timestamp key derivation failed"))?;
    let mut cipher = ChaCha20::new_from_slices(&key_nonce[..32], &key_nonce[32..])
        .map_err(|_| Error::new(ErrorKind::Protocol, "invalid AEAD timestamp cipher"))?;
    cipher.apply_keystream(data);
    Ok(())
}

fn validate_timestamp(timestamp: &[u8; TIME_SIZE]) -> Result<()> {
    let timestamp = u64::from_be_bytes(*timestamp);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new(ErrorKind::Protocol, "system clock is before Unix epoch"))?
        .as_secs();
    if now.abs_diff(timestamp) > 30 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "AEAD handshake timestamp expired",
        ));
    }
    Ok(())
}

fn derive_cipher(
    method: CryptoMethod,
    shared: &[u8],
    salt: &[u8],
    timestamp: &[u8],
) -> Result<DirectionCipher> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut info = Vec::with_capacity(method.name().len() + timestamp.len());
    info.extend_from_slice(method.name());
    info.extend_from_slice(timestamp);
    let mut key_nonce = vec![0u8; 32 + method.nonce_size()];
    hkdf.expand(&info, &mut key_nonce)
        .map_err(|_| Error::new(ErrorKind::Protocol, "AEAD stream key derivation failed"))?;
    Ok(DirectionCipher {
        method,
        key: key_nonce[..32].to_vec(),
        nonce: key_nonce[32..].to_vec(),
    })
}

fn fill_random(bytes: &mut [u8]) {
    rand::RngExt::fill(&mut rand::rng(), bytes);
}

#[derive(Clone)]
struct DirectionCipher {
    method: CryptoMethod,
    key: Vec<u8>,
    nonce: Vec<u8>,
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

struct AeadStream {
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
    fn new(
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

fn io_error(error: io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn password_salt_and_method_aliases_are_stable() {
        assert_eq!(password_salt(b"secret").len(), HASH_SIZE);
        assert_eq!(
            CryptoMethod::parse("AeadCryptoMethod_XChacha20Poly1305"),
            CryptoMethod::XChacha20Poly1305
        );
        assert_eq!(
            CryptoMethod::parse("unknown"),
            CryptoMethod::Chacha20Poly1305
        );
    }

    #[tokio::test]
    async fn client_and_server_round_trip_both_cipher_methods() {
        for method in [
            CryptoMethod::Chacha20Poly1305,
            CryptoMethod::XChacha20Poly1305,
        ] {
            let (client_io, server_io) = tokio::io::duplex(256 * 1024);
            let (client, server) = tokio::join!(
                super::client(Box::new(client_io), b"secret", method),
                super::server(Box::new(server_io), b"secret", method),
            );
            let mut client = client.unwrap();
            let mut server = server.unwrap();
            client.write_all(b"client-to-server").await.unwrap();
            let mut request = vec![0u8; 16];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"client-to-server");
            server.write_all(b"server-to-client").await.unwrap();
            let mut response = vec![0u8; 16];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"server-to-client");
        }
    }

    #[test]
    fn udp_packet_round_trip_both_cipher_methods_and_rejects_wrong_password() {
        for method in [
            CryptoMethod::Chacha20Poly1305,
            CryptoMethod::XChacha20Poly1305,
        ] {
            let packet = encrypt_packet(b"udp-payload", b"secret", method).unwrap();
            assert_eq!(
                decrypt_packet(&packet, b"secret", method).unwrap(),
                b"udp-payload"
            );
            assert!(decrypt_packet(&packet, b"wrong", method).is_err());
        }
    }
}
