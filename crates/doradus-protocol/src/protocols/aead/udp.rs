//! AEAD UDP packet framing and socket adapters.

use super::*;

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

pub(super) struct AeadUdpDatagram {
    pub(super) socket: tokio::net::UdpSocket,
    pub(super) server: std::net::SocketAddr,
    pub(super) password: Vec<u8>,
    pub(super) method: CryptoMethod,
    pub(super) receive_buffer: AsyncMutex<Vec<u8>>,
}

/// Server-side authenticated UDP socket for an outer Go AEAD transport.
/// Unlike [`AeadUdpDatagram`], replies are sent to the peer returned by the
/// receive operation; this is the boundary needed by inbound protocols such as
/// Yuubinsya that carry their own target address inside the decrypted payload.
pub struct AeadUdpServer {
    socket: tokio::net::UdpSocket,
    password: Vec<u8>,
    method: CryptoMethod,
    receive_buffer: AsyncMutex<Vec<u8>>,
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
            receive_buffer: AsyncMutex::new(Vec::new()),
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
            let mut packet = self.receive_buffer.lock().await;
            ensure_receive_buffer(&mut packet, buffer.len(), self.method);
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
            let mut packet = self.receive_buffer.lock().await;
            ensure_receive_buffer(&mut packet, buffer.len(), self.method);
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

pub(super) struct AeadDatagram {
    pub(super) upstream: Box<dyn AsyncDatagram>,
    pub(super) password: Vec<u8>,
    pub(super) method: CryptoMethod,
    pub(super) receive_buffer: AsyncMutex<Vec<u8>>,
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
            let mut packet = self.receive_buffer.lock().await;
            ensure_receive_buffer(&mut packet, buffer.len(), self.method);
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

fn ensure_receive_buffer(packet: &mut Vec<u8>, payload_capacity: usize, method: CryptoMethod) {
    let required = payload_capacity
        .saturating_add(method.nonce_size())
        .saturating_add(FRAME_TAG_SIZE)
        .min(MAX_PAYLOAD_SIZE);
    if packet.len() < required {
        packet.resize(required, 0);
    }
}
