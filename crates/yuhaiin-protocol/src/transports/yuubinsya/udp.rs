//! Native Yuubinsya UDP protocol adapters.

use std::net::SocketAddr;
use std::sync::Arc;

use yuhaiin_core::network::bind_tokio_udp_socket_for_target;
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};
use yuhaiin_types::{InboundUdpCodec, InboundUdpFlowId, InboundUdpRequest, InboundUdpResponse};

struct TokioDatagram {
    socket: tokio::net::UdpSocket,
}

impl AsyncDatagram for TokioDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let address = target
                .addr()
                .ok_or_else(|| Error::invalid("Yuubinsya UDP target must have an address"))?;
            self.socket
                .send_to(payload, address)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, format!("Yuubinsya UDP send: {error}")))
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let (length, address) = self.socket.recv_from(buffer).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("Yuubinsya UDP receive: {error}"))
            })?;
            Ok((length, Endpoint::ip(Network::Udp, address)))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.socket
            .local_addr()
            .map(|address| Endpoint::ip(Network::Udp, address))
            .map_err(|error| {
                Error::new(
                    ErrorKind::Io,
                    format!("Yuubinsya UDP local address: {error}"),
                )
            })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// Authenticated Yuubinsya native-UDP adapter over any async datagram
/// transport.  The underlying transport only knows the fixed Yuubinsya server
/// endpoint; the original destination remains inside the authenticated packet
/// so full-cone NAT and proxy routing can preserve it independently.
pub struct YuubinsyaUdpDatagram {
    transport: Box<dyn AsyncDatagram>,
    password_hash: [u8; 32],
    server: Endpoint,
    socks5_prefix: bool,
}

/// Async proxy boundary for a native Yuubinsya UDP node.
///
/// Yuubinsya native UDP has no TCP stream operation.  Keeping that fact in
/// the proxy implementation makes accidental stream fallback impossible,
/// while `open_datagram` still creates one authenticated socket per TUN flow.
pub struct YuubinsyaUdpProxy {
    pub server: SocketAddr,
    pub password_hash: [u8; 32],
    pub socks5_prefix: bool,
}

impl AsyncProxy for YuubinsyaUdpProxy {
    fn connect<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "native Yuubinsya UDP proxy has no TCP stream path",
            ))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let server = self.server;
        let password_hash = self.password_hash;
        let socks5_prefix = self.socks5_prefix;
        let fallback = match server {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let bind_address = context.local_bind_for(server).unwrap_or(fallback);
        let bind_interface = context.bind_interface.clone();
        Box::pin(async move {
            Ok(Box::new(
                YuubinsyaUdpDatagram::bind_with_interface(
                    bind_address,
                    password_hash,
                    Endpoint::ip(Network::Udp, server),
                    socks5_prefix,
                    bind_interface.as_deref(),
                )
                .await?,
            ) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// Native Yuubinsya UDP server boundary.  It is intentionally transport
/// agnostic so a platform UDP socket, a TUN-facing relay, or a test fixture
/// can provide the actual datagram I/O.
pub struct YuubinsyaUdpServer {
    transport: Box<dyn AsyncDatagram>,
    password_hashes: Arc<[[u8; 32]]>,
    socks5_prefix: bool,
}

/// Yuubinsya inbound UDP protocol codec.
///
/// [`YuubinsyaUdpServer`] owns authenticated wire transport.  This adapter
/// turns it into the shared inbound UDP contract while leaving routing and
/// flow management to the runtime.
pub struct InboundUdpServer {
    server: YuubinsyaUdpServer,
    packet: Vec<u8>,
}

impl InboundUdpServer {
    pub fn new(server: YuubinsyaUdpServer, buffer_size: usize) -> Self {
        Self {
            server,
            packet: vec![0u8; buffer_size.max(512)],
        }
    }
}

impl InboundUdpCodec for InboundUdpServer {
    type Request = InboundUdpRequest;
    type Response = InboundUdpResponse;

    fn recv<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<InboundUdpRequest>>> {
        Box::pin(async move {
            let (length, target, peer, password_hash) = self
                .server
                .recv_from_authenticated(&mut self.packet)
                .await?;
            let peer_addr = peer
                .addr()
                .ok_or_else(|| Error::invalid("Yuubinsya UDP peer has no IP address"))?;
            Ok(Some(InboundUdpRequest {
                id: InboundUdpFlowId {
                    peer: peer_addr,
                    target: target.clone(),
                    authentication: Some(password_hash),
                },
                peer,
                target,
                payload: self.packet[..length].to_vec(),
            }))
        })
    }

    fn send<'a>(&'a mut self, response: InboundUdpResponse) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let password_hash = response
                .id
                .authentication
                .ok_or_else(|| Error::invalid("Yuubinsya UDP response has no password hash"))?;
            self.server
                .send_to_with_password_hash(
                    &response.payload,
                    response.target,
                    response.peer,
                    password_hash,
                )
                .await?;
            Ok(())
        })
    }
}

impl YuubinsyaUdpServer {
    pub async fn bind(
        address: SocketAddr,
        password_hash: [u8; 32],
        socks5_prefix: bool,
    ) -> Result<Self> {
        Self::bind_with_password_hashes(address, vec![password_hash], socks5_prefix).await
    }

    pub async fn bind_with_password_hashes(
        address: SocketAddr,
        password_hashes: Vec<[u8; 32]>,
        socks5_prefix: bool,
    ) -> Result<Self> {
        let socket = tokio::net::UdpSocket::bind(address)
            .await
            .map_err(|error| {
                Error::new(ErrorKind::Io, format!("bind Yuubinsya UDP server: {error}"))
            })?;
        Ok(Self::new_with_password_hashes(
            Box::new(TokioDatagram { socket }),
            password_hashes,
            socks5_prefix,
        ))
    }

    pub fn new(
        transport: Box<dyn AsyncDatagram>,
        password_hash: [u8; 32],
        socks5_prefix: bool,
    ) -> Self {
        Self::new_with_password_hashes(transport, vec![password_hash], socks5_prefix)
    }

    pub fn new_with_password_hashes(
        transport: Box<dyn AsyncDatagram>,
        password_hashes: Vec<[u8; 32]>,
        socks5_prefix: bool,
    ) -> Self {
        let password_hashes = if password_hashes.is_empty() {
            vec![[0u8; 32]]
        } else {
            password_hashes
        };
        Self {
            transport,
            password_hashes: password_hashes.into(),
            socks5_prefix,
        }
    }

    pub async fn recv_from(&self, buffer: &mut [u8]) -> Result<(usize, Endpoint, Endpoint)> {
        let (length, target, peer, _) = self.recv_from_authenticated(buffer).await?;
        Ok((length, target, peer))
    }

    pub async fn recv_from_authenticated(
        &self,
        buffer: &mut [u8],
    ) -> Result<(usize, Endpoint, Endpoint, [u8; 32])> {
        let mut packet = vec![0u8; crate::yuubinsya::MAX_SEGMENT_SIZE + 32 + 3 + 260];
        let (length, peer) = self.transport.recv_from(&mut packet).await?;
        let (target, payload, password_hash) = crate::yuubinsya::decode_udp_packet_any(
            &self.password_hashes,
            &packet[..length],
            self.socks5_prefix,
        )?;
        if buffer.len() < payload.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Yuubinsya UDP server buffer is too small",
            ));
        }
        buffer[..payload.len()].copy_from_slice(payload);
        Ok((payload.len(), target, peer, password_hash))
    }

    pub async fn send_to(&self, payload: &[u8], target: Endpoint, peer: Endpoint) -> Result<usize> {
        self.send_to_with_password_hash(payload, target, peer, self.password_hashes[0])
            .await
    }

    pub async fn send_to_with_password_hash(
        &self,
        payload: &[u8],
        target: Endpoint,
        peer: Endpoint,
        password_hash: [u8; 32],
    ) -> Result<usize> {
        if peer.network() != Network::Udp || peer.addr().is_none() {
            return Err(Error::invalid(
                "Yuubinsya UDP peer must be an IP UDP endpoint",
            ));
        }
        let packet = crate::yuubinsya::encode_udp_packet(
            &password_hash,
            &target,
            payload,
            self.socks5_prefix,
        )?;
        self.transport.send_to(&packet, peer).await?;
        Ok(payload.len())
    }

    pub fn local_addr(&self) -> Result<Endpoint> {
        self.transport.local_addr()
    }

    pub fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.transport.close()
    }
}

impl YuubinsyaUdpDatagram {
    pub async fn bind(
        address: SocketAddr,
        password_hash: [u8; 32],
        server: Endpoint,
        socks5_prefix: bool,
    ) -> Result<Self> {
        Self::bind_with_interface(address, password_hash, server, socks5_prefix, None).await
    }

    pub async fn bind_with_interface(
        address: SocketAddr,
        password_hash: [u8; 32],
        server: Endpoint,
        socks5_prefix: bool,
        bind_interface: Option<&str>,
    ) -> Result<Self> {
        let server_address = server
            .addr()
            .ok_or_else(|| Error::invalid("Yuubinsya native UDP server has no address"))?;
        let socket = bind_tokio_udp_socket_for_target(
            address,
            server_address,
            bind_interface,
            "Yuubinsya client",
        )
        .await?;
        Self::new(
            Box::new(TokioDatagram { socket }),
            password_hash,
            server,
            socks5_prefix,
        )
    }

    pub fn new(
        transport: Box<dyn AsyncDatagram>,
        password_hash: [u8; 32],
        server: Endpoint,
        socks5_prefix: bool,
    ) -> Result<Self> {
        if server.network() != Network::Udp || server.addr().is_none() {
            return Err(Error::invalid(
                "Yuubinsya native UDP server must be an IP UDP endpoint",
            ));
        }
        Ok(Self {
            transport,
            password_hash,
            server,
            socks5_prefix,
        })
    }
}

impl AsyncDatagram for YuubinsyaUdpDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            if target.network() != Network::Udp {
                return Err(Error::invalid(
                    "Yuubinsya native UDP target has wrong network",
                ));
            }
            let packet = crate::yuubinsya::encode_udp_packet(
                &self.password_hash,
                &target,
                payload,
                self.socks5_prefix,
            )?;
            self.transport.send_to(&packet, self.server.clone()).await?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            // Password + optional prefix + max address + max payload.  Keep
            // this bounded and independent from the caller's output buffer so
            // truncated caller buffers cannot desynchronize the next packet.
            let mut packet = vec![0u8; crate::yuubinsya::MAX_SEGMENT_SIZE + 32 + 3 + 260];
            let (length, _) = self.transport.recv_from(&mut packet).await?;
            let (target, payload) = crate::yuubinsya::decode_udp_packet(
                &self.password_hash,
                &packet[..length],
                self.socks5_prefix,
            )?;
            if buffer.len() < payload.len() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Yuubinsya UDP payload exceeds receive buffer",
                ));
            }
            buffer[..payload.len()].copy_from_slice(payload);
            Ok((payload.len(), target))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.transport.local_addr()
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.transport.close()
    }
}
