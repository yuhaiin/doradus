use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::UdpSocket;
use yuhaiin_core::proxy::BoxAsyncStream;
use yuhaiin_core::{BoxFuture, Endpoint, Network, Result};

use crate::inbound::{
    InboundHandler, InboundUdpCodec, InboundUdpRequest, InboundUdpResponse, InboundUdpSession,
};
use crate::proxy::common::io_error;

pub(crate) use yuhaiin_protocol::socks5_server::{
    encode_udp_packet as encode_socks_udp_packet, parse_udp_packet as parse_socks_udp_packet,
};

pub(crate) async fn handle(
    mut stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let spec = inbound.spec();
    let central_auth = spec.auth.as_deref().filter(|auth| auth.has_basic_users());
    let requires_auth =
        central_auth.is_some() || !spec.username.is_empty() || !spec.password.is_empty();
    let request = yuhaiin_protocol::socks5_server::server_handshake(
        &mut stream,
        Network::Tcp,
        requires_auth,
        |username, password| {
            if let Some(auth) = central_auth {
                auth.authenticate_basic(username, password)
            } else {
                username == spec.username.as_bytes() && password == spec.password.as_bytes()
            }
        },
    )
    .await?;
    if matches!(
        request.command,
        yuhaiin_protocol::socks5_server::Socks5Command::UdpAssociate
    ) {
        let bind_ip = if peer.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        };
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .map_err(io_error)?;
        let address = socket.local_addr().map_err(io_error)?;
        let advertised_address = SocketAddr::new(peer.ip(), address.port());
        yuhaiin_protocol::socks5_server::write_reply_endpoint(&mut stream, 0, advertised_address)
            .await?;
        return serve_socks5_udp_loop(Box::new(socket), Arc::clone(&inbound), Some(peer.ip()))
            .await;
    }
    let destination = request.destination;
    let connection = match inbound.open_stream("socks5", peer, destination).await {
        Ok(connection) => connection,
        Err(error) => {
            yuhaiin_protocol::socks5_server::write_reply(&mut stream, 5).await?;
            return Err(error);
        }
    };
    yuhaiin_protocol::socks5_server::write_reply(&mut stream, 0).await?;
    inbound
        .relay(stream, connection, peer)
        .await
        .map_err(io_error)
}

pub(crate) async fn serve_udp_socket(
    socket: Box<dyn InboundUdpSocket>,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    serve_socks5_udp_loop(socket, inbound, None).await
}

pub(crate) async fn serve_socks5_udp_loop(
    socket: Box<dyn InboundUdpSocket>,
    inbound: Arc<InboundHandler>,
    allowed_peer: Option<IpAddr>,
) -> Result<()> {
    InboundUdpSession::new(
        Socks5UdpCodec::new(
            socket,
            allowed_peer,
            inbound.selector().udp_buffer_size().max(512),
        ),
        inbound,
    )
    .run()
    .await
}

struct Socks5UdpCodec {
    socket: Box<dyn InboundUdpSocket>,
    allowed_peer: Option<IpAddr>,
    client: Option<SocketAddr>,
    packet: Vec<u8>,
}

impl Socks5UdpCodec {
    fn new(
        socket: Box<dyn InboundUdpSocket>,
        allowed_peer: Option<IpAddr>,
        buffer_size: usize,
    ) -> Self {
        Self {
            socket,
            allowed_peer,
            client: None,
            packet: vec![0u8; buffer_size],
        }
    }
}

impl InboundUdpCodec for Socks5UdpCodec {
    fn recv<'a>(&'a mut self) -> BoxFuture<'a, Result<Option<InboundUdpRequest>>> {
        Box::pin(async move {
            loop {
                let (length, peer) = self
                    .socket
                    .recv_from(&mut self.packet)
                    .await
                    .map_err(io_error)?;
                if self
                    .allowed_peer
                    .is_some_and(|allowed| allowed != peer.ip())
                {
                    continue;
                }
                let Some((target, payload)) = parse_socks_udp_packet(&self.packet[..length])?
                else {
                    continue;
                };
                if let Some(expected) = self.client {
                    if expected != peer {
                        continue;
                    }
                } else {
                    self.client = Some(peer);
                }
                return Ok(Some(InboundUdpRequest {
                    id: crate::proxy::common::UdpFlowId {
                        peer,
                        target: target.clone(),
                        authentication: None,
                    },
                    peer: Endpoint::ip(Network::Udp, peer),
                    target,
                    payload: payload.to_vec(),
                }));
            }
        })
    }

    fn send<'a>(&'a mut self, response: InboundUdpResponse) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let peer = response
                .peer
                .addr()
                .ok_or_else(|| yuhaiin_core::Error::invalid("SOCKS5 UDP peer has no IP address"))?;
            let packet = encode_socks_udp_packet(&response.target, &response.payload)?;
            self.socket.send_to(&packet, peer).await.map_err(io_error)?;
            Ok(())
        })
    }
}

#[allow(clippy::type_complexity)]
pub(crate) trait InboundUdpSocket: Send + Unpin + 'static {
    fn recv_from<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>>;

    fn send_to<'a>(
        &'a mut self,
        buffer: &'a [u8],
        peer: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;
}

impl InboundUdpSocket for UdpSocket {
    fn recv_from<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        Box::pin(UdpSocket::recv_from(self, buffer))
    }

    fn send_to<'a>(
        &'a mut self,
        buffer: &'a [u8],
        peer: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(UdpSocket::send_to(self, buffer, peer))
    }
}

pub(crate) struct AeadUdpSocket {
    socket: UdpSocket,
    password: Vec<u8>,
    method: yuhaiin_protocol::aead::CryptoMethod,
    packet: Vec<u8>,
}

impl AeadUdpSocket {
    pub(crate) fn new(
        socket: UdpSocket,
        password: impl Into<Vec<u8>>,
        method: yuhaiin_protocol::aead::CryptoMethod,
    ) -> Self {
        Self {
            socket,
            password: password.into(),
            method,
            packet: Vec::new(),
        }
    }
}

impl InboundUdpSocket for AeadUdpSocket {
    fn recv_from<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move {
            const AEAD_UDP_MAX_OVERHEAD: usize = 24 + 16;
            let required = buffer
                .len()
                .saturating_add(AEAD_UDP_MAX_OVERHEAD)
                .min(u16::MAX as usize);
            if self.packet.len() < required {
                self.packet.resize(required, 0);
            }
            let (length, peer) = self.socket.recv_from(&mut self.packet).await?;
            let plaintext = yuhaiin_protocol::aead::decrypt_packet(
                &self.packet[..length],
                &self.password,
                self.method,
            )
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
            if buffer.len() < plaintext.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "AEAD UDP payload exceeds receive buffer",
                ));
            }
            buffer[..plaintext.len()].copy_from_slice(&plaintext);
            Ok((plaintext.len(), peer))
        })
    }

    fn send_to<'a>(
        &'a mut self,
        buffer: &'a [u8],
        peer: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move {
            let packet =
                yuhaiin_protocol::aead::encrypt_packet(buffer, &self.password, self.method)
                    .map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                    })?;
            self.socket
                .send_to(&packet, peer)
                .await
                .map(|_| buffer.len())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yuhaiin_core::DomainName;

    #[test]
    fn socks_udp_packet_round_trips_ip_and_domain_targets() {
        let targets = [
            Endpoint::ip(Network::Udp, "192.0.2.10:5353".parse().unwrap()),
            Endpoint::ip(Network::Udp, "[2001:db8::10]:443".parse().unwrap()),
            Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 443),
        ];
        for target in targets {
            let packet = encode_socks_udp_packet(&target, b"payload").unwrap();
            let (decoded, payload) = parse_socks_udp_packet(&packet).unwrap().unwrap();
            assert_eq!(decoded, target);
            assert_eq!(payload, b"payload");
        }
    }

    #[test]
    fn socks_udp_fragments_are_ignored_but_malformed_headers_fail() {
        assert!(parse_socks_udp_packet(&[0, 0, 1, 1]).unwrap().is_none());
        assert!(parse_socks_udp_packet(&[1, 0, 0, 1]).is_err());
        assert!(parse_socks_udp_packet(&[0, 0, 0, 1, 127]).is_err());
    }
}
