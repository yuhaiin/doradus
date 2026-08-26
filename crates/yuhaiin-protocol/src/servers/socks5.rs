//! SOCKS5 server-side wire protocol.
//!
//! The runtime owns listener policy, route selection and UDP flow lifetime.
//! This module owns only the bytes exchanged with a SOCKS5 client, so the
//! same server implementation can be reused by another inbound frontend.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use yuhaiin_core::{DomainName, Endpoint, Error, ErrorKind, Network, Result};
use yuhaiin_types::{InboundUdpCodec, InboundUdpFlowId, InboundUdpRequest, InboundUdpResponse};

type UdpRecvFuture<'a> = Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>>;
type UdpSendFuture<'a> = Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5Command {
    Connect,
    UdpAssociate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Request {
    pub command: Socks5Command,
    pub destination: Endpoint,
}

/// The small socket port needed by the SOCKS5 UDP server codec.
///
/// Listener setup remains a runtime concern; defining this port here lets
/// SOCKS5 packet framing and client-peer pinning live with the protocol.
pub trait UdpTransport: Send + Unpin + 'static {
    fn recv_from<'a>(&'a mut self, buffer: &'a mut [u8]) -> UdpRecvFuture<'a>;

    fn send_to<'a>(&'a mut self, buffer: &'a [u8], peer: SocketAddr) -> UdpSendFuture<'a>;
}

impl UdpTransport for Box<dyn UdpTransport> {
    fn recv_from<'a>(&'a mut self, buffer: &'a mut [u8]) -> UdpRecvFuture<'a> {
        (**self).recv_from(buffer)
    }

    fn send_to<'a>(&'a mut self, buffer: &'a [u8], peer: SocketAddr) -> UdpSendFuture<'a> {
        (**self).send_to(buffer, peer)
    }
}

/// AEAD packet transport layered on top of a UDP socket adapter.
///
/// The runtime supplies only the socket operations.  Encryption, packet
/// overhead and the conversion between wire errors and `io::Error` belong to
/// this protocol layer and can therefore be reused by every SOCKS5 UDP
/// listener.
pub struct AeadUdpTransport<S> {
    inner: S,
    password: Vec<u8>,
    method: crate::aead::CryptoMethod,
    packet: Vec<u8>,
}

impl<S> AeadUdpTransport<S> {
    pub fn new(inner: S, password: impl Into<Vec<u8>>, method: crate::aead::CryptoMethod) -> Self {
        Self {
            inner,
            password: password.into(),
            method,
            packet: Vec::new(),
        }
    }
}

impl<S> UdpTransport for AeadUdpTransport<S>
where
    S: UdpTransport,
{
    fn recv_from<'a>(&'a mut self, buffer: &'a mut [u8]) -> UdpRecvFuture<'a> {
        Box::pin(async move {
            const AEAD_UDP_MAX_OVERHEAD: usize = 24 + 16;
            let required = buffer
                .len()
                .saturating_add(AEAD_UDP_MAX_OVERHEAD)
                .min(u16::MAX as usize);
            if self.packet.len() < required {
                self.packet.resize(required, 0);
            }
            let (length, peer) = self.inner.recv_from(&mut self.packet).await?;
            let plaintext =
                crate::aead::decrypt_packet(&self.packet[..length], &self.password, self.method)
                    .map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                    })?;
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

    fn send_to<'a>(&'a mut self, buffer: &'a [u8], peer: SocketAddr) -> UdpSendFuture<'a> {
        Box::pin(async move {
            let packet = crate::aead::encrypt_packet(buffer, &self.password, self.method)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
            self.inner
                .send_to(&packet, peer)
                .await
                .map(|_| buffer.len())
        })
    }
}

/// SOCKS5 UDP associate server codec.
pub struct UdpServer<S> {
    socket: S,
    allowed_peer: Option<IpAddr>,
    client: Option<SocketAddr>,
    packet: Vec<u8>,
}

impl<S> UdpServer<S> {
    pub fn new(socket: S, allowed_peer: Option<IpAddr>, buffer_size: usize) -> Self {
        Self {
            socket,
            allowed_peer,
            client: None,
            packet: vec![0u8; buffer_size.max(512)],
        }
    }
}

impl<S> InboundUdpCodec for UdpServer<S>
where
    S: UdpTransport,
{
    type Request = InboundUdpRequest;
    type Response = InboundUdpResponse;

    fn recv<'a>(&'a mut self) -> yuhaiin_types::BoxFuture<'a, Result<Option<InboundUdpRequest>>> {
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
                let Some((target, payload)) = parse_udp_packet(&self.packet[..length])? else {
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
                    id: InboundUdpFlowId {
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

    fn send<'a>(
        &'a mut self,
        response: InboundUdpResponse,
    ) -> yuhaiin_types::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let peer = response
                .peer
                .addr()
                .ok_or_else(|| Error::invalid("SOCKS5 UDP peer has no IP address"))?;
            let packet = encode_udp_packet(&response.target, &response.payload)?;
            self.socket.send_to(&packet, peer).await.map_err(io_error)?;
            Ok(())
        })
    }
}

/// Complete the SOCKS5 greeting, optional username/password exchange and
/// request parsing. Authentication policy is supplied by the runtime and is
/// deliberately not coupled to the persisted configuration model.
pub async fn server_handshake<S, F>(
    stream: &mut S,
    network: Network,
    requires_auth: bool,
    authenticate: F,
) -> Result<Socks5Request>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(&[u8], &[u8]) -> bool,
{
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.map_err(io_error)?;
    if greeting[0] != 5 {
        return Err(Error::new(ErrorKind::Protocol, "SOCKS5 version is not 5"));
    }
    let mut methods = vec![0u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await.map_err(io_error)?;
    let selected = if requires_auth && methods.contains(&2) {
        2
    } else if !requires_auth && methods.contains(&0) {
        0
    } else {
        255
    };
    stream.write_all(&[5, selected]).await.map_err(io_error)?;
    if selected == 255 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "SOCKS5 no acceptable method",
        ));
    }
    if selected == 2 {
        let mut auth_head = [0u8; 2];
        stream.read_exact(&mut auth_head).await.map_err(io_error)?;
        if auth_head[0] != 1 {
            return Err(Error::new(
                ErrorKind::Protocol,
                "SOCKS5 auth version is not 1",
            ));
        }
        let mut username = vec![0u8; usize::from(auth_head[1])];
        stream.read_exact(&mut username).await.map_err(io_error)?;
        let mut password_len = [0u8; 1];
        stream
            .read_exact(&mut password_len)
            .await
            .map_err(io_error)?;
        let mut password = vec![0u8; usize::from(password_len[0])];
        stream.read_exact(&mut password).await.map_err(io_error)?;
        let ok = authenticate(&username, &password);
        stream
            .write_all(&[1, if ok { 0 } else { 1 }])
            .await
            .map_err(io_error)?;
        if !ok {
            return Err(Error::new(
                ErrorKind::Protocol,
                "SOCKS5 authentication failed",
            ));
        }
    }

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await.map_err(io_error)?;
    if request[0] != 5 || request[2] != 0 {
        return Err(Error::new(ErrorKind::Protocol, "invalid SOCKS5 request"));
    }
    let command = match request[1] {
        1 => Socks5Command::Connect,
        3 => Socks5Command::UdpAssociate,
        _ => {
            write_reply(stream, 7).await?;
            return Err(Error::new(
                ErrorKind::Unsupported,
                "SOCKS5 command is not supported",
            ));
        }
    };
    let destination = read_endpoint(stream, network, request[3]).await?;
    Ok(Socks5Request {
        command,
        destination,
    })
}

pub async fn read_endpoint<S>(stream: &mut S, network: Network, atyp: u8) -> Result<Endpoint>
where
    S: AsyncRead + Unpin,
{
    match atyp {
        1 => {
            let mut address = [0u8; 4 + 2];
            stream.read_exact(&mut address).await.map_err(io_error)?;
            let ip = IpAddr::from([address[0], address[1], address[2], address[3]]);
            Ok(Endpoint::ip(
                network,
                SocketAddr::new(ip, u16::from_be_bytes([address[4], address[5]])),
            ))
        }
        4 => {
            let mut address = [0u8; 16 + 2];
            stream.read_exact(&mut address).await.map_err(io_error)?;
            let ip = IpAddr::from(<[u8; 16]>::try_from(&address[..16]).unwrap());
            Ok(Endpoint::ip(
                network,
                SocketAddr::new(ip, u16::from_be_bytes([address[16], address[17]])),
            ))
        }
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await.map_err(io_error)?;
            if length[0] == 0 || usize::from(length[0]) > 253 {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "invalid SOCKS5 domain length",
                ));
            }
            let mut host = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut host).await.map_err(io_error)?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await.map_err(io_error)?;
            let host = String::from_utf8(host).map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("SOCKS5 domain: {error}"))
            })?;
            Ok(Endpoint::domain(
                network,
                DomainName::new(&host)?,
                u16::from_be_bytes(port),
            ))
        }
        _ => Err(Error::new(
            ErrorKind::Protocol,
            "unsupported SOCKS5 address type",
        )),
    }
}

pub fn parse_endpoint_bytes(bytes: &[u8], network: Network) -> Result<(Endpoint, usize)> {
    let atyp = *bytes
        .first()
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "SOCKS5 address is empty"))?;
    match atyp {
        1 => {
            if bytes.len() < 1 + 4 + 2 {
                return Err(Error::new(ErrorKind::Protocol, "short SOCKS5 IPv4 address"));
            }
            let ip = IpAddr::from([bytes[1], bytes[2], bytes[3], bytes[4]]);
            let port = u16::from_be_bytes([bytes[5], bytes[6]]);
            Ok((Endpoint::ip(network, SocketAddr::new(ip, port)), 1 + 4 + 2))
        }
        4 => {
            if bytes.len() < 1 + 16 + 2 {
                return Err(Error::new(ErrorKind::Protocol, "short SOCKS5 IPv6 address"));
            }
            let ip = IpAddr::from(<[u8; 16]>::try_from(&bytes[1..17]).unwrap());
            let port = u16::from_be_bytes([bytes[17], bytes[18]]);
            Ok((Endpoint::ip(network, SocketAddr::new(ip, port)), 1 + 16 + 2))
        }
        3 => {
            let length =
                usize::from(*bytes.get(1).ok_or_else(|| {
                    Error::new(ErrorKind::Protocol, "short SOCKS5 domain address")
                })?);
            if length == 0 || length > 253 || bytes.len() < 2 + length + 2 {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "invalid SOCKS5 domain address",
                ));
            }
            let host = std::str::from_utf8(&bytes[2..2 + length]).map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("SOCKS5 domain: {error}"))
            })?;
            let port = u16::from_be_bytes([bytes[2 + length], bytes[3 + length]]);
            Ok((
                Endpoint::domain(network, DomainName::new(host)?, port),
                2 + length + 2,
            ))
        }
        _ => Err(Error::new(
            ErrorKind::Protocol,
            "unsupported SOCKS5 address type",
        )),
    }
}

pub fn encode_endpoint(packet: &mut Vec<u8>, target: &Endpoint) -> Result<()> {
    match target {
        Endpoint::Ip { addr, .. } => match addr.ip() {
            IpAddr::V4(ip) => {
                packet.push(1);
                packet.extend_from_slice(&ip.octets());
                packet.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                packet.push(4);
                packet.extend_from_slice(&ip.octets());
                packet.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
        Endpoint::Domain { host, port, .. } => {
            let host = host.as_str().as_bytes();
            if host.is_empty() || host.len() > 253 {
                return Err(Error::new(ErrorKind::Protocol, "SOCKS5 domain is too long"));
            }
            packet.push(3);
            packet.push(host.len() as u8);
            packet.extend_from_slice(host);
            packet.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(())
}

pub fn parse_udp_packet(packet: &[u8]) -> Result<Option<(Endpoint, &[u8])>> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 {
        return Err(Error::new(ErrorKind::Protocol, "invalid SOCKS5 UDP header"));
    }
    if packet[2] != 0 {
        return Ok(None);
    }
    let (target, offset) = parse_endpoint_bytes(&packet[3..], Network::Udp)?;
    Ok(Some((target, &packet[3 + offset..])))
}

pub fn encode_udp_packet(target: &Endpoint, payload: &[u8]) -> Result<Vec<u8>> {
    let mut packet = vec![0, 0, 0];
    encode_endpoint(&mut packet, target)?;
    packet.extend_from_slice(payload);
    Ok(packet)
}

pub async fn write_reply<S>(stream: &mut S, code: u8) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(io_error)
}

pub async fn write_reply_endpoint<S>(stream: &mut S, code: u8, address: SocketAddr) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut reply = Vec::with_capacity(22);
    reply.extend_from_slice(&[5, code, 0]);
    encode_endpoint(&mut reply, &Endpoint::ip(Network::Tcp, address))?;
    stream.write_all(&reply).await.map_err(io_error)
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn udp_packet_round_trips_ip_and_domain_targets() {
        let targets = [
            Endpoint::ip(Network::Udp, "192.0.2.10:5353".parse().unwrap()),
            Endpoint::ip(Network::Udp, "[2001:db8::10]:443".parse().unwrap()),
            Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 443),
        ];
        for target in targets {
            let packet = encode_udp_packet(&target, b"payload").unwrap();
            let (decoded, payload) = parse_udp_packet(&packet).unwrap().unwrap();
            assert_eq!(decoded, target);
            assert_eq!(payload, b"payload");
        }
    }

    #[test]
    fn udp_fragments_are_ignored_but_malformed_headers_fail() {
        assert!(parse_udp_packet(&[0, 0, 1, 1]).unwrap().is_none());
        assert!(parse_udp_packet(&[1, 0, 0, 1]).is_err());
        assert!(parse_udp_packet(&[0, 0, 0, 1, 127]).is_err());
    }

    #[tokio::test]
    async fn server_handshake_authenticates_and_preserves_domain_request() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(async move {
            let request = server_handshake(&mut server, Network::Tcp, true, |user, password| {
                user == b"user" && password == b"pass"
            })
            .await
            .unwrap();
            assert_eq!(request.command, Socks5Command::Connect);
            assert_eq!(
                request.destination,
                Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443)
            );
        });

        client.write_all(&[5, 2, 0, 2]).await.unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [5, 2]);
        client
            .write_all(&[1, 4, b'u', b's', b'e', b'r', 4, b'p', b'a', b's', b's'])
            .await
            .unwrap();
        let mut auth_response = [0u8; 2];
        client.read_exact(&mut auth_response).await.unwrap();
        assert_eq!(auth_response, [1, 0]);
        client.write_all(&[5, 1, 0, 3, 11]).await.unwrap();
        client.write_all(b"example.com").await.unwrap();
        client.write_all(&443u16.to_be_bytes()).await.unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn server_handshake_rejects_bad_credentials() {
        let (mut client, mut server) = tokio::io::duplex(128);
        let server_task = tokio::spawn(async move {
            let error = server_handshake(&mut server, Network::Tcp, true, |user, password| {
                user == b"user" && password == b"pass"
            })
            .await
            .unwrap_err();
            assert!(error.to_string().contains("authentication failed"));
        });
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [5, 2]);
        client
            .write_all(&[1, 4, b'u', b's', b'e', b'r', 4, b'b', b'a', b'd', b'!'])
            .await
            .unwrap();
        let mut auth_response = [0u8; 2];
        client.read_exact(&mut auth_response).await.unwrap();
        assert_eq!(auth_response, [1, 1]);
        server_task.await.unwrap();
    }
}
