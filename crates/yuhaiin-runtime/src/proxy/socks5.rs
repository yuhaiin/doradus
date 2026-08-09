use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use yuhaiin_core::flow::{
    Flow as TunFlow, FlowDirection as TunFlowDirection, FlowKey as TunFlowKey,
    FlowObserver as TunFlowObserver,
};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxySelector};
use yuhaiin_core::{DomainName, Endpoint, Error, ErrorKind, FlowContext, Network, Result};

use super::common::{
    UdpFlowId, UdpFlowState, UdpReply, close_udp_flows, io_error, relay_counted, udp_flow_key,
};
use crate::inbound::InboundSpec;
use crate::{ConnectionMonitor, RuntimeProxySelector};

pub(crate) async fn serve<S>(
    mut stream: S,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.map_err(io_error)?;
    if greeting[0] != 5 {
        return Err(Error::new(ErrorKind::Protocol, "SOCKS5 version is not 5"));
    }
    let mut methods = vec![0u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await.map_err(io_error)?;
    let requires_auth = !spec.username.is_empty() || !spec.password.is_empty();
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
        let ok = username == spec.username.as_bytes() && password == spec.password.as_bytes();
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
    if request[1] != 1 && request[1] != 3 {
        write_socks_reply(&mut stream, 7).await?;
        return Err(Error::new(
            ErrorKind::Unsupported,
            "SOCKS5 command is not CONNECT",
        ));
    }
    let destination = read_socks_endpoint(&mut stream, Network::Tcp, request[3]).await?;
    if request[1] == 3 {
        let bind_ip = if peer.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        };
        let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .map_err(io_error)?;
        let address = socket.local_addr().map_err(io_error)?;
        write_socks_reply_endpoint(&mut stream, 0, address).await?;
        return serve_socks5_udp_loop(socket, spec, selector, monitor, Some(peer)).await;
    }
    let source = Endpoint::ip(Network::Tcp, peer);
    let mut context = FlowContext::new(destination.clone());
    context.source = Some(source);
    context.original_domain = destination.host().cloned();
    spec.annotate_context(&mut context);
    let proxy = selector.select(&context);
    let outbound = match proxy.connect(&context).await {
        Ok(outbound) => outbound,
        Err(error) => {
            write_socks_reply(&mut stream, 5).await?;
            monitor.record_failure("socks5", &destination.to_string(), &error.to_string());
            return Err(error);
        }
    };
    write_socks_reply(&mut stream, 0).await?;
    relay_counted(
        stream,
        outbound,
        TunFlowKey {
            network: Network::Tcp,
            source: peer,
            destination: destination
                .addr()
                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
        },
        context,
        monitor,
    )
    .await
    .map_err(io_error)
}

pub(crate) async fn serve_udp_socket(
    socket: impl InboundUdpSocket,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()> {
    serve_socks5_udp_loop(socket, spec, selector, monitor, None).await
}

pub(crate) async fn serve_socks5_udp_loop(
    mut socket: impl InboundUdpSocket,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    allowed_peer: Option<SocketAddr>,
) -> Result<()> {
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpReply>(64);
    let mut flows = HashMap::<UdpFlowId, UdpFlowState>::new();
    let mut close_events = monitor.subscribe_close_requests();
    let mut client = allowed_peer;
    let mut packet = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            received = socket.recv_from(&mut packet) => {
                let (length, peer) = received.map_err(io_error)?;
                if allowed_peer.is_some_and(|allowed| allowed != peer) {
                    continue;
                }
                let Some((target, payload)) = parse_socks_udp_packet(&packet[..length])? else {
                    continue;
                };
                if let Some(expected) = client {
                    if expected != peer {
                        continue;
                    }
                } else {
                    client = Some(peer);
                }
                let id = UdpFlowId { peer, target: target.clone() };
                let state = if let Some(state) = flows.get(&id) {
                    state
                } else {
                    let source = Endpoint::ip(Network::Udp, peer);
                    let mut context = FlowContext::new(target.clone());
                    context.source = Some(source.clone());
                    context.original_domain = target.host().cloned();
                    spec.annotate_context(&mut context);
                    let key = udp_flow_key(peer, &target);
                    let datagram = selector.select(&context).open_datagram(&context).await?;
                    let datagram: Arc<dyn AsyncDatagram> = Arc::from(datagram);
                    monitor.opened(TunFlow { key }, context);
                    let receiver = Arc::clone(&datagram);
                    let reply_tx = reply_tx.clone();
                    let id_for_task = id.clone();
                    tokio::spawn(async move {
                        let mut buffer = vec![0u8; 64 * 1024];
                        loop {
                            match receiver.recv_from(&mut buffer).await {
                                Ok((length, target)) => {
                                    if reply_tx.send(UdpReply {
                                        id: id_for_task.clone(),
                                        target,
                                        payload: buffer[..length].to_vec(),
                                    }).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                    flows.entry(id.clone()).or_insert(UdpFlowState {
                        datagram,
                        key,
                        peer: source,
                    })
                };
                state.datagram.send_to(payload, target).await?;
                monitor.bytes(state.key, TunFlowDirection::Upload, payload.len());
            }
            close_event = close_events.recv() => {
                match close_event {
                    Ok(flow) => {
                        close_udp_flows(&mut flows, flow, &monitor).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            Some(reply) = reply_rx.recv() => {
                let Some(state) = flows.get(&reply.id) else { continue; };
                let Some(client) = client else { continue; };
                let packet = encode_socks_udp_packet(&reply.target, &reply.payload)?;
                socket.send_to(&packet, client).await.map_err(io_error)?;
                monitor.bytes(state.key, TunFlowDirection::Download, reply.payload.len());
            }
            else => break,
        }
    }
    for state in flows.into_values() {
        let _ = state.datagram.close().await;
        monitor.closed(state.key);
    }
    let _ = spec;
    Ok(())
}

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
        }
    }
}

impl InboundUdpSocket for AeadUdpSocket {
    fn recv_from<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> Pin<Box<dyn Future<Output = io::Result<(usize, SocketAddr)>> + Send + 'a>> {
        Box::pin(async move {
            let mut packet = vec![0u8; 65_535];
            let (length, peer) = self.socket.recv_from(&mut packet).await?;
            let plaintext = yuhaiin_protocol::aead::decrypt_packet(
                &packet[..length],
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

async fn read_socks_endpoint<S>(stream: &mut S, network: Network, atyp: u8) -> Result<Endpoint>
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

pub(crate) fn parse_socks_udp_packet(packet: &[u8]) -> Result<Option<(Endpoint, &[u8])>> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 {
        return Err(Error::new(ErrorKind::Protocol, "invalid SOCKS5 UDP header"));
    }
    if packet[2] != 0 {
        return Ok(None);
    }
    let (target, offset) = parse_socks_endpoint_bytes(&packet[3..], Network::Udp)?;
    Ok(Some((target, &packet[3 + offset..])))
}

fn parse_socks_endpoint_bytes(bytes: &[u8], network: Network) -> Result<(Endpoint, usize)> {
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

pub(crate) fn encode_socks_udp_packet(target: &Endpoint, payload: &[u8]) -> Result<Vec<u8>> {
    let mut packet = vec![0, 0, 0];
    encode_socks_endpoint(&mut packet, target)?;
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn encode_socks_endpoint(packet: &mut Vec<u8>, target: &Endpoint) -> Result<()> {
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

async fn write_socks_reply<S>(stream: &mut S, code: u8) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(io_error)
}

async fn write_socks_reply_endpoint<S>(stream: &mut S, code: u8, address: SocketAddr) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut reply = Vec::with_capacity(22);
    reply.extend_from_slice(&[5, code, 0]);
    encode_socks_endpoint(&mut reply, &Endpoint::ip(Network::Tcp, address))?;
    stream.write_all(&reply).await.map_err(io_error)
}

#[cfg(test)]
mod tests {
    use super::*;

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
