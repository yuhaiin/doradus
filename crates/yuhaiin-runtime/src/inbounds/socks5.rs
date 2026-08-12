use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use yuhaiin_core::flow::{
    Flow as TunFlow, FlowDirection as TunFlowDirection, FlowKey as TunFlowKey,
    FlowObserver as TunFlowObserver, FlowObserverGuard,
};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxySelector};
use yuhaiin_core::{Endpoint, FlowContext, Network, Result};

use crate::inbound::InboundSpec;
use crate::proxy::common::{
    UdpFlowId, UdpFlowState, UdpReply, answer_dns_packet, close_udp_flows, io_error,
    reap_expired_udp_flows_with_timeout, relay_counted_with_buffer, shutdown_udp_flow,
    udp_flow_key, udp_idle_timeout,
};
use crate::{ConnectionMonitor, RuntimeProxySelector};

pub(crate) use yuhaiin_protocol::socks5_server::{
    encode_udp_packet as encode_socks_udp_packet, parse_udp_packet as parse_socks_udp_packet,
};

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
        return serve_socks5_udp_loop(socket, spec, selector, monitor, Some(peer.ip())).await;
    }
    let destination = request.destination;
    let source = Endpoint::ip(Network::Tcp, peer);
    let mut context = FlowContext::new(destination.clone());
    context.source = Some(source);
    context.original_domain = destination.host().cloned();
    spec.annotate_context(&mut context);
    selector.route_context(&mut context);
    let process = context.process.clone();
    let proxy = selector.select(&context);
    let outbound = match proxy.connect(&context).await {
        Ok(outbound) => outbound,
        Err(error) => {
            yuhaiin_protocol::socks5_server::write_reply(&mut stream, 5).await?;
            monitor.record_failure_with_process(
                "socks5",
                &destination.to_string(),
                &error.to_string(),
                process.as_deref(),
            );
            return Err(error);
        }
    };
    yuhaiin_protocol::socks5_server::write_reply(&mut stream, 0).await?;
    relay_counted_with_buffer(
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
        selector.relay_buffer_size(),
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
    allowed_peer: Option<IpAddr>,
) -> Result<()> {
    let udp_buffer_size = selector.udp_buffer_size().max(512);
    let udp_ringbuffer_size = selector.udp_ringbuffer_size().max(1);
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpReply>(udp_ringbuffer_size);
    let mut flows = HashMap::<UdpFlowId, UdpFlowState>::new();
    let mut close_events = monitor.subscribe_close_requests();
    let idle_timeout = udp_idle_timeout();
    let mut idle_tick = tokio::time::interval(idle_timeout);
    let mut client = None;
    let mut packet = vec![0u8; udp_buffer_size];
    loop {
        tokio::select! {
            received = socket.recv_from(&mut packet) => {
                let (length, peer) = received.map_err(io_error)?;
                if allowed_peer.is_some_and(|allowed| allowed != peer.ip()) {
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
                if target.port() == Some(53)
                    && let Some(answer) = answer_dns_packet(&monitor, payload).await
                {
                    if let Ok(response) = answer {
                        let packet = encode_socks_udp_packet(&target, &response)?;
                        socket.send_to(&packet, peer).await.map_err(io_error)?;
                    }
                    continue;
                }
                let id = UdpFlowId {
                    peer,
                    target: target.clone(),
                    authentication: None,
                };
                let state = if let Some(state) = flows.get(&id) {
                    state
                } else {
                    let source = Endpoint::ip(Network::Udp, peer);
                    let mut context = FlowContext::new(target.clone());
                    context.source = Some(source.clone());
                    context.original_domain = target.host().cloned();
                    spec.annotate_context(&mut context);
                    selector.route_context(&mut context);
                    let key = udp_flow_key(peer, &target);
                    let datagram = selector.select(&context).open_datagram(&context).await?;
                    let datagram: Arc<dyn AsyncDatagram> = Arc::from(datagram);
                    let observation =
                        FlowObserverGuard::open(monitor.clone(), TunFlow { key }, context);
                    let receiver = Arc::clone(&datagram);
                    let reply_tx = reply_tx.clone();
                    let id_for_task = id.clone();
                    let receiver_task = tokio::spawn(async move {
                        let mut buffer = vec![0u8; udp_buffer_size];
                        while let Ok((length, target)) = receiver.recv_from(&mut buffer).await {
                            if reply_tx.send(UdpReply {
                                id: id_for_task.clone(),
                                target,
                                payload: buffer[..length].to_vec(),
                            }).await.is_err() {
                                break;
                            }
                        }
                    });
                    flows.entry(id.clone()).or_insert(UdpFlowState {
                        datagram,
                        receiver_task,
                        key,
                        peer: source,
                        last_seen: std::time::Instant::now(),
                        _observation: observation,
                    })
                };
                state.datagram.send_to(payload, target).await?;
                monitor.bytes(state.key, TunFlowDirection::Upload, payload.len());
                if let Some(state) = flows.get_mut(&id) {
                    state.last_seen = std::time::Instant::now();
                }
            }
            close_event = close_events.recv() => {
                match close_event {
                    Ok(flow) => {
                        close_udp_flows(&mut flows, flow).await;
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
                if let Some(state) = flows.get_mut(&reply.id) {
                    state.last_seen = std::time::Instant::now();
                }
            }
            _ = idle_tick.tick() => {
                reap_expired_udp_flows_with_timeout(&mut flows, idle_timeout).await;
            }
            else => break,
        }
    }
    for state in flows.into_values() {
        shutdown_udp_flow(state).await;
    }
    let _ = spec;
    Ok(())
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
