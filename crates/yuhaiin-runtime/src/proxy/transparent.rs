//! Linux transparent TCP inbound adapters.
//!
//! `tproxy` receives the original destination from the accepted socket's
//! local address, while `redir` obtains it through `SO_ORIGINAL_DST`.  The
//! socket setup is isolated here because it is Linux capability/namespace
//! dependent; after the destination is recovered, both protocols use the
//! ordinary runtime router and outbound relay.

use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;

use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, SockaddrStorage, getsockopt, recvmsg, setsockopt, sockopt,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use yuhaiin_core::flow::{
    Flow as TunFlow, FlowDirection as TunFlowDirection, FlowKey as TunFlowKey,
    FlowObserver as TunFlowObserver, FlowObserverGuard,
};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxySelector};
use yuhaiin_core::{Endpoint, Error, ErrorKind, FlowContext, Network, Result};

use super::common::{
    UdpFlowId, UdpFlowState, UdpReply, answer_dns_packet, close_udp_flows, io_error,
    relay_counted_with_buffer, udp_flow_key,
};
use crate::inbound::InboundSpec;
use crate::{ConnectionMonitor, RuntimeProxySelector};

const BACKLOG: i32 = 256;

pub(crate) async fn serve_listener(
    listen: SocketAddr,
    protocol: String,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()> {
    let listener = bind_listener(listen, protocol.eq_ignore_ascii_case("tproxy"))?;
    let mut connections = JoinSet::new();
    let result = async {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, peer) = accepted.map_err(io_error)?;
                    let protocol = protocol.clone();
                    let spec = spec.clone();
                    let selector = selector.clone();
                    let monitor = monitor.clone();
                    connections.spawn(async move {
                        handle_connection(stream, peer, &protocol, spec, selector, monitor).await
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        monitor.warn(format!("transparent connection task stopped: {error}"));
                    } else if let Ok(Err(error)) = result {
                        monitor.warn(format!("transparent connection failed: {error}"));
                    }
                }
            }
        }
    }
    .await;
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    result
}

pub(crate) async fn serve_udp_listener(
    listen: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()> {
    let socket = bind_udp_socket(listen)?;
    let udp_buffer_size = selector.udp_buffer_size().max(512);
    let udp_ringbuffer_size = selector.udp_ringbuffer_size().max(1);
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpReply>(udp_ringbuffer_size);
    let mut flows = HashMap::<UdpFlowId, UdpFlowState>::new();
    let mut close_events = monitor.subscribe_close_requests();
    let mut packet = vec![0u8; udp_buffer_size];
    loop {
        tokio::select! {
            received = recv_udp(&socket, &mut packet) => {
                let (length, peer, destination) = received?;
                let target = Endpoint::ip(Network::Udp, destination);
                if target.port() == Some(53) {
                    if let Some(answer) = answer_dns_packet(&monitor, &packet[..length]).await {
                        if let Ok(response) = answer {
                            send_udp_reply(&response, destination, peer).await?;
                        }
                        continue;
                    }
                }
                let id = UdpFlowId { peer, target: target.clone() };
                let state = if let Some(state) = flows.get(&id) {
                    state
                } else {
                    let source = Endpoint::ip(Network::Udp, peer);
                    let mut context = FlowContext::new(target.clone());
                    context.source = Some(source.clone());
                    spec.annotate_context(&mut context);
                    selector.route_context(&mut context);
                    let key = udp_flow_key(peer, &target);
                    let datagram: Arc<dyn AsyncDatagram> =
                        Arc::from(selector.select(&context).open_datagram(&context).await?);
                    let observation =
                        FlowObserverGuard::open(monitor.clone(), TunFlow { key }, context);
                    let receiver = Arc::clone(&datagram);
                    let reply_tx = reply_tx.clone();
                    let id_for_task = id.clone();
                    tokio::spawn(async move {
                        let mut buffer = vec![0u8; udp_buffer_size];
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
                        _observation: observation,
                    })
                };
                state.datagram.send_to(&packet[..length], target).await?;
                monitor.bytes(state.key, TunFlowDirection::Upload, length);
            }
            close_event = close_events.recv() => {
                match close_event {
                    Ok(flow) => close_udp_flows(&mut flows, flow).await,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            Some(reply) = reply_rx.recv() => {
                let Some(state) = flows.get(&reply.id) else { continue; };
                let Some(client) = state.peer.addr() else { continue; };
                let original_target = state.key.destination;
                send_udp_reply(&reply.payload, original_target, client).await?;
                monitor.bytes(state.key, TunFlowDirection::Download, reply.payload.len());
            }
            else => break,
        }
    }
    for state in flows.into_values() {
        let _ = state.datagram.close().await;
        drop(state);
    }
    Ok(())
}

fn bind_listener(listen: SocketAddr, transparent: bool) -> Result<TcpListener> {
    let domain = if listen.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)).map_err(io_error)?;
    socket.set_reuse_address(true).map_err(io_error)?;
    if transparent {
        if listen.is_ipv4() {
            socket
                .set_ip_transparent_v4(true)
                .map_err(|error| capability_error("IP_TRANSPARENT", error))?;
        } else {
            socket
                .set_ip_transparent_v6(true)
                .map_err(|error| capability_error("IPV6_TRANSPARENT", error))?;
        }
    }
    socket
        .bind(&listen.into())
        .map_err(|error| capability_error("transparent bind", error))?;
    socket.listen(BACKLOG).map_err(io_error)?;
    socket.set_nonblocking(true).map_err(io_error)?;
    let listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(listener).map_err(io_error)
}

fn bind_udp_socket(listen: SocketAddr) -> Result<AsyncFd<Socket>> {
    let domain = if listen.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(io_error)?;
    socket.set_reuse_address(true).map_err(io_error)?;
    if listen.is_ipv4() {
        socket
            .set_ip_transparent_v4(true)
            .map_err(|error| capability_error("IP_TRANSPARENT", error))?;
        setsockopt(&socket, sockopt::Ipv4OrigDstAddr, &true).map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("IP_ORIGDSTADDR socket option failed: {error}"),
            )
        })?;
    } else {
        socket
            .set_ip_transparent_v6(true)
            .map_err(|error| capability_error("IPV6_TRANSPARENT", error))?;
        setsockopt(&socket, sockopt::Ipv6OrigDstAddr, &true).map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("IPV6_ORIGDSTADDR socket option failed: {error}"),
            )
        })?;
    }
    socket
        .bind(&listen.into())
        .map_err(|error| capability_error("transparent UDP bind", error))?;
    socket.set_nonblocking(true).map_err(io_error)?;
    AsyncFd::new(socket).map_err(io_error)
}

async fn recv_udp(
    socket: &AsyncFd<Socket>,
    payload: &mut [u8],
) -> Result<(usize, SocketAddr, SocketAddr)> {
    loop {
        let mut guard = socket.readable().await.map_err(io_error)?;
        match guard.try_io(|inner| recv_udp_now(inner.get_ref(), payload)) {
            Ok(result) => return result.map_err(io_error),
            Err(_would_block) => continue,
        }
    }
}

fn recv_udp_now(
    socket: &Socket,
    payload: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut iov = [IoSliceMut::new(payload)];
    let mut cmsg = nix::cmsg_space!(nix::libc::sockaddr_in, nix::libc::sockaddr_in6);
    let message = recvmsg::<SockaddrStorage>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::MSG_DONTWAIT,
    )
    .map_err(errno_to_io)?;
    let peer = message
        .address
        .as_ref()
        .and_then(sockaddr_to_socket_addr)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "UDP peer address missing"))?;
    let destination = message
        .cmsgs()
        .map_err(errno_to_io)?
        .find_map(|message| match message {
            ControlMessageOwned::Ipv4OrigDstAddr(address) => Some(SocketAddr::new(
                IpAddr::V4(decode_original_ipv4(address.sin_addr.s_addr)),
                u16::from_be(address.sin_port),
            )),
            ControlMessageOwned::Ipv6OrigDstAddr(address) => Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)),
                u16::from_be(address.sin6_port),
            )),
            _ => None,
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "transparent UDP original destination missing",
            )
        })?;
    Ok((message.bytes, peer, destination))
}

fn sockaddr_to_socket_addr(address: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(address) = address.as_sockaddr_in() {
        return Some(SocketAddr::new(IpAddr::V4(address.ip()), address.port()));
    }
    address
        .as_sockaddr_in6()
        .map(|address| SocketAddr::new(IpAddr::V6(address.ip()), address.port()))
}

fn decode_original_ipv4(raw: u32) -> Ipv4Addr {
    // Linux exposes the network-order address through a native-endian
    // integer. `from_be` restores the integer representation expected by
    // `Ipv4Addr::from` on every target endian.
    Ipv4Addr::from(u32::from_be(raw))
}

async fn send_udp_reply(payload: &[u8], source: SocketAddr, destination: SocketAddr) -> Result<()> {
    if source.is_ipv4() != destination.is_ipv4() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "transparent UDP reply address families differ",
        ));
    }
    let domain = if source.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(io_error)?;
    socket.set_reuse_address(true).map_err(io_error)?;
    if source.is_ipv4() {
        socket
            .set_ip_transparent_v4(true)
            .map_err(|error| capability_error("IP_TRANSPARENT", error))?;
    } else {
        socket
            .set_ip_transparent_v6(true)
            .map_err(|error| capability_error("IPV6_TRANSPARENT", error))?;
    }
    socket.bind(&source.into()).map_err(io_error)?;
    socket.connect(&destination.into()).map_err(io_error)?;
    socket.set_nonblocking(true).map_err(io_error)?;
    let socket = tokio::net::UdpSocket::from_std(socket.into()).map_err(io_error)?;
    socket.send(payload).await.map_err(io_error)?;
    Ok(())
}

fn errno_to_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    protocol: &str,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()> {
    let destination = if protocol.eq_ignore_ascii_case("tproxy") {
        stream.local_addr().map_err(io_error)?
    } else {
        original_destination(&stream)?
    };
    if destination.ip().is_unspecified() || destination.port() == 0 {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("{protocol} did not provide a usable original destination"),
        ));
    }
    let endpoint = Endpoint::ip(Network::Tcp, destination);
    let mut context = FlowContext::new(endpoint.clone());
    context.source = Some(Endpoint::ip(Network::Tcp, peer));
    spec.annotate_context(&mut context);
    selector.route_context(&mut context);
    let outbound = selector
        .select(&context)
        .connect(&context)
        .await
        .map_err(|error| {
            monitor.record_failure(protocol, &endpoint.to_string(), &error.to_string());
            error
        })?;
    relay_counted_with_buffer(
        stream,
        outbound,
        TunFlowKey {
            network: Network::Tcp,
            source: peer,
            destination,
        },
        context,
        monitor,
        selector.relay_buffer_size(),
    )
    .await
    .map_err(io_error)
}

fn original_destination(stream: &TcpStream) -> Result<SocketAddr> {
    let local = stream.local_addr().map_err(io_error)?;
    if local.is_ipv4() {
        let raw = getsockopt(stream, sockopt::OriginalDst).map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("SO_ORIGINAL_DST unavailable for redir inbound: {error}"),
            )
        })?;
        return Ok(SocketAddr::new(
            // `sin_addr` is stored in network byte order but exposed as a
            // native-endian integer by libc on Linux. Converting from network
            // order avoids reversing 10.254.0.3 into 3.0.254.10.
            IpAddr::V4(decode_original_ipv4(raw.sin_addr.s_addr)),
            u16::from_be(raw.sin_port),
        ));
    }
    let raw = getsockopt(stream, sockopt::Ip6tOriginalDst).map_err(|error| {
        Error::new(
            ErrorKind::Io,
            format!("IP6T_SO_ORIGINAL_DST unavailable for redir inbound: {error}"),
        )
    })?;
    Ok(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::from(raw.sin6_addr.s6_addr)),
        u16::from_be(raw.sin6_port),
    ))
}

fn capability_error(option: &str, error: std::io::Error) -> Error {
    Error::new(
        ErrorKind::Io,
        format!("Linux transparent socket option {option} failed: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn redir_listener_binds_an_ephemeral_tcp_port_without_transparent_capability() {
        let listener = bind_listener("127.0.0.1:0".parse().unwrap(), false).unwrap();
        assert_ne!(listener.local_addr().unwrap().port(), 0);
    }

    #[test]
    fn original_destination_ipv4_decodes_network_order() {
        let raw = u32::from_ne_bytes([10, 254, 0, 3]);
        assert_eq!(decode_original_ipv4(raw), Ipv4Addr::new(10, 254, 0, 3));
    }
}
