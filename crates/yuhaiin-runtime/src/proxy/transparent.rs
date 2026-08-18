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
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxySelector, BoxAsyncStream};
use yuhaiin_core::{Endpoint, Error, ErrorKind, FlowContext, Network, Result};

use super::common::{
    UdpFlowId, UdpFlowState, UdpReply, answer_dns_packet, close_udp_flows, io_error,
    reap_expired_udp_flows_with_timeout, record_outbound_datagram, record_outbound_stream,
    relay_counted_with_buffer, shutdown_udp_flow, udp_flow_key, udp_idle_timeout,
};
use crate::inbound::{InboundSpec, InboundTlsAcceptor, prepare_inbound_stream};
use crate::{ConnectionMonitor, RuntimeProxySelector};

const BACKLOG: i32 = 256;

pub(crate) async fn serve_listener(
    listen: SocketAddr,
    protocol: String,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    tls_acceptor: Option<InboundTlsAcceptor>,
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
                    let tls_acceptor = tls_acceptor.clone();
                    connections.spawn(async move {
                        handle_connection(
                            stream,
                            peer,
                            &protocol,
                            spec,
                            selector,
                            monitor,
                            tls_acceptor,
                        )
                        .await
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
    monitor.info(format!("transparent UDP listener ready at {listen}"));
    let udp_buffer_size = selector.udp_buffer_size().max(512);
    let udp_ringbuffer_size = selector.udp_ringbuffer_size().max(1);
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpReply>(udp_ringbuffer_size);
    let mut flows = HashMap::<UdpFlowId, UdpFlowState>::new();
    let mut close_events = monitor.subscribe_close_requests();
    let idle_timeout = udp_idle_timeout();
    let mut idle_tick = tokio::time::interval(idle_timeout);
    let mut packet = vec![0u8; udp_buffer_size];
    loop {
        tokio::select! {
            received = recv_udp(&socket, &mut packet) => {
                let (length, peer, destination) = match received {
                    Ok(received) => received,
                    Err(error) => {
                        monitor.error(format!("transparent UDP receive failed: {error}"));
                        return Err(error);
                    }
                };
                let target = Endpoint::ip(Network::Udp, destination);
                if target.port() == Some(53)
                    && let Some(answer) = answer_dns_packet(&monitor, &packet[..length]).await
                {
                    if let Ok(response) = answer {
                        send_udp_reply(&response, destination, peer).await?;
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
                    spec.annotate_context(&mut context);
                    selector.route_context(&mut context);
                    let key = udp_flow_key(peer, &target);
                    let datagram: Arc<dyn AsyncDatagram> = match selector
                        .select(&context)
                        .open_datagram(&context)
                        .await
                    {
                        Ok(datagram) => {
                            record_outbound_datagram(&mut context, &*datagram);
                            Arc::from(datagram)
                        }
                        Err(error) => {
                            monitor.error(format!("transparent UDP open outbound failed: {error}"));
                            return Err(error);
                        }
                    };
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
                if let Err(error) = state.datagram.send_to(&packet[..length], target).await {
                    monitor.error(format!("transparent UDP send outbound failed: {error}"));
                    return Err(error);
                }
                monitor.bytes(state.key, TunFlowDirection::Upload, length);
                if let Some(state) = flows.get_mut(&id) {
                    state.last_seen = std::time::Instant::now();
                }
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
                if let Err(error) = send_udp_reply(&reply.payload, original_target, client).await {
                    monitor.error(format!("transparent UDP send reply failed: {error}"));
                    return Err(error);
                }
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
        if !socket
            .ip_transparent_v4()
            .map_err(|error| capability_error("IP_TRANSPARENT readback", error))?
        {
            return Err(Error::new(
                ErrorKind::Io,
                "IP_TRANSPARENT readback was disabled",
            ));
        }
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
        if !socket
            .ip_transparent_v6()
            .map_err(|error| capability_error("IPV6_TRANSPARENT readback", error))?
        {
            return Err(Error::new(
                ErrorKind::Io,
                "IPV6_TRANSPARENT readback was disabled",
            ));
        }
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
    // Keep this post-bind as well as the pre-bind setup above. Go's
    // net.ListenUDP path applies the transparent option after bind, and this
    // makes the Rust socket contract explicit for kernels that inspect the
    // bound UDP socket during TPROXY lookup.
    if listen.is_ipv4() {
        socket
            .set_ip_transparent_v4(true)
            .map_err(|error| capability_error("IP_TRANSPARENT post-bind", error))?;
        if !socket
            .ip_transparent_v4()
            .map_err(|error| capability_error("IP_TRANSPARENT post-bind readback", error))?
        {
            return Err(Error::new(
                ErrorKind::Io,
                "IP_TRANSPARENT post-bind readback was disabled",
            ));
        }
    } else {
        socket
            .set_ip_transparent_v6(true)
            .map_err(|error| capability_error("IPV6_TRANSPARENT post-bind", error))?;
        if !socket
            .ip_transparent_v6()
            .map_err(|error| capability_error("IPV6_TRANSPARENT post-bind readback", error))?
        {
            return Err(Error::new(
                ErrorKind::Io,
                "IPV6_TRANSPARENT post-bind readback was disabled",
            ));
        }
    }
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
    tls_acceptor: Option<InboundTlsAcceptor>,
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
    let stream = prepare_inbound_stream(stream, &spec, tls_acceptor, false).await?;
    handle_transparent_stream(stream, peer, protocol, spec, selector, monitor, destination).await
}

async fn handle_transparent_stream(
    stream: BoxAsyncStream,
    peer: SocketAddr,
    protocol: &str,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    destination: SocketAddr,
) -> Result<()> {
    let endpoint = Endpoint::ip(Network::Tcp, destination);
    let mut context = FlowContext::new(endpoint.clone());
    context.source = Some(Endpoint::ip(Network::Tcp, peer));
    spec.annotate_context(&mut context);
    selector.route_context(&mut context);
    let process = context.process.clone();
    let outbound = selector
        .select(&context)
        .connect(&context)
        .await
        .inspect_err(|error| {
            monitor.record_failure_with_process(
                protocol,
                &endpoint.to_string(),
                &error.to_string(),
                process.as_deref(),
            );
        })?;
    record_outbound_stream(&mut context, &outbound);
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
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
    use yuhaiin_store::{ConfigStore, GoNodeRecord};

    #[cfg(feature = "doh-tls")]
    use std::io::Cursor;

    #[cfg(feature = "doh-tls")]
    use rustls::pki_types::ServerName;
    #[cfg(feature = "doh-tls")]
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    #[cfg(feature = "doh-tls")]
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[cfg(feature = "doh-tls")]
    const CA_CERTIFICATE_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBlTCCATugAwIBAgIUbS/bRRel4PtBGY4lbCYyc2lxKngwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNeXVoYWlpbi1wMC1jYTAeFw0yNjA4MDYxODIwMzRaFw0zNjA4
MDMxODIwMzRaMBgxFjAUBgNVBAMMDXl1aGFpaW4tcDAtY2EwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAATBHNZR0dSTLNKfYwheVmhyGdCeMBSibhHEGBzXtZ6v0nIA
DhHIIK38v1qnoiTWN9Fof8HXKfhvl1LxSY0rSqe0o2MwYTAdBgNVHQ4EFgQUhaYk
OXheQ1JzLpIKK4I2FEcRMyMwHwYDVR0jBBgwFoAUhaYkOXheQ1JzLpIKK4I2FEcR
MyMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID
SAAwRQIhAOzmDAm07/ezq+5WBQhYYOi/F1onvS4skssoRtRq8w8XAiBH0LCIlJk5
QX0jqAZz0309NRht+WWJtz28CPHvuhGXNg==
-----END CERTIFICATE-----
"#;

    #[cfg(feature = "doh-tls")]
    const LEAF_CERTIFICATE_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUA6T+/U88N9aMPipK+MdNsAFRUAUwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNeXVoYWlpbi1wMC1jYTAeFw0yNjA4MDYxODIwNDlaFw0zNjA4
MDMxODIwNDlaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABLPnwlYFERi1MgbJNuBHZV/eSpTGdJCQIOyxBt8LlR1ZTEG06pWy
FnJVIzUS4oPuuHc0RcDEltGb/WolyQlM75SjbTBrMBQGA1UdEQQNMAuCCWxvY2Fs
aG9zdDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUZoMmXETR998IsWt1
UTBOVMIs7jMwHwYDVR0jBBgwFoAUhaYkOXheQ1JzLpIKK4I2FEcRMyMwCgYIKoZI
zj0EAwIDSAAwRQIgGEU+sldusbLVAE/kxzZYXaMpIt6l+CZ0cC2jm7lQBqoCIQCw
M5PhuwMhCCb+dUnK6ueJUMHwyK3l2pIAJTMp9+cwqw==
-----END CERTIFICATE-----
"#;

    #[cfg(feature = "doh-tls")]
    const PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqkH6SeIb9vVEJ6WecsMk5Pn/a8sQ+vdNS/ZSkl3KwfoAoGCCqGSM49
AwEHoUQDQgAEs+fCVgURGLUyBsk24EdlX95KlMZ0kJAg7LEG3wuVHVlMQbTqlbIW
clUjNRLig+64dzRFwMSW0Zv9aiXJCUzvlA==
-----END EC PRIVATE KEY-----
"#;

    #[cfg(feature = "doh-tls")]
    fn transparent_tls_acceptor() -> TlsAcceptor {
        let certificate = rustls_pemfile::certs(&mut Cursor::new(LEAF_CERTIFICATE_PEM))
            .next()
            .unwrap()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY_PEM))
            .unwrap()
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }

    #[cfg(feature = "doh-tls")]
    fn transparent_tls_connector() -> TlsConnector {
        let mut roots = RootCertStore::empty();
        let certificate = rustls_pemfile::certs(&mut Cursor::new(CA_CERTIFICATE_PEM))
            .next()
            .unwrap()
            .unwrap();
        roots.add(certificate).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }

    async fn direct_test_runtime() -> (Arc<RuntimeProxySelector>, Arc<ConnectionMonitor>) {
        use crate::{RuntimeBuilder, RuntimeController};

        let store = ConfigStore::open_memory().await.unwrap();
        let controller = RuntimeController::from_builder(RuntimeBuilder::new(
            store,
            Arc::new(SystemAsyncIpResolver),
        ))
        .await
        .unwrap();
        controller
            .store()
            .repository()
            .put_go_node(&GoNodeRecord {
                id: "direct".to_owned(),
                name: "Direct".to_owned(),
                group_name: "default".to_owned(),
                origin: "transparent-test".to_owned(),
                enabled: true,
                chain_types_json: br#"["direct"]"#.to_vec(),
                updated_at: 1,
                data_json: br#"{"protocol":"direct"}"#.to_vec(),
            })
            .await
            .unwrap();
        controller.reload().await.unwrap();
        let selector = controller
            .build_proxy_selector("", "direct", "", "", Duration::from_secs(2))
            .await
            .unwrap();
        (selector, controller.monitor())
    }

    #[test]
    fn transparent_transport_allowlist_preserves_original_destination() {
        for transport in ["normal", "tls", "tls_auto", "aead", "http_mock"] {
            assert!(
                crate::inbound::is_supported_transparent_transport(transport),
                "transparent transport {transport} should be accepted"
            );
        }
        for transport in ["http2", "websocket", "proxy", "mux", "reality", "quic"] {
            assert!(
                !crate::inbound::is_supported_transparent_transport(transport),
                "transparent transport {transport} must not lose the original destination"
            );
        }
    }

    #[tokio::test]
    async fn transparent_aead_transport_is_unwrapped_before_relay() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_test_runtime().await;
        let server_task = tokio::spawn(async move {
            let (stream, peer) = inbound_listener.accept().await.unwrap();
            let spec = InboundSpec {
                id: "transparent-aead".to_owned(),
                name: "transparent-aead".to_owned(),
                protocol: "redir".to_owned(),
                listen: inbound,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: crate::inbound::UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["aead".to_owned()],
                aead_password: Some("secret".to_owned()),
                aead_method: yuhaiin_protocol::aead::CryptoMethod::XChacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            };
            let stream = prepare_inbound_stream(stream, &spec, None, false)
                .await
                .unwrap();
            handle_transparent_stream(stream, peer, "redir", spec, selector, monitor, target)
                .await
                .unwrap();
        });

        let mut client = yuhaiin_protocol::aead::client(
            Box::new(TcpStream::connect(inbound).await.unwrap()),
            b"secret",
            yuhaiin_protocol::aead::CryptoMethod::XChacha20Poly1305,
        )
        .await
        .unwrap();
        client.write_all(b"transparent-aead-payload").await.unwrap();
        client.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"transparent-aead-payload");

        server_task.await.unwrap();
        target_task.await.unwrap();
    }

    #[cfg(feature = "doh-tls")]
    #[tokio::test]
    async fn transparent_tls_transport_is_unwrapped_before_relay() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_test_runtime().await;
        let acceptor = transparent_tls_acceptor();
        let server_task = tokio::spawn(async move {
            let (stream, peer) = inbound_listener.accept().await.unwrap();
            let spec = InboundSpec {
                id: "transparent-tls".to_owned(),
                name: "transparent-tls".to_owned(),
                protocol: "redir".to_owned(),
                listen: inbound,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: crate::inbound::UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["tls".to_owned()],
                aead_password: None,
                aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            };
            let stream = prepare_inbound_stream(stream, &spec, Some(acceptor), false)
                .await
                .unwrap();
            handle_transparent_stream(stream, peer, "redir", spec, selector, monitor, target)
                .await
                .unwrap();
        });

        let connector = transparent_tls_connector();
        let mut client = connector
            .connect(
                ServerName::try_from("localhost".to_owned()).unwrap(),
                TcpStream::connect(inbound).await.unwrap(),
            )
            .await
            .unwrap();
        client.write_all(b"transparent-tls-payload").await.unwrap();
        client.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"transparent-tls-payload");

        server_task.await.unwrap();
        target_task.await.unwrap();
    }

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

    #[test]
    fn recv_udp_now_reads_linux_ipv4_original_destination_ancillary() {
        let receiver = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        setsockopt(&receiver, sockopt::Ipv4OrigDstAddr, &true).unwrap();
        receiver
            .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        receiver.set_nonblocking(true).unwrap();
        let destination = receiver.local_addr().unwrap().as_socket().unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"ipv4-orig-dst", destination).unwrap();

        let mut payload = [0u8; 64];
        let (length, peer, original) = recv_until_ready(&receiver, &mut payload);
        assert_eq!(&payload[..length], b"ipv4-orig-dst");
        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(original, destination);
    }

    #[test]
    fn recv_udp_now_reads_linux_ipv6_original_destination_ancillary() {
        let receiver = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        setsockopt(&receiver, sockopt::Ipv6OrigDstAddr, &true).unwrap();
        receiver
            .bind(&"[::1]:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        receiver.set_nonblocking(true).unwrap();
        let destination = receiver.local_addr().unwrap().as_socket().unwrap();
        let sender = std::net::UdpSocket::bind("[::1]:0").unwrap();
        sender.send_to(b"ipv6-orig-dst", destination).unwrap();

        let mut payload = [0u8; 64];
        let (length, peer, original) = recv_until_ready(&receiver, &mut payload);
        assert_eq!(&payload[..length], b"ipv6-orig-dst");
        assert_eq!(peer.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(original, destination);
    }

    fn recv_until_ready(socket: &Socket, payload: &mut [u8]) -> (usize, SocketAddr, SocketAddr) {
        for _ in 0..100 {
            match recv_udp_now(socket, payload) {
                Ok(result) => return result,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("receive original destination ancillary: {error}"),
            }
        }
        panic!("timed out waiting for original destination ancillary");
    }
}
