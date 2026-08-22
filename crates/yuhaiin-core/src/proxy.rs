//! Asynchronous stream and datagram proxy primitives.

use std::any::Any;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use crate::DomainName;
use crate::{BoxFuture, FlowContext, Network};
use crate::{Endpoint, Error, ErrorKind, Result};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::Notify;
use tokio::time::Sleep;

/// Internal marker used by the runtime for Go's `useDefaultInterface` mode.
/// It is resolved to the current physical default-route interface immediately
/// before each outbound socket is bound, rather than when a runtime snapshot
/// is built.
pub const DEFAULT_INTERFACE: &str = "__yuhaiin_default_interface__";

pub async fn connect_tokio_tcp(
    address: SocketAddr,
    local_bind: Option<SocketAddr>,
    timeout: Duration,
) -> Result<tokio::net::TcpStream> {
    connect_tokio_tcp_with_interface(address, local_bind, None, timeout).await
}

pub async fn connect_tokio_tcp_with_interface(
    address: SocketAddr,
    local_bind: Option<SocketAddr>,
    bind_interface: Option<&str>,
    timeout: Duration,
) -> Result<tokio::net::TcpStream> {
    if local_bind.is_some_and(|local| local.is_ipv4() != address.is_ipv4()) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "local bind address and TCP destination use different address families",
        ));
    }
    let socket = if address.is_ipv4() {
        tokio::net::TcpSocket::new_v4()
    } else {
        tokio::net::TcpSocket::new_v6()
    }
    .map_err(|error| Error::new(ErrorKind::Io, format!("create TCP socket: {error}")))?;
    bind_tokio_tcp_socket_to_interface(&socket, interface_for_address(address, bind_interface))?;
    if let Some(local_bind) = local_bind {
        socket
            .bind(local_bind)
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind TCP socket: {error}")))?;
    }
    tokio::time::timeout(timeout, socket.connect(address))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "TCP connect timed out"))?
        .map_err(|error| Error::new(ErrorKind::Io, format!("TCP connect: {error}")))
}

pub fn bind_socket_to_interface(socket: &Socket, bind_interface: Option<&str>) -> Result<()> {
    let Some(interface) = bind_interface.and_then(resolve_bind_interface) else {
        return Ok(());
    };
    bind_socket_to_interface_platform(socket, &interface)
}

fn resolve_bind_interface(bind_interface: &str) -> Option<String> {
    let bind_interface = bind_interface.trim();
    if bind_interface.is_empty() {
        return None;
    }
    if bind_interface == DEFAULT_INTERFACE {
        return default_route_interface();
    }
    Some(bind_interface.to_owned())
}

fn interface_for_address(address: SocketAddr, bind_interface: Option<&str>) -> Option<&str> {
    if address.ip().is_loopback()
        && bind_interface.is_some_and(|interface| interface.trim() == DEFAULT_INTERFACE)
    {
        None
    } else {
        bind_interface
    }
}

#[cfg(target_os = "linux")]
fn default_route_interface() -> Option<String> {
    std::fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|content| default_route_interface_v4(&content))
        .or_else(|| {
            std::fs::read_to_string("/proc/net/ipv6_route")
                .ok()
                .and_then(|content| default_route_interface_v6(&content))
        })
}

#[cfg(not(target_os = "linux"))]
fn default_route_interface() -> Option<String> {
    // Non-Linux platforms use the OS route and the source-address fallback.
    // Keeping the marker unresolved is preferable to binding to a stale or
    // guessed interface name.
    None
}

#[cfg(target_os = "linux")]
fn default_route_interface_v4(content: &str) -> Option<String> {
    content.lines().skip(1).find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
            return None;
        }
        let interface = fields[0];
        (!ignored_default_interface(interface)).then(|| interface.to_owned())
    })
}

#[cfg(target_os = "linux")]
fn default_route_interface_v6(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 10
            || fields[0].len() != 32
            || !fields[0].bytes().all(|byte| byte == b'0')
            || fields[1] != "00000000"
        {
            return None;
        }
        let interface = fields[9];
        (!ignored_default_interface(interface)).then(|| interface.to_owned())
    })
}

#[cfg(target_os = "linux")]
fn ignored_default_interface(interface: &str) -> bool {
    ["tailscale", "wg", "tun", "yuhaiin"]
        .iter()
        .any(|prefix| interface.starts_with(prefix))
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn bind_socket_to_interface_platform(socket: &Socket, interface: &str) -> Result<()> {
    socket
        .bind_device(Some(interface.as_bytes()))
        .map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("bind socket to interface {interface:?}: {error}"),
            )
        })
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
fn bind_socket_to_interface_platform(_socket: &Socket, _interface: &str) -> Result<()> {
    // macOS and Windows use the source-address fallback supplied by the
    // runtime interface snapshot. Their native interface-index APIs are
    // platform-specific and are intentionally kept out of this shared core.
    Ok(())
}

fn bind_tokio_tcp_socket_to_interface(
    socket: &tokio::net::TcpSocket,
    bind_interface: Option<&str>,
) -> Result<()> {
    let Some(interface) = bind_interface.and_then(resolve_bind_interface) else {
        return Ok(());
    };
    bind_tokio_tcp_socket_to_interface_platform(socket, &interface)
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn bind_tokio_tcp_socket_to_interface_platform(
    socket: &tokio::net::TcpSocket,
    interface: &str,
) -> Result<()> {
    socket
        .bind_device(Some(interface.as_bytes()))
        .map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("bind TCP socket to interface {interface:?}: {error}"),
            )
        })
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
fn bind_tokio_tcp_socket_to_interface_platform(
    _socket: &tokio::net::TcpSocket,
    _interface: &str,
) -> Result<()> {
    Ok(())
}

pub async fn bind_tokio_udp_socket_for_target(
    bind_address: SocketAddr,
    target: SocketAddr,
    bind_interface: Option<&str>,
    label: &str,
) -> Result<tokio::net::UdpSocket> {
    bind_tokio_udp_socket_with_target(bind_address, Some(target), bind_interface, label).await
}

async fn bind_tokio_udp_socket_with_target(
    bind_address: SocketAddr,
    target: Option<SocketAddr>,
    bind_interface: Option<&str>,
    label: &str,
) -> Result<tokio::net::UdpSocket> {
    let socket = tokio::net::UdpSocket::bind(bind_address)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("{label} UDP bind: {error}")))?;
    let bind_interface = target.map_or(bind_interface, |target| {
        interface_for_address(target, bind_interface)
    });
    let Some(interface) = bind_interface.and_then(resolve_bind_interface) else {
        return Ok(socket);
    };
    bind_tokio_udp_socket_to_interface(&socket, &interface, label)?;
    Ok(socket)
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn bind_tokio_udp_socket_to_interface(
    socket: &tokio::net::UdpSocket,
    interface: &str,
    label: &str,
) -> Result<()> {
    socket
        .bind_device(Some(interface.as_bytes()))
        .map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("{label} UDP interface {interface:?}: {error}"),
            )
        })
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
fn bind_tokio_udp_socket_to_interface(
    _socket: &tokio::net::UdpSocket,
    _interface: &str,
    _label: &str,
) -> Result<()> {
    Ok(())
}
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send + Any {
    fn as_any(&self) -> &dyn Any;
}

impl<T> AsyncStream for T
where
    T: AsyncRead + AsyncWrite + Unpin + Send + Any,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub type BoxAsyncStream = Box<dyn AsyncStream>;

/// Preserve the socket's local endpoint while protocol layers replace the
/// concrete stream type (TLS, HTTP/2, Yuubinsya, and WebSocket all do this).
/// The runtime uses this metadata for loopback protection; it is deliberately
/// optional because in-memory test streams do not have a socket endpoint.
pub struct LocalAddrStream {
    inner: BoxAsyncStream,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
}

impl LocalAddrStream {
    pub fn new(inner: BoxAsyncStream, local_addr: SocketAddr) -> Self {
        Self {
            inner,
            local_addr: Some(local_addr),
            remote_addr: None,
        }
    }

    fn with_socket_addrs(
        inner: BoxAsyncStream,
        local_addr: Option<SocketAddr>,
        remote_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            inner,
            local_addr,
            remote_addr,
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }
}

impl AsyncRead for LocalAddrStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for LocalAddrStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub fn stream_local_addr(stream: &dyn AsyncStream) -> Option<SocketAddr> {
    stream
        .as_any()
        .downcast_ref::<LocalAddrStream>()
        .and_then(LocalAddrStream::local_addr)
}

pub fn stream_remote_addr(stream: &dyn AsyncStream) -> Option<SocketAddr> {
    stream
        .as_any()
        .downcast_ref::<LocalAddrStream>()
        .and_then(LocalAddrStream::remote_addr)
}

pub fn with_stream_local_addr(
    stream: BoxAsyncStream,
    local_addr: Option<SocketAddr>,
) -> BoxAsyncStream {
    with_stream_socket_addrs(stream, local_addr, None)
}

pub fn with_stream_socket_addrs(
    stream: BoxAsyncStream,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
) -> BoxAsyncStream {
    if (local_addr.is_none() || stream_local_addr(&*stream).is_some())
        && (remote_addr.is_none() || stream_remote_addr(&*stream).is_some())
    {
        return stream;
    }
    Box::new(LocalAddrStream::with_socket_addrs(
        stream,
        local_addr,
        remote_addr,
    ))
}

pub trait AsyncDatagram: Send + Sync {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>>;
    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>>;
    fn local_addr(&self) -> Result<Endpoint>;
    fn close(&self) -> BoxFuture<'_, Result<()>>;
}

pub trait AsyncProxy: Send + Sync {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>>;
    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>>;
    fn ping<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "proxy does not provide ping",
            ))
        })
    }
    fn close(&self) -> BoxFuture<'_, Result<()>>;
}

pub trait AsyncProxySelector: Send + Sync {
    /// Annotate a mutable flow with the route snapshot used for selection.
    /// Static selectors intentionally leave this as a no-op; runtime-backed
    /// selectors use it to keep management metadata and proxy choice aligned.
    fn route_context(&self, _context: &mut FlowContext) {}

    fn select(&self, context: &FlowContext) -> Arc<dyn AsyncProxy>;
}

pub struct StaticProxySelector {
    pub direct: Arc<dyn AsyncProxy>,
    pub proxy: Arc<dyn AsyncProxy>,
    pub bypass: Arc<dyn AsyncProxy>,
    pub drop: Arc<dyn AsyncProxy>,
}

impl AsyncProxySelector for StaticProxySelector {
    fn select(&self, context: &FlowContext) -> Arc<dyn AsyncProxy> {
        match context.route_mode {
            crate::RouteMode::Direct => Arc::clone(&self.direct),
            crate::RouteMode::Proxy => Arc::clone(&self.proxy),
            crate::RouteMode::Bypass => Arc::clone(&self.bypass),
            crate::RouteMode::Block => Arc::clone(&self.drop),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DirectAsyncProxy {
    pub timeout: Duration,
}

static NEXT_ICMP_SEQUENCE: AtomicU16 = AtomicU16::new(1);

impl AsyncProxy for DirectAsyncProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let destination = context.proxy_destination();
        let preferred_ipv4 = context
            .local_bind_addresses
            .first()
            .map(|address| address.is_ipv4());
        let bind_interface = context.bind_interface.clone();
        Box::pin(async move {
            let addresses = resolve_direct_addresses(&destination, preferred_ipv4).await?;
            let mut last_error = None;
            for address in addresses {
                match connect_tokio_tcp_with_interface(
                    address,
                    context.local_bind_for(address),
                    bind_interface.as_deref(),
                    self.timeout,
                )
                .await
                {
                    Ok(stream) => {
                        let local_addr = stream.local_addr().ok();
                        return Ok(with_stream_socket_addrs(
                            Box::new(stream) as BoxAsyncStream,
                            local_addr,
                            Some(address),
                        ));
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| Error::invalid("direct destination has no address")))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let destination = context.proxy_destination();
        let preferred_ipv4 = context
            .local_bind_addresses
            .first()
            .map(|address| address.is_ipv4());
        let bind_interface = context.bind_interface.clone();
        Box::pin(async move {
            let address = resolve_direct_addresses(&destination, preferred_ipv4)
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| Error::invalid("direct destination has no address"))?;
            let bind_address: SocketAddr = match address {
                std::net::SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                std::net::SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
            };
            let bind_address = context.local_bind_for(address).unwrap_or(bind_address);
            let socket = bind_tokio_udp_socket_for_target(
                bind_address,
                address,
                bind_interface.as_deref(),
                "direct",
            )
            .await?;
            Ok(Box::new(TokioDatagram { socket }) as Box<dyn AsyncDatagram>)
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        let destination = context.proxy_destination();
        let preferred_ipv4 = context
            .local_bind_addresses
            .first()
            .map(|address| address.is_ipv4());
        let local_bind_addresses = context.local_bind_addresses.clone();
        let bind_interface = context.bind_interface.clone();
        let timeout = self.timeout;
        Box::pin(async move {
            let addresses = resolve_direct_addresses(&destination, preferred_ipv4).await?;
            let started = std::time::Instant::now();
            let mut last_error = None;
            for address in addresses {
                let target = SocketAddr::new(address.ip(), 0);
                let local_bind = local_bind_addresses
                    .iter()
                    .copied()
                    .find(|local| local.is_ipv4() == target.is_ipv4())
                    .map(|local| SocketAddr::new(local, 0));
                let remaining = timeout.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    last_error = Some(Error::new(ErrorKind::Timeout, "direct ICMP ping timed out"));
                    break;
                }
                match tokio::time::timeout(
                    remaining,
                    direct_icmp_ping_once(target, local_bind, bind_interface.as_deref()),
                )
                .await
                {
                    Ok(Ok(elapsed)) => return Ok(elapsed),
                    Ok(Err(error)) => last_error = Some(error),
                    Err(_) => {
                        last_error = Some(Error::new(
                            ErrorKind::Timeout,
                            format!("direct ICMP ping timed out for {target}"),
                        ));
                    }
                }
            }
            Err(last_error
                .unwrap_or_else(|| Error::invalid("direct destination has no usable ICMP address")))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

async fn direct_icmp_ping_once(
    target: SocketAddr,
    local_bind: Option<SocketAddr>,
    bind_interface: Option<&str>,
) -> Result<Duration> {
    let (domain, protocol) = if target.is_ipv4() {
        (Domain::IPV4, Protocol::ICMPV4)
    } else {
        (Domain::IPV6, Protocol::ICMPV6)
    };
    if local_bind.is_some_and(|local| local.is_ipv4() != target.is_ipv4()) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "local bind address and ICMP destination use different address families",
        ));
    }
    let socket = Socket::new(domain, Type::DGRAM, Some(protocol))
        .map_err(|error| Error::new(ErrorKind::Io, format!("create ICMP socket: {error}")))?;
    bind_socket_to_interface(&socket, interface_for_address(target, bind_interface))?;
    if let Some(local_bind) = local_bind {
        socket
            .bind(&local_bind.into())
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind ICMP socket: {error}")))?;
    }
    socket.set_nonblocking(true).map_err(|error| {
        Error::new(
            ErrorKind::Io,
            format!("set ICMP socket nonblocking: {error}"),
        )
    })?;
    let socket: std::net::UdpSocket = socket.into();
    let socket = tokio::net::UdpSocket::from_std(socket)
        .map_err(|error| Error::new(ErrorKind::Io, format!("adopt ICMP socket: {error}")))?;
    socket
        .connect(target)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("connect ICMP socket: {error}")))?;
    let source = socket
        .local_addr()
        .map_err(|error| Error::new(ErrorKind::Io, format!("read ICMP local address: {error}")))?
        .ip();
    let identifier = (std::process::id() & u32::from(u16::MAX)) as u16;
    let sequence = NEXT_ICMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let payload = icmp_ping_payload(identifier, sequence);
    let packet = build_icmp_echo_request(source, target.ip(), identifier, sequence, &payload)?;
    let started = std::time::Instant::now();
    socket
        .send(&packet)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("send ICMP echo request: {error}")))?;
    let mut response = [0u8; 2048];
    loop {
        let length = socket.recv(&mut response).await.map_err(|error| {
            Error::new(ErrorKind::Io, format!("receive ICMP echo reply: {error}"))
        })?;
        if icmp_echo_reply_matches(&response[..length], target.ip(), sequence, &payload) {
            return Ok(started.elapsed());
        }
    }
}

fn icmp_ping_payload(identifier: u16, sequence: u16) -> Vec<u8> {
    [
        b'y',
        b'u',
        b'h',
        b'a',
        b'i',
        b'i',
        (identifier >> 8) as u8,
        identifier as u8,
        (sequence >> 8) as u8,
        sequence as u8,
        0x52,
        0x75,
        0x73,
        0x74,
        0x50,
        0x69,
    ]
    .to_vec()
}

fn build_icmp_echo_request(
    source: IpAddr,
    destination: IpAddr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut packet = vec![0u8; 8 + payload.len()];
    packet[0] = if destination.is_ipv4() { 8 } else { 128 };
    packet[4..6].copy_from_slice(&identifier.to_be_bytes());
    packet[6..8].copy_from_slice(&sequence.to_be_bytes());
    packet[8..].copy_from_slice(payload);
    let checksum = match (source, destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => internet_checksum(&packet),
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            icmpv6_checksum(source, destination, &packet)
        }
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "ICMP source and destination use different address families",
            ));
        }
    };
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    Ok(packet)
}

fn icmp_echo_reply_matches(
    packet: &[u8],
    destination: IpAddr,
    sequence: u16,
    payload: &[u8],
) -> bool {
    let packet = match destination {
        IpAddr::V4(_) if packet.first().is_some_and(|byte| byte >> 4 == 4) => {
            let header_length = packet
                .first()
                .map(|byte| usize::from(byte & 0x0f) * 4)
                .unwrap_or(0);
            packet.get(header_length..).unwrap_or_default()
        }
        IpAddr::V6(_) if packet.first().is_some_and(|byte| byte >> 4 == 6) => {
            packet.get(40..).unwrap_or_default()
        }
        _ => packet,
    };
    let expected_type = if destination.is_ipv4() { 0 } else { 129 };
    packet.len() >= 8
        && packet[0] == expected_type
        && packet[1] == 0
        && u16::from_be_bytes([packet[6], packet[7]]) == sequence
        && packet[8..] == *payload
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmpv6_checksum(source: Ipv6Addr, destination: Ipv6Addr, packet: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + packet.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(packet.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(packet);
    internet_checksum(&pseudo)
}

/// Resolve a domain only when a caller reaches the low-level direct transport
/// without the runtime's configured resolver wrapper. Runtime traffic still
/// resolves through `ResolvingProxy` first, so hosts/FakeIP/route resolver
/// policy remain authoritative; this fallback prevents standalone direct
/// users from failing merely because they supplied a domain endpoint.
async fn resolve_direct_addresses(
    destination: &Endpoint,
    preferred_ipv4: Option<bool>,
) -> Result<Vec<SocketAddr>> {
    if let Some(address) = destination.addr() {
        return Ok(vec![address]);
    }
    let host = destination
        .host()
        .ok_or_else(|| Error::invalid("direct destination has no host"))?;
    let port = destination
        .port()
        .ok_or_else(|| Error::invalid("direct destination has no port"))?;
    let addresses = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("resolve direct destination {host}:{port}: {error}"),
            )
        })?;
    let addresses = addresses.collect::<Vec<_>>();
    let preferred = addresses
        .iter()
        .copied()
        .filter(|address| preferred_ipv4.is_none_or(|ipv4| address.is_ipv4() == ipv4))
        .collect::<Vec<_>>();
    if !preferred.is_empty() {
        return Ok(preferred);
    }
    if !addresses.is_empty() {
        return Ok(addresses);
    }
    Err(Error::invalid(format!(
        "direct destination {host}:{port} resolved to no usable address"
    )))
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DropAsyncProxy;

impl AsyncProxy for DropAsyncProxy {
    fn connect<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Closed,
                "connection dropped by route policy",
            ))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Closed,
                "datagram dropped by route policy",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// Go's `drop` proxy accepts a flow, acknowledges writes, and silently waits
/// before ending reads.  The wait grows per destination so repeated blocked
/// attempts do not immediately consume CPU or create observable connection
/// errors.  This is deliberately separate from [`DropAsyncProxy`], which is
/// the internal fail-closed placeholder used while a runtime slot is closed.
pub struct DelayedDropAsyncProxy {
    state: Arc<DelayedDropState>,
}

impl Default for DelayedDropAsyncProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl DelayedDropAsyncProxy {
    pub fn new() -> Self {
        Self {
            state: Arc::new(DelayedDropState::default()),
        }
    }
}

const DROP_CACHE_CAPACITY: usize = 512;

const DROP_CACHE_EXPIRY: Duration = Duration::from_secs(5);

const DROP_MAX_DELAY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
struct DelayedDropEntry {
    delay: Duration,
    last_seen: std::time::Instant,
}

#[derive(Default)]
struct DelayedDropState {
    entries: Mutex<HashMap<u64, DelayedDropEntry>>,
}

impl DelayedDropState {
    fn next_delay(&self, destination: &Endpoint) -> Duration {
        let key = destination.comparable_key();
        let now = std::time::Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        match entries.get_mut(&key) {
            Some(entry) if now.duration_since(entry.last_seen) <= DROP_CACHE_EXPIRY => {
                entry.delay = if entry.delay.is_zero() {
                    Duration::from_secs(1)
                } else {
                    (entry.delay * 2).min(DROP_MAX_DELAY)
                };
                entry.last_seen = now;
                entry.delay
            }
            Some(entry) => {
                entry.delay = Duration::ZERO;
                entry.last_seen = now;
                Duration::ZERO
            }
            None => {
                if entries.len() >= DROP_CACHE_CAPACITY
                    && let Some(oldest_key) = entries
                        .iter()
                        .min_by_key(|(_, entry)| entry.last_seen)
                        .map(|(key, _)| *key)
                {
                    entries.remove(&oldest_key);
                }
                entries.insert(
                    key,
                    DelayedDropEntry {
                        delay: Duration::ZERO,
                        last_seen: now,
                    },
                );
                Duration::ZERO
            }
        }
    }
}

struct DelayedDropStream {
    sleep: Option<Pin<Box<Sleep>>>,
}

impl DelayedDropStream {
    fn new(delay: Duration) -> Self {
        Self {
            sleep: (!delay.is_zero()).then(|| Box::pin(tokio::time::sleep(delay))),
        }
    }
}

impl AsyncRead for DelayedDropStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(sleep) = self.sleep.as_mut() {
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.sleep = None;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for DelayedDropStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.sleep = None;
        Poll::Ready(Ok(()))
    }
}

struct DelayedDropDatagram {
    delay: Duration,
    closed: Arc<DelayedDropDatagramState>,
}

struct DelayedDropDatagramState {
    closed: AtomicBool,
    notify: Notify,
}

impl DelayedDropDatagramState {
    fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }
}

impl AsyncDatagram for DelayedDropDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], _target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move { Ok(payload.len()) })
    }

    fn recv_from<'a>(&'a self, _buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        let closed = Arc::clone(&self.closed);
        let delay = self.delay;
        Box::pin(async move {
            if closed.closed.load(Ordering::Acquire) {
                return Err(Error::new(
                    ErrorKind::Closed,
                    "datagram dropped by route policy",
                ));
            }
            let sleep = tokio::time::sleep(delay);
            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut sleep => Err(Error::new(
                    ErrorKind::Closed,
                    "datagram dropped by route policy",
                )),
                _ = closed.notify.notified() => Err(Error::new(
                    ErrorKind::Closed,
                    "datagram dropped by route policy",
                )),
            }
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(Endpoint::ip(
            Network::Udp,
            SocketAddr::from(([0, 0, 0, 0], 0)),
        ))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.closed.closed.store(true, Ordering::Release);
        self.closed.notify.notify_waiters();
        Box::pin(async { Ok(()) })
    }
}

impl AsyncProxy for DelayedDropAsyncProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let delay = self.state.next_delay(&context.effective_destination());
        Box::pin(async move { Ok(Box::new(DelayedDropStream::new(delay)) as BoxAsyncStream) })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let delay = self.state.next_delay(&context.effective_destination());
        Box::pin(async move {
            Ok(Box::new(DelayedDropDatagram {
                delay,
                closed: Arc::new(DelayedDropDatagramState::new()),
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn ping<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Closed,
                "drop proxy does not support ping",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FixedAsyncProxy {
    pub address: SocketAddr,
    pub timeout: Duration,
}

/// Apply one node's per-endpoint interface policy before entering the actual
/// proxy implementation.  Go's fixedv2 model allows alternate addresses to
/// carry their own interface, while the common `FlowContext` keeps the
/// policy at the flow boundary; this adapter bridges those two shapes.
pub struct BindInterfaceProxy {
    pub inner: Arc<dyn AsyncProxy>,
    pub interface: Option<String>,
}

impl BindInterfaceProxy {
    pub fn new(inner: Arc<dyn AsyncProxy>, interface: Option<String>) -> Self {
        Self { inner, interface }
    }

    fn context(&self, context: &FlowContext) -> FlowContext {
        let mut context = context.clone();
        context.bind_interface = self.interface.clone();
        context
    }
}

impl AsyncProxy for BindInterfaceProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let context = self.context(context);
        Box::pin(async move { self.inner.connect(&context).await })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let context = self.context(context);
        Box::pin(async move { self.inner.open_datagram(&context).await })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        let context = self.context(context);
        Box::pin(async move { self.inner.ping(&context).await })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

/// Try the endpoints of one Go fixedv2 node in order.  The first successful
/// endpoint is enough for a flow; failures during a protocol handshake (not
/// just the TCP connect) are deliberately included in the fallback boundary.
pub struct FallbackAsyncProxy {
    pub proxies: Vec<Arc<dyn AsyncProxy>>,
}

impl FallbackAsyncProxy {
    pub fn new(proxies: Vec<Arc<dyn AsyncProxy>>) -> Result<Self> {
        if proxies.is_empty() {
            return Err(Error::invalid("proxy endpoint fallback has no endpoints"));
        }
        Ok(Self { proxies })
    }
}

impl AsyncProxy for FallbackAsyncProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let proxies = self.proxies.clone();
        let context = context.clone();
        Box::pin(async move {
            let mut last_error = None;
            for proxy in proxies {
                match proxy.connect(&context).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| Error::invalid("proxy endpoint fallback failed")))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let proxies = self.proxies.clone();
        let context = context.clone();
        Box::pin(async move {
            let mut last_error = None;
            for proxy in proxies {
                match proxy.open_datagram(&context).await {
                    Ok(datagram) => return Ok(datagram),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| Error::invalid("proxy endpoint fallback failed")))
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        let proxies = self.proxies.clone();
        let context = context.clone();
        Box::pin(async move {
            let mut last_error = None;
            for proxy in proxies {
                match proxy.ping(&context).await {
                    Ok(duration) => return Ok(duration),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| Error::invalid("proxy endpoint fallback failed")))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let mut last_error = None;
            for proxy in &self.proxies {
                if let Err(error) = proxy.close().await {
                    last_error = Some(error);
                }
            }
            last_error.map_or(Ok(()), Err)
        })
    }
}

impl AsyncProxy for FixedAsyncProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let local_bind = context.local_bind_for(self.address);
        let bind_interface = context.bind_interface.clone();
        Box::pin(async move {
            let stream = connect_tokio_tcp_with_interface(
                self.address,
                local_bind,
                bind_interface.as_deref(),
                self.timeout,
            )
            .await?;
            let local_addr = stream.local_addr().ok();
            Ok(with_stream_socket_addrs(
                Box::new(stream) as BoxAsyncStream,
                local_addr,
                Some(self.address),
            ))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let target = self.address;
        let fallback = if target.is_ipv4() {
            "0.0.0.0:0".parse().expect("valid IPv4 wildcard")
        } else {
            "[::]:0".parse().expect("valid IPv6 wildcard")
        };
        let bind_address = context.local_bind_for(target).unwrap_or(fallback);
        let bind_interface = context.bind_interface.clone();
        Box::pin(async move {
            let socket = bind_tokio_udp_socket_for_target(
                bind_address,
                target,
                bind_interface.as_deref(),
                "fixed",
            )
            .await?;
            Ok(Box::new(FixedDatagram { socket, target }) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// Native asynchronous SOCKS5 proxy.
///
/// Runtime outbound proxies use this implementation so SOCKS5 UDP ASSOCIATE
/// shares the same `AsyncProxy` contract as direct and Yuubinsya datagrams.
#[derive(Clone)]
pub struct Socks5AsyncProxy {
    pub proxy: SocketAddr,
    pub timeout: Duration,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl AsyncProxy for Socks5AsyncProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let destination = context.effective_destination();
        let local_bind = context.local_bind_for(self.proxy);
        let bind_interface = context.bind_interface.clone();
        let proxy = self.clone();
        Box::pin(async move {
            let result = tokio::time::timeout(proxy.timeout, async move {
                let mut stream = connect_tokio_tcp_with_interface(
                    proxy.proxy,
                    local_bind,
                    bind_interface.as_deref(),
                    proxy.timeout,
                )
                .await
                .map_err(|error| socks5_stage("proxy TCP connect", error))?;
                socks5_authenticate(
                    &mut stream,
                    proxy.username.as_deref(),
                    proxy.password.as_deref(),
                )
                .await
                .map_err(|error| socks5_stage("authentication", error))?;
                socks5_request(&mut stream, 1, &destination)
                    .await
                    .map_err(|error| socks5_stage("CONNECT", error))?;
                Ok::<_, Error>(stream)
            })
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "SOCKS5 CONNECT timed out"))??;
            let local_addr = result.local_addr().ok();
            Ok(with_stream_local_addr(
                Box::new(result) as BoxAsyncStream,
                local_addr,
            ))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let proxy = self.clone();
        let local_bind = context.local_bind_for(self.proxy).unwrap_or_else(|| {
            if self.proxy.is_ipv4() {
                "0.0.0.0:0".parse().expect("valid IPv4 wildcard")
            } else {
                "[::]:0".parse().expect("valid IPv6 wildcard")
            }
        });
        let bind_interface = context.bind_interface.clone();
        Box::pin(async move {
            let result = tokio::time::timeout(proxy.timeout, async move {
                let mut control = connect_tokio_tcp_with_interface(
                    proxy.proxy,
                    Some(local_bind),
                    bind_interface.as_deref(),
                    proxy.timeout,
                )
                .await
                .map_err(|error| socks5_stage("UDP associate TCP connect", error))?;
                socks5_authenticate(
                    &mut control,
                    proxy.username.as_deref(),
                    proxy.password.as_deref(),
                )
                .await
                .map_err(|error| socks5_stage("UDP associate authentication", error))?;
                let unspecified = if proxy.proxy.is_ipv4() {
                    SocketAddr::from(([0, 0, 0, 0], 0))
                } else {
                    SocketAddr::from(([0u16; 8], 0))
                };
                let reply =
                    socks5_request(&mut control, 3, &Endpoint::ip(Network::Udp, unspecified))
                        .await
                        .map_err(|error| socks5_stage("UDP associate request", error))?;
                let relay = if reply.ip().is_unspecified() {
                    SocketAddr::new(proxy.proxy.ip(), reply.port())
                } else {
                    reply
                };
                if relay.is_ipv4() != local_bind.is_ipv4() {
                    return Err(Error::new(
                        ErrorKind::Protocol,
                        "SOCKS5 UDP relay and local bind use different address families",
                    ));
                }
                let socket = bind_tokio_udp_socket_for_target(
                    local_bind,
                    proxy.proxy,
                    bind_interface.as_deref(),
                    "SOCKS5",
                )
                .await?;
                Ok::<_, Error>(Socks5UdpDatagram {
                    socket,
                    relay,
                    control: Mutex::new(Some(control)),
                    receive_buffer: AsyncMutex::new(Vec::new()),
                })
            })
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "SOCKS5 UDP ASSOCIATE timed out"))??;
            Ok(Box::new(result) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

async fn socks5_authenticate(
    stream: &mut tokio::net::TcpStream,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<()> {
    let has_auth = username.is_some() && password.is_some();
    let methods: &[u8] = if has_auth { &[0, 2] } else { &[0] };
    stream
        .write_all(&[5, methods.len() as u8])
        .await
        .map_err(io_error)?;
    stream.write_all(methods).await.map_err(io_error)?;
    let mut selected = [0; 2];
    stream.read_exact(&mut selected).await.map_err(io_error)?;
    match selected[1] {
        0 => {}
        2 if has_auth => {
            let username = username.unwrap_or_default();
            let password = password.unwrap_or_default();
            if username.len() > 255 || password.len() > 255 {
                return Err(Error::invalid("SOCKS5 credentials are too long"));
            }
            let mut auth = vec![1, username.len() as u8];
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            stream.write_all(&auth).await.map_err(io_error)?;
            let mut response = [0; 2];
            stream.read_exact(&mut response).await.map_err(io_error)?;
            if response != [1, 0] {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "SOCKS5 authentication failed",
                ));
            }
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "SOCKS5 no acceptable method",
            ));
        }
    }
    Ok(())
}

fn socks5_stage(stage: &str, error: Error) -> Error {
    Error::new(error.kind, format!("SOCKS5 {stage}: {}", error.message))
}

async fn socks5_request(
    stream: &mut tokio::net::TcpStream,
    command: u8,
    destination: &Endpoint,
) -> Result<SocketAddr> {
    let (atyp, address) = socks_address(destination)?;
    let mut request = vec![5, command, 0, atyp];
    request.extend_from_slice(&address);
    request.extend_from_slice(&destination.port().unwrap_or_default().to_be_bytes());
    stream.write_all(&request).await.map_err(io_error)?;

    let mut head = [0; 4];
    stream.read_exact(&mut head).await.map_err(io_error)?;
    if head[1] != 0 {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("SOCKS5 request failed with code {}", head[1]),
        ));
    }
    let (host, port) = match head[3] {
        1 => {
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await.map_err(io_error)?;
            (
                IpAddr::V4(bytes.into()).to_string(),
                read_u16(stream).await?,
            )
        }
        4 => {
            let mut bytes = [0; 16];
            stream.read_exact(&mut bytes).await.map_err(io_error)?;
            (
                IpAddr::V6(bytes.into()).to_string(),
                read_u16(stream).await?,
            )
        }
        3 => {
            let mut length = [0; 1];
            stream.read_exact(&mut length).await.map_err(io_error)?;
            let mut bytes = vec![0; usize::from(length[0])];
            stream.read_exact(&mut bytes).await.map_err(io_error)?;
            let host = String::from_utf8(bytes)
                .map_err(|_| Error::new(ErrorKind::Protocol, "SOCKS5 reply domain is invalid"))?;
            (host, read_u16(stream).await?)
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "invalid SOCKS5 reply address type",
            ));
        }
    };
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(address, port));
    }
    tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("resolve SOCKS5 relay: {error}")))?
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "SOCKS5 relay resolved to no address"))
}

async fn read_u16(stream: &mut tokio::net::TcpStream) -> Result<u16> {
    let mut bytes = [0; 2];
    stream.read_exact(&mut bytes).await.map_err(io_error)?;
    Ok(u16::from_be_bytes(bytes))
}

struct Socks5UdpDatagram {
    socket: tokio::net::UdpSocket,
    relay: SocketAddr,
    // SOCKS5 keeps the TCP control connection open for the lifetime of the
    // UDP association. The mutex is only needed to make the datagram object
    // satisfy the shared AsyncDatagram Send + Sync contract; no I/O is done
    // through it after the handshake.
    control: Mutex<Option<tokio::net::TcpStream>>,
    // Keep the SOCKS5 header scratch space with the association. The TUN
    // caller's buffer is payload-sized, so a maximum-sized allocation here
    // would multiply memory by the number of live UDP associations.
    receive_buffer: AsyncMutex<Vec<u8>>,
}

impl AsyncDatagram for Socks5UdpDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            if target.network() != Network::Udp {
                return Err(Error::invalid("SOCKS5 UDP target has wrong network"));
            }
            let (atyp, address) = socks_address(&target)?;
            let mut packet = Vec::with_capacity(4 + address.len() + 2 + payload.len());
            packet.extend_from_slice(&[0, 0, 0, atyp]);
            packet.extend_from_slice(&address);
            packet.extend_from_slice(&target.port().unwrap_or_default().to_be_bytes());
            packet.extend_from_slice(payload);
            self.socket
                .send_to(&packet, self.relay)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, format!("SOCKS5 UDP send: {error}")))?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            // The TUN UDP relay already supplies the maximum legal UDP
            // datagram buffer. Read the SOCKS5 packet directly into it so a
            // high-rate relay does not allocate a fresh 64 KiB Vec for every
            // response. Smaller callers retain the historical fallback so
            // the output buffer can remain payload-sized.
            if buffer.len() >= u16::MAX as usize {
                let length = self.socket.recv(buffer).await.map_err(|error| {
                    Error::new(ErrorKind::Io, format!("SOCKS5 UDP receive: {error}"))
                })?;
                let (target, offset) = decode_socks5_udp_endpoint(&buffer[..length])?;
                let payload_len = length.saturating_sub(offset);
                buffer.copy_within(offset..length, 0);
                return Ok((payload_len, target));
            }

            const SOCKS5_UDP_MAX_HEADER_SIZE: usize = 262;
            let mut packet = self.receive_buffer.lock().await;
            let required = buffer
                .len()
                .saturating_add(SOCKS5_UDP_MAX_HEADER_SIZE)
                .min(u16::MAX as usize);
            if packet.len() < required {
                packet.resize(required, 0);
            }
            let length = self.socket.recv(&mut packet).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("SOCKS5 UDP receive: {error}"))
            })?;
            let (target, offset) = decode_socks5_udp_endpoint(&packet[..length])?;
            let payload = &packet[offset..length];
            if buffer.len() < payload.len() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "SOCKS5 UDP payload exceeds receive buffer",
                ));
            }
            buffer[..payload.len()].copy_from_slice(payload);
            Ok((payload.len(), target))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.socket
            .local_addr()
            .map(|address| Endpoint::ip(Network::Udp, address))
            .map_err(|error| {
                Error::new(ErrorKind::Io, format!("SOCKS5 UDP local address: {error}"))
            })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        if let Ok(mut control) = self.control.lock() {
            control.take();
        }
        Box::pin(async { Ok(()) })
    }
}

fn decode_socks5_udp_endpoint(packet: &[u8]) -> Result<(Endpoint, usize)> {
    if packet.len() < 4 || packet[0..2] != [0, 0] {
        return Err(Error::new(
            ErrorKind::Protocol,
            "invalid SOCKS5 UDP response header",
        ));
    }
    if packet[2] != 0 {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "fragmented SOCKS5 UDP responses are not supported",
        ));
    }
    let atyp = packet[3];
    let mut offset = 4;
    let host = match atyp {
        1 => {
            let end = offset + 4;
            let bytes = packet.get(offset..end).ok_or_else(|| {
                Error::new(ErrorKind::Protocol, "SOCKS5 UDP IPv4 address is truncated")
            })?;
            offset = end;
            IpAddr::V4(std::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(bytes).expect("validated IPv4 length"),
            ))
            .to_string()
        }
        4 => {
            let end = offset + 16;
            let bytes = packet.get(offset..end).ok_or_else(|| {
                Error::new(ErrorKind::Protocol, "SOCKS5 UDP IPv6 address is truncated")
            })?;
            offset = end;
            IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes).expect("validated IPv6 length"),
            ))
            .to_string()
        }
        3 => {
            let length = usize::from(*packet.get(offset).ok_or_else(|| {
                Error::new(ErrorKind::Protocol, "SOCKS5 UDP domain length is missing")
            })?);
            offset += 1;
            let end = offset + length;
            let bytes = packet
                .get(offset..end)
                .ok_or_else(|| Error::new(ErrorKind::Protocol, "SOCKS5 UDP domain is truncated"))?;
            offset = end;
            String::from_utf8(bytes.to_vec())
                .map_err(|_| Error::new(ErrorKind::Protocol, "SOCKS5 UDP domain is invalid"))?
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "invalid SOCKS5 UDP address type",
            ));
        }
    };
    let port_end = offset + 2;
    let port_bytes = packet
        .get(offset..port_end)
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "SOCKS5 UDP port is truncated"))?;
    let port = u16::from_be_bytes(port_bytes.try_into().expect("validated port length"));
    offset = port_end;
    let endpoint = match host.parse::<IpAddr>() {
        Ok(address) => Endpoint::ip(Network::Udp, SocketAddr::new(address, port)),
        Err(_) => Endpoint::domain(Network::Udp, DomainName::new(&host)?, port),
    };
    Ok((endpoint, offset))
}

struct TokioDatagram {
    socket: tokio::net::UdpSocket,
}

struct FixedDatagram {
    socket: tokio::net::UdpSocket,
    target: SocketAddr,
}

impl AsyncDatagram for TokioDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            if target.network() != Network::Udp {
                return Err(Error::invalid("UDP datagram target has wrong network"));
            }
            let preferred_ipv4 = self
                .socket
                .local_addr()
                .ok()
                .map(|address| address.is_ipv4());
            let addresses = resolve_direct_addresses(&target, preferred_ipv4).await?;
            let mut last_error = None;
            for address in addresses {
                match self.socket.send_to(payload, address).await {
                    Ok(length) => return Ok(length),
                    Err(error) => {
                        last_error = Some(Error::new(
                            ErrorKind::Io,
                            format!("UDP send to {address}: {error}"),
                        ));
                    }
                }
            }
            Err(last_error
                .unwrap_or_else(|| Error::invalid("direct UDP destination has no address")))
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let (length, address) = self
                .socket
                .recv_from(buffer)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, format!("UDP receive: {error}")))?;
            Ok((length, Endpoint::ip(Network::Udp, address)))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.socket
            .local_addr()
            .map(|address| Endpoint::ip(Network::Udp, address))
            .map_err(|error| Error::new(ErrorKind::Io, format!("UDP local address: {error}")))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl AsyncDatagram for FixedDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            if target.network() != Network::Udp {
                return Err(Error::invalid("UDP datagram target has wrong network"));
            }
            self.socket
                .send_to(payload, self.target)
                .await
                .map_err(|error| {
                    Error::new(
                        ErrorKind::Io,
                        format!("fixed UDP send to {}: {error}", self.target),
                    )
                })
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let (length, _) = self.socket.recv_from(buffer).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("fixed UDP receive: {error}"))
            })?;
            Ok((length, Endpoint::ip(Network::Udp, self.target)))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.socket
            .local_addr()
            .map(|address| Endpoint::ip(Network::Udp, address))
            .map_err(|error| Error::new(ErrorKind::Io, format!("fixed UDP local address: {error}")))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

fn socks_address(destination: &Endpoint) -> Result<(u8, Vec<u8>)> {
    match destination {
        Endpoint::Ip { addr, .. } => match addr.ip() {
            IpAddr::V4(value) => Ok((1, value.octets().to_vec())),
            IpAddr::V6(value) => Ok((4, value.octets().to_vec())),
        },
        Endpoint::Domain { host, .. } => {
            if host.as_str().len() > 255 {
                return Err(Error::invalid("SOCKS5 domain is too long"));
            }
            let mut value = vec![host.as_str().len() as u8];
            value.extend_from_slice(host.as_str().as_bytes());
            Ok((3, value))
        }
    }
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DomainName, Network};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn endpoint() -> Endpoint {
        Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443)
    }

    #[test]
    fn delayed_drop_escalates_per_destination() {
        let state = DelayedDropState::default();
        let destination = Endpoint::domain(
            Network::Tcp,
            DomainName::new("blocked.example").unwrap(),
            443,
        );
        assert_eq!(state.next_delay(&destination), Duration::ZERO);
        assert_eq!(state.next_delay(&destination), Duration::from_secs(1));
        assert_eq!(state.next_delay(&destination), Duration::from_secs(2));
        assert_eq!(state.next_delay(&destination), Duration::from_secs(4));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_stream_metadata_survives_async_io_delegation() {
        let (mut peer, stream) = tokio::io::duplex(64);
        let local = "127.0.0.1:24568".parse().unwrap();
        let mut stream = with_stream_local_addr(Box::new(stream), Some(local));
        assert_eq!(stream_local_addr(&*stream), Some(local));

        peer.write_all(b"ping").await.unwrap();
        let mut buffer = [0; 4];
        stream.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"ping");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fixed_async_proxy_routes_datagrams_to_fixed_endpoint() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fixed = server.local_addr().unwrap();
        let proxy = FixedAsyncProxy {
            address: fixed,
            timeout: Duration::from_secs(1),
        };
        let logical_target = Endpoint::ip(Network::Udp, "127.0.0.1:9".parse().unwrap());
        let context = FlowContext::new(logical_target.clone());
        let datagram = proxy.open_datagram(&context).await.unwrap();

        let payload = b"fixed-udp";
        assert_eq!(
            datagram.send_to(payload, logical_target).await.unwrap(),
            payload.len()
        );

        let mut buffer = [0u8; 64];
        let (length, peer) =
            tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buffer[..length], payload);
        server.send_to(b"fixed-reply", peer).await.unwrap();

        let (length, source) =
            tokio::time::timeout(Duration::from_secs(1), datagram.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buffer[..length], b"fixed-reply");
        assert_eq!(source, Endpoint::ip(Network::Udp, fixed));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn fixed_async_proxy_applies_linux_network_interface_to_udp() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fixed = server.local_addr().unwrap();
        let proxy = FixedAsyncProxy {
            address: fixed,
            timeout: Duration::from_secs(1),
        };
        let mut context = FlowContext::new(Endpoint::ip(Network::Udp, fixed));
        context.bind_interface = Some("lo".to_owned());
        let datagram = proxy.open_datagram(&context).await.unwrap();
        datagram
            .send_to(b"interface-udp", Endpoint::ip(Network::Udp, fixed))
            .await
            .unwrap();

        let mut buffer = [0u8; 64];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buffer[..length], b"interface-udp");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn default_route_parser_skips_virtual_interfaces() {
        let routes = r#"Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
tun0 00000000 00000000 0001 0 0 0 00000000 0 0 0
wg0 00000000 00000000 0001 0 0 0 00000000 0 0 0
enp0s5 00000000 0100370A 0001 0 0 100 00000000 0 0 0"#;
        assert_eq!(
            default_route_interface_v4(routes).as_deref(),
            Some("enp0s5")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn default_ipv6_route_parser_skips_virtual_interfaces() {
        let routes = r#"00000000000000000000000000000000 00000000 00000000000000000000000000000000 00000000 00000000000000000000000000000000 00000000 00000000 00000000 00000000 tun0
00000000000000000000000000000000 00000000 00000000000000000000000000000000 00000000 00000000000000000000000000000000 00000000 00000000 00000000 00000000 enp0s5"#;
        assert_eq!(
            default_route_interface_v6(routes).as_deref(),
            Some("enp0s5")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_async_proxy_resolves_domain_when_called_without_runtime_wrapper() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut payload = [0u8; 13];
            stream.read_exact(&mut payload).await.unwrap();
            payload
        });

        let context = FlowContext::new(Endpoint::domain(
            Network::Tcp,
            DomainName::new("localhost").unwrap(),
            address.port(),
        ));
        let proxy = DirectAsyncProxy {
            timeout: Duration::from_secs(1),
        };
        let mut stream = proxy.connect(&context).await.unwrap();
        stream.write_all(b"direct-domain").await.unwrap();
        assert_eq!(server.await.unwrap(), *b"direct-domain");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_async_datagram_resolves_domain_targets_on_send() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let mut payload = [0u8; 64];
            let (length, peer) = server.recv_from(&mut payload).await.unwrap();
            server.send_to(&payload[..length], peer).await.unwrap();
            payload[..length].to_vec()
        });

        let mut context = FlowContext::new(Endpoint::domain(
            Network::Udp,
            DomainName::new("localhost").unwrap(),
            address.port(),
        ));
        context
            .local_bind_addresses
            .push("127.0.0.1".parse().unwrap());
        let proxy = DirectAsyncProxy {
            timeout: Duration::from_secs(1),
        };
        let datagram = proxy.open_datagram(&context).await.unwrap();
        let target = Endpoint::domain(
            Network::Udp,
            DomainName::new("localhost").unwrap(),
            address.port(),
        );
        datagram
            .send_to(b"direct-udp-domain", target)
            .await
            .unwrap();
        let mut response = [0u8; 64];
        let (length, _) = datagram.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..length], b"direct-udp-domain");
        assert_eq!(server_task.await.unwrap(), b"direct-udp-domain");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn direct_async_proxy_pings_loopback_with_icmp() {
        let proxy = DirectAsyncProxy {
            timeout: Duration::from_secs(1),
        };
        let context = FlowContext::new(Endpoint::ip(Network::Tcp, "127.0.0.1:0".parse().unwrap()));
        let elapsed = proxy.ping(&context).await.unwrap();
        assert!(elapsed >= Duration::ZERO);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn direct_async_proxy_pings_ipv6_loopback_with_icmp() {
        let proxy = DirectAsyncProxy {
            timeout: Duration::from_secs(1),
        };
        let context = FlowContext::new(Endpoint::ip(Network::Tcp, "[::1]:0".parse().unwrap()));
        let elapsed = proxy.ping(&context).await.unwrap();
        assert!(elapsed >= Duration::ZERO);
    }

    #[test]
    fn socks_address_encodes_domain_and_ip() {
        assert_eq!(socks_address(&endpoint()).unwrap().0, 3);
        let ip = Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap());
        assert_eq!(socks_address(&ip).unwrap(), (1, vec![192, 0, 2, 1]));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn native_socks5_udp_associate_round_trips_authenticated_domain() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();

            let mut greeting = [0u8; 4];
            control.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 2, 0, 2]);
            control.write_all(&[5, 2]).await.unwrap();

            let mut auth = [0u8; 1];
            control.read_exact(&mut auth).await.unwrap();
            assert_eq!(auth[0], 1);
            let mut username_length = [0u8; 1];
            control.read_exact(&mut username_length).await.unwrap();
            let mut username = vec![0u8; usize::from(username_length[0])];
            control.read_exact(&mut username).await.unwrap();
            let mut password_length = [0u8; 1];
            control.read_exact(&mut password_length).await.unwrap();
            let mut password = vec![0u8; usize::from(password_length[0])];
            control.read_exact(&mut password).await.unwrap();
            assert_eq!(username, b"user");
            assert_eq!(password, b"pass");
            control.write_all(&[1, 0]).await.unwrap();

            let mut request = [0u8; 10];
            control.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[5, 3, 0, 1]);
            control
                .write_all(&[
                    5,
                    0,
                    0,
                    1,
                    127,
                    0,
                    0,
                    1,
                    relay_address.port().to_be_bytes()[0],
                    relay_address.port().to_be_bytes()[1],
                ])
                .await
                .unwrap();

            let mut packet = [0u8; 2048];
            let (length, peer) = relay.recv_from(&mut packet).await.unwrap();
            assert!(length >= 12);
            assert_eq!(&packet[..4], &[0, 0, 0, 3]);
            let host_length = usize::from(packet[4]);
            let host_end = 5 + host_length;
            assert_eq!(&packet[5..host_end], b"example.com");
            let port = u16::from_be_bytes([packet[host_end], packet[host_end + 1]]);
            assert_eq!(port, 53);
            assert_eq!(&packet[host_end + 2..length], b"ping");

            let mut response = vec![0, 0, 0, 3, 11];
            response.extend_from_slice(b"example.com");
            response.extend_from_slice(&53u16.to_be_bytes());
            response.extend_from_slice(b"pong");
            relay.send_to(&response, peer).await.unwrap();

            let mut closed = [0u8; 1];
            let _ = control.read(&mut closed).await;
        });

        let proxy = Socks5AsyncProxy {
            proxy: proxy_address,
            timeout: Duration::from_secs(1),
            username: Some("user".to_owned()),
            password: Some("pass".to_owned()),
        };
        let target = Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);
        let mut context = FlowContext::new(target.clone());
        context
            .local_bind_addresses
            .push("127.0.0.2".parse().unwrap());
        let datagram = proxy.open_datagram(&context).await.unwrap();
        assert_eq!(
            datagram.local_addr().unwrap().addr().unwrap().ip(),
            "127.0.0.2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(datagram.send_to(b"ping", target.clone()).await.unwrap(), 4);

        let mut buffer = [0u8; 64];
        let (length, response_target) = datagram.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"pong");
        assert_eq!(response_target, target);
        datagram.close().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }
}
