//! The first TUN data-plane adapter.
//!
//! This module intentionally exposes one implementation only:
//! `tun-rs::AsyncDevice` is the OS boundary and smoltcp is the packet/socket
//! engine.  There is no tun2socket implementation and no second userspace
//! stack to keep in sync with this one.

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, ChecksumCapabilities, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol, IpVersion,
    TcpPacket, UdpPacket,
};
#[cfg(feature = "async-proxy")]
use std::collections::HashSet;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(all(feature = "tun-routes", target_os = "linux"))]
use std::path::Path;
use std::sync::{Arc, Mutex};
#[cfg(feature = "async-proxy")]
use std::time::Duration;
use tun_rs::AsyncDevice;
#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
use tun_rs::DeviceBuilder;

#[cfg(feature = "async-proxy")]
use tokio::sync::mpsc;

#[cfg(feature = "async-proxy")]
use futures_util::stream::FuturesUnordered;
#[cfg(feature = "async-proxy")]
use futures_util::{FutureExt, StreamExt};

#[cfg(feature = "async-proxy")]
use crate::Endpoint;
#[cfg(feature = "async-proxy")]
use crate::LocalBoxFuture;
#[cfg(feature = "async-proxy")]
use crate::nat::{NatKey, NatTable};
#[cfg(feature = "async-proxy")]
use crate::process::{ProcessResolver, default_process_resolver};
use crate::{Error, ErrorKind, Network, Result};

pub use crate::flow::{Flow as TunFlow, FlowKey as TunFlowKey};
#[cfg(feature = "async-proxy")]
pub use crate::flow::{FlowDirection as TunFlowDirection, FlowObserver as TunFlowObserver};

#[cfg(feature = "async-proxy")]
use crate::dns::{AsyncDnsHandler, DnsHandler, answer_query};

#[cfg(feature = "async-proxy")]
use crate::proxy::{AsyncProxy, AsyncProxySelector};

#[cfg(feature = "async-proxy")]
fn tun_debug(message: impl std::fmt::Display) {
    if std::env::var_os("YUHAIIN_TUN_DEBUG").is_some() {
        eprintln!("yuhaiin-rust: tun-debug: {message}");
    }
}

pub const DEFAULT_MTU: usize = 1500;
pub const DEFAULT_QUEUE_CAPACITY: usize = 256;
const MAX_TCP_EVENT_BYTES_PER_POLL: usize = 64 * 1024;

#[cfg(feature = "async-proxy")]
const DEFAULT_GRACEFUL_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    pub name: Option<String>,
    pub ipv4: Option<(Ipv4Addr, u8)>,
    pub ipv6: Vec<(Ipv6Addr, u8)>,
    pub mtu: usize,
    pub queue_capacity: usize,
}
impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            ipv4: None,
            ipv6: Vec::new(),
            mtu: DEFAULT_MTU,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
        }
    }
}

impl TunConfig {
    pub fn validate(&self) -> Result<()> {
        if !(576..=9216).contains(&self.mtu) {
            return Err(Error::invalid("TUN MTU must be between 576 and 9216"));
        }
        if self.queue_capacity == 0 {
            return Err(Error::invalid("TUN queue capacity must be non-zero"));
        }
        if self.ipv4.as_ref().is_some_and(|(_, prefix)| *prefix > 32)
            || self.ipv6.iter().any(|(_, prefix)| *prefix > 128)
        {
            return Err(Error::invalid("TUN address prefix is out of range"));
        }
        Ok(())
    }
}

/// A route that should be installed on the operating-system TUN interface.
///
/// Routes are deliberately separate from [`TunConfig`]. The first TUN path
/// can therefore continue to use a minimal device configuration, while an
/// application that owns system routing can opt into an explicit, reversible
/// route lease. The route lease never participates in NAT lookup: NAT remains
/// endpoint-independent Full Cone NAT.
#[cfg(feature = "tun-routes")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TunRoute {
    pub destination: IpAddr,
    pub prefix: u8,
    pub gateway: Option<IpAddr>,
    pub metric: Option<u32>,
}

#[cfg(feature = "tun-routes")]
impl TunRoute {
    pub fn new(destination: IpAddr, prefix: u8) -> Result<Self> {
        let route = Self {
            destination,
            prefix,
            gateway: None,
            metric: None,
        };
        route.validate()?;
        Ok(route)
    }

    pub fn validate(&self) -> Result<()> {
        let max_prefix = if self.destination.is_ipv4() { 32 } else { 128 };
        if self.prefix > max_prefix {
            return Err(Error::invalid("TUN route prefix is out of range"));
        }
        if self
            .gateway
            .is_some_and(|gateway| gateway.is_ipv4() != self.destination.is_ipv4())
        {
            return Err(Error::invalid(
                "TUN route gateway must use the destination address family",
            ));
        }
        Ok(())
    }

    /// Return the canonical network address used by the kernel route API.
    pub fn network(&self) -> IpAddr {
        match self.destination {
            IpAddr::V4(address) => {
                let bits = u32::from(address);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                IpAddr::V4(Ipv4Addr::from(bits & mask))
            }
            IpAddr::V6(address) => {
                let bits = u128::from(address);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                IpAddr::V6(Ipv6Addr::from(bits & mask))
            }
        }
    }

    fn canonicalized(&self) -> Result<Self> {
        self.validate()?;
        Ok(Self {
            destination: self.network(),
            prefix: self.prefix,
            gateway: self.gateway,
            metric: self.metric,
        })
    }
}

/// The narrow system-operation boundary used by [`TunRouteLease`].
///
/// Keeping this trait independent of netlink makes all ordering and rollback
/// behavior testable without CAP_NET_ADMIN. The production Linux backend is
/// implemented below with the pure-Rust `route_manager` netlink client.
#[cfg(feature = "tun-routes")]
pub trait TunRouteBackend {
    fn add_route(&mut self, route: &TunRoute) -> io::Result<()>;
    fn remove_route(&mut self, route: &TunRoute) -> io::Result<()>;
}

/// An owned, reversible set of routes installed for one TUN runtime.
///
/// Applying routes is transactional from the caller's perspective: if any
/// add fails, already-added routes are removed in reverse order before the
/// error is returned. Closing is idempotent and also removes in reverse order.
/// A failed removal remains tracked so a later explicit close can retry it;
/// `Drop` makes a best-effort final cleanup when the owner is force-dropped.
#[cfg(feature = "tun-routes")]
pub struct TunRouteLease {
    backend: Box<dyn TunRouteBackend>,
    routes: Vec<TunRoute>,
}

#[cfg(feature = "tun-routes")]
impl TunRouteLease {
    pub fn apply<B>(mut backend: B, routes: &[TunRoute]) -> io::Result<Self>
    where
        B: TunRouteBackend + 'static,
    {
        let mut normalized = Vec::with_capacity(routes.len());
        for route in routes {
            let route = route
                .canonicalized()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
            if normalized.contains(&route) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "duplicate TUN route",
                ));
            }
            normalized.push(route);
        }

        let mut added = Vec::with_capacity(normalized.len());
        for route in normalized {
            if let Err(error) = backend.add_route(&route) {
                let mut rollback_errors = Vec::new();
                for applied in added.iter().rev() {
                    if let Err(rollback_error) = backend.remove_route(applied) {
                        rollback_errors.push(rollback_error.to_string());
                    }
                }
                let message = if rollback_errors.is_empty() {
                    format!("failed to add TUN route: {error}")
                } else {
                    format!(
                        "failed to add TUN route: {error}; route rollback also failed: {}",
                        rollback_errors.join("; ")
                    )
                };
                return Err(io::Error::new(error.kind(), message));
            }
            added.push(route);
        }

        Ok(Self {
            backend: Box::new(backend),
            routes: added,
        })
    }

    pub fn routes(&self) -> &[TunRoute] {
        &self.routes
    }

    pub fn close(&mut self) -> io::Result<()> {
        let mut remaining = Vec::new();
        let mut first_error = None;
        for route in self.routes.drain(..).rev() {
            match self.backend.remove_route(&route) {
                Ok(()) => {}
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    remaining.push(route);
                }
            }
        }
        self.routes = remaining.into_iter().rev().collect();
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(feature = "tun-routes")]
impl Drop for TunRouteLease {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Linux route backend. It sends route netlink messages directly through the
/// pure-Rust `route_manager` crate and never shells out to `ip` or another
/// platform command.
#[cfg(all(feature = "tun-routes", target_os = "linux"))]
pub struct LinuxTunRouteBackend {
    interface: String,
    manager: route_manager::RouteManager,
}

#[cfg(all(feature = "tun-routes", target_os = "linux"))]
impl LinuxTunRouteBackend {
    pub fn new(interface: impl Into<String>) -> io::Result<Self> {
        let interface = interface.into();
        if interface.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN route interface name must not be empty",
            ));
        }
        Ok(Self {
            interface,
            manager: route_manager::RouteManager::new()?,
        })
    }

    fn system_route(&self, route: &TunRoute) -> route_manager::Route {
        let mut system_route = route_manager::Route::new(route.network(), route.prefix)
            .with_if_name(self.interface.clone());
        if let Some(gateway) = route.gateway {
            system_route = system_route.with_gateway(gateway);
        }
        if let Some(metric) = route.metric {
            system_route = system_route.with_metric(metric);
        }
        system_route
    }
}

#[cfg(all(feature = "tun-routes", target_os = "linux"))]
impl TunRouteBackend for LinuxTunRouteBackend {
    fn add_route(&mut self, route: &TunRoute) -> io::Result<()> {
        self.manager.add(&self.system_route(route))
    }

    fn remove_route(&mut self, route: &TunRoute) -> io::Result<()> {
        self.manager.delete(&self.system_route(route))
    }
}

#[cfg(feature = "tun-routes")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityState {
    Available,
    Unavailable,
    Unknown,
}

#[cfg(feature = "tun-routes")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunCapabilities {
    pub tun_device: CapabilityState,
    pub route_control: CapabilityState,
    pub multi_queue: CapabilityState,
}

/// Probe Linux capabilities without creating a device or changing routes.
///
/// Route control is only reported as available when the process has
/// `CAP_NET_ADMIN` in its effective capability set and a read-only netlink
/// probe succeeds.  Merely being able to dump routes is not enough: an
/// unprivileged process can often list routes but cannot create the route
/// lease required by the TUN runtime.
///
/// Multi-queue is probed from the tun driver's read-only module parameter.
/// If the driver is built in, the parameter can be absent; that remains
/// `Unknown` rather than claiming support without opening a real device.
#[cfg(all(feature = "tun-routes", target_os = "linux"))]
pub fn probe_linux_capabilities() -> TunCapabilities {
    let tun_device = if Path::new("/dev/net/tun").exists() {
        CapabilityState::Available
    } else {
        CapabilityState::Unavailable
    };
    let route_control = match read_effective_capabilities() {
        Some(capabilities) if !has_capability(capabilities, CAP_NET_ADMIN) => {
            CapabilityState::Unavailable
        }
        _ => match route_manager::RouteManager::new().and_then(|mut manager| manager.list()) {
            Ok(_) => CapabilityState::Available,
            Err(_) => CapabilityState::Unavailable,
        },
    };
    TunCapabilities {
        tun_device,
        route_control,
        multi_queue: read_multi_queue_capability(),
    }
}

#[cfg(all(feature = "tun-routes", target_os = "linux"))]
const CAP_NET_ADMIN: u8 = 12;

#[cfg(all(feature = "tun-routes", target_os = "linux"))]
fn read_effective_capabilities() -> Option<u128> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))?;
    u128::from_str_radix(value.trim(), 16).ok()
}

#[cfg(all(feature = "tun-routes", target_os = "linux"))]
fn has_capability(capabilities: u128, capability: u8) -> bool {
    capabilities & (1_u128 << capability) != 0
}

#[cfg(all(feature = "tun-routes", target_os = "linux"))]
fn read_multi_queue_capability() -> CapabilityState {
    match std::fs::read_to_string("/sys/module/tun/parameters/multi_queue") {
        Ok(value) => match value.trim() {
            "Y" | "y" | "1" => CapabilityState::Available,
            "N" | "n" | "0" => CapabilityState::Unavailable,
            _ => CapabilityState::Unknown,
        },
        Err(_) => CapabilityState::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpPacketVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInfo {
    pub version: IpPacketVersion,
    pub length: usize,
    /// Whether this packet is one fragment of an IPv4/IPv6 datagram.
    ///
    /// The first implementation deliberately preserves fragments and does
    /// not add a second reassembly engine.  MTU validation is applied to each
    /// wire fragment, which matches the TUN device contract.
    pub fragmented: bool,
}

/// Events emitted after `TunDispatcher::poll` has allowed smoltcp to consume
/// packets and advance socket state.
///
/// Events own their payloads.  A runtime can therefore hand them to an async
/// proxy task without borrowing the smoltcp socket set or holding a mutex
/// across I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunEvent {
    TcpOpened { flow: TunFlow },
    TcpData { flow: TunFlow, payload: Vec<u8> },
    TcpHalfClosed { flow: TunFlow },
    TcpClosed { flow: TunFlow },
    UdpDatagram { flow: TunFlow, payload: Vec<u8> },
}

#[derive(Debug)]
struct TcpFlowState {
    key: Option<TunFlowKey>,
    opened: bool,
    half_closed: bool,
}

#[derive(Debug)]
struct UdpSocketState {
    local: SocketAddr,
    closing: bool,
}

/// The smoltcp-to-runtime adapter for the first TUN implementation.
///
/// `TunDispatcher` owns socket state and emits owned events.  It does not
/// perform routing or proxy I/O itself.  The caller can consume events,
/// construct a `FlowContext`, and later call `write_tcp`/`write_udp` with data
/// returned by its selected proxy.  This separation keeps the packet engine
/// deterministic and makes it possible to run proxy work on an async runtime
/// without blocking `Interface::poll`.
pub struct TunDispatcher {
    sockets: SocketSet<'static>,
    tcp: HashMap<SocketHandle, TcpFlowState>,
    tcp_by_key: HashMap<TunFlowKey, SocketHandle>,
    udp: HashMap<SocketHandle, UdpSocketState>,
    udp_by_local: HashMap<SocketAddr, SocketHandle>,
    events: VecDeque<TunEvent>,
    rx_buffer_size: usize,
    tx_buffer_size: usize,
    udp_packet_capacity: usize,
}

impl TunDispatcher {
    pub fn new(
        rx_buffer_size: usize,
        tx_buffer_size: usize,
        udp_packet_capacity: usize,
    ) -> Result<Self> {
        if rx_buffer_size == 0 || tx_buffer_size == 0 || udp_packet_capacity == 0 {
            return Err(Error::invalid("TUN dispatcher buffers must be non-zero"));
        }
        Ok(Self {
            sockets: SocketSet::new(Vec::new()),
            tcp: HashMap::new(),
            tcp_by_key: HashMap::new(),
            udp: HashMap::new(),
            udp_by_local: HashMap::new(),
            events: VecDeque::new(),
            rx_buffer_size,
            tx_buffer_size,
            udp_packet_capacity,
        })
    }

    pub fn events(&mut self) -> impl Iterator<Item = TunEvent> + '_ {
        self.events.drain(..)
    }

    pub fn poll(
        &mut self,
        runtime: &mut TunRuntime,
        timestamp: Instant,
    ) -> Result<smoltcp::iface::PollResult> {
        self.poll_with(
            &mut runtime.interface,
            &mut runtime.smoltcp_device,
            timestamp,
        )
    }

    pub fn poll_with(
        &mut self,
        interface: &mut Interface,
        device: &mut SmoltcpTunDevice,
        timestamp: Instant,
    ) -> Result<smoltcp::iface::PollResult> {
        self.prepare_rx(device)?;
        let result = interface.poll(timestamp, device, &mut self.sockets);
        self.collect_events()?;
        Ok(result)
    }

    /// Create a socket for the packet at the head of the TUN RX queue before
    /// smoltcp consumes it.  TCP requires this for the first SYN; UDP sockets
    /// are keyed by their local destination endpoint and can receive multiple
    /// application source tuples.
    pub fn prepare_rx(&mut self, device: &SmoltcpTunDevice) -> Result<()> {
        let Some(packet) = device.peek_rx_packet()? else {
            return Ok(());
        };
        let Some(tuple) = parse_transport_tuple(&packet)? else {
            return Ok(());
        };
        match tuple.protocol {
            IpProtocol::Tcp if tuple.tcp_syn => self.ensure_tcp_listener(tuple),
            IpProtocol::Udp => self.ensure_udp_socket(tuple.destination),
            _ => Ok(()),
        }
    }

    pub fn write_tcp(&mut self, flow: TunFlowKey, payload: &[u8]) -> Result<usize> {
        let handle = self
            .tcp_by_key
            .get(&flow)
            .copied()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "TUN TCP flow is not registered"))?;
        self.sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(payload)
            .map_err(|error| Error::new(ErrorKind::Closed, format!("TUN TCP write: {error:?}")))
    }

    pub fn close_tcp(&mut self, flow: TunFlowKey) -> Result<()> {
        let handle = self
            .tcp_by_key
            .get(&flow)
            .copied()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "TUN TCP flow is not registered"))?;
        self.sockets.get_mut::<tcp::Socket>(handle).close();
        Ok(())
    }

    pub fn abort_tcp(&mut self, flow: TunFlowKey) -> Result<()> {
        let handle = self
            .tcp_by_key
            .get(&flow)
            .copied()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "TUN TCP flow is not registered"))?;
        self.sockets.get_mut::<tcp::Socket>(handle).abort();
        Ok(())
    }

    pub fn write_udp(&mut self, flow: TunFlowKey, payload: &[u8]) -> Result<()> {
        let handle = self
            .udp_by_local
            .get(&flow.destination)
            .copied()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "TUN UDP socket is not registered"))?;
        self.sockets
            .get_mut::<udp::Socket>(handle)
            .send_slice(payload, IpEndpoint::from(flow.source))
            .map_err(|error| Error::new(ErrorKind::Closed, format!("TUN UDP write: {error:?}")))
    }

    pub fn close_udp(&mut self, flow: TunFlowKey) -> Result<()> {
        let Some(handle) = self.udp_by_local.get(&flow.destination).copied() else {
            return Ok(());
        };
        if let Some(state) = self.udp.get_mut(&handle) {
            // Keep the socket until the next smoltcp poll. A preceding
            // UdpData output may already be queued in its TX packet buffer;
            // removing it here would silently drop that packet.
            state.closing = true;
        }
        Ok(())
    }

    fn ensure_tcp_listener(&mut self, tuple: TransportTuple) -> Result<()> {
        let key = TunFlowKey {
            network: Network::Tcp,
            source: tuple.source,
            destination: tuple.destination,
        };
        if self.tcp_by_key.contains_key(&key)
            || self.tcp.values().any(|state| state.key == Some(key))
        {
            return Ok(());
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; self.rx_buffer_size]),
            tcp::SocketBuffer::new(vec![0; self.tx_buffer_size]),
        );
        socket
            .listen(IpListenEndpoint {
                // A TUN gateway must accept destinations that are not local
                // interface addresses. smoltcp keeps the packet's actual
                // local endpoint on the established socket, so a wildcard
                // listener preserves the original destination in the flow
                // key while allowing ordinary Internet routes.
                addr: None,
                port: tuple.destination.port(),
            })
            .map_err(|error| {
                Error::new(ErrorKind::Unsupported, format!("TUN TCP listen: {error:?}"))
            })?;
        let handle = self.sockets.add(socket);
        self.tcp.insert(
            handle,
            TcpFlowState {
                key: Some(key),
                opened: false,
                half_closed: false,
            },
        );
        Ok(())
    }

    fn ensure_udp_socket(&mut self, local: SocketAddr) -> Result<()> {
        if self.udp_by_local.contains_key(&local) {
            return Ok(());
        }
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; self.udp_packet_capacity],
                vec![0; self.rx_buffer_size],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; self.udp_packet_capacity],
                vec![0; self.tx_buffer_size],
            ),
        );
        socket
            .bind(IpListenEndpoint::from(local))
            .map_err(|error| {
                Error::new(ErrorKind::Unsupported, format!("TUN UDP bind: {error:?}"))
            })?;
        let handle = self.sockets.add(socket);
        self.udp.insert(
            handle,
            UdpSocketState {
                local,
                closing: false,
            },
        );
        self.udp_by_local.insert(local, handle);
        Ok(())
    }

    fn collect_events(&mut self) -> Result<()> {
        let tcp_handles: Vec<_> = self.tcp.keys().copied().collect();
        let mut closed_tcp = Vec::new();
        for handle in tcp_handles {
            let Some(state) = self.tcp.get_mut(&handle) else {
                continue;
            };
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            let key = state.key.or_else(|| {
                let local = socket.local_endpoint()?;
                let remote = socket.remote_endpoint()?;
                Some(TunFlowKey {
                    network: Network::Tcp,
                    source: remote.into(),
                    destination: local.into(),
                })
            });
            state.key = key;
            let Some(key) = key else {
                continue;
            };
            self.tcp_by_key.insert(key, handle);
            let flow = TunFlow { key };
            if socket.is_active() && socket.may_send() && !state.opened {
                state.opened = true;
                self.events.push_back(TunEvent::TcpOpened { flow });
            }
            let mut event_bytes = 0usize;
            while socket.can_recv() && event_bytes < MAX_TCP_EVENT_BYTES_PER_POLL {
                // `recv_capacity` is the remaining socket buffer, not the
                // size of the next packet. Keep each event bounded so a fast
                // TUN stream cannot allocate one large Vec per segment.
                let mut payload = vec![0; socket.recv_capacity().min(64 * 1024)];
                match socket.recv_slice(&mut payload) {
                    Ok(length) if length != 0 => {
                        payload.truncate(length);
                        event_bytes = event_bytes.saturating_add(length);
                        self.events.push_back(TunEvent::TcpData { flow, payload });
                    }
                    Ok(_) => break,
                    Err(tcp::RecvError::Finished) => {
                        if !state.half_closed {
                            state.half_closed = true;
                            self.events.push_back(TunEvent::TcpHalfClosed { flow });
                        }
                        break;
                    }
                    Err(_) => break,
                }
            }
            if state.opened && socket.is_active() && !socket.may_recv() && !state.half_closed {
                state.half_closed = true;
                self.events.push_back(TunEvent::TcpHalfClosed { flow });
            }
            if !socket.is_open() && state.opened {
                self.events.push_back(TunEvent::TcpClosed { flow });
            }
            if !socket.is_open() {
                closed_tcp.push((handle, key));
            }
        }
        for (handle, key) in closed_tcp {
            self.tcp.remove(&handle);
            self.tcp_by_key.remove(&key);
            self.sockets.remove(handle);
        }

        let udp_handles: Vec<_> = self.udp.keys().copied().collect();
        let mut closed_udp = Vec::new();
        for handle in udp_handles {
            let Some(state) = self.udp.get(&handle) else {
                continue;
            };
            let local = state.local;
            let closing = state.closing;
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            while socket.can_recv() {
                let (payload, metadata) = socket.recv().map_err(|error| {
                    Error::new(ErrorKind::Protocol, format!("TUN UDP read: {error:?}"))
                })?;
                let flow = TunFlow {
                    key: TunFlowKey {
                        network: Network::Udp,
                        source: metadata.endpoint.into(),
                        destination: local,
                    },
                };
                self.events.push_back(TunEvent::UdpDatagram {
                    flow,
                    payload: payload.to_vec(),
                });
            }
            if closing {
                closed_udp.push((handle, local));
            }
        }
        for (handle, local) in closed_udp {
            self.udp_by_local.remove(&local);
            self.udp.remove(&handle);
            self.sockets.remove(handle);
        }
        Ok(())
    }
}

#[cfg(feature = "async-proxy")]
enum ProxyCommand {
    Data(Vec<u8>),
    Shutdown,
}

/// Independent deadlines for one TUN proxy flow.
///
/// `connect` bounds proxy stream/datagram establishment, `read` bounds one
/// inbound read, `write` bounds one outbound write, and `idle` bounds the
/// period in which a flow may make no progress at all.  Keeping these
/// meanings separate lets callers tune UDP idle expiry without accidentally
/// shortening a TLS/HTTP2 connect or a large backpressured write.
#[cfg(feature = "async-proxy")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyTimeouts {
    pub connect: Duration,
    pub read: Duration,
    pub write: Duration,
    pub idle: Duration,
}

#[cfg(feature = "async-proxy")]
impl ProxyTimeouts {
    pub fn all(timeout: Duration) -> Result<Self> {
        let timeouts = Self {
            connect: timeout,
            read: timeout,
            write: timeout,
            idle: timeout,
        };
        timeouts.validate()?;
        Ok(timeouts)
    }

    pub fn validate(&self) -> Result<()> {
        if self.connect.is_zero()
            || self.read.is_zero()
            || self.write.is_zero()
            || self.idle.is_zero()
        {
            return Err(Error::invalid("TUN proxy timeouts must be non-zero"));
        }
        Ok(())
    }
}

#[cfg(feature = "async-proxy")]
impl Default for ProxyTimeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(30),
            read: Duration::from_secs(30),
            write: Duration::from_secs(30),
            idle: Duration::from_secs(30),
        }
    }
}

#[cfg(feature = "async-proxy")]
enum UdpProxyCommand {
    Data {
        flow: TunFlowKey,
        target: Endpoint,
        payload: Vec<u8>,
    },
    CloseFlow(TunFlowKey),
    Shutdown,
}

#[cfg(feature = "async-proxy")]
enum ProxyOutput {
    TcpData {
        flow: TunFlowKey,
        payload: Vec<u8>,
    },
    TcpClosed {
        flow: TunFlowKey,
    },
    UdpBound {
        source: UdpSourceKey,
        translated: SocketAddr,
    },
    UdpData {
        flow: TunFlowKey,
        payload: Vec<u8>,
    },
    UdpClosed {
        flow: TunFlowKey,
    },
}

#[cfg(feature = "async-proxy")]
struct ProxyTask {
    command: mpsc::Sender<ProxyCommand>,
    join: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "async-proxy")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpSourceKey {
    network: Network,
    source: SocketAddr,
}

#[cfg(feature = "async-proxy")]
struct UdpProxyTask {
    command: mpsc::Sender<UdpProxyCommand>,
    join: tokio::task::JoinHandle<()>,
    flows: HashSet<TunFlowKey>,
}

#[cfg(feature = "async-proxy")]
struct NatBinding {
    table: NatTable,
    idle_timeout: Duration,
}

#[cfg(feature = "async-proxy")]
type AsyncDnsTask = LocalBoxFuture<'static, (TunFlowKey, Result<Vec<u8>>)>;

/// Bridges owned TUN events to async proxy tasks.
///
/// The dispatcher remains the owner of smoltcp sockets.  Each flow task owns
/// exactly one proxy stream/datagram and communicates through bounded Tokio
/// channels.  This gives the packet side a visible backpressure boundary and
/// ensures no blocking connector or async read/write is performed while
/// `Interface::poll` holds mutable access to the packet engine.
#[cfg(feature = "async-proxy")]
pub struct TunProxyRuntime {
    selector: Arc<dyn AsyncProxySelector>,
    context_provider: Arc<dyn Fn(TunFlow) -> crate::FlowContext + Send + Sync>,
    process_resolver: Option<Arc<dyn ProcessResolver>>,
    observer: Option<Arc<dyn TunFlowObserver>>,
    dns_handler: Option<Arc<dyn DnsHandler>>,
    async_dns_handler: Option<Arc<dyn AsyncDnsHandler>>,
    nat: Option<NatBinding>,
    tasks: HashMap<TunFlowKey, ProxyTask>,
    udp_tasks: HashMap<UdpSourceKey, UdpProxyTask>,
    udp_flow_sources: HashMap<TunFlowKey, UdpSourceKey>,
    pending_tcp: HashMap<TunFlowKey, VecDeque<Vec<u8>>>,
    dns_tasks: Vec<tokio::task::JoinHandle<()>>,
    async_dns_tasks: FuturesUnordered<AsyncDnsTask>,
    tracked_flows: HashSet<TunFlowKey>,
    output_tx: mpsc::Sender<ProxyOutput>,
    output_rx: mpsc::Receiver<ProxyOutput>,
    channel_capacity: usize,
    timeouts: ProxyTimeouts,
}

#[cfg(feature = "async-proxy")]
impl TunProxyRuntime {
    pub fn new(selector: Arc<dyn AsyncProxySelector>, channel_capacity: usize) -> Result<Self> {
        if channel_capacity == 0 {
            return Err(Error::invalid(
                "proxy flow channel capacity must be non-zero",
            ));
        }
        let (output_tx, output_rx) = mpsc::channel(channel_capacity);
        Ok(Self {
            selector,
            context_provider: Arc::new(|flow| flow.context()),
            process_resolver: default_process_resolver(),
            observer: None,
            dns_handler: None,
            async_dns_handler: None,
            nat: None,
            tasks: HashMap::new(),
            udp_tasks: HashMap::new(),
            udp_flow_sources: HashMap::new(),
            pending_tcp: HashMap::new(),
            dns_tasks: Vec::new(),
            async_dns_tasks: FuturesUnordered::new(),
            tracked_flows: HashSet::new(),
            output_tx,
            output_rx,
            channel_capacity,
            timeouts: ProxyTimeouts::default(),
        })
    }

    pub fn with_dns_handler(mut self, handler: Arc<dyn DnsHandler>) -> Self {
        self.dns_handler = Some(handler);
        self
    }

    pub fn with_async_dns_handler(mut self, handler: Arc<dyn AsyncDnsHandler>) -> Self {
        self.async_dns_handler = Some(handler);
        self
    }

    pub fn with_observer(mut self, observer: Arc<dyn TunFlowObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    pub fn with_context_provider<F>(mut self, provider: F) -> Self
    where
        F: Fn(TunFlow) -> crate::FlowContext + Send + Sync + 'static,
    {
        self.context_provider = Arc::new(provider);
        self
    }

    /// Add process ownership metadata to newly opened flows when the target
    /// platform exposes socket ownership.  The default is Linux `/proc`; a
    /// caller can replace it with a native Android or desktop resolver.
    pub fn with_process_resolver<R>(mut self, resolver: R) -> Self
    where
        R: ProcessResolver + 'static,
    {
        self.process_resolver = Some(Arc::new(resolver));
        self
    }

    pub fn set_process_resolver(&mut self, resolver: Option<Arc<dyn ProcessResolver>>) {
        self.process_resolver = resolver;
    }

    /// Replace the read-only flow context snapshot at a lifecycle boundary.
    ///
    /// FakeIP allocation and other owner-task state can change while the TUN
    /// runtime is running. Updating the provider explicitly keeps that state
    /// out of `Send + Sync` packet tasks while allowing the next flow to use a
    /// refreshed reverse-lookup view.
    pub fn set_context_provider<F>(&mut self, provider: F)
    where
        F: Fn(TunFlow) -> crate::FlowContext + Send + Sync + 'static,
    {
        self.context_provider = Arc::new(provider);
    }

    pub fn with_nat(mut self, table: NatTable, idle_timeout: Duration) -> Result<Self> {
        if idle_timeout.is_zero() {
            return Err(Error::invalid("TUN proxy NAT timeout must be non-zero"));
        }
        self.nat = Some(NatBinding {
            table,
            idle_timeout,
        });
        Ok(self)
    }

    pub fn with_io_timeout(mut self, timeout: Duration) -> Result<Self> {
        self.timeouts = ProxyTimeouts::all(timeout)?;
        Ok(self)
    }

    pub fn with_timeouts(mut self, timeouts: ProxyTimeouts) -> Result<Self> {
        timeouts.validate()?;
        self.timeouts = timeouts;
        Ok(self)
    }

    pub fn nat_len(&self) -> Result<usize> {
        self.nat.as_ref().map_or(Ok(0), |nat| nat.table.len())
    }

    /// Number of currently registered proxy flow tasks.
    ///
    /// This is intentionally a small lifecycle metric: callers can assert
    /// that timeout, close, and cancellation paths have released their task
    /// owner without reaching into the task map.
    pub fn task_len(&self) -> usize {
        self.tasks.len() + self.udp_tasks.len() + self.dns_tasks.len() + self.async_dns_tasks.len()
    }

    fn context_for_flow(&self, flow: TunFlow) -> crate::FlowContext {
        let mut context = (self.context_provider)(flow);
        if context.component.is_none() {
            context.component = Some("tun".to_owned());
        }
        let needs_process =
            context.process.is_none() || context.process_id.is_none() || context.user_id.is_none();
        if needs_process {
            if let Some(resolver) = &self.process_resolver {
                if let Ok(Some(process)) =
                    resolver.resolve(flow.key.network, flow.key.source, flow.key.destination)
                {
                    if context.process.is_none() {
                        context.process = Some(process.path);
                    }
                    if context.process_id.is_none() {
                        context.process_id = Some(process.pid);
                    }
                    if context.user_id.is_none() {
                        context.user_id = Some(process.uid);
                    }
                }
            }
        }
        context
    }

    pub fn sweep(&mut self, dispatcher: &mut TunDispatcher) -> Result<usize> {
        let Some(nat) = &self.nat else {
            return Ok(0);
        };
        let expired = nat.table.sweep_keys()?;
        for key in &expired {
            let flow = TunFlowKey {
                network: key.network,
                source: key.source,
                destination: key.destination,
            };
            if key.network == Network::Tcp {
                let _ = dispatcher.abort_tcp(flow);
            } else if key.network == Network::Udp {
                let _ = dispatcher.close_udp(flow);
            }
            self.remove_flow_task(&flow);
        }
        Ok(expired.len())
    }

    pub fn handle_event(&mut self, event: TunEvent) -> Result<()> {
        match event {
            TunEvent::TcpOpened { flow } => {
                self.track_flow(flow.key)?;
                self.remove_task(&flow.key);
                let mut context = self.context_for_flow(flow);
                self.selector.route_context(&mut context);
                if let Some(observer) = &self.observer {
                    observer.opened(flow, context.clone());
                }
                let proxy = self.selector.select(&context);
                let (command, commands) = mpsc::channel(self.channel_capacity);
                let output = self.output_tx.clone();
                let key = flow.key;
                let timeouts = self.timeouts;
                let join = tokio::spawn(async move {
                    run_tcp_proxy(proxy, context, key, commands, output, timeouts).await;
                });
                self.tasks.insert(key, ProxyTask { command, join });
            }
            TunEvent::TcpData { flow, payload } => {
                self.touch_flow(flow.key)?;
                if let Some(observer) = &self.observer {
                    observer.bytes(flow.key, TunFlowDirection::Upload, payload.len());
                }
                self.send_command_or_cleanup(&flow.key, ProxyCommand::Data(payload))?;
            }
            TunEvent::TcpHalfClosed { flow } => {
                tun_debug(format!("TUN TCP half-closed flow={:?}", flow.key));
                self.touch_flow(flow.key)?;
                self.send_command_or_cleanup(&flow.key, ProxyCommand::Shutdown)?;
            }
            TunEvent::TcpClosed { flow } => {
                tun_debug(format!("TUN TCP socket closed flow={:?}", flow.key));
                self.remove_task(&flow.key);
                self.untrack_flow(&flow.key)?;
            }
            TunEvent::UdpDatagram { flow, payload } => {
                let first = !self.tracked_flows.contains(&flow.key);
                self.track_flow(flow.key)?;
                let mut context = self.context_for_flow(flow);
                self.selector.route_context(&mut context);
                if first && let Some(observer) = &self.observer {
                    observer.opened(flow, context.clone());
                }
                if let Some(observer) = &self.observer {
                    observer.bytes(flow.key, TunFlowDirection::Upload, payload.len());
                }
                if flow.key.destination.port() == 53 {
                    if let Some(handler) = self.dns_handler.clone() {
                        let output = self.output_tx.clone();
                        let timeout = self.timeouts.read;
                        let join = tokio::spawn(async move {
                            run_dns_query(handler, flow.key, payload, output, timeout).await;
                        });
                        self.dns_tasks.push(join);
                        return Ok(());
                    }
                }
                let target = context.effective_destination();
                let source = udp_source_key(flow.key);
                if !self.udp_tasks.contains_key(&source) {
                    let proxy = self.selector.select(&context);
                    let (command, commands) = mpsc::channel(self.channel_capacity);
                    let output = self.output_tx.clone();
                    let timeouts = self.timeouts;
                    let join = tokio::spawn(async move {
                        run_udp_proxy(proxy, context, flow.key, commands, output, timeouts).await;
                    });
                    self.udp_tasks.insert(
                        source,
                        UdpProxyTask {
                            command,
                            join,
                            flows: HashSet::from([flow.key]),
                        },
                    );
                } else if let Some(task) = self.udp_tasks.get_mut(&source) {
                    task.flows.insert(flow.key);
                }
                self.udp_flow_sources.insert(flow.key, source);
                if let Err(error) = self.send_udp_command(
                    &source,
                    UdpProxyCommand::Data {
                        flow: flow.key,
                        target,
                        payload,
                    },
                ) {
                    let flows = self.remove_udp_source_task(source);
                    for flow in flows {
                        self.untrack_flow(&flow)?;
                    }
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub async fn handle_event_async(&mut self, event: TunEvent) -> Result<()> {
        if let TunEvent::UdpDatagram { flow, payload } = event {
            if flow.key.destination.port() == 53
                && let Some(handler) = self.async_dns_handler.clone()
            {
                self.track_flow(flow.key)?;
                let timeout = self.timeouts.read;
                self.async_dns_tasks.push(Box::pin(async move {
                    let answer = match tokio::time::timeout(timeout, handler.answer(&payload)).await
                    {
                        Ok(answer) => answer,
                        Err(_) => Err(Error::new(
                            ErrorKind::Timeout,
                            "TUN async DNS resolver timed out",
                        )),
                    };
                    (flow.key, answer)
                }));
                return Ok(());
            }
            return self.handle_event(TunEvent::UdpDatagram { flow, payload });
        }
        self.handle_event(event)
    }

    pub fn poll_outputs(&mut self, dispatcher: &mut TunDispatcher) -> Result<usize> {
        self.apply_close_requests(dispatcher)?;
        self.poll_async_dns()?;
        let mut count = 0;
        let pending_flows = self.pending_tcp.keys().copied().collect::<Vec<_>>();
        for flow in pending_flows {
            let mut drained = false;
            while let Some(payload) = self
                .pending_tcp
                .get_mut(&flow)
                .and_then(VecDeque::pop_front)
            {
                if dispatcher.write_tcp(flow, &payload).is_err() {
                    self.pending_tcp
                        .entry(flow)
                        .or_default()
                        .push_front(payload);
                    break;
                }
                drained = true;
            }
            if drained && self.pending_tcp.get(&flow).is_some_and(VecDeque::is_empty) {
                self.pending_tcp.remove(&flow);
            }
        }
        while let Ok(output) = self.output_rx.try_recv() {
            count += 1;
            match output {
                ProxyOutput::TcpData { flow, payload } => {
                    self.touch_flow(flow)?;
                    if let Some(observer) = &self.observer {
                        observer.bytes(flow, TunFlowDirection::Download, payload.len());
                    }
                    if let Err(error) = dispatcher.write_tcp(flow, &payload) {
                        tun_debug(format!(
                            "TCP output backpressure/close flow={flow:?}: {error}"
                        ));
                        self.pending_tcp.entry(flow).or_default().push_back(payload);
                        break;
                    }
                }
                ProxyOutput::UdpData { flow, payload } => {
                    self.touch_flow(flow)?;
                    if let Some(observer) = &self.observer {
                        observer.bytes(flow, TunFlowDirection::Download, payload.len());
                    }
                    if dispatcher.write_udp(flow, &payload).is_err() {
                        self.remove_flow_task(&flow);
                        self.untrack_flow(&flow)?;
                    }
                }
                ProxyOutput::UdpClosed { flow } => {
                    let source = self.udp_flow_sources.get(&flow).copied();
                    let flows = source
                        .map(|source| self.remove_udp_source_task(source))
                        .unwrap_or_else(|| {
                            self.remove_flow_task(&flow);
                            vec![flow]
                        });
                    for flow in flows {
                        let _ = dispatcher.close_udp(flow);
                        self.untrack_flow(&flow)?;
                    }
                }
                ProxyOutput::TcpClosed { flow } => {
                    tun_debug(format!("TCP proxy task closed flow={flow:?}"));
                    let _ = dispatcher.close_tcp(flow);
                    self.pending_tcp.remove(&flow);
                    self.remove_task(&flow);
                    self.untrack_flow(&flow)?;
                }
                ProxyOutput::UdpBound { source, translated } => {
                    let Some(nat) = &self.nat else {
                        continue;
                    };
                    if let Err(error) =
                        nat.table
                            .bind_translated(source.network, source.source, translated)
                    {
                        let flows = self.remove_udp_source_task(source);
                        for flow in flows {
                            let _ = dispatcher.close_udp(flow);
                            self.untrack_flow(&flow)?;
                        }
                        return Err(error);
                    }
                }
            }
        }
        let finished_tcp: Vec<_> = self
            .tasks
            .iter()
            .filter(|(_, task)| task.join.is_finished())
            .map(|(flow, _)| *flow)
            .collect();
        for flow in finished_tcp {
            if let Some(task) = self.tasks.remove(&flow) {
                if let Some(Err(error)) = task.join.now_or_never() {
                    tun_debug(format!(
                        "TCP proxy task ended with join error flow={flow:?}: {error}"
                    ));
                }
                let _ = dispatcher.close_tcp(flow);
                self.untrack_flow(&flow)?;
            }
        }
        let finished: Vec<_> = self
            .udp_tasks
            .iter()
            .filter(|(_, task)| task.join.is_finished())
            .map(|(source, _)| *source)
            .collect();
        for source in finished {
            let flows = self.remove_udp_source_task(source);
            for flow in flows {
                let _ = dispatcher.close_udp(flow);
                self.untrack_flow(&flow)?;
            }
        }
        self.dns_tasks.retain(|task| !task.is_finished());
        Ok(count)
    }

    fn apply_close_requests(&mut self, dispatcher: &mut TunDispatcher) -> Result<()> {
        let Some(observer) = &self.observer else {
            return Ok(());
        };
        let requested = self
            .tracked_flows
            .iter()
            .copied()
            .filter(|flow| observer.close_requested(*flow))
            .collect::<Vec<_>>();
        for flow in requested {
            self.remove_flow_task(&flow);
            if flow.network == Network::Tcp {
                let _ = dispatcher.abort_tcp(flow);
            } else if flow.network == Network::Udp {
                let _ = dispatcher.close_udp(flow);
            }
            self.untrack_flow(&flow)?;
        }
        Ok(())
    }

    /// Poll locally-owned async DNS futures without awaiting a pending
    /// resolver. This keeps the TUN packet loop responsive while preserving
    /// `LocalBoxFuture` support for handlers that do not require `Send`.
    fn poll_async_dns(&mut self) -> Result<usize> {
        let mut count = 0;
        while let Some(Some((flow, answer))) = self.async_dns_tasks.next().now_or_never() {
            count += 1;
            let output = match answer {
                Ok(payload) => ProxyOutput::UdpData { flow, payload },
                Err(_) => ProxyOutput::UdpClosed { flow },
            };
            if let Err(error) = self.output_tx.try_send(output) {
                self.remove_flow_task(&flow);
                let _ = self.untrack_flow(&flow);
                return Err(Error::new(
                    ErrorKind::Timeout,
                    format!("TUN async DNS output channel: {error}"),
                ));
            }
        }
        Ok(count)
    }

    pub fn close(&mut self) {
        // This is the force-stop path. The async path below gives transports a
        // bounded opportunity to flush/shutdown before falling back here.
        let flows: Vec<_> = self.tasks.keys().copied().collect();
        for (_, task) in self.tasks.drain() {
            task.join.abort();
        }
        for flow in flows {
            let _ = self.untrack_flow(&flow);
        }
        let sources: Vec<_> = self.udp_tasks.keys().copied().collect();
        for source in sources {
            let flows = self.remove_udp_source_task(source);
            for flow in flows {
                let _ = self.untrack_flow(&flow);
            }
        }
        for task in self.dns_tasks.drain(..) {
            task.abort();
        }
        self.async_dns_tasks = FuturesUnordered::new();
        self.clear_tracked_flows();
    }

    /// Ask every owned transport to perform its protocol-level shutdown, then
    /// force-abort whatever has not exited by `deadline`.
    pub async fn close_graceful(&mut self, deadline: Duration) {
        let end = tokio::time::Instant::now() + deadline;
        let tcp_commands = self
            .tasks
            .values()
            .map(|task| task.command.clone())
            .collect::<Vec<_>>();
        let udp_commands = self
            .udp_tasks
            .values()
            .map(|task| task.command.clone())
            .collect::<Vec<_>>();
        let remaining = end.saturating_duration_since(tokio::time::Instant::now());
        if !remaining.is_zero() {
            let send_commands = async move {
                let tcp_sends = async move {
                    let mut sends = FuturesUnordered::new();
                    for command in tcp_commands {
                        sends.push(async move {
                            let _ = command.send(ProxyCommand::Shutdown).await;
                        });
                    }
                    while sends.next().await.is_some() {}
                };
                let udp_sends = async move {
                    let mut sends = FuturesUnordered::new();
                    for command in udp_commands {
                        sends.push(async move {
                            let _ = command.send(UdpProxyCommand::Shutdown).await;
                        });
                    }
                    while sends.next().await.is_some() {}
                };
                tokio::join!(tcp_sends, udp_sends);
            };
            let _ = tokio::time::timeout(remaining, send_commands).await;
        }
        while self.tasks.values().any(|task| !task.join.is_finished())
            || self.udp_tasks.values().any(|task| !task.join.is_finished())
            || self.dns_tasks.iter().any(|task| !task.is_finished())
            || !self.async_dns_tasks.is_empty()
        {
            if tokio::time::Instant::now() >= end {
                break;
            }
            let _ = self.poll_async_dns();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        self.close();
    }

    fn send_command(&self, flow: &TunFlowKey, command: ProxyCommand) -> Result<()> {
        let Some(task) = self.tasks.get(flow) else {
            return Err(Error::new(
                ErrorKind::NotFound,
                "TUN flow has no proxy task",
            ));
        };
        task.command.try_send(command).map_err(|error| {
            let message = error.to_string();
            let kind = match &error {
                mpsc::error::TrySendError::Full(_) => ErrorKind::Timeout,
                mpsc::error::TrySendError::Closed(_) => ErrorKind::Closed,
            };
            Error::new(kind, format!("TUN proxy flow channel: {message}"))
        })
    }

    fn send_command_or_cleanup(&mut self, flow: &TunFlowKey, command: ProxyCommand) -> Result<()> {
        match self.send_command(flow, command) {
            Ok(()) => Ok(()),
            Err(error) => {
                if matches!(error.kind, ErrorKind::Closed | ErrorKind::NotFound) {
                    self.remove_task(flow);
                    self.untrack_flow(flow)?;
                }
                Err(error)
            }
        }
    }

    fn remove_task(&mut self, flow: &TunFlowKey) {
        if let Some(task) = self.tasks.remove(flow) {
            task.join.abort();
        }
        self.pending_tcp.remove(flow);
    }

    fn remove_flow_task(&mut self, flow: &TunFlowKey) {
        self.remove_task(flow);
        let Some(source) = self.udp_flow_sources.remove(flow) else {
            return;
        };
        let remove_source = if let Some(task) = self.udp_tasks.get_mut(&source) {
            task.flows.remove(flow);
            if task.flows.is_empty() {
                true
            } else {
                let _ = task.command.try_send(UdpProxyCommand::CloseFlow(*flow));
                false
            }
        } else {
            false
        };
        if remove_source {
            let _ = self.remove_udp_source_task(source);
        }
    }

    fn send_udp_command(&self, source: &UdpSourceKey, command: UdpProxyCommand) -> Result<()> {
        let Some(task) = self.udp_tasks.get(source) else {
            return Err(Error::new(
                ErrorKind::NotFound,
                "TUN UDP source has no proxy task",
            ));
        };
        task.command.try_send(command).map_err(|error| {
            let message = error.to_string();
            let kind = match &error {
                mpsc::error::TrySendError::Full(_) => ErrorKind::Timeout,
                mpsc::error::TrySendError::Closed(_) => ErrorKind::Closed,
            };
            Error::new(kind, format!("TUN UDP source channel: {message}"))
        })
    }

    fn remove_udp_source_task(&mut self, source: UdpSourceKey) -> Vec<TunFlowKey> {
        let Some(task) = self.udp_tasks.remove(&source) else {
            return Vec::new();
        };
        let _ = task.command.try_send(UdpProxyCommand::Shutdown);
        task.join.abort();
        let flows = task.flows.into_iter().collect::<Vec<_>>();
        for flow in &flows {
            self.udp_flow_sources.remove(flow);
        }
        flows
    }

    fn track_flow(&mut self, flow: TunFlowKey) -> Result<()> {
        if let Some(nat) = &self.nat {
            let key = nat_key(flow);
            if nat.table.touch(&key)?.is_none() {
                nat.table.insert(key, flow.source, nat.idle_timeout)?;
            }
        }
        self.tracked_flows.insert(flow);
        Ok(())
    }

    fn touch_flow(&self, flow: TunFlowKey) -> Result<()> {
        let Some(nat) = &self.nat else {
            return Ok(());
        };
        let key = nat_key(flow);
        let _ = nat.table.touch(&key)?;
        Ok(())
    }

    fn untrack_flow(&mut self, flow: &TunFlowKey) -> Result<()> {
        if !self.tracked_flows.remove(flow) {
            return Ok(());
        }
        let Some(nat) = &self.nat else {
            if let Some(observer) = &self.observer {
                observer.closed(*flow);
            }
            return Ok(());
        };
        let _ = nat.table.remove(&nat_key(*flow))?;
        if let Some(observer) = &self.observer {
            observer.closed(*flow);
        }
        Ok(())
    }

    fn clear_tracked_flows(&mut self) {
        let flows = self.tracked_flows.drain().collect::<Vec<_>>();
        for flow in flows {
            if let Some(nat) = &self.nat {
                let _ = nat.table.remove(&nat_key(flow));
            }
            if let Some(observer) = &self.observer {
                observer.closed(flow);
            }
        }
    }
}

#[cfg(feature = "async-proxy")]
impl Drop for TunProxyRuntime {
    fn drop(&mut self) {
        let flows: Vec<_> = self.tasks.keys().copied().collect();
        for task in self.tasks.drain().map(|(_, task)| task) {
            task.join.abort();
        }
        for task in self.dns_tasks.drain(..) {
            task.abort();
        }
        let nat_table = self.nat.as_ref().map(|nat| nat.table.clone());
        if let Some(nat_table) = nat_table {
            for flow in flows {
                let _ = nat_table.remove(&nat_key(flow));
            }
            let sources: Vec<_> = self.udp_tasks.keys().copied().collect();
            for source in sources {
                let flows = self.remove_udp_source_task(source);
                for flow in flows {
                    let _ = nat_table.remove(&nat_key(flow));
                }
            }
            for flow in self.tracked_flows.drain() {
                let _ = nat_table.remove(&nat_key(flow));
            }
        } else {
            let sources: Vec<_> = self.udp_tasks.keys().copied().collect();
            for source in sources {
                let _ = self.remove_udp_source_task(source);
            }
            self.tracked_flows.clear();
        }
    }
}

#[cfg(feature = "async-proxy")]
fn nat_key(flow: TunFlowKey) -> NatKey {
    NatKey {
        network: flow.network,
        source: flow.source,
        destination: flow.destination,
    }
}

#[cfg(feature = "async-proxy")]
fn udp_source_key(flow: TunFlowKey) -> UdpSourceKey {
    UdpSourceKey {
        network: flow.network,
        source: flow.source,
    }
}

#[cfg(feature = "async-proxy")]
async fn run_tcp_proxy(
    proxy: Arc<dyn AsyncProxy>,
    context: crate::FlowContext,
    flow: TunFlowKey,
    mut commands: mpsc::Receiver<ProxyCommand>,
    output: mpsc::Sender<ProxyOutput>,
    timeouts: ProxyTimeouts,
) {
    let stream = match tokio::time::timeout(timeouts.connect, proxy.connect(&context)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(_)) => {
            tun_debug(format!("TCP proxy connect failed flow={flow:?}"));
            let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
            return;
        }
        Err(_) => {
            tun_debug(format!("TCP proxy connect timed out flow={flow:?}"));
            let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
            return;
        }
    };
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer = vec![0u8; 16 * 1024];
    let mut write_closed = false;
    let mut idle = Box::pin(tokio::time::sleep(timeouts.idle));
    loop {
        tokio::select! {
            result = tokio::time::timeout(timeouts.read, tokio::io::AsyncReadExt::read(&mut reader, &mut buffer)) => {
                match result {
                    Ok(Ok(0)) => {
                        tun_debug(format!("TCP proxy remote EOF flow={flow:?}"));
                        let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
                        return;
                    }
                    Ok(Err(_)) => {
                        tun_debug(format!("TCP proxy remote read failed flow={flow:?}"));
                        let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
                        return;
                    }
                    Err(_) => {
                        tun_debug(format!("TCP proxy remote read timed out flow={flow:?}"));
                        let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
                        return;
                    }
                    Ok(Ok(length)) => {
                        idle.as_mut().reset(tokio::time::Instant::now() + timeouts.idle);
                        if !emit_output(
                            &output,
                            ProxyOutput::TcpData { flow, payload: buffer[..length].to_vec() },
                            timeouts.idle,
                        ).await {
                            tun_debug(format!("TCP proxy output channel timed out flow={flow:?}"));
                            let _ = tokio::time::timeout(
                                timeouts.write,
                                tokio::io::AsyncWriteExt::shutdown(&mut writer),
                            )
                            .await;
                            return;
                        }
                    }
                }
            }
            command = commands.recv() => {
                match command {
                    Some(ProxyCommand::Data(payload)) if !write_closed => {
                        let write = tokio::time::timeout(
                            timeouts.write,
                            tokio::io::AsyncWriteExt::write_all(&mut writer, &payload),
                        )
                        .await;
                        if !matches!(write, Ok(Ok(()))) {
                            tun_debug(format!("TCP proxy remote write failed flow={flow:?}"));
                            let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
                            return;
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + timeouts.idle);
                    }
                    Some(ProxyCommand::Shutdown) | None if !write_closed => {
                        let _ = tokio::time::timeout(
                            timeouts.write,
                            tokio::io::AsyncWriteExt::shutdown(&mut writer),
                        ).await;
                        write_closed = true;
                        idle.as_mut().reset(tokio::time::Instant::now() + timeouts.idle);
                    }
                    Some(ProxyCommand::Data(_)) | Some(ProxyCommand::Shutdown) | None => {}
                }
            }
            _ = &mut idle => {
                tun_debug(format!("TCP proxy idle timeout flow={flow:?}"));
                let _ = emit_output(&output, ProxyOutput::TcpClosed { flow }, timeouts.idle).await;
                return;
            }
        }
    }
}

#[cfg(feature = "async-proxy")]
async fn run_udp_proxy(
    proxy: Arc<dyn AsyncProxy>,
    context: crate::FlowContext,
    initial_flow: TunFlowKey,
    mut commands: mpsc::Receiver<UdpProxyCommand>,
    output: mpsc::Sender<ProxyOutput>,
    timeouts: ProxyTimeouts,
) {
    let datagram = match tokio::time::timeout(timeouts.connect, proxy.open_datagram(&context)).await
    {
        Ok(Ok(datagram)) => datagram,
        Ok(Err(_)) => {
            let _ = emit_output(
                &output,
                ProxyOutput::UdpClosed { flow: initial_flow },
                timeouts.idle,
            )
            .await;
            return;
        }
        Err(_) => {
            let _ = emit_output(
                &output,
                ProxyOutput::UdpClosed { flow: initial_flow },
                timeouts.idle,
            )
            .await;
            return;
        }
    };
    if let Ok(Endpoint::Ip {
        network: Network::Udp,
        addr: translated,
    }) = datagram.local_addr()
    {
        if !emit_output(
            &output,
            ProxyOutput::UdpBound {
                source: udp_source_key(initial_flow),
                translated,
            },
            timeouts.idle,
        )
        .await
        {
            let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
            return;
        }
    }
    let mut buffer = vec![0u8; 65_535];
    let mut routes = HashMap::<Endpoint, TunFlowKey>::new();
    let mut last_flow = None;
    let mut idle = Box::pin(tokio::time::sleep(timeouts.idle));
    loop {
        tokio::select! {
            command = commands.recv() => {
                match command {
                    Some(UdpProxyCommand::Data {
                        flow,
                        target,
                        payload,
                    }) => {
                        let destination = target;
                        routes.insert(destination.clone(), flow);
                        last_flow = Some(flow);
                        let send = tokio::time::timeout(
                            timeouts.write,
                            datagram.send_to(&payload, destination),
                        )
                        .await;
                        if !matches!(send, Ok(Ok(_))) {
                            let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                            for flow in routes.values().copied().collect::<HashSet<_>>() {
                                let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.idle).await;
                            }
                            return;
                        }
                        idle.as_mut().reset(tokio::time::Instant::now() + timeouts.idle);
                    }
                    Some(UdpProxyCommand::CloseFlow(flow)) => {
                        routes.retain(|_, current| *current != flow);
                        if last_flow == Some(flow) {
                            last_flow = routes.values().next().copied();
                        }
                        if routes.is_empty() {
                            let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                            let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.idle).await;
                            return;
                        }
                    }
                    Some(UdpProxyCommand::Shutdown) | None => {
                        let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                        for flow in routes.values().copied().collect::<HashSet<_>>() {
                            let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.idle).await;
                        }
                        return;
                    }
                }
            }
            result = tokio::time::timeout(timeouts.read, datagram.recv_from(&mut buffer)) => {
                let Ok(Ok((length, source))) = result else {
                    let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                    for flow in routes.values().copied().collect::<HashSet<_>>() {
                        let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.idle).await;
                    }
                    return;
                };
                idle.as_mut().reset(tokio::time::Instant::now() + timeouts.idle);
                let flow = routes
                    .get(&source)
                    .copied()
                    .or(last_flow);
                let Some(flow) = flow else {
                    continue;
                };
                routes.entry(source).or_insert(flow);
                if !emit_output(
                    &output,
                    ProxyOutput::UdpData {
                        flow,
                        payload: buffer[..length].to_vec(),
                    },
                    timeouts.idle,
                ).await {
                    let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                    return;
                }
            }
            _ = &mut idle => {
                let _ = tokio::time::timeout(timeouts.write, datagram.close()).await;
                for flow in routes.values().copied().collect::<HashSet<_>>() {
                    let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeouts.idle).await;
                }
                return;
            }
        }
    }
}

#[cfg(feature = "async-proxy")]
async fn emit_output(
    output: &mpsc::Sender<ProxyOutput>,
    value: ProxyOutput,
    timeout: Duration,
) -> bool {
    matches!(
        tokio::time::timeout(timeout, output.send(value)).await,
        Ok(Ok(()))
    )
}

#[cfg(feature = "async-proxy")]
async fn run_dns_query(
    handler: Arc<dyn DnsHandler>,
    flow: TunFlowKey,
    payload: Vec<u8>,
    output: mpsc::Sender<ProxyOutput>,
    timeout: Duration,
) {
    let mut task = tokio::task::spawn_blocking(move || answer_query(&payload, handler.as_ref()));
    let answer = match tokio::time::timeout(timeout, &mut task).await {
        Ok(Ok(answer)) => answer.ok(),
        Ok(Err(_)) | Err(_) => {
            task.abort();
            None
        }
    };
    match answer {
        Some(payload) => {
            let _ = emit_output(&output, ProxyOutput::UdpData { flow, payload }, timeout).await;
        }
        None => {
            let _ = emit_output(&output, ProxyOutput::UdpClosed { flow }, timeout).await;
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct TransportTuple {
    protocol: IpProtocol,
    source: SocketAddr,
    destination: SocketAddr,
    tcp_syn: bool,
}

fn parse_transport_tuple(packet: &[u8]) -> Result<Option<TransportTuple>> {
    let version = IpVersion::of_packet(packet)
        .map_err(|_| Error::invalid("TUN packet is not IPv4 or IPv6"))?;
    let (source, destination, protocol, payload) = match version {
        IpVersion::Ipv4 => {
            let packet = smoltcp::wire::Ipv4Packet::new_checked(packet)
                .map_err(|_| Error::invalid("malformed IPv4 packet"))?;
            (
                SocketAddr::new(IpAddr::V4(packet.src_addr().into()), 0),
                SocketAddr::new(IpAddr::V4(packet.dst_addr().into()), 0),
                packet.next_header(),
                packet.payload(),
            )
        }
        IpVersion::Ipv6 => {
            let packet = smoltcp::wire::Ipv6Packet::new_checked(packet)
                .map_err(|_| Error::invalid("malformed IPv6 packet"))?;
            (
                SocketAddr::new(IpAddr::V6(packet.src_addr().into()), 0),
                SocketAddr::new(IpAddr::V6(packet.dst_addr().into()), 0),
                packet.next_header(),
                packet.payload(),
            )
        }
    };
    match protocol {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(payload)
                .map_err(|_| Error::invalid("malformed TUN TCP packet"))?;
            Ok(Some(TransportTuple {
                protocol,
                source: SocketAddr::new(source.ip(), tcp.src_port()),
                destination: SocketAddr::new(destination.ip(), tcp.dst_port()),
                tcp_syn: tcp.syn(),
            }))
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(payload)
                .map_err(|_| Error::invalid("malformed TUN UDP packet"))?;
            Ok(Some(TransportTuple {
                protocol,
                source: SocketAddr::new(source.ip(), udp.src_port()),
                destination: SocketAddr::new(destination.ip(), udp.dst_port()),
                tcp_syn: false,
            }))
        }
        _ => Ok(None),
    }
}

pub fn inspect_ip_packet(packet: &[u8]) -> Result<PacketInfo> {
    if packet.is_empty() {
        return Err(Error::invalid("TUN packet is empty"));
    }
    let version = IpVersion::of_packet(packet)
        .map_err(|_| Error::invalid("TUN packet is not IPv4 or IPv6"))?;
    let fragmented = match version {
        IpVersion::Ipv4 => {
            let packet = smoltcp::wire::Ipv4Packet::new_checked(packet)
                .map_err(|_| Error::invalid("malformed IPv4 packet"))?;
            packet.more_frags() || packet.frag_offset() != 0
        }
        IpVersion::Ipv6 => {
            let packet = smoltcp::wire::Ipv6Packet::new_checked(packet)
                .map_err(|_| Error::invalid("malformed IPv6 packet"))?;
            ipv6_has_fragment_header(packet.into_inner())
        }
    };
    Ok(PacketInfo {
        version: match version {
            IpVersion::Ipv4 => IpPacketVersion::V4,
            IpVersion::Ipv6 => IpPacketVersion::V6,
        },
        length: packet.len(),
        fragmented,
    })
}

/// Validate a packet against the TUN MTU without attempting reassembly.
///
/// A fragmented IP datagram is represented by multiple wire packets, and
/// each packet must fit the interface MTU independently.  This helper keeps
/// that behavior explicit for both real `AsyncDevice` reads and injected
/// devices used by Android/iOS hosts.
pub fn inspect_ip_packet_with_mtu(packet: &[u8], mtu: usize) -> Result<PacketInfo> {
    if !(576..=9216).contains(&mtu) {
        return Err(Error::invalid("TUN MTU must be between 576 and 9216"));
    }
    let info = inspect_ip_packet(packet)?;
    if info.length > mtu {
        return Err(Error::invalid("TUN packet exceeds configured MTU"));
    }
    Ok(info)
}

fn ipv6_has_fragment_header(bytes: &[u8]) -> bool {
    let mut next_header = bytes[6];
    let mut offset = 40usize;

    // Hop-by-hop, routing and destination options are all TLV extension
    // headers whose length is expressed in eight-octet units.  AH uses
    // four-octet units.  Stop at ESP/unknown headers rather than guessing
    // offsets from attacker-controlled bytes.
    for _ in 0..16 {
        match next_header {
            44 => {
                if offset + 8 > bytes.len() {
                    return false;
                }
                let fragment = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
                return fragment & 0xfff9 != 0;
            }
            0 | 43 | 60 => {
                if offset + 2 > bytes.len() {
                    return false;
                }
                let header_len = (bytes[offset + 1] as usize + 1) * 8;
                if header_len < 8 || offset + header_len > bytes.len() {
                    return false;
                }
                next_header = bytes[offset];
                offset += header_len;
            }
            51 => {
                if offset + 2 > bytes.len() {
                    return false;
                }
                let header_len = (bytes[offset + 1] as usize + 2) * 4;
                if header_len < 12 || offset + header_len > bytes.len() {
                    return false;
                }
                next_header = bytes[offset];
                offset += header_len;
            }
            _ => return false,
        }
    }
    false
}

#[derive(Debug, Default)]
struct PacketQueue {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl PacketQueue {
    fn new(capacity: usize) -> Self {
        Self {
            rx: VecDeque::with_capacity(capacity),
            tx: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push_rx(&mut self, packet: Vec<u8>) -> bool {
        if self.rx.len() >= self.capacity {
            return false;
        }
        self.rx.push_back(packet);
        true
    }

    fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }

    fn pop_rx(&mut self) -> Option<Vec<u8>> {
        self.rx.pop_front()
    }
}

pub struct QueueRxToken {
    packet: Vec<u8>,
}

impl phy::RxToken for QueueRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

pub struct QueueTxToken {
    queue: Arc<Mutex<PacketQueue>>,
    timestamp: Instant,
    mtu: usize,
}

impl phy::TxToken for QueueTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        if len <= self.mtu {
            if let Ok(mut queue) = self.queue.lock() {
                if queue.tx.len() < queue.capacity {
                    queue.tx.push_back(packet);
                }
            }
        }
        let _ = self.timestamp;
        result
    }
}

/// A smoltcp `Device` backed by bounded in-memory queues.
///
/// Async TUN I/O is deliberately kept outside smoltcp's synchronous token API:
/// `recv_from_tun` fills the RX queue and `send_to_tun` drains the TX queue.
/// This keeps the runtime boundary small and makes the packet engine testable
/// with no privileged TUN device.
pub struct SmoltcpTunDevice {
    queue: Arc<Mutex<PacketQueue>>,
    mtu: usize,
}

impl SmoltcpTunDevice {
    pub fn new(mtu: usize, queue_capacity: usize) -> Result<Self> {
        if !(576..=9216).contains(&mtu) || queue_capacity == 0 {
            return Err(Error::invalid("invalid smoltcp TUN device configuration"));
        }
        Ok(Self {
            queue: Arc::new(Mutex::new(PacketQueue::new(queue_capacity))),
            mtu,
        })
    }

    pub fn enqueue_rx(&self, packet: Vec<u8>) -> Result<bool> {
        inspect_ip_packet_with_mtu(&packet, self.mtu)?;
        self.queue
            .lock()
            .map(|mut queue| queue.push_rx(packet))
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    pub fn take_tx(&self) -> Result<Option<Vec<u8>>> {
        self.queue
            .lock()
            .map(|mut queue| queue.pop_tx())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    /// Inspect the next TX packet without removing it.
    pub fn peek_tx_packet(&self) -> Result<Option<Vec<u8>>> {
        self.queue
            .lock()
            .map(|queue| queue.tx.front().cloned())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    /// Inspect the next RX packet without removing it.
    ///
    /// This is primarily useful for a dispatcher that must choose an ICMP
    /// identifier or another socket before handing the packet to smoltcp.
    pub fn peek_rx_packet(&self) -> Result<Option<Vec<u8>>> {
        self.queue
            .lock()
            .map(|queue| queue.rx.front().cloned())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    /// Remove the next RX packet without handing it to smoltcp.
    ///
    /// A dispatcher may use this for packets it deliberately handles outside
    /// the socket set, or for control traffic that is not part of the current
    /// protocol loop. Normal data-plane code should let `Interface::poll`
    /// consume the queue instead.
    pub fn take_rx_packet(&self) -> Result<Option<Vec<u8>>> {
        self.queue
            .lock()
            .map(|mut queue| queue.pop_rx())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    pub fn queued_rx(&self) -> Result<usize> {
        self.queue
            .lock()
            .map(|queue| queue.rx.len())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    pub fn queued_tx(&self) -> Result<usize> {
        self.queue
            .lock()
            .map(|queue| queue.tx.len())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }
}

impl phy::Device for SmoltcpTunDevice {
    type RxToken<'a> = QueueRxToken;
    type TxToken<'a> = QueueTxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = self.mtu;
        capabilities.medium = Medium::Ip;
        capabilities.checksum = ChecksumCapabilities::default();
        capabilities
    }

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.queue.lock().ok()?.rx.pop_front()?;
        Some((
            QueueRxToken { packet },
            QueueTxToken {
                queue: Arc::clone(&self.queue),
                timestamp,
                mtu: self.mtu,
            },
        ))
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let queue = self.queue.lock().ok()?;
        if queue.tx.len() >= queue.capacity {
            return None;
        }
        drop(queue);
        Some(QueueTxToken {
            queue: Arc::clone(&self.queue),
            timestamp,
            mtu: self.mtu,
        })
    }
}

pub struct TunRuntime {
    #[cfg(feature = "tun-routes")]
    route_lease: Option<TunRouteLease>,
    device: AsyncDevice,
    smoltcp_device: SmoltcpTunDevice,
    interface: Interface,
    buffer: Vec<u8>,
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
    configured_name: Option<String>,
}

impl TunRuntime {
    /// Assemble the packet engine around an already-created asynchronous TUN.
    ///
    /// Desktop callers normally use [`Self::open`]. Android/iOS VPN hosts
    /// create the device through their platform API and pass ownership of the
    /// resulting `tun-rs::AsyncDevice` here. This keeps the platform fd/FFI
    /// boundary outside smoltcp and avoids a second packet-stack path.
    pub fn from_async_device(config: TunConfig, device: AsyncDevice) -> io::Result<Self> {
        config
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
        let configured_name = config.name.clone();
        let mut smoltcp_device = SmoltcpTunDevice::new(config.mtu, config.queue_capacity)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut smoltcp_device,
            Instant::from_millis(0),
        );
        // A TUN gateway receives packets for arbitrary routed destinations;
        // they are not necessarily assigned to the TUN interface itself.
        // smoltcp's AnyIP mode accepts those packets while retaining the
        // original destination endpoint for the dispatcher flow key.
        interface.set_any_ip(true);
        if let Some((address, prefix)) = config.ipv4 {
            interface.update_ip_addrs(|addresses| {
                let _ = addresses.push(IpCidr::new(IpAddress::Ipv4(address), prefix));
            });
        }
        for (address, prefix) in &config.ipv6 {
            interface.update_ip_addrs(|addresses| {
                let _ = addresses.push(IpCidr::new(IpAddress::Ipv6(*address), *prefix));
            });
        }
        Ok(Self {
            #[cfg(feature = "tun-routes")]
            route_lease: None,
            device,
            smoltcp_device,
            interface,
            buffer: vec![0; config.mtu.max(65535)],
            #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
            configured_name,
        })
    }

    #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
    pub fn open(config: TunConfig) -> io::Result<Self> {
        config
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let mut builder = DeviceBuilder::new().mtu(config.mtu as u16);
        if let Some(name) = config.name.as_deref() {
            builder = builder.name(name);
        }
        if let Some((address, prefix)) = config.ipv4 {
            builder = builder.ipv4(address, prefix, None);
        }
        for (address, prefix) in &config.ipv6 {
            builder = builder.ipv6(*address, *prefix);
        }
        let device = builder.build_async()?;
        Self::from_async_device(config, device)
    }

    /// Mobile platforms receive their TUN from the host VPN API rather than
    /// creating a desktop device. Callers must provide that device through
    /// [`Self::from_async_device`].
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
    pub fn open(_config: TunConfig) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this platform requires an injected TUN device",
        ))
    }

    /// Open a TUN device and install its owned routes as one startup
    /// operation. If route setup fails, dropping the partially initialized
    /// runtime closes the TUN descriptor so callers never receive a device
    /// without the route contract they requested.
    #[cfg(feature = "tun-routes")]
    pub fn open_with_routes<B>(
        config: TunConfig,
        backend: B,
        routes: &[TunRoute],
    ) -> io::Result<Self>
    where
        B: TunRouteBackend + 'static,
    {
        let mut runtime = Self::open(config)?;
        if let Err(error) = runtime.install_routes(backend, routes) {
            drop(runtime);
            return Err(error);
        }
        Ok(runtime)
    }

    pub fn smoltcp_device(&self) -> &SmoltcpTunDevice {
        &self.smoltcp_device
    }

    /// Return the kernel-assigned TUN interface name.
    ///
    /// A caller may request a name in [`TunConfig`], but the OS is the
    /// authority on the final name. Exposing the resolved value lets route
    /// ownership and teardown diagnostics refer to the same device.
    pub fn name(&self) -> io::Result<String> {
        #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
        {
            return Ok(self
                .configured_name
                .clone()
                .unwrap_or_else(|| "fd".to_owned()));
        }
        #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
        {
            self.device.name()
        }
    }

    /// Install and own a reversible route set for this TUN device.
    ///
    /// The backend is injected so callers can use the Linux netlink backend in
    /// production and a deterministic fake backend in tests. A second route
    /// lease is rejected until the first one has been closed successfully.
    #[cfg(feature = "tun-routes")]
    pub fn install_routes<B>(&mut self, backend: B, routes: &[TunRoute]) -> io::Result<()>
    where
        B: TunRouteBackend + 'static,
    {
        if self.route_lease.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "TUN routes are already installed",
            ));
        }
        self.route_lease = Some(TunRouteLease::apply(backend, routes)?);
        Ok(())
    }

    /// Install routes through Linux netlink after the TUN device exists.
    ///
    /// Address/device creation remains owned by `tun-rs`; this method only
    /// installs the explicit routes supplied by the application.
    #[cfg(all(feature = "tun-routes", target_os = "linux"))]
    pub fn install_linux_routes(&mut self, routes: &[TunRoute]) -> io::Result<()> {
        let interface = self.device.name()?;
        self.install_routes(LinuxTunRouteBackend::new(interface)?, routes)
    }

    /// Remove all routes owned by this runtime. Failed removals remain tracked
    /// and can be retried; a successful close makes the method idempotent.
    #[cfg(feature = "tun-routes")]
    pub fn close_routes(&mut self) -> io::Result<()> {
        let Some(mut lease) = self.route_lease.take() else {
            return Ok(());
        };
        match lease.close() {
            Ok(()) => Ok(()),
            Err(error) => {
                self.route_lease = Some(lease);
                Err(error)
            }
        }
    }

    /// Explicitly tear down this runtime.
    ///
    /// Route cleanup runs before `self` is consumed and the underlying TUN
    /// file descriptor is dropped. Cleanup errors are returned to the caller;
    /// the destructor still performs its final best-effort cleanup.
    pub fn shutdown(self) -> io::Result<()> {
        #[cfg(feature = "tun-routes")]
        {
            let mut this = self;
            this.close_routes()?;
        }
        #[cfg(not(feature = "tun-routes"))]
        let _ = self;
        Ok(())
    }

    /// Add an address to the smoltcp interface after the OS TUN device has
    /// been opened.
    ///
    /// This is useful for a gateway layout where the OS-facing TUN address
    /// and the virtual service address are different. The OS address remains
    /// managed by `TunConfig`; this method only changes the packet stack.
    pub fn add_ip_address(&mut self, address: IpAddress, prefix: u8) -> Result<()> {
        if (matches!(address, IpAddress::Ipv4(_)) && prefix > 32)
            || (matches!(address, IpAddress::Ipv6(_)) && prefix > 128)
        {
            return Err(Error::invalid("TUN address prefix is out of range"));
        }
        let mut result = Ok(());
        self.interface.update_ip_addrs(|addresses| {
            result = addresses.push(IpCidr::new(address, prefix));
        });
        result.map_err(|_| Error::invalid("smoltcp IP address capacity is exhausted"))
    }

    /// Replace the smoltcp interface address order without changing the OS
    /// address already applied to the TUN device.
    pub fn replace_ip_addresses(&mut self, addresses: &[IpCidr]) -> Result<()> {
        let mut result = Ok(());
        self.interface.update_ip_addrs(|current| {
            current.clear();
            for address in addresses {
                if current.push(*address).is_err() {
                    result = Err(());
                    break;
                }
            }
        });
        result.map_err(|_| Error::invalid("smoltcp IP address capacity is exhausted"))
    }

    pub async fn recv_from_tun(&mut self) -> io::Result<usize> {
        let length = self.device.recv(&mut self.buffer).await?;
        let packet = self.buffer[..length].to_vec();
        let accepted = self
            .smoltcp_device
            .enqueue_rx(packet)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
        if !accepted {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "TUN RX queue is full",
            ));
        }
        Ok(length)
    }

    pub async fn send_to_tun(&self) -> io::Result<Option<usize>> {
        let Some(packet) = self
            .smoltcp_device
            .take_tx()
            .map_err(|error| io::Error::other(error.to_string()))?
        else {
            return Ok(None);
        };
        Ok(Some(self.device.send(&packet).await?))
    }

    pub fn poll_smoltcp(
        &mut self,
        timestamp: Instant,
        sockets: &mut SocketSet<'_>,
    ) -> smoltcp::iface::PollResult {
        self.interface
            .poll(timestamp, &mut self.smoltcp_device, sockets)
    }

    /// Run the complete first-generation TUN data-plane loop.
    ///
    /// The loop has one packet-reader future and one timer branch.  Both paths
    /// advance smoltcp, drain proxy outputs, dispatch owned flow events, and
    /// flush all available TX packets.  The proxy runtime remains injectable;
    /// this method only owns lifecycle ordering and never selects a route by
    /// itself.
    #[cfg(feature = "async-proxy")]
    pub async fn run_dispatcher(
        &mut self,
        dispatcher: &mut TunDispatcher,
        proxy_runtime: &mut TunProxyRuntime,
        tick: Duration,
    ) -> io::Result<()> {
        self.run_dispatcher_until(
            dispatcher,
            proxy_runtime,
            tick,
            std::future::pending::<()>(),
        )
        .await
    }

    /// Run the TUN data plane until the caller's shutdown future completes.
    ///
    /// The shutdown branch is part of the runtime contract rather than an
    /// outer task convention: it closes all proxy flow tasks before returning
    /// so graceful stop and force-cancel have the same ownership boundary.
    #[cfg(feature = "async-proxy")]
    pub async fn run_dispatcher_until<F>(
        &mut self,
        dispatcher: &mut TunDispatcher,
        proxy_runtime: &mut TunProxyRuntime,
        tick: Duration,
        shutdown: F,
    ) -> io::Result<()>
    where
        F: std::future::Future<Output = ()>,
    {
        if tick.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN dispatcher tick must be non-zero",
            ));
        }
        let started = std::time::Instant::now();
        let mut ticker = tokio::time::interval(tick);
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                result = self.recv_from_tun() => {
                    if let Err(error) = result {
                        proxy_runtime.close();
                        return Err(error);
                    }
                }
                _ = ticker.tick() => {}
                _ = &mut shutdown => {
                    proxy_runtime
                        .close_graceful(DEFAULT_GRACEFUL_CLOSE_TIMEOUT)
                        .await;
                    return Ok(());
                }
            }
            let elapsed = started.elapsed();
            let timestamp = Instant::from_millis(elapsed.as_millis().min(i64::MAX as u128) as i64);
            if let Err(error) = dispatcher.poll(self, timestamp) {
                proxy_runtime.close();
                return Err(io::Error::other(error.to_string()));
            }
            for event in dispatcher.events().collect::<Vec<_>>() {
                if let Err(error) = proxy_runtime.handle_event_async(event).await {
                    proxy_runtime.close();
                    return Err(io::Error::other(error.to_string()));
                }
            }
            if let Err(error) = proxy_runtime.poll_outputs(dispatcher) {
                proxy_runtime.close();
                return Err(io::Error::other(error.to_string()));
            }
            if let Err(error) = proxy_runtime.sweep(dispatcher) {
                proxy_runtime.close();
                return Err(io::Error::other(error.to_string()));
            }
            loop {
                match self.send_to_tun().await {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(error) => {
                        proxy_runtime.close();
                        return Err(error);
                    }
                }
            }
            // A current-thread runtime can keep the TUN reader ready while a
            // newly opened proxy is still connecting. Yield once per loop so
            // flow tasks get a chance to consume their bounded command queue;
            // otherwise a large upload can fill that queue before the proxy
            // task is ever polled.
            tokio::task::yield_now().await;
        }
    }
}

#[cfg(feature = "tun")]
impl Drop for TunRuntime {
    fn drop(&mut self) {
        #[cfg(feature = "tun-routes")]
        {
            let _ = self.close_routes();
        }
    }
}

#[cfg(test)]
#[path = "tun_proxy_tests.rs"]
mod tun_proxy_tests;
#[cfg(test)]
#[path = "tun_runtime_tests.rs"]
mod tun_runtime_tests;
#[cfg(test)]
#[path = "tun_test_support.rs"]
mod tun_test_support;
#[cfg(test)]
#[path = "tun_unit_tests.rs"]
mod tun_unit_tests;
