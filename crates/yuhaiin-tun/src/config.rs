//! TUN configuration, route leases, and capability probes.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    pub name: Option<String>,
    pub ipv4: Option<(Ipv4Addr, u8)>,
    pub ipv6: Vec<(Ipv6Addr, u8)>,
    pub mtu: usize,
    pub queue_capacity: usize,
    /// Drop IP multicast packets before smoltcp dispatches them.  This keeps
    /// the default desktop TUN behavior aligned with Go's `skipMulticast`
    /// setting and avoids treating discovery traffic as proxy flows.
    pub skip_multicast: bool,
}
impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: None,
            ipv4: None,
            ipv6: Vec::new(),
            mtu: DEFAULT_MTU,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            skip_multicast: false,
        }
    }
}

impl TunConfig {
    pub fn validate(&self) -> Result<()> {
        if !(576..=9216).contains(&self.mtu) {
            return Err(Error::invalid("TUN MTU must be between 576 and 9216"));
        }
        if !self.ipv6.is_empty() && self.mtu < 1280 {
            return Err(Error::invalid(
                "TUN MTU must be at least 1280 when IPv6 is configured",
            ));
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
/// implemented below with the pure-Rust `route_manager` client.
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

/// macOS route backend for utun devices.
///
/// Darwin routes need an actual next-hop address for an utun interface.  The
/// Go implementation uses the configured portal address as that gateway, so
/// this backend applies the same fallback when a route did not specify one.
#[cfg(all(feature = "tun-routes", target_os = "macos"))]
pub struct MacosTunRouteBackend {
    interface: String,
    ipv4_gateway: Option<Ipv4Addr>,
    ipv6_gateway: Option<Ipv6Addr>,
    manager: route_manager::RouteManager,
    preexisting: Vec<TunRoute>,
}

#[cfg(all(feature = "tun-routes", target_os = "macos"))]
impl MacosTunRouteBackend {
    pub fn new(
        interface: impl Into<String>,
        ipv4_gateway: Option<Ipv4Addr>,
        ipv6_gateway: Option<Ipv6Addr>,
    ) -> io::Result<Self> {
        let interface = interface.into();
        if interface.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN route interface name must not be empty",
            ));
        }
        Ok(Self {
            interface,
            ipv4_gateway,
            ipv6_gateway,
            manager: route_manager::RouteManager::new()?,
            preexisting: Vec::new(),
        })
    }

    fn gateway_for(&self, route: &TunRoute) -> Option<IpAddr> {
        route.gateway.or_else(|| match route.destination {
            IpAddr::V4(_) => self.ipv4_gateway.map(IpAddr::V4),
            IpAddr::V6(_) => self.ipv6_gateway.map(IpAddr::V6),
        })
    }

    fn system_route(&self, route: &TunRoute) -> route_manager::Route {
        let gateway = self.gateway_for(route);
        let mut system_route = route_manager::Route::new(route.network(), route.prefix)
            .with_if_name(self.interface.clone());
        if let Some(gateway) = gateway {
            system_route = system_route.with_gateway(gateway);
        }
        system_route
    }

    fn already_present(&mut self, route: &TunRoute) -> io::Result<bool> {
        let destination = route.network();
        let gateway = self.gateway_for(route);
        let present = self.manager.list()?.into_iter().any(|existing| {
            existing.destination() == destination
                && existing.prefix() == route.prefix
                && existing.gateway() == gateway
                && existing
                    .if_name()
                    .is_none_or(|interface| interface == &self.interface)
        });
        if present && !self.preexisting.contains(route) {
            self.preexisting.push(route.clone());
        }
        Ok(present)
    }
}

#[cfg(all(feature = "tun-routes", target_os = "macos"))]
impl TunRouteBackend for MacosTunRouteBackend {
    fn add_route(&mut self, route: &TunRoute) -> io::Result<()> {
        if self.already_present(route)? {
            return Ok(());
        }
        match self.manager.add(&self.system_route(route)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if self.already_present(route)? {
                    Ok(())
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    fn remove_route(&mut self, route: &TunRoute) -> io::Result<()> {
        if let Some(index) = self.preexisting.iter().position(|owned| owned == route) {
            self.preexisting.swap_remove(index);
            return Ok(());
        }
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
pub(crate) const CAP_NET_ADMIN: u8 = 12;

#[cfg(all(feature = "tun-routes", target_os = "linux"))]
pub(crate) fn read_effective_capabilities() -> Option<u128> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))?;
    u128::from_str_radix(value.trim(), 16).ok()
}

#[cfg(all(feature = "tun-routes", target_os = "linux"))]
pub(crate) fn has_capability(capabilities: u128, capability: u8) -> bool {
    capabilities & (1_u128 << capability) != 0
}

#[cfg(all(feature = "tun-routes", target_os = "linux"))]
pub(crate) fn read_multi_queue_capability() -> CapabilityState {
    match std::fs::read_to_string("/sys/module/tun/parameters/multi_queue") {
        Ok(value) => match value.trim() {
            "Y" | "y" | "1" => CapabilityState::Available,
            "N" | "n" | "0" => CapabilityState::Unavailable,
            _ => CapabilityState::Unknown,
        },
        Err(_) => CapabilityState::Unknown,
    }
}
