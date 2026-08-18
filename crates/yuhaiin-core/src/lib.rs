//! Stable contracts shared by the yuhaiin-rust crates.
//!
//! This crate intentionally has no asynchronous-runtime or platform dependency.
//! Higher-level crates can therefore be tested independently and can choose the
//! runtime appropriate for desktop, Android, or embedded integration.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, atomic::AtomicU64};

pub mod dns {
    pub use yuhaiin_dns::dns::*;
}
pub mod dns_hosts {
    pub use yuhaiin_dns::dns_hosts::*;
}
pub mod dns_resolver {
    pub use yuhaiin_dns::dns_resolver::*;
}
#[cfg(feature = "async-proxy")]
pub mod dns_resolver_async {
    pub use yuhaiin_dns::dns_resolver_async::*;
}
#[cfg(feature = "async-proxy")]
pub mod dns_resolver_stack {
    pub use yuhaiin_dns::dns_resolver_stack::*;
}
pub mod dns_tcp {
    pub use yuhaiin_dns::dns_tcp::*;
}
#[cfg(feature = "async-proxy")]
pub mod dns_tcp_async {
    pub use yuhaiin_dns::dns_tcp_async::*;
}
#[cfg(feature = "async-proxy")]
pub mod dns_udp_async {
    pub use yuhaiin_dns::dns_udp_async::*;
}
pub mod flow;
pub mod geo;
pub use geo::GeoLookup;
#[cfg(feature = "http2")]
pub mod http2 {
    pub use yuhaiin_dns::http2::*;
}
pub mod nat;
pub mod process;
pub mod proxy;
#[cfg(feature = "async-proxy")]
pub mod sniff;

pub use yuhaiin_types::{
    BoxFuture, DomainName, Error, ErrorKind, IpSet, LocalBoxFuture, ResolveStrategy, Result,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Tcp,
    Udp,
    Icmp,
    Any,
}
impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Any => "any",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Endpoint {
    Ip {
        network: Network,
        addr: SocketAddr,
    },
    Domain {
        network: Network,
        host: DomainName,
        port: u16,
    },
}

impl Endpoint {
    pub fn ip(network: Network, addr: SocketAddr) -> Self {
        Self::Ip { network, addr }
    }

    pub fn domain(network: Network, host: DomainName, port: u16) -> Self {
        Self::Domain {
            network,
            host,
            port,
        }
    }

    pub fn network(&self) -> Network {
        match self {
            Self::Ip { network, .. } | Self::Domain { network, .. } => *network,
        }
    }

    pub fn port(&self) -> Option<u16> {
        match self {
            Self::Ip { addr, .. } => Some(addr.port()),
            Self::Domain { port, .. } => Some(*port),
        }
    }

    pub fn host(&self) -> Option<&DomainName> {
        match self {
            Self::Domain { host, .. } => Some(host),
            Self::Ip { .. } => None,
        }
    }

    pub fn addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Ip { addr, .. } => Some(*addr),
            Self::Domain { .. } => None,
        }
    }

    /// A deterministic, process-independent key for route/cache indexing.
    pub fn comparable_key(&self) -> u64 {
        // FNV-1a is sufficient here: this is an index key, not a security hash.
        let mut hash = 0xcbf29ce484222325u64;
        let feed = |hash: &mut u64, bytes: &[u8]| {
            for byte in bytes {
                *hash ^= u64::from(*byte);
                *hash = hash.wrapping_mul(0x100000001b3);
            }
        };
        feed(&mut hash, &[self.network() as u8]);
        match self {
            Self::Ip { addr, .. } => feed(&mut hash, addr.to_string().as_bytes()),
            Self::Domain { host, port, .. } => {
                feed(&mut hash, host.as_str().as_bytes());
                feed(&mut hash, &port.to_be_bytes());
            }
        }
        hash
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip { network, addr } => write!(f, "{network}://{addr}"),
            Self::Domain {
                network,
                host,
                port,
            } => write!(f, "{network}://{host}:{port}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMode {
    Bypass,
    Proxy,
    Direct,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolverPolicy {
    pub strategy: ResolveStrategy,
    pub use_fake_ip: bool,
    pub fake_ip_skip_check_upstream: bool,
    pub udp_skip_resolve_target: bool,
}

impl Default for ResolverPolicy {
    fn default() -> Self {
        Self {
            strategy: ResolveStrategy::Default,
            use_fake_ip: false,
            fake_ip_skip_check_upstream: false,
            udp_skip_resolve_target: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowContext {
    pub source: Option<Endpoint>,
    /// The local endpoint of the inbound socket, when the flow came from a
    /// socket-backed inbound.  It is kept separate from `source`: Go's
    /// connection contract exposes both the peer and `LocalAddr()`.
    pub local_addr: Option<Endpoint>,
    pub destination: Endpoint,
    /// The address selected by the runtime resolver for the final direct
    /// socket. Keep this separate from `destination`: protocol layers must
    /// still see the original domain for routing, SNI and proxy framing.
    pub resolved_destination: Option<Endpoint>,
    /// Do not resolve the destination through the runtime resolver.  Proxy
    /// transports that can carry a domain remotely use this to avoid
    /// recursively invoking the resolver while that resolver is connecting
    /// to its own upstream endpoint.
    pub skip_resolve: bool,
    pub network: Network,
    pub route_mode: RouteMode,
    pub resolver_policy: ResolverPolicy,
    pub original_domain: Option<DomainName>,
    /// The rule selected by the route snapshot. This is deliberately kept on
    /// the flow rather than in the monitor so protocol adapters and future
    /// observability consumers see the same decision.
    pub tag: Option<String>,
    pub match_history: Vec<MatchHistoryEntry>,
    pub lists: Vec<String>,
    pub resolver: Option<String>,
    pub geo: Option<String>,
    /// Address/source metadata recorded by the resolver layer.  Go exposes
    /// this as `hosts` on connection records; keeping it on the shared flow
    /// context lets DNS, TUN and inbound adapters populate it without making
    /// the monitor depend on a particular resolver implementation.
    pub hosts: Option<String>,
    /// The packet destination before FakeIP reverse lookup.  Keeping this
    /// separate from `destination` lets routing use the restored domain while
    /// observability still reports that the application connected to a
    /// synthetic address.
    pub fake_ip: Option<String>,
    /// Local source addresses selected by the runtime's interface policy.
    /// Keeping all addresses allows a dual-stack interface to select the
    /// family matching the actual upstream socket.
    pub local_bind_addresses: Vec<IpAddr>,
    /// Optional operating-system interface to which outbound sockets should
    /// be bound.  Source addresses remain useful as a portable fallback, but
    /// Go's node-level `network_interface` is stronger than selecting an
    /// address: on Linux it also constrains routing through `SO_BINDTODEVICE`.
    pub bind_interface: Option<String>,
    /// Management-plane identity of the component that accepted the flow.
    /// These fields are optional so packet-only callers do not need a second
    /// DTO or synthetic values.
    pub component: Option<String>,
    pub inbound: Option<String>,
    pub inbound_name: Option<String>,
    pub outbound: Option<String>,
    pub outbound_name: Option<String>,
    /// Application protocol discovered while accepting or sniffing a flow.
    /// This is intentionally separate from `network`: Go's connection API
    /// reports values such as `http`/`tls` here, and leaves it empty when no
    /// protocol was identified.
    pub protocol: Option<String>,
    /// Protocol metadata discovered while accepting or sniffing a flow.
    pub tls_server_name: Option<String>,
    pub http_host: Option<String>,
    /// Local interface and the selected outbound endpoint's GeoIP label.  A
    /// flow may legitimately leave either value unset on platforms where the
    /// socket does not expose it.
    pub interface: Option<String>,
    pub outbound_geo: Option<String>,
    /// Actual remote socket endpoint of the selected outbound proxy. This is
    /// distinct from `outbound`, which stores the configured node ID used by
    /// the React contract's `nodeId` field.
    pub outbound_addr: Option<Endpoint>,
    /// Local socket endpoint allocated by the selected outbound proxy. Go's
    /// connection contract exposes this as `localAddr`; it must remain
    /// separate from `local_addr`, which is the inbound listener endpoint
    /// used by loopback detection.
    pub outbound_local_addr: Option<Endpoint>,
    /// Process metadata supplied by a platform process resolver. TUN callers
    /// can leave this empty when the operating system does not expose socket
    /// ownership; inbound and test callers can still provide it explicitly.
    pub process: Option<String>,
    pub process_id: Option<u32>,
    pub user_id: Option<u32>,
    pub skip_route: bool,
    pub udp_migrate_id: Arc<AtomicU64>,
}

impl FlowContext {
    pub fn new(destination: Endpoint) -> Self {
        let network = destination.network();
        Self {
            source: None,
            local_addr: None,
            destination,
            resolved_destination: None,
            skip_resolve: false,
            network,
            route_mode: RouteMode::Proxy,
            resolver_policy: ResolverPolicy::default(),
            original_domain: None,
            tag: None,
            match_history: Vec::new(),
            lists: Vec::new(),
            resolver: None,
            geo: None,
            hosts: None,
            fake_ip: None,
            local_bind_addresses: Vec::new(),
            bind_interface: None,
            component: None,
            inbound: None,
            inbound_name: None,
            outbound: None,
            outbound_name: None,
            protocol: None,
            tls_server_name: None,
            http_host: None,
            interface: None,
            outbound_geo: None,
            outbound_addr: None,
            outbound_local_addr: None,
            process: None,
            process_id: None,
            user_id: None,
            skip_route: false,
            udp_migrate_id: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Destination to present to a proxy after a TUN/FakeIP reverse lookup.
    /// The packet tuple remains the original IP endpoint for routing and
    /// write-back, while proxy-capable transports can preserve the hostname.
    pub fn effective_destination(&self) -> Endpoint {
        let Some(domain) = &self.original_domain else {
            return self.destination.clone();
        };
        let Some(port) = self.destination.port() else {
            return self.destination.clone();
        };
        Endpoint::domain(self.network, domain.clone(), port)
    }

    /// Return the endpoint that a final direct transport should dial.
    /// `effective_destination` deliberately restores a domain for protocol
    /// layers; a resolver may additionally provide an IP for direct sockets.
    pub fn proxy_destination(&self) -> Endpoint {
        self.resolved_destination
            .clone()
            .unwrap_or_else(|| self.effective_destination())
    }

    pub fn local_bind_for(&self, remote: SocketAddr) -> Option<SocketAddr> {
        self.local_bind_addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == remote.is_ipv4())
            .map(|address| SocketAddr::new(address, 0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchHistoryEntry {
    pub rule_name: String,
    pub history: Vec<MatchResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchResult {
    pub list_name: String,
    pub matched: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn domain_names_are_canonicalized_and_checked() {
        assert_eq!(
            DomainName::new(" Example.COM. ").unwrap().as_str(),
            "example.com"
        );
        assert!(DomainName::new("").is_err());
        assert!(DomainName::new("a..example.com").is_err());
        assert!(DomainName::new("-bad.example.com").is_err());
        assert!(DomainName::new("bad label.example.com").is_err());
    }

    #[test]
    fn endpoint_key_includes_kind_and_port() {
        let domain = DomainName::new("example.com").unwrap();
        let a = Endpoint::domain(Network::Tcp, domain.clone(), 443);
        let b = Endpoint::domain(Network::Tcp, domain.clone(), 8443);
        let c = Endpoint::ip(Network::Tcp, "93.184.216.34:443".parse().unwrap());
        assert_ne!(a.comparable_key(), b.comparable_key());
        assert_ne!(a.comparable_key(), c.comparable_key());
    }

    #[test]
    fn fakeip_context_preserves_packet_tuple_but_restores_proxy_domain() {
        let mut context = FlowContext::new(Endpoint::ip(
            Network::Udp,
            "198.18.0.1:443".parse().unwrap(),
        ));
        context.original_domain = Some(DomainName::new("example.com").unwrap());
        assert_eq!(
            context.destination,
            Endpoint::ip(Network::Udp, "198.18.0.1:443".parse().unwrap())
        );
        assert_eq!(
            context.effective_destination(),
            Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 443)
        );
    }

    #[test]
    fn local_bind_selects_the_remote_address_family() {
        let mut context =
            FlowContext::new(Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap()));
        context.local_bind_addresses = vec![
            IpAddr::V6("2001:db8::10".parse().unwrap()),
            IpAddr::V4("192.0.2.10".parse().unwrap()),
        ];
        assert_eq!(
            context.local_bind_for("198.51.100.1:443".parse().unwrap()),
            Some("192.0.2.10:0".parse().unwrap())
        );
        assert_eq!(
            context.local_bind_for("[2001:db8::20]:443".parse().unwrap()),
            Some("[2001:db8::10]:0".parse().unwrap())
        );
    }

    #[test]
    fn ip_set_iterates_ipv4_before_ipv6() {
        let set = IpSet {
            v4: vec![Ipv4Addr::LOCALHOST],
            v6: vec![Ipv6Addr::LOCALHOST],
        };
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ]
        );
    }
}
