//! Small, runtime-independent contracts shared by the doradus crates.
//!
//! This crate intentionally has no networking or async-runtime dependency.
//! Keeping the common error, name and address-set types here lets the DNS
//! engine remain independent from the proxy/TUN core while preserving the
//! existing public types through `doradus-core` re-exports.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, atomic::AtomicU64};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub mod dns;
pub use dns::{
    AsyncDnsHandler, AsyncIpResolver, DnsHandler, DnsRecordType, DnsResponse, DnsServiceBinding,
    DnsServiceParam,
};

pub mod inbound;
pub use inbound::{
    InboundBasicAuth, InboundDnsHandler, InboundHttpRequest, InboundStreamHandler, InboundUdpCodec,
    InboundUdpFlowId, InboundUdpRequest, InboundUdpResponse,
};
pub mod net;
pub use net::{Endpoint, Network};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainName(String);

impl DomainName {
    pub fn new(value: &str) -> Result<Self> {
        let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
        if value.is_empty() || value.len() > 253 {
            return Err(Error::invalid("domain must contain 1..=253 bytes"));
        }
        for label in value.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(Error::invalid("domain label must contain 1..=63 bytes"));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(Error::invalid("domain label cannot start or end with '-'"));
            }
            if !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            {
                return Err(Error::invalid("domain contains an unsupported character"));
            }
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn labels(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.0.split('.')
    }
}

impl TryFrom<&str> for DomainName {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl TryFrom<String> for DomainName {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(&value)
    }
}

impl AsRef<str> for DomainName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveStrategy {
    Default,
    OnlyIpv4,
    PreferIpv4,
    OnlyIpv6,
    PreferIpv6,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpSet {
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
}

impl IpSet {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.v4
            .iter()
            .copied()
            .map(IpAddr::V4)
            .chain(self.v6.iter().copied().map(IpAddr::V6))
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

/// Flow metadata shared by routing, DNS, proxy adapters and observability.
///
/// This is deliberately a data contract rather than a proxy/runtime type:
/// it contains no Tokio traits, sockets or task handles.  The core crate keeps
/// the runtime-heavy operations which consume this context and re-exports the
/// type for compatibility.
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
    /// Stable persisted identity of the inbound that accepted this flow.
    /// This is separate from the display name so per-inbound statistics stay
    /// correct when an inbound is renamed.
    pub inbound_id: Option<String>,
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
            inbound_id: None,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidInput,
    NotFound,
    Conflict,
    Unsupported,
    Io,
    Protocol,
    Storage,
    Timeout,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidInput, message)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

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
