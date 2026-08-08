//! Stable contracts shared by the yuhaiin-rust crates.
//!
//! This crate intentionally has no asynchronous-runtime or platform dependency.
//! Higher-level crates can therefore be tested independently and can choose the
//! runtime appropriate for desktop, Android, or embedded integration.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, atomic::AtomicU64};

pub mod dns;
pub mod dns_hosts;
pub mod dns_resolver;
#[cfg(feature = "async-proxy")]
pub mod dns_resolver_async;
#[cfg(feature = "async-proxy")]
pub mod dns_resolver_stack;
pub mod dns_tcp;
#[cfg(feature = "async-proxy")]
pub mod dns_tcp_async;
#[cfg(feature = "async-proxy")]
pub mod dns_udp_async;
pub mod flow;
pub mod geo;
pub use geo::GeoLookup;
#[cfg(feature = "http2")]
pub mod http2;
pub mod nat;
pub mod proxy;
#[cfg(feature = "async-proxy")]
pub mod proxy_factory;
#[cfg(feature = "tls-rustcrypto")]
pub mod tls;
#[cfg(feature = "tun")]
pub mod tun;
pub mod yuubinsya;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

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
pub enum ResolveStrategy {
    Default,
    OnlyIpv4,
    PreferIpv4,
    OnlyIpv6,
    PreferIpv6,
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

#[derive(Debug, Clone)]
pub struct FlowContext {
    pub source: Option<Endpoint>,
    pub destination: Endpoint,
    pub network: Network,
    pub route_mode: RouteMode,
    pub resolver_policy: ResolverPolicy,
    pub original_domain: Option<DomainName>,
    /// Management-plane identity of the component that accepted the flow.
    /// These fields are optional so packet-only callers do not need a second
    /// DTO or synthetic values.
    pub inbound: Option<String>,
    pub inbound_name: Option<String>,
    pub outbound: Option<String>,
    pub outbound_name: Option<String>,
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
            destination,
            network,
            route_mode: RouteMode::Proxy,
            resolver_policy: ResolverPolicy::default(),
            original_domain: None,
            inbound: None,
            inbound_name: None,
            outbound: None,
            outbound_name: None,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidInput,
    NotFound,
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
