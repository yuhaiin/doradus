//! Network-independent address and transport models.

use std::fmt;
use std::net::SocketAddr;

use crate::DomainName;

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
