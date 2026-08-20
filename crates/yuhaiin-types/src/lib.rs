//! Small, runtime-independent contracts shared by the yuhaiin crates.
//!
//! This crate intentionally has no networking or async-runtime dependency.
//! Keeping the common error, name and address-set types here lets the DNS
//! engine remain independent from the proxy/TUN core while preserving the
//! existing public types through `yuhaiin-core` re-exports.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

pub mod dns;
pub use dns::{
    AsyncDnsHandler, AsyncIpResolver, DnsHandler, DnsRecordType, DnsResponse, DnsServiceBinding,
    DnsServiceParam,
};

pub mod inbound;
pub use inbound::InboundDnsHandler;
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
