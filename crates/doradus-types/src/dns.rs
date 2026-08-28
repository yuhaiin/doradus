//! DNS contracts shared by resolvers, proxy layers and inbound adapters.
//!
//! This module contains only protocol-neutral data and capability traits.
//! DNS wire encoding, caches and concrete transports stay in `doradus-dns`.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{BoxFuture, DomainName, Error, ErrorKind, IpSet, ResolveStrategy, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Ptr,
    Https,
    Svcb,
}

/// Protocol-neutral representation of an RFC 9460 service binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServiceBinding {
    pub priority: u16,
    pub target: Option<DomainName>,
    pub params: Vec<DnsServiceParam>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsServiceParam {
    Mandatory(Vec<u16>),
    Alpn(Vec<String>),
    NoDefaultAlpn,
    Port(u16),
    Ipv4Hint(Vec<Ipv4Addr>),
    Ech(Vec<u8>),
    Ipv6Hint(Vec<Ipv6Addr>),
    Unknown { key: u16, value: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponse {
    pub addresses: IpSet,
    pub ptr_names: Vec<DomainName>,
    pub service_bindings: Vec<DnsServiceBinding>,
    pub minimum_ttl: Option<u32>,
}

/// Synchronous DNS answer boundary.
pub trait DnsHandler: Send + Sync {
    fn resolve(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse>;
}

/// Packet-level DNS answer boundary for send-safe async callers.
pub trait AsyncDnsHandler: Send + Sync {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>>;
}

/// Send-safe address resolution boundary.
pub trait AsyncIpResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>>;

    /// Resolve one record while retaining non-address data such as PTR names
    /// and HTTPS/SVCB service bindings.
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            let strategy = match record_type {
                DnsRecordType::A => ResolveStrategy::OnlyIpv4,
                DnsRecordType::Aaaa => ResolveStrategy::OnlyIpv6,
                DnsRecordType::Ptr | DnsRecordType::Https | DnsRecordType::Svcb => {
                    ResolveStrategy::Default
                }
            };
            Ok(DnsResponse {
                addresses: self.resolve(domain, strategy).await?,
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            })
        })
    }

    /// Forward a complete DNS message without converting its records into
    /// the address-oriented model above.
    fn query_packet<'a>(&'a self, _packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "resolver does not support raw DNS packet queries",
            ))
        })
    }
}
