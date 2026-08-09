//! Runtime hosts overrides shared by synchronous and asynchronous DNS paths.
//!
//! The table is deliberately independent from SQLite.  A store adapter can
//! load `dns_hosts` into this snapshot, while tests and callers that receive a
//! live configuration can update it without coupling the resolver to a
//! database connection.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use crate::dns::{DnsHandler, DnsRecordType, DnsResponse};
use crate::{DomainName, Error, ErrorKind, IpSet, Result};

#[cfg(feature = "async-proxy")]
use crate::LocalBoxFuture;
#[cfg(feature = "async-proxy")]
use crate::dns::{AsyncDnsHandler, decode_query, encode_response};

/// Mutable owner for an immutable-at-read hosts snapshot.
///
/// Reads clone one small `IpSet` and release the lock before calling an
/// upstream resolver.  This keeps configuration reloads from blocking DNS
/// network I/O and makes the same table safe for UDP and DoH handlers.
#[derive(Clone, Default)]
pub struct HostsTable {
    entries: Arc<RwLock<BTreeMap<DomainName, HostsEntry>>>,
}

#[derive(Debug, Clone, Default)]
struct HostsEntry {
    addresses: IpSet,
    alias: Option<DomainName>,
}

impl HostsTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, domain: DomainName, mut addresses: IpSet) -> Result<()> {
        if addresses.is_empty() {
            return Err(Error::invalid("hosts entry must contain an address"));
        }
        addresses.v4.sort_unstable();
        addresses.v4.dedup();
        addresses.v6.sort_unstable();
        addresses.v6.dedup();
        self.entries
            .write()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .insert(
                domain,
                HostsEntry {
                    addresses,
                    alias: None,
                },
            );
        Ok(())
    }

    pub fn insert_ip(&self, domain: DomainName, address: IpAddr) -> Result<()> {
        let mut entries = self
            .entries
            .write()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?;
        let entry = entries.entry(domain).or_default();
        entry.alias = None;
        match address {
            IpAddr::V4(address) => entry.addresses.v4.push(address),
            IpAddr::V6(address) => entry.addresses.v6.push(address),
        }
        entry.addresses.v4.sort_unstable();
        entry.addresses.v4.dedup();
        entry.addresses.v6.sort_unstable();
        entry.addresses.v6.dedup();
        Ok(())
    }

    /// Insert either an IP target or a hostname alias from Go's textual
    /// `dns_hosts.target` column.
    pub fn insert_target(&self, domain: DomainName, target: &str) -> Result<()> {
        let target = host_without_port(target);
        if let Ok(address) = target.parse::<IpAddr>() {
            return self.insert_ip(domain, address);
        }
        let target = DomainName::new(target)?;
        // Go stores a self-mapping as a valid no-op hosts override (the
        // fresh database currently contains `example.com -> example.com`).
        // Keep that legacy row loadable without turning it into an alias
        // cycle; normal resolution falls through to the upstream resolver.
        if domain == target {
            return Ok(());
        }
        self.insert_alias(domain, target)
    }

    pub fn insert_alias(&self, domain: DomainName, target: DomainName) -> Result<()> {
        if domain == target {
            return Err(Error::invalid("DNS hosts alias cannot target itself"));
        }
        self.entries
            .write()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .insert(
                domain,
                HostsEntry {
                    addresses: IpSet::default(),
                    alias: Some(target),
                },
            );
        Ok(())
    }

    /// Replace entries with a higher-priority table while keeping the lower
    /// layer intact.  Runtime assembly uses this to put persisted Go hosts
    /// overrides above the operating-system hosts file.
    pub fn overlay(&self, overrides: &HostsTable) -> Result<()> {
        let overrides = overrides
            .entries
            .read()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .clone();
        self.entries
            .write()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .extend(overrides);
        Ok(())
    }

    pub fn remove(&self, domain: &DomainName) -> Result<bool> {
        Ok(self
            .entries
            .write()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .remove(domain)
            .is_some())
    }

    pub fn lookup(&self, domain: &DomainName) -> Result<Option<IpSet>> {
        Ok(self
            .entries
            .read()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .get(domain)
            .map(|entry| entry.addresses.clone())
            .filter(|addresses| !addresses.is_empty()))
    }

    /// Follow aliases without calling upstream while holding the table lock.
    /// An unresolved alias is reported as `None`, allowing the handler to use
    /// normal DNS resolution; a cycle is a configuration error.
    pub fn resolve(&self, domain: &DomainName) -> Result<Option<IpSet>> {
        let entries = self
            .entries
            .read()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?;
        let mut current = domain.clone();
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(current.clone()) {
                return Err(Error::invalid("DNS hosts alias cycle"));
            }
            let Some(entry) = entries.get(&current) else {
                return Ok(None);
            };
            if !entry.addresses.is_empty() {
                return Ok(Some(entry.addresses.clone()));
            }
            let Some(alias) = entry.alias.as_ref() else {
                return Ok(None);
            };
            current = alias.clone();
        }
    }

    pub fn len(&self) -> Result<usize> {
        Ok(self
            .entries
            .read()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .len())
    }
}

/// Return the hostname part of the address-like strings accepted by Go's
/// hosts configuration.  The compatibility table may contain entries such
/// as `name.example:443` or `[2001:db8::1]:443`; DNS itself only indexes the
/// hostname, so the optional port is intentionally discarded here.
pub fn host_without_port(value: &str) -> &str {
    if value.starts_with('[') {
        if let Some(end) = value.find(']') {
            if value.as_bytes().get(end + 1) == Some(&b':')
                && value[end + 2..].parse::<u16>().is_ok()
            {
                return &value[1..end];
            }
        }
        return value;
    }
    if value.parse::<IpAddr>().is_ok() {
        return value;
    }
    if let Some((host, port)) = value.rsplit_once(':')
        && !host.is_empty()
        && port.parse::<u16>().is_ok()
    {
        return host;
    }
    value
}

fn host_response(addresses: IpSet) -> DnsResponse {
    DnsResponse {
        addresses,
        ptr_names: Vec::new(),
        service_bindings: Vec::new(),
        minimum_ttl: Some(60),
    }
}

/// Resolve A/AAAA queries from a hosts table and delegate other record types
/// or unknown domains to the configured upstream handler.
pub struct HostsDnsHandler<H> {
    pub hosts: HostsTable,
    pub upstream: H,
}

impl<H: DnsHandler> DnsHandler for HostsDnsHandler<H> {
    fn resolve(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        let Some(addresses) = self.hosts.resolve(domain)? else {
            return self.upstream.resolve(domain, record_type);
        };
        match record_type {
            DnsRecordType::A => Ok(host_response(IpSet {
                v4: addresses.v4,
                v6: Vec::new(),
            })),
            DnsRecordType::Aaaa => Ok(host_response(IpSet {
                v4: Vec::new(),
                v6: addresses.v6,
            })),
            DnsRecordType::Ptr | DnsRecordType::Https | DnsRecordType::Svcb => {
                self.upstream.resolve(domain, record_type)
            }
        }
    }
}

/// Async packet-level equivalent of [`HostsDnsHandler`].
#[cfg(feature = "async-proxy")]
pub struct AsyncHostsDnsHandler<H> {
    pub hosts: HostsTable,
    pub upstream: H,
}

#[cfg(feature = "async-proxy")]
impl<H: AsyncDnsHandler> AsyncDnsHandler for AsyncHostsDnsHandler<H> {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let question = decode_query(packet)?;
            let Some(addresses) = self.hosts.resolve(&question.domain)? else {
                return self.upstream.answer(packet).await;
            };
            match question.record_type {
                DnsRecordType::A => encode_response(
                    packet,
                    &host_response(IpSet {
                        v4: addresses.v4,
                        v6: Vec::new(),
                    }),
                ),
                DnsRecordType::Aaaa => encode_response(
                    packet,
                    &host_response(IpSet {
                        v4: Vec::new(),
                        v6: addresses.v6,
                    }),
                ),
                DnsRecordType::Ptr | DnsRecordType::Https | DnsRecordType::Svcb => {
                    self.upstream.answer(packet).await
                }
            }
        })
    }
}

#[cfg(test)]
#[path = "dns_hosts_tests.rs"]
mod tests;
