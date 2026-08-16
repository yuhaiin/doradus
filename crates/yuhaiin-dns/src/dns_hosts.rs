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
    ip_entries: Arc<RwLock<BTreeMap<IpAddr, HostsEntry>>>,
    ptr_entries: Arc<RwLock<BTreeMap<IpAddr, Vec<DomainName>>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostsTarget {
    Ip(IpAddr),
    Domain(DomainName),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsDispatchTarget {
    pub target: HostsTarget,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Default)]
struct HostsEntry {
    addresses: IpSet,
    alias: Option<DomainName>,
    port_map: BTreeMap<u16, HostsDispatchTarget>,
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
                    port_map: BTreeMap::new(),
                },
            );
        self.rebuild_ptr_entries()
    }

    fn rebuild_ptr_entries(&self) -> Result<()> {
        let entries = self
            .entries
            .read()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?;
        let mut reverse = BTreeMap::<IpAddr, Vec<DomainName>>::new();
        for (domain, entry) in entries.iter() {
            for address in &entry.addresses.v4 {
                reverse
                    .entry(IpAddr::V4(*address))
                    .or_default()
                    .push(domain.clone());
            }
            for address in &entry.addresses.v6 {
                reverse
                    .entry(IpAddr::V6(*address))
                    .or_default()
                    .push(domain.clone());
            }
        }
        *self
            .ptr_entries
            .write()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))? = reverse;
        Ok(())
    }

    /// Insert a Go `dns_hosts` row. Go accepts either a hostname or an IP as
    /// the source key; the latter is used by the common proxy dispatcher, not
    /// only by DNS resolution.
    pub fn insert_host_target(&self, host: &str, target: &str) -> Result<()> {
        let (host, host_port) = host_and_port(host);
        let (target, target_port) = parse_host_target(target)?;
        if let Ok(address) = host.parse::<IpAddr>() {
            return self.insert_ip_target(address, host_port, target, target_port);
        }
        self.insert_domain_target(DomainName::new(host)?, host_port, target, target_port)
    }

    fn insert_ip_target(
        &self,
        address: IpAddr,
        host_port: Option<u16>,
        target: HostsTarget,
        target_port: Option<u16>,
    ) -> Result<()> {
        let mut entries = self
            .ip_entries
            .write()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?;
        let entry = entries.entry(address).or_default();
        if let (Some(host_port), Some(target_port)) = (host_port, target_port) {
            entry.port_map.insert(
                host_port,
                HostsDispatchTarget {
                    target,
                    port: Some(target_port),
                },
            );
        } else {
            apply_default_target(entry, target);
        }
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
        drop(entries);
        self.rebuild_ptr_entries()
    }

    /// Insert either an IP target or a hostname alias from Go's textual
    /// `dns_hosts.target` column.
    pub fn insert_target(&self, domain: DomainName, target: &str) -> Result<()> {
        let (target, _) = parse_host_target(target)?;
        self.insert_domain_target(domain, None, target, None)
    }

    fn insert_domain_target(
        &self,
        domain: DomainName,
        host_port: Option<u16>,
        target: HostsTarget,
        target_port: Option<u16>,
    ) -> Result<()> {
        if let (Some(host_port), Some(target_port)) = (host_port, target_port) {
            self.entries
                .write()
                .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
                .entry(domain)
                .or_default()
                .port_map
                .insert(
                    host_port,
                    HostsDispatchTarget {
                        target,
                        port: Some(target_port),
                    },
                );
            return Ok(());
        }

        // Go stores a self-mapping as a valid no-op hosts override (the
        // fresh database currently contains `example.com -> example.com`).
        // Keep that legacy row loadable without turning it into an alias
        // cycle; normal resolution falls through to the upstream resolver.
        if matches!(&target, HostsTarget::Domain(target) if domain == *target) {
            return Ok(());
        }
        match target {
            HostsTarget::Ip(address) => self.insert_ip(domain, address),
            HostsTarget::Domain(target) => self.insert_alias(domain, target),
        }
    }

    pub fn insert_alias(&self, domain: DomainName, target: DomainName) -> Result<()> {
        if domain == target {
            return Err(Error::invalid("DNS hosts alias cannot target itself"));
        }
        let mut entries = self
            .entries
            .write()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?;
        let entry = entries.entry(domain).or_default();
        entry.addresses = IpSet::default();
        entry.alias = Some(target);
        drop(entries);
        self.rebuild_ptr_entries()
    }

    /// Replace entries with a higher-priority table while keeping the lower
    /// layer intact.  Runtime assembly uses this to put persisted Go hosts
    /// overrides above the operating-system hosts file.
    pub fn overlay(&self, overrides: &HostsTable) -> Result<()> {
        let domain_overrides = overrides
            .entries
            .read()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .clone();
        let ip_overrides = overrides
            .ip_entries
            .read()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .clone();
        self.entries
            .write()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .extend(domain_overrides);
        self.ip_entries
            .write()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .extend(ip_overrides);
        self.rebuild_ptr_entries()
    }

    pub fn remove(&self, domain: &DomainName) -> Result<bool> {
        let removed = self
            .entries
            .write()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .remove(domain)
            .is_some();
        if removed {
            self.rebuild_ptr_entries()?;
        }
        Ok(removed)
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

    /// Dispatch a domain source key the same way Go's `Hosts.Dispatch` does.
    /// Unlike DNS lookup, this preserves an exact source-port mapping and
    /// returns the target endpoint kind (IP or domain) for the proxy flow.
    pub fn resolve_domain_target(
        &self,
        domain: &DomainName,
        port: u16,
    ) -> Result<Option<HostsDispatchTarget>> {
        let entries = self
            .entries
            .read()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?;
        let Some(entry) = entries.get(domain) else {
            return Ok(None);
        };
        if port != 0
            && let Some(target) = entry.port_map.get(&port)
        {
            return Ok(Some(target.clone()));
        }
        if let Some(alias) = &entry.alias {
            return Ok(Some(HostsDispatchTarget {
                target: HostsTarget::Domain(alias.clone()),
                port: None,
            }));
        }
        let target = entry
            .addresses
            .v4
            .first()
            .copied()
            .map(IpAddr::V4)
            .or_else(|| entry.addresses.v6.first().copied().map(IpAddr::V6));
        Ok(target.map(|target| HostsDispatchTarget {
            target: HostsTarget::Ip(target),
            port: None,
        }))
    }

    /// Resolve an IP source key from Go's hosts dispatcher. This is kept
    /// separate from DNS lookup because the source address itself is not a
    /// domain name and therefore never reaches `AsyncHostsResolver`.
    pub fn resolve_ip_target(
        &self,
        address: IpAddr,
        port: u16,
    ) -> Result<Option<HostsDispatchTarget>> {
        let entries = self
            .ip_entries
            .read()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?;
        let Some(entry) = entries.get(&address) else {
            return Ok(None);
        };
        if port != 0
            && let Some(target) = entry.port_map.get(&port)
        {
            return Ok(Some(target.clone()));
        }
        if entry.addresses.is_empty() && entry.alias.is_none() {
            return Ok(None);
        }
        if let Some(alias) = &entry.alias {
            return Ok(Some(HostsDispatchTarget {
                target: HostsTarget::Domain(alias.clone()),
                port: None,
            }));
        }
        let target = entry
            .addresses
            .v4
            .first()
            .copied()
            .map(IpAddr::V4)
            .or_else(|| entry.addresses.v6.first().copied().map(IpAddr::V6));
        Ok(target.map(|target| HostsDispatchTarget {
            target: HostsTarget::Ip(target),
            port: None,
        }))
    }

    pub fn resolve_ptr(&self, address: IpAddr) -> Result<Vec<DomainName>> {
        Ok(self
            .ptr_entries
            .read()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .get(&address)
            .cloned()
            .unwrap_or_default())
    }

    pub fn len(&self) -> Result<usize> {
        let domains = self
            .entries
            .read()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .len();
        let ips = self
            .ip_entries
            .read()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .len();
        Ok(domains + ips)
    }

    pub fn is_empty(&self) -> Result<bool> {
        let domains = self
            .entries
            .read()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .is_empty();
        let ips = self
            .ip_entries
            .read()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS hosts lock poisoned"))?
            .is_empty();
        Ok(domains && ips)
    }
}

/// Return the hostname part of the address-like strings accepted by Go's
/// hosts configuration.  The compatibility table may contain entries such
/// as `name.example:443` or `[2001:db8::1]:443`; DNS itself only indexes the
/// hostname, while the optional port is retained by the dispatch loader.
pub fn host_without_port(value: &str) -> &str {
    host_and_port(value).0
}

fn host_and_port(value: &str) -> (&str, Option<u16>) {
    if value.starts_with('[') {
        if let Some(end) = value.find(']')
            && value.as_bytes().get(end + 1) == Some(&b':')
            && let Ok(port) = value[end + 2..].parse::<u16>()
        {
            return (&value[1..end], Some(port));
        }
        if let Some(end) = value.strip_suffix(']')
            && let Some(end) = end.strip_prefix('[')
        {
            return (end, None);
        }
        return (value, None);
    }
    if value.parse::<IpAddr>().is_ok() {
        return (value, None);
    }
    if let Some((host, port)) = value.rsplit_once(':')
        && !host.is_empty()
        && let Ok(port) = port.parse::<u16>()
    {
        return (host, Some(port));
    }
    (value, None)
}

fn parse_host_target(value: &str) -> Result<(HostsTarget, Option<u16>)> {
    let (host, port) = host_and_port(value);
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok((HostsTarget::Ip(address), port));
    }
    Ok((HostsTarget::Domain(DomainName::new(host)?), port))
}

fn apply_default_target(entry: &mut HostsEntry, target: HostsTarget) {
    entry.addresses = IpSet::default();
    entry.alias = None;
    match target {
        HostsTarget::Ip(IpAddr::V4(address)) => entry.addresses.v4.push(address),
        HostsTarget::Ip(IpAddr::V6(address)) => entry.addresses.v6.push(address),
        HostsTarget::Domain(target) => entry.alias = Some(target),
    }
}

fn host_response(addresses: IpSet) -> DnsResponse {
    DnsResponse {
        addresses,
        ptr_names: Vec::new(),
        service_bindings: Vec::new(),
        minimum_ttl: Some(60),
    }
}

fn ptr_response(ptr_names: Vec<DomainName>) -> DnsResponse {
    DnsResponse {
        addresses: IpSet::default(),
        ptr_names,
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
        if record_type == DnsRecordType::Ptr
            && let Some(address) = crate::fakeip::reverse_name_to_ip(domain)
        {
            let ptr_names = self.hosts.resolve_ptr(address)?;
            if !ptr_names.is_empty() {
                return Ok(ptr_response(ptr_names));
            }
            return self.upstream.resolve(domain, record_type);
        }
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
            if question.record_type == DnsRecordType::Ptr
                && let Some(address) = crate::fakeip::reverse_name_to_ip(&question.domain)
            {
                let ptr_names = self.hosts.resolve_ptr(address)?;
                if !ptr_names.is_empty() {
                    return encode_response(packet, &ptr_response(ptr_names));
                }
                return self.upstream.answer(packet).await;
            }
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
