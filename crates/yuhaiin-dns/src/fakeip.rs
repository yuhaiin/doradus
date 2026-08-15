//! Pure FakeIP contracts shared by DNS and the persistent store adapter.
//!
//! Allocation is deliberately not implemented here: the allocator owns a
//! persistence backend and therefore belongs to `yuhaiin-store`.  The range,
//! lifecycle options and packet-plane reverse view are backend-independent
//! DNS concepts and live in this crate so they can be reused without pulling
//! SQLite into the DNS layer.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{DomainName, Error, ErrorKind, Result};

const DEFAULT_TTL_SECONDS: i64 = 24 * 60 * 60;
const DEFAULT_TOUCH_INTERVAL_SECONDS: i64 = 5 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeIpConfig {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
}

impl FakeIpConfig {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Result<Self> {
        if u32::from(start) > u32::from(end) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "FakeIP start must not be greater than end",
            ));
        }
        Ok(Self { start, end })
    }

    pub fn size(self) -> u64 {
        u64::from(u32::from(self.end) - u32::from(self.start)) + 1
    }

    pub fn range_prefix(self) -> String {
        format!("range:{}-{}", self.start, self.end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeIpV6Config {
    pub start: Ipv6Addr,
    pub end: Ipv6Addr,
}

impl FakeIpV6Config {
    pub fn new(start: Ipv6Addr, end: Ipv6Addr) -> Result<Self> {
        if u128::from(start) > u128::from(end) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "FakeIP IPv6 start must not be greater than end",
            ));
        }
        Ok(Self { start, end })
    }

    pub fn size(self) -> Result<u128> {
        u128::from(self.end)
            .checked_sub(u128::from(self.start))
            .and_then(|size| size.checked_add(1))
            .ok_or_else(|| Error::invalid("FakeIP IPv6 pool is too large"))
    }

    pub fn range_prefix(self) -> String {
        format!("range:{}-{}", self.start, self.end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeIpPoolOptions {
    /// Maximum number of live mappings in this pool.
    pub max_entries: u64,
    /// An entry is eligible for reuse after this many seconds without a hit.
    pub ttl_seconds: i64,
    /// Coalesce persisted `last_used_at` updates until this interval elapses.
    pub touch_interval_seconds: i64,
}

/// Domain policy used by the FakeIP resolver layer.  It intentionally lives
/// beside the DNS transformation contracts; the persistent allocator does
/// not need to know whether a name was whitelisted or skip-check enabled.
#[derive(Clone, Default)]
pub struct FakeIpPolicy {
    whitelist: DomainMatcher,
    skip_check: DomainMatcher,
}

impl FakeIpPolicy {
    pub fn from_lists(whitelist: &[String], skip_check: &[String]) -> Result<Self> {
        Ok(Self {
            whitelist: DomainMatcher::from_patterns(whitelist, "whitelist")?,
            skip_check: DomainMatcher::from_patterns(skip_check, "skip-check")?,
        })
    }

    pub fn is_whitelisted(&self, domain: &DomainName) -> bool {
        self.whitelist.matches(domain)
    }

    pub fn is_skip_check(&self, domain: &DomainName) -> bool {
        self.skip_check.matches(domain)
    }
}

#[derive(Clone, Default)]
struct DomainMatcher {
    suffixes: BTreeSet<String>,
    wildcards: BTreeSet<String>,
}

impl DomainMatcher {
    fn from_patterns(patterns: &[String], field: &str) -> Result<Self> {
        let mut matcher = Self::default();
        for pattern in patterns {
            let normalized = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
            let (wildcard, suffix) = normalized
                .strip_prefix("*.")
                .map_or((false, normalized.as_str()), |suffix| (true, suffix));
            if suffix.is_empty() || suffix.contains('*') || DomainName::new(suffix).is_err() {
                return Err(Error::invalid(format!(
                    "invalid FakeIP {field} entry {pattern:?}"
                )));
            }
            if wildcard {
                matcher.wildcards.insert(suffix.to_owned());
            } else {
                matcher.suffixes.insert(suffix.to_owned());
            }
        }
        Ok(matcher)
    }

    fn matches(&self, domain: &DomainName) -> bool {
        let domain = domain.as_str();
        self.suffixes
            .iter()
            .any(|suffix| domain == suffix || domain.ends_with(&format!(".{suffix}")))
            || self.wildcards.iter().any(|suffix| {
                let Some(prefix) = domain.strip_suffix(&format!(".{suffix}")) else {
                    return false;
                };
                !prefix.is_empty() && !prefix.contains('.')
            })
    }
}

impl FakeIpPoolOptions {
    pub fn for_config(config: FakeIpConfig) -> Self {
        Self {
            max_entries: config.size(),
            ttl_seconds: DEFAULT_TTL_SECONDS,
            touch_interval_seconds: DEFAULT_TOUCH_INTERVAL_SECONDS,
        }
    }

    pub fn for_v6_config(config: FakeIpV6Config) -> Self {
        Self {
            max_entries: config
                .size()
                .unwrap_or(u64::MAX as u128)
                .min(u64::MAX as u128) as u64,
            ttl_seconds: DEFAULT_TTL_SECONDS,
            touch_interval_seconds: DEFAULT_TOUCH_INTERVAL_SECONDS,
        }
    }

    pub fn new(max_entries: u64, ttl_seconds: i64) -> Result<Self> {
        if max_entries == 0 || ttl_seconds <= 0 {
            return Err(Error::invalid(
                "FakeIP max_entries and ttl_seconds must be positive",
            ));
        }
        Ok(Self {
            max_entries,
            ttl_seconds,
            touch_interval_seconds: DEFAULT_TOUCH_INTERVAL_SECONDS,
        })
    }

    pub fn with_touch_interval(mut self, seconds: i64) -> Result<Self> {
        if seconds <= 0 {
            return Err(Error::invalid(
                "FakeIP touch_interval_seconds must be positive",
            ));
        }
        self.touch_interval_seconds = seconds;
        Ok(self)
    }
}

/// Send/Sync reverse map used by the packet data plane. It intentionally has
/// no persistence handle and can therefore be captured by synchronous TUN
/// callbacks.
#[derive(Debug, Clone, Default)]
pub struct FakeIpView {
    reverse: Arc<HashMap<Ipv4Addr, DomainName>>,
    reverse_v6: Arc<HashMap<Ipv6Addr, DomainName>>,
}

impl FakeIpView {
    /// Construct a view from allocator-owned maps. The maps are copied into
    /// immutable reference-counted snapshots before they cross the async to
    /// packet-plane boundary.
    pub fn from_maps(
        reverse: HashMap<Ipv4Addr, DomainName>,
        reverse_v6: HashMap<Ipv6Addr, DomainName>,
    ) -> Self {
        Self {
            reverse: Arc::new(reverse),
            reverse_v6: Arc::new(reverse_v6),
        }
    }

    pub fn lookup_domain(&self, address: Ipv4Addr) -> Option<DomainName> {
        self.reverse.get(&address).cloned()
    }

    pub fn lookup_domain_v6(&self, address: Ipv6Addr) -> Option<DomainName> {
        self.reverse_v6.get(&address).cloned()
    }

    pub fn lookup_domain_ip(&self, address: IpAddr) -> Option<DomainName> {
        match address {
            IpAddr::V4(address) => self.lookup_domain(address),
            IpAddr::V6(address) => self.lookup_domain_v6(address),
        }
    }

    pub fn merge(&self, other: &Self) -> Self {
        let mut reverse = (*self.reverse).clone();
        reverse.extend(
            other
                .reverse
                .iter()
                .map(|(address, domain)| (*address, domain.clone())),
        );
        let mut reverse_v6 = (*self.reverse_v6).clone();
        reverse_v6.extend(
            other
                .reverse_v6
                .iter()
                .map(|(address, domain)| (*address, domain.clone())),
        );
        Self::from_maps(reverse, reverse_v6)
    }
}

/// Synchronous holder for the latest immutable reverse-lookup snapshot.
#[derive(Clone, Default)]
pub struct FakeIpViewStore {
    view: Arc<std::sync::RwLock<FakeIpView>>,
}

impl FakeIpViewStore {
    pub fn new(view: FakeIpView) -> Self {
        Self {
            view: Arc::new(std::sync::RwLock::new(view)),
        }
    }

    pub fn lookup_domain_ip(&self, address: IpAddr) -> Option<DomainName> {
        self.view
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .lookup_domain_ip(address)
    }

    pub fn replace(&self, view: FakeIpView) {
        *self
            .view
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = view;
    }

    pub fn snapshot(&self) -> FakeIpView {
        self.view
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

/// Parse an `in-addr.arpa` or canonical lower-case `ip6.arpa` name.
pub fn reverse_name_to_ip(domain: &DomainName) -> Option<IpAddr> {
    let labels: Vec<_> = domain.labels().collect();
    if labels.len() == 6
        && labels[4] == "in-addr"
        && labels[5] == "arpa"
        && labels[..4].iter().all(|label| label.parse::<u8>().is_ok())
    {
        return Some(IpAddr::V4(Ipv4Addr::new(
            labels[3].parse().ok()?,
            labels[2].parse().ok()?,
            labels[1].parse().ok()?,
            labels[0].parse().ok()?,
        )));
    }
    if labels.len() != 34 || labels[32] != "ip6" || labels[33] != "arpa" {
        return None;
    }
    let mut nibbles = Vec::with_capacity(32);
    for label in labels[..32].iter().rev() {
        let nibble = u8::from_str_radix(label, 16).ok()?;
        if *label != format!("{nibble:x}") {
            return None;
        }
        nibbles.push(nibble);
    }
    let mut bytes = [0u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (nibbles[index * 2] << 4) | nibbles[index * 2 + 1];
    }
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_name_parser_accepts_both_families() {
        let v4 = DomainName::new("1.0.0.127.in-addr.arpa").unwrap();
        assert_eq!(reverse_name_to_ip(&v4), Some("127.0.0.1".parse().unwrap()));
        let v6 = DomainName::new(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        )
        .unwrap();
        assert_eq!(reverse_name_to_ip(&v6), Some("::1".parse().unwrap()));
    }

    #[test]
    fn options_reject_unbounded_refresh_values() {
        assert!(FakeIpPoolOptions::new(0, 1).is_err());
        assert!(FakeIpPoolOptions::new(1, 0).is_err());
        assert!(
            FakeIpPoolOptions::new(1, 1)
                .unwrap()
                .with_touch_interval(0)
                .is_err()
        );
    }
}
