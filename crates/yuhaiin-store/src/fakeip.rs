//! Persistent FakeIP allocation and reverse lookup.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::lock::Mutex;
use serde::{Deserialize, Serialize};
use yuhaiin_core::dns::{DnsRecordType, DnsResponse, DnsServiceParam};
use yuhaiin_core::{DomainName, Error, ErrorKind, IpSet, Result};

#[cfg(feature = "async-dns")]
use yuhaiin_core::LocalBoxFuture;
#[cfg(feature = "async-dns")]
use yuhaiin_core::dns::{AsyncDnsHandler, decode_query, encode_response};

use crate::{ConfigStore, FakeIpCursorRecord, FakeIpEntryRecord};

const NEXT_KEY: &str = "fakeip/next";
const MAP_PREFIX: &str = "fakeip/map/";
const NEXT_V6_KEY: &str = "fakeip/ipv6/next";
const MAP_V6_PREFIX: &str = "fakeip/ipv6/map/";
const IMPORT_MARKER_PREFIX: &str = "fakeip/legacy-import/";
const DEFAULT_TTL_SECONDS: i64 = 24 * 60 * 60;
const DEFAULT_TOUCH_INTERVAL_SECONDS: i64 = 5 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeIpConfig {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
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

    fn size(self) -> Result<u128> {
        u128::from(self.end)
            .checked_sub(u128::from(self.start))
            .and_then(|size| size.checked_add(1))
            .ok_or_else(|| Error::invalid("FakeIP IPv6 pool is too large"))
    }

    fn range_prefix(self) -> String {
        format!("range:{}-{}", self.start, self.end)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyFakeIpEntry {
    pub domain: DomainName,
    pub address: Ipv4Addr,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyFakeIpSnapshot {
    pub entries: Vec<LegacyFakeIpEntry>,
    pub next: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyFakeIpV6Entry {
    pub domain: DomainName,
    pub address: Ipv6Addr,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyFakeIpV6Snapshot {
    pub entries: Vec<LegacyFakeIpV6Entry>,
    pub next: Option<Ipv6Addr>,
}

/// Versioned export envelope used by the Go Pebble/bbolt migration helper.
///
/// The Rust runtime intentionally does not open Pebble files. The Go side
/// exports one mapping or cursor per NDJSON line, while this type validates
/// the stable interchange contract before handing the snapshot to the
/// transactional importer below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyFakeIpExport {
    pub version: u32,
    pub family: u8,
    pub prefix: String,
    pub snapshot: LegacyFakeIpSnapshot,
}

/// IPv6 counterpart to [`LegacyFakeIpExport`].  It uses the same versioned
/// NDJSON wire contract but never shares the IPv4 importer or cursor key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyFakeIpV6Export {
    pub version: u32,
    pub family: u8,
    pub prefix: String,
    pub snapshot: LegacyFakeIpV6Snapshot,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyFakeIpExportLine {
    version: u32,
    family: u8,
    prefix: String,
    kind: String,
    domain: Option<String>,
    address: Option<String>,
    next: Option<String>,
}

impl LegacyFakeIpExport {
    /// Parse the version-1 NDJSON export contract.
    ///
    /// Every non-empty line repeats the version/family/prefix metadata so a
    /// concatenated or partially replaced export cannot silently mix pools.
    /// Unknown fields, record kinds, duplicate cursors, malformed domains and
    /// malformed addresses fail closed before any SQLite write occurs.
    pub fn parse_ndjson(input: &str) -> Result<Self> {
        let parsed = parse_legacy_fakeip_ndjson(input, 4)?;
        let entries = parsed
            .entries
            .into_iter()
            .map(|(domain, address)| match address {
                IpAddr::V4(address) => LegacyFakeIpEntry { domain, address },
                IpAddr::V6(_) => unreachable!("family-checked legacy export"),
            })
            .collect();
        Ok(Self {
            version: parsed.version,
            family: parsed.family,
            prefix: parsed.prefix,
            snapshot: LegacyFakeIpSnapshot {
                entries,
                next: parsed.next.map(|address| match address {
                    IpAddr::V4(address) => address,
                    IpAddr::V6(_) => unreachable!("family-checked legacy cursor"),
                }),
            },
        })
    }
}

impl LegacyFakeIpV6Export {
    pub fn parse_ndjson(input: &str) -> Result<Self> {
        let parsed = parse_legacy_fakeip_ndjson(input, 6)?;
        let entries = parsed
            .entries
            .into_iter()
            .map(|(domain, address)| match address {
                IpAddr::V6(address) => LegacyFakeIpV6Entry { domain, address },
                IpAddr::V4(_) => unreachable!("family-checked legacy export"),
            })
            .collect();
        Ok(Self {
            version: parsed.version,
            family: parsed.family,
            prefix: parsed.prefix,
            snapshot: LegacyFakeIpV6Snapshot {
                entries,
                next: parsed.next.map(|address| match address {
                    IpAddr::V6(address) => address,
                    IpAddr::V4(_) => unreachable!("family-checked legacy cursor"),
                }),
            },
        })
    }
}

struct ParsedLegacyFakeIpExport {
    version: u32,
    family: u8,
    prefix: String,
    entries: Vec<(DomainName, IpAddr)>,
    next: Option<IpAddr>,
}

fn parse_legacy_fakeip_ndjson(
    input: &str,
    expected_family: u8,
) -> Result<ParsedLegacyFakeIpExport> {
    let mut version = None;
    let mut family = None;
    let mut prefix = None;
    let mut entries = Vec::new();
    let mut next = None;

    for (line_index, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let record: LegacyFakeIpExportLine = serde_json::from_str(line).map_err(|error| {
            Error::invalid(format!(
                "invalid FakeIP legacy NDJSON line {}: {error}",
                line_index + 1
            ))
        })?;
        if record.version != 1 {
            return Err(Error::invalid(format!(
                "unsupported FakeIP legacy export version {}",
                record.version
            )));
        }
        if record.family != expected_family {
            return Err(Error::invalid(format!(
                "version-1 FakeIP legacy NDJSON family {} does not match expected family {}",
                record.family, expected_family
            )));
        }
        validate_legacy_export_prefix(&record.prefix, expected_family)?;

        if let Some(expected) = version {
            if expected != record.version {
                return Err(Error::invalid("FakeIP legacy export mixes versions"));
            }
        } else {
            version = Some(record.version);
        }
        if let Some(expected) = family {
            if expected != record.family {
                return Err(Error::invalid(
                    "FakeIP legacy export mixes address families",
                ));
            }
        } else {
            family = Some(record.family);
        }
        if let Some(expected) = prefix.as_deref() {
            if expected != record.prefix {
                return Err(Error::invalid("FakeIP legacy export mixes pool prefixes"));
            }
        } else {
            prefix = Some(record.prefix.clone());
        }

        match record.kind.as_str() {
            "entry" => {
                let domain = DomainName::new(
                    record
                        .domain
                        .as_deref()
                        .ok_or_else(|| Error::invalid("FakeIP entry record is missing domain"))?,
                )?;
                let address = record
                    .address
                    .ok_or_else(|| Error::invalid("FakeIP entry record is missing address"))?
                    .parse::<IpAddr>()
                    .map_err(|error| Error::invalid(format!("invalid FakeIP address: {error}")))?;
                if address.is_ipv4() != (expected_family == 4) {
                    return Err(Error::invalid(
                        "FakeIP entry address family does not match export",
                    ));
                }
                if record.next.is_some() {
                    return Err(Error::invalid(
                        "FakeIP entry record must not contain a cursor",
                    ));
                }
                entries.push((domain, address));
            }
            "cursor" => {
                if record.domain.is_some() || record.address.is_some() {
                    return Err(Error::invalid(
                        "FakeIP cursor record must not contain an entry",
                    ));
                }
                if next.is_some() {
                    return Err(Error::invalid(
                        "FakeIP legacy export contains duplicate cursors",
                    ));
                }
                let cursor = record
                    .next
                    .ok_or_else(|| Error::invalid("FakeIP cursor record is missing next"))?
                    .parse::<IpAddr>()
                    .map_err(|error| Error::invalid(format!("invalid FakeIP cursor: {error}")))?;
                if cursor.is_ipv4() != (expected_family == 4) {
                    return Err(Error::invalid("FakeIP cursor family does not match export"));
                }
                next = Some(cursor);
            }
            kind => {
                return Err(Error::invalid(format!(
                    "unsupported FakeIP legacy record kind {kind:?}"
                )));
            }
        }
    }

    let Some(version) = version else {
        return Err(Error::invalid("FakeIP legacy NDJSON export is empty"));
    };
    Ok(ParsedLegacyFakeIpExport {
        version,
        family: family.expect("version is set together with family"),
        prefix: prefix.expect("version is set together with prefix"),
        entries,
        next,
    })
}

fn validate_legacy_export_prefix(prefix: &str, expected_family: u8) -> Result<()> {
    let Some((address, bits)) = prefix.rsplit_once('/') else {
        return Err(Error::invalid("FakeIP legacy export prefix is missing '/'"));
    };
    let address = address
        .parse::<IpAddr>()
        .map_err(|error| Error::invalid(format!("invalid FakeIP legacy prefix: {error}")))?;
    if address.is_ipv4() != (expected_family == 4) {
        return Err(Error::invalid(
            "FakeIP legacy export prefix family does not match record family",
        ));
    }
    let bits = bits
        .parse::<u8>()
        .map_err(|error| Error::invalid(format!("invalid FakeIP legacy prefix length: {error}")))?;
    let max_bits = if address.is_ipv4() { 32 } else { 128 };
    if bits > max_bits {
        return Err(Error::invalid(
            "FakeIP legacy export prefix length is out of range",
        ));
    }
    Ok(())
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

    fn size(self) -> u64 {
        u64::from(u32::from(self.end) - u32::from(self.start)) + 1
    }

    fn range_prefix(self) -> String {
        format!("range:{}-{}", self.start, self.end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeIpPoolOptions {
    /// Maximum number of live mappings in this pool.  It may be lower than
    /// the address range to bound database growth and memory use.
    pub max_entries: u64,
    /// An entry is eligible for reuse after this many seconds without a hit.
    pub ttl_seconds: i64,
    /// `last_used_at` touches are coalesced until this interval elapses.  A
    /// final [`FakeIpPool::flush_touches`] persists all dirty timestamps.
    pub touch_interval_seconds: i64,
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

#[derive(Debug, Default)]
struct State {
    next: u32,
    forward: HashMap<DomainName, Mapping4>,
    reverse: HashMap<Ipv4Addr, DomainName>,
}

#[derive(Debug, Clone, Copy)]
struct Mapping4 {
    address: Ipv4Addr,
    created_at: i64,
    last_used_at: i64,
    persisted_last_used_at: i64,
}

pub struct FakeIpPool {
    store: ConfigStore,
    config: FakeIpConfig,
    prefix: String,
    options: FakeIpPoolOptions,
    state: Arc<Mutex<State>>,
}

/// Send/Sync read-only view used by the packet data plane. It contains no
/// SQLite handle, so it can safely be captured by a TUN context provider.
#[derive(Debug, Clone, Default)]
pub struct FakeIpView {
    reverse: Arc<HashMap<Ipv4Addr, DomainName>>,
    reverse_v6: Arc<HashMap<Ipv6Addr, DomainName>>,
}

/// Synchronous, SQLite-free holder for the latest reverse-lookup view.
///
/// Packet callbacks use this holder while the async resolver replaces the
/// view after allocating a new FakeIP.  The lock is intentionally limited to
/// a small immutable-map read and is never held across an await.
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

impl FakeIpView {
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

    /// Combine independently snapshotted IPv4 and IPv6 pools for a dual-stack
    /// TUN context.  The address families have disjoint maps, so merging is
    /// deterministic and does not allow one pool to shadow the other.
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
        Self {
            reverse: Arc::new(reverse),
            reverse_v6: Arc::new(reverse_v6),
        }
    }
}

/// Applies the IPv4 FakeIP answer policy while keeping the store on its
/// owner/future boundary. This intentionally does not implement the
/// synchronous `DnsHandler`: the current store SQLite connection is owned by
/// the synchronous repository boundary and must not be moved into a `Send +
/// Sync` task.
pub struct FakeIpAnswerTransform {
    pub pool: Arc<FakeIpPool>,
}

/// IPv6 counterpart to [`FakeIpAnswerTransform`].  It is kept as a separate
/// type so existing IPv4 callers keep their source-compatible struct literal
/// while a future dual-stack resolver can choose both pools explicitly.
pub struct FakeIpV6AnswerTransform {
    pub pool: Arc<FakeIpV6Pool>,
}

/// Dual-stack transform for callers that answer HTTPS/SVCB in one resolver
/// request.  The family-specific transforms remain public for resolvers that
/// issue separate A/AAAA requests; this wrapper composes the same semantics
/// without duplicating allocation or hint-rewrite logic.
pub struct FakeIpDualStackAnswerTransform {
    pub ipv4: Arc<FakeIpPool>,
    pub ipv6: Arc<FakeIpV6Pool>,
}

impl FakeIpDualStackAnswerTransform {
    pub async fn apply(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> Result<DnsResponse> {
        let response = FakeIpAnswerTransform {
            pool: Arc::clone(&self.ipv4),
        }
        .apply(domain, record_type, response)
        .await?;
        FakeIpV6AnswerTransform {
            pool: Arc::clone(&self.ipv6),
        }
        .apply(domain, record_type, response)
        .await
    }
}

impl FakeIpV6AnswerTransform {
    pub async fn apply(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> Result<DnsResponse> {
        if record_type == DnsRecordType::Aaaa && !response.addresses.v6.is_empty() {
            let address = self.pool.allocate(domain.clone()).await?;
            return Ok(DnsResponse {
                addresses: IpSet {
                    v4: Vec::new(),
                    v6: vec![address],
                },
                ptr_names: response.ptr_names,
                service_bindings: response.service_bindings,
                minimum_ttl: response.minimum_ttl,
            });
        }
        if !matches!(record_type, DnsRecordType::Https | DnsRecordType::Svcb)
            || !response.service_bindings.iter().any(|binding| {
                binding.params.iter().any(|param| {
                    matches!(param, DnsServiceParam::Ipv6Hint(values) if !values.is_empty())
                })
            })
        {
            return Ok(response);
        }
        let address = self.pool.allocate(domain.clone()).await?;
        let mut service_bindings = response.service_bindings;
        for binding in &mut service_bindings {
            for param in &mut binding.params {
                if let DnsServiceParam::Ipv6Hint(values) = param {
                    *values = vec![address];
                }
            }
        }
        Ok(DnsResponse {
            addresses: response.addresses,
            ptr_names: response.ptr_names,
            service_bindings,
            minimum_ttl: response.minimum_ttl,
        })
    }
}

/// Resolves PTR queries for addresses currently owned by either FakeIP pool.
/// A local hit is answered before the upstream resolver is called; an unknown
/// reverse name returns `None` so the caller can preserve the upstream path.
pub struct FakeIpPtrTransform {
    pub ipv4: Arc<FakeIpPool>,
    pub ipv6: Arc<FakeIpV6Pool>,
}

impl FakeIpPtrTransform {
    async fn local_response(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
    ) -> Result<Option<DnsResponse>> {
        if record_type != DnsRecordType::Ptr {
            return Ok(None);
        }
        let Some(address) = reverse_name_to_ip(domain) else {
            return Ok(None);
        };
        let mapped = match address {
            IpAddr::V4(address) => self.ipv4.lookup_domain(address).await,
            IpAddr::V6(address) => self.ipv6.lookup_domain(address).await,
        };
        Ok(mapped.map(|domain| DnsResponse {
            addresses: IpSet::default(),
            ptr_names: vec![domain],
            service_bindings: Vec::new(),
            minimum_ttl: Some(60),
        }))
    }

    pub async fn apply(
        &self,
        _domain: &DomainName,
        _record_type: DnsRecordType,
        response: DnsResponse,
    ) -> Result<DnsResponse> {
        Ok(response)
    }
}

fn reverse_name_to_ip(domain: &DomainName) -> Option<IpAddr> {
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

impl FakeIpAnswerTransform {
    pub async fn apply(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> Result<DnsResponse> {
        if record_type == DnsRecordType::A && !response.addresses.v4.is_empty() {
            let address = self.pool.allocate(domain.clone()).await?;
            return Ok(DnsResponse {
                addresses: IpSet {
                    v4: vec![address],
                    v6: Vec::new(),
                },
                ptr_names: response.ptr_names,
                service_bindings: response.service_bindings,
                minimum_ttl: response.minimum_ttl,
            });
        }
        if !matches!(record_type, DnsRecordType::Https | DnsRecordType::Svcb)
            || !response.service_bindings.iter().any(|binding| {
                binding.params.iter().any(|param| {
                    matches!(param, DnsServiceParam::Ipv4Hint(values) if !values.is_empty())
                })
            })
        {
            return Ok(response);
        }
        let address = self.pool.allocate(domain.clone()).await?;
        let mut service_bindings = response.service_bindings;
        for binding in &mut service_bindings {
            for param in &mut binding.params {
                if let DnsServiceParam::Ipv4Hint(values) = param {
                    *values = vec![address];
                }
            }
        }
        Ok(DnsResponse {
            addresses: response.addresses,
            ptr_names: response.ptr_names,
            service_bindings,
            minimum_ttl: response.minimum_ttl,
        })
    }
}

#[cfg(feature = "async-dns")]
pub trait AsyncDomainResolver {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>>;
}

#[cfg(feature = "async-dns")]
pub trait FakeIpResponseTransform {
    fn local_response<'a>(
        &'a self,
        _domain: &'a DomainName,
        _record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<Option<DnsResponse>>> {
        Box::pin(async { Ok(None) })
    }

    fn apply<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>>;
}

#[cfg(feature = "async-dns")]
impl FakeIpResponseTransform for FakeIpAnswerTransform {
    fn apply<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(
            async move { FakeIpAnswerTransform::apply(self, domain, record_type, response).await },
        )
    }
}

#[cfg(feature = "async-dns")]
impl FakeIpResponseTransform for FakeIpV6AnswerTransform {
    fn apply<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            FakeIpV6AnswerTransform::apply(self, domain, record_type, response).await
        })
    }
}

#[cfg(feature = "async-dns")]
impl FakeIpResponseTransform for FakeIpDualStackAnswerTransform {
    fn apply<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { self.apply(domain, record_type, response).await })
    }
}

#[cfg(feature = "async-dns")]
impl FakeIpResponseTransform for FakeIpPtrTransform {
    fn local_response<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<Option<DnsResponse>>> {
        Box::pin(async move { FakeIpPtrTransform::local_response(self, domain, record_type).await })
    }

    fn apply<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(
            async move { FakeIpPtrTransform::apply(self, domain, record_type, response).await },
        )
    }
}

#[cfg(feature = "async-dns")]
pub struct FakeIpAsyncDnsHandler<R, T = FakeIpAnswerTransform> {
    pub upstream: R,
    pub transform: T,
}

#[cfg(feature = "async-dns")]
impl<R, T> AsyncDnsHandler for FakeIpAsyncDnsHandler<R, T>
where
    R: AsyncDomainResolver,
    T: FakeIpResponseTransform,
{
    fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let question = decode_query(packet)?;
            let response = if let Some(response) = self
                .transform
                .local_response(&question.domain, question.record_type)
                .await?
            {
                response
            } else {
                self.upstream
                    .resolve(&question.domain, question.record_type)
                    .await?
            };
            let response = self
                .transform
                .apply(&question.domain, question.record_type, response)
                .await?;
            encode_response(packet, &response)
        })
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn expired_at(last_used_at: i64, now: i64, ttl_seconds: i64) -> bool {
    now >= last_used_at && now - last_used_at >= ttl_seconds
}

fn config_contains(config: FakeIpConfig, address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    value >= u32::from(config.start) && value <= u32::from(config.end)
}

fn config_contains_v6(config: FakeIpV6Config, address: Ipv6Addr) -> bool {
    let value = u128::from(address);
    value >= u128::from(config.start) && value <= u128::from(config.end)
}

fn normalize_next_v4(next: &mut u32, config: FakeIpConfig) {
    if !config_contains(config, Ipv4Addr::from(*next)) {
        *next = u32::from(config.start);
    }
}

fn normalize_next_v6(next: &mut u128, config: FakeIpV6Config) {
    if !config_contains_v6(config, Ipv6Addr::from(*next)) {
        *next = u128::from(config.start);
    }
}

async fn load_legacy_keys(store: &ConfigStore, prefix: &str) -> Result<Vec<String>> {
    Ok(store
        .list_config(prefix)
        .await?
        .into_iter()
        .map(|(key, _)| key)
        .collect())
}

async fn load_legacy_v4(
    store: &ConfigStore,
    config: FakeIpConfig,
    prefix: &str,
    now: i64,
) -> Result<Vec<FakeIpEntryRecord>> {
    let mut entries = Vec::new();
    let mut addresses = HashMap::new();
    for (key, value) in store.list_config(MAP_PREFIX).await? {
        if value.len() != 4 {
            continue;
        }
        let Some(domain) = key.strip_prefix(MAP_PREFIX) else {
            continue;
        };
        let Ok(domain) = DomainName::new(domain) else {
            continue;
        };
        let address = Ipv4Addr::from(<[u8; 4]>::try_from(value).unwrap());
        if !config_contains(config, address) || addresses.contains_key(&address) {
            continue;
        }
        addresses.insert(address, domain.clone());
        entries.push(FakeIpEntryRecord {
            family: 4,
            prefix: prefix.to_owned(),
            domain: domain.to_string(),
            ip: address.octets().to_vec(),
            created_at: now,
            last_used_at: now,
        });
    }
    Ok(entries)
}

async fn load_legacy_v6(
    store: &ConfigStore,
    config: FakeIpV6Config,
    prefix: &str,
    now: i64,
) -> Result<Vec<FakeIpEntryRecord>> {
    let mut entries = Vec::new();
    let mut addresses = HashMap::new();
    for (key, value) in store.list_config(MAP_V6_PREFIX).await? {
        if value.len() != 16 {
            continue;
        }
        let Some(domain) = key.strip_prefix(MAP_V6_PREFIX) else {
            continue;
        };
        let Ok(domain) = DomainName::new(domain) else {
            continue;
        };
        let address = Ipv6Addr::from(<[u8; 16]>::try_from(value).unwrap());
        if !config_contains_v6(config, address) || addresses.contains_key(&address) {
            continue;
        }
        addresses.insert(address, domain.clone());
        entries.push(FakeIpEntryRecord {
            family: 6,
            prefix: prefix.to_owned(),
            domain: domain.to_string(),
            ip: address.octets().to_vec(),
            created_at: now,
            last_used_at: now,
        });
    }
    Ok(entries)
}

impl FakeIpPool {
    pub async fn open(store: ConfigStore, config: FakeIpConfig) -> Result<Self> {
        Self::open_with_options(store, config, FakeIpPoolOptions::for_config(config)).await
    }

    pub async fn open_with_options(
        store: ConfigStore,
        config: FakeIpConfig,
        options: FakeIpPoolOptions,
    ) -> Result<Self> {
        Self::open_with_prefix(store, config, config.range_prefix(), options).await
    }

    /// Open a pool under an explicit canonical prefix such as
    /// `198.18.0.0/15`.  The range constructor remains available for older
    /// callers whose configuration only contains start/end addresses.
    pub async fn open_with_prefix(
        store: ConfigStore,
        config: FakeIpConfig,
        prefix: impl Into<String>,
        options: FakeIpPoolOptions,
    ) -> Result<Self> {
        if options.max_entries == 0 || options.max_entries > config.size() {
            return Err(Error::invalid(
                "FakeIP max_entries must fit inside the configured pool",
            ));
        }
        if options.ttl_seconds <= 0 || options.touch_interval_seconds <= 0 {
            return Err(Error::invalid("FakeIP time options must be positive"));
        }
        let prefix = prefix.into();
        if prefix.is_empty() || prefix.len() > 512 || prefix.chars().any(char::is_control) {
            return Err(Error::invalid("invalid FakeIP pool prefix"));
        }
        let now = unix_now();
        let family = 4;
        let typed_entries = store.list_fakeip_entries(family, &prefix).await?;
        let typed_entries_were_absent = typed_entries.is_empty();
        let typed_cursor = store.get_fakeip_cursor(family, &prefix).await?;
        let legacy_entries = if typed_entries_were_absent {
            load_legacy_v4(&store, config, &prefix, now).await?
        } else {
            Vec::new()
        };
        let legacy_cursor = if typed_entries_were_absent {
            store.get_config(NEXT_KEY).await?.and_then(|value| {
                (value.len() == 4).then(|| u32::from_be_bytes(value.try_into().unwrap()))
            })
        } else {
            None
        };

        let mut state = State {
            next: typed_cursor
                .as_ref()
                .and_then(|cursor| {
                    (cursor.cursor_ip.len() == 4)
                        .then(|| u32::from_be_bytes(cursor.cursor_ip.clone().try_into().unwrap()))
                })
                .or(legacy_cursor)
                .unwrap_or(u32::from(config.start)),
            ..State::default()
        };
        normalize_next_v4(&mut state.next, config);

        let mut expired = Vec::new();
        let mut source_entries = typed_entries;
        if source_entries.is_empty() {
            source_entries = legacy_entries;
        }
        for entry in &source_entries {
            if entry.ip.len() != 4 || entry.family != family || entry.prefix != prefix {
                continue;
            }
            let domain = match DomainName::new(&entry.domain) {
                Ok(domain) => domain,
                Err(_) => continue,
            };
            let address = Ipv4Addr::from(<[u8; 4]>::try_from(entry.ip.as_slice()).unwrap());
            if !config_contains(config, address)
                || state.reverse.contains_key(&address)
                || state.forward.contains_key(&domain)
            {
                continue;
            }
            if expired_at(entry.last_used_at, now, options.ttl_seconds) {
                expired.push(entry.domain.clone());
                continue;
            }
            state.reverse.insert(address, domain.clone());
            state.forward.insert(
                domain,
                Mapping4 {
                    address,
                    created_at: entry.created_at,
                    last_used_at: entry.last_used_at,
                    persisted_last_used_at: entry.last_used_at,
                },
            );
        }

        if !expired.is_empty() {
            store
                .delete_fakeip_entries(family, &prefix, &expired)
                .await?;
        }

        let over_capacity = state
            .forward
            .iter()
            .map(|(domain, mapping)| (domain.clone(), mapping.last_used_at))
            .collect::<Vec<_>>();
        let mut trim = over_capacity;
        trim.sort_by_key(|(_, last_used_at)| *last_used_at);
        let trim_count = state
            .forward
            .len()
            .saturating_sub(options.max_entries as usize);
        if trim_count != 0 {
            let domains: Vec<_> = trim
                .into_iter()
                .take(trim_count)
                .map(|(domain, _)| domain)
                .collect();
            store
                .delete_fakeip_entries(
                    family,
                    &prefix,
                    &domains.iter().map(ToString::to_string).collect::<Vec<_>>(),
                )
                .await?;
            for domain in domains {
                if let Some(mapping) = state.forward.remove(&domain) {
                    state.reverse.remove(&mapping.address);
                }
            }
        }

        let pool = Self {
            store,
            config,
            prefix,
            options,
            state: Arc::new(Mutex::new(state)),
        };

        if typed_entries_were_absent {
            let entries = pool
                .state
                .lock()
                .await
                .forward
                .iter()
                .map(|(domain, mapping)| FakeIpEntryRecord {
                    family,
                    prefix: pool.prefix.clone(),
                    domain: domain.to_string(),
                    ip: mapping.address.octets().to_vec(),
                    created_at: mapping.created_at,
                    last_used_at: mapping.last_used_at,
                })
                .collect::<Vec<_>>();
            let next = pool.state.lock().await.next;
            let cursor = FakeIpCursorRecord {
                family,
                prefix: pool.prefix.clone(),
                cursor_ip: next.to_be_bytes().to_vec(),
                cursor_idx: i64::from(next.saturating_sub(u32::from(config.start))),
                updated_at: now,
            };
            let mut legacy_keys = vec![NEXT_KEY.to_owned()];
            legacy_keys.extend(load_legacy_keys(&pool.store, MAP_PREFIX).await?);
            if !entries.is_empty() || legacy_keys.len() > 1 {
                pool.store
                    .import_fakeip_state(&entries, &cursor, &legacy_keys, None)
                    .await?;
            }
        }
        Ok(pool)
    }

    pub async fn allocate(&self, domain: DomainName) -> Result<Ipv4Addr> {
        self.allocate_at(domain, unix_now()).await
    }

    pub async fn allocate_at(&self, domain: DomainName, now: i64) -> Result<Ipv4Addr> {
        let mut state = self.state.lock().await;
        if let Some(mapping) = state.forward.get(&domain).copied() {
            if !expired_at(mapping.last_used_at, now, self.options.ttl_seconds) {
                if now.saturating_sub(mapping.persisted_last_used_at)
                    >= self.options.touch_interval_seconds
                {
                    self.store
                        .touch_fakeip_entries(4, &self.prefix, &[(domain.to_string(), now)])
                        .await?;
                    if let Some(mapping) = state.forward.get_mut(&domain) {
                        mapping.persisted_last_used_at = now;
                        mapping.last_used_at = now;
                    }
                } else if let Some(mapping) = state.forward.get_mut(&domain) {
                    mapping.last_used_at = now;
                }
                return Ok(mapping.address);
            }
            self.store
                .delete_fakeip_entries(4, &self.prefix, &[domain.to_string()])
                .await?;
            state.forward.remove(&domain);
            state.reverse.remove(&mapping.address);
        }

        let expired: Vec<_> = state
            .forward
            .iter()
            .filter(|(_, mapping)| expired_at(mapping.last_used_at, now, self.options.ttl_seconds))
            .map(|(domain, _)| domain.clone())
            .collect();
        if !expired.is_empty() {
            let names: Vec<_> = expired.iter().map(ToString::to_string).collect();
            self.store
                .delete_fakeip_entries(4, &self.prefix, &names)
                .await?;
            for domain in expired {
                if let Some(mapping) = state.forward.remove(&domain) {
                    state.reverse.remove(&mapping.address);
                }
            }
        }

        let start = u32::from(self.config.start);
        let size = self.config.size();
        let (address, evicted_domain) = if state.forward.len() as u64 >= self.options.max_entries {
            let Some((evicted_domain, mapping)) = state
                .forward
                .iter()
                .min_by_key(|(_, mapping)| mapping.last_used_at)
                .map(|(domain, mapping)| (domain.clone(), *mapping))
            else {
                return Err(Error::new(ErrorKind::Storage, "FakeIP pool is exhausted"));
            };
            (mapping.address, Some(evicted_domain))
        } else {
            let mut selected = None;
            for offset in 0..size {
                let candidate = start + ((u64::from(state.next - start) + offset) % size) as u32;
                let address = Ipv4Addr::from(candidate);
                if !state.reverse.contains_key(&address) {
                    selected = Some(address);
                    break;
                }
            }
            let Some(address) = selected else {
                return Err(Error::new(ErrorKind::Storage, "FakeIP pool is exhausted"));
            };
            (address, None)
        };
        let raw = u32::from(address);
        let next = start + ((u64::from(raw - start) + 1) % size) as u32;
        let entry = FakeIpEntryRecord {
            family: 4,
            prefix: self.prefix.clone(),
            domain: domain.to_string(),
            ip: address.octets().to_vec(),
            created_at: now,
            last_used_at: now,
        };
        let cursor = FakeIpCursorRecord {
            family: 4,
            prefix: self.prefix.clone(),
            cursor_ip: next.to_be_bytes().to_vec(),
            cursor_idx: i64::from(next - start),
            updated_at: now,
        };
        self.store
            .replace_fakeip_entry(
                &entry,
                &cursor,
                evicted_domain.as_ref().map(ToString::to_string).as_deref(),
            )
            .await?;
        if let Some(evicted_domain) = evicted_domain
            && let Some(mapping) = state.forward.remove(&evicted_domain)
        {
            state.reverse.remove(&mapping.address);
        }
        state.next = next;
        state.reverse.insert(address, domain.clone());
        state.forward.insert(
            domain,
            Mapping4 {
                address,
                created_at: now,
                last_used_at: now,
                persisted_last_used_at: now,
            },
        );
        Ok(address)
    }

    /// Import a snapshot exported by the Go Pebble/bbolt layer.
    ///
    /// The Rust store does not read Pebble files directly. The Go side exports
    /// domain/address/cursor records, and this method validates and imports
    /// that export atomically. A marker makes retries safe after interruption.
    pub async fn import_legacy(
        &self,
        marker: &str,
        snapshot: LegacyFakeIpSnapshot,
    ) -> Result<bool> {
        if marker.is_empty()
            || marker.len() > 128
            || marker.chars().any(|character| character.is_control())
        {
            return Err(Error::invalid("invalid FakeIP legacy import marker"));
        }
        let marker_key = format!("{IMPORT_MARKER_PREFIX}{marker}");

        let start = u32::from(self.config.start);
        let end = u32::from(self.config.end);
        let mut imported_ips = HashMap::new();
        let mut imported_domains = HashMap::new();
        let mut entries = Vec::with_capacity(snapshot.entries.len());
        for entry in snapshot.entries {
            let address = u32::from(entry.address);
            if address < start || address > end {
                return Err(Error::invalid("legacy FakeIP address is outside the pool"));
            }
            if let Some(existing) = imported_ips.insert(entry.address, entry.domain.clone())
                && existing != entry.domain
            {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "legacy FakeIP export contains duplicate addresses",
                ));
            }
            if let Some(existing) = imported_domains.insert(entry.domain.clone(), entry.address)
                && existing != entry.address
            {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "legacy FakeIP export contains duplicate domains",
                ));
            }
            if let Some(existing) = self.state.lock().await.reverse.get(&entry.address)
                && existing != &entry.domain
            {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "legacy FakeIP address conflicts with current mapping",
                ));
            }
            if let Some(existing) = self.state.lock().await.forward.get(&entry.domain)
                && existing.address != entry.address
            {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "legacy FakeIP domain conflicts with current mapping",
                ));
            }
            entries.push(FakeIpEntryRecord {
                family: 4,
                prefix: self.prefix.clone(),
                domain: entry.domain.to_string(),
                ip: entry.address.octets().to_vec(),
                created_at: unix_now(),
                last_used_at: unix_now(),
            });
        }
        let next = snapshot.next.unwrap_or(self.config.start);
        if u32::from(next) < start || u32::from(next) > end {
            return Err(Error::invalid("legacy FakeIP cursor is outside the pool"));
        }
        let now = unix_now();
        let cursor = FakeIpCursorRecord {
            family: 4,
            prefix: self.prefix.clone(),
            cursor_ip: next.octets().to_vec(),
            cursor_idx: i64::from(u32::from(next) - u32::from(self.config.start)),
            updated_at: now,
        };
        let imported = self
            .store
            .import_fakeip_state_if_unmarked(&entries, &cursor, &[], &marker_key)
            .await?;
        if !imported {
            return Ok(false);
        }

        let mut state = self.state.lock().await;
        state.next = u32::from(next);
        for (address, domain) in imported_ips {
            state.reverse.insert(address, domain.clone());
            state.forward.insert(
                domain,
                Mapping4 {
                    address,
                    created_at: now,
                    last_used_at: now,
                    persisted_last_used_at: now,
                },
            );
        }
        Ok(true)
    }

    pub async fn lookup_domain(&self, address: Ipv4Addr) -> Option<DomainName> {
        self.state.lock().await.reverse.get(&address).cloned()
    }

    pub async fn lookup_ip(&self, domain: &DomainName) -> Option<Ipv4Addr> {
        self.state
            .lock()
            .await
            .forward
            .get(domain)
            .map(|mapping| mapping.address)
    }

    pub async fn snapshot(&self) -> FakeIpView {
        FakeIpView {
            reverse: Arc::new(self.state.lock().await.reverse.clone()),
            reverse_v6: Arc::new(HashMap::new()),
        }
    }

    pub async fn release(&self, domain: &DomainName) -> Result<bool> {
        let mut state = self.state.lock().await;
        let Some(mapping) = state.forward.get(domain).copied() else {
            return Ok(false);
        };
        self.store
            .delete_fakeip_entries(4, &self.prefix, &[domain.to_string()])
            .await?;
        state.forward.remove(domain);
        state.reverse.remove(&mapping.address);
        Ok(true)
    }

    pub async fn flush_touches(&self) -> Result<usize> {
        let mut state = self.state.lock().await;
        let touches: Vec<_> = state
            .forward
            .iter()
            .filter(|(_, mapping)| mapping.last_used_at != mapping.persisted_last_used_at)
            .map(|(domain, mapping)| (domain.to_string(), mapping.last_used_at))
            .collect();
        let updated = self
            .store
            .touch_fakeip_entries(4, &self.prefix, &touches)
            .await?;
        for (domain, _) in &touches {
            if let Ok(domain) = DomainName::new(domain)
                && let Some(mapping) = state.forward.get_mut(&domain)
            {
                mapping.persisted_last_used_at = mapping.last_used_at;
            }
        }
        Ok(updated)
    }

    pub async fn len(&self) -> usize {
        self.state.lock().await.forward.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    pub fn contains(&self, address: Ipv4Addr) -> bool {
        let start = u32::from(self.config.start);
        let end = u32::from(self.config.end);
        u32::from(address) >= start && u32::from(address) <= end
    }
}

#[derive(Debug, Default)]
struct V6State {
    next: u128,
    forward: HashMap<DomainName, Mapping6>,
    reverse: HashMap<Ipv6Addr, DomainName>,
}

#[derive(Debug, Clone, Copy)]
struct Mapping6 {
    address: Ipv6Addr,
    created_at: i64,
    last_used_at: i64,
    persisted_last_used_at: i64,
}

/// Persistent IPv6 FakeIP pool.  IPv6 uses a separate cursor and key
/// namespace so an IPv4 import or stale legacy row can never alias an IPv6
/// mapping.  The pool deliberately mirrors the IPv4 lifecycle API so the
/// caller can own one pool per address family.
pub struct FakeIpV6Pool {
    store: ConfigStore,
    config: FakeIpV6Config,
    prefix: String,
    options: FakeIpPoolOptions,
    state: Arc<Mutex<V6State>>,
}

impl FakeIpV6Pool {
    pub async fn open(store: ConfigStore, config: FakeIpV6Config) -> Result<Self> {
        Self::open_with_options(store, config, FakeIpPoolOptions::for_v6_config(config)).await
    }

    pub async fn open_with_options(
        store: ConfigStore,
        config: FakeIpV6Config,
        options: FakeIpPoolOptions,
    ) -> Result<Self> {
        Self::open_with_prefix(store, config, config.range_prefix(), options).await
    }

    pub async fn open_with_prefix(
        store: ConfigStore,
        config: FakeIpV6Config,
        prefix: impl Into<String>,
        options: FakeIpPoolOptions,
    ) -> Result<Self> {
        let size = config.size()?;
        if options.max_entries == 0 || u128::from(options.max_entries) > size {
            return Err(Error::invalid(
                "FakeIP max_entries must fit inside the configured IPv6 pool",
            ));
        }
        if options.ttl_seconds <= 0 || options.touch_interval_seconds <= 0 {
            return Err(Error::invalid("FakeIP time options must be positive"));
        }
        let prefix = prefix.into();
        if prefix.is_empty() || prefix.len() > 512 || prefix.chars().any(char::is_control) {
            return Err(Error::invalid("invalid FakeIP pool prefix"));
        }
        let now = unix_now();
        let family = 6;
        let typed_entries = store.list_fakeip_entries(family, &prefix).await?;
        let typed_entries_were_absent = typed_entries.is_empty();
        let typed_cursor = store.get_fakeip_cursor(family, &prefix).await?;
        let legacy_entries = if typed_entries_were_absent {
            load_legacy_v6(&store, config, &prefix, now).await?
        } else {
            Vec::new()
        };
        let legacy_cursor = if typed_entries_were_absent {
            store.get_config(NEXT_V6_KEY).await?.and_then(|value| {
                (value.len() == 16).then(|| u128::from_be_bytes(value.try_into().unwrap()))
            })
        } else {
            None
        };
        let mut state = V6State {
            next: typed_cursor
                .as_ref()
                .and_then(|cursor| {
                    (cursor.cursor_ip.len() == 16)
                        .then(|| u128::from_be_bytes(cursor.cursor_ip.clone().try_into().unwrap()))
                })
                .or(legacy_cursor)
                .unwrap_or(u128::from(config.start)),
            ..V6State::default()
        };
        normalize_next_v6(&mut state.next, config);

        let mut source_entries = typed_entries;
        if source_entries.is_empty() {
            source_entries = legacy_entries;
        }
        let mut expired = Vec::new();
        for entry in &source_entries {
            if entry.ip.len() != 16 || entry.family != family || entry.prefix != prefix {
                continue;
            }
            let domain = match DomainName::new(&entry.domain) {
                Ok(domain) => domain,
                Err(_) => continue,
            };
            let address = Ipv6Addr::from(<[u8; 16]>::try_from(entry.ip.as_slice()).unwrap());
            if !config_contains_v6(config, address)
                || state.reverse.contains_key(&address)
                || state.forward.contains_key(&domain)
            {
                continue;
            }
            if expired_at(entry.last_used_at, now, options.ttl_seconds) {
                expired.push(entry.domain.clone());
                continue;
            }
            state.reverse.insert(address, domain.clone());
            state.forward.insert(
                domain,
                Mapping6 {
                    address,
                    created_at: entry.created_at,
                    last_used_at: entry.last_used_at,
                    persisted_last_used_at: entry.last_used_at,
                },
            );
        }
        if !expired.is_empty() {
            store
                .delete_fakeip_entries(family, &prefix, &expired)
                .await?;
        }
        let mut trim: Vec<_> = state
            .forward
            .iter()
            .map(|(domain, mapping)| (domain.clone(), mapping.last_used_at))
            .collect();
        trim.sort_by_key(|(_, last_used_at)| *last_used_at);
        let trim_count = state
            .forward
            .len()
            .saturating_sub(options.max_entries as usize);
        if trim_count != 0 {
            let domains: Vec<_> = trim
                .into_iter()
                .take(trim_count)
                .map(|(domain, _)| domain)
                .collect();
            let names: Vec<_> = domains.iter().map(ToString::to_string).collect();
            store.delete_fakeip_entries(family, &prefix, &names).await?;
            for domain in domains {
                if let Some(mapping) = state.forward.remove(&domain) {
                    state.reverse.remove(&mapping.address);
                }
            }
        }

        let pool = Self {
            store,
            config,
            prefix,
            options,
            state: Arc::new(Mutex::new(state)),
        };
        if typed_entries_were_absent {
            let entries = pool
                .state
                .lock()
                .await
                .forward
                .iter()
                .map(|(domain, mapping)| FakeIpEntryRecord {
                    family,
                    prefix: pool.prefix.clone(),
                    domain: domain.to_string(),
                    ip: mapping.address.octets().to_vec(),
                    created_at: mapping.created_at,
                    last_used_at: mapping.last_used_at,
                })
                .collect::<Vec<_>>();
            let next = pool.state.lock().await.next;
            let cursor = FakeIpCursorRecord {
                family,
                prefix: pool.prefix.clone(),
                cursor_ip: next.to_be_bytes().to_vec(),
                cursor_idx: i64::try_from(next.saturating_sub(u128::from(config.start)))
                    .unwrap_or(i64::MAX),
                updated_at: now,
            };
            let mut legacy_keys = vec![NEXT_V6_KEY.to_owned()];
            legacy_keys.extend(load_legacy_keys(&pool.store, MAP_V6_PREFIX).await?);
            if !entries.is_empty() || legacy_keys.len() > 1 {
                pool.store
                    .import_fakeip_state(&entries, &cursor, &legacy_keys, None)
                    .await?;
            }
        }
        Ok(pool)
    }

    pub async fn allocate(&self, domain: DomainName) -> Result<Ipv6Addr> {
        self.allocate_at(domain, unix_now()).await
    }

    pub async fn allocate_at(&self, domain: DomainName, now: i64) -> Result<Ipv6Addr> {
        let mut state = self.state.lock().await;
        if let Some(mapping) = state.forward.get(&domain).copied() {
            if !expired_at(mapping.last_used_at, now, self.options.ttl_seconds) {
                if now.saturating_sub(mapping.persisted_last_used_at)
                    >= self.options.touch_interval_seconds
                {
                    self.store
                        .touch_fakeip_entries(6, &self.prefix, &[(domain.to_string(), now)])
                        .await?;
                    if let Some(mapping) = state.forward.get_mut(&domain) {
                        mapping.persisted_last_used_at = now;
                        mapping.last_used_at = now;
                    }
                } else if let Some(mapping) = state.forward.get_mut(&domain) {
                    mapping.last_used_at = now;
                }
                return Ok(mapping.address);
            }
            self.store
                .delete_fakeip_entries(6, &self.prefix, &[domain.to_string()])
                .await?;
            state.forward.remove(&domain);
            state.reverse.remove(&mapping.address);
        }

        let expired: Vec<_> = state
            .forward
            .iter()
            .filter(|(_, mapping)| expired_at(mapping.last_used_at, now, self.options.ttl_seconds))
            .map(|(domain, _)| domain.clone())
            .collect();
        if !expired.is_empty() {
            let names: Vec<_> = expired.iter().map(ToString::to_string).collect();
            self.store
                .delete_fakeip_entries(6, &self.prefix, &names)
                .await?;
            for domain in expired {
                if let Some(mapping) = state.forward.remove(&domain) {
                    state.reverse.remove(&mapping.address);
                }
            }
        }

        let start = u128::from(self.config.start);
        let size = self.config.size()?;
        let (address, evicted_domain) = if state.forward.len() as u64 >= self.options.max_entries {
            let Some((evicted_domain, mapping)) = state
                .forward
                .iter()
                .min_by_key(|(_, mapping)| mapping.last_used_at)
                .map(|(domain, mapping)| (domain.clone(), *mapping))
            else {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "FakeIP IPv6 pool is exhausted",
                ));
            };
            (mapping.address, Some(evicted_domain))
        } else {
            let mut selected = None;
            for offset in 0..size {
                let candidate = start + ((state.next - start + offset) % size);
                let address = Ipv6Addr::from(candidate);
                if !state.reverse.contains_key(&address) {
                    selected = Some(address);
                    break;
                }
            }
            let Some(address) = selected else {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "FakeIP IPv6 pool is exhausted",
                ));
            };
            (address, None)
        };
        let raw = u128::from(address);
        let next = start + ((raw - start + 1) % size);
        let entry = FakeIpEntryRecord {
            family: 6,
            prefix: self.prefix.clone(),
            domain: domain.to_string(),
            ip: address.octets().to_vec(),
            created_at: now,
            last_used_at: now,
        };
        let cursor = FakeIpCursorRecord {
            family: 6,
            prefix: self.prefix.clone(),
            cursor_ip: next.to_be_bytes().to_vec(),
            cursor_idx: i64::try_from(next.saturating_sub(start)).unwrap_or(i64::MAX),
            updated_at: now,
        };
        let evicted_domain_name = evicted_domain.as_ref().map(ToString::to_string);
        self.store
            .replace_fakeip_entry(&entry, &cursor, evicted_domain_name.as_deref())
            .await?;
        if let Some(evicted_domain) = evicted_domain
            && let Some(mapping) = state.forward.remove(&evicted_domain)
        {
            state.reverse.remove(&mapping.address);
        }
        state.next = next;
        state.reverse.insert(address, domain.clone());
        state.forward.insert(
            domain,
            Mapping6 {
                address,
                created_at: now,
                last_used_at: now,
                persisted_last_used_at: now,
            },
        );
        Ok(address)
    }

    /// Import the IPv6 half of a Go Pebble/bbolt export atomically.  IPv6
    /// deliberately has its own marker, typed scope and cursor namespace so
    /// a retried dual-stack migration cannot cross-contaminate the pools.
    pub async fn import_legacy(
        &self,
        marker: &str,
        snapshot: LegacyFakeIpV6Snapshot,
    ) -> Result<bool> {
        if marker.is_empty()
            || marker.len() > 128
            || marker.chars().any(|character| character.is_control())
        {
            return Err(Error::invalid("invalid FakeIP legacy import marker"));
        }
        let marker_key = format!("{IMPORT_MARKER_PREFIX}{marker}");

        let start = u128::from(self.config.start);
        let end = u128::from(self.config.end);
        let mut imported_ips = HashMap::new();
        let mut imported_domains = HashMap::new();
        let mut entries = Vec::with_capacity(snapshot.entries.len());
        for entry in snapshot.entries {
            let address = u128::from(entry.address);
            if address < start || address > end {
                return Err(Error::invalid(
                    "legacy FakeIP IPv6 address is outside the pool",
                ));
            }
            if let Some(existing) = imported_ips.insert(entry.address, entry.domain.clone())
                && existing != entry.domain
            {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "legacy FakeIP IPv6 export contains duplicate addresses",
                ));
            }
            if let Some(existing) = imported_domains.insert(entry.domain.clone(), entry.address)
                && existing != entry.address
            {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "legacy FakeIP IPv6 export contains duplicate domains",
                ));
            }
            if let Some(existing) = self.state.lock().await.reverse.get(&entry.address)
                && existing != &entry.domain
            {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "legacy FakeIP IPv6 address conflicts with current mapping",
                ));
            }
            if let Some(existing) = self.state.lock().await.forward.get(&entry.domain)
                && existing.address != entry.address
            {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "legacy FakeIP IPv6 domain conflicts with current mapping",
                ));
            }
            entries.push(FakeIpEntryRecord {
                family: 6,
                prefix: self.prefix.clone(),
                domain: entry.domain.to_string(),
                ip: entry.address.octets().to_vec(),
                created_at: unix_now(),
                last_used_at: unix_now(),
            });
        }
        let next = snapshot.next.unwrap_or(self.config.start);
        if u128::from(next) < start || u128::from(next) > end {
            return Err(Error::invalid(
                "legacy FakeIP IPv6 cursor is outside the pool",
            ));
        }
        let now = unix_now();
        let cursor = FakeIpCursorRecord {
            family: 6,
            prefix: self.prefix.clone(),
            cursor_ip: next.octets().to_vec(),
            cursor_idx: i64::try_from(u128::from(next) - start).unwrap_or(i64::MAX),
            updated_at: now,
        };
        let imported = self
            .store
            .import_fakeip_state_if_unmarked(&entries, &cursor, &[], &marker_key)
            .await?;
        if !imported {
            return Ok(false);
        }

        let mut state = self.state.lock().await;
        state.next = u128::from(next);
        for (address, domain) in imported_ips {
            state.reverse.insert(address, domain.clone());
            state.forward.insert(
                domain,
                Mapping6 {
                    address,
                    created_at: now,
                    last_used_at: now,
                    persisted_last_used_at: now,
                },
            );
        }
        Ok(true)
    }

    pub async fn lookup_domain(&self, address: Ipv6Addr) -> Option<DomainName> {
        self.state.lock().await.reverse.get(&address).cloned()
    }

    pub async fn lookup_ip(&self, domain: &DomainName) -> Option<Ipv6Addr> {
        self.state
            .lock()
            .await
            .forward
            .get(domain)
            .map(|mapping| mapping.address)
    }

    pub async fn snapshot(&self) -> FakeIpView {
        FakeIpView {
            reverse: Arc::new(HashMap::new()),
            reverse_v6: Arc::new(self.state.lock().await.reverse.clone()),
        }
    }

    pub async fn release(&self, domain: &DomainName) -> Result<bool> {
        let mut state = self.state.lock().await;
        let Some(mapping) = state.forward.get(domain).copied() else {
            return Ok(false);
        };
        self.store
            .delete_fakeip_entries(6, &self.prefix, &[domain.to_string()])
            .await?;
        state.forward.remove(domain);
        state.reverse.remove(&mapping.address);
        Ok(true)
    }

    pub async fn flush_touches(&self) -> Result<usize> {
        let mut state = self.state.lock().await;
        let touches: Vec<_> = state
            .forward
            .iter()
            .filter(|(_, mapping)| mapping.last_used_at != mapping.persisted_last_used_at)
            .map(|(domain, mapping)| (domain.to_string(), mapping.last_used_at))
            .collect();
        let updated = self
            .store
            .touch_fakeip_entries(6, &self.prefix, &touches)
            .await?;
        for (domain, _) in &touches {
            if let Ok(domain) = DomainName::new(domain)
                && let Some(mapping) = state.forward.get_mut(&domain)
            {
                mapping.persisted_last_used_at = mapping.last_used_at;
            }
        }
        Ok(updated)
    }

    pub async fn len(&self) -> usize {
        self.state.lock().await.forward.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    pub fn contains(&self, address: Ipv6Addr) -> bool {
        let start = u128::from(self.config.start);
        let end = u128::from(self.config.end);
        u128::from(address) >= start && u128::from(address) <= end
    }
}

#[cfg(test)]
#[path = "fakeip_tests.rs"]
mod tests;
