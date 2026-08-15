//! DNS wire codec and a small UDP client/server boundary.
//!
//! Hickory handles DNS name compression, record encoding, and malformed packet
//! checks. The surrounding code owns timeout, routing, caching, and FakeIP
//! policy; this module deliberately does not hide those decisions.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, Query};
use hickory_proto::rr::rdata::svcb::{
    Alpn, EchConfigList, IpHint, Mandatory, SvcParamKey, SvcParamValue, Unknown,
};
use hickory_proto::rr::{
    Name, RData, RecordType,
    rdata::{A, AAAA, HTTPS, PTR, SVCB},
};

use crate::{DomainName, Error, ErrorKind, IpSet, ResolveStrategy, Result};

#[cfg(feature = "async-proxy")]
use crate::LocalBoxFuture;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Ptr,
    Https,
    Svcb,
}
impl DnsRecordType {
    fn hickory(self) -> RecordType {
        match self {
            Self::A => RecordType::A,
            Self::Aaaa => RecordType::AAAA,
            Self::Ptr => RecordType::PTR,
            Self::Https => RecordType::HTTPS,
            Self::Svcb => RecordType::SVCB,
        }
    }
}

/// A pure-Rust, protocol-neutral representation of an RFC 9460 service
/// binding.  `target == None` represents the root name (`.`), which is a
/// meaningful value in SVCB alias/service mode.  Keeping this model outside
/// Hickory lets the resolver, FakeIP policy and persistent configuration
/// remain independent of the wire codec while preserving unknown parameters.
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

impl DnsServiceParam {
    fn key(&self) -> u16 {
        match self {
            Self::Mandatory(_) => 0,
            Self::Alpn(_) => 1,
            Self::NoDefaultAlpn => 2,
            Self::Port(_) => 3,
            Self::Ipv4Hint(_) => 4,
            Self::Ech(_) => 5,
            Self::Ipv6Hint(_) => 6,
            Self::Unknown { key, .. } => *key,
        }
    }

    fn from_hickory(key: SvcParamKey, value: &SvcParamValue) -> Result<Self> {
        let parameter = match (key, value) {
            (SvcParamKey::Mandatory, SvcParamValue::Mandatory(Mandatory(keys))) => {
                Self::Mandatory(keys.iter().copied().map(u16::from).collect())
            }
            (SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(values))) => Self::Alpn(values.clone()),
            (SvcParamKey::NoDefaultAlpn, SvcParamValue::NoDefaultAlpn) => Self::NoDefaultAlpn,
            (SvcParamKey::Port, SvcParamValue::Port(port)) => Self::Port(*port),
            (SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(IpHint(values))) => {
                Self::Ipv4Hint(values.iter().map(|address| address.0).collect())
            }
            (SvcParamKey::EchConfigList, SvcParamValue::EchConfigList(EchConfigList(values))) => {
                Self::Ech(values.clone())
            }
            (SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(IpHint(values))) => {
                Self::Ipv6Hint(values.iter().map(|address| address.0).collect())
            }
            (
                key @ (SvcParamKey::Key(_) | SvcParamKey::Key65535 | SvcParamKey::Unknown(_)),
                SvcParamValue::Unknown(Unknown(values)),
            ) => Self::Unknown {
                key: key.into(),
                value: values.clone(),
            },
            (key, value) => {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    format!(
                        "SVCB parameter {} has incompatible value {value:?}",
                        u16::from(key)
                    ),
                ));
            }
        };
        Ok(parameter)
    }

    fn to_hickory(&self) -> Result<(SvcParamKey, SvcParamValue)> {
        Ok(match self {
            Self::Mandatory(keys) => (
                SvcParamKey::Mandatory,
                SvcParamValue::Mandatory(Mandatory(
                    keys.iter().copied().map(SvcParamKey::from).collect(),
                )),
            ),
            Self::Alpn(values) => (SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(values.clone()))),
            Self::NoDefaultAlpn => (SvcParamKey::NoDefaultAlpn, SvcParamValue::NoDefaultAlpn),
            Self::Port(port) => (SvcParamKey::Port, SvcParamValue::Port(*port)),
            Self::Ipv4Hint(values) => (
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(values.iter().copied().map(A).collect())),
            ),
            Self::Ech(values) => (
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(values.clone())),
            ),
            Self::Ipv6Hint(values) => (
                SvcParamKey::Ipv6Hint,
                SvcParamValue::Ipv6Hint(IpHint(values.iter().copied().map(AAAA).collect())),
            ),
            Self::Unknown { key, value } => {
                let key = SvcParamKey::from(*key);
                if matches!(
                    key,
                    SvcParamKey::Mandatory
                        | SvcParamKey::Alpn
                        | SvcParamKey::NoDefaultAlpn
                        | SvcParamKey::Port
                        | SvcParamKey::Ipv4Hint
                        | SvcParamKey::EchConfigList
                        | SvcParamKey::Ipv6Hint
                        | SvcParamKey::Key65535
                ) {
                    return Err(Error::invalid(
                        "SVCB unknown parameter key must not be a defined key",
                    ));
                }
                (key, SvcParamValue::Unknown(Unknown(value.clone())))
            }
        })
    }
}

fn service_binding_from_hickory(value: &SVCB) -> Result<DnsServiceBinding> {
    let target = value.target_name.to_ascii();
    let target = if target == "." {
        None
    } else {
        Some(DomainName::new(target.trim_end_matches('.'))?)
    };
    let params = value
        .svc_params
        .iter()
        .map(|(key, value)| DnsServiceParam::from_hickory(*key, value))
        .collect::<Result<Vec<_>>>()?;
    Ok(DnsServiceBinding {
        priority: value.svc_priority,
        target,
        params,
    })
}

fn service_binding_to_hickory(binding: &DnsServiceBinding) -> Result<SVCB> {
    let target = match &binding.target {
        Some(target) => Name::from_utf8(format!("{}.", target))
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?,
        None => Name::from_utf8(".")
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?,
    };
    let mut parameters = binding.params.clone();
    parameters.sort_by_key(DnsServiceParam::key);
    let mut params = parameters
        .iter()
        .map(DnsServiceParam::to_hickory)
        .collect::<Result<Vec<_>>>()?;
    params.sort_by_key(|(key, _)| u16::from(*key));
    if params
        .windows(2)
        .any(|window| u16::from(window[0].0) == u16::from(window[1].0))
    {
        return Err(Error::invalid("SVCB parameter keys must be unique"));
    }
    Ok(SVCB::new(binding.priority, target, params))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponse {
    pub addresses: IpSet,
    pub ptr_names: Vec<DomainName>,
    pub service_bindings: Vec<DnsServiceBinding>,
    pub minimum_ttl: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPolicy {
    Upstream,
    Empty,
    Block,
}

#[derive(Clone)]
pub struct DnsCache {
    entries: Arc<Mutex<LruMap<(DomainName, DnsRecordType), CachedDnsResponse>>>,
    raw_entries: Arc<Mutex<LruMap<(DomainName, u16), CachedDnsPacket>>>,
}

#[derive(Clone)]
struct CachedDnsResponse {
    response: DnsResponse,
    expires_at: std::time::Instant,
}

#[derive(Clone)]
struct CachedDnsPacket {
    packet: Vec<u8>,
    expires_at: std::time::Instant,
}

struct LruMap<K, V> {
    map: HashMap<K, V>,
    order: VecDeque<K>,
    capacity: usize,
}

impl<K: Eq + std::hash::Hash + Clone, V> LruMap<K, V> {
    fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn touch(&mut self, key: &K) {
        if let Some(position) = self.order.iter().position(|current| current == key) {
            self.order.remove(position);
        }
        self.order.push_front(key.clone());
    }

    fn get_cloned(&mut self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        let value = self.map.get(key)?.clone();
        self.touch(key);
        Some(value)
    }

    fn insert(&mut self, key: K, value: V) {
        if self.map.contains_key(&key) {
            self.map.insert(key.clone(), value);
            self.touch(&key);
            return;
        }
        self.map.insert(key.clone(), value);
        self.order.push_front(key);
        while self.map.len() > self.capacity {
            let Some(oldest) = self.order.pop_back() else {
                break;
            };
            self.map.remove(&oldest);
        }
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        let value = self.map.remove(key);
        if value.is_some()
            && let Some(position) = self.order.iter().position(|current| current == key)
        {
            self.order.remove(position);
        }
        value
    }

    fn retain(&mut self, mut keep: impl FnMut(&V) -> bool) {
        self.map.retain(|_, value| keep(value));
        self.order.retain(|key| self.map.contains_key(key));
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Result<Self> {
        if max_entries == 0 {
            return Err(Error::invalid("DNS cache capacity must be non-zero"));
        }
        Ok(Self {
            entries: Arc::new(Mutex::new(LruMap::new(max_entries))),
            raw_entries: Arc::new(Mutex::new(LruMap::new(max_entries))),
        })
    }

    pub fn get(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
    ) -> Result<Option<DnsResponse>> {
        let key = (domain.clone(), record_type);
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS cache lock poisoned"))?;
        let Some(entry) = entries.get_cloned(&key) else {
            return Ok(None);
        };
        if entry.expires_at <= std::time::Instant::now() {
            entries.remove(&key);
            return Ok(None);
        }
        Ok(Some(entry.response.clone()))
    }

    pub fn insert(
        &self,
        domain: DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> Result<()> {
        let ttl = response.minimum_ttl.unwrap_or(300);
        if ttl <= 1 {
            return Ok(());
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS cache lock poisoned"))?;
        let now = std::time::Instant::now();
        entries.retain(|entry| entry.expires_at > now);
        entries.insert(
            (domain, record_type),
            CachedDnsResponse {
                response,
                expires_at: now + Duration::from_secs(u64::from(ttl)),
            },
        );
        Ok(())
    }

    /// Return a cached typed response even after its TTL, matching Go's
    /// `LoadOptimistically`. The boolean reports whether the entry is stale.
    pub fn get_optimistic(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
    ) -> Result<Option<(DnsResponse, bool)>> {
        let key = (domain.clone(), record_type);
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS cache lock poisoned"))?;
        let Some(entry) = entries.get_cloned(&key) else {
            return Ok(None);
        };
        Ok(Some((
            entry.response,
            entry.expires_at <= std::time::Instant::now(),
        )))
    }

    /// Return a raw DNS response while retaining stale entries for a
    /// background refresh. The cache key intentionally excludes the DNS
    /// transaction ID, just like Go's `CacheKeyFromQuestion`.
    pub(crate) fn get_raw_optimistic(
        &self,
        domain: &DomainName,
        record_type: u16,
    ) -> Result<Option<(Vec<u8>, bool)>> {
        let key = (domain.clone(), record_type);
        let mut entries = self
            .raw_entries
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS raw cache lock poisoned"))?;
        let Some(entry) = entries.get_cloned(&key) else {
            return Ok(None);
        };
        Ok(Some((
            entry.packet,
            entry.expires_at <= std::time::Instant::now(),
        )))
    }

    pub(crate) fn insert_raw(
        &self,
        domain: DomainName,
        record_type: u16,
        packet: Vec<u8>,
    ) -> Result<()> {
        let message = Message::from_vec(&packet)
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
        let ttl = message
            .answers
            .first()
            .map(|record| record.ttl)
            .unwrap_or(300);
        if ttl <= 1 {
            return Ok(());
        }
        let now = std::time::Instant::now();
        let mut entries = self
            .raw_entries
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS raw cache lock poisoned"))?;
        entries.retain(|entry| entry.expires_at > now);
        entries.insert(
            (domain, record_type),
            CachedDnsPacket {
                packet,
                expires_at: now + Duration::from_secs(u64::from(ttl)),
            },
        );
        Ok(())
    }

    pub fn remove(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<bool> {
        self.entries
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS cache lock poisoned"))
            .map(|mut entries| entries.remove(&(domain.clone(), record_type)).is_some())
    }

    pub fn len(&self) -> Result<usize> {
        self.entries
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS cache lock poisoned"))
            .map(|entries| entries.len())
    }

    pub fn is_empty(&self) -> Result<bool> {
        self.entries
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS cache lock poisoned"))
            .map(|entries| entries.len() == 0)
    }
}

pub struct CachingDnsHandler<H> {
    pub upstream: H,
    pub cache: DnsCache,
}

/// Small policy boundary kept outside the resolver transport.  This lets the
/// Router choose direct/proxy/drop DNS behavior without teaching UDP or DoH
/// codecs about route policy.
pub struct PolicyDnsHandler<H> {
    pub upstream: H,
    pub policy: DnsPolicy,
}

impl<H: DnsHandler> DnsHandler for PolicyDnsHandler<H> {
    fn resolve(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        match self.policy {
            DnsPolicy::Upstream => self.upstream.resolve(domain, record_type),
            DnsPolicy::Empty => Ok(DnsResponse {
                addresses: IpSet::default(),
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(0),
            }),
            DnsPolicy::Block => Err(Error::new(
                ErrorKind::Closed,
                "DNS query blocked by route policy",
            )),
        }
    }
}

impl<H: DnsHandler> DnsHandler for CachingDnsHandler<H> {
    fn resolve(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        if let Some(response) = self.cache.get(domain, record_type)? {
            return Ok(response);
        }
        let response = self.upstream.resolve(domain, record_type)?;
        self.cache
            .insert(domain.clone(), record_type, response.clone())?;
        Ok(response)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub id: u16,
    pub domain: DomainName,
    pub record_type: DnsRecordType,
}

pub fn encode_query(id: u16, domain: &DomainName, record_type: DnsRecordType) -> Result<Vec<u8>> {
    let name = Name::from_utf8(format!("{}.", domain))
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let mut message = Message::new(
        id,
        hickory_proto::op::MessageType::Query,
        hickory_proto::op::OpCode::Query,
    );
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, record_type.hickory()));
    let mut edns = Edns::new();
    edns.set_max_payload(8192);
    message.set_edns(edns);
    message
        .to_vec()
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
}

/// Encode a DNS query for a QTYPE that is intentionally outside the typed
/// resolver model. This is primarily useful to packet-forwarding callers and
/// tests; address resolution should continue to use [`encode_query`].
pub fn encode_raw_query(id: u16, domain: &DomainName, record_type: u16) -> Result<Vec<u8>> {
    let name = Name::from_utf8(format!("{}.", domain))
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let mut message = Message::new(
        id,
        hickory_proto::op::MessageType::Query,
        hickory_proto::op::OpCode::Query,
    );
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, RecordType::from(record_type)));
    let mut edns = Edns::new();
    edns.set_max_payload(8192);
    message.set_edns(edns);
    message
        .to_vec()
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
}

pub fn decode_response(
    packet: &[u8],
    expected_id: u16,
    record_type: DnsRecordType,
) -> Result<DnsResponse> {
    let message = Message::from_vec(packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    if message.metadata.id != expected_id {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DNS transaction id mismatch",
        ));
    }
    let mut addresses = IpSet::default();
    let mut ptr_names = Vec::new();
    let mut service_bindings = Vec::new();
    let mut minimum_ttl = None;
    for record in &message.answers {
        let ttl = record.ttl;
        minimum_ttl = Some(minimum_ttl.map_or(ttl, |current: u32| current.min(ttl)));
        match (record_type, &record.data) {
            (DnsRecordType::A, RData::A(address)) => addresses.v4.push(address.0),
            (DnsRecordType::Aaaa, RData::AAAA(address)) => addresses.v6.push(address.0),
            (DnsRecordType::Ptr, RData::PTR(name)) => {
                ptr_names.push(DomainName::new(name.to_ascii().trim_end_matches('.'))?)
            }
            (DnsRecordType::Https, RData::HTTPS(binding)) => {
                service_bindings.push(service_binding_from_hickory(&binding.0)?)
            }
            (DnsRecordType::Svcb, RData::SVCB(binding)) => {
                service_bindings.push(service_binding_from_hickory(binding)?)
            }
            _ => {}
        }
    }
    Ok(DnsResponse {
        addresses,
        ptr_names,
        service_bindings,
        minimum_ttl,
    })
}

pub fn decode_query(packet: &[u8]) -> Result<DnsQuestion> {
    let message = Message::from_vec(packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let query = message
        .queries
        .first()
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "DNS request has no question"))?;
    let domain = DomainName::new(query.name().to_ascii().trim_end_matches('.'))?;
    let record_type = match query.query_type() {
        RecordType::A => DnsRecordType::A,
        RecordType::AAAA => DnsRecordType::Aaaa,
        RecordType::PTR => DnsRecordType::Ptr,
        RecordType::HTTPS => DnsRecordType::Https,
        RecordType::SVCB => DnsRecordType::Svcb,
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "DNS server currently supports only A, AAAA, PTR, HTTPS and SVCB",
            ));
        }
    };
    Ok(DnsQuestion {
        id: message.metadata.id,
        domain,
        record_type,
    })
}

/// Decode the cache key used by the raw resolver path. Unlike [`decode_query`]
/// this accepts every DNS QTYPE, because Go caches and forwards records that
/// the address-oriented API does not model.
pub fn decode_raw_query_key(packet: &[u8]) -> Result<(DomainName, u16)> {
    let message = Message::from_vec(packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let query = message
        .queries
        .first()
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "DNS request has no question"))?;
    Ok((
        DomainName::new(query.name().to_ascii().trim_end_matches('.'))?,
        u16::from(query.query_type()),
    ))
}

/// Rewrite a DNS transaction ID after serving a response from the raw cache.
pub fn rewrite_dns_transaction_id(mut packet: Vec<u8>, id: u16) -> Result<Vec<u8>> {
    if packet.len() < 2 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DNS response is shorter than its transaction id",
        ));
    }
    packet[..2].copy_from_slice(&id.to_be_bytes());
    Ok(packet)
}

/// Rebuild the caller-visible question and transaction ID on a cached DNS
/// response. Go's `dns.Msg.SetReply` does this before returning a raw cached
/// message; replacing only the ID would leak the first request's question
/// flags or name encoding to later callers.
pub fn rewrite_dns_response_for_query(response: Vec<u8>, query: &[u8]) -> Result<Vec<u8>> {
    let mut response_message = Message::from_vec(&response)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let query_message = Message::from_vec(query)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    if query_message.queries.is_empty() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DNS request has no question",
        ));
    }
    response_message.metadata.id = query_message.metadata.id;
    response_message.queries = query_message.queries;
    response_message
        .to_vec()
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
}

/// Apply the RFC 1035 UDP size limit to a response. Go keeps the complete
/// answer for TCP/DoH but strips sections and sets TC for an oversized UDP
/// response, allowing the client to retry over TCP.
pub fn truncate_dns_response(query: &[u8], response: &[u8]) -> Result<Vec<u8>> {
    let query_message = Message::from_vec(query)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let mut response_message = Message::from_vec(response)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let client_buffer_size = query_message
        .edns
        .as_ref()
        .map(|edns| usize::from(edns.max_payload()))
        .unwrap_or(512)
        .max(512);
    if response.len() <= client_buffer_size {
        return Ok(response.to_vec());
    }
    response_message.metadata.truncation = true;
    response_message.answers.clear();
    response_message.authorities.clear();
    response_message.additionals.clear();
    response_message.signature = None;
    response_message
        .to_vec()
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
}

/// Validate a DNS query before handing it to a raw transport.
///
/// The typed resolver API intentionally models only records that yuhaiin
/// interprets locally.  Transport-facing callers still need to forward every
/// valid DNS question (for example MX, TXT, CNAME, NS and DNSSEC records), so
/// this helper validates the wire message without narrowing its QTYPE.
pub fn validate_query_packet(packet: &[u8]) -> Result<()> {
    let message = Message::from_vec(packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    if message.queries.is_empty() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DNS request has no question",
        ));
    }
    Ok(())
}

/// Check that a raw upstream response belongs to the original DNS query.
pub fn validate_response_packet(query: &[u8], response: &[u8]) -> Result<()> {
    let query = Message::from_vec(query)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let response_message = Message::from_vec(response)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    if response_message.metadata.id != query.metadata.id {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DNS transaction id mismatch",
        ));
    }
    if response_message.metadata.message_type != MessageType::Response {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DNS upstream returned a query instead of a response",
        ));
    }
    Ok(())
}

pub fn response_is_truncated(packet: &[u8]) -> Result<bool> {
    let message = Message::from_vec(packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    Ok(message.metadata.truncation)
}

/// Build an empty response for any valid DNS QTYPE while retaining every
/// question from the request. Policy layers use this instead of the typed
/// encoder when they intentionally block a raw record query.
pub fn encode_empty_response(packet: &[u8]) -> Result<Vec<u8>> {
    let message = Message::from_vec(packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    if message.queries.is_empty() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "DNS request has no question",
        ));
    }
    let mut response = Message::response(message.metadata.id, message.metadata.op_code);
    for query in &message.queries {
        response.add_query(query.clone());
    }
    response
        .to_vec()
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
}

pub fn encode_response(packet: &[u8], answer: &DnsResponse) -> Result<Vec<u8>> {
    let message = Message::from_vec(packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let query = message
        .queries
        .first()
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "DNS request has no question"))?;
    let record_type = match query.query_type() {
        RecordType::A => DnsRecordType::A,
        RecordType::AAAA => DnsRecordType::Aaaa,
        RecordType::PTR => DnsRecordType::Ptr,
        RecordType::HTTPS => DnsRecordType::Https,
        RecordType::SVCB => DnsRecordType::Svcb,
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "DNS server currently supports only A, AAAA, PTR, HTTPS and SVCB",
            ));
        }
    };
    let mut response = Message::response(message.metadata.id, message.metadata.op_code);
    response.add_query(query.clone());
    for address in answer.addresses.iter() {
        let rdata = match address {
            IpAddr::V4(address) if record_type == DnsRecordType::A => RData::A(address.into()),
            IpAddr::V6(address) if record_type == DnsRecordType::Aaaa => {
                RData::AAAA(address.into())
            }
            _ => continue,
        };
        response.add_answer(hickory_proto::rr::Record::from_rdata(
            query.name().clone(),
            answer.minimum_ttl.unwrap_or(60),
            rdata,
        ));
    }
    if record_type == DnsRecordType::Ptr {
        for domain in &answer.ptr_names {
            let name = Name::from_utf8(format!("{}.", domain))
                .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
            response.add_answer(hickory_proto::rr::Record::from_rdata(
                query.name().clone(),
                answer.minimum_ttl.unwrap_or(60),
                RData::PTR(PTR(name)),
            ));
        }
    }
    if matches!(record_type, DnsRecordType::Https | DnsRecordType::Svcb) {
        for binding in &answer.service_bindings {
            let binding = service_binding_to_hickory(binding)?;
            let rdata = if record_type == DnsRecordType::Https {
                RData::HTTPS(HTTPS(binding))
            } else {
                RData::SVCB(binding)
            };
            response.add_answer(hickory_proto::rr::Record::from_rdata(
                query.name().clone(),
                answer.minimum_ttl.unwrap_or(60),
                rdata,
            ));
        }
    }
    response
        .to_vec()
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
}

#[derive(Debug, Clone)]
pub struct UdpDnsClient {
    pub server: SocketAddr,
    pub timeout: Duration,
    pub max_packet_size: usize,
}

pub trait DohTransport: Send + Sync {
    fn post_dns_message(&self, endpoint: &str, body: &[u8], timeout: Duration) -> Result<Vec<u8>>;
}

pub struct DohClient<T> {
    pub endpoint: String,
    pub timeout: Duration,
    pub transport: T,
}

impl<T: DohTransport> DohClient<T> {
    pub fn query_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        validate_query_packet(packet)?;
        let response = self
            .transport
            .post_dns_message(&self.endpoint, packet, self.timeout)?;
        validate_response_packet(packet, &response)?;
        Ok(response)
    }

    pub fn query(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        let id = next_transaction_id();
        let request = encode_query(id, domain, record_type)?;
        let response = self.query_packet(&request)?;
        decode_response(&response, id, record_type)
    }
}

impl UdpDnsClient {
    pub fn query_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        validate_query_packet(packet)?;
        let socket = if self.server.is_ipv4() {
            UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))
        }
        .map_err(|error| Error::new(ErrorKind::Io, format!("bind DNS UDP socket: {error}")))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
        socket
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
        socket
            .send_to(packet, self.server)
            .map_err(|error| Error::new(ErrorKind::Io, format!("send DNS query: {error}")))?;
        let mut response = vec![0; self.max_packet_size.max(512)];
        let size = socket.recv(&mut response).map_err(|error| {
            Error::new(ErrorKind::Timeout, format!("receive DNS response: {error}"))
        })?;
        validate_response_packet(packet, &response[..size])?;
        Ok(response[..size].to_vec())
    }

    pub fn query(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        let id = next_transaction_id();
        let request = encode_query(id, domain, record_type)?;
        let response = self.query_packet(&request)?;
        decode_response(&response, id, record_type)
    }

    pub fn resolve(&self, domain: &DomainName, strategy: ResolveStrategy) -> Result<IpSet> {
        let mut result = IpSet::default();
        match strategy {
            ResolveStrategy::OnlyIpv4 => {
                result.v4 = self.query(domain, DnsRecordType::A)?.addresses.v4;
            }
            ResolveStrategy::OnlyIpv6 => {
                result.v6 = self.query(domain, DnsRecordType::Aaaa)?.addresses.v6;
            }
            ResolveStrategy::PreferIpv4 | ResolveStrategy::Default => {
                let v4 = self.query(domain, DnsRecordType::A)?.addresses.v4;
                let v6 = self.query(domain, DnsRecordType::Aaaa)?.addresses.v6;
                result.v4 = v4;
                result.v6 = v6;
            }
            ResolveStrategy::PreferIpv6 => {
                let v6 = self.query(domain, DnsRecordType::Aaaa)?.addresses.v6;
                let v4 = self.query(domain, DnsRecordType::A)?.addresses.v4;
                result.v6 = v6;
                result.v4 = v4;
            }
        }
        Ok(result)
    }
}

pub trait DnsHandler: Send + Sync {
    fn resolve(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse>;
}

#[cfg(feature = "async-proxy")]
pub trait AsyncDnsHandler {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>>;
}

#[cfg(feature = "async-proxy")]
pub struct AsyncPolicyDnsHandler<H> {
    pub upstream: H,
    pub policy: DnsPolicy,
}

#[cfg(feature = "async-proxy")]
impl<H: AsyncDnsHandler> AsyncDnsHandler for AsyncPolicyDnsHandler<H> {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        match self.policy {
            DnsPolicy::Upstream => self.upstream.answer(packet),
            DnsPolicy::Block => Box::pin(async {
                Err(Error::new(
                    ErrorKind::Closed,
                    "DNS query blocked by route policy",
                ))
            }),
            DnsPolicy::Empty => Box::pin(async move { encode_empty_response(packet) }),
        }
    }
}

/// Decode one DNS query, invoke the injected resolver, and encode a response.
///
/// Keeping this operation independent from a socket makes it usable by both
/// the UDP server and the TUN DNS-hijack path.  The resolver remains a
/// synchronous boundary here; callers that perform network I/O should invoke
/// it on a blocking pool rather than inside the packet poll loop.
pub fn answer_query<H: DnsHandler + ?Sized>(packet: &[u8], handler: &H) -> Result<Vec<u8>> {
    let question = decode_query(packet)?;
    let answer = handler.resolve(&question.domain, question.record_type)?;
    encode_response(packet, &answer)
}

pub struct UdpDnsServer<H> {
    pub socket: UdpSocket,
    pub handler: H,
    pub max_packet_size: usize,
}

impl<H: DnsHandler> UdpDnsServer<H> {
    pub fn bind(address: SocketAddr, handler: H, max_packet_size: usize) -> Result<Self> {
        let socket = UdpSocket::bind(address)
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind DNS UDP server: {error}")))?;
        Ok(Self {
            socket,
            handler,
            max_packet_size: max_packet_size.max(512),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.socket
            .set_read_timeout(timeout)
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
    }

    pub fn serve_once(&self) -> Result<usize> {
        let mut request = vec![0; self.max_packet_size.max(512)];
        let (size, peer) = self.socket.recv_from(&mut request).map_err(|error| {
            Error::new(ErrorKind::Timeout, format!("receive DNS request: {error}"))
        })?;
        let packet = answer_query(&request[..size], &self.handler)?;
        let packet = truncate_dns_response(&request[..size], &packet)?;
        let sent = self
            .socket
            .send_to(&packet, peer)
            .map_err(|error| Error::new(ErrorKind::Io, format!("send DNS response: {error}")))?;
        Ok(sent)
    }
}

fn next_transaction_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_round_trip_preserves_id_and_addresses() {
        let domain = DomainName::new("example.com").unwrap();
        let query = encode_query(42, &domain, DnsRecordType::A).unwrap();
        let request = Message::from_vec(&query).unwrap();
        let mut response = Message::response(request.metadata.id, request.metadata.op_code);
        response.add_query(request.queries[0].clone());
        response.add_answer(hickory_proto::rr::Record::from_rdata(
            request.queries[0].name().clone(),
            30,
            RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
        ));
        let decoded = decode_response(&response.to_vec().unwrap(), 42, DnsRecordType::A).unwrap();
        assert_eq!(decoded.addresses.v4, vec![Ipv4Addr::new(192, 0, 2, 1)]);
        assert_eq!(decoded.minimum_ttl, Some(30));
    }

    #[test]
    fn ptr_query_and_response_round_trip_preserves_names_and_ttl() {
        let reverse = DomainName::new("1.0.18.198.in-addr.arpa").unwrap();
        let packet = encode_query(43, &reverse, DnsRecordType::Ptr).unwrap();
        let question = decode_query(&packet).unwrap();
        assert_eq!(question.id, 43);
        assert_eq!(question.domain, reverse);
        assert_eq!(question.record_type, DnsRecordType::Ptr);

        let response = encode_response(
            &packet,
            &DnsResponse {
                addresses: IpSet::default(),
                ptr_names: vec![DomainName::new("host.example.com").unwrap()],
                service_bindings: Vec::new(),
                minimum_ttl: Some(17),
            },
        )
        .unwrap();
        let decoded = decode_response(&response, 43, DnsRecordType::Ptr).unwrap();
        assert_eq!(
            decoded.ptr_names,
            vec![DomainName::new("host.example.com").unwrap()]
        );
        assert_eq!(decoded.minimum_ttl, Some(17));
    }

    #[test]
    fn https_and_svcb_round_trip_preserves_targets_hints_and_unknown_params() {
        let binding = DnsServiceBinding {
            priority: 1,
            target: Some(DomainName::new("svc.example.com").unwrap()),
            params: vec![
                DnsServiceParam::Ipv6Hint(vec!["2001:db8::7".parse().unwrap()]),
                DnsServiceParam::Unknown {
                    key: 65_400,
                    value: vec![0xde, 0xad, 0xbe, 0xef],
                },
                DnsServiceParam::Alpn(vec!["h2".to_owned(), "http/1.1".to_owned()]),
                DnsServiceParam::Port(8443),
                DnsServiceParam::Ipv4Hint(vec![Ipv4Addr::new(192, 0, 2, 7)]),
                DnsServiceParam::Ech(vec![1, 2, 3, 4]),
                DnsServiceParam::Mandatory(vec![1, 3, 4]),
                DnsServiceParam::NoDefaultAlpn,
            ],
        };
        let mut expected = binding.clone();
        expected.params.sort_by_key(DnsServiceParam::key);
        let alias = DnsServiceBinding {
            priority: 0,
            target: None,
            params: Vec::new(),
        };
        for (id, record_type) in [(44, DnsRecordType::Https), (45, DnsRecordType::Svcb)] {
            let domain = DomainName::new("example.com").unwrap();
            let query = encode_query(id, &domain, record_type).unwrap();
            let response = encode_response(
                &query,
                &DnsResponse {
                    addresses: IpSet::default(),
                    ptr_names: Vec::new(),
                    service_bindings: vec![binding.clone(), alias.clone()],
                    minimum_ttl: Some(19),
                },
            )
            .unwrap();
            let decoded = decode_response(&response, id, record_type).unwrap();
            assert_eq!(
                decoded.service_bindings,
                vec![expected.clone(), alias.clone()]
            );
            assert_eq!(decoded.minimum_ttl, Some(19));
        }
    }

    #[test]
    fn malformed_packet_is_rejected() {
        assert!(decode_response(&[0, 1, 2], 1, DnsRecordType::A).is_err());
    }

    #[test]
    fn bounded_random_dns_wire_never_panics() {
        let mut state = 0x243f_6a88_u32;
        for length in 0..2048 {
            let mut packet = vec![0u8; length];
            for byte in &mut packet {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            let _ = decode_query(&packet);
            let _ = decode_response(&packet, 7, DnsRecordType::A);
            let _ = decode_response(&packet, 7, DnsRecordType::Aaaa);
            let _ = decode_response(&packet, 7, DnsRecordType::Https);
            let _ = decode_response(&packet, 7, DnsRecordType::Svcb);
            let _ = answer_query(&packet, &RandomWireHandler);
        }
    }

    struct RandomWireHandler;

    impl DnsHandler for RandomWireHandler {
        fn resolve(
            &self,
            _domain: &DomainName,
            _record_type: DnsRecordType,
        ) -> Result<DnsResponse> {
            Ok(DnsResponse {
                addresses: IpSet::default(),
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(1),
            })
        }
    }

    struct EchoTransport;

    impl DohTransport for EchoTransport {
        fn post_dns_message(
            &self,
            _endpoint: &str,
            body: &[u8],
            _timeout: Duration,
        ) -> Result<Vec<u8>> {
            let request = Message::from_vec(body)
                .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
            let mut response = Message::response(request.metadata.id, request.metadata.op_code);
            response.add_query(request.queries[0].clone());
            response.add_answer(hickory_proto::rr::Record::from_rdata(
                request.queries[0].name().clone(),
                15,
                RData::A(Ipv4Addr::new(198, 51, 100, 1).into()),
            ));
            response
                .to_vec()
                .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
        }
    }

    #[test]
    fn doh_client_uses_transport_boundary_and_dns_codec() {
        let client = DohClient {
            endpoint: "https://resolver.example/dns-query".to_owned(),
            timeout: Duration::from_secs(1),
            transport: EchoTransport,
        };
        let result = client
            .query(&DomainName::new("example.com").unwrap(), DnsRecordType::A)
            .unwrap();
        assert_eq!(result.addresses.v4, vec![Ipv4Addr::new(198, 51, 100, 1)]);
    }

    struct CountingResolver {
        calls: std::sync::atomic::AtomicUsize,
    }

    impl DnsHandler for CountingResolver {
        fn resolve(
            &self,
            _domain: &DomainName,
            _record_type: DnsRecordType,
        ) -> Result<DnsResponse> {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(DnsResponse {
                addresses: IpSet {
                    v4: vec![Ipv4Addr::new(203, 0, 113, 8)],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(60),
            })
        }
    }

    #[test]
    fn dns_cache_reuses_entries_and_evicts_by_capacity() {
        let cache = DnsCache::new(1).unwrap();
        let resolver = CountingResolver {
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let handler = CachingDnsHandler {
            upstream: resolver,
            cache: cache.clone(),
        };
        let first = DomainName::new("first.example").unwrap();
        let second = DomainName::new("second.example").unwrap();
        handler.resolve(&first, DnsRecordType::A).unwrap();
        handler.resolve(&first, DnsRecordType::A).unwrap();
        assert_eq!(
            handler
                .upstream
                .calls
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        handler.resolve(&second, DnsRecordType::A).unwrap();
        assert_eq!(cache.len().unwrap(), 1);
        assert!(cache.get(&first, DnsRecordType::A).unwrap().is_none());
    }

    #[test]
    fn dns_cache_promotes_hits_before_evicting_the_least_recent_entry() {
        let cache = DnsCache::new(2).unwrap();
        let response = |address| DnsResponse {
            addresses: IpSet {
                v4: vec![address],
                v6: Vec::new(),
            },
            ptr_names: Vec::new(),
            service_bindings: Vec::new(),
            minimum_ttl: Some(60),
        };
        let first = DomainName::new("first.example").unwrap();
        let second = DomainName::new("second.example").unwrap();
        let third = DomainName::new("third.example").unwrap();
        cache
            .insert(
                first.clone(),
                DnsRecordType::A,
                response(Ipv4Addr::new(192, 0, 2, 1)),
            )
            .unwrap();
        cache
            .insert(
                second.clone(),
                DnsRecordType::A,
                response(Ipv4Addr::new(192, 0, 2, 2)),
            )
            .unwrap();

        // A hit must move `first` to the MRU position. Inserting `third`
        // therefore evicts `second`, not the entry that was inserted first.
        assert!(cache.get(&first, DnsRecordType::A).unwrap().is_some());
        cache
            .insert(
                third.clone(),
                DnsRecordType::A,
                response(Ipv4Addr::new(192, 0, 2, 3)),
            )
            .unwrap();
        assert!(cache.get(&first, DnsRecordType::A).unwrap().is_some());
        assert!(cache.get(&second, DnsRecordType::A).unwrap().is_none());
        assert!(cache.get(&third, DnsRecordType::A).unwrap().is_some());
    }

    #[test]
    fn raw_dns_cache_has_the_same_lru_promotion_behavior() {
        let cache = DnsCache::new(2).unwrap();
        let packet = |id, domain: &DomainName, address| {
            let query = encode_query(id, domain, DnsRecordType::A).unwrap();
            encode_response(
                &query,
                &DnsResponse {
                    addresses: IpSet {
                        v4: vec![address],
                        v6: Vec::new(),
                    },
                    ptr_names: Vec::new(),
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(60),
                },
            )
            .unwrap()
        };
        let first = DomainName::new("first.example").unwrap();
        let second = DomainName::new("second.example").unwrap();
        let third = DomainName::new("third.example").unwrap();
        cache
            .insert_raw(
                first.clone(),
                1,
                packet(1, &first, Ipv4Addr::new(192, 0, 2, 1)),
            )
            .unwrap();
        cache
            .insert_raw(
                second.clone(),
                1,
                packet(2, &second, Ipv4Addr::new(192, 0, 2, 2)),
            )
            .unwrap();
        assert!(cache.get_raw_optimistic(&first, 1).unwrap().is_some());
        cache
            .insert_raw(
                third.clone(),
                1,
                packet(3, &third, Ipv4Addr::new(192, 0, 2, 3)),
            )
            .unwrap();
        assert!(cache.get_raw_optimistic(&first, 1).unwrap().is_some());
        assert!(cache.get_raw_optimistic(&second, 1).unwrap().is_none());
        assert!(cache.get_raw_optimistic(&third, 1).unwrap().is_some());
    }

    #[test]
    fn oversized_udp_dns_response_sets_truncation_without_returning_answers() {
        // A legacy client without EDNS advertises the RFC 1035 512-byte
        // limit. `encode_query` intentionally adds EDNS(0), so construct the
        // legacy form explicitly for this truncation test.
        let mut query_message =
            Message::new(0x1234, MessageType::Query, hickory_proto::op::OpCode::Query);
        query_message.add_query(Query::query(
            Name::from_utf8("large.example.").unwrap(),
            RecordType::A,
        ));
        let query = query_message.to_vec().unwrap();
        let answer = DnsResponse {
            addresses: IpSet {
                v4: (0..128)
                    .map(|index| Ipv4Addr::new(192, 0, 2, (index % 250) as u8))
                    .collect(),
                v6: Vec::new(),
            },
            ptr_names: Vec::new(),
            service_bindings: Vec::new(),
            minimum_ttl: Some(60),
        };
        let response = encode_response(&query, &answer).unwrap();
        assert!(response.len() > 512);
        let truncated = truncate_dns_response(&query, &response).unwrap();
        assert!(response_is_truncated(&truncated).unwrap());
        assert!(Message::from_vec(&truncated).unwrap().answers.is_empty());
    }

    #[test]
    fn zero_capacity_dns_cache_is_rejected() {
        assert!(DnsCache::new(0).is_err());
    }

    struct StaticHandler;
    impl DnsHandler for StaticHandler {
        fn resolve(
            &self,
            _domain: &DomainName,
            _record_type: DnsRecordType,
        ) -> Result<DnsResponse> {
            Ok(DnsResponse {
                addresses: IpSet {
                    v4: vec![Ipv4Addr::new(203, 0, 113, 7)],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            })
        }
    }

    #[test]
    fn udp_dns_server_answers_local_client_and_policy_can_block() {
        let server =
            UdpDnsServer::bind("127.0.0.1:0".parse().unwrap(), StaticHandler, 128).unwrap();
        let address = server.local_addr().unwrap();
        let server_thread = std::thread::spawn(move || server.serve_once().unwrap());
        let client = UdpDnsClient {
            server: address,
            timeout: Duration::from_secs(1),
            max_packet_size: 512,
        };
        let domain = DomainName::new("example.com").unwrap();
        let response = client.query(&domain, DnsRecordType::A).unwrap();
        assert_eq!(response.addresses.v4, vec![Ipv4Addr::new(203, 0, 113, 7)]);
        assert_eq!(server_thread.join().unwrap(), 45);

        let blocked = PolicyDnsHandler {
            upstream: StaticHandler,
            policy: DnsPolicy::Block,
        };
        assert_eq!(
            blocked.resolve(&domain, DnsRecordType::A).unwrap_err().kind,
            ErrorKind::Closed
        );
        let empty = PolicyDnsHandler {
            upstream: StaticHandler,
            policy: DnsPolicy::Empty,
        };
        assert!(
            empty
                .resolve(&domain, DnsRecordType::A)
                .unwrap()
                .addresses
                .is_empty()
        );
    }

    #[cfg(feature = "async-proxy")]
    #[tokio::test(flavor = "current_thread")]
    async fn async_dns_policy_is_cancellable_when_owner_drops_future() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct PendingResolver {
            dropped: Arc<AtomicBool>,
        }
        impl AsyncDnsHandler for PendingResolver {
            fn answer<'a>(&'a self, _packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
                let dropped = Arc::clone(&self.dropped);
                Box::pin(async move {
                    struct Guard(Arc<AtomicBool>);
                    impl Drop for Guard {
                        fn drop(&mut self) {
                            self.0.store(true, Ordering::Release);
                        }
                    }
                    let _guard = Guard(dropped);
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Ok(Vec::new())
                })
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let resolver = AsyncPolicyDnsHandler {
            upstream: PendingResolver {
                dropped: Arc::clone(&dropped),
            },
            policy: DnsPolicy::Upstream,
        };
        let packet = encode_query(
            7,
            &DomainName::new("example.com").unwrap(),
            DnsRecordType::A,
        )
        .unwrap();
        let mut future = resolver.answer(&packet);
        tokio::select! {
            _ = &mut future => panic!("pending DNS resolver unexpectedly completed"),
            _ = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
        drop(future);
        assert!(dropped.load(Ordering::Acquire));

        let blocked = AsyncPolicyDnsHandler {
            upstream: PendingResolver { dropped },
            policy: DnsPolicy::Block,
        };
        assert_eq!(
            blocked.answer(&packet).await.unwrap_err().kind,
            ErrorKind::Closed
        );
    }
}
