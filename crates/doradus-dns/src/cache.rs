//! Bounded, TTL-aware DNS response caches.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hashlink::LinkedHashMap;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RData;

use crate::dns::{DnsHandler, DnsRecordType, DnsResponse};
use crate::{DomainName, Error, ErrorKind, Result};
#[derive(Clone)]
pub struct DnsCache {
    entries: Arc<Mutex<LruMap<(DomainName, DnsRecordType), CachedDnsResponse>>>,
    raw_entries: Arc<Mutex<LruMap<(DomainName, u16), CachedDnsPacket>>>,
}

#[derive(Clone)]
struct CachedDnsResponse {
    response: DnsResponse,
    cached_at: std::time::Instant,
    expires_at: std::time::Instant,
}

#[derive(Clone)]
struct CachedDnsPacket {
    packet: Vec<u8>,
    cached_at: std::time::Instant,
    expires_at: std::time::Instant,
    negative_ttl: Option<u32>,
}

struct LruMap<K, V> {
    map: LinkedHashMap<K, V>,
    capacity: usize,
}

impl<K: Eq + std::hash::Hash + Clone, V> LruMap<K, V> {
    fn new(capacity: usize) -> Self {
        Self {
            map: LinkedHashMap::with_capacity(capacity),
            capacity,
        }
    }

    fn get_cloned(&mut self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        let value = self.map.get(key)?.clone();
        self.map.to_front(key);
        Some(value)
    }

    fn insert(&mut self, key: K, value: V) {
        self.map.insert(key.clone(), value);
        self.map.to_front(&key);
        while self.map.len() > self.capacity {
            self.map.pop_back();
        }
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        self.map.remove(key)
    }

    fn remove_expired(&mut self, budget: usize, mut expired: impl FnMut(&V) -> bool) {
        let keys = self
            .map
            .iter()
            .take(budget)
            .filter(|(_, value)| expired(value))
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        for key in keys {
            self.remove(&key);
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

const EXPIRATION_SWEEP_BUDGET: usize = 8;

fn age_typed_response(
    mut response: DnsResponse,
    cached_at: std::time::Instant,
    now: std::time::Instant,
    stale: bool,
) -> DnsResponse {
    if let Some(ttl) = response.minimum_ttl {
        let elapsed = now.saturating_duration_since(cached_at).as_secs();
        let elapsed = elapsed.min(u64::from(u32::MAX)) as u32;
        response.minimum_ttl = Some(if stale {
            0
        } else {
            ttl.saturating_sub(elapsed)
        });
    }
    response
}

fn age_raw_packet(
    packet: Vec<u8>,
    cached_at: std::time::Instant,
    now: std::time::Instant,
    stale: bool,
    negative_ttl: Option<u32>,
) -> Result<Vec<u8>> {
    let mut message = Message::from_vec(&packet)
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
    let elapsed = now.saturating_duration_since(cached_at).as_secs();
    let elapsed = elapsed.min(u64::from(u32::MAX)) as u32;
    for records in [
        &mut message.answers,
        &mut message.authorities,
        &mut message.additionals,
    ] {
        for record in records {
            let original_ttl = if let Some(negative_ttl) = negative_ttl
                && matches!(&record.data, RData::SOA(_))
            {
                record.ttl.min(negative_ttl)
            } else {
                record.ttl
            };
            record.ttl = if stale {
                0
            } else {
                original_ttl.saturating_sub(elapsed)
            };
        }
    }
    // Hickory stores EDNS(0) separately as `Message::edns`; its extended
    // RCODE and flags are not resource-record TTLs and must not be aged.
    message
        .to_vec()
        .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
}

fn raw_cache_ttl(message: &Message) -> Option<(u32, Option<u32>)> {
    if message.metadata.truncation {
        return None;
    }
    match message.metadata.response_code {
        ResponseCode::NoError if !message.answers.is_empty() => {
            let answer_ttl = message.answers.iter().map(|record| record.ttl).min()?;
            let negative_ttl = negative_soa_ttl(message);
            Some((
                negative_ttl.map_or(answer_ttl, |ttl| answer_ttl.min(ttl)),
                negative_ttl,
            ))
        }
        ResponseCode::NoError if message.answers.is_empty() => {
            negative_soa_ttl(message).map(|ttl| (ttl, Some(ttl)))
        }
        ResponseCode::NXDomain => {
            let negative_ttl = negative_soa_ttl(message)?;
            let answer_ttl = message.answers.iter().map(|record| record.ttl).min();
            Some((
                answer_ttl.map_or(negative_ttl, |ttl| ttl.min(negative_ttl)),
                Some(negative_ttl),
            ))
        }
        // Transport failures and policy/protocol errors are transient or
        // requester-specific and must not poison the response cache.
        _ => None,
    }
}

fn negative_soa_ttl(message: &Message) -> Option<u32> {
    message
        .authorities
        .iter()
        .filter_map(|record| match &record.data {
            RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
            _ => None,
        })
        .min()
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
        let now = std::time::Instant::now();
        if entry.expires_at <= now {
            entries.remove(&key);
            return Ok(None);
        }
        Ok(Some(age_typed_response(
            entry.response,
            entry.cached_at,
            now,
            false,
        )))
    }

    pub fn insert(
        &self,
        domain: DomainName,
        record_type: DnsRecordType,
        response: DnsResponse,
    ) -> Result<()> {
        let ttl = response.minimum_ttl.unwrap_or(300);
        if ttl == 0 {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| Error::new(ErrorKind::Closed, "DNS cache lock poisoned"))?;
            entries.remove(&(domain, record_type));
            return Ok(());
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS cache lock poisoned"))?;
        let now = std::time::Instant::now();
        entries.remove_expired(EXPIRATION_SWEEP_BUDGET, |entry| entry.expires_at <= now);
        entries.insert(
            (domain, record_type),
            CachedDnsResponse {
                response,
                cached_at: now,
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
        let now = std::time::Instant::now();
        let stale = entry.expires_at <= now;
        Ok(Some((
            age_typed_response(entry.response, entry.cached_at, now, stale),
            stale,
        )))
    }

    /// Return a raw DNS response while optionally retaining stale entries for
    /// a background refresh. The cache key intentionally excludes the DNS
    /// transaction ID, just like Go's `CacheKeyFromQuestion`.
    pub(crate) fn get_raw_with_stale(
        &self,
        domain: &DomainName,
        record_type: u16,
        allow_stale: bool,
    ) -> Result<Option<(Vec<u8>, bool)>> {
        let key = (domain.clone(), record_type);
        let mut entries = self
            .raw_entries
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS raw cache lock poisoned"))?;
        let Some(entry) = entries.get_cloned(&key) else {
            return Ok(None);
        };
        let now = std::time::Instant::now();
        let stale = entry.expires_at <= now;
        if stale && !allow_stale {
            entries.remove(&key);
        }
        drop(entries);
        if stale && !allow_stale {
            return Ok(None);
        }
        Ok(Some((
            age_raw_packet(
                entry.packet,
                entry.cached_at,
                now,
                stale,
                entry.negative_ttl,
            )?,
            stale,
        )))
    }

    #[cfg(test)]
    pub(crate) fn advance_raw_for_test(
        &self,
        domain: &DomainName,
        record_type: u16,
        elapsed: Duration,
    ) -> Result<()> {
        let mut entries = self
            .raw_entries
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS raw cache lock poisoned"))?;
        if let Some(entry) = entries.map.get_mut(&(domain.clone(), record_type)) {
            entry.cached_at = entry
                .cached_at
                .checked_sub(elapsed)
                .unwrap_or(entry.cached_at);
            entry.expires_at = entry
                .expires_at
                .checked_sub(elapsed)
                .unwrap_or(entry.expires_at);
        }
        Ok(())
    }

    pub(crate) fn insert_raw(
        &self,
        domain: DomainName,
        record_type: u16,
        packet: Vec<u8>,
    ) -> Result<()> {
        let message = Message::from_vec(&packet)
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
        let key = (domain.clone(), record_type);
        let Some((ttl, negative_ttl)) = raw_cache_ttl(&message) else {
            // Keep an optimistic stale entry across transient upstream
            // failures. A successful NoError/NXDomain response without a
            // usable TTL, however, supersedes the old answer.
            if !message.metadata.truncation
                && matches!(
                    message.metadata.response_code,
                    ResponseCode::NoError | ResponseCode::NXDomain
                )
            {
                let mut entries = self
                    .raw_entries
                    .lock()
                    .map_err(|_| Error::new(ErrorKind::Closed, "DNS raw cache lock poisoned"))?;
                entries.remove(&key);
            }
            return Ok(());
        };
        if ttl == 0 {
            let mut entries = self
                .raw_entries
                .lock()
                .map_err(|_| Error::new(ErrorKind::Closed, "DNS raw cache lock poisoned"))?;
            entries.remove(&key);
            return Ok(());
        }
        let now = std::time::Instant::now();
        let mut entries = self
            .raw_entries
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS raw cache lock poisoned"))?;
        entries.remove_expired(EXPIRATION_SWEEP_BUDGET, |entry| entry.expires_at <= now);
        entries.insert(
            key,
            CachedDnsPacket {
                packet,
                cached_at: now,
                expires_at: now + Duration::from_secs(u64::from(ttl)),
                negative_ttl,
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

#[derive(Clone)]
pub struct CachingDnsHandler<H> {
    pub upstream: H,
    pub cache: DnsCache,
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
