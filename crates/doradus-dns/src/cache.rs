//! Bounded, TTL-aware DNS response caches.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::Message;

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
