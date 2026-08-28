//! IPv4 FakeIP pool.

use super::*;

#[derive(Debug, Default)]
struct State {
    next: u32,
    forward: HashMap<DomainName, Mapping4>,
    reverse: HashMap<Ipv4Addr, DomainName>,
    reserved: HashMap<Ipv4Addr, i64>,
}

#[derive(Debug, Clone, Copy)]
struct Mapping4 {
    address: Ipv4Addr,
    created_at: i64,
    last_used_at: i64,
    persisted_last_used_at: i64,
}

pub struct FakeIpPool {
    pub(super) store: ConfigStore,
    config: FakeIpConfig,
    pub(super) prefix: String,
    options: FakeIpPoolOptions,
    state: Arc<Mutex<State>>,
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
        let reserved = store
            .list_fakeip_entries_in_range(
                family,
                &prefix,
                &config.start.octets(),
                &config.end.octets(),
            )
            .await?
            .into_iter()
            .filter(|entry| !expired_at(entry.last_used_at, now, options.ttl_seconds))
            .filter_map(|entry| {
                (entry.ip.len() == 4)
                    .then(|| <[u8; 4]>::try_from(entry.ip).ok())
                    .flatten()
                    .map(|ip| (Ipv4Addr::from(ip), entry.last_used_at))
            })
            .collect::<HashMap<_, _>>();
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
            reserved,
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
                || state.reserved.contains_key(&address)
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
        state
            .reserved
            .retain(|_, last_used_at| !expired_at(*last_used_at, now, self.options.ttl_seconds));
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
                if !state.reverse.contains_key(&address) && !state.reserved.contains_key(&address) {
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
        FakeIpView::from_maps(self.state.lock().await.reverse.clone(), HashMap::new())
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
