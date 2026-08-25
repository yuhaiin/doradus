//! Async resolver cache and singleflight.

use super::*;

type DnsFlightKey = (DomainName, u16);

struct AsyncDnsFlight {
    notify: Notify,
    result: Mutex<Option<Result<Vec<u8>>>>,
}

impl AsyncDnsFlight {
    fn new() -> Self {
        Self {
            notify: Notify::new(),
            result: Mutex::new(None),
        }
    }
}

#[derive(Default)]
struct AsyncDnsResolverState {
    in_flight: Mutex<HashMap<DnsFlightKey, Arc<AsyncDnsFlight>>>,
    refreshing: Mutex<HashSet<DnsFlightKey>>,
}

impl AsyncDnsResolverState {
    fn remove_flight(&self, key: &DnsFlightKey, flight: &Arc<AsyncDnsFlight>) -> bool {
        self.in_flight
            .lock()
            .ok()
            .and_then(|mut in_flight| {
                if in_flight
                    .get(key)
                    .is_some_and(|current| Arc::ptr_eq(current, flight))
                {
                    in_flight.remove(key)
                } else {
                    None
                }
            })
            .is_some()
    }
}

struct AsyncDnsFlightCleanup {
    state: Arc<AsyncDnsResolverState>,
    key: DnsFlightKey,
    flight: Arc<AsyncDnsFlight>,
    armed: bool,
}

impl AsyncDnsFlightCleanup {
    fn new(
        state: Arc<AsyncDnsResolverState>,
        key: DnsFlightKey,
        flight: Arc<AsyncDnsFlight>,
    ) -> Self {
        Self {
            state,
            key,
            flight,
            armed: true,
        }
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for AsyncDnsFlightCleanup {
    fn drop(&mut self) {
        if self.armed && self.state.remove_flight(&self.key, &self.flight) {
            self.flight.notify.notify_waiters();
        }
    }
}

pub struct AsyncDnsResolver<Q> {
    pub upstream: Arc<Q>,
    pub cache: Option<DnsCache>,
    state: Arc<AsyncDnsResolverState>,
}

impl<Q> AsyncDnsResolver<Q> {
    pub fn new(upstream: Q) -> Self {
        Self {
            upstream: Arc::new(upstream),
            cache: None,
            state: Arc::new(AsyncDnsResolverState::default()),
        }
    }

    pub fn with_cache(mut self, cache: DnsCache) -> Self {
        self.cache = Some(cache);
        self
    }

    fn begin_flight(&self, key: DnsFlightKey) -> Result<(Arc<AsyncDnsFlight>, bool)> {
        let mut in_flight =
            self.state.in_flight.lock().map_err(|_| {
                crate::Error::new(crate::ErrorKind::Closed, "DNS flight lock poisoned")
            })?;
        if let Some(waiter) = in_flight.get(&key) {
            return Ok((waiter.clone(), false));
        }
        let flight = Arc::new(AsyncDnsFlight::new());
        in_flight.insert(key, flight.clone());
        Ok((flight, true))
    }

    fn flight_result(&self, flight: &AsyncDnsFlight) -> Result<Option<Result<Vec<u8>>>> {
        flight
            .result
            .lock()
            .map_err(|_| {
                crate::Error::new(crate::ErrorKind::Closed, "DNS flight result lock poisoned")
            })
            .map(|result| result.clone())
    }

    fn finish_flight(
        &self,
        key: &DnsFlightKey,
        flight: &Arc<AsyncDnsFlight>,
        result: Result<Vec<u8>>,
    ) {
        if let Ok(mut stored) = flight.result.lock() {
            *stored = Some(result);
        }
        if self.state.remove_flight(key, flight) {
            flight.notify.notify_waiters();
        }
    }

    fn start_refresh(&self, domain: DomainName, record_type: u16)
    where
        Q: SendAsyncDnsQuery + 'static,
    {
        let key = (domain.clone(), record_type);
        let should_start = self
            .state
            .refreshing
            .lock()
            .map(|mut refreshing| refreshing.insert(key.clone()))
            .unwrap_or(false);
        if !should_start {
            return;
        }

        let Some(cache) = self.cache.clone() else {
            if let Ok(mut refreshing) = self.state.refreshing.lock() {
                refreshing.remove(&key);
            }
            return;
        };
        let upstream = self.upstream.clone();
        let state = self.state.clone();
        tokio::spawn(async move {
            let result = async {
                let request = crate::dns::encode_raw_query(
                    next_resolver_transaction_id(),
                    &domain,
                    record_type,
                )?;
                let response = upstream.query_packet_send(&request).await?;
                crate::dns::validate_response_packet(&request, &response)?;
                cache.insert_raw(domain, record_type, response)?;
                Ok::<(), crate::Error>(())
            }
            .await;
            let _ = result;
            if let Ok(mut refreshing) = state.refreshing.lock() {
                refreshing.remove(&key);
            }
        });
    }
}

impl<Q: AsyncDnsQuery> AsyncDnsResolver<Q> {
    fn query_packet_local<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            crate::dns::validate_query_packet(packet)?;
            let (domain, record_type) = crate::dns::decode_raw_query_key(packet)?;
            let key = (domain.clone(), record_type);
            loop {
                if let Some(cache) = &self.cache
                    && let Some((response, expired)) =
                        cache.get_raw_optimistic(&domain, record_type)?
                {
                    // The local-future variant is used by embedders that do
                    // not guarantee a Tokio Send task. It still returns stale
                    // data immediately; the Send variant below also starts
                    // Go-compatible background refresh.
                    let _ = expired;
                    return crate::dns::rewrite_dns_response_for_query(response, packet);
                }

                let (flight, owner) = self.begin_flight(key.clone())?;
                if owner {
                    let cleanup =
                        AsyncDnsFlightCleanup::new(self.state.clone(), key.clone(), flight.clone());
                    let result = self.upstream.query_packet(packet).await;
                    let result = result.and_then(|response| {
                        crate::dns::validate_response_packet(packet, &response)?;
                        if let Some(cache) = &self.cache {
                            cache.insert_raw(domain.clone(), record_type, response.clone())?;
                        }
                        crate::dns::rewrite_dns_response_for_query(response, packet)
                    });
                    self.finish_flight(&key, &flight, result.clone());
                    cleanup.disarm();
                    return result;
                }

                let notified = flight.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if let Some(result) = self.flight_result(&flight)? {
                    return result.and_then(|response| {
                        crate::dns::rewrite_dns_response_for_query(response, packet)
                    });
                }
                notified.await;
                if let Some(result) = self.flight_result(&flight)? {
                    return result.and_then(|response| {
                        crate::dns::rewrite_dns_response_for_query(response, packet)
                    });
                }
            }
        })
    }

    pub fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            let id = next_resolver_transaction_id();
            let request = crate::dns::encode_query(id, domain, record_type)?;
            let response = self.query_packet_local(&request).await?;
            crate::dns::decode_response(&response, id, record_type)
        })
    }

    pub fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        strategy: ResolveStrategy,
    ) -> LocalBoxFuture<'a, Result<IpSet>> {
        Box::pin(async move {
            let mut result = IpSet::default();
            match strategy {
                ResolveStrategy::OnlyIpv4 => {
                    result.v4 = self.query(domain, DnsRecordType::A).await?.addresses.v4;
                }
                ResolveStrategy::OnlyIpv6 => {
                    result.v6 = self.query(domain, DnsRecordType::Aaaa).await?.addresses.v6;
                }
                ResolveStrategy::PreferIpv4 | ResolveStrategy::Default => {
                    let (v4, v6) = tokio::join!(
                        self.query(domain, DnsRecordType::A),
                        self.query(domain, DnsRecordType::Aaaa),
                    );
                    merge_address_queries(&mut result, v4, v6)?;
                }
                ResolveStrategy::PreferIpv6 => {
                    let (v4, v6) = tokio::join!(
                        self.query(domain, DnsRecordType::A),
                        self.query(domain, DnsRecordType::Aaaa),
                    );
                    merge_address_queries(&mut result, v4, v6)?;
                }
            }
            Ok(result)
        })
    }
}

impl<Q: SendAsyncDnsQuery + 'static> AsyncDnsResolver<Q> {
    pub(super) fn query_packet_send<'a>(
        &'a self,
        packet: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            crate::dns::validate_query_packet(packet)?;
            let (domain, record_type) = crate::dns::decode_raw_query_key(packet)?;
            let key = (domain.clone(), record_type);
            loop {
                if let Some(cache) = &self.cache
                    && let Some((response, expired)) =
                        cache.get_raw_optimistic(&domain, record_type)?
                {
                    if expired {
                        self.start_refresh(domain.clone(), record_type);
                    }
                    return crate::dns::rewrite_dns_response_for_query(response, packet);
                }

                let (flight, owner) = self.begin_flight(key.clone())?;
                if owner {
                    let cleanup =
                        AsyncDnsFlightCleanup::new(self.state.clone(), key.clone(), flight.clone());
                    let result = self.upstream.query_packet_send(packet).await;
                    let result = result.and_then(|response| {
                        crate::dns::validate_response_packet(packet, &response)?;
                        if let Some(cache) = &self.cache {
                            cache.insert_raw(domain.clone(), record_type, response.clone())?;
                        }
                        crate::dns::rewrite_dns_response_for_query(response, packet)
                    });
                    self.finish_flight(&key, &flight, result.clone());
                    cleanup.disarm();
                    return result;
                }

                let notified = flight.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if let Some(result) = self.flight_result(&flight)? {
                    return result.and_then(|response| {
                        crate::dns::rewrite_dns_response_for_query(response, packet)
                    });
                }
                notified.await;
                if let Some(result) = self.flight_result(&flight)? {
                    return result.and_then(|response| {
                        crate::dns::rewrite_dns_response_for_query(response, packet)
                    });
                }
            }
        })
    }

    pub(super) fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            let id = next_resolver_transaction_id();
            let request = crate::dns::encode_query(id, domain, record_type)?;
            let response = self.query_packet_send(&request).await?;
            crate::dns::decode_response(&response, id, record_type)
        })
    }

    pub(super) fn resolve_send<'a>(
        &'a self,
        domain: &'a DomainName,
        strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        Box::pin(async move {
            let mut result = IpSet::default();
            match strategy {
                ResolveStrategy::OnlyIpv4 => {
                    result.v4 = self
                        .query_send(domain, DnsRecordType::A)
                        .await?
                        .addresses
                        .v4;
                }
                ResolveStrategy::OnlyIpv6 => {
                    result.v6 = self
                        .query_send(domain, DnsRecordType::Aaaa)
                        .await?
                        .addresses
                        .v6;
                }
                ResolveStrategy::PreferIpv4 | ResolveStrategy::Default => {
                    let (v4, v6) = tokio::join!(
                        self.query_send(domain, DnsRecordType::A),
                        self.query_send(domain, DnsRecordType::Aaaa),
                    );
                    merge_address_queries(&mut result, v4, v6)?;
                }
                ResolveStrategy::PreferIpv6 => {
                    let (v4, v6) = tokio::join!(
                        self.query_send(domain, DnsRecordType::A),
                        self.query_send(domain, DnsRecordType::Aaaa),
                    );
                    merge_address_queries(&mut result, v4, v6)?;
                }
            }
            Ok(result)
        })
    }
}

fn merge_address_queries(
    result: &mut IpSet,
    v4: Result<DnsResponse>,
    v6: Result<DnsResponse>,
) -> Result<()> {
    match (v4, v6) {
        (Ok(v4), Ok(v6)) => {
            result.v4 = v4.addresses.v4;
            result.v6 = v6.addresses.v6;
            Ok(())
        }
        (Ok(v4), Err(_)) => {
            result.v4 = v4.addresses.v4;
            Ok(())
        }
        (Err(_), Ok(v6)) => {
            result.v6 = v6.addresses.v6;
            Ok(())
        }
        (Err(v4), Err(v6)) => Err(crate::Error::new(
            crate::ErrorKind::Io,
            format!(
                "DNS A and AAAA queries failed: A: {}; AAAA: {}",
                v4.message, v6.message
            ),
        )),
    }
}

impl<Q: SendAsyncDnsQuery + 'static> AsyncIpResolver for AsyncDnsResolver<Q> {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        self.resolve_send(domain, strategy)
    }

    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        self.query_send(domain, record_type)
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        self.query_packet_send(packet)
    }
}

impl<Q: SendAsyncDnsQuery + 'static> AsyncDnsHandler for AsyncDnsResolver<Q> {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        self.query_packet_send(packet)
    }
}

fn next_resolver_transaction_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
