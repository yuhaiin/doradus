//! Async resolver cache and singleflight.

use super::*;

use crate::dns::RawDnsCacheKey;
use std::future::Future;

type DnsFlightKey = RawDnsCacheKey;

#[derive(Clone)]
enum DnsFlightOutcome {
    Pending,
    Completed(Result<Vec<u8>>),
    Cancelled,
}

struct AsyncDnsFlight {
    notify: Notify,
    outcome: Mutex<DnsFlightOutcome>,
}

impl AsyncDnsFlight {
    fn new() -> Self {
        Self {
            notify: Notify::new(),
            outcome: Mutex::new(DnsFlightOutcome::Pending),
        }
    }

    fn complete(&self, outcome: DnsFlightOutcome) {
        *self
            .outcome
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = outcome;
        self.notify.notify_waiters();
    }

    async fn wait(&self) -> Result<Option<Result<Vec<u8>>>> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let outcome = self
                .outcome
                .lock()
                .map_err(|_| {
                    crate::Error::new(crate::ErrorKind::Closed, "DNS flight result lock poisoned")
                })?
                .clone();
            match outcome {
                DnsFlightOutcome::Completed(result) => return Ok(Some(result)),
                DnsFlightOutcome::Cancelled => return Ok(None),
                DnsFlightOutcome::Pending => notified.await,
            }
        }
    }
}

#[derive(Default)]
struct AsyncDnsResolverState {
    in_flight: Mutex<HashMap<DnsFlightKey, Arc<AsyncDnsFlight>>>,
    refreshing: Mutex<HashSet<DnsFlightKey>>,
}

impl AsyncDnsResolverState {
    fn remove_flight(&self, key: &DnsFlightKey, flight: &Arc<AsyncDnsFlight>) {
        if let Ok(mut in_flight) = self.in_flight.lock()
            && in_flight
                .get(key)
                .is_some_and(|current| Arc::ptr_eq(current, flight))
        {
            in_flight.remove(key);
        }
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

    fn finish(mut self, result: Result<Vec<u8>>) {
        self.flight.complete(DnsFlightOutcome::Completed(result));
        self.state.remove_flight(&self.key, &self.flight);
        self.armed = false;
    }
}

impl Drop for AsyncDnsFlightCleanup {
    fn drop(&mut self) {
        if self.armed {
            // Persist cancellation before notifying: a follower may not yet
            // have registered with Notify on another runtime thread.
            self.flight.complete(DnsFlightOutcome::Cancelled);
            self.state.remove_flight(&self.key, &self.flight);
        }
    }
}

struct DnsRefreshCleanup {
    state: Arc<AsyncDnsResolverState>,
    key: DnsFlightKey,
}

impl Drop for DnsRefreshCleanup {
    fn drop(&mut self) {
        if let Ok(mut refreshing) = self.state.refreshing.lock() {
            refreshing.remove(&self.key);
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

    async fn query_packet_inner<F, Fut, S>(
        &self,
        packet: &[u8],
        query: F,
        allow_stale: bool,
        on_stale: S,
    ) -> Result<Vec<u8>>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<Vec<u8>>>,
        S: Fn(&RawDnsCacheKey),
    {
        let Some(key) = RawDnsCacheKey::from_packet(packet)? else {
            let response = query().await?;
            crate::dns::validate_response_packet(packet, &response)?;
            return Ok(response);
        };
        loop {
            if let Some((response, stale)) = self
                .cache
                .as_ref()
                .map_or(Ok(None), |cache| cache.get_packet(&key, allow_stale))?
            {
                if stale {
                    on_stale(&key);
                }
                return crate::dns::rewrite_dns_response_for_query(response, packet);
            }
            let (flight, owner) = self.begin_flight(key.clone())?;
            if owner {
                let cleanup = AsyncDnsFlightCleanup::new(self.state.clone(), key.clone(), flight);
                let result = query().await.and_then(|response| {
                    crate::dns::validate_response_packet(packet, &response)?;
                    if let Some(cache) = &self.cache {
                        cache.insert_packet(key.clone(), response.clone())?;
                    }
                    Ok(response)
                });
                cleanup.finish(result.clone());
                return result.and_then(|response| {
                    crate::dns::rewrite_dns_response_for_query(response, packet)
                });
            }
            if let Some(result) = flight.wait().await? {
                return result.and_then(|response| {
                    crate::dns::rewrite_dns_response_for_query(response, packet)
                });
            }
        }
    }

    fn start_refresh(&self, key: RawDnsCacheKey, packet: &[u8])
    where
        Q: SendAsyncDnsQuery + 'static,
    {
        let Some(cache) = self.cache.clone() else {
            return;
        };
        let should_start = self
            .state
            .refreshing
            .lock()
            .map(|mut refreshing| refreshing.insert(key.clone()))
            .unwrap_or(false);
        if !should_start {
            return;
        }
        // Replay all request flags and EDNS options, including CD/DO/ECS.
        let mut request = packet.to_vec();
        request[..2].copy_from_slice(&next_resolver_transaction_id().to_be_bytes());
        let upstream = self.upstream.clone();
        let cleanup = DnsRefreshCleanup {
            state: self.state.clone(),
            key: key.clone(),
        };
        tokio::spawn(async move {
            let _cleanup = cleanup;
            if let Ok(response) = upstream.query_packet_send(&request).await
                && crate::dns::validate_response_packet(&request, &response).is_ok()
            {
                let _ = cache.insert_packet(key, response);
            }
        });
    }
}

impl<Q: AsyncDnsQuery> AsyncDnsResolver<Q> {
    fn query_packet_local<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(self.query_packet_inner(
            packet,
            || self.upstream.query_packet(packet),
            false,
            |_| {},
        ))
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
                ResolveStrategy::PreferIpv4
                | ResolveStrategy::PreferIpv6
                | ResolveStrategy::Default => {
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
        Box::pin(self.query_packet_inner(
            packet,
            || self.upstream.query_packet_send(packet),
            true,
            |key| self.start_refresh(key.clone(), packet),
        ))
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
                ResolveStrategy::PreferIpv4
                | ResolveStrategy::PreferIpv6
                | ResolveStrategy::Default => {
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

#[cfg(test)]
mod cancellation_tests {
    use super::*;

    #[tokio::test]
    async fn cancellation_before_waiter_registration_is_retained() {
        let resolver = AsyncDnsResolver::new(());
        let key =
            RawDnsCacheKey::from_question(&DomainName::new("race.example").unwrap(), 1).unwrap();
        let (owner, _) = resolver.begin_flight(key.clone()).unwrap();
        let cleanup = AsyncDnsFlightCleanup::new(resolver.state.clone(), key.clone(), owner);
        let (waiter, is_owner) = resolver.begin_flight(key.clone()).unwrap();
        assert!(!is_owner);
        drop(cleanup);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), waiter.wait())
                .await
                .unwrap()
                .unwrap()
                .is_none()
        );
        assert!(resolver.begin_flight(key).unwrap().1);
    }
}

#[cfg(test)]
#[path = "dns_resolver_boundary_tests.rs"]
mod boundary_tests;
