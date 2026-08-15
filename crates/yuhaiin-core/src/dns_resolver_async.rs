//! Async resolver composition for the TUN/proxy path.
//!
//! The public boundary is packet-level so it can be wrapped by hosts, policy,
//! and FakeIP handlers.  Transport implementations expose one query-level
//! trait, keeping async UDP/DoH connection details out of the composition
//! layer and avoiding blocking work in the TUN event loop.

#[cfg(target_os = "windows")]
use crate::dns::decode_response;
use crate::dns::{
    AsyncDnsHandler, DnsCache, DnsRecordType, DnsResponse, decode_query, encode_response,
};
use crate::dns_udp_async::AsyncUdpDnsClient;
use crate::{BoxFuture, DomainName, IpSet, LocalBoxFuture, ResolveStrategy, Result};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

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

/// Send-safe address resolution boundary shared by chain and base proxies.
///
/// The resolver owns policy, hosts overrides, FakeIP and upstream transport;
/// consumers only receive addresses and never need to know whether the query
/// used UDP, DoH or the system resolver.
pub trait AsyncIpResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>>;

    /// Resolve one DNS record while retaining non-address data such as PTR
    /// names and HTTPS/SVCB service bindings.  Address-only consumers keep
    /// using [`Self::resolve`]; packet-facing DNS servers use this method so
    /// the runtime does not erase records at a trait-object boundary.
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            let strategy = match record_type {
                DnsRecordType::A => ResolveStrategy::OnlyIpv4,
                DnsRecordType::Aaaa => ResolveStrategy::OnlyIpv6,
                DnsRecordType::Ptr | DnsRecordType::Https | DnsRecordType::Svcb => {
                    ResolveStrategy::Default
                }
            };
            Ok(DnsResponse {
                addresses: self.resolve(domain, strategy).await?,
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            })
        })
    }

    /// Forward a complete DNS message without converting its QTYPE or
    /// answer records into the address-oriented model above.  Implementations
    /// backed by UDP/TCP/DoH override this method; policy layers forward it so
    /// uncommon records remain usable through the runtime DNS server.
    fn query_packet<'a>(&'a self, _packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async {
            Err(crate::Error::new(
                crate::ErrorKind::Unsupported,
                "resolver does not support raw DNS packet queries",
            ))
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemAsyncIpResolver;

impl AsyncIpResolver for SystemAsyncIpResolver {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((domain.as_str(), 0))
                .await
                .map_err(|error| {
                    crate::Error::new(
                        crate::ErrorKind::Io,
                        format!("resolve system host {}: {error}", domain.as_str()),
                    )
                })?;
            let mut result = IpSet::default();
            for address in addresses {
                match address.ip() {
                    std::net::IpAddr::V4(ip) => result.v4.push(ip),
                    std::net::IpAddr::V6(ip) => result.v6.push(ip),
                }
            }
            match strategy {
                ResolveStrategy::OnlyIpv4 => result.v6.clear(),
                ResolveStrategy::OnlyIpv6 => result.v4.clear(),
                ResolveStrategy::PreferIpv4
                | ResolveStrategy::PreferIpv6
                | ResolveStrategy::Default => {}
            }
            if result.is_empty() {
                return Err(crate::Error::invalid(format!(
                    "system host {} resolved to no address",
                    domain.as_str()
                )));
            }
            Ok(result)
        })
    }

    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            #[cfg(unix)]
            {
                let client = system_dns_client().await?;
                return query_system_server(&client, domain, record_type).await;
            }
            #[cfg(target_os = "windows")]
            {
                return query_windows_system_resolver(domain, record_type).await;
            }
            #[cfg(not(any(unix, target_os = "windows")))]
            {
                let _ = (domain, record_type);
                Err(crate::Error::new(
                    crate::ErrorKind::Unsupported,
                    "system DNS queries are unsupported on this platform",
                ))
            }
        })
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            #[cfg(unix)]
            {
                return system_dns_client().await?.query_packet(packet).await;
            }
            #[cfg(target_os = "windows")]
            {
                return query_windows_system_packet(packet).await;
            }
            #[cfg(not(any(unix, target_os = "windows")))]
            {
                let _ = packet;
                Err(crate::Error::new(
                    crate::ErrorKind::Unsupported,
                    "system DNS packet queries are unsupported on this platform",
                ))
            }
        })
    }
}

#[cfg(unix)]
async fn system_dns_client() -> Result<AsyncUdpDnsClient> {
    let server = tokio::task::spawn_blocking(read_system_dns_server)
        .await
        .map_err(|error| {
            crate::Error::new(
                crate::ErrorKind::Io,
                format!("read system DNS server task: {error}"),
            )
        })??;
    Ok(AsyncUdpDnsClient::new(
        server,
        std::time::Duration::from_secs(5),
        65535,
        std::sync::Arc::from(Vec::new().into_boxed_slice()),
        None,
    ))
}

#[cfg(unix)]
async fn query_system_server(
    client: &AsyncUdpDnsClient,
    domain: &DomainName,
    record_type: DnsRecordType,
) -> Result<DnsResponse> {
    client.query(domain, record_type).await
}

#[cfg(unix)]
fn read_system_dns_server() -> Result<std::net::SocketAddr> {
    let contents = std::fs::read_to_string("/etc/resolv.conf").map_err(|error| {
        crate::Error::new(
            crate::ErrorKind::Io,
            format!("read /etc/resolv.conf: {error}"),
        )
    })?;
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        if let Some(address) = fields.next().and_then(|value| value.parse().ok()) {
            return Ok(std::net::SocketAddr::new(address, 53));
        }
    }
    Err(crate::Error::new(
        crate::ErrorKind::NotFound,
        "system DNS configuration has no nameserver",
    ))
}

#[cfg(target_os = "windows")]
fn windows_system_resolver() -> Result<std::sync::Arc<hickory_resolver::TokioResolver>> {
    use std::sync::{Arc, OnceLock};

    static RESOLVER: OnceLock<Arc<hickory_resolver::TokioResolver>> = OnceLock::new();
    if let Some(resolver) = RESOLVER.get() {
        return Ok(Arc::clone(resolver));
    }

    let resolver = Arc::new(
        hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|error| {
                crate::Error::new(
                    crate::ErrorKind::Io,
                    format!("read Windows DNS configuration: {error}"),
                )
            })?
            .build()
            .map_err(|error| {
                crate::Error::new(
                    crate::ErrorKind::Io,
                    format!("build Windows system DNS resolver: {error}"),
                )
            })?,
    );
    let _ = RESOLVER.set(Arc::clone(&resolver));
    Ok(RESOLVER.get().cloned().unwrap_or(resolver))
}

#[cfg(target_os = "windows")]
fn hickory_record_type(record_type: DnsRecordType) -> hickory_proto::rr::RecordType {
    match record_type {
        DnsRecordType::A => hickory_proto::rr::RecordType::A,
        DnsRecordType::Aaaa => hickory_proto::rr::RecordType::AAAA,
        DnsRecordType::Ptr => hickory_proto::rr::RecordType::PTR,
        DnsRecordType::Https => hickory_proto::rr::RecordType::HTTPS,
        DnsRecordType::Svcb => hickory_proto::rr::RecordType::SVCB,
    }
}

#[cfg(target_os = "windows")]
async fn query_windows_system_resolver(
    domain: &DomainName,
    record_type: DnsRecordType,
) -> Result<DnsResponse> {
    let resolver = windows_system_resolver()?;
    let lookup = resolver
        .lookup(
            format!("{}.", domain.as_str()),
            hickory_record_type(record_type),
        )
        .await
        .map_err(|error| {
            crate::Error::new(
                crate::ErrorKind::Io,
                format!("query Windows system DNS for {}: {error}", domain.as_str()),
            )
        })?;
    let packet = lookup.message().to_vec().map_err(|error| {
        crate::Error::new(
            crate::ErrorKind::Protocol,
            format!("encode Windows system DNS response: {error}"),
        )
    })?;
    let id = dns_transaction_id(&packet)?;
    decode_response(&packet, id, record_type)
}

#[cfg(target_os = "windows")]
async fn query_windows_system_packet(packet: &[u8]) -> Result<Vec<u8>> {
    use hickory_proto::op::Message;

    let message = Message::from_vec(packet).map_err(|error| {
        crate::Error::new(
            crate::ErrorKind::Protocol,
            format!("decode Windows system DNS request: {error}"),
        )
    })?;
    let query = message.queries.first().ok_or_else(|| {
        crate::Error::new(crate::ErrorKind::Protocol, "DNS request has no question")
    })?;
    let resolver = windows_system_resolver()?;
    let lookup = resolver
        .lookup(query.name().clone(), query.query_type())
        .await
        .map_err(|error| {
            crate::Error::new(
                crate::ErrorKind::Io,
                format!("query Windows system DNS packet: {error}"),
            )
        })?;
    let response = lookup.message().to_vec().map_err(|error| {
        crate::Error::new(
            crate::ErrorKind::Protocol,
            format!("encode Windows system DNS packet response: {error}"),
        )
    })?;
    rewrite_dns_transaction_id(response, message.metadata.id)
}

#[cfg(any(test, target_os = "windows"))]
fn dns_transaction_id(packet: &[u8]) -> Result<u16> {
    let bytes = packet.get(..2).ok_or_else(|| {
        crate::Error::new(
            crate::ErrorKind::Protocol,
            "DNS response is shorter than its transaction id",
        )
    })?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(any(test, target_os = "windows"))]
fn rewrite_dns_transaction_id(mut packet: Vec<u8>, id: u16) -> Result<Vec<u8>> {
    let _ = dns_transaction_id(&packet)?;
    packet[..2].copy_from_slice(&id.to_be_bytes());
    Ok(packet)
}

/// Query-level variant whose future can safely cross a Tokio task boundary.
pub trait SendAsyncDnsQuery: Send + Sync {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>>;

    fn query_packet_send<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let question = decode_query(packet)?;
            let answer = self
                .query_send(&question.domain, question.record_type)
                .await?;
            encode_response(packet, &answer)
        })
    }
}

impl<T: SendAsyncDnsQuery + ?Sized> SendAsyncDnsQuery for Box<T> {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        (**self).query_send(domain, record_type)
    }

    fn query_packet_send<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        (**self).query_packet_send(packet)
    }
}

pub trait AsyncDnsQuery: Send + Sync {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>>;

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let question = decode_query(packet)?;
            let answer = self.query(&question.domain, question.record_type).await?;
            encode_response(packet, &answer)
        })
    }
}

impl AsyncDnsQuery for AsyncUdpDnsClient {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { AsyncUdpDnsClient::query(self, domain, record_type).await })
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { self.query_packet(packet).await })
    }
}

impl SendAsyncDnsQuery for AsyncUdpDnsClient {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { AsyncUdpDnsClient::query(self, domain, record_type).await })
    }

    fn query_packet_send<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { self.query_packet(packet).await })
    }
}

impl<T: AsyncDnsQuery + ?Sized> AsyncDnsQuery for Box<T> {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        (**self).query(domain, record_type)
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        (**self).query_packet(packet)
    }
}

#[cfg(feature = "http2")]
impl<C: crate::http2::H2DohConnector> AsyncDnsQuery for crate::http2::H2DohClient<C> {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { crate::http2::H2DohClient::query(self, domain, record_type).await })
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { self.query_packet(packet).await })
    }
}

#[cfg(feature = "http2")]
impl<C: crate::http2::H2DohConnector> SendAsyncDnsQuery for crate::http2::H2DohClient<C> {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { crate::http2::H2DohClient::query(self, domain, record_type).await })
    }

    fn query_packet_send<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { self.query_packet(packet).await })
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
        let current = self.state.in_flight.lock().ok().and_then(|mut in_flight| {
            if in_flight
                .get(key)
                .is_some_and(|current| Arc::ptr_eq(current, flight))
            {
                in_flight.remove(key)
            } else {
                None
            }
        });
        if current.is_some() {
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
                    let result = self.upstream.query_packet(packet).await;
                    let result = result.and_then(|response| {
                        crate::dns::validate_response_packet(packet, &response)?;
                        if let Some(cache) = &self.cache {
                            cache.insert_raw(domain.clone(), record_type, response.clone())?;
                        }
                        crate::dns::rewrite_dns_response_for_query(response, packet)
                    });
                    self.finish_flight(&key, &flight, result.clone());
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
    fn query_packet_send<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
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
                    let result = self.upstream.query_packet_send(packet).await;
                    let result = result.and_then(|response| {
                        crate::dns::validate_response_packet(packet, &response)?;
                        if let Some(cache) = &self.cache {
                            cache.insert_raw(domain.clone(), record_type, response.clone())?;
                        }
                        crate::dns::rewrite_dns_response_for_query(response, packet)
                    });
                    self.finish_flight(&key, &flight, result.clone());
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

    fn query_send<'a>(
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

    fn resolve_send<'a>(
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

impl<Q: AsyncDnsQuery> AsyncDnsHandler for AsyncDnsResolver<Q> {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        self.query_packet_local(packet)
    }
}

fn next_resolver_transaction_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{
        AsyncDnsHandler, DnsResponse, decode_response, encode_query, encode_response,
    };
    use crate::{Error, ErrorKind};
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct StaticQuery {
        calls: Arc<Mutex<usize>>,
    }

    impl AsyncDnsQuery for StaticQuery {
        fn query<'a>(
            &'a self,
            _domain: &'a DomainName,
            _record_type: DnsRecordType,
        ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
            Box::pin(async move {
                *self
                    .calls
                    .lock()
                    .map_err(|_| Error::new(ErrorKind::Closed, "query counter poisoned"))? += 1;
                Ok(DnsResponse {
                    addresses: IpSet {
                        v4: vec![Ipv4Addr::new(192, 0, 2, 77)],
                        v6: Vec::new(),
                    },
                    ptr_names: Vec::new(),
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(30),
                })
            })
        }
    }

    struct SlowQuery {
        calls: Arc<AtomicUsize>,
        started: Arc<Notify>,
        release: Arc<Notify>,
    }

    impl AsyncDnsQuery for SlowQuery {
        fn query<'a>(
            &'a self,
            _domain: &'a DomainName,
            _record_type: DnsRecordType,
        ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::Relaxed);
                self.started.notify_one();
                self.release.notified().await;
                Ok(DnsResponse {
                    addresses: IpSet {
                        v4: vec![Ipv4Addr::new(192, 0, 2, 78)],
                        v6: Vec::new(),
                    },
                    ptr_names: Vec::new(),
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(30),
                })
            })
        }
    }

    struct PartialQuery {
        calls: Arc<Mutex<Vec<DnsRecordType>>>,
    }

    impl PartialQuery {
        fn response(&self, record_type: DnsRecordType) -> Result<DnsResponse> {
            self.calls
                .lock()
                .map_err(|_| Error::new(ErrorKind::Closed, "query types poisoned"))?
                .push(record_type);
            if record_type == DnsRecordType::Aaaa {
                return Err(Error::new(ErrorKind::Io, "AAAA upstream unavailable"));
            }
            Ok(DnsResponse {
                addresses: IpSet {
                    v4: vec![Ipv4Addr::new(192, 0, 2, 88)],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            })
        }
    }

    impl AsyncDnsQuery for PartialQuery {
        fn query<'a>(
            &'a self,
            _domain: &'a DomainName,
            record_type: DnsRecordType,
        ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
            Box::pin(async move { self.response(record_type) })
        }
    }

    impl SendAsyncDnsQuery for PartialQuery {
        fn query_send<'a>(
            &'a self,
            _domain: &'a DomainName,
            record_type: DnsRecordType,
        ) -> BoxFuture<'a, Result<DnsResponse>> {
            Box::pin(async move { self.response(record_type) })
        }
    }

    #[test]
    fn async_resolver_caches_and_preserves_packet_transaction() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let calls = Arc::new(Mutex::new(0));
            let resolver = AsyncDnsResolver::new(StaticQuery {
                calls: calls.clone(),
            })
            .with_cache(DnsCache::new(8).unwrap());
            let domain = DomainName::new("example.com").unwrap();
            let packet = encode_query(0x4242, &domain, DnsRecordType::A).unwrap();
            let second_packet = encode_query(0x4243, &domain, DnsRecordType::A).unwrap();
            let first = resolver.answer(&packet).await.unwrap();
            let second = resolver.answer(&second_packet).await.unwrap();
            let first = decode_response(&first, 0x4242, DnsRecordType::A).unwrap();
            let second = decode_response(&second, 0x4243, DnsRecordType::A).unwrap();
            assert_eq!(first, second);
            assert_eq!(*calls.lock().unwrap(), 1);
        });
    }

    #[tokio::test(flavor = "current_thread")]
    async fn async_resolver_singleflights_concurrent_raw_queries() {
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let resolver = Arc::new(AsyncDnsResolver::new(SlowQuery {
            calls: calls.clone(),
            started: started.clone(),
            release: release.clone(),
        }));
        let domain = DomainName::new("singleflight.example").unwrap();
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let first_resolver = resolver.clone();
                let first_domain = domain.clone();
                let first = tokio::task::spawn_local(async move {
                    first_resolver.query(&first_domain, DnsRecordType::A).await
                });
                let second_resolver = resolver.clone();
                let second_domain = domain.clone();
                let second = tokio::task::spawn_local(async move {
                    second_resolver
                        .query(&second_domain, DnsRecordType::A)
                        .await
                });

                tokio::time::timeout(std::time::Duration::from_secs(1), started.notified())
                    .await
                    .expect("singleflight owner did not reach the upstream");
                // Give the second local task a chance to register as a
                // waiter before the first upstream request is released.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                assert_eq!(calls.load(Ordering::Relaxed), 1);
                release.notify_waiters();
                assert!(first.await.unwrap().is_ok());
                assert!(second.await.unwrap().is_ok());
                assert_eq!(calls.load(Ordering::Relaxed), 1);
            })
            .await;
    }

    #[tokio::test]
    async fn default_resolution_keeps_ipv4_when_ipv6_query_fails() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let resolver = AsyncDnsResolver::new(PartialQuery {
            calls: calls.clone(),
        });
        let domain = DomainName::new("partial.example").unwrap();

        let addresses = resolver
            .resolve(&domain, ResolveStrategy::Default)
            .await
            .unwrap();

        assert_eq!(addresses.v4, vec![Ipv4Addr::new(192, 0, 2, 88)]);
        assert!(addresses.v6.is_empty());
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(calls.contains(&DnsRecordType::A));
        assert!(calls.contains(&DnsRecordType::Aaaa));
    }

    #[tokio::test]
    async fn system_query_preserves_non_address_records() {
        struct PtrHandler;

        impl AsyncDnsHandler for PtrHandler {
            fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
                Box::pin(async move {
                    encode_response(
                        packet,
                        &DnsResponse {
                            addresses: IpSet::default(),
                            ptr_names: vec![DomainName::new("ptr.example").unwrap()],
                            service_bindings: Vec::new(),
                            minimum_ttl: Some(30),
                        },
                    )
                })
            }
        }

        let server = crate::dns_udp_async::AsyncUdpDnsServer::bind(
            (Ipv4Addr::LOCALHOST, 0).into(),
            PtrHandler,
            4096,
        )
        .await
        .unwrap();
        let address = server.local_addr().unwrap();
        let client = AsyncUdpDnsClient::new(
            address,
            std::time::Duration::from_secs(1),
            4096,
            Arc::from(Vec::new().into_boxed_slice()),
            None,
        );
        let domain = DomainName::new("4.3.2.1.in-addr.arpa").unwrap();
        let (server_result, response) = tokio::join!(
            server.serve_once(),
            query_system_server(&client, &domain, DnsRecordType::Ptr)
        );
        server_result.unwrap();
        let response = response.unwrap();
        assert_eq!(
            response.ptr_names,
            vec![DomainName::new("ptr.example").unwrap()]
        );
    }

    #[test]
    fn rewrite_dns_transaction_id_preserves_dns_payload() {
        let packet = rewrite_dns_transaction_id(vec![0x00, 0x01, 0xaa, 0xbb], 0xcafe).unwrap();
        assert_eq!(packet, vec![0xca, 0xfe, 0xaa, 0xbb]);
        assert!(rewrite_dns_transaction_id(vec![0x00], 0xcafe).is_err());
    }
}
