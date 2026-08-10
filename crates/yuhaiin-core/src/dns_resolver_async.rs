//! Async resolver composition for the TUN/proxy path.
//!
//! The public boundary is packet-level so it can be wrapped by hosts, policy,
//! and FakeIP handlers.  Transport implementations expose one query-level
//! trait, keeping async UDP/DoH connection details out of the composition
//! layer and avoiding blocking work in the TUN event loop.

use crate::dns::{
    AsyncDnsHandler, DnsCache, DnsRecordType, DnsResponse, decode_query, encode_response,
};
use crate::dns_udp_async::AsyncUdpDnsClient;
use crate::{BoxFuture, DomainName, IpSet, LocalBoxFuture, ResolveStrategy, Result};

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
}

/// Query-level variant whose future can safely cross a Tokio task boundary.
pub trait SendAsyncDnsQuery: Send + Sync {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>>;
}

impl<T: SendAsyncDnsQuery + ?Sized> SendAsyncDnsQuery for Box<T> {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        (**self).query_send(domain, record_type)
    }
}

pub trait AsyncDnsQuery: Send + Sync {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>>;
}

impl AsyncDnsQuery for AsyncUdpDnsClient {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { AsyncUdpDnsClient::query(self, domain, record_type).await })
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
}

impl<T: AsyncDnsQuery + ?Sized> AsyncDnsQuery for Box<T> {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        (**self).query(domain, record_type)
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
}

pub struct AsyncDnsResolver<Q> {
    pub upstream: Q,
    pub cache: Option<DnsCache>,
}

impl<Q: AsyncDnsQuery> AsyncDnsResolver<Q> {
    pub fn new(upstream: Q) -> Self {
        Self {
            upstream,
            cache: None,
        }
    }

    pub fn with_cache(mut self, cache: DnsCache) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            if let Some(cache) = &self.cache
                && let Some(response) = cache.get(domain, record_type)?
            {
                return Ok(response);
            }
            let response = self.upstream.query(domain, record_type).await?;
            if let Some(cache) = &self.cache {
                cache.insert(domain.clone(), record_type, response.clone())?;
            }
            Ok(response)
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
                    result.v4 = self.query(domain, DnsRecordType::A).await?.addresses.v4;
                    result.v6 = self.query(domain, DnsRecordType::Aaaa).await?.addresses.v6;
                }
                ResolveStrategy::PreferIpv6 => {
                    result.v6 = self.query(domain, DnsRecordType::Aaaa).await?.addresses.v6;
                    result.v4 = self.query(domain, DnsRecordType::A).await?.addresses.v4;
                }
            }
            Ok(result)
        })
    }
}

impl<Q: SendAsyncDnsQuery> AsyncDnsResolver<Q> {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            if let Some(cache) = &self.cache
                && let Some(response) = cache.get(domain, record_type)?
            {
                return Ok(response);
            }
            let response = self.upstream.query_send(domain, record_type).await?;
            if let Some(cache) = &self.cache {
                cache.insert(domain.clone(), record_type, response.clone())?;
            }
            Ok(response)
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
                    result.v4 = self
                        .query_send(domain, DnsRecordType::A)
                        .await?
                        .addresses
                        .v4;
                    result.v6 = self
                        .query_send(domain, DnsRecordType::Aaaa)
                        .await?
                        .addresses
                        .v6;
                }
                ResolveStrategy::PreferIpv6 => {
                    result.v6 = self
                        .query_send(domain, DnsRecordType::Aaaa)
                        .await?
                        .addresses
                        .v6;
                    result.v4 = self
                        .query_send(domain, DnsRecordType::A)
                        .await?
                        .addresses
                        .v4;
                }
            }
            Ok(result)
        })
    }
}

impl<Q: SendAsyncDnsQuery> AsyncIpResolver for AsyncDnsResolver<Q> {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        self.resolve_send(domain, strategy)
    }
}

impl<Q: AsyncDnsQuery> AsyncDnsHandler for AsyncDnsResolver<Q> {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        let question = match decode_query(packet) {
            Ok(question) => question,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        Box::pin(async move {
            let answer = self.query(&question.domain, question.record_type).await?;
            encode_response(packet, &answer)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsResponse, decode_response, encode_query};
    use crate::{Error, ErrorKind};
    use std::net::Ipv4Addr;
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
            let first = resolver.answer(&packet).await.unwrap();
            let second = resolver.answer(&packet).await.unwrap();
            let first = decode_response(&first, 0x4242, DnsRecordType::A).unwrap();
            let second = decode_response(&second, 0x4242, DnsRecordType::A).unwrap();
            assert_eq!(first, second);
            assert_eq!(*calls.lock().unwrap(), 1);
        });
    }
}
