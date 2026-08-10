//! Unified synchronous DNS resolver facade.
//!
//! UDP, TCP and DoH keep their own transport implementations.  This module
//! composes them behind one `DnsHandler` implementation so Router/TUN code can
//! select a resolver without knowing its wire protocol.  DoH remains injected
//! through [`crate::dns::DohTransport`], which keeps proxy/TLS ownership out of
//! the DNS core.

use std::time::Duration;

use crate::dns::{
    DnsCache, DnsHandler, DnsRecordType, DnsResponse, DohClient, DohTransport, UdpDnsClient,
};
use crate::dns_tcp::TcpDnsClient;
use crate::{DomainName, IpSet, ResolveStrategy, Result};

pub enum ResolverTransport {
    Udp(UdpDnsClient),
    Tcp(TcpDnsClient),
    Doh(DohClient<Box<dyn DohTransport>>),
    Handler(Box<dyn DnsHandler>),
}

pub struct DnsResolver {
    pub transport: ResolverTransport,
    pub cache: Option<DnsCache>,
}

impl DnsResolver {
    pub fn udp(server: std::net::SocketAddr, timeout: Duration) -> Self {
        Self {
            transport: ResolverTransport::Udp(UdpDnsClient {
                server,
                timeout,
                max_packet_size: 4096,
            }),
            cache: None,
        }
    }

    pub fn tcp(server: std::net::SocketAddr, timeout: Duration) -> Self {
        Self {
            transport: ResolverTransport::Tcp(TcpDnsClient {
                server,
                timeout,
                max_packet_size: 65535,
            }),
            cache: None,
        }
    }

    pub fn doh(endpoint: String, timeout: Duration, transport: Box<dyn DohTransport>) -> Self {
        Self {
            transport: ResolverTransport::Doh(DohClient {
                endpoint,
                timeout,
                transport,
            }),
            cache: None,
        }
    }

    pub fn handler(handler: Box<dyn DnsHandler>) -> Self {
        Self {
            transport: ResolverTransport::Handler(handler),
            cache: None,
        }
    }

    pub fn with_cache(mut self, cache: DnsCache) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn query(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        if let Some(cache) = &self.cache
            && let Some(response) = cache.get(domain, record_type)?
        {
            return Ok(response);
        }
        let response = self.query_uncached(domain, record_type)?;
        if let Some(cache) = &self.cache {
            cache.insert(domain.clone(), record_type, response.clone())?;
        }
        Ok(response)
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
                result.v4 = self.query(domain, DnsRecordType::A)?.addresses.v4;
                result.v6 = self.query(domain, DnsRecordType::Aaaa)?.addresses.v6;
            }
            ResolveStrategy::PreferIpv6 => {
                result.v6 = self.query(domain, DnsRecordType::Aaaa)?.addresses.v6;
                result.v4 = self.query(domain, DnsRecordType::A)?.addresses.v4;
            }
        }
        Ok(result)
    }

    fn query_uncached(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
    ) -> Result<DnsResponse> {
        match &self.transport {
            ResolverTransport::Udp(client) => client.query(domain, record_type),
            ResolverTransport::Tcp(client) => client.query(domain, record_type),
            ResolverTransport::Doh(client) => client.query(domain, record_type),
            ResolverTransport::Handler(handler) => handler.resolve(domain, record_type),
        }
    }
}

impl DnsHandler for DnsResolver {
    fn resolve(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        self.query(domain, record_type)
    }
}

impl<T: DohTransport + ?Sized> DohTransport for Box<T> {
    fn post_dns_message(&self, endpoint: &str, body: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        (**self).post_dns_message(endpoint, body, timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{DnsResponse, decode_query, encode_response};
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    struct MockDohTransport {
        calls: Arc<Mutex<usize>>,
    }

    impl DohTransport for MockDohTransport {
        fn post_dns_message(
            &self,
            _endpoint: &str,
            body: &[u8],
            _timeout: Duration,
        ) -> Result<Vec<u8>> {
            *self.calls.lock().unwrap() += 1;
            let _question = decode_query(body)?;
            encode_response(
                body,
                &DnsResponse {
                    addresses: IpSet {
                        v4: vec![Ipv4Addr::new(192, 0, 2, 99)],
                        v6: Vec::new(),
                    },
                    ptr_names: Vec::new(),
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(30),
                },
            )
        }
    }

    #[test]
    fn doh_transport_facade_reuses_cache_and_exposes_dns_handler() {
        let calls = Arc::new(Mutex::new(0));
        let resolver = DnsResolver::doh(
            "https://dns.example/dns-query".to_owned(),
            Duration::from_secs(1),
            Box::new(MockDohTransport {
                calls: calls.clone(),
            }),
        )
        .with_cache(DnsCache::new(8).unwrap());
        let domain = DomainName::new("example.com").unwrap();
        let first = resolver.query(&domain, DnsRecordType::A).unwrap();
        let second = resolver
            .resolve(&domain, ResolveStrategy::OnlyIpv4)
            .unwrap();
        assert_eq!(first.addresses.v4, vec![Ipv4Addr::new(192, 0, 2, 99)]);
        assert_eq!(second.v4, first.addresses.v4);
        assert_eq!(*calls.lock().unwrap(), 1);
        let handler: &dyn DnsHandler = &resolver;
        assert_eq!(handler.resolve(&domain, DnsRecordType::A).unwrap(), first);
    }
}
