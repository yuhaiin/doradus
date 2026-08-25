//! Synchronous resolver facade.

use super::*;

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

    /// Forward a complete DNS message through the selected transport. The raw
    /// cache is keyed by domain and QTYPE, so EDNS/DNSSEC fields are preserved
    /// in the first upstream request while repeated requests reuse the full
    /// response just like Go's resolver client.
    pub fn query_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        validate_query_packet(packet)?;
        let (domain, record_type) = decode_raw_query_key(packet)?;
        if let Some(cache) = &self.cache
            && let Some((response, _expired)) = cache.get_raw_optimistic(&domain, record_type)?
        {
            return rewrite_dns_response_for_query(response, packet);
        }
        let response = match &self.transport {
            ResolverTransport::Udp(client) => client.query_packet(packet),
            ResolverTransport::Tcp(client) => client.query_packet(packet),
            ResolverTransport::Doh(client) => client.query_packet(packet),
            ResolverTransport::Handler(handler) => {
                let question = decode_query(packet)?;
                let answer = handler.resolve(&question.domain, question.record_type)?;
                encode_response(packet, &answer)
            }
        }?;
        if let Some(cache) = &self.cache {
            cache.insert_raw(domain, record_type, response.clone())?;
        }
        rewrite_dns_response_for_query(response, packet)
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
