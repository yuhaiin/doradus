//! Synchronous resolver tests.

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
