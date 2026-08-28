//! DNS wire and synchronous transport tests.

use super::codec::DnsServiceParamCodec;
use super::*;

#[test]
fn query_round_trip_preserves_id_and_addresses() {
    let domain = DomainName::new("example.com").unwrap();
    let query = encode_query(42, &domain, DnsRecordType::A).unwrap();
    let request = Message::from_vec(&query).unwrap();
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.add_query(request.queries[0].clone());
    response.add_answer(hickory_proto::rr::Record::from_rdata(
        request.queries[0].name().clone(),
        30,
        RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
    ));
    let decoded = decode_response(&response.to_vec().unwrap(), 42, DnsRecordType::A).unwrap();
    assert_eq!(decoded.addresses.v4, vec![Ipv4Addr::new(192, 0, 2, 1)]);
    assert_eq!(decoded.minimum_ttl, Some(30));
}

#[test]
fn synthesized_responses_advertise_recursion_like_go() {
    let domain = DomainName::new("example.com").unwrap();
    let query = encode_query(42, &domain, DnsRecordType::A).unwrap();
    let answer = DnsResponse {
        addresses: IpSet {
            v4: vec![Ipv4Addr::new(192, 0, 2, 1)],
            v6: Vec::new(),
        },
        ptr_names: Vec::new(),
        service_bindings: Vec::new(),
        minimum_ttl: Some(30),
    };

    let response = Message::from_vec(&encode_response(&query, &answer).unwrap()).unwrap();
    assert!(response.metadata.recursion_desired);
    assert!(response.metadata.recursion_available);

    let empty = Message::from_vec(&encode_empty_response(&query).unwrap()).unwrap();
    assert!(empty.metadata.recursion_desired);
    assert!(empty.metadata.recursion_available);
}

#[test]
fn ptr_query_and_response_round_trip_preserves_names_and_ttl() {
    let reverse = DomainName::new("1.0.18.198.in-addr.arpa").unwrap();
    let packet = encode_query(43, &reverse, DnsRecordType::Ptr).unwrap();
    let question = decode_query(&packet).unwrap();
    assert_eq!(question.id, 43);
    assert_eq!(question.domain, reverse);
    assert_eq!(question.record_type, DnsRecordType::Ptr);

    let response = encode_response(
        &packet,
        &DnsResponse {
            addresses: IpSet::default(),
            ptr_names: vec![DomainName::new("host.example.com").unwrap()],
            service_bindings: Vec::new(),
            minimum_ttl: Some(17),
        },
    )
    .unwrap();
    let decoded = decode_response(&response, 43, DnsRecordType::Ptr).unwrap();
    assert_eq!(
        decoded.ptr_names,
        vec![DomainName::new("host.example.com").unwrap()]
    );
    assert_eq!(decoded.minimum_ttl, Some(17));
}

#[test]
fn supported_query_fast_gate_matches_wire_queries_without_allocating() {
    let domain = DomainName::new("example.com").unwrap();
    for record_type in [
        DnsRecordType::A,
        DnsRecordType::Aaaa,
        DnsRecordType::Ptr,
        DnsRecordType::Https,
        DnsRecordType::Svcb,
    ] {
        let packet = encode_query(7, &domain, record_type).unwrap();
        assert!(looks_like_supported_query(&packet));
    }

    let mut response = encode_query(7, &domain, DnsRecordType::A).unwrap();
    response[2] |= 0x80;
    assert!(!looks_like_supported_query(&response));

    let mut unsupported = encode_raw_query(7, &domain, 16).unwrap();
    assert!(!looks_like_supported_query(&unsupported));
    unsupported[0] = 0;
    assert!(!looks_like_supported_query(&unsupported[..8]));

    let mut invalid_pointer = vec![0; 18];
    invalid_pointer[5] = 1;
    invalid_pointer[12..14].copy_from_slice(&[0xc0, 0xff]);
    invalid_pointer[14..16].copy_from_slice(&1u16.to_be_bytes());
    invalid_pointer[16..18].copy_from_slice(&1u16.to_be_bytes());
    assert!(!looks_like_supported_query(&invalid_pointer));
}

#[test]
fn https_and_svcb_round_trip_preserves_targets_hints_and_unknown_params() {
    let binding = DnsServiceBinding {
        priority: 1,
        target: Some(DomainName::new("svc.example.com").unwrap()),
        params: vec![
            DnsServiceParam::Ipv6Hint(vec!["2001:db8::7".parse().unwrap()]),
            DnsServiceParam::Unknown {
                key: 65_400,
                value: vec![0xde, 0xad, 0xbe, 0xef],
            },
            DnsServiceParam::Alpn(vec!["h2".to_owned(), "http/1.1".to_owned()]),
            DnsServiceParam::Port(8443),
            DnsServiceParam::Ipv4Hint(vec![Ipv4Addr::new(192, 0, 2, 7)]),
            DnsServiceParam::Ech(vec![1, 2, 3, 4]),
            DnsServiceParam::Mandatory(vec![1, 3, 4]),
            DnsServiceParam::NoDefaultAlpn,
        ],
    };
    let mut expected = binding.clone();
    expected.params.sort_by_key(|parameter| parameter.key());
    let alias = DnsServiceBinding {
        priority: 0,
        target: None,
        params: Vec::new(),
    };
    for (id, record_type) in [(44, DnsRecordType::Https), (45, DnsRecordType::Svcb)] {
        let domain = DomainName::new("example.com").unwrap();
        let query = encode_query(id, &domain, record_type).unwrap();
        let response = encode_response(
            &query,
            &DnsResponse {
                addresses: IpSet::default(),
                ptr_names: Vec::new(),
                service_bindings: vec![binding.clone(), alias.clone()],
                minimum_ttl: Some(19),
            },
        )
        .unwrap();
        let decoded = decode_response(&response, id, record_type).unwrap();
        assert_eq!(
            decoded.service_bindings,
            vec![expected.clone(), alias.clone()]
        );
        assert_eq!(decoded.minimum_ttl, Some(19));
    }
}

#[test]
fn malformed_packet_is_rejected() {
    assert!(decode_response(&[0, 1, 2], 1, DnsRecordType::A).is_err());
}

#[test]
fn bounded_random_dns_wire_never_panics() {
    let mut state = 0x243f_6a88_u32;
    for length in 0..2048 {
        let mut packet = vec![0u8; length];
        for byte in &mut packet {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        let _ = decode_query(&packet);
        let _ = decode_response(&packet, 7, DnsRecordType::A);
        let _ = decode_response(&packet, 7, DnsRecordType::Aaaa);
        let _ = decode_response(&packet, 7, DnsRecordType::Https);
        let _ = decode_response(&packet, 7, DnsRecordType::Svcb);
        let _ = answer_query(&packet, &RandomWireHandler);
    }
}

struct RandomWireHandler;

impl DnsHandler for RandomWireHandler {
    fn resolve(&self, _domain: &DomainName, _record_type: DnsRecordType) -> Result<DnsResponse> {
        Ok(DnsResponse {
            addresses: IpSet::default(),
            ptr_names: Vec::new(),
            service_bindings: Vec::new(),
            minimum_ttl: Some(1),
        })
    }
}

struct EchoTransport;

impl DohTransport for EchoTransport {
    fn post_dns_message(
        &self,
        _endpoint: &str,
        body: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>> {
        let request = Message::from_vec(body)
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
        let mut response = Message::response(request.metadata.id, request.metadata.op_code);
        response.add_query(request.queries[0].clone());
        response.add_answer(hickory_proto::rr::Record::from_rdata(
            request.queries[0].name().clone(),
            15,
            RData::A(Ipv4Addr::new(198, 51, 100, 1).into()),
        ));
        response
            .to_vec()
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
    }
}

#[test]
fn doh_client_uses_transport_boundary_and_dns_codec() {
    let client = DohClient {
        endpoint: "https://resolver.example/dns-query".to_owned(),
        timeout: Duration::from_secs(1),
        transport: EchoTransport,
    };
    let result = client
        .query(&DomainName::new("example.com").unwrap(), DnsRecordType::A)
        .unwrap();
    assert_eq!(result.addresses.v4, vec![Ipv4Addr::new(198, 51, 100, 1)]);
}

struct CountingResolver {
    calls: std::sync::atomic::AtomicUsize,
}

impl DnsHandler for CountingResolver {
    fn resolve(&self, _domain: &DomainName, _record_type: DnsRecordType) -> Result<DnsResponse> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(DnsResponse {
            addresses: IpSet {
                v4: vec![Ipv4Addr::new(203, 0, 113, 8)],
                v6: Vec::new(),
            },
            ptr_names: Vec::new(),
            service_bindings: Vec::new(),
            minimum_ttl: Some(60),
        })
    }
}

#[test]
fn dns_cache_reuses_entries_and_evicts_by_capacity() {
    let cache = DnsCache::new(1).unwrap();
    let resolver = CountingResolver {
        calls: std::sync::atomic::AtomicUsize::new(0),
    };
    let handler = CachingDnsHandler {
        upstream: resolver,
        cache: cache.clone(),
    };
    let first = DomainName::new("first.example").unwrap();
    let second = DomainName::new("second.example").unwrap();
    handler.resolve(&first, DnsRecordType::A).unwrap();
    handler.resolve(&first, DnsRecordType::A).unwrap();
    assert_eq!(
        handler
            .upstream
            .calls
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    handler.resolve(&second, DnsRecordType::A).unwrap();
    assert_eq!(cache.len().unwrap(), 1);
    assert!(cache.get(&first, DnsRecordType::A).unwrap().is_none());
}

#[test]
fn dns_cache_promotes_hits_before_evicting_the_least_recent_entry() {
    let cache = DnsCache::new(2).unwrap();
    let response = |address| DnsResponse {
        addresses: IpSet {
            v4: vec![address],
            v6: Vec::new(),
        },
        ptr_names: Vec::new(),
        service_bindings: Vec::new(),
        minimum_ttl: Some(60),
    };
    let first = DomainName::new("first.example").unwrap();
    let second = DomainName::new("second.example").unwrap();
    let third = DomainName::new("third.example").unwrap();
    cache
        .insert(
            first.clone(),
            DnsRecordType::A,
            response(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .unwrap();
    cache
        .insert(
            second.clone(),
            DnsRecordType::A,
            response(Ipv4Addr::new(192, 0, 2, 2)),
        )
        .unwrap();

    // A hit must move `first` to the MRU position. Inserting `third`
    // therefore evicts `second`, not the entry that was inserted first.
    assert!(cache.get(&first, DnsRecordType::A).unwrap().is_some());
    cache
        .insert(
            third.clone(),
            DnsRecordType::A,
            response(Ipv4Addr::new(192, 0, 2, 3)),
        )
        .unwrap();
    assert!(cache.get(&first, DnsRecordType::A).unwrap().is_some());
    assert!(cache.get(&second, DnsRecordType::A).unwrap().is_none());
    assert!(cache.get(&third, DnsRecordType::A).unwrap().is_some());
}

#[test]
fn raw_dns_cache_has_the_same_lru_promotion_behavior() {
    let cache = DnsCache::new(2).unwrap();
    let packet = |id, domain: &DomainName, address| {
        let query = encode_query(id, domain, DnsRecordType::A).unwrap();
        encode_response(
            &query,
            &DnsResponse {
                addresses: IpSet {
                    v4: vec![address],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(60),
            },
        )
        .unwrap()
    };
    let first = DomainName::new("first.example").unwrap();
    let second = DomainName::new("second.example").unwrap();
    let third = DomainName::new("third.example").unwrap();
    cache
        .insert_raw(
            first.clone(),
            1,
            packet(1, &first, Ipv4Addr::new(192, 0, 2, 1)),
        )
        .unwrap();
    cache
        .insert_raw(
            second.clone(),
            1,
            packet(2, &second, Ipv4Addr::new(192, 0, 2, 2)),
        )
        .unwrap();
    assert!(cache.get_raw_optimistic(&first, 1).unwrap().is_some());
    cache
        .insert_raw(
            third.clone(),
            1,
            packet(3, &third, Ipv4Addr::new(192, 0, 2, 3)),
        )
        .unwrap();
    assert!(cache.get_raw_optimistic(&first, 1).unwrap().is_some());
    assert!(cache.get_raw_optimistic(&second, 1).unwrap().is_none());
    assert!(cache.get_raw_optimistic(&third, 1).unwrap().is_some());
}

#[test]
fn oversized_udp_dns_response_sets_truncation_without_returning_answers() {
    // A legacy client without EDNS advertises the RFC 1035 512-byte
    // limit. `encode_query` intentionally adds EDNS(0), so construct the
    // legacy form explicitly for this truncation test.
    let mut query_message =
        Message::new(0x1234, MessageType::Query, hickory_proto::op::OpCode::Query);
    query_message.add_query(Query::query(
        Name::from_utf8("large.example.").unwrap(),
        RecordType::A,
    ));
    let query = query_message.to_vec().unwrap();
    let answer = DnsResponse {
        addresses: IpSet {
            v4: (0..128)
                .map(|index| Ipv4Addr::new(192, 0, 2, (index % 250) as u8))
                .collect(),
            v6: Vec::new(),
        },
        ptr_names: Vec::new(),
        service_bindings: Vec::new(),
        minimum_ttl: Some(60),
    };
    let response = encode_response(&query, &answer).unwrap();
    assert!(response.len() > 512);
    let truncated = truncate_dns_response(&query, &response).unwrap();
    assert!(response_is_truncated(&truncated).unwrap());
    assert!(Message::from_vec(&truncated).unwrap().answers.is_empty());
}

#[test]
fn zero_capacity_dns_cache_is_rejected() {
    assert!(DnsCache::new(0).is_err());
}

struct StaticHandler;
impl DnsHandler for StaticHandler {
    fn resolve(&self, _domain: &DomainName, _record_type: DnsRecordType) -> Result<DnsResponse> {
        Ok(DnsResponse {
            addresses: IpSet {
                v4: vec![Ipv4Addr::new(203, 0, 113, 7)],
                v6: Vec::new(),
            },
            ptr_names: Vec::new(),
            service_bindings: Vec::new(),
            minimum_ttl: Some(30),
        })
    }
}

#[test]
fn udp_dns_server_answers_local_client_and_policy_can_block() {
    let server = UdpDnsServer::bind("127.0.0.1:0".parse().unwrap(), StaticHandler, 128).unwrap();
    let address = server.local_addr().unwrap();
    let server_thread = std::thread::spawn(move || server.serve_once().unwrap());
    let client = UdpDnsClient {
        server: address,
        timeout: Duration::from_secs(1),
        max_packet_size: 512,
    };
    let domain = DomainName::new("example.com").unwrap();
    let response = client.query(&domain, DnsRecordType::A).unwrap();
    assert_eq!(response.addresses.v4, vec![Ipv4Addr::new(203, 0, 113, 7)]);
    assert_eq!(server_thread.join().unwrap(), 45);

    let blocked = PolicyDnsHandler {
        upstream: StaticHandler,
        policy: DnsPolicy::Block,
    };
    assert_eq!(
        blocked.resolve(&domain, DnsRecordType::A).unwrap_err().kind,
        ErrorKind::Closed
    );
    let empty = PolicyDnsHandler {
        upstream: StaticHandler,
        policy: DnsPolicy::Empty,
    };
    assert!(
        empty
            .resolve(&domain, DnsRecordType::A)
            .unwrap()
            .addresses
            .is_empty()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn async_dns_policy_is_cancellable_when_owner_drops_future() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct PendingResolver {
        dropped: Arc<AtomicBool>,
    }
    impl AsyncDnsHandler for PendingResolver {
        fn answer<'a>(&'a self, _packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
            let dropped = Arc::clone(&self.dropped);
            Box::pin(async move {
                struct Guard(Arc<AtomicBool>);
                impl Drop for Guard {
                    fn drop(&mut self) {
                        self.0.store(true, Ordering::Release);
                    }
                }
                let _guard = Guard(dropped);
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(Vec::new())
            })
        }
    }

    let dropped = Arc::new(AtomicBool::new(false));
    let resolver = AsyncPolicyDnsHandler {
        upstream: PendingResolver {
            dropped: Arc::clone(&dropped),
        },
        policy: DnsPolicy::Upstream,
    };
    let packet = encode_query(
        7,
        &DomainName::new("example.com").unwrap(),
        DnsRecordType::A,
    )
    .unwrap();
    let mut future = resolver.answer(&packet);
    tokio::select! {
        _ = &mut future => panic!("pending DNS resolver unexpectedly completed"),
        _ = tokio::time::sleep(Duration::from_millis(5)) => {}
    }
    drop(future);
    assert!(dropped.load(Ordering::Acquire));

    let blocked = AsyncPolicyDnsHandler {
        upstream: PendingResolver { dropped },
        policy: DnsPolicy::Block,
    };
    assert_eq!(
        blocked.answer(&packet).await.unwrap_err().kind,
        ErrorKind::Closed
    );
}
