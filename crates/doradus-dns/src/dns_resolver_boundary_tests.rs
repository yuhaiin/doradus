use super::*;
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::{A, opt::EdnsOption};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use std::time::Duration;

#[derive(Default)]
struct RecordingQuery {
    packets: Mutex<Vec<Message>>,
}

impl SendAsyncDnsQuery for RecordingQuery {
    fn query_send<'a>(
        &'a self,
        _: &'a DomainName,
        _: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async { Err(crate::Error::invalid("raw query expected")) })
    }

    fn query_packet_send<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let mut message = Message::from_vec(packet).unwrap();
            self.packets.lock().unwrap().push(message.clone());
            tokio::task::yield_now().await;
            message.metadata.message_type = MessageType::Response;
            message.add_answer(Record::from_rdata(
                message.queries[0].name().clone(),
                30,
                RData::A(A("192.0.2.1".parse().unwrap())),
            ));
            Ok(message.to_vec().unwrap())
        })
    }
}

fn request() -> Message {
    Message::from_vec(
        &crate::dns::encode_raw_query(1, &DomainName::new("cache.example").unwrap(), 1).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn cache_and_singleflight_keep_request_flags_class_and_edns_separate() {
    let resolver =
        AsyncDnsResolver::new(RecordingQuery::default()).with_cache(DnsCache::new(16).unwrap());
    let base = request();
    let mut variants = vec![base.clone()];
    let mut cd = base.clone();
    cd.metadata.checking_disabled = true;
    variants.push(cd);
    let mut dnssec = base.clone();
    dnssec.edns.as_mut().unwrap().set_dnssec_ok(true);
    variants.push(dnssec);
    let mut class = base.clone();
    class.queries[0].set_query_class(DNSClass::CH);
    variants.push(class);
    for value in [1, 2] {
        let mut option = base.clone();
        option
            .edns
            .as_mut()
            .unwrap()
            .options_mut()
            .insert(EdnsOption::Unknown(65001, vec![value]));
        variants.push(option);
    }
    let packets = variants
        .iter()
        .map(|message| message.to_vec().unwrap())
        .collect::<Vec<_>>();
    let results = futures_util::future::join_all(
        packets
            .iter()
            .map(|packet| resolver.query_packet_send(packet)),
    )
    .await;
    for (response, original) in results.into_iter().zip(&variants) {
        let response = Message::from_vec(&response.unwrap()).unwrap();
        assert_eq!(
            response.metadata.checking_disabled,
            original.metadata.checking_disabled
        );
        assert_eq!(
            response.queries[0].query_class(),
            original.queries[0].query_class()
        );
        assert_eq!(response.edns, original.edns);
    }
    assert_eq!(
        resolver.upstream.packets.lock().unwrap().len(),
        variants.len()
    );
    for mut variant in variants.iter().cloned() {
        variant.metadata.id = 99;
        variant.queries[0].set_name(Name::from_ascii("CACHE.Example.").unwrap());
        let response = resolver
            .query_packet_send(&variant.to_vec().unwrap())
            .await
            .unwrap();
        let response = Message::from_vec(&response).unwrap();
        assert_eq!(response.metadata.id, 99);
        assert_eq!(response.queries[0].name().to_ascii(), "CACHE.Example.");
    }
    assert_eq!(
        resolver.upstream.packets.lock().unwrap().len(),
        variants.len()
    );
}

#[tokio::test]
async fn stale_refresh_preserves_original_request_options() {
    let resolver =
        AsyncDnsResolver::new(RecordingQuery::default()).with_cache(DnsCache::new(4).unwrap());
    let mut query = request();
    query.metadata.checking_disabled = true;
    let edns = query.edns.as_mut().unwrap();
    edns.set_dnssec_ok(true);
    edns.options_mut()
        .insert(EdnsOption::Unknown(65001, vec![3, 4]));
    let packet = query.to_vec().unwrap();
    resolver.query_packet_send(&packet).await.unwrap();
    let key = RawDnsCacheKey::from_packet(&packet).unwrap().unwrap();
    resolver
        .cache
        .as_ref()
        .unwrap()
        .advance_packet_for_test(&key, Duration::from_secs(31))
        .unwrap();
    resolver.query_packet_send(&packet).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while resolver.upstream.packets.lock().unwrap().len() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let packets = resolver.upstream.packets.lock().unwrap();
    assert!(packets[1].metadata.checking_disabled);
    assert_eq!(packets[1].edns, query.edns);
    assert_eq!(packets[1].queries, query.queries);
}

#[tokio::test]
async fn multi_question_requests_bypass_cache() {
    let resolver =
        AsyncDnsResolver::new(RecordingQuery::default()).with_cache(DnsCache::new(4).unwrap());
    let mut query = request();
    let mut second = query.queries[0].clone();
    second.set_name(Name::from_ascii("second.example.").unwrap());
    query.add_query(second);
    let packet = query.to_vec().unwrap();
    let (one, two) = tokio::join!(
        resolver.query_packet_send(&packet),
        resolver.query_packet_send(&packet)
    );
    one.unwrap();
    two.unwrap();
    resolver.query_packet_send(&packet).await.unwrap();
    assert_eq!(resolver.upstream.packets.lock().unwrap().len(), 3);
}

#[test]
fn responses_must_match_the_complete_question() {
    let query = request();
    let packet = query.to_vec().unwrap();
    let mut response = query.clone();
    response.metadata.message_type = MessageType::Response;
    let mut variants = Vec::new();
    let mut name = response.clone();
    name.queries[0].set_name(Name::from_ascii("other.example.").unwrap());
    variants.push(name);
    let mut ty = response.clone();
    ty.queries[0].set_query_type(RecordType::AAAA);
    variants.push(ty);
    let mut class = response.clone();
    class.queries[0].set_query_class(DNSClass::CH);
    variants.push(class);
    let mut count = response.clone();
    count.queries.clear();
    variants.push(count);
    let mut opcode = response.clone();
    opcode.metadata.op_code = OpCode::Status;
    variants.push(opcode);
    for variant in variants {
        assert!(crate::dns::validate_response_packet(&packet, &variant.to_vec().unwrap()).is_err());
    }
    response.queries[0].set_name(Name::from_ascii("CACHE.Example.").unwrap());
    crate::dns::validate_response_packet(&packet, &response.to_vec().unwrap()).unwrap();
}
