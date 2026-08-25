//! Async resolver tests.

use super::system::{rewrite_dns_transaction_id, shared_system_dns_resolver};
use super::*;
use crate::dns::{AsyncDnsHandler, DnsResponse, decode_response, encode_query, encode_response};
use crate::{Error, ErrorKind};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn system_resolver_is_process_shared_and_has_per_client_lru_cache() {
    let first = shared_system_dns_resolver().await.unwrap();
    let second = shared_system_dns_resolver().await.unwrap();

    assert!(Arc::ptr_eq(&first, &second));
    assert!(first.cache.is_some());
    assert!(Arc::ptr_eq(&first.upstream, &second.upstream));
}

struct StaticQuery {
    calls: Arc<Mutex<usize>>,
}

impl SendAsyncDnsQuery for StaticQuery {
    fn query_send<'a>(
        &'a self,
        _domain: &'a DomainName,
        _record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
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

struct CancellableSendQuery {
    calls: Arc<AtomicUsize>,
    started: Arc<Notify>,
}

impl SendAsyncDnsQuery for CancellableSendQuery {
    fn query_send<'a>(
        &'a self,
        _domain: &'a DomainName,
        _record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::Relaxed);
            self.started.notify_one();
            if call == 0 {
                std::future::pending::<()>().await;
            }
            Ok(DnsResponse {
                addresses: IpSet {
                    v4: vec![Ipv4Addr::new(192, 0, 2, 79)],
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

#[tokio::test(flavor = "current_thread")]
async fn async_resolver_cancellation_clears_send_singleflight() {
    let calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let resolver = Arc::new(AsyncDnsResolver::new(CancellableSendQuery {
        calls: calls.clone(),
        started: started.clone(),
    }));
    let domain = DomainName::new("cancelled.example").unwrap();

    let first_resolver = resolver.clone();
    let first_domain = domain.clone();
    let first = tokio::spawn(async move {
        <AsyncDnsResolver<CancellableSendQuery> as AsyncIpResolver>::query(
            &first_resolver,
            &first_domain,
            DnsRecordType::A,
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), started.notified())
        .await
        .expect("singleflight owner did not reach the upstream");

    let second_resolver = resolver.clone();
    let second_domain = domain.clone();
    let second = tokio::spawn(async move {
        <AsyncDnsResolver<CancellableSendQuery> as AsyncIpResolver>::query(
            &second_resolver,
            &second_domain,
            DnsRecordType::A,
        )
        .await
    });
    tokio::task::yield_now().await;

    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());

    let result = tokio::time::timeout(std::time::Duration::from_secs(1), second)
        .await
        .expect("query remained stuck behind a cancelled singleflight owner")
        .unwrap();

    assert!(result.is_ok());
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn async_resolver_cancellation_clears_local_singleflight() {
    let calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let resolver = Arc::new(AsyncDnsResolver::new(SlowQuery {
        calls: calls.clone(),
        started: started.clone(),
        release: release.clone(),
    }));
    let domain = DomainName::new("cancelled-local.example").unwrap();
    let local = tokio::task::LocalSet::new();

    local
        .run_until(async move {
            let first_resolver = resolver.clone();
            let first_domain = domain.clone();
            let first = tokio::task::spawn_local(async move {
                first_resolver.query(&first_domain, DnsRecordType::A).await
            });
            tokio::time::timeout(std::time::Duration::from_secs(1), started.notified())
                .await
                .expect("local singleflight owner did not reach the upstream");

            let second_resolver = resolver.clone();
            let second_domain = domain.clone();
            let second = tokio::task::spawn_local(async move {
                second_resolver
                    .query(&second_domain, DnsRecordType::A)
                    .await
            });
            tokio::task::yield_now().await;

            first.abort();
            assert!(first.await.unwrap_err().is_cancelled());
            tokio::time::timeout(std::time::Duration::from_secs(1), started.notified())
                .await
                .expect("local query remained behind a cancelled singleflight owner");
            release.notify_waiters();

            assert!(second.await.unwrap().is_ok());
            assert_eq!(calls.load(Ordering::Relaxed), 2);
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
        fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
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

    let server =
        crate::dns::AsyncUdpDnsServer::bind((Ipv4Addr::LOCALHOST, 0).into(), PtrHandler, 4096)
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
        client.query(&domain, DnsRecordType::Ptr)
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
