//! Resolver transport tests.

use super::*;
use doradus_core::dns::{
    AsyncDnsHandler, DnsRecordType, DnsResponse, decode_query, encode_response,
};
use doradus_core::dns_tcp::AsyncTcpDnsServer;
use doradus_core::proxy::{
    AsyncDatagram, AsyncProxy, AsyncProxySelector, with_stream_socket_addrs,
};
use doradus_core::{BoxFuture, DomainName, IpSet, ResolveStrategy};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct BridgeProxy {
    calls: Arc<AtomicUsize>,
    fail: bool,
    saw_skip_resolve: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl AsyncProxy for BridgeProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let calls = self.calls.clone();
        let fail = self.fail;
        if let Some(flag) = &self.saw_skip_resolve {
            flag.store(context.skip_resolve, Ordering::Relaxed);
        }
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            if fail {
                Err(Error::new(ErrorKind::Io, "proxy resolver failed"))
            } else {
                let (stream, mut peer) = tokio::io::duplex(64);
                tokio::spawn(async move {
                    let mut buffer = [0u8; 64];
                    let _ = peer.read(&mut buffer).await;
                });
                Ok(with_stream_socket_addrs(
                    Box::new(stream) as BoxAsyncStream,
                    Some("127.0.0.1:41001".parse().unwrap()),
                    Some("192.0.2.10:443".parse().unwrap()),
                ))
            }
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async { Err(Error::new(ErrorKind::Unsupported, "test proxy has no UDP")) })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

struct FixedBridgeSelector {
    proxy: Arc<dyn AsyncProxy>,
}

impl AsyncProxySelector for FixedBridgeSelector {
    fn select(&self, _context: &FlowContext) -> Arc<dyn AsyncProxy> {
        self.proxy.clone()
    }
}

struct RouteModeBridgeSelector {
    direct: Arc<dyn AsyncProxy>,
    proxy: Arc<dyn AsyncProxy>,
}

impl AsyncProxySelector for RouteModeBridgeSelector {
    fn select(&self, context: &FlowContext) -> Arc<dyn AsyncProxy> {
        match context.route_mode {
            RouteMode::Direct => self.direct.clone(),
            RouteMode::Proxy => self.proxy.clone(),
            RouteMode::Bypass | RouteMode::Block => self.direct.clone(),
        }
    }
}

struct ProxyDnsDatagram {
    response: std::sync::Mutex<Option<Vec<u8>>>,
}

impl AsyncDatagram for ProxyDnsDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            assert_eq!(target.network(), Network::Udp);
            let query = decode_query(payload)?;
            let response = encode_response(
                payload,
                &DnsResponse {
                    addresses: IpSet {
                        v4: vec!["192.0.2.123".parse().unwrap()],
                        v6: Vec::new(),
                    },
                    ptr_names: Vec::new(),
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(30),
                },
            )?;
            assert_eq!(query.domain.as_str(), "proxy.example");
            *self
                .response
                .lock()
                .map_err(|_| Error::new(ErrorKind::Closed, "DNS proxy response poisoned"))? =
                Some(response);
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let response = self
                .response
                .lock()
                .map_err(|_| Error::new(ErrorKind::Closed, "DNS proxy response poisoned"))?
                .take()
                .ok_or_else(|| Error::new(ErrorKind::Timeout, "DNS proxy response missing"))?;
            let length = response.len();
            buffer[..length].copy_from_slice(&response);
            Ok((
                length,
                Endpoint::ip(Network::Udp, "127.0.0.1:53".parse().unwrap()),
            ))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(Endpoint::ip(
            Network::Udp,
            "127.0.0.1:40000".parse().unwrap(),
        ))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

struct ProxyDnsProxy {
    udp_calls: Arc<AtomicUsize>,
    tcp_calls: Arc<AtomicUsize>,
}

impl AsyncProxy for ProxyDnsProxy {
    fn connect<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let calls = self.tcp_calls.clone();
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            let (stream, mut peer) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut length = [0u8; 2];
                peer.read_exact(&mut length).await.unwrap();
                let length = u16::from_be_bytes(length) as usize;
                let mut query = vec![0; length];
                peer.read_exact(&mut query).await.unwrap();
                let response = encode_response(
                    &query,
                    &DnsResponse {
                        addresses: IpSet {
                            v4: vec!["192.0.2.124".parse().unwrap()],
                            v6: Vec::new(),
                        },
                        ptr_names: Vec::new(),
                        service_bindings: Vec::new(),
                        minimum_ttl: Some(30),
                    },
                )
                .unwrap();
                peer.write_all(&(response.len() as u16).to_be_bytes())
                    .await
                    .unwrap();
                peer.write_all(&response).await.unwrap();
            });
            Ok(Box::new(stream) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let calls = self.udp_calls.clone();
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(Box::new(ProxyDnsDatagram {
                response: std::sync::Mutex::new(None),
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

struct StaticDnsHandler;

impl AsyncDnsHandler for StaticDnsHandler {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> doradus_core::BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let query = decode_query(packet)?;
            assert_eq!(query.record_type, DnsRecordType::A);
            encode_response(
                packet,
                &DnsResponse {
                    addresses: IpSet {
                        v4: vec!["192.0.2.53".parse().unwrap()],
                        v6: Vec::new(),
                    },
                    ptr_names: Vec::new(),
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(30),
                },
            )
        })
    }
}

fn config(transport: GoResolverTransport, host: &str) -> GoResolverRuntimeConfig {
    GoResolverRuntimeConfig {
        id: "resolver-1".to_owned(),
        transport,
        host: host.to_owned(),
        subnet: None,
        tls_server_name: None,
    }
}

#[test]
fn numeric_dns_server_accepts_common_ipv4_and_ipv6_forms() {
    assert_eq!(
        parse_dns_server("1.1.1.1", 53, "r").unwrap(),
        "1.1.1.1:53".parse().unwrap()
    );
    assert_eq!(
        parse_dns_server("[::1]", 5353, "r").unwrap(),
        "[::1]:5353".parse().unwrap()
    );
    assert_eq!(
        parse_dns_server("192.0.2.53:853", 53, "r").unwrap(),
        "192.0.2.53:853".parse().unwrap()
    );
}

#[test]
fn builtins_construct_system_udp_and_tcp_without_connecting() {
    let factory = BuiltinResolverFactory::new(Duration::from_secs(1), 32);
    assert!(
        factory
            .build(&config(GoResolverTransport::System, "system default"))
            .is_ok()
    );
    assert!(
        factory
            .build(&config(GoResolverTransport::Udp, "192.0.2.53:53"))
            .is_ok()
    );
    assert!(
        factory
            .build(&config(GoResolverTransport::Tcp, "192.0.2.53:53"))
            .is_ok()
    );
}

#[test]
fn builtin_tcp_resolver_performs_an_async_dns_query() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let server = AsyncTcpDnsServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            StaticDnsHandler,
            2048,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let address = server.local_addr().unwrap();
        let factory = BuiltinResolverFactory::new(Duration::from_secs(1), 32);
        let resolver = factory
            .build_with_policy(
                &config(GoResolverTransport::Tcp, &address.to_string()),
                &["127.0.0.2".parse::<IpAddr>().unwrap()],
            )
            .unwrap();
        let domain = DomainName::new("example.com").unwrap();
        let (server_result, resolve_result) = tokio::join!(
            server.serve_once(),
            resolver.resolve(&domain, ResolveStrategy::OnlyIpv4)
        );
        assert!(server_result.unwrap() > 2);
        assert_eq!(
            resolve_result.unwrap().v4,
            vec!["192.0.2.53".parse::<std::net::Ipv4Addr>().unwrap()]
        );
    });
}

#[test]
fn builtin_udp_resolver_uses_the_proxy_chain_for_proxy_dns() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let bridge = Arc::new(ResolverProxyBridge::new());
        let monitor = Arc::new(ConnectionMonitor::new());
        bridge.set_monitor(&monitor);
        bridge.set_proxy_resolver_id(Some("resolver-1"));
        let udp_calls = Arc::new(AtomicUsize::new(0));
        let tcp_calls = Arc::new(AtomicUsize::new(0));
        bridge.set_selector(Arc::new(FixedBridgeSelector {
            proxy: Arc::new(ProxyDnsProxy {
                udp_calls: udp_calls.clone(),
                tcp_calls,
            }),
        }));
        let factory =
            BuiltinResolverFactory::new(Duration::from_secs(1), 32).with_proxy_bridge(bridge);
        let resolver = factory
            .build(&config(GoResolverTransport::Udp, "127.0.0.1:9"))
            .unwrap();
        let domain = DomainName::new("proxy.example").unwrap();
        let addresses = resolver
            .resolve(&domain, ResolveStrategy::OnlyIpv4)
            .await
            .unwrap();
        assert_eq!(
            addresses.v4,
            vec!["192.0.2.123".parse::<std::net::Ipv4Addr>().unwrap()]
        );
        assert_eq!(udp_calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            monitor.all_history_value()["items"][0]["connection"]["component"],
            "dns:resolver-1"
        );
        assert_eq!(
            monitor.all_history_value()["items"][0]["connection"]["resolver"],
            "resolver-1"
        );
    });
}

#[test]
fn builtin_bootstrap_udp_resolver_enters_selector_but_uses_direct_slot() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let bridge = Arc::new(ResolverProxyBridge::new());
        bridge.set_configured_resolver_ids(["bootstrap"]);
        let direct_calls = Arc::new(AtomicUsize::new(0));
        let proxy_calls = Arc::new(AtomicUsize::new(0));
        bridge.set_selector(Arc::new(RouteModeBridgeSelector {
            direct: Arc::new(ProxyDnsProxy {
                udp_calls: direct_calls.clone(),
                tcp_calls: Arc::new(AtomicUsize::new(0)),
            }),
            proxy: Arc::new(ProxyDnsProxy {
                udp_calls: proxy_calls.clone(),
                tcp_calls: Arc::new(AtomicUsize::new(0)),
            }),
        }));
        let factory =
            BuiltinResolverFactory::new(Duration::from_secs(1), 32).with_proxy_bridge(bridge);
        let resolver = factory
            .build(&GoResolverRuntimeConfig {
                id: "bootstrap".to_owned(),
                transport: GoResolverTransport::Udp,
                host: "127.0.0.1:9".to_owned(),
                subnet: None,
                tls_server_name: None,
            })
            .unwrap();
        let domain = DomainName::new("proxy.example").unwrap();
        let addresses = resolver
            .resolve(&domain, ResolveStrategy::OnlyIpv4)
            .await
            .unwrap();
        assert_eq!(
            addresses.v4,
            vec!["192.0.2.123".parse::<std::net::Ipv4Addr>().unwrap()]
        );
        assert_eq!(direct_calls.load(Ordering::Relaxed), 1);
        assert_eq!(proxy_calls.load(Ordering::Relaxed), 0);
    });
}

#[test]
fn builtin_tcp_resolver_uses_the_proxy_chain_for_proxy_dns() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let bridge = Arc::new(ResolverProxyBridge::new());
        bridge.set_proxy_resolver_id(Some("resolver-1"));
        let udp_calls = Arc::new(AtomicUsize::new(0));
        let tcp_calls = Arc::new(AtomicUsize::new(0));
        bridge.set_selector(Arc::new(FixedBridgeSelector {
            proxy: Arc::new(ProxyDnsProxy {
                udp_calls,
                tcp_calls: tcp_calls.clone(),
            }),
        }));
        let factory =
            BuiltinResolverFactory::new(Duration::from_secs(1), 32).with_proxy_bridge(bridge);
        let resolver = factory
            .build(&config(GoResolverTransport::Tcp, "127.0.0.1:9"))
            .unwrap();
        let domain = DomainName::new("proxy.example").unwrap();
        let addresses = resolver
            .resolve(&domain, ResolveStrategy::OnlyIpv4)
            .await
            .unwrap();
        assert_eq!(
            addresses.v4,
            vec!["192.0.2.124".parse::<std::net::Ipv4Addr>().unwrap()]
        );
        assert_eq!(tcp_calls.load(Ordering::Relaxed), 1);
    });
}

#[test]
fn encrypted_transports_require_an_injected_connector() {
    let factory = BuiltinResolverFactory::new(Duration::from_secs(1), 32);
    let error = match factory.build(&config(GoResolverTransport::Doh, "https://dns.example")) {
        Ok(_) => panic!("DoH unexpectedly had a built-in connector"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Unsupported);
}

#[test]
fn resolver_proxy_bridge_routes_configured_resolvers_and_bootstrap_direct() {
    let calls = Arc::new(AtomicUsize::new(0));
    let saw_skip_resolve = Arc::new(AtomicBool::new(false));
    let bridge = ResolverProxyBridge::new();
    bridge.set_proxy_resolver_id(Some("proxy"));
    assert!(bridge.is_proxy_resolver("proxy"));
    assert!(!bridge.is_proxy_resolver("direct"));
    bridge.set_configured_resolver_ids(["direct", "bootstrap"]);
    assert!(bridge.is_proxy_resolver("direct"));
    assert!(!bridge.is_proxy_resolver("bootstrap"));
    assert_eq!(
        bridge.route_mode_for_resolver("bootstrap"),
        Some(RouteMode::Direct)
    );
    bridge.set_selector(Arc::new(FixedBridgeSelector {
        proxy: Arc::new(BridgeProxy {
            calls: calls.clone(),
            fail: false,
            saw_skip_resolve: Some(saw_skip_resolve.clone()),
        }),
    }));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        assert!(
            bridge
                .connect("resolver.example", 443, false)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            bridge
                .connect("resolver.example", 443, true)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            bridge
                .connect_direct_for_resolver("", "resolver.example", 443)
                .await
                .is_ok()
        );
    });
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert!(saw_skip_resolve.load(Ordering::Relaxed));
}

#[test]
fn resolver_proxy_bridge_records_only_actual_proxy_connect_failures() {
    let bridge = ResolverProxyBridge::new();
    let monitor = Arc::new(ConnectionMonitor::new());
    bridge.set_monitor(&monitor);
    bridge.set_selector(Arc::new(FixedBridgeSelector {
        proxy: Arc::new(BridgeProxy {
            calls: Arc::new(AtomicUsize::new(0)),
            fail: true,
            saw_skip_resolve: None,
        }),
    }));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let error = match runtime.block_on(bridge.connect("resolver.example", 443, true)) {
        Ok(_) => panic!("proxy bridge unexpectedly connected"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Io);
    let history = monitor.failed_history_value();
    assert_eq!(history["items"][0]["protocol"], "tcp");
    assert_eq!(history["items"][0]["host"], "resolver.example:443");
}

#[test]
fn resolver_proxy_bridge_records_successful_chain_entries() {
    let bridge = ResolverProxyBridge::new();
    let monitor = Arc::new(ConnectionMonitor::new());
    bridge.set_monitor(&monitor);
    bridge.set_selector(Arc::new(FixedBridgeSelector {
        proxy: Arc::new(BridgeProxy {
            calls: Arc::new(AtomicUsize::new(0)),
            fail: false,
            saw_skip_resolve: None,
        }),
    }));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut stream = bridge
            .connect_for_resolver("resolver-1", "resolver.example", 443, true)
            .await
            .unwrap()
            .unwrap();
        let connection = &monitor.connections_value()["connections"][0];
        assert_eq!(connection["component"], "dns:resolver-1");
        assert_eq!(connection["resolver"], "resolver-1");
        assert_eq!(connection["mode"], "proxy");
        assert_eq!(connection["localAddr"], "127.0.0.1:41001");
        assert_eq!(connection["domain"], "resolver.example");

        stream.write_all(b"query").await.unwrap();
        assert_eq!(monitor.total_flow_value()["upload"], "5");
        drop(stream);
    });

    assert!(
        monitor.connections_value()["connections"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        monitor.all_history_value()["items"][0]["connection"]["component"],
        "dns:resolver-1"
    );
}

#[cfg(feature = "http2")]
#[test]
fn h2_doh_factory_constructs_a_cached_resolver_from_injected_connector() {
    struct DuplexConnector;

    impl DnsOverHttpConnector for DuplexConnector {
        type Stream = tokio::io::DuplexStream;

        fn connect<'a>(
            &'a self,
            _uri: &'a http::Uri,
        ) -> BoxFuture<'a, Result<HttpConnection<Self::Stream>>> {
            Box::pin(async {
                let (stream, _peer) = tokio::io::duplex(4096);
                Ok(HttpConnection {
                    stream,
                    version: HttpVersion::Http2,
                })
            })
        }
    }

    let factory = DnsOverHttpResolverFactory::<_, DuplexConnector>::new(
        Duration::from_secs(1),
        8,
        |_config: &GoResolverRuntimeConfig| -> Result<DuplexConnector> { Ok(DuplexConnector) },
    );
    let resolver = factory
        .build(&config(
            GoResolverTransport::Doh,
            "https://dns.example/dns-query",
        ))
        .unwrap();
    let _ = resolver;
}
