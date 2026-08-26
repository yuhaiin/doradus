use super::*;
use crate::RuntimeSnapshot;
use base64::Engine;
use std::sync::Arc;
use yuhaiin_core::dns_resolver::SystemAsyncIpResolver;
use yuhaiin_core::{FlowContext, GeoLookup, RouteMode};
use yuhaiin_protocol::YuubinsyaUdpServer;
use yuhaiin_protocol::proxy::FixedAsyncProxy;
use yuhaiin_protocol::proxy_factory::{BaseProxyConfig, BaseProxyKind};
use yuhaiin_protocol::trojan::{self, Command};
use yuhaiin_store::GoProxyLayer;
use yuhaiin_store::GoProxyTransport;
use yuhaiin_trie::router::{RouteDecision, Router, RouterRuntime};

fn snapshot(config: GoProxyRuntimeConfig) -> RuntimeSnapshot {
    snapshot_with_resolver(config, Arc::new(SystemAsyncIpResolver))
}

fn snapshot_with_resolver(
    config: GoProxyRuntimeConfig,
    resolver: Arc<dyn AsyncIpResolver>,
) -> RuntimeSnapshot {
    RuntimeSnapshot {
        settings: crate::RuntimeSettings::default(),
        connect_semaphore: Arc::new(tokio::sync::Semaphore::new(250)),
        socket_bind_addresses: Arc::from(Vec::<std::net::IpAddr>::new().into_boxed_slice()),
        socket_bind_interface: None,
        resolver: Arc::clone(&resolver),
        inbound_resolver: Arc::clone(&resolver),
        dns_resolver: resolver,
        hosts: yuhaiin_core::dns_hosts::HostsTable::new(),
        fakeip: None,
        inbound_fakeip: None,
        inbound_settings: yuhaiin_store::InboundSettings::default(),
        resolvers: Vec::new(),
        route: None,
        route_rules: Vec::new(),
        node_tags: Vec::new(),
        route_lists: Arc::new(crate::RouteListSnapshot::default()),
        router: RouterRuntime::new(
            Router::compile(
                Vec::new(),
                RouteDecision {
                    mode: yuhaiin_core::RouteMode::Direct,
                    resolver_policy: yuhaiin_core::ResolverPolicy::default(),
                    priority: 0,
                },
            )
            .unwrap(),
        ),
        resolver_by_id: std::collections::BTreeMap::new(),
        inbound_resolver_by_id: std::collections::BTreeMap::new(),
        dns_resolver_by_id: std::collections::BTreeMap::new(),
        resolver_errors: std::collections::BTreeMap::new(),
        resolver_registry_enabled: false,
        geo_metadata: Vec::new(),
        geo: None,
        proxies: vec![config],
        nat: yuhaiin_store::NatConfigRecord::default(),
    }
}

#[tokio::test]
async fn loopback_stream_wrapper_preserves_outbound_local_address() {
    let detector = LoopbackDetector::new();
    let (stream, _peer) = tokio::io::duplex(64);
    let local = "127.0.0.1:41000".parse().unwrap();
    let remote = "198.51.100.20:443".parse().unwrap();
    let stream = with_stream_socket_addrs(Box::new(stream), Some(local), Some(remote));

    let tracked = track_stream(&detector, stream);

    assert_eq!(stream_local_addr(&*tracked), Some(local));
    assert_eq!(stream_remote_addr(&*tracked), Some(remote));
}

#[test]
fn node_tag_parser_accepts_legacy_and_extended_member_shapes() {
    let legacy = yuhaiin_store::GoNodeTagRecord {
        id: "edge".to_owned(),
        name: "edge".to_owned(),
        members_json: br#"{"type":"node","hash":"node-a"}"#.to_vec(),
        updated_at: 1,
    };
    let parsed = parse_node_tag(&legacy).unwrap();
    assert_eq!(parsed.kind, "node");
    assert_eq!(parsed.targets, ["node-a"]);

    let extended = yuhaiin_store::GoNodeTagRecord {
        id: "mirror".to_owned(),
        name: "mirror".to_owned(),
        members_json: br#"{"type":"mirror","hash":["edge"],"strategy":"round_robin"}"#.to_vec(),
        updated_at: 1,
    };
    let parsed = parse_node_tag(&extended).unwrap();
    assert_eq!(parsed.kind, "mirror");
    assert_eq!(parsed.targets, ["edge"]);
    assert!(parsed.round_robin);
}

#[test]
fn node_tag_mirror_resolution_stops_on_cycles() {
    let definitions = BTreeMap::from([
        (
            "a".to_owned(),
            NodeTagDefinition {
                kind: "mirror".to_owned(),
                targets: vec!["b".to_owned()],
                round_robin: false,
            },
        ),
        (
            "b".to_owned(),
            NodeTagDefinition {
                kind: "mirror".to_owned(),
                targets: vec!["a".to_owned()],
                round_robin: false,
            },
        ),
        (
            "edge".to_owned(),
            NodeTagDefinition {
                kind: "node".to_owned(),
                targets: vec!["node-a".to_owned(), "node-b".to_owned()],
                round_robin: false,
            },
        ),
    ]);
    assert!(resolve_node_tag_targets("a", &definitions, &mut BTreeSet::new()).is_empty());
    assert_eq!(
        resolve_node_tag_targets("edge", &definitions, &mut BTreeSet::new()),
        ["node-a", "node-b"]
    );
}

#[cfg(feature = "doh-tls")]
#[test]
fn tls_termination_preserves_go_certificate_name_and_byte_shapes() {
    assert_eq!(tls_termination_name("example.com"), "*.example.com");
    assert_eq!(tls_termination_name("*.Example.COM."), "*.example.com");
    assert_eq!(tls_termination_name("127.0.0.1"), "127.0.0.1");

    let value = serde_json::json!({
        "cert": [1, 2, 255],
        "keyBase64": base64::engine::general_purpose::STANDARD.encode([3u8, 4, 5]),
    });
    let object = value.as_object().unwrap();
    assert_eq!(
        tls_termination_bytes(object, &["cert"], &[], "cert").unwrap(),
        [1, 2, 255]
    );
    assert_eq!(
        tls_termination_bytes(object, &["keyBase64"], &[], "key").unwrap(),
        [3, 4, 5]
    );

    // Workspace tests execute the compiled harness in a minimal Podman
    // image that only mounts `/target`; use the harness itself as a
    // portable readable file instead of assuming the source tree exists.
    let harness = std::env::current_exe().unwrap();
    let file_value = serde_json::json!({
        "certFile": harness,
        "keyFile": harness,
    });
    let file_object = file_value.as_object().unwrap();
    assert!(
        !tls_termination_bytes(file_object, &[], &["certFile"], "cert")
            .unwrap()
            .is_empty()
    );
    assert!(
        !tls_termination_bytes(file_object, &[], &["keyFile"], "key")
            .unwrap()
            .is_empty()
    );
}

#[cfg(feature = "doh-tls")]
#[test]
fn tls_termination_selects_exact_then_single_label_wildcard_and_allows_default_fallback() {
    let named = BTreeMap::from([
        ("api.example.com".to_owned(), "exact"),
        ("*.example.com".to_owned(), "wildcard"),
    ]);
    assert_eq!(
        tls_termination_match_name(Some("API.EXAMPLE.COM."), &named),
        Some(&"exact")
    );
    assert_eq!(
        tls_termination_match_name(Some("cdn.example.com"), &named),
        Some(&"wildcard")
    );
    assert!(tls_termination_match_name(Some("deep.cdn.example.com"), &named).is_none());
    assert!(tls_termination_match_name(None, &named).is_none());
}

#[cfg(feature = "doh-tls")]
#[test]
fn tls_termination_rejects_empty_certificate_set_before_runtime_use() {
    let config = GoProxyRuntimeConfig {
        id: "tls-termination-empty".to_owned(),
        name: "tls-termination-empty".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["tls_termination".to_owned()],
        layers: vec![GoProxyLayer {
            kind: "tls_termination".to_owned(),
            config: serde_json::json!({"tls": {"certificates": []}}),
        }],
        transport: GoProxyTransport::TlsTermination,
        data_json: br#"{"chain":[]}"#.to_vec(),
    };
    let parent = Arc::new(DirectAsyncProxy {
        timeout: Duration::from_secs(1),
    });
    let error = match build_tls_termination_proxy(&config, parent) {
        Ok(_) => panic!("empty TLS termination certificate set must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("TLS termination"));
}

#[tokio::test]
async fn node_set_proxy_retries_a_failed_member() {
    let failed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let failed_address = failed_listener.local_addr().unwrap();
    drop(failed_listener);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = listener.accept().await.unwrap();
    });
    let proxy = NodeSetProxy::new(
        vec![
            Arc::new(FixedAsyncProxy {
                address: failed_address,
                timeout: Duration::from_secs(1),
            }),
            Arc::new(FixedAsyncProxy {
                address,
                timeout: Duration::from_secs(1),
            }),
        ],
        true,
    )
    .unwrap();
    let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    assert!(proxy.connect(&context).await.is_ok());
    server.await.unwrap();
}

#[tokio::test]
async fn runtime_selector_uses_node_tag_for_tcp_and_udp() {
    let config = GoProxyRuntimeConfig {
        id: "tagged-node".to_owned(),
        name: "tagged-node".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let mut snapshot = snapshot(config);
    snapshot.node_tags.push(yuhaiin_store::GoNodeTagRecord {
        id: "edge".to_owned(),
        name: "edge".to_owned(),
        members_json: br#"{"type":"node","hash":["tagged-node"]}"#.to_vec(),
        updated_at: 1,
    });
    let selector = snapshot
        .build_proxy_selector("", "", "", "", Duration::from_secs(1))
        .await
        .unwrap();
    for network in [yuhaiin_core::Network::Tcp, yuhaiin_core::Network::Udp] {
        let mut context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            network,
            "192.0.2.1:443".parse().unwrap(),
        ));
        context.route_mode = RouteMode::Proxy;
        context.tag = Some("edge".to_owned());
        let selected = selector.select(&context);
        let tagged = if network == yuhaiin_core::Network::Udp {
            selector
                .udp_tagged
                .read()
                .unwrap()
                .get("edge")
                .cloned()
                .unwrap()
        } else {
            selector
                .tagged
                .read()
                .unwrap()
                .get("edge")
                .cloned()
                .unwrap()
        };
        assert!(Arc::ptr_eq(&selected, &tagged));
    }
}

#[test]
fn base_proxy_build_uses_shared_snapshot_config_without_a_dto() {
    let config = GoProxyRuntimeConfig {
        id: "direct".to_owned(),
        name: "Direct".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let built = block_on(snapshot(config).build_proxy("direct", Duration::from_secs(1))).unwrap();
    assert_eq!(built.config.id, "direct");
    let _ = BaseProxyConfig {
        kind: BaseProxyKind::Direct,
        timeout: Duration::from_secs(1),
    };
}

#[tokio::test]
async fn runtime_builds_go_http_mock_around_a_fixed_parent() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let expected =
                b"GET / HTTP/1.1\r\nHost: www.speedtest.cn\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n";
        let mut request = vec![0u8; expected.len()];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(request, expected);
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });

    let config = GoProxyRuntimeConfig {
        id: "http-mock".to_owned(),
        name: "HTTP mock".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "http_mock".to_owned()],
        layers: vec![
            GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [{
                        "host": address.ip().to_string(),
                        "port": address.port()
                    }]
                }),
            },
            GoProxyLayer {
                kind: "http_mock".to_owned(),
                config: serde_json::json!({"data": []}),
            },
        ],
        transport: GoProxyTransport::HttpMock,
        data_json: Vec::new(),
    };
    let proxy = snapshot(config)
        .build_proxy("http-mock", Duration::from_secs(1))
        .await
        .unwrap()
        .proxy;
    let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    let mut stream = proxy.connect(&context).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");
    server.await.unwrap();
}

#[cfg(feature = "http-termination")]
#[tokio::test]
async fn runtime_builds_go_http_termination_around_a_fixed_parent() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
        assert!(
            request.starts_with("get /runtime http/1.1\r\n"),
            "request={request:?}"
        );
        assert!(
            request.contains("host: runtime.example:80\r\n"),
            "request={request:?}"
        );
        assert!(
            request.contains("x-runtime: http-termination\r\n"),
            "request={request:?}"
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nruntime")
            .await
            .unwrap();
    });
    let config = GoProxyRuntimeConfig {
        id: "http-termination".to_owned(),
        name: "HTTP termination".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "http_termination".to_owned()],
        layers: vec![
            GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [{
                        "host": address.ip().to_string(),
                        "port": address.port()
                    }]
                }),
            },
            GoProxyLayer {
                kind: "http_termination".to_owned(),
                config: serde_json::json!({
                    "headers": {
                        "runtime.example": {
                            "headers": [{"key": "X-Runtime", "value": "http-termination"}]
                        }
                    }
                }),
            },
        ],
        transport: GoProxyTransport::HttpTermination,
        data_json: Vec::new(),
    };
    let proxy = snapshot(config)
        .build_proxy("http-termination", Duration::from_secs(1))
        .await
        .unwrap()
        .proxy;
    let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    let mut stream = proxy.connect(&context).await.unwrap();
    stream
        .write_all(
            b"GET /runtime HTTP/1.1\r\nHost: runtime.example:80\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(b"runtime"));
    proxy.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn runtime_network_split_dispatches_tcp_and_udp_branches() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 4];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });
    let config = GoProxyRuntimeConfig {
        id: "network-split".to_owned(),
        name: "network split".to_owned(),
        group_name: "default".to_owned(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "network_split".to_owned()],
        layers: vec![
            GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [{
                        "host": target.ip().to_string(),
                        "port": target.port()
                    }]
                }),
            },
            GoProxyLayer {
                kind: "network_split".to_owned(),
                config: serde_json::json!({
                    "tcp": {
                        "type": "proxy",
                        "proxy": {}
                    },
                    "udp": {"type": "drop", "drop": {}}
                }),
            },
        ],
        transport: GoProxyTransport::NetworkSplit,
        data_json: Vec::new(),
    };
    let proxy = snapshot(config)
        .build_proxy("network-split", Duration::from_secs(1))
        .await
        .unwrap()
        .proxy;

    let tcp_context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        target,
    ));
    let mut stream = proxy.connect(&tcp_context).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");

    let udp_context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Udp,
        "127.0.0.1:53".parse().unwrap(),
    ));
    let datagram = proxy.open_datagram(&udp_context).await.unwrap();
    assert_eq!(
        datagram
            .send_to(b"drop", udp_context.destination.clone())
            .await
            .unwrap(),
        4
    );
    let mut dropped = [0u8; 8];
    let error = match datagram.recv_from(&mut dropped).await {
        Ok(_) => panic!("UDP must be dispatched to the drop branch"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Closed);

    datagram.close().await.unwrap();
    proxy.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn runtime_network_split_wraps_http2_tcp_branch_over_parent() {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut connection = h2::server::handshake(socket).await.unwrap();
        while let Some(result) = connection.accept().await {
            let (request, mut respond) = result.unwrap();
            assert_eq!(request.method(), ::http::Method::CONNECT);
            assert_eq!(request.uri().host(), Some("localhost"));
            tokio::spawn(async move {
                let mut body = request.into_body();
                let mut send = respond
                    .send_response(::http::Response::new(()), false)
                    .unwrap();
                while let Some(data) = body.data().await {
                    let Ok(data) = data else { break };
                    if body.flow_control().release_capacity(data.len()).is_err()
                        || send.send_data(data, false).is_err()
                    {
                        break;
                    }
                }
                let _ = send.send_data(Bytes::new(), true);
            });
        }
    });
    let config = GoProxyRuntimeConfig {
        id: "network-split-http2".to_owned(),
        name: "network split HTTP/2".to_owned(),
        group_name: "default".to_owned(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "network_split".to_owned()],
        layers: vec![
            GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [{
                        "host": target.ip().to_string(),
                        "port": target.port()
                    }]
                }),
            },
            GoProxyLayer {
                kind: "network_split".to_owned(),
                config: serde_json::json!({
                    "tcp": {
                        "type": "http2",
                        "http2": {"concurrency": 1, "max_streams": 1}
                    },
                    "udp": {"type": "direct", "direct": {}}
                }),
            },
        ],
        transport: GoProxyTransport::NetworkSplit,
        data_json: Vec::new(),
    };
    let proxy = snapshot(config)
        .build_proxy("network-split-http2", Duration::from_secs(1))
        .await
        .unwrap()
        .proxy;
    let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    let mut stream = proxy.connect(&context).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"ping");

    proxy.close().await.unwrap();
    server.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn runtime_builds_wireguard_from_go_layer() {
    let key = |value| base64::engine::general_purpose::STANDARD.encode([value; 32]);
    let config = GoProxyRuntimeConfig {
        id: "wireguard".to_owned(),
        name: "WireGuard".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["wireguard".to_owned()],
        layers: vec![GoProxyLayer {
            kind: "wireguard".to_owned(),
            config: serde_json::json!({
                "secretKey": key(1),
                "endpoint": ["10.0.0.2/32"],
                "reserved": "AAAA",
                "peers": [{
                    "publicKey": key(2),
                    "endpoint": "127.0.0.1:51820",
                    "allowedIps": ["0.0.0.0/0"]
                }]
            }),
        }],
        transport: GoProxyTransport::Wireguard,
        data_json: Vec::new(),
    };
    let built = snapshot(config)
        .build_proxy("wireguard", Duration::from_secs(1))
        .await
        .unwrap();
    built.proxy.close().await.unwrap();
}

struct MappingResolver {
    address: std::net::Ipv4Addr,
    queries: Arc<Mutex<Vec<String>>>,
}

impl AsyncIpResolver for MappingResolver {
    fn resolve<'a>(
        &'a self,
        domain: &'a yuhaiin_core::DomainName,
        _strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        self.queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(domain.to_string());
        let address = self.address;
        Box::pin(async move {
            Ok(IpSet {
                v4: vec![address],
                v6: Vec::new(),
            })
        })
    }
}

fn snapshot_with_localhost_resolver(config: GoProxyRuntimeConfig) -> RuntimeSnapshot {
    snapshot_with_resolver(
        config,
        Arc::new(MappingResolver {
            address: std::net::Ipv4Addr::LOCALHOST,
            queries: Arc::new(Mutex::new(Vec::new())),
        }),
    )
}

#[tokio::test(flavor = "current_thread")]
async fn runtime_wireguard_resolves_peer_and_domain_targets_with_configured_resolver() {
    let key = |value| base64::engine::general_purpose::STANDARD.encode([value; 32]);
    let config = GoProxyRuntimeConfig {
        id: "wireguard-domain".to_owned(),
        name: "WireGuard domain".to_owned(),
        group_name: "default".to_owned(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["wireguard".to_owned()],
        layers: vec![GoProxyLayer {
            kind: "wireguard".to_owned(),
            config: serde_json::json!({
                "secretKey": key(3),
                "endpoint": ["10.0.0.2/32"],
                "peers": [{
                    "publicKey": key(4),
                    "endpoint": "peer-resolver-only.invalid:51820",
                    "allowedIps": ["0.0.0.0/0"]
                }]
            }),
        }],
        transport: GoProxyTransport::Wireguard,
        data_json: Vec::new(),
    };
    let queries = Arc::new(Mutex::new(Vec::new()));
    let resolver = Arc::new(MappingResolver {
        address: std::net::Ipv4Addr::LOCALHOST,
        queries: Arc::clone(&queries),
    });
    let built = snapshot_with_resolver(config, resolver)
        .build_proxy("wireguard-domain", Duration::from_secs(1))
        .await
        .unwrap();
    let context = FlowContext::new(Endpoint::domain(
        yuhaiin_core::Network::Tcp,
        yuhaiin_core::DomainName::new("resolver-only.invalid").unwrap(),
        80,
    ));
    let _stream = built.proxy.connect(&context).await.unwrap();
    built.proxy.close().await.unwrap();

    assert_eq!(
        queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_slice(),
        ["peer-resolver-only.invalid", "resolver-only.invalid"]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn standalone_build_proxy_resolves_domain_destinations() {
    let config = GoProxyRuntimeConfig {
        id: "direct".to_owned(),
        name: "Direct".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let built = snapshot_with_localhost_resolver(config)
        .build_proxy("direct", Duration::from_secs(1))
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut payload = [0u8; 18];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
            .await
            .unwrap();
        payload
    });
    let context = FlowContext::new(yuhaiin_core::Endpoint::domain(
        yuhaiin_core::Network::Tcp,
        yuhaiin_core::DomainName::new("localhost").unwrap(),
        address.port(),
    ));
    let mut stream = built.proxy.connect(&context).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"standalone-resolve")
        .await
        .unwrap();
    assert_eq!(server.await.unwrap(), *b"standalone-resolve");
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn runtime_proxy_carries_node_network_interface_into_direct_socket() {
    let config = GoProxyRuntimeConfig {
        id: "direct-interface".to_owned(),
        name: "Direct interface".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: vec![GoProxyLayer {
            kind: "direct".to_owned(),
            config: serde_json::json!({ "network_interface": "lo" }),
        }],
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let built = snapshot(config)
        .build_proxy("direct-interface", Duration::from_secs(1))
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
    let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        address,
    ));
    let mut stream = built.proxy.connect(&context).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"interface")
        .await
        .unwrap();
    let mut accepted = server.await.unwrap();
    let mut payload = [0u8; 9];
    tokio::io::AsyncReadExt::read_exact(&mut accepted, &mut payload)
        .await
        .unwrap();
    assert_eq!(&payload, b"interface");
}

#[test]
fn proxy_selector_assembles_snapshot_proxies_and_safe_builtin_slots() {
    let config = GoProxyRuntimeConfig {
        id: "proxy".to_owned(),
        name: "Proxy".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let selector = block_on(snapshot(config).build_proxy_selector(
        "",
        "proxy",
        "",
        "",
        Duration::from_secs(1),
    ))
    .unwrap();

    let mut context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    context.route_mode = RouteMode::Proxy;
    context.skip_route = true;
    let selected = selector.select(&context);
    context.route_mode = RouteMode::Direct;
    let direct = selector.select(&context);
    assert!(!Arc::ptr_eq(&selected, &direct));
}

#[test]
fn proxy_selector_uses_independent_tcp_and_udp_selected_nodes() {
    let make_direct = |id: &str| GoProxyRuntimeConfig {
        id: id.to_owned(),
        name: id.to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let mut snapshot = snapshot(make_direct("tcp-node"));
    snapshot.proxies.push(make_direct("udp-node"));
    let selector = block_on(snapshot.build_proxy_selector_with_udp(
        "",
        "tcp-node",
        "udp-node",
        "",
        "",
        Duration::from_secs(1),
    ))
    .unwrap();

    let mut tcp = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    tcp.route_mode = RouteMode::Proxy;
    let mut udp = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Udp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    udp.route_mode = RouteMode::Proxy;
    udp.skip_route = true;

    let tcp_proxy = selector.select(&tcp);
    let udp_proxy = selector.select(&udp);
    assert!(!Arc::ptr_eq(&tcp_proxy, &udp_proxy));
    assert!(selector.active_node_ids().contains(&"udp-node".to_owned()));
    selector.route_context(&mut udp);
    assert_eq!(udp.outbound.as_deref(), Some("udp-node"));
}

#[test]
fn runtime_selector_blocks_inbound_listener_cycle_before_route_rules() {
    let config = GoProxyRuntimeConfig {
        id: "proxy".to_owned(),
        name: "Proxy".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let selector = block_on(snapshot(config).build_proxy_selector(
        "",
        "proxy",
        "",
        "",
        Duration::from_secs(1),
    ))
    .unwrap();
    let address = "127.0.0.1:18080".parse().unwrap();
    let mut context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        address,
    ));
    context.local_addr = Some(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        address,
    ));

    selector.route_context(&mut context);

    assert_eq!(context.route_mode, RouteMode::Block);
    assert!(context.skip_route);
    assert_eq!(context.tag.as_deref(), Some("loopback cycle"));
}

#[tokio::test(flavor = "current_thread")]
async fn selector_resolves_domain_for_direct_socket_without_losing_protocol_domain() {
    let config = GoProxyRuntimeConfig {
        id: "proxy".to_owned(),
        name: "Proxy".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let selector = snapshot_with_localhost_resolver(config)
        .build_proxy_selector("", "proxy", "", "", Duration::from_secs(1))
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut payload = [0u8; 15];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
            .await
            .unwrap();
        payload
    });

    let mut context = FlowContext::new(yuhaiin_core::Endpoint::domain(
        yuhaiin_core::Network::Tcp,
        yuhaiin_core::DomainName::new("localhost").unwrap(),
        address.port(),
    ));
    context.route_mode = RouteMode::Proxy;
    let selected = selector.select(&context);
    let mut stream = selected.connect(&context).await.unwrap();
    assert_eq!(
        context.effective_destination().host().unwrap().as_str(),
        "localhost"
    );
    assert!(context.resolved_destination.is_none());
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"resolved-domain")
        .await
        .unwrap();
    assert_eq!(server.await.unwrap(), *b"resolved-domain");
}

#[tokio::test(flavor = "current_thread")]
async fn tun_fakeip_domain_uses_non_fakeip_resolver_for_direct_socket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut payload = [0u8; 18];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
            .await
            .unwrap();
        payload
    });

    let fake_queries = Arc::new(Mutex::new(Vec::new()));
    let fake_resolver = Arc::new(MappingResolver {
        address: "198.18.0.1".parse().unwrap(),
        queries: Arc::clone(&fake_queries),
    });
    let real_queries = Arc::new(Mutex::new(Vec::new()));
    let real_resolver = Arc::new(MappingResolver {
        address: address.ip().to_string().parse().unwrap(),
        queries: Arc::clone(&real_queries),
    });
    let config = GoProxyRuntimeConfig {
        id: "direct".to_owned(),
        name: "Direct".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let mut snapshot = snapshot_with_resolver(config, fake_resolver);
    snapshot.dns_resolver = real_resolver;
    let selector = snapshot
        .build_proxy_selector("", "", "", "", Duration::from_secs(1))
        .await
        .unwrap();

    let fake_ip = "198.18.0.1".parse().unwrap();
    let domain = yuhaiin_core::DomainName::new("ip.sb").unwrap();
    let mut context = FlowContext::new(Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        SocketAddr::new(fake_ip, address.port()),
    ));
    context.original_domain = Some(domain);
    context.fake_ip = Some(fake_ip.to_string());
    context.route_mode = RouteMode::Direct;
    let proxy = selector.select(&context);
    let mut stream = proxy.connect(&context).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"fakeip-real-target")
        .await
        .unwrap();

    assert_eq!(server.await.unwrap(), *b"fakeip-real-target");
    assert!(
        fake_queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
    );
    assert_eq!(
        real_queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_slice(),
        ["ip.sb"]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn tagged_direct_node_uses_proxy_resolver_for_proxy_mode_tun_fakeip() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut payload = [0u8; 16];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
            .await
            .unwrap();
        payload
    });

    let fake_queries = Arc::new(Mutex::new(Vec::new()));
    let fake_resolver: Arc<dyn AsyncIpResolver> = Arc::new(MappingResolver {
        address: "198.18.0.1".parse().unwrap(),
        queries: Arc::clone(&fake_queries),
    });
    let real_queries = Arc::new(Mutex::new(Vec::new()));
    let real_resolver: Arc<dyn AsyncIpResolver> = Arc::new(MappingResolver {
        address: address.ip().to_string().parse().unwrap(),
        queries: Arc::clone(&real_queries),
    });
    let config = GoProxyRuntimeConfig {
        id: "direct-node".to_owned(),
        name: "Direct node".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let mut snapshot = snapshot_with_resolver(config, Arc::clone(&fake_resolver));
    snapshot.route = Some(yuhaiin_store::GoRouteRuntimeConfig {
        direct_resolver: "direct".to_owned(),
        proxy_resolver: "proxy".to_owned(),
        resolve_locally: false,
        udp_proxy_fqdn: yuhaiin_store::GoUdpProxyFqdnStrategy::Resolve,
    });
    snapshot
        .dns_resolver_by_id
        .insert("direct".to_owned(), Arc::clone(&fake_resolver));
    snapshot
        .dns_resolver_by_id
        .insert("proxy".to_owned(), real_resolver);
    snapshot.resolver_registry_enabled = true;
    snapshot.node_tags.push(yuhaiin_store::GoNodeTagRecord {
        id: "edge".to_owned(),
        name: "edge".to_owned(),
        members_json: br#"{"type":"node","hash":["direct-node"]}"#.to_vec(),
        updated_at: 1,
    });

    let selector = snapshot
        .build_proxy_selector("", "", "", "", Duration::from_secs(1))
        .await
        .unwrap();
    let fake_ip = "198.18.0.1".parse().unwrap();
    let domain = yuhaiin_core::DomainName::new("www.baidu.com").unwrap();
    let mut context = FlowContext::new(Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        SocketAddr::new(fake_ip, address.port()),
    ));
    context.original_domain = Some(domain);
    context.fake_ip = Some(fake_ip.to_string());
    // A node tag is selected in Proxy mode, while the selected node's
    // protocol is direct. This is the exact TUN route shape reported by
    // the UI and must still use the non-FakeIP Proxy resolver.
    context.route_mode = RouteMode::Proxy;
    context.tag = Some("edge".to_owned());

    let proxy = selector.select(&context);
    let mut stream = proxy.connect(&context).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"tagged-direct-ok")
        .await
        .unwrap();

    assert_eq!(server.await.unwrap(), *b"tagged-direct-ok");
    assert!(
        fake_queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
    );
    assert_eq!(
        real_queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_slice(),
        ["www.baidu.com"]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn selector_resolves_domain_for_direct_udp_even_when_proxy_dns_is_skipped() {
    let config = GoProxyRuntimeConfig {
        id: "proxy".to_owned(),
        name: "Proxy".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let selector = snapshot_with_localhost_resolver(config)
        .build_proxy_selector("", "proxy", "", "", Duration::from_secs(1))
        .await
        .unwrap();
    let destination = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = destination.local_addr().unwrap().port();
    let mut context = FlowContext::new(yuhaiin_core::Endpoint::domain(
        yuhaiin_core::Network::Udp,
        yuhaiin_core::DomainName::new("localhost").unwrap(),
        port,
    ));
    context.route_mode = RouteMode::Proxy;
    context.resolver_policy.udp_skip_resolve_target = true;

    selector
        .select(&context)
        .open_datagram(&context)
        .await
        .expect("direct transport must resolve its own UDP target");
}

#[tokio::test(flavor = "current_thread")]
async fn live_selector_reload_replaces_data_plane_settings() {
    let config = GoProxyRuntimeConfig {
        id: "proxy".to_owned(),
        name: "Proxy".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let mut first = snapshot(config.clone());
    first.settings.udp_buffer_size = 4096;
    first.settings.relay_buffer_size = 8192;
    first.settings.udp_ringbuffer_size = 512;
    first.socket_bind_addresses =
        Arc::from(vec!["127.0.0.2".parse::<std::net::IpAddr>().unwrap()].into_boxed_slice());
    let selector = first
        .build_proxy_selector("", "proxy", "", "", Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(selector.udp_buffer_size(), 4096);
    assert_eq!(selector.relay_buffer_size(), 8192);
    assert_eq!(selector.udp_ringbuffer_size(), 512);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || listener.accept().unwrap().0.peer_addr().unwrap());
    let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        address,
    ));
    let _stream = selector.select(&context).connect(&context).await.unwrap();
    assert_eq!(
        peer.join().unwrap().ip(),
        "127.0.0.2".parse::<std::net::IpAddr>().unwrap()
    );

    let mut next = snapshot(config);
    next.settings.udp_buffer_size = 2048;
    next.settings.relay_buffer_size = 2049;
    next.settings.udp_ringbuffer_size = 100;
    next.socket_bind_addresses =
        Arc::from(vec!["127.0.0.2".parse::<std::net::IpAddr>().unwrap()].into_boxed_slice());
    let prepared = selector.prepare(&next).await.unwrap();
    selector.replace(prepared);
    assert_eq!(selector.udp_buffer_size(), 2048);
    assert_eq!(selector.relay_buffer_size(), 2049);
    assert_eq!(selector.udp_ringbuffer_size(), 100);
}

struct TestGeo;

impl GeoLookup for TestGeo {
    fn country_code(&self, _address: std::net::IpAddr) -> yuhaiin_core::Result<Option<String>> {
        Ok(Some("ZZ".to_owned()))
    }
}

#[test]
fn selector_populates_hosts_and_outbound_geo_before_proxy_connect() {
    let config = GoProxyRuntimeConfig {
        id: "proxy".to_owned(),
        name: "Proxy".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let mut snapshot = snapshot(config);
    let domain = yuhaiin_core::DomainName::new("hosts.example").unwrap();
    snapshot
        .hosts
        .insert_ip(domain.clone(), "192.0.2.44".parse().unwrap())
        .unwrap();
    snapshot.geo = Some(Arc::new(TestGeo));
    let selector =
        block_on(snapshot.build_proxy_selector("", "proxy", "", "", Duration::from_secs(1)))
            .unwrap();

    let mut context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.44:443".parse().unwrap(),
    ));
    context.original_domain = Some(domain);
    context.route_mode = RouteMode::Direct;
    selector.route_context(&mut context);

    assert_eq!(context.hosts.as_deref(), Some("hosts.example:443"));
    assert_eq!(context.outbound_geo.as_deref(), Some("ZZ"));
    assert_eq!(
        context.outbound_addr,
        Some(Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.44:443".parse().unwrap(),
        ))
    );
}

#[tokio::test]
async fn trojan_outbound_wraps_fixed_parent_and_preserves_connect_payload() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let hash = trojan::password_hash(b"secret");
        let request = trojan::read_request(&mut stream, &hash).await.unwrap();
        assert_eq!(request.command, Command::Connect);
        let mut payload = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, &payload)
            .await
            .unwrap();
    });
    let parent: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
        address,
        timeout: Duration::from_secs(2),
    });
    let proxy = yuhaiin_protocol::trojan::TrojanProxy::new(parent, "secret");
    let destination = yuhaiin_core::Endpoint::domain(
        yuhaiin_core::Network::Tcp,
        yuhaiin_core::DomainName::new("example.com").unwrap(),
        443,
    );
    let context = yuhaiin_core::FlowContext::new(destination);
    let mut stream = proxy.connect(&context).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"hello")
        .await
        .unwrap();
    let mut echoed = [0u8; 5];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut echoed)
        .await
        .unwrap();
    assert_eq!(&echoed, b"hello");
    server.await.unwrap();
}

#[tokio::test]
async fn go_aead_layer_builds_stream_transport_over_fixed_parent() {
    let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_address = tcp_listener.local_addr().unwrap();
    let tcp_server = tokio::spawn(async move {
        let (stream, _) = tcp_listener.accept().await.unwrap();
        let mut stream = yuhaiin_protocol::aead::server(
            Box::new(stream),
            b"secret",
            yuhaiin_protocol::aead::CryptoMethod::XChacha20Poly1305,
        )
        .await
        .unwrap();
        let mut payload = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, &payload)
            .await
            .unwrap();
    });
    let config = GoProxyRuntimeConfig {
        id: "aead".to_owned(),
        name: "aead".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "aead".to_owned()],
        layers: vec![
            GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [{"host": "127.0.0.1", "port": tcp_address.port()}]
                }),
            },
            GoProxyLayer {
                kind: "aead".to_owned(),
                config: serde_json::json!({
                    "password": "secret",
                    "cryptoMethod": "AeadCryptoMethod_XChacha20Poly1305"
                }),
            },
        ],
        transport: GoProxyTransport::Aead,
        data_json: serde_json::json!({"chain": []}).to_string().into_bytes(),
    };
    let built = snapshot(config)
        .build_proxy("aead", Duration::from_secs(2))
        .await
        .unwrap();
    let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    let mut stream = built.proxy.connect(&context).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"hello")
        .await
        .unwrap();
    let mut echoed = [0u8; 5];
    tokio::io::AsyncReadExt::read_exact(&mut stream, &mut echoed)
        .await
        .unwrap();
    assert_eq!(&echoed, b"hello");
    tcp_server.await.unwrap();
}

#[tokio::test]
async fn go_aead_layer_builds_authenticated_udp_over_fixed_parent() {
    let udp_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_address = udp_socket.local_addr().unwrap();
    let udp_server = tokio::spawn(async move {
        let mut packet = [0u8; 2048];
        let (length, peer) = udp_socket.recv_from(&mut packet).await.unwrap();
        let payload = yuhaiin_protocol::aead::decrypt_packet(
            &packet[..length],
            b"secret",
            yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
        )
        .unwrap();
        assert_eq!(payload, b"udp-hello");
        let reply = yuhaiin_protocol::aead::encrypt_packet(
            b"udp-world",
            b"secret",
            yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
        )
        .unwrap();
        udp_socket.send_to(&reply, peer).await.unwrap();
    });
    let config = GoProxyRuntimeConfig {
        id: "aead-udp".to_owned(),
        name: "aead-udp".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "aead".to_owned()],
        layers: vec![
            GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [{"host": "127.0.0.1", "port": udp_address.port()}]
                }),
            },
            GoProxyLayer {
                kind: "aead".to_owned(),
                config: serde_json::json!({"password": "secret"}),
            },
        ],
        transport: GoProxyTransport::Aead,
        data_json: serde_json::json!({"chain": []}).to_string().into_bytes(),
    };
    let built = snapshot(config)
        .build_proxy("aead-udp", Duration::from_secs(2))
        .await
        .unwrap();
    let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Udp,
        "192.0.2.1:5353".parse().unwrap(),
    ));
    let datagram = built.proxy.open_datagram(&context).await.unwrap();
    let target = context.effective_destination();
    datagram.send_to(b"udp-hello", target).await.unwrap();
    let mut response = [0u8; 64];
    let (length, _) = datagram.recv_from(&mut response).await.unwrap();
    assert_eq!(&response[..length], b"udp-world");
    udp_server.await.unwrap();
}

#[tokio::test]
async fn go_trojan_layer_builds_a_runtime_proxy_without_dropping_unknown_fields() {
    let address: std::net::SocketAddr = "127.0.0.1:24443".parse().unwrap();
    let config = GoProxyRuntimeConfig {
        id: "trojan".to_owned(),
        name: "trojan".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "trojan".to_owned()],
        layers: vec![
            yuhaiin_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":address.port()}]}),
            },
            yuhaiin_store::GoProxyLayer {
                kind: "trojan".to_owned(),
                config: serde_json::json!({"password":"secret","futureField":true}),
            },
        ],
        transport: GoProxyTransport::Trojan,
        data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
    };
    let built = snapshot(config)
        .build_proxy("trojan", Duration::from_secs(2))
        .await
        .unwrap();
    let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    assert!(built.proxy.connect(&context).await.is_err());
}

#[tokio::test]
async fn go_shadowsocks_layer_builds_a_runtime_proxy_without_dropping_unknown_fields() {
    let config = GoProxyRuntimeConfig {
        id: "shadowsocks".to_owned(),
        name: "shadowsocks".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "shadowsocks".to_owned()],
        layers: vec![
            yuhaiin_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24444}]}),
            },
            yuhaiin_store::GoProxyLayer {
                kind: "shadowsocks".to_owned(),
                config: serde_json::json!({
                    "method":"AEAD_AES_256_GCM",
                    "password":"secret",
                    "futureField":true
                }),
            },
        ],
        transport: GoProxyTransport::Shadowsocks,
        data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
    };
    let built = snapshot(config)
        .build_proxy("shadowsocks", Duration::from_secs(2))
        .await
        .unwrap();
    let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    assert!(built.proxy.connect(&context).await.is_err());
}

#[tokio::test]
async fn go_shadowsocks_obfs_http_layer_builds_before_protocol_framing() {
    let config = GoProxyRuntimeConfig {
        id: "shadowsocks-obfs-http".to_owned(),
        name: "shadowsocks-obfs-http".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec![
            "fixedv2".to_owned(),
            "obfs_http".to_owned(),
            "shadowsocks".to_owned(),
        ],
        layers: vec![
            yuhaiin_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24445}]}),
            },
            yuhaiin_store::GoProxyLayer {
                kind: "obfs_http".to_owned(),
                config: serde_json::json!({"host":"obfs.example","port":"80"}),
            },
            yuhaiin_store::GoProxyLayer {
                kind: "shadowsocks".to_owned(),
                config: serde_json::json!({"method":"AEAD_AES_256_GCM","password":"secret"}),
            },
        ],
        transport: GoProxyTransport::Shadowsocks,
        data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
    };
    let built = snapshot(config)
        .build_proxy("shadowsocks-obfs-http", Duration::from_secs(2))
        .await
        .unwrap();
    let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    assert!(built.proxy.connect(&context).await.is_err());
}

#[tokio::test]
async fn go_shadowsocksr_layer_builds_a_runtime_proxy() {
    let config = GoProxyRuntimeConfig {
        id: "shadowsocksr".to_owned(),
        name: "shadowsocksr".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "shadowsocksr".to_owned()],
        layers: vec![
            yuhaiin_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24447}]}),
            },
            yuhaiin_store::GoProxyLayer {
                kind: "shadowsocksr".to_owned(),
                config: serde_json::json!({
                    "method":"aes-256-ctr",
                    "password":"secret",
                    "protocol":"auth_aes128_md5",
                    "obfs":"plain",
                    "futureField":true
                }),
            },
        ],
        transport: GoProxyTransport::Shadowsocksr,
        data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
    };
    let built = snapshot(config)
        .build_proxy("shadowsocksr", Duration::from_secs(2))
        .await
        .unwrap();
    let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    assert!(built.proxy.connect(&context).await.is_err());
}

#[tokio::test]
async fn go_vless_layer_builds_a_runtime_proxy_without_password_assumption() {
    let config = GoProxyRuntimeConfig {
        id: "vless".to_owned(),
        name: "vless".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "vless".to_owned()],
        layers: vec![
            yuhaiin_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24445}]}),
            },
            yuhaiin_store::GoProxyLayer {
                kind: "vless".to_owned(),
                config: serde_json::json!({
                    "uuid":"00112233-4455-6677-8899-aabbccddeeff",
                    "futureField":true
                }),
            },
        ],
        transport: GoProxyTransport::Vless,
        data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
    };
    let built = snapshot(config)
        .build_proxy("vless", Duration::from_secs(2))
        .await
        .unwrap();
    let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    assert!(built.proxy.connect(&context).await.is_err());
}

#[tokio::test]
async fn go_stream_protocols_build_over_http2_transport_chain() {
    for (name, transport, protocol_layer) in [
        (
            "vless-http2",
            GoProxyTransport::Vless,
            serde_json::json!({
                "type": "vless",
                "vless": {"uuid": "00112233-4455-6677-8899-aabbccddeeff"}
            }),
        ),
        (
            "vmess-http2",
            GoProxyTransport::Vmess,
            serde_json::json!({
                "type": "vmess",
                "vmess": {
                    "id": "00112233-4455-6677-8899-aabbccddeeff",
                    "aid": "0",
                    "security": "aes-128-gcm"
                }
            }),
        ),
        (
            "trojan-http2",
            GoProxyTransport::Trojan,
            serde_json::json!({
                "type": "trojan",
                "trojan": {"password": "runtime-password"}
            }),
        ),
    ] {
        let protocol = protocol_layer["type"].as_str().unwrap();
        let config = GoProxyRuntimeConfig {
            id: name.to_owned(),
            name: name.to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec![
                "fixedv2".to_owned(),
                "http2".to_owned(),
                protocol.to_owned(),
            ],
            layers: vec![yuhaiin_store::GoProxyLayer {
                kind: protocol.to_owned(),
                config: protocol_layer[protocol].clone(),
            }],
            transport,
            data_json: serde_json::to_vec(&serde_json::json!({
                "id": name,
                "chain": [
                    {"type": "fixedv2", "fixedv2": {
                        "addresses": [{"host": "127.0.0.1", "port": 24448}]
                    }},
                    {"type": "http2", "http2": {"concurrency": 1}},
                    protocol_layer
                ]
            }))
            .unwrap(),
        };
        let built = snapshot(config)
            .build_proxy(name, Duration::from_secs(2))
            .await;
        if let Err(error) = built {
            panic!("{name} HTTP/2 transport failed: {error}");
        }
    }
}

#[tokio::test]
async fn go_stream_protocol_http2_rejects_missing_transport_chain() {
    let config = GoProxyRuntimeConfig {
        id: "vless-http2-invalid".to_owned(),
        name: "vless-http2-invalid".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "http2".to_owned(), "vless".to_owned()],
        layers: vec![yuhaiin_store::GoProxyLayer {
            kind: "vless".to_owned(),
            config: serde_json::json!({
                "uuid": "00112233-4455-6677-8899-aabbccddeeff"
            }),
        }],
        transport: GoProxyTransport::Vless,
        data_json: serde_json::to_vec(&serde_json::json!({"chain": []})).unwrap(),
    };
    let error = match snapshot(config)
        .build_proxy("vless-http2-invalid", Duration::from_secs(2))
        .await
    {
        Ok(_) => panic!("invalid HTTP/2 protocol chain unexpectedly built"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::InvalidInput);
    assert!(error.message.contains("chain"));
}

#[tokio::test]
async fn go_vmess_layer_builds_a_modern_runtime_proxy() {
    let config = GoProxyRuntimeConfig {
        id: "vmess".to_owned(),
        name: "vmess".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "vmess".to_owned()],
        layers: vec![
            yuhaiin_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24446}]}),
            },
            yuhaiin_store::GoProxyLayer {
                kind: "vmess".to_owned(),
                config: serde_json::json!({
                    "id":"00112233-4455-6677-8899-aabbccddeeff",
                    "aid":"0",
                    "security":"aes-128-gcm",
                    "futureField":true
                }),
            },
        ],
        transport: GoProxyTransport::Vmess,
        data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
    };
    let built = snapshot(config)
        .build_proxy("vmess", Duration::from_secs(2))
        .await
        .unwrap();
    let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    assert!(built.proxy.connect(&context).await.is_err());
}

#[tokio::test]
async fn go_vmess_legacy_alter_id_builds_runtime_proxy() {
    let config = GoProxyRuntimeConfig {
        id: "vmess-legacy".to_owned(),
        name: "vmess-legacy".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "vmess".to_owned()],
        layers: vec![
            yuhaiin_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24447}]}),
            },
            yuhaiin_store::GoProxyLayer {
                kind: "vmess".to_owned(),
                config: serde_json::json!({
                    "id":"00112233-4455-6677-8899-aabbccddeeff",
                    "aid":"2",
                    "security":"aes-128-gcm"
                }),
            },
        ],
        transport: GoProxyTransport::Vmess,
        data_json: Vec::new(),
    };
    let built = snapshot(config)
        .build_proxy("vmess-legacy", Duration::from_secs(2))
        .await
        .unwrap();
    let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    assert!(built.proxy.connect(&context).await.is_err());
}

#[cfg(feature = "doh-tls")]
#[tokio::test]
async fn go_trojan_layer_builds_tls_transport_before_protocol_wrapper() {
    let config = GoProxyRuntimeConfig {
        id: "trojan-tls".to_owned(),
        name: "trojan-tls".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "tls".to_owned(), "trojan".to_owned()],
        layers: vec![
            yuhaiin_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24443}]}),
            },
            yuhaiin_store::GoProxyLayer {
                kind: "tls".to_owned(),
                config: serde_json::json!({"servernames":["example.com"], "insecure_skip_verify": true}),
            },
            yuhaiin_store::GoProxyLayer {
                kind: "trojan".to_owned(),
                config: serde_json::json!({"password":"secret"}),
            },
        ],
        transport: GoProxyTransport::Trojan,
        data_json: Vec::new(),
    };
    let built = snapshot(config)
        .build_proxy("trojan-tls", Duration::from_secs(2))
        .await
        .unwrap();
    assert!(
        built
            .proxy
            .ping(&FlowContext::new(yuhaiin_core::Endpoint::ip(
                yuhaiin_core::Network::Tcp,
                "192.0.2.1:443".parse().unwrap(),
            )))
            .await
            .is_err()
    );
}

#[test]
fn runtime_builds_native_yuubinsya_udp_from_go_layers() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let password_hash = yuhaiin_protocol::yuubinsya::derive_salt(b"password");
        let server = YuubinsyaUdpServer::bind("127.0.0.1:0".parse().unwrap(), password_hash, false)
            .await
            .unwrap();
        let server_address = server.local_addr().unwrap().addr().unwrap();
        let config = GoProxyRuntimeConfig {
            id: "yuubinsya-udp".to_owned(),
            name: "yuubinsya-udp".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "yuubinsya".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{
                            "host": server_address.ip().to_string(),
                            "port": server_address.port()
                        }]
                    }),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "yuubinsya".to_owned(),
                    config: serde_json::json!({ "password": "password" }),
                },
            ],
            transport: GoProxyTransport::Yuubinsya,
            data_json: Vec::new(),
        };
        let proxy = snapshot(config)
            .build_proxy("yuubinsya-udp", Duration::from_secs(3))
            .await
            .unwrap()
            .proxy;
        let target = yuhaiin_core::Endpoint::domain(
            yuhaiin_core::Network::Udp,
            yuhaiin_core::DomainName::new("example.com").unwrap(),
            53,
        );
        let context = FlowContext::new(target.clone());
        let datagram = proxy.open_datagram(&context).await.unwrap();
        datagram.send_to(b"query", target.clone()).await.unwrap();
        let mut buffer = [0; 64];
        let (length, decoded_target, peer) = server.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"query");
        assert_eq!(decoded_target, target);
        server
            .send_to(b"answer", decoded_target.clone(), peer)
            .await
            .unwrap();
        let (length, response_target) = datagram.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..length], b"answer");
        assert_eq!(response_target, decoded_target);
    });
}

#[test]
fn runtime_builds_simple_go_yuubinsya_uot_chain_without_four_layer_assumption() {
    let config = GoProxyRuntimeConfig {
        id: "yuubinsya-uot".to_owned(),
        name: "yuubinsya-uot".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned(), "yuubinsya".to_owned()],
        layers: vec![
            yuhaiin_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [{ "host": "127.0.0.1", "port": 40501 }]
                }),
            },
            yuhaiin_store::GoProxyLayer {
                kind: "yuubinsya".to_owned(),
                config: serde_json::json!({
                    "password": "password",
                    "udp_over_stream": true,
                    "udp_coalesce": true
                }),
            },
        ],
        transport: GoProxyTransport::Yuubinsya,
        data_json: serde_json::json!({
            "chain": [
                { "type": "fixedv2", "fixedv2": {
                    "addresses": [{ "host": "127.0.0.1", "port": 40501 }]
                }},
                { "type": "yuubinsya", "yuubinsya": {
                    "password": "password",
                    "udp_over_stream": true,
                    "udp_coalesce": true
                }}
            ]
        })
        .to_string()
        .into_bytes(),
    };
    let built =
        block_on(snapshot(config).build_proxy("yuubinsya-uot", Duration::from_secs(1))).unwrap();
    let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    let error = match block_on(built.proxy.connect(&context)) {
        Ok(_) => panic!("simple Yuubinsya UOT must reject TCP stream connect"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Unsupported);
}

#[test]
fn runtime_routes_go_websocket_http2_chain_to_chain_builder() {
    let config = GoProxyRuntimeConfig {
        id: "websocket-chain".to_owned(),
        name: "websocket-chain".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec![
            "fixedv2".to_owned(),
            "websocket".to_owned(),
            "http2".to_owned(),
            "yuubinsya".to_owned(),
        ],
        layers: Vec::new(),
        transport: GoProxyTransport::Yuubinsya,
        data_json: serde_json::json!({
            "chain": [
                {"type": "fixedv2", "fixedv2": {
                    "addresses": [{"host": "127.0.0.1:40501"}]
                }},
                {"type": "websocket", "websocket": {
                    "host": "localhost", "path": "/proxy/ws"
                }},
                {"type": "http2", "http2": {"concurrency": 2}},
                {"type": "yuubinsya", "yuubinsya": {
                    "password": "password"
                }}
            ]
        })
        .to_string()
        .into_bytes(),
    };
    let built =
        block_on(snapshot(config).build_proxy("websocket-chain", Duration::from_secs(1))).unwrap();
    assert_eq!(built.config.id, "websocket-chain");
}

#[tokio::test]
async fn go_chain_upstream_endpoint_bypasses_tun_fakeip_resolver() {
    let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed_listener.local_addr().unwrap().port();
    drop(closed_listener);

    let fake_queries = Arc::new(Mutex::new(Vec::new()));
    let fake_resolver: Arc<dyn AsyncIpResolver> = Arc::new(MappingResolver {
        address: "198.18.0.1".parse().unwrap(),
        queries: Arc::clone(&fake_queries),
    });
    let real_queries = Arc::new(Mutex::new(Vec::new()));
    let real_resolver: Arc<dyn AsyncIpResolver> = Arc::new(MappingResolver {
        address: "127.0.0.1".parse().unwrap(),
        queries: Arc::clone(&real_queries),
    });
    let config = GoProxyRuntimeConfig {
        id: "chain".to_owned(),
        name: "chain".to_owned(),
        group_name: "default".to_owned(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec![
            "fixedv2".to_owned(),
            "tls".to_owned(),
            "http2".to_owned(),
            "yuubinsya".to_owned(),
        ],
        layers: Vec::new(),
        transport: GoProxyTransport::Yuubinsya,
        data_json: serde_json::json!({
            "chain": [
                {"type": "fixedv2", "fixedv2": {
                    "addresses": [{"host": "proxy.example", "port": port}]
                }},
                {"type": "tls", "tls": {
                    "enable": true,
                    "insecure_skip_verify": true,
                    "next_protos": ["h2"],
                    "servernames": ["proxy.example"]
                }},
                {"type": "http2", "http2": {"concurrency": 8}},
                {"type": "yuubinsya", "yuubinsya": {
                    "password": "test-secret",
                    "udp_coalesce": true,
                    "udp_over_stream": true
                }}
            ]
        })
        .to_string()
        .into_bytes(),
    };
    let mut snapshot = snapshot_with_resolver(config, fake_resolver);
    snapshot.dns_resolver = real_resolver;

    let proxy = snapshot
        .build_proxy("chain", Duration::from_secs(1))
        .await
        .unwrap()
        .proxy;
    let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
        yuhaiin_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    let _ = tokio::time::timeout(Duration::from_secs(1), proxy.connect(&context)).await;

    assert!(
        fake_queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
    );
    assert_eq!(
        real_queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_slice(),
        ["proxy.example"]
    );
}

#[cfg(feature = "websocket")]
#[test]
fn runtime_builds_vless_over_websocket_transport_chain() {
    let config = GoProxyRuntimeConfig {
        id: "vless-websocket".to_owned(),
        name: "vless-websocket".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec![
            "fixedv2".to_owned(),
            "websocket".to_owned(),
            "vless".to_owned(),
        ],
        layers: vec![
            GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [{"host": "127.0.0.1", "port": 40501}]
                }),
            },
            GoProxyLayer {
                kind: "websocket".to_owned(),
                config: serde_json::json!({"host": "localhost", "path": "/vless"}),
            },
            GoProxyLayer {
                kind: "vless".to_owned(),
                config: serde_json::json!({
                    "uuid": "00000000-0000-0000-0000-000000000001"
                }),
            },
        ],
        transport: GoProxyTransport::Vless,
        data_json: serde_json::json!({}).to_string().into_bytes(),
    };
    let built =
        block_on(snapshot(config).build_proxy("vless-websocket", Duration::from_secs(1))).unwrap();
    assert_eq!(built.config.id, "vless-websocket");
}

#[cfg(feature = "websocket")]
#[test]
fn runtime_builds_vmess_over_websocket_transport_chain() {
    let config = GoProxyRuntimeConfig {
        id: "vmess-websocket".to_owned(),
        name: "vmess-websocket".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec![
            "fixedv2".to_owned(),
            "websocket".to_owned(),
            "vmess".to_owned(),
        ],
        layers: vec![
            GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [{"host": "127.0.0.1", "port": 40502}]
                }),
            },
            GoProxyLayer {
                kind: "websocket".to_owned(),
                config: serde_json::json!({"host": "localhost", "path": "/vmess"}),
            },
            GoProxyLayer {
                kind: "vmess".to_owned(),
                config: serde_json::json!({
                    "id": "00000000-0000-0000-0000-000000000001",
                    "aid": 0,
                    "security": "auto"
                }),
            },
        ],
        transport: GoProxyTransport::Vmess,
        data_json: serde_json::json!({}).to_string().into_bytes(),
    };
    let built =
        block_on(snapshot(config).build_proxy("vmess-websocket", Duration::from_secs(1))).unwrap();
    assert_eq!(built.config.id, "vmess-websocket");
}

#[cfg(feature = "websocket")]
#[test]
fn runtime_builds_trojan_over_websocket_transport_chain() {
    let config = GoProxyRuntimeConfig {
        id: "trojan-websocket".to_owned(),
        name: "trojan-websocket".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec![
            "fixedv2".to_owned(),
            "websocket".to_owned(),
            "trojan".to_owned(),
        ],
        layers: vec![
            GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [{"host": "127.0.0.1", "port": 40503}]
                }),
            },
            GoProxyLayer {
                kind: "websocket".to_owned(),
                config: serde_json::json!({"host": "localhost", "path": "/trojan"}),
            },
            GoProxyLayer {
                kind: "trojan".to_owned(),
                config: serde_json::json!({"password": "secret"}),
            },
        ],
        transport: GoProxyTransport::Trojan,
        data_json: serde_json::json!({}).to_string().into_bytes(),
    };
    let built =
        block_on(snapshot(config).build_proxy("trojan-websocket", Duration::from_secs(1))).unwrap();
    assert_eq!(built.config.id, "trojan-websocket");
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => return value,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}
