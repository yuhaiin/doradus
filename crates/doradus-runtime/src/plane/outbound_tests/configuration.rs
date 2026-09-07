use super::*;

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
    let legacy = doradus_store::GoNodeTagRecord {
        id: "edge".to_owned(),
        name: "edge".to_owned(),
        members_json: br#"{"type":"node","hash":"node-a"}"#.to_vec(),
        updated_at: 1,
    };
    let parsed = parse_node_tag(&legacy).unwrap();
    assert_eq!(parsed.kind, "node");
    assert_eq!(parsed.targets, ["node-a"]);

    let extended = doradus_store::GoNodeTagRecord {
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
    let error = match TlsTerminationPlan::compile(&config) {
        Ok(_) => panic!("empty TLS termination certificate set must fail during compile"),
        Err(error) => error,
    };
    let _ = parent;
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
    let context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
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
    snapshot.node_tags.push(doradus_store::GoNodeTagRecord {
        id: "edge".to_owned(),
        name: "edge".to_owned(),
        members_json: br#"{"type":"node","hash":["tagged-node"]}"#.to_vec(),
        updated_at: 1,
    });
    let selector = snapshot
        .build_proxy_selector("", "", "", "", Duration::from_secs(1))
        .await
        .unwrap();
    for network in [doradus_core::Network::Tcp, doradus_core::Network::Udp] {
        let mut context = FlowContext::new(doradus_core::Endpoint::ip(
            network,
            "192.0.2.1:443".parse().unwrap(),
        ));
        context.route_mode = RouteMode::Proxy;
        context.tag = Some("edge".to_owned());
        let selected = selector.select(&context);
        let tagged = selector.tagged_proxy(network, "edge").unwrap();
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
    let context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
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
    let context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
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

    let tcp_context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
        target,
    ));
    let mut stream = proxy.connect(&tcp_context).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"pong");

    let udp_context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Udp,
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
    let context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
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
