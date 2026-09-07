use super::*;

#[test]
fn runtime_builds_native_yuubinsya_udp_from_go_layers() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let password_hash = doradus_protocol::yuubinsya::derive_salt(b"password");
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
                doradus_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{
                            "host": server_address.ip().to_string(),
                            "port": server_address.port()
                        }]
                    }),
                },
                doradus_store::GoProxyLayer {
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
        let target = doradus_core::Endpoint::domain(
            doradus_core::Network::Udp,
            doradus_core::DomainName::new("example.com").unwrap(),
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

#[cfg(feature = "doh-tls")]
fn quic_test_server_tls() -> Arc<rustls::ServerConfig> {
    const CERTIFICATE_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUA6T+/U88N9aMPipK+MdNsAFRUAUwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNeXVoYWlpbi1wMC1jYTAeFw0yNjA4MDYxODIwNDlaFw0zNjA4
MDMxODIwNDlaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABLPnwlYFERi1MgbJNuBHZV/eSpTGdJCQIOyxBt8LlR1ZTEG06pWy
FnJVIzUS4oPuuHc0RcDEltGb/WolyQlM75SjbTBrMBQGA1UdEQQNMAuCCWxvY2Fs
aG9zdDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUZoMmXETR998IsWt1
UTBOVMIs7jMwHwYDVR0jBBgwFoAUhaYkOXheQ1JzLpIKK4I2FEcRMyMwCgYIKoZI
zj0EAwIDSAAwRQIgGEU+sldusbLVAE/kxzZYXaMpIt6l+CZ0cC2jm7lQBqoCIQCw
M5PhuwMhCCb+dUnK6ueJUMHwyK3l2pIAJTMp9+cwqw==
-----END CERTIFICATE-----
"#;
    const PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqkH6SeIb9vVEJ6WecsMk5Pn/a8sQ+vdNS/ZSkl3KwfoAoGCCqGSM49
AwEHoUQDQgAEs+fCVgURGLUyBsk24EdlX95KlMZ0kJAg7LEG3wuVHVlMQbTqlbIW
clUjNRLig+64dzRFwMSW0Zv9aiXJCUzvlA==
-----END EC PRIVATE KEY-----
"#;
    let certificate = rustls_pemfile::certs(&mut Cursor::new(CERTIFICATE_PEM))
        .next()
        .unwrap()
        .unwrap();
    let private_key = rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY_PEM))
        .unwrap()
        .unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .unwrap(),
    )
}

#[cfg(feature = "doh-tls")]
#[tokio::test]
async fn runtime_wraps_yuubinsya_above_raw_quic() {
    let server = Arc::new(
        QuicServer::new(
            "127.0.0.1:0".parse().unwrap(),
            quic_test_server_tls(),
            QuicServerConfig::default(),
        )
        .unwrap(),
    );
    let server_address = server.local_addr().unwrap();
    let accepting = {
        let server = server.clone();
        tokio::spawn(async move { server.accept().await.unwrap() })
    };
    let config = GoProxyRuntimeConfig {
        id: "yuubinsya-quic".to_owned(),
        name: "yuubinsya-quic".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec![
            "fixedv2".to_owned(),
            "quic".to_owned(),
            "yuubinsya".to_owned(),
        ],
        layers: vec![
            GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [{
                        "host": server_address.ip().to_string(),
                        "port": server_address.port()
                    }]
                }),
            },
            GoProxyLayer {
                kind: "quic".to_owned(),
                config: serde_json::json!({
                    "host": server_address.to_string(),
                    "tls": {
                        "serverName": "localhost",
                        "insecureSkipVerify": true
                    }
                }),
            },
            GoProxyLayer {
                kind: "yuubinsya".to_owned(),
                config: serde_json::json!({ "password": "password" }),
            },
        ],
        transport: GoProxyTransport::Yuubinsya,
        data_json: Vec::new(),
    };
    let proxy = snapshot(config)
        .build_proxy("yuubinsya-quic", Duration::from_secs(3))
        .await
        .unwrap()
        .proxy;
    let target = doradus_core::Endpoint::domain(
        doradus_core::Network::Udp,
        doradus_core::DomainName::new("example.com").unwrap(),
        53,
    );
    let datagram = proxy
        .open_datagram(&FlowContext::new(target.clone()))
        .await
        .unwrap();
    let connection = accepting.await.unwrap();
    datagram.send_to(b"query", target.clone()).await.unwrap();
    let raw_server = connection.accept_datagram().await.unwrap();
    let server_protocol = YuubinsyaUdpServer::new(
        Box::new(raw_server),
        doradus_protocol::yuubinsya::derive_salt(b"password"),
        false,
    );
    let mut buffer = [0; 128];
    let (length, decoded_target, peer) = server_protocol.recv_from(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..length], b"query");
    assert_eq!(decoded_target, target);
    server_protocol
        .send_to(b"answer", decoded_target.clone(), peer)
        .await
        .unwrap();
    let (length, response_target) = datagram.recv_from(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..length], b"answer");
    assert_eq!(response_target, decoded_target);
    proxy.close().await.unwrap();
    server.close();
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
            doradus_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({
                    "addresses": [{ "host": "127.0.0.1", "port": 40501 }]
                }),
            },
            doradus_store::GoProxyLayer {
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
    let context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
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
    let context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
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
