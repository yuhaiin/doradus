use super::*;

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
    let proxy = doradus_protocol::trojan::TrojanProxy::new(parent, "secret");
    let destination = doradus_core::Endpoint::domain(
        doradus_core::Network::Tcp,
        doradus_core::DomainName::new("example.com").unwrap(),
        443,
    );
    let context = doradus_core::FlowContext::new(destination);
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
        let mut stream = doradus_protocol::aead::server(
            Box::new(stream),
            b"secret",
            doradus_protocol::aead::CryptoMethod::XChacha20Poly1305,
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
    let context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
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
        let payload = doradus_protocol::aead::decrypt_packet(
            &packet[..length],
            b"secret",
            doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
        )
        .unwrap();
        assert_eq!(payload, b"udp-hello");
        let reply = doradus_protocol::aead::encrypt_packet(
            b"udp-world",
            b"secret",
            doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
    let context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Udp,
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
            doradus_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":address.port()}]}),
            },
            doradus_store::GoProxyLayer {
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
    let context = doradus_core::FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
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
            doradus_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24444}]}),
            },
            doradus_store::GoProxyLayer {
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
    let context = doradus_core::FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
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
            doradus_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24445}]}),
            },
            doradus_store::GoProxyLayer {
                kind: "obfs_http".to_owned(),
                config: serde_json::json!({"host":"obfs.example","port":"80"}),
            },
            doradus_store::GoProxyLayer {
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
    let context = doradus_core::FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
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
            doradus_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24447}]}),
            },
            doradus_store::GoProxyLayer {
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
    let context = doradus_core::FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
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
            doradus_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24445}]}),
            },
            doradus_store::GoProxyLayer {
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
    let context = doradus_core::FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
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
            layers: vec![doradus_store::GoProxyLayer {
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
        layers: vec![doradus_store::GoProxyLayer {
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
            doradus_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24446}]}),
            },
            doradus_store::GoProxyLayer {
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
    let context = doradus_core::FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
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
            doradus_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24447}]}),
            },
            doradus_store::GoProxyLayer {
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
    let context = doradus_core::FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
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
            doradus_store::GoProxyLayer {
                kind: "fixedv2".to_owned(),
                config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24443}]}),
            },
            doradus_store::GoProxyLayer {
                kind: "tls".to_owned(),
                config: serde_json::json!({"servernames":["example.com"], "insecure_skip_verify": true}),
            },
            doradus_store::GoProxyLayer {
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
            .ping(&FlowContext::new(doradus_core::Endpoint::ip(
                doradus_core::Network::Tcp,
                "192.0.2.1:443".parse().unwrap(),
            )))
            .await
            .is_err()
    );
}
