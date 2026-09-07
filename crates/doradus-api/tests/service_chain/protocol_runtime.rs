use super::*;

pub(super) async fn configure_protocol_outbound_chain(
    service: &ServiceProcess,
    kind: ProtocolOutboundKind,
    inbound: SocketAddr,
    server: SocketAddr,
    udp: bool,
) {
    let node_id = kind.node_id();
    let inbound_id = kind.inbound_id();
    let rule_name = kind.rule_name();
    let protocol_layer = match kind {
        ProtocolOutboundKind::Vless | ProtocolOutboundKind::VlessTlsWebsocket => json!({
            "type":"vless",
            "vless":{"uuid":"00112233-4455-6677-8899-aabbccddeeff"}
        }),
        ProtocolOutboundKind::Vmess | ProtocolOutboundKind::VmessTlsWebsocket => json!({
            "type":"vmess",
            "vmess":{
                "id":"00112233-4455-6677-8899-aabbccddeeff",
                "aid":"0",
                "security":"aes-128-gcm"
            }
        }),
        ProtocolOutboundKind::Trojan => json!({
            "type":"trojan",
            "trojan":{"password":"runtime-protocol-password"}
        }),
        ProtocolOutboundKind::TrojanWebsocket => json!({
            "type":"trojan",
            "trojan":{"password":"runtime-protocol-password"}
        }),
        ProtocolOutboundKind::TrojanTlsWebsocket => json!({
            "type":"trojan",
            "trojan":{"password":"runtime-protocol-password"}
        }),
    };
    let mut chain = vec![json!({
        "type":"fixed",
        "fixed":{"host":"127.0.0.1","port":server.port()}
    })];
    if matches!(
        kind,
        ProtocolOutboundKind::VlessTlsWebsocket
            | ProtocolOutboundKind::VmessTlsWebsocket
            | ProtocolOutboundKind::TrojanTlsWebsocket
    ) {
        chain.push(json!({
            "type":"tls",
            "tls":{
                "enable":true,
                "insecure_skip_verify":true,
                "servernames":["localhost"],
                "next_protos":["http/1.1"],
                "ca_cert":[]
            }
        }));
    }
    if matches!(
        kind,
        ProtocolOutboundKind::VlessTlsWebsocket
            | ProtocolOutboundKind::VmessTlsWebsocket
            | ProtocolOutboundKind::TrojanWebsocket
            | ProtocolOutboundKind::TrojanTlsWebsocket
    ) {
        chain.push(json!({
            "type":"websocket",
            "websocket":{"host":"localhost","path":"/trojan"}
        }));
    }
    chain.push(protocol_layer);
    let node = json!({
        "id":node_id,
        "name":format!("{} runtime protocol outbound", kind.name()),
        "group":"integration",
        "enabled":true,
        "chain":chain
    });
    api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        &format!("/api/v2/nodes/{node_id}/use"),
        None,
    )
    .await;

    let inbound_protocol = if udp {
        json!({"type":"mixed","mixed":{"username":"","password":""}})
    } else {
        json!({"type":"http","http":{"username":"","password":""}})
    };
    let inbound = json!({
        "id":inbound_id,
        "name":format!("{} runtime protocol inbound", kind.name()),
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":if udp { "enabled" } else { "disabled" }}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":inbound_protocol
    });
    api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":rule_name,
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"protocol-integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(120)).await;
}

pub(super) async fn configure_protocol_h2_outbound_chain(
    service: &ServiceProcess,
    kind: ProtocolOutboundKind,
    inbound: SocketAddr,
    server: SocketAddr,
    udp: bool,
) {
    let protocol_layer = match kind {
        ProtocolOutboundKind::Vless | ProtocolOutboundKind::VlessTlsWebsocket => json!({
            "type":"vless",
            "vless":{"uuid":"00112233-4455-6677-8899-aabbccddeeff"}
        }),
        ProtocolOutboundKind::Vmess | ProtocolOutboundKind::VmessTlsWebsocket => json!({
            "type":"vmess",
            "vmess":{
                "id":"00112233-4455-6677-8899-aabbccddeeff",
                "aid":"0",
                "security":"aes-128-gcm"
            }
        }),
        ProtocolOutboundKind::Trojan
        | ProtocolOutboundKind::TrojanWebsocket
        | ProtocolOutboundKind::TrojanTlsWebsocket => json!({
            "type":"trojan",
            "trojan":{"password":"runtime-protocol-password"}
        }),
    };
    let node_id = kind.node_id();
    let node = json!({
        "id":node_id,
        "name":format!("{} runtime HTTP/2 protocol outbound", kind.name()),
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":server.ip().to_string(),"port":server.port()}},
            {"type":"http2","http2":{"concurrency":1,"max_streams":8,"idle_timeout_secs":30}},
            protocol_layer
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        &format!("/api/v2/nodes/{node_id}/use"),
        None,
    )
    .await;

    let inbound = json!({
        "id":kind.inbound_id(),
        "name":kind.inbound_name(),
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":if udp { "enabled" } else { "disabled" }}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":if udp {
            json!({"type":"mixed","mixed":{"username":"","password":""}})
        } else {
            json!({"type":"http","http":{"username":"","password":""}})
        }
    });
    api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;
    let rule = json!({
        "name":kind.rule_name(),
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"protocol-integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(120)).await;
}

pub(super) async fn run_protocol_h2_outbound_chain(kind: ProtocolOutboundKind) {
    run_protocol_h2_outbound_chain_on_host(kind, "127.0.0.1").await;
}

pub(super) async fn run_protocol_h2_outbound_chain_on_host(
    kind: ProtocolOutboundKind,
    bind_host: &str,
) {
    eprintln!(
        "starting HTTP/2 protocol outbound integration: {} host={bind_host}",
        kind.name(),
    );
    let expected_payload: &'static [u8] = match kind {
        ProtocolOutboundKind::Vless => b"runtime-vless-http2-outbound",
        ProtocolOutboundKind::Vmess => b"runtime-vmess-http2-outbound",
        ProtocolOutboundKind::Trojan => b"runtime-trojan-http2-outbound",
        ProtocolOutboundKind::VlessTlsWebsocket
        | ProtocolOutboundKind::VmessTlsWebsocket
        | ProtocolOutboundKind::TrojanWebsocket
        | ProtocolOutboundKind::TrojanTlsWebsocket => {
            panic!("TLS/WebSocket protocol variants are not part of this H2 fixture")
        }
    };
    let protocol_listener = TcpListener::bind((bind_host, 0)).await.unwrap();
    let protocol_server = protocol_listener.local_addr().unwrap();
    let server_task = tokio::spawn(protocol_h2_outbound_server(
        kind,
        protocol_listener,
        expected_payload,
        false,
    ));

    let _default_mixed_blocker = TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound = support::reserve_loopback().await;
    let host_suffix = bind_host.replace([':', '[', ']'], "_");
    let root = integration_dir(&format!(
        "service-{}-runtime-h2-outbound-{host_suffix}",
        kind.name()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_protocol_h2_outbound_chain(&service, kind, inbound, protocol_server, false).await;

    let mut client = connect_loopback(inbound).await;
    client
        .write_all(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
        .await
        .unwrap();
    let mut headers = Vec::new();
    let mut buffer = [0u8; 1024];
    while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        let length = client.read(&mut buffer).await.unwrap();
        assert!(
            length > 0,
            "HTTP inbound closed before H2 protocol response"
        );
        headers.extend_from_slice(&buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));
    client.write_all(expected_payload).await.unwrap();
    let mut echoed = vec![0u8; expected_payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, expected_payload);

    let connections = wait_for_connection(&service.client, &service.base_url).await;
    let item = connections["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == kind.inbound_name())
        .expect("HTTP/2 protocol connection must be visible");
    assert_eq!(item["outbound"], protocol_server.to_string());
    assert_eq!(item["nodeId"], kind.node_id());
    assert_eq!(item["mode"], "proxy");

    client.shutdown().await.unwrap();
    let node_id = kind.node_id();
    let latency = api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        &format!("/api/v2/nodes/{node_id}/latency"),
        Some(&json!({
            "id": node_id,
            "type": "http",
            "url": "http://example.test/health",
            "timeoutMs": 5_000
        })),
    )
    .await;
    assert_eq!(
        latency["ok"], true,
        "HTTP/2 protocol node latency failed: {latency}"
    );
    service.shutdown().await;
    server_task.await.unwrap();
}

pub(super) async fn run_protocol_h2_udp_outbound_chain(kind: ProtocolOutboundKind) {
    eprintln!(
        "starting HTTP/2 protocol UDP outbound integration: {}",
        kind.name()
    );
    let expected_payload: &'static [u8] = match kind {
        ProtocolOutboundKind::Vless => b"runtime-vless-http2-udp-outbound",
        ProtocolOutboundKind::Vmess => b"runtime-vmess-http2-udp-outbound",
        ProtocolOutboundKind::Trojan => b"runtime-trojan-http2-udp-outbound",
        ProtocolOutboundKind::VlessTlsWebsocket
        | ProtocolOutboundKind::VmessTlsWebsocket
        | ProtocolOutboundKind::TrojanWebsocket
        | ProtocolOutboundKind::TrojanTlsWebsocket => {
            panic!("TLS/WebSocket protocol variants are not part of this H2 UDP fixture")
        }
    };
    let protocol_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let protocol_server = protocol_listener.local_addr().unwrap();
    let server_task = tokio::spawn(protocol_h2_outbound_server(
        kind,
        protocol_listener,
        expected_payload,
        true,
    ));

    let _default_mixed_blocker = TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound = support::reserve_loopback().await;
    let root = integration_dir(&format!("service-{}-runtime-h2-udp-outbound", kind.name()));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_protocol_h2_outbound_chain(&service, kind, inbound, protocol_server, true).await;

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0, 1, 8, 8, 8, 8];
    packet.extend_from_slice(&5353u16.to_be_bytes());
    packet.extend_from_slice(expected_payload);
    let mut response = [0u8; 2048];
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    let mut next_send = std::time::Instant::now();
    let mut received = None;
    while std::time::Instant::now() < deadline {
        if std::time::Instant::now() >= next_send {
            client.send_to(&packet, inbound).await.unwrap();
            next_send = std::time::Instant::now() + Duration::from_millis(250);
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let wait = remaining.min(Duration::from_millis(250));
        if let Ok(Ok(result)) = tokio::time::timeout(wait, client.recv_from(&mut response)).await {
            received = Some(result);
            break;
        }
    }
    let (length, _) = received.unwrap_or_else(|| {
        panic!(
            "HTTP/2 protocol UDP inbound timed out for {}; inbound={inbound}; outbound={protocol_server}; diagnostics={}",
            kind.name(),
            service.diagnostics()
        )
    });
    assert!(
        response[..length]
            .windows(expected_payload.len())
            .any(|window| window == expected_payload),
        "HTTP/2 protocol UDP response did not contain payload: {:?}",
        &response[..length]
    );

    let connections = wait_for_named_connection(&service, &kind.inbound_name()).await;
    let item = connections["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == kind.inbound_name())
        .expect("HTTP/2 protocol UDP connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], protocol_server.to_string());
    assert_eq!(item["nodeId"], kind.node_id());
    assert_eq!(item["mode"], "proxy");

    service.shutdown().await;
    server_task.await.unwrap();
}

pub(super) async fn run_protocol_outbound_chain(kind: ProtocolOutboundKind) {
    eprintln!("starting protocol outbound integration: {}", kind.name());
    let expected_payload: &'static [u8] = match kind {
        ProtocolOutboundKind::Vless => b"runtime-vless-outbound",
        ProtocolOutboundKind::VlessTlsWebsocket => b"runtime-vless-tls-websocket-outbound",
        ProtocolOutboundKind::Vmess => b"runtime-vmess-outbound",
        ProtocolOutboundKind::VmessTlsWebsocket => b"runtime-vmess-tls-websocket-outbound",
        ProtocolOutboundKind::Trojan => b"runtime-trojan-outbound",
        ProtocolOutboundKind::TrojanWebsocket => b"runtime-trojan-websocket-outbound",
        ProtocolOutboundKind::TrojanTlsWebsocket => b"runtime-trojan-tls-websocket-outbound",
    };
    let protocol_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let protocol_server = protocol_listener.local_addr().unwrap();
    let server_task = tokio::spawn(protocol_outbound_server(
        kind,
        protocol_listener,
        expected_payload,
    ));

    let _default_mixed_blocker = TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound = support::reserve_loopback().await;
    let root = integration_dir(&format!("service-{}-runtime-outbound", kind.name()));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_protocol_outbound_chain(&service, kind, inbound, protocol_server, false).await;

    let mut client = connect_loopback(inbound).await;
    let authority = "example.test:443";
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut headers = Vec::new();
    let mut buffer = [0u8; 1024];
    while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        let length = client.read(&mut buffer).await.unwrap();
        assert!(length > 0, "HTTP inbound closed before protocol response");
        headers.extend_from_slice(&buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));

    client.write_all(expected_payload).await.unwrap();
    let mut echoed = vec![0u8; expected_payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, expected_payload);

    let mut connections = json!({});
    let mut visible = false;
    for _ in 0..500 {
        connections = api_json(
            &service.client,
            &service.base_url,
            http::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        if connections["connections"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        {
            visible = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        visible,
        "{} connection did not become visible; connections={connections}; diagnostics={}",
        kind.name(),
        service.diagnostics()
    );
    let node_id = kind.node_id();
    let item = connections["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == kind.inbound_name())
        .expect("runtime protocol outbound connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], protocol_server.to_string());
    assert_eq!(item["nodeId"], node_id);
    assert_eq!(item["mode"], "proxy");
    assert!(item["matchHistory"].as_array().is_some_and(|history| {
        history
            .iter()
            .any(|entry| entry["ruleName"] == kind.rule_name())
    }));

    let total = api_json(
        &service.client,
        &service.base_url,
        http::Method::GET,
        "/api/v2/connections/total",
        None,
    )
    .await;
    assert!(total["upload"].as_str().unwrap().parse::<u64>().unwrap() > 0);
    assert!(total["download"].as_str().unwrap().parse::<u64>().unwrap() > 0);

    let latency = api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        &format!("/api/v2/nodes/{node_id}/latency"),
        Some(&json!({
            "id": node_id,
            "type": "http",
            "url": "http://example.test/health",
            "timeoutMs": 5_000
        })),
    )
    .await;
    assert_eq!(
        latency["ok"], true,
        "protocol node latency failed: {latency}"
    );

    client.shutdown().await.unwrap();
    service.shutdown().await;
    server_task.await.unwrap();
}

pub(super) async fn run_protocol_udp_outbound_chain(kind: ProtocolOutboundKind) {
    eprintln!(
        "starting protocol UDP outbound integration: {}",
        kind.name()
    );
    let expected_payload: &'static [u8] = match kind {
        ProtocolOutboundKind::Vless => b"runtime-vless-udp-outbound",
        ProtocolOutboundKind::VlessTlsWebsocket => b"runtime-vless-tls-websocket-udp-outbound",
        ProtocolOutboundKind::Vmess => b"runtime-vmess-udp-outbound",
        ProtocolOutboundKind::VmessTlsWebsocket => b"runtime-vmess-tls-websocket-udp-outbound",
        ProtocolOutboundKind::Trojan => b"runtime-trojan-udp-outbound",
        ProtocolOutboundKind::TrojanWebsocket | ProtocolOutboundKind::TrojanTlsWebsocket => {
            panic!("Trojan WebSocket does not expose a datagram transport")
        }
    };
    let protocol_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let protocol_server = protocol_listener.local_addr().unwrap();
    let server_task = tokio::spawn(protocol_udp_outbound_server(
        kind,
        protocol_listener,
        expected_payload,
    ));

    let _default_mixed_blocker = TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound = support::reserve_loopback().await;
    let root = integration_dir(&format!("service-{}-runtime-udp-outbound", kind.name()));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_protocol_outbound_chain(&service, kind, inbound, protocol_server, true).await;

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0, 1, 8, 8, 8, 8];
    packet.extend_from_slice(&5353u16.to_be_bytes());
    packet.extend_from_slice(expected_payload);

    let mut response = [0u8; 2048];
    // The UDP listener and the first protocol session are both created after
    // the API reload notification.  GitHub's shared runners can delay that
    // reload, or the TLS/HTTP2 handshake, well beyond the local happy path.
    // Keep retransmits bounded so a slow runner does not turn one flow into a
    // burst of concurrent outbound sessions, while leaving enough time for
    // the real end-to-end path to settle.
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    let mut next_send = std::time::Instant::now();
    let mut received = None;
    while std::time::Instant::now() < deadline {
        if std::time::Instant::now() >= next_send {
            client.send_to(&packet, inbound).await.unwrap();
            next_send = std::time::Instant::now() + Duration::from_millis(250);
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let wait = remaining.min(Duration::from_millis(250));
        if let Ok(Ok(result)) = tokio::time::timeout(wait, client.recv_from(&mut response)).await {
            received = Some(result);
            break;
        }
    }
    let (length, _) = received.unwrap_or_else(|| {
        panic!(
            "protocol UDP inbound timed out for {}; inbound={inbound}; outbound={protocol_server}; diagnostics={}",
            kind.name(),
            service.diagnostics()
        )
    });
    assert!(
        response[..length]
            .windows(expected_payload.len())
            .any(|window| window == expected_payload),
        "protocol UDP response did not contain payload: {:?}",
        &response[..length]
    );

    let connections = wait_for_named_connection(&service, &kind.inbound_name()).await;
    let item = connections["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == kind.inbound_name())
        .expect("runtime protocol UDP connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], protocol_server.to_string());
    assert_eq!(item["nodeId"], kind.node_id());
    assert_eq!(item["mode"], "proxy");
    assert!(item["matchHistory"].as_array().is_some_and(|history| {
        history
            .iter()
            .any(|entry| entry["ruleName"] == kind.rule_name())
    }));

    service.shutdown().await;
    server_task.await.unwrap();
}
