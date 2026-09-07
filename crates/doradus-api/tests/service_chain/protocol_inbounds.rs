use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_and_yuubinsya_inbounds_route_through_tls_h2_yuubinsya_outbound() {
    let fixture = H2YuubinsyaFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_inbound = http_listener.local_addr().unwrap();
    drop(http_listener);
    let socks5_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks5_inbound = socks5_listener.local_addr().unwrap();
    drop(socks5_listener);
    let yuubinsya_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let yuubinsya_inbound = yuubinsya_listener.local_addr().unwrap();
    drop(yuubinsya_listener);

    let root = integration_dir("service-required-inbounds-tls-h2-yuubinsya");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_tls_h2_yuubinsya_chain(&service, http_inbound, fixture.outbound).await;
    add_socks5_inbound(
        &service,
        "tls-h2-yuubinsya-socks5-in",
        socks5_inbound,
        "integration-user",
        "integration-password",
    )
    .await;
    add_yuubinsya_inbound(&service, "tls-h2-yuubinsya-yuubinsya-in", yuubinsya_inbound).await;

    let authority = format!("example.test:{}", fixture.target.port());
    let mut socks5 = connect_loopback(socks5_inbound).await;
    socks5.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0u8; 2];
    socks5.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    let username = b"integration-user";
    let password = b"integration-password";
    let mut auth = vec![1, username.len() as u8];
    auth.extend_from_slice(username);
    auth.push(password.len() as u8);
    auth.extend_from_slice(password);
    socks5.write_all(&auth).await.unwrap();
    let mut auth_reply = [0u8; 2];
    socks5.read_exact(&mut auth_reply).await.unwrap();
    assert_eq!(auth_reply, [1, 0]);
    let host = b"example.test";
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&fixture.target.port().to_be_bytes());
    socks5.write_all(&request).await.unwrap();
    read_socks5_reply(&mut socks5).await;
    let socks5_payload = b"socks5-to-tls-h2-yuubinsya";
    socks5.write_all(socks5_payload).await.unwrap();
    let mut socks5_echo = vec![0u8; socks5_payload.len()];
    socks5.read_exact(&mut socks5_echo).await.unwrap();
    assert_eq!(&socks5_echo, socks5_payload);

    let yuubinsya_stream = connect_loopback(yuubinsya_inbound).await;
    let mut yuubinsya = AsyncYuubinsyaTcpSession::connect(
        yuubinsya_stream,
        derive_salt(YUUBINSYA_PASSWORD.as_bytes()),
        Endpoint::domain(
            Network::Tcp,
            DomainName::new("example.test").unwrap(),
            fixture.target.port(),
        ),
    )
    .await
    .unwrap();
    let yuubinsya_payload = b"yuubinsya-to-tls-h2-yuubinsya";
    yuubinsya.write_all(yuubinsya_payload).await.unwrap();
    let mut yuubinsya_echo = vec![0u8; yuubinsya_payload.len()];
    yuubinsya.read_exact(&mut yuubinsya_echo).await.unwrap();
    assert_eq!(&yuubinsya_echo, yuubinsya_payload);

    let connections = wait_for_connection(&service.client, &service.base_url).await;
    let connections = connections["connections"].as_array().unwrap();
    for (inbound_name, inbound_address) in [
        ("SOCKS5 integration inbound", socks5_inbound),
        ("Yuubinsya integration inbound", yuubinsya_inbound),
    ] {
        let item = connections
            .iter()
            .find(|item| item["inboundName"] == inbound_name)
            .unwrap_or_else(|| panic!("connection for {inbound_name} is missing"));
        assert_eq!(item["inbound"], inbound_address.to_string());
        assert_eq!(item["outbound"], fixture.outbound.to_string());
        assert_eq!(item["mode"], "proxy");
        assert!(item["matchHistory"].as_array().is_some_and(|history| {
            history
                .iter()
                .any(|entry| entry["ruleName"] == "proxy-example-test-over-yuubinsya")
        }));
    }

    let latency = api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/nodes/tls-h2-yuubinsya-out/latency",
        Some(&json!({
            "type":"tcp",
            "url":format!("http://{authority}/health")
        })),
    )
    .await;
    assert_eq!(
        latency["ok"], true,
        "multi-inbound chain latency: {latency}"
    );

    yuubinsya.shutdown().await.unwrap();
    socks5.shutdown().await.unwrap();
    service.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_inbound_exposes_socks5_udp_and_keeps_supervisor_alive() {
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let root = integration_dir("service-mixed-udp");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    support::seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;

    let mixed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mixed = mixed_listener.local_addr().unwrap();
    drop(mixed_listener);
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let mut packet = [0u8; 2048];
        if let Ok((length, peer)) = target.recv_from(&mut packet).await {
            let _ = target.send_to(&packet[..length], peer).await;
        }
    });

    let mixed_config = json!({
        "id":"mixed",
        "name":"mixed",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":mixed.to_string(),"udp":"enabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"mixed","mixed":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        http::Method::PUT,
        "/api/v2/inbounds/mixed",
        Some(&mixed_config),
    )
    .await;

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = b"mixed-udp-payload";
    // Keep the destination as a domain all the way through the inbound and
    // direct outbound. This is the process-level regression for the old
    // "already-resolved IP endpoint" failure; the local echo server still
    // gives the resolver a deterministic loopback result.
    let target_domain = b"localhost";
    let mut packet = vec![0, 0, 0, 3, target_domain.len() as u8];
    packet.extend_from_slice(target_domain);
    packet.extend_from_slice(&target_address.port().to_be_bytes());
    packet.extend_from_slice(payload);

    let mut response = [0u8; 2048];
    let mut received = None;
    for _ in 0..100 {
        client.send_to(&packet, mixed).await.unwrap();
        if let Ok(Ok((length, _))) =
            tokio::time::timeout(Duration::from_millis(50), client.recv_from(&mut response)).await
        {
            received = Some(length);
            break;
        }
    }
    let length = received.expect("mixed SOCKS5 UDP listener did not respond");
    assert!(
        response
            .windows(payload.len())
            .any(|window| window == payload)
    );

    let connection = wait_for_connection(&service.client, &service.base_url).await;
    let item = connection["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "mixed")
        .expect("mixed UDP connection must be visible");
    assert_eq!(item["inbound"], mixed.to_string());
    // The Go contract only exposes domain after resolver/FakeIP routing has
    // explicitly recorded it; a socket flow's original SOCKS5 domain is not
    // emitted as `domain` by itself.
    assert_eq!(item["domain"], "");
    assert_eq!(
        item["destination"],
        format!("localhost:{}", target_address.port())
    );
    assert!(length > payload.len());

    let logs = api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/rpc/tools.logs",
        Some(&json!({})),
    )
    .await
    .to_string();
    assert!(!logs.contains("protocol \\\"mixed\\\" has no UDP mode"));
    assert!(!logs.contains("direct async proxy requires an already-resolved IP endpoint"));

    let _ = target_task.await;
    service.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_and_yuubinsya_inbounds_route_through_the_runtime_process() {
    let fixture = ConnectFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let socks5_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks5_inbound = socks5_listener.local_addr().unwrap();
    drop(socks5_listener);
    let yuubinsya_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let yuubinsya_inbound = yuubinsya_listener.local_addr().unwrap();
    drop(yuubinsya_listener);

    let root = integration_dir("service-required-inbounds");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    add_socks5_inbound(
        &service,
        "socks5-required-in",
        socks5_inbound,
        "integration-user",
        "integration-password",
    )
    .await;
    add_yuubinsya_inbound(&service, "yuubinsya-required-in", yuubinsya_inbound).await;

    let mut socks5 = connect_loopback(socks5_inbound).await;
    socks5.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0u8; 2];
    socks5.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    let username = b"integration-user";
    let password = b"integration-password";
    let mut auth_request = vec![1, username.len() as u8];
    auth_request.extend_from_slice(username);
    auth_request.push(password.len() as u8);
    auth_request.extend_from_slice(password);
    socks5.write_all(&auth_request).await.unwrap();
    let mut auth = [0u8; 2];
    socks5.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, [1, 0]);
    let target_ip = match fixture.target {
        SocketAddr::V4(address) => address.ip().octets().to_vec(),
        SocketAddr::V6(_) => panic!("integration target must be IPv4"),
    };
    let mut connect_request = vec![5, 1, 0, 1];
    connect_request.extend_from_slice(&target_ip);
    connect_request.extend_from_slice(&fixture.target.port().to_be_bytes());
    socks5.write_all(&connect_request).await.unwrap();
    let mut socks5_reply = [0u8; 10];
    socks5.read_exact(&mut socks5_reply).await.unwrap();
    assert_eq!(socks5_reply[..2], [5, 0]);
    socks5.write_all(b"socks5-inbound-payload").await.unwrap();
    let mut socks5_echo = [0u8; 22];
    socks5.read_exact(&mut socks5_echo).await.unwrap();
    assert_eq!(&socks5_echo, b"socks5-inbound-payload");

    let yuubinsya_stream = connect_loopback(yuubinsya_inbound).await;
    let mut yuubinsya = AsyncYuubinsyaTcpSession::connect(
        yuubinsya_stream,
        derive_salt(YUUBINSYA_PASSWORD.as_bytes()),
        Endpoint::ip(Network::Tcp, fixture.target),
    )
    .await
    .unwrap();
    yuubinsya
        .write_all(b"yuubinsya-inbound-payload")
        .await
        .unwrap();
    let mut yuubinsya_echo = [0u8; 25];
    yuubinsya.read_exact(&mut yuubinsya_echo).await.unwrap();
    assert_eq!(&yuubinsya_echo, b"yuubinsya-inbound-payload");

    let connections = wait_for_connection(&service.client, &service.base_url).await;
    let connections = connections["connections"].as_array().unwrap();
    let socks5_connection = connections
        .iter()
        .find(|item| item["inboundName"] == "SOCKS5 integration inbound")
        .expect("SOCKS5 inbound connection must be visible");
    assert_eq!(socks5_connection["inbound"], socks5_inbound.to_string());
    assert_eq!(socks5_connection["outbound"], fixture.target.to_string());
    let yuubinsya_connection = connections
        .iter()
        .find(|item| item["inboundName"] == "Yuubinsya integration inbound")
        .expect("Yuubinsya inbound connection must be visible");
    assert_eq!(
        yuubinsya_connection["inbound"],
        yuubinsya_inbound.to_string()
    );
    assert_eq!(yuubinsya_connection["outbound"], fixture.target.to_string());

    yuubinsya.shutdown().await.unwrap();
    socks5.shutdown().await.unwrap();
    service.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn yuubinsya_native_udp_and_uot_inbounds_route_through_the_runtime_process() {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_address = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut packet = [0u8; 2048];
        for _ in 0..2 {
            let (length, peer) = echo.recv_from(&mut packet).await.unwrap();
            echo.send_to(&packet[..length], peer).await.unwrap();
        }
    });

    let _default_mixed_blocker = TcpListener::bind("127.0.0.1:1080").await.ok();
    let (tcp_listener, udp_listener) = loop {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp_listener.local_addr().unwrap();
        match UdpSocket::bind(address).await {
            Ok(udp_listener) => break (tcp_listener, udp_listener),
            Err(_) => drop(tcp_listener),
        }
    };
    let inbound = tcp_listener.local_addr().unwrap();
    drop(tcp_listener);
    drop(udp_listener);

    let root = integration_dir("service-yuubinsya-udp-uot-inbounds");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    add_yuubinsya_udp_inbound(&service, "yuubinsya-udp-uot-in", inbound).await;

    let password_hash = derive_salt(YUUBINSYA_PASSWORD.as_bytes());
    let destination = Endpoint::ip(Network::Udp, echo_address);

    let native = YuubinsyaUdpDatagram::bind(
        "127.0.0.1:0".parse().unwrap(),
        password_hash,
        Endpoint::ip(Network::Udp, inbound),
        false,
    )
    .await
    .unwrap();
    let native_payload = b"yuubinsya-native-udp-inbound-payload";
    native
        .send_to(native_payload, destination.clone())
        .await
        .unwrap();
    let mut native_response = [0u8; 2048];
    let (native_length, native_target) = tokio::time::timeout(
        Duration::from_secs(2),
        native.recv_from(&mut native_response),
    )
    .await
    .expect("native Yuubinsya UDP inbound did not respond")
    .unwrap();
    assert_eq!(&native_response[..native_length], native_payload);
    assert_eq!(native_target, destination);

    let uot_stream = connect_loopback(inbound).await;
    let uot = AsyncYuubinsyaUotSession::connect(uot_stream, password_hash, 0, false)
        .await
        .unwrap();
    let uot_payload = b"yuubinsya-uot-inbound-payload";
    uot.send_to(&destination, uot_payload).await.unwrap();
    let (uot_target, uot_response) = tokio::time::timeout(Duration::from_secs(2), uot.recv_from())
        .await
        .expect("Yuubinsya UOT inbound did not respond")
        .unwrap();
    assert_eq!(uot_target, destination);
    assert_eq!(&uot_response, uot_payload);

    let mut snapshot = Value::Null;
    for _ in 0..100 {
        snapshot = api_json(
            &service.client,
            &service.base_url,
            http::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        let items = snapshot["connections"].as_array().unwrap();
        let yuubinsya_items = items
            .iter()
            .filter(|item| item["inboundName"] == "Yuubinsya UDP integration inbound");
        let has_native = yuubinsya_items
            .clone()
            .any(|item| item["network"]["underlyingType"] == "udp" && item["udpMigrateId"] == "");
        let has_uot = yuubinsya_items.clone().any(|item| {
            item["network"]["underlyingType"] == "udp"
                && item["udpMigrateId"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty())
        });
        if has_native && has_uot {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let items = snapshot["connections"].as_array().unwrap();
    let yuubinsya_items: Vec<_> = items
        .iter()
        .filter(|item| item["inboundName"] == "Yuubinsya UDP integration inbound")
        .collect();
    assert!(yuubinsya_items.iter().any(|item| {
        item["inbound"] == inbound.to_string()
            && item["outbound"] == echo_address.to_string()
            && item["network"]["underlyingType"] == "udp"
            && item["udpMigrateId"] == ""
    }));
    assert!(
        yuubinsya_items.iter().any(|item| {
            item["inbound"] == inbound.to_string()
                && item["outbound"] == echo_address.to_string()
                && item["network"]["underlyingType"] == "udp"
                && item["udpMigrateId"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty())
        }),
        "Yuubinsya UDP/UOT connection metadata: {yuubinsya_items:?}"
    );

    native.close().await.unwrap();
    uot.shutdown().await.unwrap();
    service.shutdown().await;
    echo_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vless_and_trojan_inbounds_route_through_the_runtime_process() {
    const VLESS_UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
    const TROJAN_PASSWORD: &str = "runtime-integration-trojan";

    let fixture = ConnectFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let vless_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let vless_inbound = vless_listener.local_addr().unwrap();
    drop(vless_listener);
    let trojan_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let trojan_inbound = trojan_listener.local_addr().unwrap();
    drop(trojan_listener);

    let root = integration_dir("service-vless-trojan-inbounds");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    add_vless_inbound(&service, "vless-required-in", vless_inbound, VLESS_UUID).await;
    add_trojan_inbound(
        &service,
        "trojan-required-in",
        trojan_inbound,
        TROJAN_PASSWORD,
    )
    .await;

    let destination = Endpoint::ip(Network::Tcp, fixture.target);
    let uuid = vless::parse_uuid(VLESS_UUID).unwrap();
    let mut vless_client = connect_loopback(vless_inbound).await;
    vless::write_request(&mut vless_client, &uuid, vless::Command::Tcp, &destination)
        .await
        .unwrap();
    vless::read_response(&mut vless_client).await.unwrap();
    let vless_payload = b"vless-runtime-inbound-payload";
    vless_client.write_all(vless_payload).await.unwrap();
    let mut vless_echo = vec![0u8; vless_payload.len()];
    vless_client.read_exact(&mut vless_echo).await.unwrap();
    assert_eq!(vless_echo, vless_payload);

    let hash = trojan::password_hash(TROJAN_PASSWORD.as_bytes());
    let mut trojan_client = connect_loopback(trojan_inbound).await;
    trojan::write_request(
        &mut trojan_client,
        &hash,
        trojan::Command::Connect,
        &destination,
    )
    .await
    .unwrap();
    let trojan_payload = b"trojan-runtime-inbound-payload";
    trojan_client.write_all(trojan_payload).await.unwrap();
    let mut trojan_echo = vec![0u8; trojan_payload.len()];
    trojan_client.read_exact(&mut trojan_echo).await.unwrap();
    assert_eq!(trojan_echo, trojan_payload);

    let mut snapshot = Value::Null;
    for _ in 0..100 {
        snapshot = api_json(
            &service.client,
            &service.base_url,
            http::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        let items = snapshot["connections"].as_array().unwrap();
        if items.iter().any(|item| {
            item["inboundName"] == "VLESS integration inbound"
                && item["inbound"] == vless_inbound.to_string()
        }) && items.iter().any(|item| {
            item["inboundName"] == "Trojan integration inbound"
                && item["inbound"] == trojan_inbound.to_string()
        }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let items = snapshot["connections"].as_array().unwrap();
    let vless_connection = items
        .iter()
        .find(|item| item["inboundName"] == "VLESS integration inbound")
        .expect("VLESS inbound connection must be visible");
    assert_eq!(vless_connection["inbound"], vless_inbound.to_string());
    assert_eq!(vless_connection["outbound"], fixture.target.to_string());
    let trojan_connection = items
        .iter()
        .find(|item| item["inboundName"] == "Trojan integration inbound")
        .expect("Trojan inbound connection must be visible");
    assert_eq!(trojan_connection["inbound"], trojan_inbound.to_string());
    assert_eq!(trojan_connection["outbound"], fixture.target.to_string());

    vless_client.shutdown().await.unwrap();
    trojan_client.shutdown().await.unwrap();
    service.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vless_and_trojan_udp_inbounds_route_through_the_runtime_process() {
    const VLESS_UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
    const TROJAN_PASSWORD: &str = "runtime-integration-trojan-udp";

    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_address = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut packet = [0u8; 2048];
        for _ in 0..2 {
            let (length, peer) = echo.recv_from(&mut packet).await.unwrap();
            echo.send_to(&packet[..length], peer).await.unwrap();
        }
    });

    let _default_mixed_blocker = TcpListener::bind("127.0.0.1:1080").await.ok();
    let vless_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let vless_inbound = vless_listener.local_addr().unwrap();
    drop(vless_listener);
    let trojan_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let trojan_inbound = trojan_listener.local_addr().unwrap();
    drop(trojan_listener);

    let root = integration_dir("service-vless-trojan-udp-inbounds");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    add_vless_udp_inbound(&service, "vless-udp-required-in", vless_inbound, VLESS_UUID).await;
    add_trojan_udp_inbound(
        &service,
        "trojan-udp-required-in",
        trojan_inbound,
        TROJAN_PASSWORD,
    )
    .await;

    let destination = Endpoint::ip(Network::Udp, echo_address);
    let uuid = vless::parse_uuid(VLESS_UUID).unwrap();
    let mut vless_client = connect_loopback(vless_inbound).await;
    vless::write_request(&mut vless_client, &uuid, vless::Command::Udp, &destination)
        .await
        .unwrap();
    let vless_payload = b"vless-runtime-udp-inbound-payload";
    vless_client
        .write_u16(vless_payload.len() as u16)
        .await
        .unwrap();
    vless_client.write_all(vless_payload).await.unwrap();
    let vless_length = usize::from(vless_client.read_u16().await.unwrap());
    let mut vless_echo = vec![0u8; vless_length];
    vless_client.read_exact(&mut vless_echo).await.unwrap();
    assert_eq!(&vless_echo, vless_payload);

    let hash = trojan::password_hash(TROJAN_PASSWORD.as_bytes());
    let mut trojan_client = connect_loopback(trojan_inbound).await;
    trojan::write_request(
        &mut trojan_client,
        &hash,
        trojan::Command::Associate,
        &destination,
    )
    .await
    .unwrap();
    let trojan_payload = b"trojan-runtime-udp-inbound-payload";
    trojan::write_udp_frame(&mut trojan_client, &destination, trojan_payload)
        .await
        .unwrap();
    let mut trojan_echo = vec![0u8; 2048];
    let (trojan_length, trojan_target) =
        trojan::read_udp_frame(&mut trojan_client, &mut trojan_echo)
            .await
            .unwrap();
    assert_eq!(trojan_target, destination);
    assert_eq!(&trojan_echo[..trojan_length], trojan_payload);

    let mut snapshot = Value::Null;
    for _ in 0..100 {
        snapshot = api_json(
            &service.client,
            &service.base_url,
            http::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        let items = snapshot["connections"].as_array().unwrap();
        if items.iter().any(|item| {
            item["inboundName"] == "VLESS UDP integration inbound"
                && item["inbound"] == vless_inbound.to_string()
        }) && items.iter().any(|item| {
            item["inboundName"] == "Trojan UDP integration inbound"
                && item["inbound"] == trojan_inbound.to_string()
        }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let items = snapshot["connections"].as_array().unwrap();
    let vless_connection = items
        .iter()
        .find(|item| item["inboundName"] == "VLESS UDP integration inbound")
        .expect("VLESS UDP inbound connection must be visible");
    assert_eq!(vless_connection["inbound"], vless_inbound.to_string());
    assert_eq!(vless_connection["outbound"], echo_address.to_string());
    assert_eq!(vless_connection["network"]["underlyingType"], "udp");
    let trojan_connection = items
        .iter()
        .find(|item| item["inboundName"] == "Trojan UDP integration inbound")
        .expect("Trojan UDP inbound connection must be visible");
    assert_eq!(trojan_connection["inbound"], trojan_inbound.to_string());
    assert_eq!(trojan_connection["outbound"], echo_address.to_string());
    assert_eq!(trojan_connection["network"]["underlyingType"], "udp");

    vless_client.shutdown().await.unwrap();
    trojan_client.shutdown().await.unwrap();
    service.shutdown().await;
    echo_task.await.unwrap();
}
