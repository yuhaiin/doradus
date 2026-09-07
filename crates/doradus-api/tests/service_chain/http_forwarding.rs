use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_inbound_routes_through_socks5_outbound() {
    let fixture = Socks5Fixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let root = integration_dir("service-socks5-chain");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_socks5_chain(&service, inbound, fixture.outbound).await;

    let mut client = connect_loopback(inbound).await;
    let authority = format!("example.test:{}", fixture.target.port());
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut headers = Vec::new();
    let mut buffer = [0u8; 1024];
    while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        let length = client.read(&mut buffer).await.unwrap();
        assert!(length > 0, "HTTP inbound closed before SOCKS5 response");
        headers.extend_from_slice(&buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));

    let payload = b"socks5-outbound-payload";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, payload);

    let connection = wait_for_connection(&service.client, &service.base_url).await;
    let item = connection["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "SOCKS5 outbound chain inbound")
        .expect("SOCKS5 outbound chain connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], fixture.outbound.to_string());
    assert!(item["matchHistory"].as_array().is_some_and(|history| {
        history
            .iter()
            .any(|entry| entry["ruleName"] == "proxy-example-test-over-socks5")
    }));

    let mut destinations = Vec::new();
    for _ in 0..100 {
        destinations = fixture
            .destinations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if destinations
            .iter()
            .any(|destination| destination == &authority)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        destinations
            .iter()
            .any(|destination| destination == &authority)
    );

    let latency = api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/nodes/socks5-out/latency",
        Some(&json!({
            "type":"tcp",
            "url":format!("http://{authority}/health")
        })),
    )
    .await;
    assert_eq!(
        latency["ok"], true,
        "SOCKS5 chain latency response: {latency}"
    );

    client.shutdown().await.unwrap();
    service.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_inbound_reuses_client_connection_for_multiple_forward_requests() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = target_listener.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        for (path, body) in [
            ("/first", b"one".as_slice()),
            ("/second", b"two".as_slice()),
        ] {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let request = read_http_headers(&mut stream).await;
            assert!(
                String::from_utf8_lossy(&request).starts_with(&format!("GET {path} HTTP/1.1\r\n"))
            );
            assert!(
                String::from_utf8_lossy(&request)
                    .contains(&format!("Host: 127.0.0.1:{}\r\n", target.port()))
            );
            assert!(!String::from_utf8_lossy(&request).contains("Connection:"));
            assert!(!String::from_utf8_lossy(&request).contains("X-Remove:"));
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(body).await.unwrap();
        }
    });

    let inbound = support::reserve_loopback().await;
    let root = integration_dir("service-http-persistent-client");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_direct_http_inbound(&service, inbound).await;

    let mut client = connect_loopback(inbound).await;
    for (path, expected) in [
        ("/first", b"one".as_slice()),
        ("/second", b"two".as_slice()),
    ] {
        client
            .write_all(
                format!(
                    "GET http://127.0.0.1:{}{path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: keep-alive, X-Remove\r\nX-Remove: client-hop\r\n\r\n",
                    target.port(),
                    target.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_headers(&mut client).await;
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let mut body = vec![0u8; expected.len()];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(body, expected);
    }
    client.shutdown().await.unwrap();
    service.shutdown().await;
    target_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_inbound_handles_expect_continue_and_upstream_informational_response() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = target_listener.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.unwrap();
        let request = read_http_headers(&mut stream).await;
        let request = String::from_utf8_lossy(&request);
        assert!(request.starts_with("POST /upload HTTP/1.1\r\n"));
        assert!(request.contains(&format!("Host: 127.0.0.1:{}\r\n", target.port())));
        assert!(request.contains("Content-Length: 11\r\n"));
        assert!(!request.contains("Expect:"));

        let mut body = [0u8; 11];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"hello world");
        stream
            .write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n")
            .await
            .unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    });

    let inbound = support::reserve_loopback().await;
    let root = integration_dir("service-http-expect-continue");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_direct_http_inbound(&service, inbound).await;

    let mut client = connect_loopback(inbound).await;
    client
        .write_all(
            format!(
                "POST http://127.0.0.1:{}/upload HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nExpect: 100-continue\r\nContent-Length: 11\r\nConnection: close\r\n\r\n",
                target.port(),
                target.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response = read_http_headers(&mut client).await;
    assert!(response.starts_with(b"HTTP/1.1 100 Continue\r\n"));
    client.write_all(b"hello world").await.unwrap();

    let response = read_http_headers(&mut client).await;
    assert!(response.starts_with(b"HTTP/1.1 103 Early Hints\r\n"));
    let response = read_http_headers(&mut client).await;
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let mut body = [0u8; 2];
    client.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"ok");

    client.shutdown().await.unwrap();
    service.shutdown().await;
    target_task.await.unwrap();
}

/// Go's httputil.ReverseProxy also accepts absolute-form HTTPS requests on an
/// HTTP proxy inbound. Keep this opt-in because it reaches a public endpoint,
/// but exercise the complete path when requested: HTTP inbound -> selected
/// direct outbound -> origin TLS -> HTTP/1.1 response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires external network access"]
async fn http_inbound_forwards_absolute_https_request() {
    let inbound = support::reserve_loopback().await;
    let root = integration_dir("service-http-absolute-https");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_direct_http_inbound(&service, inbound).await;

    let mut client = connect_loopback(inbound).await;
    client
        .write_all(
            b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .unwrap();
    // Observe the flow while the origin request is still in flight. Reading
    // the complete public response first makes this assertion race with the
    // HTTP proxy's normal close path, which removes the live connection.
    let connections = wait_for_connection(&service.client, &service.base_url).await;
    let response = tokio::time::timeout(Duration::from_secs(20), read_http_headers(&mut client))
        .await
        .expect("absolute HTTPS proxy response timed out");
    assert!(
        response.starts_with(b"HTTP/1.1 "),
        "absolute HTTPS proxy response: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        !response.starts_with(b"HTTP/1.1 501") && !response.starts_with(b"HTTP/1.1 502"),
        "absolute HTTPS proxy request was rejected: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert!(connections["connections"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["inboundName"] == "Direct HTTP inbound")
    }));
    service.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_inbound_routes_through_tls_h2_yuubinsya_outbound() {
    let fixture = H2YuubinsyaFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);
    let (udp_inbound, udp_listener) = loop {
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp_listener.local_addr().unwrap();
        match tokio::net::UdpSocket::bind(address).await {
            Ok(udp_listener) => break (address, (tcp_listener, udp_listener)),
            Err(_) => drop(tcp_listener),
        }
    };
    drop(udp_listener);

    let root = integration_dir("service-tls-h2-yuubinsya");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_tls_h2_yuubinsya_chain(&service, inbound, fixture.outbound).await;
    add_mixed_udp_inbound(&service, "tls-h2-yuubinsya-udp-in", udp_inbound).await;

    let mut client = None;
    for _ in 0..100 {
        match TcpStream::connect(inbound).await {
            Ok(stream) => {
                client = Some(stream);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    let mut client = client.expect("TLS/H2/Yuubinsya HTTP inbound did not start");
    let authority = format!("example.test:{}", fixture.target.port());
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut headers = Vec::new();
    let mut buffer = [0u8; 1024];
    while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        let length = client.read(&mut buffer).await.unwrap();
        assert!(length > 0, "HTTP inbound closed before chain response");
        headers.extend_from_slice(&buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));

    client.write_all(b"tls-h2-yuubinsya-payload").await.unwrap();
    let mut payload = [0u8; 24];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"tls-h2-yuubinsya-payload");

    let connection = wait_for_connection(&service.client, &service.base_url).await;
    let item = connection["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "TLS H2 Yuubinsya chain inbound")
        .expect("TLS/H2/Yuubinsya connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], fixture.outbound.to_string());
    assert_eq!(item["mode"], "proxy");
    assert!(item["matchHistory"].as_array().is_some_and(|history| {
        history
            .iter()
            .any(|entry| entry["ruleName"] == "proxy-example-test-over-yuubinsya")
    }));

    let udp_client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_payload = b"tls-h2-yuubinsya-udp";
    let udp_domain = b"example.test";
    let mut packet = vec![0, 0, 0, 3, udp_domain.len() as u8];
    packet.extend_from_slice(udp_domain);
    packet.extend_from_slice(&fixture.udp_target.port().to_be_bytes());
    packet.extend_from_slice(udp_payload);
    let mut udp_response = [0u8; 2048];
    let mut udp_length = None;
    for _ in 0..100 {
        udp_client.send_to(&packet, udp_inbound).await.unwrap();
        if let Ok(Ok((length, _))) = tokio::time::timeout(
            Duration::from_millis(50),
            udp_client.recv_from(&mut udp_response),
        )
        .await
        {
            udp_length = Some(length);
            break;
        }
    }
    let udp_length = if let Some(length) = udp_length {
        length
    } else {
        let logs = api_json(
            &service.client,
            &service.base_url,
            http::Method::POST,
            "/api/v2/rpc/tools.logs",
            Some(&json!({})),
        )
        .await;
        let inbounds = api_json(
            &service.client,
            &service.base_url,
            http::Method::GET,
            "/api/v2/inbounds?page=1&pageSize=100",
            None,
        )
        .await;
        let connections = api_json(
            &service.client,
            &service.base_url,
            http::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        panic!(
            "TLS/H2/Yuubinsya UDP flow did not respond; logs={logs}; inbounds={inbounds}; connections={connections}; stderr={}",
            service.diagnostics()
        );
    };
    assert!(
        udp_response
            .windows(udp_payload.len())
            .any(|window| window == udp_payload)
    );

    let range_end = OffsetDateTime::now_utc();
    let range_start = range_end - time::Duration::hours(1);
    let range_start = range_start.format(&Rfc3339).unwrap();
    let range_end = (range_end + time::Duration::hours(1))
        .format(&Rfc3339)
        .unwrap();
    let traffic = api_json(
        &service.client,
        &service.base_url,
        http::Method::GET,
        &format!("/api/v2/connections/traffic?interval=hour&from={range_start}&to={range_end}"),
        None,
    )
    .await;
    assert_eq!(traffic["interval"], "hour");
    assert!(traffic["items"].as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item["upload"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|value| value > 0)
        })
    }));

    let telemetry = api_json(
        &service.client,
        &service.base_url,
        http::Method::GET,
        &format!("/api/v2/connections/telemetry?from={range_start}&to={range_end}&limit=6"),
        None,
    )
    .await;
    assert!(telemetry["groups"].as_array().is_some_and(|groups| {
        groups.iter().any(|group| {
            group["items"].as_array().is_some_and(|items| {
                items.iter().any(|item| {
                    item["upload"]
                        .as_str()
                        .and_then(|value| value.parse::<u64>().ok())
                        .is_some_and(|value| value > 0)
                })
            })
        })
    }));

    let failed_history = api_json(
        &service.client,
        &service.base_url,
        http::Method::GET,
        "/api/v2/connections/failed-history",
        None,
    )
    .await;
    assert!(failed_history["items"].is_array());
    assert!(failed_history["dumpProcessEnabled"].is_boolean());

    let mut udp_connection = None;
    for _ in 0..100 {
        let current = api_json(
            &service.client,
            &service.base_url,
            http::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        udp_connection = current["connections"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| item["inboundName"] == "TLS H2 Yuubinsya UDP chain inbound")
            })
            .cloned();
        if udp_connection.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let udp_item = udp_connection.expect("TLS/H2/Yuubinsya UDP connection must be visible");
    assert_eq!(udp_item["inbound"], udp_inbound.to_string());
    assert_eq!(udp_item["outbound"], fixture.outbound.to_string());
    assert_eq!(udp_item["mode"], "proxy");
    assert!(udp_length > udp_payload.len());

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
    assert_eq!(latency["ok"], true, "chain latency response: {latency}");

    client.shutdown().await.unwrap();

    let mut history = None;
    for _ in 0..100 {
        let current = api_json(
            &service.client,
            &service.base_url,
            http::Method::GET,
            "/api/v2/connections/history",
            None,
        )
        .await;
        history = current["items"].as_array().and_then(|items| {
            items
                .iter()
                .find(|item| item["connection"]["inboundName"] == "TLS H2 Yuubinsya chain inbound")
                .cloned()
        });
        if history.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let history = history.expect("closed HTTP chain must be visible in history");
    assert!(history["count"].as_str().is_some_and(|value| value != "0"));
    assert!(
        history["time"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );

    service.shutdown().await;
    fixture.shutdown().await;
}
