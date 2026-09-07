use super::*;

pub(super) async fn yuubinsya_auth_is_rejected(
    address: SocketAddr,
    password: &str,
    host: &str,
    port: u16,
) -> bool {
    let stream = connect_loopback(address).await;
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        AsyncYuubinsyaTcpSession::connect(
            stream,
            derive_salt(password.as_bytes()),
            Endpoint::domain(Network::Tcp, DomainName::new(host).unwrap(), port),
        ),
    )
    .await;
    match result {
        Ok(Ok(mut session)) => {
            let payload = b"yuubinsya-auth-probe";
            if session.write_all(payload).await.is_err() {
                return true;
            }
            let mut echoed = vec![0u8; payload.len()];
            !matches!(
                tokio::time::timeout(Duration::from_secs(1), session.read_exact(&mut echoed))
                    .await,
                Ok(Ok(())) if echoed == payload
            )
        }
        Ok(Err(_)) | Err(_) => true,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http2_inbound_routes_through_http_outbound() {
    let fixture = ConnectFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let root = integration_dir("service-h2-http-inbound");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_h2_http_inbound(&service, inbound, fixture.outbound).await;

    let transport = connect_loopback(inbound).await;
    let (mut client, connection) = h2::client::handshake(transport).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(http::Method::CONNECT)
        .uri("http://localhost")
        .body(())
        .unwrap();
    let (response, mut request_body) = client.send_request(request, false).unwrap();
    let response = match response.await {
        Ok(response) => response,
        Err(error) => {
            let logs = api_json(
                &service.client,
                &service.base_url,
                http::Method::POST,
                "/api/v2/rpc/tools.logs",
                Some(&json!({})),
            )
            .await;
            panic!(
                "HTTP/2 inbound response failed: {error}; logs={logs}; stderr={}",
                service.diagnostics()
            );
        }
    };
    assert_eq!(response.status(), http::StatusCode::OK);

    let authority = format!("example.test:{}", fixture.target.port());
    request_body
        .send_data(
            Bytes::from(format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
            )),
            false,
        )
        .unwrap();
    let payload = b"h2-inbound-http-outbound";
    request_body
        .send_data(Bytes::from_static(payload), true)
        .unwrap();

    let mut body = response.into_body();
    let mut received = Vec::new();
    while let Some(data) = body.data().await {
        let data = data.unwrap();
        body.flow_control().release_capacity(data.len()).unwrap();
        received.extend_from_slice(&data);
        if received.ends_with(payload) {
            break;
        }
    }
    assert!(
        received.starts_with(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
        "H2 inbound response: {received:?}"
    );
    assert!(received.ends_with(payload));

    let connection_value = wait_for_connection(&service.client, &service.base_url).await;
    let item = connection_value["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "HTTP/2 HTTP inbound")
        .expect("HTTP/2 inbound connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], fixture.outbound.to_string());
    // This HTTP/2 fixture carries the proxy request inside an H2 data stream;
    // the Go monitor leaves protocol empty when no application sniff metadata
    // survives that bridge.
    assert_eq!(item["protocol"], "");

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

    let authorities = fixture
        .connect_authorities
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert!(
        authorities.iter().any(|value| value == &authority),
        "HTTP outbound authorities: {authorities:?}"
    );

    connection_task.abort();
    let _ = connection_task.await;
    service.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_inbound_routes_through_network_split_http_tcp_branch() {
    let fixture = ConnectFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound = support::reserve_loopback().await;

    let root = integration_dir("service-network-split-http");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_network_split_http_chain(&service, inbound, fixture.outbound).await;

    let authority = format!("example.test:{}", fixture.target.port());
    let (mut client, headers) = http_connect_with_auth(inbound, &authority, None)
        .await
        .unwrap();
    assert!(
        headers.starts_with("HTTP/1.1 200"),
        "HTTP response: {headers}"
    );
    let payload = b"network-split-http-tcp-branch";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);

    let connections = wait_for_connection(&service.client, &service.base_url).await;
    let item = connections["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "NetworkSplit HTTP inbound")
        .expect("network_split connection must be visible");
    assert_eq!(item["nodeId"], "network-split-http-out");
    assert_eq!(item["outbound"], fixture.outbound.to_string());

    let authorities = fixture
        .connect_authorities
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert!(
        authorities.iter().any(|value| value == &authority),
        "network_split HTTP branch authorities: {authorities:?}"
    );

    client.shutdown().await.unwrap();
    service.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aead_http2_inbound_routes_through_http_outbound() {
    let fixture = ConnectFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound = support::reserve_loopback().await;

    let root = integration_dir("service-aead-h2-http-inbound");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_aead_h2_http_inbound(&service, inbound, fixture.outbound).await;

    let transport = connect_loopback(inbound).await;
    let transport = doradus_protocol::aead::client(
        Box::new(transport),
        b"runtime-aead-password",
        doradus_protocol::aead::CryptoMethod::XChacha20Poly1305,
    )
    .await
    .unwrap();
    let (mut client, connection) = h2::client::handshake(transport).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(http::Method::CONNECT)
        .uri("http://localhost")
        .body(())
        .unwrap();
    let (response, mut request_body) = client.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);

    let authority = format!("example.test:{}", fixture.target.port());
    request_body
        .send_data(
            Bytes::from(format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
            )),
            false,
        )
        .unwrap();
    let payload = b"aead-h2-inbound-http-outbound";
    request_body
        .send_data(Bytes::from_static(payload), true)
        .unwrap();

    let mut body = response.into_body();
    let mut received = Vec::new();
    while let Some(data) = body.data().await {
        let data = data.unwrap();
        body.flow_control().release_capacity(data.len()).unwrap();
        received.extend_from_slice(&data);
        if received.ends_with(payload) {
            break;
        }
    }
    assert!(
        received.starts_with(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
        "AEAD/H2 inbound response: {received:?}"
    );
    assert!(received.ends_with(payload));

    let connection_value = wait_for_connection(&service.client, &service.base_url).await;
    let item = connection_value["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "AEAD HTTP/2 inbound")
        .expect("AEAD/H2 inbound connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], fixture.outbound.to_string());

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

    let authorities = fixture
        .connect_authorities
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert!(
        authorities.iter().any(|value| value == &authority),
        "HTTP outbound authorities: {authorities:?}"
    );

    connection_task.abort();
    let _ = connection_task.await;
    service.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_inbound_routes_through_http2_http_outbound() {
    run_h2_protocol_chain(H2FinalProtocol::Http).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_inbound_routes_through_http2_socks5_outbound() {
    run_h2_protocol_chain(H2FinalProtocol::Socks5).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_http_inbound_terminates_tls_and_routes_through_direct_outbound() {
    run_tls_http_inbound(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_auto_http_inbound_issues_sni_certificate_and_routes_through_direct_outbound() {
    run_tls_http_inbound(true).await;
}

async fn run_tls_http_inbound(tls_auto: bool) {
    let fixture = ConnectFixture::start().await;
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let root = integration_dir(if tls_auto {
        "service-tls-auto-http-inbound"
    } else {
        "service-tls-http-inbound"
    });
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    if tls_auto {
        configure_tls_auto_http_inbound(&service, inbound).await;
    } else {
        configure_tls_http_inbound(&service, inbound).await;
    }

    let mut client = connect_tls_loopback(inbound).await;
    let authority = fixture.target.to_string();
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut headers = Vec::new();
    let mut buffer = [0u8; 1024];
    while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        let length = client.read(&mut buffer).await.unwrap();
        assert!(
            length > 0,
            "TLS HTTP inbound closed before CONNECT response"
        );
        headers.extend_from_slice(&buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));

    let payload = b"tls-inbound-payload";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, payload);

    let connection = wait_for_connection(&service.client, &service.base_url).await;
    let inbound_name = if tls_auto {
        "TLS-auto HTTP inbound"
    } else {
        "TLS HTTP inbound"
    };
    let item = connection["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == inbound_name)
        .expect("TLS/TLS-auto HTTP inbound connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], fixture.target.to_string());
    assert_eq!(item["protocol"], "tls");

    client.shutdown().await.unwrap();
    service.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_http2_inbound_routes_through_http_outbound() {
    let fixture = ConnectFixture::start().await;
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let root = integration_dir("service-tls-h2-http-inbound");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_tls_h2_http_inbound(&service, inbound, fixture.outbound).await;

    let transport = connect_tls_h2_loopback(inbound).await;
    let (mut client, connection) = h2::client::handshake(transport).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://localhost")
        .body(())
        .unwrap();
    let (response, mut request_body) = client.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);

    let authority = format!("example.test:{}", fixture.target.port());
    request_body
        .send_data(
            Bytes::from(format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
            )),
            false,
        )
        .unwrap();
    let payload = b"tls-h2-inbound-http-outbound";
    request_body
        .send_data(Bytes::from_static(payload), true)
        .unwrap();

    let mut body = response.into_body();
    let mut received = Vec::new();
    while let Some(data) = body.data().await {
        let data = data.unwrap();
        body.flow_control().release_capacity(data.len()).unwrap();
        received.extend_from_slice(&data);
        if received.ends_with(payload) {
            break;
        }
    }
    assert!(
        received.starts_with(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
        "TLS/H2 inbound response: {received:?}"
    );
    assert!(received.ends_with(payload));

    let connection_value = wait_for_connection(&service.client, &service.base_url).await;
    let item = connection_value["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "TLS HTTP/2 inbound")
        .expect("TLS/HTTP2 inbound connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    // TLS is intentionally retained as the protocol metadata when the
    // inbound transport is TLS-wrapped; this matches the existing Go-facing
    // precedence used by `InboundSpec::annotate_context`.
    assert_eq!(item["protocol"], "tls");
    assert_eq!(item["outbound"], fixture.outbound.to_string());

    let authorities = fixture
        .connect_authorities
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert!(
        authorities.iter().any(|value| value == &authority),
        "HTTP outbound authorities: {authorities:?}"
    );

    connection_task.abort();
    let _ = connection_task.await;
    service.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_aead_http2_inbound_routes_through_http_outbound() {
    let fixture = ConnectFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound = support::reserve_loopback().await;

    let root = integration_dir("service-tls-aead-h2-http-inbound");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_tls_aead_h2_http_inbound(&service, inbound, fixture.outbound).await;

    let tls = connect_tls_h2_loopback(inbound).await;
    let transport = doradus_protocol::aead::client(
        Box::new(tls),
        b"runtime-aead-password",
        doradus_protocol::aead::CryptoMethod::XChacha20Poly1305,
    )
    .await
    .unwrap();
    let (mut client, connection) = h2::client::handshake(transport).await.unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://localhost")
        .body(())
        .unwrap();
    let (response, mut request_body) = client.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);

    let authority = format!("example.test:{}", fixture.target.port());
    request_body
        .send_data(
            Bytes::from(format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
            )),
            false,
        )
        .unwrap();
    let payload = b"tls-aead-h2-inbound-http-outbound";
    request_body
        .send_data(Bytes::from_static(payload), true)
        .unwrap();

    let mut body = response.into_body();
    let mut received = Vec::new();
    while let Some(data) = body.data().await {
        let data = data.unwrap();
        body.flow_control().release_capacity(data.len()).unwrap();
        received.extend_from_slice(&data);
        if received.ends_with(payload) {
            break;
        }
    }
    assert!(
        received.starts_with(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
        "TLS/AEAD/H2 inbound response: {received:?}"
    );
    assert!(received.ends_with(payload));

    let connection_value = wait_for_connection(&service.client, &service.base_url).await;
    let item = connection_value["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "TLS AEAD HTTP/2 inbound")
        .expect("TLS/AEAD/H2 inbound connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], fixture.outbound.to_string());
    assert_eq!(item["protocol"], "tls");

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

    let authorities = fixture
        .connect_authorities
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert!(
        authorities.iter().any(|value| value == &authority),
        "HTTP outbound authorities: {authorities:?}"
    );

    connection_task.abort();
    let _ = connection_task.await;
    service.shutdown().await;
    fixture.shutdown().await;
}

async fn run_h2_protocol_chain(protocol: H2FinalProtocol) {
    let fixture = H2ProtocolFixture::start(protocol).await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let (node_id, inbound_name, rule_name) = match protocol {
        H2FinalProtocol::Http => (
            "h2-http-out",
            "HTTP/2 protocol chain inbound",
            "proxy-example-test-over-h2-http",
        ),
        H2FinalProtocol::Socks5 => (
            "h2-socks5-out",
            "HTTP/2 protocol chain inbound",
            "proxy-example-test-over-h2-socks5",
        ),
    };
    let root = integration_dir(node_id);
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    match protocol {
        H2FinalProtocol::Http => configure_h2_http_chain(&service, inbound, fixture.outbound).await,
        H2FinalProtocol::Socks5 => {
            configure_h2_socks5_chain(&service, inbound, fixture.outbound).await
        }
    }

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
        assert!(length > 0, "HTTP inbound closed before H2 chain response");
        headers.extend_from_slice(&buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));

    let payload = match protocol {
        H2FinalProtocol::Http => b"h2-http-payload".as_slice(),
        H2FinalProtocol::Socks5 => b"h2-socks5-payload".as_slice(),
    };
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, payload);

    let connection = wait_for_connection(&service.client, &service.base_url).await;
    let item = connection["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == inbound_name)
        .expect("HTTP/2 protocol chain connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], fixture.outbound.to_string());
    assert_eq!(item["mode"], "proxy");
    assert!(
        item["matchHistory"]
            .as_array()
            .is_some_and(|history| { history.iter().any(|entry| entry["ruleName"] == rule_name) })
    );

    let latency = api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        &format!("/api/v2/nodes/{node_id}/latency"),
        Some(&json!({"type":"tcp","url":"http://example.test:443/health"})),
    )
    .await;
    assert_eq!(latency["ok"], true, "H2 protocol chain latency: {latency}");

    client.shutdown().await.unwrap();
    service.shutdown().await;
    fixture.shutdown().await;
}
