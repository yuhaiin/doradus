use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_inbound_routes_through_http_outbound_and_exposes_runtime_state() {
    let fixture = ConnectFixture::start().await;
    // Keep the Go-compatible default mixed port occupied so this test also
    // proves that one failed inbound bind does not terminate the supervisor.
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let root = integration_dir("service-http-chain");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_http_chain(&service, inbound, fixture.outbound).await;
    let configured_inbounds = api_json(
        &service.client,
        &service.base_url,
        http::Method::GET,
        "/api/v2/inbounds?page=1&pageSize=100",
        None,
    )
    .await;
    assert!(
        configured_inbounds["items"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item["id"] == "http-chain-in")),
        "configured inbounds: {configured_inbounds}"
    );

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
    let mut client = if let Some(client) = client {
        client
    } else {
        let logs = api_json(
            &service.client,
            &service.base_url,
            http::Method::POST,
            "/api/v2/rpc/tools.logs",
            Some(&json!({})),
        )
        .await;
        panic!(
            "HTTP inbound did not start; logs={logs}; stderr={}",
            service.diagnostics()
        );
    };
    let authority = format!("example.test:{}", fixture.target.port());
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut headers = Vec::new();
    let mut buffer = [0u8; 1024];
    while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        let length = client.read(&mut buffer).await.unwrap();
        assert!(length > 0, "HTTP inbound closed before CONNECT response");
        headers.extend_from_slice(&buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));

    client.write_all(b"integration-payload").await.unwrap();
    let mut payload = [0u8; 19];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"integration-payload");

    let connection = wait_for_connection(&service.client, &service.base_url).await;
    let item = connection["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "HTTP chain inbound")
        .expect("HTTP inbound connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], fixture.outbound.to_string());
    assert_eq!(item["nodeId"], "http-out");
    assert_eq!(item["mode"], "proxy");
    assert!(
        item["localAddr"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert_ne!(item["localAddr"], inbound.to_string());
    assert_eq!(item["network"]["underlyingType"], "tcp");
    assert_eq!(item["protocol"], "");
    assert!(item["matchHistory"].as_array().is_some_and(|history| {
        history
            .iter()
            .any(|entry| entry["ruleName"] == "proxy-example-test")
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

    let route_test = api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/route/rules/test",
        Some(&json!({"host":authority})),
    )
    .await;
    assert_eq!(route_test["mode"], "proxy");

    let latency = api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/nodes/http-out/latency",
        Some(&json!({
            "type":"tcp",
            "url":format!("http://{authority}/health")
        })),
    )
    .await;
    assert_eq!(latency["ok"], true, "latency response: {latency}");

    let authorities = fixture
        .connect_authorities
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert!(authorities.iter().any(|value| value == &authority));

    client.shutdown().await.unwrap();
    for _ in 0..100 {
        let current = api_json(
            &service.client,
            &service.base_url,
            http::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        if current["connections"].as_array().is_some_and(Vec::is_empty) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    service.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transparent_go_inbound_transports_route_http() {
    let fixture = ConnectFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();

    for transport in ["proxy", "http_mock"] {
        let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound = inbound_listener.local_addr().unwrap();
        drop(inbound_listener);

        let root = integration_dir(&format!("service-http-transport-{transport}"));
        std::fs::create_dir_all(&root).unwrap();
        let database = root.join("state.sqlite");
        seed_empty_database(&database).await;
        let service = ServiceProcess::start(&database).await;
        let inbound_id = format!("http-{transport}-in");
        configure_http_chain_with_transport(
            &service,
            inbound,
            fixture.outbound,
            &inbound_id,
            transport,
        )
        .await;

        let authority = format!("example.test:{}", fixture.target.port());
        let (mut client, headers) = http_connect_with_auth(inbound, &authority, None)
            .await
            .unwrap();
        assert!(
            headers.starts_with("HTTP/1.1 200"),
            "{transport} inbound response: {headers}"
        );
        let payload = format!("{transport}-inbound-transport");
        client.write_all(payload.as_bytes()).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload.as_bytes(), "transport {transport}");
        client.shutdown().await.unwrap();

        service.shutdown().await;
    }

    fixture.shutdown().await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn process_and_inbound_route_matchers_select_real_http_outbound() {
    let fixture = ConnectFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let root = integration_dir("service-process-inbound-route");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    let process_path = std::env::current_exe().unwrap();
    configure_http_process_inbound_chain(
        &service,
        inbound,
        fixture.outbound,
        process_path.to_str().unwrap(),
    )
    .await;

    let authority = format!("example.test:{}", fixture.target.port());
    let (mut client, headers) = http_connect_with_auth(inbound, &authority, None)
        .await
        .unwrap();
    assert!(
        headers.starts_with("HTTP/1.1 200"),
        "HTTP response: {headers}"
    );
    let payload = b"process-inbound-route-payload";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, payload);

    let connection = wait_for_connection(&service.client, &service.base_url).await;
    let item = connection["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "HTTP process matcher inbound")
        .expect("process/inbound matcher connection must be visible");
    assert_eq!(item["mode"], "proxy");
    assert_eq!(item["outbound"], fixture.outbound.to_string());
    assert!(item["process"].as_str().is_some_and(|value| {
        value == process_path.to_str().unwrap() || value.ends_with(" (deleted)")
    }));
    assert!(
        item["lists"]
            .as_array()
            .is_some_and(|lists| { lists.iter().any(|value| value == "process-current") }),
        "connection metadata: {item}"
    );
    assert!(item["matchHistory"].as_array().is_some_and(|history| {
        history
            .iter()
            .any(|entry| entry["ruleName"] == "proxy-process-inbound")
    }));
    let authorities = fixture
        .connect_authorities
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert!(
        authorities.iter().any(|value| value == &authority),
        "HTTP outbound authorities: {authorities:?}"
    );

    client.shutdown().await.unwrap();
    service.shutdown().await;
    fixture.shutdown().await;
}
