use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reverse_inbounds_route_through_the_runtime_process() {
    let reverse_tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reverse_tcp_inbound = reverse_tcp_listener.local_addr().unwrap();
    drop(reverse_tcp_listener);
    let reverse_http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reverse_http_inbound = reverse_http_listener.local_addr().unwrap();
    drop(reverse_http_listener);

    let tcp_target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_target = tcp_target_listener.local_addr().unwrap();
    let tcp_target_payload = b"reverse-process-tcp";
    let tcp_target_task = tokio::spawn(async move {
        let (mut stream, _) = tcp_target_listener.accept().await.unwrap();
        let mut payload = vec![0u8; tcp_target_payload.len()];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, tcp_target_payload);
        stream.write_all(tcp_target_payload).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    let http_target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_target = http_target_listener.local_addr().unwrap();
    let http_target_task = tokio::spawn(async move {
        let (mut stream, _) = http_target_listener.accept().await.unwrap();
        let request = read_http_headers(&mut stream).await;
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET /base/health HTTP/1.1\r\n"));
        assert!(request.contains(&format!("Host: {http_target}\r\n")));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nreverse-ok!",
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    let root = integration_dir("service-reverse-inbounds");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    add_reverse_inbounds(
        &service,
        reverse_tcp_inbound,
        tcp_target,
        reverse_http_inbound,
        &format!("http://{http_target}/base"),
    )
    .await;

    let mut reverse_tcp = connect_loopback(reverse_tcp_inbound).await;
    reverse_tcp.write_all(tcp_target_payload).await.unwrap();
    let mut echoed = vec![0u8; tcp_target_payload.len()];
    reverse_tcp.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, tcp_target_payload);

    let mut reverse_http = connect_loopback(reverse_http_inbound).await;
    reverse_http
        .write_all(b"GET /health HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response_headers = Vec::new();
    let mut buffer = [0u8; 1024];
    while !response_headers
        .windows(4)
        .any(|window| window == b"\r\n\r\n")
    {
        let length = tokio::time::timeout(Duration::from_secs(2), reverse_http.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert!(length > 0, "reverse HTTP inbound closed before response");
        response_headers.extend_from_slice(&buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&response_headers).starts_with("HTTP/1.1 200 OK"));
    let body_start = response_headers
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let mut body = response_headers.split_off(body_start);
    while body.len() < 11 {
        let length = tokio::time::timeout(Duration::from_secs(2), reverse_http.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert!(
            length > 0,
            "reverse HTTP inbound closed before response body"
        );
        body.extend_from_slice(&buffer[..length]);
    }
    assert_eq!(&body[..11], b"reverse-ok!");

    let mut connections = serde_json::Value::Null;
    for _ in 0..100 {
        connections = api_json(
            &service.client,
            &service.base_url,
            http::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        let items = connections["connections"].as_array().unwrap();
        if items
            .iter()
            .any(|item| item["inboundName"] == "Reverse TCP integration inbound")
            && items
                .iter()
                .any(|item| item["inboundName"] == "Reverse HTTP integration inbound")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let items = connections["connections"].as_array().unwrap();
    let tcp_connection = items
        .iter()
        .find(|item| item["inboundName"] == "Reverse TCP integration inbound")
        .expect("reverse TCP inbound connection must be visible");
    assert_eq!(tcp_connection["inbound"], reverse_tcp_inbound.to_string());
    assert_eq!(tcp_connection["outbound"], tcp_target.to_string());
    let http_connection = items
        .iter()
        .find(|item| item["inboundName"] == "Reverse HTTP integration inbound")
        .expect("reverse HTTP inbound connection must be visible");
    assert_eq!(http_connection["inbound"], reverse_http_inbound.to_string());
    assert_eq!(http_connection["outbound"], http_target.to_string());
    assert_eq!(http_connection["mode"], "direct");

    reverse_tcp.shutdown().await.unwrap();
    reverse_http.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), tcp_target_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), http_target_task)
        .await
        .unwrap()
        .unwrap();
    service.shutdown().await;
}

async fn write_reverse_http_request<S>(client: &mut S, host: &str)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    client
        .write_all(
            format!("GET /health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
}

async fn read_reverse_http_response<S>(client: &mut S) -> Vec<u8>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    response
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reverse_http_inbound_routes_through_http_termination_outbound() {
    reverse_http_termination_service_chain(false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reverse_http_inbound_routes_through_tls_and_http_termination_outbound() {
    reverse_http_termination_service_chain(true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reverse_http_inbound_routes_through_standalone_tls_termination_without_sni() {
    reverse_http_termination_service_chain(true, true).await;
}

async fn reverse_http_termination_service_chain(tls_termination: bool, standalone_tls: bool) {
    assert!(!standalone_tls || tls_termination);
    let reverse_http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reverse_http_inbound = reverse_http_listener.local_addr().unwrap();
    drop(reverse_http_listener);

    let http_target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_target = http_target_listener.local_addr().unwrap();
    let expected_path = if tls_termination {
        "/health"
    } else {
        "/base/health"
    };
    let http_target_task = tokio::spawn(async move {
        let (mut stream, _) = http_target_listener.accept().await.unwrap();
        let request = read_http_headers(&mut stream).await;
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")));
        let request_lower = request.to_ascii_lowercase();
        assert!(request_lower.contains(&format!("host: 127.0.0.1:{}\r\n", http_target.port())));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\ntermination-ok!",
            )
            .await
            .unwrap();
    });

    // The three termination variants run concurrently in the default Rust
    // test harness. Keep their SQLite stores separate; sharing this directory
    // makes one service's migration/cleanup race with another and can surface
    // as a misleading TLS InvalidContentType handshake failure.
    let root = integration_dir(&format!(
        "service-reverse-http-termination-{tls_termination}-{standalone_tls}"
    ));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;

    let mut chain = vec![json!({"type":"direct","direct":{}})];
    if !standalone_tls {
        chain.push(json!({
            "type":"http_termination",
            "http_termination":{"headers":{}}
        }));
    }
    if tls_termination {
        chain.push(json!({
            "type":"tls_termination",
            "tls_termination":{
                "tls":{
                    "certificates":[tls_termination_certificate()],
                    "nextProtos":[]
                }
            }
        }));
    }
    let node = json!({
        "id":"reverse-http-termination",
        "name":"Reverse HTTP termination outbound",
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
        "/api/v2/nodes/reverse-http-termination/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"reverse-http-termination-in",
        "name":"Reverse HTTP termination inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":reverse_http_inbound.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"reverse_http","reverse_http":{"url":format!("http://127.0.0.1:{}/base", http_target.port())}}
    });
    api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/route/rules",
        Some(&json!({
            "name":"reverse-http-termination-proxy",
            "mode":"proxy",
            "match":{"cidr":"127.0.0.1/32"}
        })),
    )
    .await;
    // Fresh stores contain the built-in LAN rule (127.0.0.1/8) at the first
    // priority. This scenario intentionally proxies a loopback target, so
    // make that precedence explicit instead of relying on insertion order.
    api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/route/rules/priority",
        Some(&json!({
            "source":{"name":"reverse-http-termination-proxy","index":2},
            "target":{"name":"LAN","index":1},
            "operate":"insert_before"
        })),
    )
    .await;
    let route_test = api_json(
        &service.client,
        &service.base_url,
        http::Method::POST,
        "/api/v2/route/rules/test",
        Some(&json!({"host":format!("127.0.0.1:{}", http_target.port())})),
    )
    .await;
    assert_eq!(route_test["mode"], "proxy", "reverse termination route");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let connections = if tls_termination {
        let client = tokio::time::timeout(Duration::from_secs(5), async {
            if standalone_tls {
                connect_tls_loopback_without_sni(reverse_http_inbound).await
            } else {
                connect_tls_loopback(reverse_http_inbound).await
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "TLS termination handshake timed out; runtime diagnostics: {}",
                service.diagnostics()
            )
        });
        let mut client = client;
        write_reverse_http_request(&mut client, &format!("127.0.0.1:{}", http_target.port())).await;
        let connections = wait_for_connection(&service.client, &service.base_url).await;
        let response = read_reverse_http_response(&mut client).await;
        (connections, response)
    } else {
        let mut client = connect_loopback(reverse_http_inbound).await;
        write_reverse_http_request(&mut client, "public.example").await;
        let connections = wait_for_connection(&service.client, &service.base_url).await;
        let response = read_reverse_http_response(&mut client).await;
        (connections, response)
    };
    let (connections, response) = connections;
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK"),
        "response={response:?}"
    );
    assert!(
        response.ends_with(b"termination-ok!"),
        "response={response:?}"
    );

    let connection = connections["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "Reverse HTTP termination inbound")
        .expect("HTTP termination reverse connection must be visible");
    assert_eq!(connection["inbound"], reverse_http_inbound.to_string());
    assert_eq!(connection["mode"], "proxy");

    tokio::time::timeout(Duration::from_secs(2), http_target_task)
        .await
        .unwrap()
        .unwrap();
    service.shutdown().await;
}
