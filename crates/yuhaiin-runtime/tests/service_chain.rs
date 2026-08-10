mod support;

use base64::Engine;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::Request;
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use yuhaiin_chain::AsyncYuubinsyaTcpSession;
use yuhaiin_core::{DomainName, Endpoint, Network};

use support::{
    ConnectFixture, H2FinalProtocol, H2ProtocolFixture, H2YuubinsyaFixture, ServiceProcess,
    Socks5Fixture, YUUBINSYA_PASSWORD, add_mixed_udp_inbound, add_socks5_inbound,
    add_yuubinsya_inbound, api_json, configure_h2_http_chain, configure_h2_http_inbound,
    configure_h2_socks5_chain, configure_http_chain, configure_http_process_inbound_chain,
    configure_socks5_chain, configure_tls_h2_http_inbound, configure_tls_h2_yuubinsya_chain,
    configure_tls_http_inbound, connect_loopback, connect_tls_h2_loopback, connect_tls_loopback,
    integration_dir, seed_empty_database, wait_for_connection,
};

async fn http_connect_with_auth(
    address: SocketAddr,
    authority: &str,
    token: Option<&str>,
) -> std::io::Result<(TcpStream, String)> {
    let mut stream = connect_loopback(address).await;
    let authorization = token
        .map(|token| format!("Proxy-Authorization: Basic {token}\r\n"))
        .unwrap_or_default();
    stream
        .write_all(
            format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{authorization}\r\n")
                .as_bytes(),
        )
        .await?;
    let mut headers = Vec::new();
    let mut buffer = [0u8; 1024];
    while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        let length = match stream.read(&mut buffer).await {
            Ok(length) => length,
            Err(_) => break,
        };
        if length == 0 {
            break;
        }
        headers.extend_from_slice(&buffer[..length]);
    }
    Ok((stream, String::from_utf8_lossy(&headers).into_owned()))
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
        .find(|item| item["inboundName"] == "h2-http-in")
        .expect("HTTP/2 inbound connection must be visible");
    assert_eq!(item["inbound"], "http");
    assert_eq!(item["outbound"], fixture.outbound.to_string());
    assert_eq!(item["protocol"], "http");

    let total = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::GET,
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
    let fixture = ConnectFixture::start().await;
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let root = integration_dir("service-tls-http-inbound");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_tls_http_inbound(&service, inbound).await;

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
    let item = connection["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "tls-http-in")
        .expect("TLS HTTP inbound connection must be visible");
    assert_eq!(item["inbound"], "http");
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
        .find(|item| item["inboundName"] == "tls-h2-http-in")
        .expect("TLS/HTTP2 inbound connection must be visible");
    assert_eq!(item["inbound"], "http");
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

async fn run_h2_protocol_chain(protocol: H2FinalProtocol) {
    let fixture = H2ProtocolFixture::start(protocol).await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let (node_id, inbound_id, rule_name) = match protocol {
        H2FinalProtocol::Http => (
            "h2-http-out",
            "h2-http-chain-in",
            "proxy-example-test-over-h2-http",
        ),
        H2FinalProtocol::Socks5 => (
            "h2-socks5-out",
            "h2-socks5-chain-in",
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
        .find(|item| item["inboundName"] == inbound_id)
        .expect("HTTP/2 protocol chain connection must be visible");
    assert_eq!(item["inbound"], "http");
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
        reqwest::Method::POST,
        &format!("/api/v2/nodes/{node_id}/latency"),
        Some(&json!({"type":"tcp","url":"http://example.test:443/health"})),
    )
    .await;
    assert_eq!(latency["ok"], true, "H2 protocol chain latency: {latency}");

    client.shutdown().await.unwrap();
    service.shutdown().await;
    fixture.shutdown().await;
}

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
        reqwest::Method::GET,
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
            reqwest::Method::POST,
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
        .find(|item| item["inboundName"] == "http-chain-in")
        .expect("HTTP inbound connection must be visible");
    assert_eq!(item["inbound"], "http");
    assert_eq!(item["outbound"], fixture.outbound.to_string());
    assert_eq!(item["mode"], "proxy");
    assert_eq!(item["localAddr"], inbound.to_string());
    assert_eq!(item["network"]["underlyingType"], "tcp");
    assert_eq!(item["protocol"], "http");
    assert!(item["matchHistory"].as_array().is_some_and(|history| {
        history
            .iter()
            .any(|entry| entry["ruleName"] == "proxy-example-test")
    }));

    let total = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::GET,
        "/api/v2/connections/total",
        None,
    )
    .await;
    assert!(total["upload"].as_str().unwrap().parse::<u64>().unwrap() > 0);

    let route_test = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules/test",
        Some(&json!({"host":authority})),
    )
    .await;
    assert_eq!(route_test["mode"], "proxy");

    let latency = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
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
            reqwest::Method::GET,
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
        .find(|item| item["inboundName"] == "http-process-in")
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn central_basic_user_authenticates_http_inbound_chain() {
    let fixture = ConnectFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let inbound = inbound_listener.local_addr().unwrap();
    drop(inbound_listener);

    let root = integration_dir("service-central-http-auth");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_http_chain(&service, inbound, fixture.outbound).await;

    let user = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/users",
        Some(&json!({
            "id":"central-http-user",
            "name":"Central HTTP user",
            "enabled":true,
            "origin":"manual",
            "usage":"inbound",
            "credential":{
                "type":"basic",
                "basic":{
                    "username":"central-user",
                    "password":"central-password"
                }
            }
        })),
    )
    .await;
    let user_id = user["id"].as_str().unwrap();
    let user_path = format!("/api/v2/users/{user_id}");

    let good_token =
        base64::engine::general_purpose::STANDARD.encode("central-user:central-password");
    let bad_token = base64::engine::general_purpose::STANDARD.encode("central-user:wrong");
    let authority = format!("example.test:{}", fixture.target.port());
    let mut central_auth_ready = false;
    let mut last_probe_headers = Vec::new();
    for _ in 0..100 {
        let Ok((mut probe, response)) =
            http_connect_with_auth(inbound, &authority, Some(&bad_token)).await
        else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        let rejected = response.starts_with("HTTP/1.1 403");
        last_probe_headers = response.into_bytes();
        let _ = probe.shutdown().await;
        if rejected {
            central_auth_ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        central_auth_ready,
        "central inbound auth snapshot did not reload; headers={:?}; logs={}",
        String::from_utf8_lossy(&last_probe_headers),
        service.diagnostics()
    );

    let (mut client, response) = http_connect_with_auth(inbound, &authority, Some(&good_token))
        .await
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));

    let payload = b"central-auth-http-payload";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, payload);

    let connection = wait_for_connection(&service.client, &service.base_url).await;
    let item = connection["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == "http-chain-in")
        .expect("central-auth HTTP inbound connection must be visible");
    assert_eq!(item["inbound"], "http");
    assert_eq!(item["outbound"], fixture.outbound.to_string());
    assert!(item["matchHistory"].as_array().is_some_and(|history| {
        history
            .iter()
            .any(|entry| entry["ruleName"] == "proxy-example-test")
    }));

    client.shutdown().await.unwrap();

    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::PUT,
        &user_path,
        Some(&json!({
            "name":"Central HTTP user updated",
            "enabled":true,
            "usage":"inbound",
            "credential":{
                "type":"basic",
                "basic":{
                    "username":"central-user-v2",
                    "password":"central-password-v2"
                }
            }
        })),
    )
    .await;
    let old_token = good_token;
    let new_token =
        base64::engine::general_purpose::STANDARD.encode("central-user-v2:central-password-v2");
    let mut updated = false;
    for _ in 0..100 {
        let Ok((mut probe, response)) =
            http_connect_with_auth(inbound, &authority, Some(&old_token)).await
        else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        let rejected = response.starts_with("HTTP/1.1 403");
        let _ = probe.shutdown().await;
        if rejected {
            updated = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(updated, "updated central user credential did not reload");
    let (mut updated_client, response) =
        http_connect_with_auth(inbound, &authority, Some(&new_token))
            .await
            .unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    updated_client
        .write_all(b"central-auth-http-updated-payload")
        .await
        .unwrap();
    let mut updated_echo = vec![0u8; b"central-auth-http-updated-payload".len()];
    updated_client.read_exact(&mut updated_echo).await.unwrap();
    assert_eq!(&updated_echo, b"central-auth-http-updated-payload");
    updated_client.shutdown().await.unwrap();

    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::DELETE,
        &user_path,
        None,
    )
    .await;
    let mut deleted = false;
    for _ in 0..100 {
        let Ok((mut probe, response)) = http_connect_with_auth(inbound, &authority, None).await
        else {
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        let available = response.starts_with("HTTP/1.1 200");
        let _ = probe.shutdown().await;
        if available {
            deleted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(deleted, "deleted central user auth did not reload");

    service.shutdown().await;
    fixture.shutdown().await;
}

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
        .find(|item| item["inboundName"] == "socks5-chain-in")
        .expect("SOCKS5 outbound chain connection must be visible");
    assert_eq!(item["inbound"], "http");
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
        reqwest::Method::POST,
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
        .find(|item| item["inboundName"] == "tls-h2-yuubinsya-in")
        .expect("TLS/H2/Yuubinsya connection must be visible");
    assert_eq!(item["inbound"], "http");
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
            reqwest::Method::POST,
            "/api/v2/rpc/tools.logs",
            Some(&json!({})),
        )
        .await;
        let inbounds = api_json(
            &service.client,
            &service.base_url,
            reqwest::Method::GET,
            "/api/v2/inbounds?page=1&pageSize=100",
            None,
        )
        .await;
        let connections = api_json(
            &service.client,
            &service.base_url,
            reqwest::Method::GET,
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
        reqwest::Method::GET,
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
        reqwest::Method::GET,
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
        reqwest::Method::GET,
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
            reqwest::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        udp_connection = current["connections"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| item["inboundName"] == "tls-h2-yuubinsya-udp-in")
            })
            .cloned();
        if udp_connection.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let udp_item = udp_connection.expect("TLS/H2/Yuubinsya UDP connection must be visible");
    assert_eq!(udp_item["inbound"], "mixed");
    assert_eq!(udp_item["outbound"], fixture.outbound.to_string());
    assert_eq!(udp_item["mode"], "proxy");
    assert!(udp_length > udp_payload.len());

    let latency = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
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
            reqwest::Method::GET,
            "/api/v2/connections/history",
            None,
        )
        .await;
        history = current["items"].as_array().and_then(|items| {
            items
                .iter()
                .find(|item| item["connection"]["inboundName"] == "tls-h2-yuubinsya-in")
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
        yuhaiin_core::yuubinsya::derive_salt(YUUBINSYA_PASSWORD.as_bytes()),
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
    for (inbound, protocol) in [
        ("tls-h2-yuubinsya-socks5-in", "socks5"),
        ("tls-h2-yuubinsya-yuubinsya-in", "yuubinsya"),
    ] {
        let item = connections
            .iter()
            .find(|item| item["inboundName"] == inbound)
            .unwrap_or_else(|| panic!("connection for {inbound} is missing"));
        assert_eq!(item["inbound"], protocol);
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
        reqwest::Method::POST,
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

async fn read_socks5_reply(stream: &mut TcpStream) {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[..3], [5, 0, 0]);
    let address_length = match header[3] {
        1 => 4,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await.unwrap();
            usize::from(length[0])
        }
        4 => 16,
        atyp => panic!("unexpected SOCKS5 reply address type {atyp}"),
    };
    let mut address_and_port = vec![0u8; address_length + 2];
    stream.read_exact(&mut address_and_port).await.unwrap();
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
        reqwest::Method::PUT,
        "/api/v2/inbounds/mixed",
        Some(&mixed_config),
    )
    .await;

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = b"mixed-udp-payload";
    let mut packet = vec![0, 0, 0, 1];
    match target_address {
        SocketAddr::V4(address) => packet.extend_from_slice(&address.ip().octets()),
        SocketAddr::V6(_) => panic!("mixed UDP integration target must be IPv4"),
    }
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
    assert_eq!(item["inbound"], "mixed");
    assert_eq!(item["outbound"], target_address.to_string());
    assert!(length > payload.len());

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
        yuhaiin_core::yuubinsya::derive_salt(YUUBINSYA_PASSWORD.as_bytes()),
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
        .find(|item| item["inboundName"] == "socks5-required-in")
        .expect("SOCKS5 inbound connection must be visible");
    assert_eq!(socks5_connection["inbound"], "socks5");
    assert_eq!(socks5_connection["outbound"], fixture.target.to_string());
    let yuubinsya_connection = connections
        .iter()
        .find(|item| item["inboundName"] == "yuubinsya-required-in")
        .expect("Yuubinsya inbound connection must be visible");
    assert_eq!(yuubinsya_connection["inbound"], "yuubinsya");
    assert_eq!(yuubinsya_connection["outbound"], fixture.target.to_string());

    yuubinsya.shutdown().await.unwrap();
    socks5.shutdown().await.unwrap();
    service.shutdown().await;
    fixture.shutdown().await;
}
