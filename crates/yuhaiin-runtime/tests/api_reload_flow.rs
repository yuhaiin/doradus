mod support;

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use support::{
    ConnectFixture, ServiceProcess, api_json, configure_http_chain, connect_loopback,
    integration_dir, reserve_loopback, seed_empty_database,
};

async fn connect_and_echo(inbound: SocketAddr, authority: &str, payload: &[u8]) {
    let mut client = connect_loopback(inbound).await;
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
            "HTTP inbound closed before reload-flow response"
        );
        headers.extend_from_slice(&buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));

    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    client.shutdown().await.unwrap();
}

async fn wait_for_authority(fixture: &ConnectFixture, expected: &str) {
    for _ in 0..100 {
        let authorities = fixture
            .connect_authorities
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if authorities.iter().any(|authority| authority == expected) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("HTTP fixture did not receive CONNECT authority {expected}");
}

async fn wait_for_listener_closed(address: SocketAddr) {
    for _ in 0..100 {
        if TcpStream::connect(address).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("old inbound listener {address} remained active after PUT reload");
}

async fn wait_for_history(service: &ServiceProcess) -> serde_json::Value {
    for _ in 0..100 {
        let history = api_json(
            &service.client,
            &service.base_url,
            reqwest::Method::GET,
            "/api/v2/connections/history",
            None,
        )
        .await;
        if history["items"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["connection"]["inboundName"] == "http-chain-in"
                    && item["count"]
                        .as_str()
                        .and_then(|value| value.parse::<u64>().ok())
                        .is_some_and(|count| count > 0)
            })
        }) {
            return history;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("reload-flow connections history did not become visible");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_mutations_reload_real_flow_and_survive_restart() {
    let first = ConnectFixture::start().await;
    let second = ConnectFixture::start().await;
    let inbound = reserve_loopback().await;
    let root = integration_dir("api-reload-flow");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;

    let service = ServiceProcess::start(&database).await;
    configure_http_chain(&service, inbound, first.outbound).await;

    let first_authority = format!("example.test:{}", first.target.port());
    connect_and_echo(inbound, &first_authority, b"before-reload").await;
    wait_for_authority(&first, &first_authority).await;

    let updated_node = json!({
        "name":"HTTP test outbound after reload",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":second.outbound.port()}},
            {"type":"http","http":{"user":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::PUT,
        "/api/v2/nodes/http-out",
        Some(&updated_node),
    )
    .await;

    let latency = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes/http-out/latency",
        Some(&json!({
            "type":"tcp",
            "url":format!("http://example.test:{}/health", second.target.port())
        })),
    )
    .await;
    assert_eq!(latency["ok"], true, "reloaded node latency: {latency}");

    let second_authority = format!("example.test:{}", second.target.port());
    connect_and_echo(inbound, &second_authority, b"after-reload").await;
    wait_for_authority(&second, &second_authority).await;
    assert!(
        first
            .connect_authorities
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .any(|authority| authority == &first_authority)
    );
    assert!(
        second
            .connect_authorities
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .any(|authority| authority == &second_authority)
    );

    let moved_inbound = reserve_loopback().await;
    let updated_inbound = json!({
        "name":"HTTP chain inbound moved",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":moved_inbound.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::PUT,
        "/api/v2/inbounds/http-chain-in",
        Some(&updated_inbound),
    )
    .await;
    wait_for_listener_closed(inbound).await;
    connect_and_echo(moved_inbound, &second_authority, b"after-inbound-reload").await;

    let proxy_authority_count_before_direct_route = second
        .connect_authorities
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .len();
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::PUT,
        "/api/v2/route/rules/proxy-example-test/0",
        Some(&json!({
            "mode":"direct",
            "match":{"domain":"localhost"},
            "tag":"integration"
        })),
    )
    .await;
    let route_test = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules/test",
        Some(&json!({"host":format!("localhost:{}", second.target.port())})),
    )
    .await;
    assert_eq!(route_test["mode"], "direct", "reloaded route: {route_test}");
    connect_and_echo(
        moved_inbound,
        &format!("localhost:{}", second.target.port()),
        b"after-route-reload",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let proxy_authority_count_after_direct_route = second
        .connect_authorities
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .len();
    assert_eq!(
        proxy_authority_count_after_direct_route, proxy_authority_count_before_direct_route,
        "direct route must bypass the HTTP outbound fixture"
    );

    let total = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::GET,
        "/api/v2/connections/total",
        None,
    )
    .await;
    assert!(
        total["upload"]
            .as_str()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|value| value > 0),
        "reload-flow total: {total}"
    );

    let range_end = OffsetDateTime::now_utc();
    let range_start = (range_end - time::Duration::hours(1))
        .format(&Rfc3339)
        .unwrap();
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
    assert!(
        traffic["items"].as_array().is_some_and(|items| {
            items.iter().any(|item| {
                item["upload"]
                    .as_str()
                    .and_then(|value| value.parse::<u64>().ok())
                    .is_some_and(|value| value > 0)
            })
        }),
        "reload-flow traffic: {traffic}"
    );
    let history = wait_for_history(&service).await;

    service.shutdown().await;
    let restarted = ServiceProcess::start(&database).await;
    let nodes = api_json(
        &restarted.client,
        &restarted.base_url,
        reqwest::Method::GET,
        "/api/v2/nodes?page=1&pageSize=100",
        None,
    )
    .await;
    let node = nodes["items"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["id"] == "http-out"))
        .unwrap_or_else(|| panic!("reloaded node missing after restart: {nodes}"));
    assert_eq!(node["chain"][0]["fixed"]["port"], second.outbound.port());

    let inbounds = api_json(
        &restarted.client,
        &restarted.base_url,
        reqwest::Method::GET,
        "/api/v2/inbounds?page=1&pageSize=100",
        None,
    )
    .await;
    assert!(inbounds["items"].as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item["id"] == "http-chain-in"
                && item["network"]["tcp_udp"]["host"] == moved_inbound.to_string()
        })
    }));
    let persisted_total = api_json(
        &restarted.client,
        &restarted.base_url,
        reqwest::Method::GET,
        "/api/v2/connections/total",
        None,
    )
    .await;
    assert_ne!(persisted_total["upload"], "0");
    let persisted_history = api_json(
        &restarted.client,
        &restarted.base_url,
        reqwest::Method::GET,
        "/api/v2/connections/history",
        None,
    )
    .await;
    assert!(persisted_history["items"].as_array().is_some_and(|items| {
        items
            .iter()
            .any(|item| item["connection"]["inboundName"] == "http-chain-in")
    }));
    assert!(history["items"].is_array());

    restarted.shutdown().await;
    first.shutdown().await;
    second.shutdown().await;
}
