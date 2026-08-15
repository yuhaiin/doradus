mod support;

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use yuhaiin_chain::AsyncYuubinsyaTcpSession;
use yuhaiin_core::{Endpoint, Network};

use support::{
    ConnectFixture, ServiceProcess, YUUBINSYA_PASSWORD, add_socks5_inbound, add_yuubinsya_inbound,
    api_json, configure_http_chain, connect_loopback, echo_on_tunnel, integration_dir,
    open_http_tunnel, reserve_loopback, seed_empty_database,
};

async fn connect_and_echo(inbound: SocketAddr, authority: &str, payload: &[u8]) {
    let mut client = open_http_tunnel(inbound, authority).await;
    echo_on_tunnel(&mut client, payload).await;
    client.shutdown().await.unwrap();
}

async fn open_socks5_tunnel(
    inbound: SocketAddr,
    username: &str,
    password: &str,
    destination: SocketAddr,
) -> TcpStream {
    let mut client = connect_loopback(inbound).await;
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);

    let username = username.as_bytes();
    let password = password.as_bytes();
    let mut auth = vec![1, username.len() as u8];
    auth.extend_from_slice(username);
    auth.push(password.len() as u8);
    auth.extend_from_slice(password);
    client.write_all(&auth).await.unwrap();
    let mut auth_reply = [0u8; 2];
    client.read_exact(&mut auth_reply).await.unwrap();
    assert_eq!(auth_reply, [1, 0]);

    let mut request = vec![5, 1, 0];
    match destination {
        SocketAddr::V4(address) => {
            request.push(1);
            request.extend_from_slice(&address.ip().octets());
            request.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            request.push(4);
            request.extend_from_slice(&address.ip().octets());
            request.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    client.write_all(&request).await.unwrap();

    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[..2], [5, 0]);
    let address_len = match reply[3] {
        1 => 4,
        3 => {
            let mut length = [0u8; 1];
            client.read_exact(&mut length).await.unwrap();
            usize::from(length[0])
        }
        4 => 16,
        atyp => panic!("unexpected SOCKS5 reply address type {atyp}"),
    };
    let mut bound_address = vec![0u8; address_len + 2];
    client.read_exact(&mut bound_address).await.unwrap();
    client
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
    panic!("inbound listener {address} remained active after reload");
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
                item["connection"]["inboundName"] == "HTTP chain inbound moved"
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

    let mut disabled_inbound = updated_inbound.clone();
    disabled_inbound["enabled"] = json!(false);
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::PUT,
        "/api/v2/inbounds/http-chain-in",
        Some(&disabled_inbound),
    )
    .await;
    wait_for_listener_closed(moved_inbound).await;

    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::PUT,
        "/api/v2/inbounds/http-chain-in",
        Some(&updated_inbound),
    )
    .await;
    connect_and_echo(moved_inbound, &second_authority, b"after-inbound-reenable").await;

    let mut persistent = open_http_tunnel(moved_inbound, &second_authority).await;
    echo_on_tunnel(&mut persistent, b"before-route-reload-persistent").await;

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
    echo_on_tunnel(&mut persistent, b"after-route-reload-persistent").await;
    persistent.shutdown().await.unwrap();
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
            .any(|item| item["connection"]["inboundName"] == "HTTP chain inbound moved")
    }));
    assert!(history["items"].is_array());

    restarted.shutdown().await;
    first.shutdown().await;
    second.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_tun_inbound_toggle_reloads_and_persists() {
    let root = integration_dir("api-tun-toggle");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;

    let service = ServiceProcess::start(&database).await;
    let tun_id = "tun-api-toggle";
    let tun_name = format!("yrtun-api-toggle-{}", std::process::id());
    let mut config = json!({
        "name":"TUN API toggle",
        "enabled":false,
        "network":{"type":"empty","empty":{}},
        "transports":[],
        "protocol":{
            "type":"tun",
            "tun":{
                "name":tun_name,
                "mtu":1500,
                "portal":"10.42.0.1/24",
                "portalV6":"fd42::1/64",
                "routes":[],
                "excludes":[]
            }
        }
    });

    let path = format!("/api/v2/inbounds/{tun_id}");
    let saved = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::PUT,
        &path,
        Some(&config),
    )
    .await;
    assert_eq!(saved["id"], tun_id);
    assert_eq!(saved["enabled"], false);
    assert_eq!(saved["protocol"]["type"], "tun");

    config["enabled"] = json!(true);
    let enabled = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::PUT,
        &path,
        Some(&config),
    )
    .await;
    assert_eq!(enabled["enabled"], true);
    // Give the desktop TUN owner a chance to consume the reload. Rootless
    // Podman will fail closed at device creation; rootful Podman exercises the
    // same owner against a real namespace device.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let _ = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::GET,
        "/api/v2/info",
        None,
    )
    .await;

    config["enabled"] = json!(false);
    let disabled = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::PUT,
        &path,
        Some(&config),
    )
    .await;
    assert_eq!(disabled["enabled"], false);

    service.shutdown().await;
    let restarted = ServiceProcess::start(&database).await;
    let persisted = api_json(
        &restarted.client,
        &restarted.base_url,
        reqwest::Method::GET,
        &path,
        None,
    )
    .await;
    assert_eq!(persisted["id"], tun_id);
    assert_eq!(persisted["enabled"], false);
    assert_eq!(persisted["protocol"]["tun"]["name"], tun_name);
    restarted.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_adds_and_removes_socks5_and_yuubinsya_inbounds_live() {
    let fixture = ConnectFixture::start().await;
    let root = integration_dir("api-normal-inbound-add-remove");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;

    let service = ServiceProcess::start(&database).await;
    let http_inbound = reserve_loopback().await;
    configure_http_chain(&service, http_inbound, fixture.outbound).await;

    let socks5_inbound = reserve_loopback().await;
    let yuubinsya_inbound = reserve_loopback().await;
    add_socks5_inbound(
        &service,
        "api-live-socks5-in",
        socks5_inbound,
        "reload-user",
        "reload-password",
    )
    .await;
    add_yuubinsya_inbound(&service, "api-live-yuubinsya-in", yuubinsya_inbound).await;

    let mut socks5 = open_socks5_tunnel(
        socks5_inbound,
        "reload-user",
        "reload-password",
        fixture.target,
    )
    .await;
    echo_on_tunnel(&mut socks5, b"api-live-socks5-payload").await;

    let mut yuubinsya = AsyncYuubinsyaTcpSession::connect(
        connect_loopback(yuubinsya_inbound).await,
        yuhaiin_core::yuubinsya::derive_salt(YUUBINSYA_PASSWORD.as_bytes()),
        Endpoint::ip(Network::Tcp, fixture.target),
    )
    .await
    .unwrap();
    yuubinsya
        .write_all(b"api-live-yuubinsya-payload")
        .await
        .unwrap();
    let mut yuubinsya_echo = [0u8; 26];
    yuubinsya.read_exact(&mut yuubinsya_echo).await.unwrap();
    assert_eq!(&yuubinsya_echo, b"api-live-yuubinsya-payload");

    let mut connections = serde_json::Value::Null;
    for _ in 0..100 {
        connections = api_json(
            &service.client,
            &service.base_url,
            reqwest::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        let items = connections["connections"].as_array().unwrap();
        if items.iter().any(|item| {
            item["inboundName"] == "SOCKS5 integration inbound"
                && item["inbound"] == socks5_inbound.to_string()
        }) && items.iter().any(|item| {
            item["inboundName"] == "Yuubinsya integration inbound"
                && item["inbound"] == yuubinsya_inbound.to_string()
        }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let items = connections["connections"].as_array().unwrap();
    assert!(
        items.iter().any(|item| {
            item["inboundName"] == "SOCKS5 integration inbound"
                && item["inbound"] == socks5_inbound.to_string()
        }),
        "SOCKS5 live connection metadata: {items:?}"
    );
    assert!(
        items.iter().any(|item| {
            item["inboundName"] == "Yuubinsya integration inbound"
                && item["inbound"] == yuubinsya_inbound.to_string()
        }),
        "Yuubinsya live connection metadata: {items:?}"
    );

    yuubinsya.shutdown().await.unwrap();
    socks5.shutdown().await.unwrap();

    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::DELETE,
        "/api/v2/inbounds/api-live-socks5-in",
        None,
    )
    .await;
    wait_for_listener_closed(socks5_inbound).await;

    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::DELETE,
        "/api/v2/inbounds/api-live-yuubinsya-in",
        None,
    )
    .await;
    wait_for_listener_closed(yuubinsya_inbound).await;

    let inbounds = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::GET,
        "/api/v2/inbounds?page=1&pageSize=100",
        None,
    )
    .await;
    let items = inbounds["items"].as_array().unwrap();
    assert!(!items.iter().any(|item| {
        item["id"] == "api-live-socks5-in" || item["id"] == "api-live-yuubinsya-in"
    }));

    service.shutdown().await;
    fixture.shutdown().await;
}
