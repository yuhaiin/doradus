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
    ConnectFixture, H2YuubinsyaFixture, ServiceProcess, YUUBINSYA_PASSWORD, add_mixed_udp_inbound,
    add_socks5_inbound, add_yuubinsya_inbound, api_json, configure_http_chain,
    configure_tls_h2_yuubinsya_chain, connect_loopback, integration_dir, seed_empty_database,
    wait_for_connection,
};

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
    assert_eq!(item["outbound"], "http-out");
    assert_eq!(item["mode"], "proxy");
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
    assert_eq!(item["outbound"], "tls-h2-yuubinsya-out");
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
    assert_eq!(udp_item["outbound"], "tls-h2-yuubinsya-out");
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
    assert_eq!(item["outbound"], "direct");
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
    assert_eq!(socks5_connection["outbound"], "direct");
    let yuubinsya_connection = connections
        .iter()
        .find(|item| item["inboundName"] == "yuubinsya-required-in")
        .expect("Yuubinsya inbound connection must be visible");
    assert_eq!(yuubinsya_connection["inbound"], "yuubinsya");
    assert_eq!(yuubinsya_connection["outbound"], "direct");

    yuubinsya.shutdown().await.unwrap();
    socks5.shutdown().await.unwrap();
    service.shutdown().await;
    fixture.shutdown().await;
}
