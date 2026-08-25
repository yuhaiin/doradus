use std::{sync::Arc, time::Duration};

#[cfg(feature = "websocket")]
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
#[cfg(feature = "websocket")]
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue};

use super::*;
use crate::{RuntimeBuilder, RuntimeController};
use serde_json::json;
use yuhaiin_chain::AsyncYuubinsyaTcpSession;
use yuhaiin_core::dns_resolver::SystemAsyncIpResolver;
use yuhaiin_core::process::ProcessInfo;
use yuhaiin_core::{Endpoint, Network};
use yuhaiin_protocol::trojan::{self, Command};
use yuhaiin_protocol::vless::{self, Command as VlessCommand};
use yuhaiin_store::{ConfigStore, GoInboundRecord, GoNodeRecord};

#[cfg(feature = "doh-tls")]
const CA_CERTIFICATE_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBlTCCATugAwIBAgIUbS/bRRel4PtBGY4lbCYyc2lxKngwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNeXVoYWlpbi1wMC1jYTAeFw0yNjA4MDYxODIwMzRaFw0zNjA4
MDMxODIwMzRaMBgxFjAUBgNVBAMMDXl1aGFpaW4tcDAtY2EwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAATBHNZR0dSTLNKfYwheVmhyGdCeMBSibhHEGBzXtZ6v0nIA
DhHIIK38v1qnoiTWN9Fof8HXKfhvl1LxSY0rSqe0o2MwYTAdBgNVHQ4EFgQUhaYk
OXheQ1JzLpIKK4I2FEcRMyMwHwYDVR0jBBgwFoAUhaYkOXheQ1JzLpIKK4I2FEcR
MyMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID
SAAwRQIhAOzmDAm07/ezq+5WBQhYYOi/F1onvS4skssoRtRq8w8XAiBH0LCIlJk5
QX0jqAZz0309NRht+WWJtz28CPHvuhGXNg==
-----END CERTIFICATE-----
"#;

#[cfg(feature = "doh-tls")]
const LEAF_CERTIFICATE_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUA6T+/U88N9aMPipK+MdNsAFRUAUwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNeXVoYWlpbi1wMC1jYTAeFw0yNjA4MDYxODIwNDlaFw0zNjA4
MDMxODIwNDlaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABLPnwlYFERi1MgbJNuBHZV/eSpTGdJCQIOyxBt8LlR1ZTEG06pWy
FnJVIzUS4oPuuHc0RcDEltGb/WolyQlM75SjbTBrMBQGA1UdEQQNMAuCCWxvY2Fs
aG9zdDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUZoMmXETR998IsWt1
UTBOVMIs7jMwHwYDVR0jBBgwFoAUhaYkOXheQ1JzLpIKK4I2FEcRMyMwCgYIKoZI
zj0EAwIDSAAwRQIgGEU+sldusbLVAE/kxzZYXaMpIt6l+CZ0cC2jm7lQBqoCIQCw
M5PhuwMhCCb+dUnK6ueJUMHwyK3l2pIAJTMp9+cwqw==
-----END CERTIFICATE-----
"#;

#[cfg(feature = "doh-tls")]
const PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqkH6SeIb9vVEJ6WecsMk5Pn/a8sQ+vdNS/ZSkl3KwfoAoGCCqGSM49
AwEHoUQDQgAEs+fCVgURGLUyBsk24EdlX95KlMZ0kJAg7LEG3wuVHVlMQbTqlbIW
clUjNRLig+64dzRFwMSW0Zv9aiXJCUzvlA==
-----END EC PRIVATE KEY-----
"#;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(future)
}

#[test]
fn inbound_transport_allowlist_matches_go_transparent_wrappers() {
    for transport in [
        "normal",
        "TLS",
        "http2",
        "websocket",
        "aead",
        "proxy",
        "HTTP_MOCK",
    ] {
        assert!(
            is_supported_inbound_transport(transport),
            "transport {transport} should use the shared listener path"
        );
    }

    for transport in ["mux", "reality", "quic", "unknown"] {
        assert!(
            !is_supported_inbound_transport(transport),
            "transport {transport} must remain explicitly deferred"
        );
    }
    assert!(is_supported_inbound_transport("tls_auto"));
}

#[test]
fn inbound_stream_wrappers_unwrap_in_go_accept_order() {
    let names = |values: &[&str]| -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    };

    // Go wraps listeners in declaration order, therefore Accept unwraps
    // the first declared stream wrapper before the later one.
    assert!(!aead_before_tls(&names(&["tls", "aead", "http2"])));
    assert!(aead_before_tls(&names(&["aead", "tls", "http2"])));
    assert!(aead_before_tls(&names(&["aead", "tls_auto", "websocket"])));
    assert!(!aead_before_tls(&names(&["websocket", "aead"])));
}

async fn direct_runtime() -> (Arc<RuntimeProxySelector>, Arc<ConnectionMonitor>) {
    let store = ConfigStore::open_memory().await.unwrap();
    let controller = RuntimeController::from_builder(RuntimeBuilder::new(
        store,
        Arc::new(SystemAsyncIpResolver),
    ))
    .await
    .unwrap();
    controller
        .store()
        .repository()
        .put_go_node(&GoNodeRecord {
            id: "direct".to_owned(),
            name: "Direct".to_owned(),
            group_name: "default".to_owned(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types_json: br#"["direct"]"#.to_vec(),
            updated_at: 1,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        })
        .await
        .unwrap();
    controller.reload().await.unwrap();
    let selector = controller
        .build_proxy_selector("", "direct", "", "", Duration::from_secs(2))
        .await
        .unwrap();
    (selector, controller.monitor())
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_inbound_preserves_go_early_data_prefix() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (stream, early_data) = accept_websocket_stream(stream).await.unwrap();
        assert_eq!(early_data, b"early-data");
        let mut stream = PrefixedIo::new(early_data, stream);
        let mut received = vec![0u8; b"early-dataafter".len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, b"early-dataafter");
    });

    let raw = TcpStream::connect(address).await.unwrap();
    let mut request = format!("ws://{address}/proxy")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Key",
        HeaderValue::from_static("ZWFybHktZGF0YQ"),
    );
    request
        .headers_mut()
        .insert("early_data", HeaderValue::from_static("base64"));
    let (mut websocket, response) = tokio_tungstenite::client_async(request, raw).await.unwrap();
    assert_eq!(
        response
            .headers()
            .get("early_data")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    websocket
        .send(tokio_tungstenite::tungstenite::Message::binary(
            b"after".to_vec(),
        ))
        .await
        .unwrap();
    server.await.unwrap();
}

async fn echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while let Ok(size) = stream.read(&mut buffer).await {
                    if size == 0 || stream.write_all(&buffer[..size]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (address, task)
}

#[tokio::test]
async fn reverse_tcp_inbound_routes_a_raw_flow_through_shared_outbound() {
    let (selector, monitor) = direct_runtime().await;
    let (echo_address, echo_task) = echo_server().await;
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let spec = InboundSpec {
        id: "reverse-tcp-inbound".to_owned(),
        name: "reverse-tcp-inbound".to_owned(),
        protocol: "reverse_tcp".to_owned(),
        listen: "127.0.0.1:19084".parse().unwrap(),
        username: String::new(),
        password: String::new(),
        auth: None,
        udp_mode: UdpMode::Disabled,
        protocol_udp: false,
        transports: vec!["normal".to_owned()],
        aead_password: None,
        aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: Some(Endpoint::ip(Network::Tcp, echo_address)),
        reverse_http: None,
    };
    let task = tokio::spawn(crate::inbound::adapters::reverse::handle_tcp(
        Box::new(server),
        "127.0.0.1:41005".parse().unwrap(),
        InboundHandler::new(spec, selector, monitor),
    ));
    client.write_all(b"reverse-tcp-flow").await.unwrap();
    let mut echoed = [0u8; 16];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"reverse-tcp-flow");
    client.shutdown().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    echo_task.abort();
}

#[tokio::test]
async fn reverse_http_inbound_rewrites_requests_and_routes_response() {
    let (selector, monitor) = direct_runtime().await;
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target_listener.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await.unwrap();
        let headers = read_headers(&mut stream).await;
        let headers = String::from_utf8(headers).unwrap();
        assert!(headers.starts_with("GET /base/health HTTP/1.1\r\n"));
        assert!(headers.contains("Host: 127.0.0.1:"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nreverse-ok!",
            )
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let spec = InboundSpec {
        id: "reverse-http-inbound".to_owned(),
        name: "reverse-http-inbound".to_owned(),
        protocol: "reverse_http".to_owned(),
        listen: "127.0.0.1:19085".parse().unwrap(),
        username: String::new(),
        password: String::new(),
        auth: None,
        udp_mode: UdpMode::Disabled,
        protocol_udp: false,
        transports: vec!["normal".to_owned()],
        aead_password: None,
        aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: None,
        reverse_http: Some(ReverseHttpConfig {
            target: Endpoint::ip(Network::Tcp, target_address),
            path: "/base".to_owned(),
            authority: target_address.to_string(),
            https: false,
        }),
    };
    let task = tokio::spawn(crate::inbound::adapters::reverse::handle_http(
        Box::new(server),
        "127.0.0.1:41006".parse().unwrap(),
        InboundHandler::new(spec, selector, monitor),
    ));
    client
        .write_all(b"GET /health HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    assert!(response.ends_with(b"reverse-ok!"));
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    target_task.await.unwrap();
}

#[test]
fn reverse_inbound_fields_follow_go_contract_json() {
    let reverse_tcp = InboundSpec::from_record(GoInboundRecord {
        id: "reverse-tcp".to_owned(),
        name: "Reverse TCP".to_owned(),
        enabled: true,
        network_type: "tcp_udp".to_owned(),
        protocol_type: "reverse_tcp".to_owned(),
        transport_types_json: br#"[]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{
            "network":{"type":"tcp_udp","tcp_udp":{"host":":3000","udp":false}},
            "protocol":{"type":"reverse_tcp","reverse_tcp":{"host":"backend.example:3389"}}
        }"#
        .to_vec(),
    })
    .unwrap();
    assert_eq!(
        reverse_tcp.reverse_target,
        Some(Endpoint::domain(
            Network::Tcp,
            yuhaiin_core::DomainName::new("backend.example").unwrap(),
            3389,
        ))
    );

    let reverse_http = InboundSpec::from_record(GoInboundRecord {
        id: "reverse-http".to_owned(),
        name: "Reverse HTTP".to_owned(),
        enabled: true,
        network_type: "tcp_udp".to_owned(),
        protocol_type: "reverse_http".to_owned(),
        transport_types_json: br#"[]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{
            "network":{"type":"tcp_udp","tcp_udp":{"host":":3001","udp":false}},
            "protocol":{"type":"reverse_http","reverse_http":{"url":"https://api.example/base"}}
        }"#
        .to_vec(),
    })
    .unwrap();
    let reverse_http = reverse_http.reverse_http.unwrap();
    assert!(reverse_http.https);
    assert_eq!(reverse_http.path, "/base");
    assert_eq!(reverse_http.authority, "api.example");
    assert_eq!(reverse_http.target.port(), Some(443));

    let tproxy = InboundSpec::from_record(GoInboundRecord {
        id: "tproxy".to_owned(),
        name: "TProxy".to_owned(),
        enabled: true,
        network_type: "empty".to_owned(),
        protocol_type: "tproxy".to_owned(),
        transport_types_json: br#"[]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{
            "network":{"type":"empty"},
            "protocol":{"type":"tproxy","tproxy":{"host":"127.0.0.1:12345"}}
        }"#
        .to_vec(),
    })
    .unwrap();
    assert_eq!(tproxy.listen, "127.0.0.1:12345".parse().unwrap());
    assert_eq!(tproxy.udp_mode, UdpMode::Enabled);

    let mixed = InboundSpec::from_record(GoInboundRecord {
        id: "mixed-alias".to_owned(),
        name: "Mixed alias".to_owned(),
        enabled: true,
        network_type: "tcp_udp".to_owned(),
        protocol_type: "mix".to_owned(),
        transport_types_json: br#"[]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{
            "network":{"type":"tcp_udp","tcp_udp":{"host":"127.0.0.1:12346"}},
            "protocol":{"type":"mix","mix":{"username":"u","password":"p"}}
        }"#
        .to_vec(),
    })
    .unwrap();
    assert_eq!(mixed.protocol, "mixed");
    assert_eq!(mixed.username, "u");
    assert_eq!(mixed.password, "p");

    let mixed_with_whitespace = InboundSpec::from_record(GoInboundRecord {
        id: "mixed-whitespace".to_owned(),
        name: "Mixed whitespace".to_owned(),
        enabled: true,
        network_type: "tcp_udp".to_owned(),
        protocol_type: " MIXED ".to_owned(),
        transport_types_json: br#"[]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{
            "network":{"type":"tcp_udp","tcp_udp":{"host":"127.0.0.1:12348","udp":"enabled"}},
            "protocol":{"type":" MIXED ","mixed":{"username":"","password":""}}
        }"#
        .to_vec(),
    })
    .unwrap();
    assert_eq!(mixed_with_whitespace.protocol, "mixed");
    assert_eq!(mixed_with_whitespace.udp_mode, UdpMode::Enabled);
    assert!(supports_socks5_udp(
        &mixed_with_whitespace.protocol,
        mixed_with_whitespace.protocol_udp
    ));

    let none = InboundSpec::from_record(GoInboundRecord {
        id: "none".to_owned(),
        name: "None".to_owned(),
        enabled: true,
        network_type: "tcp_udp".to_owned(),
        protocol_type: "none".to_owned(),
        transport_types_json: br#"[]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{
            "network":{"type":"tcp_udp","tcp_udp":{"host":"127.0.0.1:12347"}},
            "protocol":{"type":"none","none":{}}
        }"#
        .to_vec(),
    })
    .unwrap();
    assert_eq!(none.protocol, "none");
}

#[tokio::test]
async fn none_inbound_accepts_and_closes_without_routing() {
    let (selector, monitor) = direct_runtime().await;
    let (mut client, server) = tokio::io::duplex(64);
    let spec = InboundSpec {
        id: "none".to_owned(),
        name: "none".to_owned(),
        protocol: "none".to_owned(),
        listen: "127.0.0.1:12347".parse().unwrap(),
        username: String::new(),
        password: String::new(),
        auth: None,
        udp_mode: UdpMode::Disabled,
        protocol_udp: false,
        transports: Vec::new(),
        aead_password: None,
        aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: None,
        reverse_http: None,
    };
    let handler = protocol_handler("none".to_owned(), spec, selector, monitor, None);
    let task = tokio::spawn(serve_connection(
        server,
        "127.0.0.1:12347".parse().unwrap(),
        handler,
    ));
    let mut byte = [0u8; 1];
    assert_eq!(client.read(&mut byte).await.unwrap(), 0);
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn aead_socks5_inbound_routes_through_shared_outbound() {
    let (selector, monitor) = direct_runtime().await;
    let (echo_address, echo_task) = echo_server().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let spec = InboundSpec {
        id: "aead-socks5-inbound".to_owned(),
        name: "aead-socks5-inbound".to_owned(),
        protocol: "socks5".to_owned(),
        listen: address,
        username: String::new(),
        password: String::new(),
        auth: None,
        udp_mode: UdpMode::Disabled,
        protocol_udp: false,
        transports: vec!["aead".to_owned()],
        aead_password: Some("secret".to_owned()),
        aead_method: yuhaiin_protocol::aead::CryptoMethod::XChacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: None,
        reverse_http: None,
    };
    let listener_task = tokio::spawn(serve_listener(listener, spec, selector, monitor, None));

    let raw = TcpStream::connect(address).await.unwrap();
    let mut client = yuhaiin_protocol::aead::client(
        Box::new(raw),
        b"secret",
        yuhaiin_protocol::aead::CryptoMethod::XChacha20Poly1305,
    )
    .await
    .unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    assert_eq!(read_exact_array::<2>(&mut client).await, [5, 0]);
    let mut request = vec![5, 1, 0, 1];
    let std::net::IpAddr::V4(echo_ip) = echo_address.ip() else {
        panic!("echo server must bind an IPv4 address");
    };
    request.extend_from_slice(&echo_ip.octets());
    request.extend_from_slice(&echo_address.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let reply = read_exact_array::<10>(&mut client).await;
    assert_eq!(reply[0..2], [5, 0]);
    client.write_all(b"aead-flow").await.unwrap();
    let mut echoed = [0u8; 9];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"aead-flow");

    listener_task.abort();
    let _ = listener_task.await;
    echo_task.abort();
}

async fn read_exact_array<const N: usize>(
    stream: &mut yuhaiin_core::proxy::BoxAsyncStream,
) -> [u8; N] {
    let mut value = [0u8; N];
    stream.read_exact(&mut value).await.unwrap();
    value
}

async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut headers = Vec::new();
    let mut byte = [0u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        headers.push(byte[0]);
    }
    headers
}

#[tokio::test]
async fn trojan_inbound_routes_a_real_tcp_flow_through_shared_outbound() {
    let (selector, monitor) = direct_runtime().await;
    let (echo_address, echo_task) = echo_server().await;
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let spec = InboundSpec {
        id: "trojan-inbound".to_owned(),
        name: "trojan-inbound".to_owned(),
        protocol: "trojan".to_owned(),
        listen: "127.0.0.1:19080".parse().unwrap(),
        username: String::new(),
        password: "secret".to_owned(),
        auth: None,
        udp_mode: UdpMode::Disabled,
        protocol_udp: false,
        transports: vec!["normal".to_owned()],
        aead_password: None,
        aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: None,
        reverse_http: None,
    };
    let task = tokio::spawn(async move {
        let inbound = InboundHandler::new(spec, selector, monitor);
        let hashes = crate::inbound::adapters::trojan::password_hashes(inbound.spec());
        let udp_inbound = Arc::clone(&inbound);
        yuhaiin_protocol::trojan::handle(
            Box::new(server) as BoxAsyncStream,
            "127.0.0.1:41001".parse().unwrap(),
            &hashes,
            inbound.selector().udp_buffer_size(),
            inbound.as_ref(),
            move |codec| async move { InboundUdpSession::new(codec, udp_inbound).run().await },
        )
        .await
    });
    let destination = Endpoint::ip(Network::Tcp, echo_address);
    let hash = trojan::password_hash(b"secret");
    trojan::write_request(&mut client, &hash, Command::Connect, &destination)
        .await
        .unwrap();
    client.write_all(b"trojan-inbound").await.unwrap();
    let mut response = [0u8; 14];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"trojan-inbound");
    client.shutdown().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    echo_task.abort();
}

#[tokio::test]
async fn vless_inbound_routes_a_real_tcp_flow_through_shared_outbound() {
    let (selector, monitor) = direct_runtime().await;
    let (echo_address, echo_task) = echo_server().await;
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let spec = InboundSpec {
        id: "vless-inbound".to_owned(),
        name: "vless-inbound".to_owned(),
        protocol: "vless".to_owned(),
        listen: "127.0.0.1:19082".parse().unwrap(),
        username: String::new(),
        password: "00112233-4455-6677-8899-aabbccddeeff".to_owned(),
        auth: None,
        udp_mode: UdpMode::Disabled,
        protocol_udp: false,
        transports: vec!["normal".to_owned()],
        aead_password: None,
        aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: None,
        reverse_http: None,
    };
    let task = tokio::spawn(async move {
        let inbound = InboundHandler::new(spec, selector, monitor);
        let uuid = yuhaiin_protocol::vless::parse_uuid(&inbound.spec().password)?;
        let udp_inbound = Arc::clone(&inbound);
        yuhaiin_protocol::vless::handle(
            Box::new(server) as BoxAsyncStream,
            "127.0.0.1:41003".parse().unwrap(),
            &uuid,
            inbound.selector().udp_buffer_size(),
            inbound.as_ref(),
            move |server| async move {
                let codec = crate::inbound::adapters::vless::VlessUdpCodec {
                    server,
                    flow_key: None,
                };
                InboundUdpSession::new(codec, udp_inbound).run().await
            },
        )
        .await
    });
    let destination = Endpoint::ip(Network::Tcp, echo_address);
    let uuid = vless::parse_uuid("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    vless::write_request(&mut client, &uuid, VlessCommand::Tcp, &destination)
        .await
        .unwrap();
    let mut response = [0u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [0, 0]);
    client.write_all(b"vless-inbound").await.unwrap();
    let mut echoed = [0u8; 13];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"vless-inbound");
    client.shutdown().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    echo_task.abort();
}

#[tokio::test]
async fn vless_udp_command_routes_length_prefixed_packets_through_shared_outbound() {
    let (selector, monitor) = direct_runtime().await;
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_address = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 1024];
        let (length, peer) = echo.recv_from(&mut buffer).await.unwrap();
        echo.send_to(&buffer[..length], peer).await.unwrap();
    });
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let spec = InboundSpec {
        id: "vless-udp-inbound".to_owned(),
        name: "vless-udp-inbound".to_owned(),
        protocol: "vless".to_owned(),
        listen: "127.0.0.1:19083".parse().unwrap(),
        username: String::new(),
        password: "00112233-4455-6677-8899-aabbccddeeff".to_owned(),
        auth: None,
        udp_mode: UdpMode::Enabled,
        protocol_udp: true,
        transports: vec!["normal".to_owned()],
        aead_password: None,
        aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: None,
        reverse_http: None,
    };
    let task = tokio::spawn(async move {
        let inbound = InboundHandler::new(spec, selector, monitor);
        let uuid = yuhaiin_protocol::vless::parse_uuid(&inbound.spec().password)?;
        let udp_inbound = Arc::clone(&inbound);
        yuhaiin_protocol::vless::handle(
            Box::new(server) as BoxAsyncStream,
            "127.0.0.1:41004".parse().unwrap(),
            &uuid,
            inbound.selector().udp_buffer_size(),
            inbound.as_ref(),
            move |server| async move {
                let codec = crate::inbound::adapters::vless::VlessUdpCodec {
                    server,
                    flow_key: None,
                };
                InboundUdpSession::new(codec, udp_inbound).run().await
            },
        )
        .await
    });
    let destination = Endpoint::ip(Network::Udp, echo_address);
    let uuid = vless::parse_uuid("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    vless::write_request(&mut client, &uuid, VlessCommand::Udp, &destination)
        .await
        .unwrap();
    client.write_u16(9).await.unwrap();
    client.write_all(b"vless-udp").await.unwrap();
    let length = usize::from(client.read_u16().await.unwrap());
    let mut payload = vec![0u8; length];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(payload, b"vless-udp");
    client.shutdown().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    echo_task.await.unwrap();
}

#[tokio::test]
async fn trojan_associate_routes_udp_frames_through_shared_outbound() {
    let (selector, monitor) = direct_runtime().await;
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_address = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buffer = [0u8; 1024];
        let (length, peer) = echo.recv_from(&mut buffer).await.unwrap();
        echo.send_to(&buffer[..length], peer).await.unwrap();
    });
    let (mut client, server) = tokio::io::duplex(16 * 1024);
    let spec = InboundSpec {
        id: "trojan-udp-inbound".to_owned(),
        name: "trojan-udp-inbound".to_owned(),
        protocol: "trojan".to_owned(),
        listen: "127.0.0.1:19081".parse().unwrap(),
        username: String::new(),
        password: "secret".to_owned(),
        auth: None,
        udp_mode: UdpMode::Enabled,
        protocol_udp: true,
        transports: vec!["normal".to_owned()],
        aead_password: None,
        aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: None,
        reverse_http: None,
    };
    let task = tokio::spawn(async move {
        let inbound = InboundHandler::new(spec, selector, monitor);
        let hashes = crate::inbound::adapters::trojan::password_hashes(inbound.spec());
        let udp_inbound = Arc::clone(&inbound);
        yuhaiin_protocol::trojan::handle(
            Box::new(server) as BoxAsyncStream,
            "127.0.0.1:41002".parse().unwrap(),
            &hashes,
            inbound.selector().udp_buffer_size(),
            inbound.as_ref(),
            move |codec| async move { InboundUdpSession::new(codec, udp_inbound).run().await },
        )
        .await
    });
    let destination = Endpoint::ip(Network::Udp, echo_address);
    let hash = trojan::password_hash(b"secret");
    trojan::write_request(&mut client, &hash, Command::Associate, &destination)
        .await
        .unwrap();
    trojan::write_udp_frame(&mut client, &destination, b"trojan-udp")
        .await
        .unwrap();
    let mut payload = [0u8; 64];
    let (length, _source) = trojan::read_udp_frame(&mut client, &mut payload)
        .await
        .unwrap();
    assert_eq!(&payload[..length], b"trojan-udp");
    client.shutdown().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    echo_task.await.unwrap();
}

#[test]
fn inbound_udp_mode_accepts_frontend_strings_and_legacy_booleans() {
    assert_eq!(
        UdpMode::from_value(Some(&json!("enabled"))),
        UdpMode::Enabled
    );
    assert_eq!(
        UdpMode::from_value(Some(&json!("udp_only"))),
        UdpMode::UdpOnly
    );
    assert_eq!(UdpMode::from_value(Some(&json!(true))), UdpMode::Enabled);
    assert!(UdpMode::UdpOnly.udp_enabled());
    assert!(!UdpMode::UdpOnly.tcp_enabled());
}

#[test]
fn mixed_inbound_inherits_go_socks5_udp_mode() {
    assert!(supports_socks5_udp("mixed", false));
    assert!(supports_socks5_udp("  MIXED  ", false));
    assert!(supports_socks5_udp("mix", true));
    assert!(supports_socks5_udp("socks5", true));
    assert!(!supports_socks5_udp("socks5", false));
    assert!(!supports_socks5_udp("http", true));
}

struct FixedProcessResolver;

impl ProcessResolver for FixedProcessResolver {
    fn resolve(
        &self,
        _network: Network,
        _source: SocketAddr,
        _destination: SocketAddr,
    ) -> std::io::Result<Option<ProcessInfo>> {
        Ok(Some(ProcessInfo {
            path: "/usr/bin/inbound-client".to_owned(),
            pid: 4242,
            uid: 1000,
        }))
    }
}

#[test]
fn inbound_context_enriches_process_metadata_before_shared_router_selection() {
    let spec = InboundSpec {
        id: "process-inbound".to_owned(),
        name: "process display name".to_owned(),
        protocol: "http".to_owned(),
        listen: "127.0.0.1:18080".parse().unwrap(),
        username: String::new(),
        password: String::new(),
        auth: None,
        udp_mode: UdpMode::Disabled,
        protocol_udp: false,
        transports: vec!["normal".to_owned()],
        aead_password: None,
        aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: None,
        reverse_http: None,
    };
    let mut context = FlowContext::new(Endpoint::ip(
        Network::Tcp,
        "198.51.100.10:443".parse().unwrap(),
    ));
    context.source = Some(Endpoint::ip(
        Network::Tcp,
        "127.0.0.1:41000".parse().unwrap(),
    ));
    spec.annotate_context_with_process_resolver(&mut context, Some(&FixedProcessResolver));
    assert_eq!(context.inbound.as_deref(), Some("127.0.0.1:18080"));
    assert_eq!(
        context.inbound_name.as_deref(),
        Some("process display name")
    );
    assert_eq!(context.outbound.as_deref(), Some("direct"));
    assert_eq!(
        context.local_addr,
        Some(Endpoint::ip(
            Network::Tcp,
            "127.0.0.1:18080".parse().unwrap()
        ))
    );
    assert_eq!(context.process.as_deref(), Some("/usr/bin/inbound-client"));
    assert_eq!(context.process_id, Some(4242));
    assert_eq!(context.user_id, Some(1000));
}

#[test]
fn inbound_context_marks_tls_auto_as_tls_before_protocol_sniffing() {
    let spec = InboundSpec {
        id: "tls-auto-inbound".to_owned(),
        name: "tls-auto-inbound".to_owned(),
        protocol: "http".to_owned(),
        listen: "127.0.0.1:18081".parse().unwrap(),
        username: String::new(),
        password: String::new(),
        auth: None,
        udp_mode: UdpMode::Disabled,
        protocol_udp: false,
        transports: vec!["tls_auto".to_owned()],
        aead_password: None,
        aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: None,
        reverse_http: None,
    };
    let mut context = FlowContext::new(Endpoint::ip(
        Network::Tcp,
        "198.51.100.12:443".parse().unwrap(),
    ));
    spec.annotate_context_with_process_resolver(&mut context, None);
    assert_eq!(context.protocol.as_deref(), Some("tls"));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn inbound_context_resolves_the_real_local_client_process_from_proc() {
    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        let client = TcpStream::connect(listen).await.unwrap();
        let (_server, peer) = listener.accept().await.unwrap();
        let spec = InboundSpec {
            id: "real-process-inbound".to_owned(),
            name: "real-process-inbound".to_owned(),
            protocol: "socks5".to_owned(),
            listen,
            username: String::new(),
            password: String::new(),
            auth: None,
            udp_mode: UdpMode::Disabled,
            protocol_udp: false,
            transports: vec!["normal".to_owned()],
            aead_password: None,
            aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
            outbound_id: "direct".to_owned(),
            reverse_target: None,
            reverse_http: None,
        };
        let mut context = FlowContext::new(Endpoint::ip(
            Network::Tcp,
            "198.51.100.11:443".parse().unwrap(),
        ));
        context.source = Some(Endpoint::ip(Network::Tcp, peer));
        spec.annotate_context(&mut context);
        assert_eq!(context.process_id, Some(std::process::id()));
        assert!(
            context
                .process
                .as_deref()
                .is_some_and(|path| !path.is_empty())
        );
        drop(client);
    });
}

#[test]
fn socks5_inbound_routes_a_real_tcp_flow_through_the_shared_outbound() {
    block_on(async {
        let (echo_address, echo_task) = echo_server().await;
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_address = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_task = tokio::spawn(serve_listener(
            inbound_listener,
            InboundSpec {
                id: "socks-inbound".to_owned(),
                name: "socks-inbound".to_owned(),
                protocol: "socks5".to_owned(),
                listen: inbound_address,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["normal".to_owned()],
                aead_password: None,
                aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            },
            selector,
            monitor,
            None,
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let mut client = TcpStream::connect(inbound_address).await.unwrap();
            client.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0u8; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);

            let ip = match echo_address.ip() {
                std::net::IpAddr::V4(ip) => ip.octets(),
                std::net::IpAddr::V6(_) => panic!("test echo server must be IPv4"),
            };
            let mut request = vec![5, 1, 0, 1];
            request.extend_from_slice(&ip);
            request.extend_from_slice(&echo_address.port().to_be_bytes());
            client.write_all(&request).await.unwrap();
            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0..2], [5, 0]);

            client.write_all(b"socks5-through-direct").await.unwrap();
            let mut echoed = vec![0u8; 21];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"socks5-through-direct");
        })
        .await;

        listener_task.abort();
        let _ = listener_task.await;
        echo_task.abort();
        let _ = echo_task.await;
        result.unwrap();
    });
}

#[test]
fn socks4a_inbound_routes_a_real_tcp_flow_through_the_shared_outbound() {
    block_on(async {
        let (echo_address, echo_task) = echo_server().await;
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_address = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_task = tokio::spawn(serve_listener(
            inbound_listener,
            InboundSpec {
                id: "socks4a-inbound".to_owned(),
                name: "socks4a-inbound".to_owned(),
                protocol: "socks4a".to_owned(),
                listen: inbound_address,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["normal".to_owned()],
                aead_password: None,
                aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            },
            selector,
            monitor,
            None,
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let mut client = TcpStream::connect(inbound_address).await.unwrap();
            let ip = match echo_address.ip() {
                std::net::IpAddr::V4(ip) => ip.octets(),
                std::net::IpAddr::V6(_) => panic!("test echo server must be IPv4"),
            };
            let mut request = vec![4, 1];
            request.extend_from_slice(&echo_address.port().to_be_bytes());
            request.extend_from_slice(&ip);
            request.extend_from_slice(b"rust-test");
            request.push(0);
            client.write_all(&request).await.unwrap();
            let mut reply = [0u8; 8];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0..2], [0, 90]);

            client.write_all(b"socks4a-through-direct").await.unwrap();
            let mut echoed = vec![0u8; 22];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"socks4a-through-direct");
        })
        .await;

        listener_task.abort();
        let _ = listener_task.await;
        echo_task.abort();
        let _ = echo_task.await;
        result.unwrap();
    });
}

#[test]
fn mixed_inbound_dispatches_socks4a_socks5_and_http_to_the_shared_outbound() {
    block_on(async {
        let (echo_address, echo_task) = echo_server().await;
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_address = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_task = tokio::spawn(serve_listener(
            inbound_listener,
            InboundSpec {
                id: "mixed-inbound".to_owned(),
                name: "mixed-inbound".to_owned(),
                protocol: "mixed".to_owned(),
                listen: inbound_address,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["normal".to_owned()],
                aead_password: None,
                aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            },
            selector,
            monitor,
            None,
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let mut socks = TcpStream::connect(inbound_address).await.unwrap();
            socks.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0u8; 2];
            socks.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            let ip = match echo_address.ip() {
                std::net::IpAddr::V4(ip) => ip.octets(),
                std::net::IpAddr::V6(_) => panic!("test echo server must be IPv4"),
            };
            let mut request = vec![5, 1, 0, 1];
            request.extend_from_slice(&ip);
            request.extend_from_slice(&echo_address.port().to_be_bytes());
            socks.write_all(&request).await.unwrap();
            let mut reply = [0u8; 10];
            socks.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0..2], [5, 0]);
            socks.write_all(b"mixed-socks").await.unwrap();
            let mut echoed = [0u8; 11];
            socks.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"mixed-socks");

            let mut socks4a = TcpStream::connect(inbound_address).await.unwrap();
            let ip = match echo_address.ip() {
                std::net::IpAddr::V4(ip) => ip.octets(),
                std::net::IpAddr::V6(_) => panic!("test echo server must be IPv4"),
            };
            let mut request = vec![4, 1];
            request.extend_from_slice(&echo_address.port().to_be_bytes());
            request.extend_from_slice(&ip);
            request.extend_from_slice(b"mixed-test");
            request.push(0);
            socks4a.write_all(&request).await.unwrap();
            let mut reply = [0u8; 8];
            socks4a.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0..2], [0, 90]);
            socks4a.write_all(b"mixed-socks4a").await.unwrap();
            let mut echoed = [0u8; 13];
            socks4a.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"mixed-socks4a");

            let mut http = TcpStream::connect(inbound_address).await.unwrap();
            http.write_all(
                format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo_address, echo_address
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            let response = read_headers(&mut http).await;
            assert!(response.starts_with(b"HTTP/1.1 200"));
            http.write_all(b"mixed-http").await.unwrap();
            let mut echoed = [0u8; 10];
            http.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"mixed-http");
        })
        .await;

        listener_task.abort();
        let _ = listener_task.await;
        echo_task.abort();
        let _ = echo_task.await;
        result.unwrap();
    });
}

#[test]
fn connections_close_aborts_a_live_socks5_relay() {
    block_on(async {
        let (echo_address, echo_task) = echo_server().await;
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_address = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_task = tokio::spawn(serve_listener(
            inbound_listener,
            InboundSpec {
                id: "socks-close-inbound".to_owned(),
                name: "socks-close-inbound".to_owned(),
                protocol: "socks5".to_owned(),
                listen: inbound_address,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["normal".to_owned()],
                aead_password: None,
                aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            },
            selector,
            monitor.clone(),
            None,
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let mut client = TcpStream::connect(inbound_address).await.unwrap();
            client.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0u8; 2];
            client.read_exact(&mut method).await.unwrap();
            let ip = match echo_address.ip() {
                std::net::IpAddr::V4(ip) => ip.octets(),
                std::net::IpAddr::V6(_) => panic!("test echo server must be IPv4"),
            };
            let mut request = vec![5, 1, 0, 1];
            request.extend_from_slice(&ip);
            request.extend_from_slice(&echo_address.port().to_be_bytes());
            client.write_all(&request).await.unwrap();
            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await.unwrap();
            client.write_all(b"close-me").await.unwrap();
            let mut echoed = [0u8; 8];
            client.read_exact(&mut echoed).await.unwrap();

            let connection_id = monitor.connections_value()["connections"][0]["id"]
                .as_str()
                .unwrap()
                .to_owned();
            assert_eq!(monitor.request_close(&[connection_id]), 1);
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if monitor.connections_value()["connections"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("close request should remove the live relay");
        })
        .await;

        listener_task.abort();
        let _ = listener_task.await;
        echo_task.abort();
        let _ = echo_task.await;
        result.unwrap();
    });
}

#[test]
fn aborting_an_inbound_listener_closes_its_owned_live_flow() {
    block_on(async {
        let (echo_address, echo_task) = echo_server().await;
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_address = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_task = tokio::spawn(serve_listener(
            inbound_listener,
            InboundSpec {
                id: "socks-abort-inbound".to_owned(),
                name: "socks-abort-inbound".to_owned(),
                protocol: "socks5".to_owned(),
                listen: inbound_address,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["normal".to_owned()],
                aead_password: None,
                aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            },
            selector,
            monitor.clone(),
            None,
        ));

        let mut client = TcpStream::connect(inbound_address).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        let ip = match echo_address.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            std::net::IpAddr::V6(_) => panic!("test echo server must be IPv4"),
        };
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&ip);
        request.extend_from_slice(&echo_address.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !monitor.connections_value()["connections"]
                    .as_array()
                    .is_some_and(Vec::is_empty)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("relay should be observed before listener abort");

        listener_task.abort();
        let _ = listener_task.await;
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if monitor.connections_value()["connections"]
                    .as_array()
                    .is_some_and(Vec::is_empty)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("aborting listener must close its child relay and monitor entry");
        assert_eq!(
            monitor.all_history_value()["items"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );

        drop(client);
        echo_task.abort();
        let _ = echo_task.await;
    });
}

#[test]
fn connections_close_removes_a_live_socks5_udp_flow() {
    block_on(async {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            if let Ok((length, peer)) = target.recv_from(&mut buffer).await {
                let _ = target.send_to(&buffer[..length], peer).await;
            }
        });
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_address = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_task = tokio::spawn(crate::inbound::socks5::serve_socks5_udp_loop(
            Box::new(crate::inbound::socks5::RuntimeUdpTransport(Box::new(
                server,
            ))),
            InboundHandler::new(
                InboundSpec {
                    id: "socks-udp-close-inbound".to_owned(),
                    name: "socks-udp-close-inbound".to_owned(),
                    protocol: "socks5".to_owned(),
                    listen: server_address,
                    username: String::new(),
                    password: String::new(),
                    auth: None,
                    udp_mode: UdpMode::Enabled,
                    protocol_udp: true,
                    transports: vec!["normal".to_owned()],
                    aead_password: None,
                    aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                    outbound_id: "direct".to_owned(),
                    reverse_target: None,
                    reverse_http: None,
                },
                selector,
                monitor.clone(),
            ),
            None,
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let target = Endpoint::ip(Network::Udp, target_address);
            let packet =
                yuhaiin_protocol::socks5_server::encode_udp_packet(&target, b"udp-close").unwrap();
            client.send_to(&packet, server_address).await.unwrap();
            let mut reply = [0u8; 2048];
            let (length, _) = client.recv_from(&mut reply).await.unwrap();
            let (_, payload) = yuhaiin_protocol::socks5_server::parse_udp_packet(&reply[..length])
                .unwrap()
                .unwrap();
            assert_eq!(payload, b"udp-close");

            let connection_id = tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if let Some(id) = monitor.connections_value()["connections"]
                        .as_array()
                        .and_then(|connections| connections.first())
                        .and_then(|connection| connection["id"].as_str())
                    {
                        break id.to_owned();
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("UDP flow should be visible to the monitor");
            assert_eq!(monitor.request_close(&[connection_id]), 1);
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if monitor.connections_value()["connections"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("close request should remove the UDP flow");
        })
        .await;

        listener_task.abort();
        let _ = listener_task.await;
        target_task.abort();
        let _ = target_task.await;
        result.unwrap();
    });
}

#[test]
fn socks5_udp_associate_routes_through_the_shared_outbound() {
    block_on(async {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            if let Ok((length, peer)) = target.recv_from(&mut buffer).await {
                let _ = target.send_to(&buffer[..length], peer).await;
            }
        });

        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_address = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_monitor = monitor.clone();
        let listener_task = tokio::spawn(async move {
            let (stream, peer) = inbound_listener.accept().await.unwrap();
            let _ = crate::inbound::socks5::handle(
                Box::new(stream),
                peer,
                InboundHandler::new(
                    InboundSpec {
                        id: "socks-associate-inbound".to_owned(),
                        name: "socks-associate-inbound".to_owned(),
                        protocol: "socks5".to_owned(),
                        listen: inbound_address,
                        username: String::new(),
                        password: String::new(),
                        auth: None,
                        udp_mode: UdpMode::Enabled,
                        protocol_udp: true,
                        transports: vec!["normal".to_owned()],
                        aead_password: None,
                        aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                        outbound_id: "direct".to_owned(),
                        reverse_target: None,
                        reverse_http: None,
                    },
                    selector,
                    listener_monitor,
                ),
            )
            .await;
        });

        let control_socket = TcpSocket::new_v4().unwrap();
        control_socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
        let mut control = control_socket.connect(inbound_address).await.unwrap();
        control.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        control.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        control
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut bind_reply = [0u8; 10];
        control.read_exact(&mut bind_reply).await.unwrap();
        assert_eq!(&bind_reply[..4], &[5, 0, 0, 1]);
        let relay_address = SocketAddr::new(
            std::net::Ipv4Addr::new(bind_reply[4], bind_reply[5], bind_reply[6], bind_reply[7])
                .into(),
            u16::from_be_bytes([bind_reply[8], bind_reply[9]]),
        );
        assert_eq!(
            relay_address.ip(),
            "127.0.0.2".parse::<std::net::IpAddr>().unwrap()
        );

        let client = UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let target = Endpoint::ip(Network::Udp, target_address);
        let packet =
            yuhaiin_protocol::socks5_server::encode_udp_packet(&target, b"udp-associate").unwrap();
        client.send_to(&packet, relay_address).await.unwrap();
        let mut reply = [0u8; 2048];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut reply))
                .await
                .unwrap()
                .unwrap();
        let (_, payload) = yuhaiin_protocol::socks5_server::parse_udp_packet(&reply[..length])
            .unwrap()
            .unwrap();
        assert_eq!(payload, b"udp-associate");

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if monitor.connections_value()["connections"]
                    .as_array()
                    .is_some_and(|connections| !connections.is_empty())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("SOCKS5 UDP ASSOCIATE flow should reach the monitor");
        let connection = monitor.connections_value()["connections"][0].clone();
        assert_eq!(connection["inboundName"], "socks-associate-inbound");
        assert_eq!(connection["outbound"], target_address.to_string());

        listener_task.abort();
        let _ = listener_task.await;
        target_task.abort();
        let _ = target_task.await;
    });
}

#[test]
fn http_connect_inbound_routes_a_real_tcp_flow_through_the_shared_outbound() {
    block_on(async {
        let (echo_address, echo_task) = echo_server().await;
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_address = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_task = tokio::spawn(serve_listener(
            inbound_listener,
            InboundSpec {
                id: "http-inbound".to_owned(),
                name: "http-inbound".to_owned(),
                protocol: "http".to_owned(),
                listen: inbound_address,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["normal".to_owned()],
                aead_password: None,
                aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            },
            selector,
            monitor,
            None,
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let mut client = TcpStream::connect(inbound_address).await.unwrap();
            client
                .write_all(
                    format!(
                        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                        echo_address, echo_address
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let headers = read_headers(&mut client).await;
            assert!(headers.starts_with(b"HTTP/1.1 200 Connection Established"));

            client.write_all(b"http-through-direct").await.unwrap();
            let mut echoed = vec![0u8; 19];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"http-through-direct");
        })
        .await;

        listener_task.abort();
        let _ = listener_task.await;
        echo_task.abort();
        let _ = echo_task.await;
        result.unwrap();
    });
}

#[cfg(feature = "websocket")]
#[test]
fn websocket_transport_wraps_http_inbound_and_routes_a_real_tcp_flow() {
    block_on(async {
        let (echo_address, echo_task) = echo_server().await;
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_address = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_task = tokio::spawn(serve_websocket_listener(
            inbound_listener,
            InboundSpec {
                id: "websocket-http-inbound".to_owned(),
                name: "websocket-http-inbound".to_owned(),
                protocol: "http".to_owned(),
                listen: inbound_address,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["websocket".to_owned()],
                aead_password: None,
                aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            },
            selector,
            monitor,
            None,
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let stream = TcpStream::connect(inbound_address).await.unwrap();
            let (mut websocket, _) = tokio_tungstenite::client_async("ws://localhost/ws", stream)
                .await
                .unwrap();
            use tokio_tungstenite::tungstenite::Message;

            websocket
                .send(Message::binary(
                    format!(
                        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                        echo_address, echo_address
                    )
                    .into_bytes(),
                ))
                .await
                .unwrap();
            let response = websocket.next().await.unwrap().unwrap();
            let response = match response {
                Message::Binary(data) => data.to_vec(),
                Message::Text(data) => data.as_bytes().to_vec(),
                other => panic!("unexpected WebSocket response: {other:?}"),
            };
            assert!(response.starts_with(b"HTTP/1.1 200"));

            websocket
                .send(Message::binary(b"websocket-http".to_vec()))
                .await
                .unwrap();
            let echoed = websocket.next().await.unwrap().unwrap();
            let echoed = match echoed {
                Message::Binary(data) => data.to_vec(),
                Message::Text(data) => data.as_bytes().to_vec(),
                other => panic!("unexpected WebSocket echo: {other:?}"),
            };
            assert_eq!(echoed, b"websocket-http");
            websocket.close(None).await.unwrap();
        })
        .await;

        listener_task.abort();
        let _ = listener_task.await;
        echo_task.abort();
        let _ = echo_task.await;
        result.unwrap();
    });
}

#[test]
fn yuubinsya_inbound_routes_a_real_tcp_flow_through_the_shared_outbound() {
    block_on(async {
        let (echo_address, echo_task) = echo_server().await;
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_address = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_task = tokio::spawn(serve_listener(
            inbound_listener,
            InboundSpec {
                id: "yuubinsya-inbound".to_owned(),
                name: "yuubinsya-inbound".to_owned(),
                protocol: "yuubinsya".to_owned(),
                listen: inbound_address,
                username: String::new(),
                password: "test-password".to_owned(),
                auth: None,
                udp_mode: UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["normal".to_owned()],
                aead_password: None,
                aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            },
            selector,
            monitor,
            None,
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let transport = TcpStream::connect(inbound_address).await.unwrap();
            let password = yuhaiin_protocol::yuubinsya::derive_salt(b"test-password");
            let destination = Endpoint::ip(Network::Tcp, echo_address);
            let mut client = AsyncYuubinsyaTcpSession::connect(transport, password, destination)
                .await
                .unwrap();
            client.write_all(b"yuubinsya-through-direct").await.unwrap();
            let mut echoed = vec![0u8; 24];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"yuubinsya-through-direct");
        })
        .await;

        listener_task.abort();
        let _ = listener_task.await;
        echo_task.abort();
        let _ = echo_task.await;
        result.unwrap();
    });
}

#[cfg(feature = "doh-tls")]
#[test]
fn tls_transport_wraps_http_inbound_and_routes_a_real_tcp_flow() {
    block_on(async {
        use std::io::Cursor;

        use base64::Engine;
        use rustls::pki_types::ServerName;
        use tokio_rustls::TlsConnector;

        let (echo_address, echo_task) = echo_server().await;
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_address = inbound_listener.local_addr().unwrap();
        let config = json!({
            "transport": [{
                "type": "tls",
                "tls": {
                    "tls": {
                        "certificates": [{
                            "certBase64": base64::engine::general_purpose::STANDARD.encode(
                                [LEAF_CERTIFICATE_PEM, CA_CERTIFICATE_PEM].concat()
                            ),
                            "keyBase64": base64::engine::general_purpose::STANDARD.encode(PRIVATE_KEY_PEM)
                        }],
                        "nextProtos": []
                    }
                }
            }]
        });
        let acceptor =
            build_inbound_tls_acceptor(&serde_json::to_vec(&config).unwrap(), &["tls".to_owned()])
                .unwrap()
                .unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_task = tokio::spawn(serve_listener(
            inbound_listener,
            InboundSpec {
                id: "tls-http-inbound".to_owned(),
                name: "tls-http-inbound".to_owned(),
                protocol: "http".to_owned(),
                listen: inbound_address,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["tls".to_owned()],
                aead_password: None,
                aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            },
            selector,
            monitor,
            Some(acceptor),
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let mut roots = rustls::RootCertStore::empty();
            let certificate = rustls_pemfile::certs(&mut Cursor::new(CA_CERTIFICATE_PEM))
                .next()
                .unwrap()
                .unwrap();
            roots.add(certificate).unwrap();
            let client = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(client));
            let transport = TcpStream::connect(inbound_address).await.unwrap();
            let mut client = connector
                .connect(
                    ServerName::try_from("localhost".to_owned()).unwrap(),
                    transport,
                )
                .await
                .unwrap();
            client
                .write_all(
                    format!(
                        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                        echo_address, echo_address
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let headers = {
                let mut headers = Vec::new();
                let mut byte = [0u8; 1];
                while !headers.ends_with(b"\r\n\r\n") {
                    client.read_exact(&mut byte).await.unwrap();
                    headers.push(byte[0]);
                }
                headers
            };
            assert!(headers.starts_with(b"HTTP/1.1 200 Connection Established"));
            client.write_all(b"tls-through-direct").await.unwrap();
            let mut echoed = vec![0u8; 18];
            client.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"tls-through-direct");
        })
        .await;

        listener_task.abort();
        let _ = listener_task.await;
        echo_task.abort();
        let _ = echo_task.await;
        result.unwrap();
    });
}

#[cfg(all(feature = "websocket", feature = "http2"))]
#[test]
fn websocket_http2_transport_bridges_http_inbound_and_routes_a_real_tcp_flow() {
    block_on(async {
        use bytes::Bytes;
        use http::Request;

        let (echo_address, echo_task) = echo_server().await;
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_address = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_task = tokio::spawn(serve_websocket_h2_listener(
            inbound_listener,
            InboundSpec {
                id: "websocket-http2-inbound".to_owned(),
                name: "websocket-http2-inbound".to_owned(),
                protocol: "http".to_owned(),
                listen: inbound_address,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["websocket".to_owned(), "http2".to_owned()],
                aead_password: None,
                aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            },
            selector,
            monitor,
            None,
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let transport = TcpStream::connect(inbound_address).await.unwrap();
            let (websocket, _) =
                tokio_tungstenite::client_async("ws://localhost/proxy/ws", transport)
                    .await
                    .unwrap();
            let (mut client, connection) =
                h2::client::handshake(yuhaiin_protocol::websocket::WebSocketIo::new(websocket))
                    .await
                    .unwrap();
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
            let request_headers = format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                echo_address, echo_address
            );
            request_body
                .send_data(Bytes::from(request_headers), false)
                .unwrap();
            request_body
                .send_data(Bytes::from_static(b"websocket-http2"), true)
                .unwrap();
            let mut body = response.into_body();
            let mut received = Vec::new();
            while let Some(data) = body.data().await {
                let data = data.unwrap();
                body.flow_control().release_capacity(data.len()).unwrap();
                received.extend_from_slice(&data);
                if received.ends_with(b"websocket-http2") {
                    break;
                }
            }
            assert!(received.starts_with(b"HTTP/1.1 200 Connection Established\r\n\r\n"));
            assert!(received.ends_with(b"websocket-http2"));
            connection_task.abort();
            let _ = connection_task.await;
        })
        .await;

        listener_task.abort();
        let _ = listener_task.await;
        echo_task.abort();
        let _ = echo_task.await;
        result.unwrap();
    });
}

#[cfg(feature = "http2")]
#[test]
fn aead_http2_transport_bridges_http_inbound_and_routes_a_real_tcp_flow() {
    block_on(async {
        use bytes::Bytes;
        use http::Request;

        let (echo_address, echo_task) = echo_server().await;
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_address = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_task = tokio::spawn(serve_h2_listener(
            inbound_listener,
            InboundSpec {
                id: "aead-http2-inbound".to_owned(),
                name: "aead-http2-inbound".to_owned(),
                protocol: "http".to_owned(),
                listen: inbound_address,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["aead".to_owned(), "http2".to_owned()],
                aead_password: Some("secret".to_owned()),
                aead_method: yuhaiin_protocol::aead::CryptoMethod::XChacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            },
            selector,
            monitor,
            None,
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let transport = TcpStream::connect(inbound_address).await.unwrap();
            let transport = yuhaiin_protocol::aead::client(
                Box::new(transport),
                b"secret",
                yuhaiin_protocol::aead::CryptoMethod::XChacha20Poly1305,
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
            let request_headers = format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                echo_address, echo_address
            );
            request_body
                .send_data(Bytes::from(request_headers), false)
                .unwrap();
            request_body
                .send_data(Bytes::from_static(b"aead-http2"), true)
                .unwrap();
            let mut body = response.into_body();
            let mut received = Vec::new();
            while let Some(data) = body.data().await {
                let data = data.unwrap();
                body.flow_control().release_capacity(data.len()).unwrap();
                received.extend_from_slice(&data);
                if received.ends_with(b"aead-http2") {
                    break;
                }
            }
            assert!(received.starts_with(b"HTTP/1.1 200 Connection Established\r\n\r\n"));
            assert!(received.ends_with(b"aead-http2"));
            connection_task.abort();
            let _ = connection_task.await;
        })
        .await;

        listener_task.abort();
        let _ = listener_task.await;
        echo_task.abort();
        let _ = echo_task.await;
        result.unwrap();
    });
}

#[cfg(feature = "websocket")]
#[test]
fn aead_websocket_transport_wraps_http_inbound_and_routes_a_real_tcp_flow() {
    block_on(async {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let (echo_address, echo_task) = echo_server().await;
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_address = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_task = tokio::spawn(serve_websocket_listener(
            inbound_listener,
            InboundSpec {
                id: "aead-websocket-inbound".to_owned(),
                name: "aead-websocket-inbound".to_owned(),
                protocol: "http".to_owned(),
                listen: inbound_address,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["aead".to_owned(), "websocket".to_owned()],
                aead_password: Some("secret".to_owned()),
                aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            },
            selector,
            monitor,
            None,
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let transport = TcpStream::connect(inbound_address).await.unwrap();
            let transport = yuhaiin_protocol::aead::client(
                Box::new(transport),
                b"secret",
                yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
            )
            .await
            .unwrap();
            let (mut websocket, _) =
                tokio_tungstenite::client_async("ws://localhost/ws", transport)
                    .await
                    .unwrap();
            websocket
                .send(Message::binary(
                    format!(
                        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                        echo_address, echo_address
                    )
                    .into_bytes(),
                ))
                .await
                .unwrap();
            let response = websocket.next().await.unwrap().unwrap();
            let response = match response {
                Message::Binary(data) => data.to_vec(),
                Message::Text(data) => data.as_bytes().to_vec(),
                other => panic!("unexpected WebSocket response: {other:?}"),
            };
            assert!(response.starts_with(b"HTTP/1.1 200"));
            websocket
                .send(Message::binary(b"aead-websocket".to_vec()))
                .await
                .unwrap();
            let echoed = websocket.next().await.unwrap().unwrap();
            let echoed = match echoed {
                Message::Binary(data) => data.to_vec(),
                Message::Text(data) => data.as_bytes().to_vec(),
                other => panic!("unexpected WebSocket echo: {other:?}"),
            };
            assert_eq!(echoed, b"aead-websocket");
            websocket.close(None).await.unwrap();
        })
        .await;

        listener_task.abort();
        let _ = listener_task.await;
        echo_task.abort();
        let _ = echo_task.await;
        result.unwrap();
    });
}

#[cfg(feature = "http2")]
#[test]
fn http2_transport_bridges_each_connect_stream_to_the_protocol_server() {
    block_on(async {
        use bytes::Bytes;
        use http::Request;

        let (echo_address, echo_task) = echo_server().await;
        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound_address = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_runtime().await;
        let listener_task = tokio::spawn(serve_h2_listener(
            inbound_listener,
            InboundSpec {
                id: "http2-http-inbound".to_owned(),
                name: "http2-http-inbound".to_owned(),
                protocol: "http".to_owned(),
                listen: inbound_address,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["http2".to_owned()],
                aead_password: None,
                aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            },
            selector,
            monitor,
            None,
        ));

        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let transport = TcpStream::connect(inbound_address).await.unwrap();
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
            let request_headers = format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                echo_address, echo_address
            );
            request_body
                .send_data(Bytes::from(request_headers), false)
                .unwrap();
            request_body
                .send_data(Bytes::from_static(b"http2-through-direct"), true)
                .unwrap();
            let mut body = response.into_body();
            let mut received = Vec::new();
            while let Some(data) = body.data().await {
                let data = data.unwrap();
                body.flow_control().release_capacity(data.len()).unwrap();
                received.extend_from_slice(&data);
                if received.len() >= 58 {
                    break;
                }
            }
            assert!(received.starts_with(b"HTTP/1.1 200 Connection Established\r\n\r\n"));
            assert!(received.ends_with(b"http2-through-direct"));
            connection_task.abort();
            let _ = connection_task.await;
        })
        .await;

        listener_task.abort();
        let _ = listener_task.await;
        echo_task.abort();
        let _ = echo_task.await;
        result.unwrap();
    });
}
