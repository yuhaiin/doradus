mod support;

use base64::Engine;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http::Request;
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use yuhaiin_chain::AsyncYuubinsyaTcpSession;
use yuhaiin_core::{DomainName, Endpoint, Network, websocket::WebSocketIo};
use yuhaiin_protocol::{trojan, vless, vmess};

use support::{
    ConnectFixture, H2FinalProtocol, H2ProtocolFixture, H2YuubinsyaFixture, ServiceProcess,
    Socks5Fixture, YUUBINSYA_PASSWORD, add_mixed_udp_inbound, add_reverse_inbounds,
    add_socks5_inbound, add_yuubinsya_inbound, api_json, configure_aead_h2_http_inbound,
    configure_direct_http_inbound, configure_h2_http_chain, configure_h2_http_inbound,
    configure_h2_socks5_chain, configure_http_chain, configure_http_chain_with_transport,
    configure_network_split_http_chain, configure_socks5_chain, configure_tls_aead_h2_http_inbound,
    configure_tls_auto_http_inbound, configure_tls_h2_http_inbound,
    configure_tls_h2_yuubinsya_chain, configure_tls_http_inbound, connect_loopback,
    connect_tls_h2_loopback, connect_tls_loopback, connect_tls_loopback_without_sni,
    integration_dir, seed_empty_database, tls_server_acceptor, tls_termination_certificate,
    wait_for_connection,
};

#[cfg(target_os = "linux")]
use support::configure_http_process_inbound_chain;

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

async fn socks5_auth_probe(
    address: SocketAddr,
    username: &str,
    password: &str,
) -> std::io::Result<[u8; 2]> {
    let mut stream = connect_loopback(address).await;
    stream.write_all(&[5, 1, 2]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 2] {
        return Ok(method);
    }
    let username = username.as_bytes();
    let password = password.as_bytes();
    let mut request = vec![1, username.len() as u8];
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream.write_all(&request).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    let _ = stream.shutdown().await;
    Ok(reply)
}

async fn connect_socks5_with_auth(
    address: SocketAddr,
    username: &str,
    password: &str,
    host: &str,
    port: u16,
) -> TcpStream {
    let mut stream = connect_loopback(address).await;
    stream.write_all(&[5, 1, 2]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    let username = username.as_bytes();
    let password = password.as_bytes();
    let mut auth = vec![1, username.len() as u8];
    auth.extend_from_slice(username);
    auth.push(password.len() as u8);
    auth.extend_from_slice(password);
    stream.write_all(&auth).await.unwrap();
    let mut auth_reply = [0u8; 2];
    stream.read_exact(&mut auth_reply).await.unwrap();
    assert_eq!(auth_reply, [1, 0]);
    let host = host.as_bytes();
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.unwrap();
    read_socks5_reply(&mut stream).await;
    stream
}

#[derive(Clone, Copy)]
enum ProtocolOutboundKind {
    Vless,
    VlessTlsWebsocket,
    Vmess,
    VmessTlsWebsocket,
    Trojan,
    TrojanWebsocket,
    TrojanTlsWebsocket,
}

impl ProtocolOutboundKind {
    fn name(self) -> &'static str {
        match self {
            Self::Vless => "vless",
            Self::VlessTlsWebsocket => "vless-tls-websocket",
            Self::Vmess => "vmess",
            Self::VmessTlsWebsocket => "vmess-tls-websocket",
            Self::Trojan => "trojan",
            Self::TrojanWebsocket => "trojan-websocket",
            Self::TrojanTlsWebsocket => "trojan-tls-websocket",
        }
    }

    fn node_id(self) -> String {
        format!("{}-runtime-out", self.name())
    }

    fn inbound_id(self) -> String {
        format!("{}-runtime-in", self.name())
    }

    fn inbound_name(self) -> String {
        format!("{} runtime protocol inbound", self.name())
    }

    fn rule_name(self) -> String {
        format!("proxy-example-test-over-{}", self.name())
    }
}

async fn protocol_outbound_server(
    kind: ProtocolOutboundKind,
    listener: TcpListener,
    expected_payload: &'static [u8],
) {
    for connection in 0..2 {
        let (mut stream, _) = listener.accept().await.unwrap();
        let destination = Endpoint::domain(
            Network::Tcp,
            DomainName::new("example.test").unwrap(),
            if connection == 0 { 443 } else { 80 },
        );
        match kind {
            ProtocolOutboundKind::Vless => {
                serve_vless_connection(&mut stream, connection, destination, expected_payload)
                    .await;
            }
            ProtocolOutboundKind::VlessTlsWebsocket => {
                let stream = tls_server_acceptor().accept(stream).await.unwrap();
                let websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut stream = WebSocketIo::new(websocket);
                serve_vless_connection(&mut stream, connection, destination, expected_payload)
                    .await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            ProtocolOutboundKind::Trojan => {
                serve_trojan_connection(&mut stream, connection, destination, expected_payload)
                    .await;
            }
            ProtocolOutboundKind::TrojanWebsocket => {
                let websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut stream = WebSocketIo::new(websocket);
                serve_trojan_connection(&mut stream, connection, destination, expected_payload)
                    .await;
                // Keep the WebSocket peer alive long enough for the runtime
                // monitor to publish the connection before the fixture drops
                // the close event.
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            ProtocolOutboundKind::TrojanTlsWebsocket => {
                let stream = tls_server_acceptor().accept(stream).await.unwrap();
                let websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut stream = WebSocketIo::new(websocket);
                serve_trojan_connection(&mut stream, connection, destination, expected_payload)
                    .await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            ProtocolOutboundKind::Vmess => {
                serve_vmess_connection(&mut stream, connection, destination, expected_payload)
                    .await;
            }
            ProtocolOutboundKind::VmessTlsWebsocket => {
                let stream = tls_server_acceptor().accept(stream).await.unwrap();
                let websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut stream = WebSocketIo::new(websocket);
                serve_vmess_connection(&mut stream, connection, destination, expected_payload)
                    .await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

async fn protocol_h2_outbound_server(
    kind: ProtocolOutboundKind,
    listener: TcpListener,
    expected_payload: &'static [u8],
    udp: bool,
) {
    let (socket, _) = listener.accept().await.unwrap();
    let mut connection = h2::server::handshake(socket).await.unwrap();
    let (request, mut respond) = connection.accept().await.unwrap().unwrap();
    assert_eq!(request.method(), http::Method::CONNECT);
    assert_eq!(request.uri().host(), Some("localhost"));
    let mut body = request.into_body();
    let mut send = respond
        .send_response(http::Response::new(()), false)
        .unwrap();
    let (application, relay) = tokio::io::duplex(64 * 1024);
    let (mut relay_read, mut relay_write) = tokio::io::split(relay);
    let body_to_relay = tokio::spawn(async move {
        while let Some(data) = body.data().await {
            let Ok(data) = data else { break };
            if body.flow_control().release_capacity(data.len()).is_err() {
                break;
            }
            if relay_write.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = relay_write.shutdown().await;
    });
    let relay_to_body = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        while let Ok(length) = relay_read.read(&mut buffer).await {
            if length == 0 {
                break;
            }
            if send
                .send_data(Bytes::copy_from_slice(&buffer[..length]), false)
                .is_err()
            {
                break;
            }
        }
        let _ = send.send_data(Bytes::new(), true);
    });
    let destination = if udp {
        Endpoint::ip(Network::Udp, "8.8.8.8:5353".parse().unwrap())
    } else {
        Endpoint::domain(Network::Tcp, DomainName::new("example.test").unwrap(), 443)
    };
    let protocol_task = tokio::spawn(async move {
        match kind {
            ProtocolOutboundKind::Vless => {
                let mut application = application;
                if udp {
                    serve_vless_udp_connection(&mut application, destination, expected_payload)
                        .await;
                } else {
                    serve_vless_connection(&mut application, 0, destination, expected_payload)
                        .await;
                }
            }
            ProtocolOutboundKind::Vmess => {
                let mut application = application;
                if udp {
                    serve_vmess_udp_connection(&mut application, destination, expected_payload)
                        .await;
                } else {
                    serve_vmess_connection(&mut application, 0, destination, expected_payload)
                        .await;
                }
            }
            ProtocolOutboundKind::Trojan => {
                let mut application = application;
                if udp {
                    serve_trojan_udp_connection(&mut application, destination, expected_payload)
                        .await;
                } else {
                    serve_trojan_connection(&mut application, 0, destination, expected_payload)
                        .await;
                }
            }
            ProtocolOutboundKind::VlessTlsWebsocket
            | ProtocolOutboundKind::VmessTlsWebsocket
            | ProtocolOutboundKind::TrojanWebsocket
            | ProtocolOutboundKind::TrojanTlsWebsocket => {
                panic!("TLS/WebSocket protocol variants are not part of this H2 fixture")
            }
        }
    });

    // Keep polling the H2 connection while the protocol task exchanges bytes.
    let driver = tokio::spawn(async move {
        while let Some(result) = connection.accept().await {
            let Ok((request, mut respond)) = result else {
                break;
            };
            let _ = request.into_body();
            let _ = respond.send_response(http::Response::new(()), true);
        }
    });
    protocol_task.await.unwrap();
    body_to_relay.await.unwrap();
    relay_to_body.await.unwrap();
    driver.abort();
    let _ = driver.await;
}

async fn serve_vless_connection<S>(
    stream: &mut S,
    connection: usize,
    destination: Endpoint,
    expected_payload: &'static [u8],
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let uuid = vless::parse_uuid("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let request = vless::read_request(stream, &uuid).await.unwrap();
    assert_eq!(request.command, vless::Command::Tcp);
    assert_eq!(request.destination, destination);
    vless::write_response(stream, &[]).await.unwrap();
    if connection == 0 {
        let mut payload = vec![0u8; expected_payload.len()];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, expected_payload);
        stream.write_all(expected_payload).await.unwrap();
    } else {
        let request = read_http_headers(stream).await;
        assert!(request.starts_with(b"GET /health HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    }
}

async fn serve_vmess_connection<S>(
    stream: &mut S,
    connection: usize,
    destination: Endpoint,
    expected_payload: &'static [u8],
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    const UUID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let request = vmess::read_request(stream, &UUID).await.unwrap();
    assert_eq!(request.destination, destination);
    let response_key = sha256_key(&request.body_key);
    let response_iv = sha256_key(&request.body_iv);
    stream
        .write_all(
            &vmess::encode_response_header(request.response_v, &response_key, &response_iv)
                .unwrap(),
        )
        .await
        .unwrap();
    let payload = vmess::read_body_frame(
        stream,
        &request.body_key,
        &request.body_iv,
        request.security,
        0,
    )
    .await
    .unwrap()
    .unwrap();
    if connection == 0 {
        assert_eq!(payload, expected_payload);
        vmess::write_body_frame(
            stream,
            &response_key,
            &response_iv,
            request.security,
            0,
            expected_payload,
        )
        .await
        .unwrap();
    } else {
        assert!(payload.starts_with(b"GET /health HTTP/1.1\r\n"));
        vmess::write_body_frame(
            stream,
            &response_key,
            &response_iv,
            request.security,
            0,
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    }
}

async fn serve_trojan_connection<S>(
    stream: &mut S,
    connection: usize,
    destination: Endpoint,
    expected_payload: &'static [u8],
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hash = trojan::password_hash(b"runtime-protocol-password");
    let request = trojan::read_request(stream, &hash).await.unwrap();
    assert_eq!(request.command, trojan::Command::Connect);
    assert_eq!(request.destination, destination);
    if connection == 0 {
        let mut payload = vec![0u8; expected_payload.len()];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, expected_payload);
        stream.write_all(expected_payload).await.unwrap();
    } else {
        let request = read_http_headers(stream).await;
        assert!(request.starts_with(b"GET /health HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    }
}

async fn serve_trojan_udp_connection<S>(
    stream: &mut S,
    destination: Endpoint,
    expected_payload: &'static [u8],
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hash = trojan::password_hash(b"runtime-protocol-password");
    let request = trojan::read_request(stream, &hash).await.unwrap();
    assert_eq!(request.command, trojan::Command::Associate);
    assert_eq!(request.destination, destination);

    let mut buffer = vec![0u8; 2048];
    let (length, target) = trojan::read_udp_frame(stream, &mut buffer).await.unwrap();
    assert_eq!(target, destination);
    assert_eq!(&buffer[..length], expected_payload);
    trojan::write_udp_frame(stream, &target, expected_payload)
        .await
        .unwrap();
}

async fn protocol_udp_outbound_server(
    kind: ProtocolOutboundKind,
    listener: TcpListener,
    expected_payload: &'static [u8],
) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let destination = Endpoint::ip(Network::Udp, "8.8.8.8:5353".parse().unwrap());
    match kind {
        ProtocolOutboundKind::Vless => {
            serve_vless_udp_connection(&mut stream, destination, expected_payload).await;
        }
        ProtocolOutboundKind::VlessTlsWebsocket => {
            let stream = tls_server_acceptor().accept(stream).await.unwrap();
            let websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut stream = WebSocketIo::new(websocket);
            serve_vless_udp_connection(&mut stream, destination, expected_payload).await;
        }
        ProtocolOutboundKind::Trojan => {
            serve_trojan_udp_connection(&mut stream, destination, expected_payload).await;
        }
        ProtocolOutboundKind::Vmess => {
            serve_vmess_udp_connection(&mut stream, destination, expected_payload).await;
        }
        ProtocolOutboundKind::VmessTlsWebsocket => {
            let stream = tls_server_acceptor().accept(stream).await.unwrap();
            let websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let mut stream = WebSocketIo::new(websocket);
            serve_vmess_udp_connection(&mut stream, destination, expected_payload).await;
        }
        ProtocolOutboundKind::TrojanWebsocket | ProtocolOutboundKind::TrojanTlsWebsocket => {
            panic!("Trojan WebSocket does not expose a datagram transport");
        }
    }
}

async fn serve_vless_udp_connection<S>(
    stream: &mut S,
    destination: Endpoint,
    expected_payload: &'static [u8],
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let uuid = vless::parse_uuid("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let request = vless::read_request(stream, &uuid).await.unwrap();
    assert_eq!(request.command, vless::Command::Udp);
    assert_eq!(request.destination, destination);

    let length = stream.read_u16().await.unwrap();
    assert_eq!(usize::from(length), expected_payload.len());
    let mut payload = vec![0u8; usize::from(length)];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(payload, expected_payload);
    stream.write_u16(length).await.unwrap();
    stream.write_all(expected_payload).await.unwrap();
}

async fn serve_vmess_udp_connection<S>(
    stream: &mut S,
    destination: Endpoint,
    expected_payload: &'static [u8],
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    const UUID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let request = vmess::read_request(stream, &UUID).await.unwrap();
    assert_eq!(request.command, 2, "VMess command must be UDP");
    assert_eq!(request.destination, destination);
    let response_key = sha256_key(&request.body_key);
    let response_iv = sha256_key(&request.body_iv);
    stream
        .write_all(
            &vmess::encode_response_header(request.response_v, &response_key, &response_iv)
                .unwrap(),
        )
        .await
        .unwrap();
    let payload = vmess::read_body_frame(
        stream,
        &request.body_key,
        &request.body_iv,
        request.security,
        0,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(payload, expected_payload);
    vmess::write_body_frame(
        stream,
        &response_key,
        &response_iv,
        request.security,
        0,
        expected_payload,
    )
    .await
    .unwrap();
}

async fn read_http_headers<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        request.push(byte[0]);
        assert!(
            request.len() <= 16 * 1024,
            "HTTP latency request exceeded header limit"
        );
    }
    request
}

fn sha256_key(input: &[u8; 16]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    Sha256::digest(input)[..16].try_into().unwrap()
}

async fn configure_protocol_outbound_chain(
    service: &ServiceProcess,
    kind: ProtocolOutboundKind,
    inbound: SocketAddr,
    server: SocketAddr,
    udp: bool,
) {
    let node_id = kind.node_id();
    let inbound_id = kind.inbound_id();
    let rule_name = kind.rule_name();
    let protocol_layer = match kind {
        ProtocolOutboundKind::Vless | ProtocolOutboundKind::VlessTlsWebsocket => json!({
            "type":"vless",
            "vless":{"uuid":"00112233-4455-6677-8899-aabbccddeeff"}
        }),
        ProtocolOutboundKind::Vmess | ProtocolOutboundKind::VmessTlsWebsocket => json!({
            "type":"vmess",
            "vmess":{
                "id":"00112233-4455-6677-8899-aabbccddeeff",
                "aid":"0",
                "security":"aes-128-gcm"
            }
        }),
        ProtocolOutboundKind::Trojan => json!({
            "type":"trojan",
            "trojan":{"password":"runtime-protocol-password"}
        }),
        ProtocolOutboundKind::TrojanWebsocket => json!({
            "type":"trojan",
            "trojan":{"password":"runtime-protocol-password"}
        }),
        ProtocolOutboundKind::TrojanTlsWebsocket => json!({
            "type":"trojan",
            "trojan":{"password":"runtime-protocol-password"}
        }),
    };
    let mut chain = vec![json!({
        "type":"fixed",
        "fixed":{"host":"127.0.0.1","port":server.port()}
    })];
    if matches!(
        kind,
        ProtocolOutboundKind::VlessTlsWebsocket
            | ProtocolOutboundKind::VmessTlsWebsocket
            | ProtocolOutboundKind::TrojanTlsWebsocket
    ) {
        chain.push(json!({
            "type":"tls",
            "tls":{
                "enable":true,
                "insecure_skip_verify":true,
                "servernames":["localhost"],
                "next_protos":["http/1.1"],
                "ca_cert":[]
            }
        }));
    }
    if matches!(
        kind,
        ProtocolOutboundKind::VlessTlsWebsocket
            | ProtocolOutboundKind::VmessTlsWebsocket
            | ProtocolOutboundKind::TrojanWebsocket
            | ProtocolOutboundKind::TrojanTlsWebsocket
    ) {
        chain.push(json!({
            "type":"websocket",
            "websocket":{"host":"localhost","path":"/trojan"}
        }));
    }
    chain.push(protocol_layer);
    let node = json!({
        "id":node_id,
        "name":format!("{} runtime protocol outbound", kind.name()),
        "group":"integration",
        "enabled":true,
        "chain":chain
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        &format!("/api/v2/nodes/{node_id}/use"),
        None,
    )
    .await;

    let inbound_protocol = if udp {
        json!({"type":"mixed","mixed":{"username":"","password":""}})
    } else {
        json!({"type":"http","http":{"username":"","password":""}})
    };
    let inbound = json!({
        "id":inbound_id,
        "name":format!("{} runtime protocol inbound", kind.name()),
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":if udp { "enabled" } else { "disabled" }}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":inbound_protocol
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":rule_name,
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"protocol-integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(120)).await;
}

async fn configure_protocol_h2_outbound_chain(
    service: &ServiceProcess,
    kind: ProtocolOutboundKind,
    inbound: SocketAddr,
    server: SocketAddr,
    udp: bool,
) {
    let protocol_layer = match kind {
        ProtocolOutboundKind::Vless | ProtocolOutboundKind::VlessTlsWebsocket => json!({
            "type":"vless",
            "vless":{"uuid":"00112233-4455-6677-8899-aabbccddeeff"}
        }),
        ProtocolOutboundKind::Vmess | ProtocolOutboundKind::VmessTlsWebsocket => json!({
            "type":"vmess",
            "vmess":{
                "id":"00112233-4455-6677-8899-aabbccddeeff",
                "aid":"0",
                "security":"aes-128-gcm"
            }
        }),
        ProtocolOutboundKind::Trojan
        | ProtocolOutboundKind::TrojanWebsocket
        | ProtocolOutboundKind::TrojanTlsWebsocket => json!({
            "type":"trojan",
            "trojan":{"password":"runtime-protocol-password"}
        }),
    };
    let node_id = kind.node_id();
    let node = json!({
        "id":node_id,
        "name":format!("{} runtime HTTP/2 protocol outbound", kind.name()),
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":server.ip().to_string(),"port":server.port()}},
            {"type":"http2","http2":{"concurrency":1,"max_streams":8,"idle_timeout_secs":30}},
            protocol_layer
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        &format!("/api/v2/nodes/{node_id}/use"),
        None,
    )
    .await;

    let inbound = json!({
        "id":kind.inbound_id(),
        "name":kind.inbound_name(),
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":if udp { "enabled" } else { "disabled" }}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":if udp {
            json!({"type":"mixed","mixed":{"username":"","password":""}})
        } else {
            json!({"type":"http","http":{"username":"","password":""}})
        }
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;
    let rule = json!({
        "name":kind.rule_name(),
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"protocol-integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(120)).await;
}

async fn run_protocol_h2_outbound_chain(kind: ProtocolOutboundKind) {
    run_protocol_h2_outbound_chain_on_host(kind, "127.0.0.1").await;
}

async fn run_protocol_h2_outbound_chain_on_host(kind: ProtocolOutboundKind, bind_host: &str) {
    eprintln!(
        "starting HTTP/2 protocol outbound integration: {} host={bind_host}",
        kind.name(),
    );
    let expected_payload: &'static [u8] = match kind {
        ProtocolOutboundKind::Vless => b"runtime-vless-http2-outbound",
        ProtocolOutboundKind::Vmess => b"runtime-vmess-http2-outbound",
        ProtocolOutboundKind::Trojan => b"runtime-trojan-http2-outbound",
        ProtocolOutboundKind::VlessTlsWebsocket
        | ProtocolOutboundKind::VmessTlsWebsocket
        | ProtocolOutboundKind::TrojanWebsocket
        | ProtocolOutboundKind::TrojanTlsWebsocket => {
            panic!("TLS/WebSocket protocol variants are not part of this H2 fixture")
        }
    };
    let protocol_listener = TcpListener::bind((bind_host, 0)).await.unwrap();
    let protocol_server = protocol_listener.local_addr().unwrap();
    let server_task = tokio::spawn(protocol_h2_outbound_server(
        kind,
        protocol_listener,
        expected_payload,
        false,
    ));

    let _default_mixed_blocker = TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound = support::reserve_loopback().await;
    let root = integration_dir(&format!("service-{}-runtime-h2-outbound", kind.name()));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_protocol_h2_outbound_chain(&service, kind, inbound, protocol_server, false).await;

    let mut client = connect_loopback(inbound).await;
    client
        .write_all(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
        .await
        .unwrap();
    let mut headers = Vec::new();
    let mut buffer = [0u8; 1024];
    while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        let length = client.read(&mut buffer).await.unwrap();
        assert!(
            length > 0,
            "HTTP inbound closed before H2 protocol response"
        );
        headers.extend_from_slice(&buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));
    client.write_all(expected_payload).await.unwrap();
    let mut echoed = vec![0u8; expected_payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, expected_payload);

    let connections = wait_for_connection(&service.client, &service.base_url).await;
    let item = connections["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == kind.inbound_name())
        .expect("HTTP/2 protocol connection must be visible");
    assert_eq!(item["outbound"], protocol_server.to_string());
    assert_eq!(item["nodeId"], kind.node_id());
    assert_eq!(item["mode"], "proxy");

    client.shutdown().await.unwrap();
    service.shutdown().await;
    server_task.await.unwrap();
}

async fn run_protocol_h2_udp_outbound_chain(kind: ProtocolOutboundKind) {
    eprintln!(
        "starting HTTP/2 protocol UDP outbound integration: {}",
        kind.name()
    );
    let expected_payload: &'static [u8] = match kind {
        ProtocolOutboundKind::Vless => b"runtime-vless-http2-udp-outbound",
        ProtocolOutboundKind::Vmess => b"runtime-vmess-http2-udp-outbound",
        ProtocolOutboundKind::Trojan => b"runtime-trojan-http2-udp-outbound",
        ProtocolOutboundKind::VlessTlsWebsocket
        | ProtocolOutboundKind::VmessTlsWebsocket
        | ProtocolOutboundKind::TrojanWebsocket
        | ProtocolOutboundKind::TrojanTlsWebsocket => {
            panic!("TLS/WebSocket protocol variants are not part of this H2 UDP fixture")
        }
    };
    let protocol_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let protocol_server = protocol_listener.local_addr().unwrap();
    let server_task = tokio::spawn(protocol_h2_outbound_server(
        kind,
        protocol_listener,
        expected_payload,
        true,
    ));

    let _default_mixed_blocker = TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound = support::reserve_loopback().await;
    let root = integration_dir(&format!("service-{}-runtime-h2-udp-outbound", kind.name()));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_protocol_h2_outbound_chain(&service, kind, inbound, protocol_server, true).await;

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0, 1, 8, 8, 8, 8];
    packet.extend_from_slice(&5353u16.to_be_bytes());
    packet.extend_from_slice(expected_payload);
    let mut response = [0u8; 2048];
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    let mut next_send = std::time::Instant::now();
    let mut received = None;
    while std::time::Instant::now() < deadline {
        if std::time::Instant::now() >= next_send {
            client.send_to(&packet, inbound).await.unwrap();
            next_send = std::time::Instant::now() + Duration::from_millis(250);
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let wait = remaining.min(Duration::from_millis(250));
        if let Ok(Ok(result)) = tokio::time::timeout(wait, client.recv_from(&mut response)).await {
            received = Some(result);
            break;
        }
    }
    let (length, _) = received.unwrap_or_else(|| {
        panic!(
            "HTTP/2 protocol UDP inbound timed out for {}; inbound={inbound}; outbound={protocol_server}; diagnostics={}",
            kind.name(),
            service.diagnostics()
        )
    });
    assert!(
        response[..length]
            .windows(expected_payload.len())
            .any(|window| window == expected_payload),
        "HTTP/2 protocol UDP response did not contain payload: {:?}",
        &response[..length]
    );

    let connections = wait_for_connection(&service.client, &service.base_url).await;
    let item = connections["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == kind.inbound_name())
        .expect("HTTP/2 protocol UDP connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], protocol_server.to_string());
    assert_eq!(item["nodeId"], kind.node_id());
    assert_eq!(item["mode"], "proxy");

    service.shutdown().await;
    server_task.await.unwrap();
}

async fn run_protocol_outbound_chain(kind: ProtocolOutboundKind) {
    eprintln!("starting protocol outbound integration: {}", kind.name());
    let expected_payload: &'static [u8] = match kind {
        ProtocolOutboundKind::Vless => b"runtime-vless-outbound",
        ProtocolOutboundKind::VlessTlsWebsocket => b"runtime-vless-tls-websocket-outbound",
        ProtocolOutboundKind::Vmess => b"runtime-vmess-outbound",
        ProtocolOutboundKind::VmessTlsWebsocket => b"runtime-vmess-tls-websocket-outbound",
        ProtocolOutboundKind::Trojan => b"runtime-trojan-outbound",
        ProtocolOutboundKind::TrojanWebsocket => b"runtime-trojan-websocket-outbound",
        ProtocolOutboundKind::TrojanTlsWebsocket => b"runtime-trojan-tls-websocket-outbound",
    };
    let protocol_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let protocol_server = protocol_listener.local_addr().unwrap();
    let server_task = tokio::spawn(protocol_outbound_server(
        kind,
        protocol_listener,
        expected_payload,
    ));

    let _default_mixed_blocker = TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound = support::reserve_loopback().await;
    let root = integration_dir(&format!("service-{}-runtime-outbound", kind.name()));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_protocol_outbound_chain(&service, kind, inbound, protocol_server, false).await;

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
        assert!(length > 0, "HTTP inbound closed before protocol response");
        headers.extend_from_slice(&buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));

    client.write_all(expected_payload).await.unwrap();
    let mut echoed = vec![0u8; expected_payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, expected_payload);

    let mut connections = json!({});
    let mut visible = false;
    for _ in 0..500 {
        connections = api_json(
            &service.client,
            &service.base_url,
            reqwest::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        if connections["connections"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        {
            visible = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        visible,
        "{} connection did not become visible; connections={connections}; diagnostics={}",
        kind.name(),
        service.diagnostics()
    );
    let node_id = kind.node_id();
    let item = connections["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == kind.inbound_name())
        .expect("runtime protocol outbound connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], protocol_server.to_string());
    assert_eq!(item["nodeId"], node_id);
    assert_eq!(item["mode"], "proxy");
    assert!(item["matchHistory"].as_array().is_some_and(|history| {
        history
            .iter()
            .any(|entry| entry["ruleName"] == kind.rule_name())
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
    assert!(total["download"].as_str().unwrap().parse::<u64>().unwrap() > 0);

    let latency = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        &format!("/api/v2/nodes/{node_id}/latency"),
        Some(&json!({
            "id": node_id,
            "type": "http",
            "url": "http://example.test/health",
            "timeoutMs": 5_000
        })),
    )
    .await;
    assert_eq!(
        latency["ok"], true,
        "protocol node latency failed: {latency}"
    );

    client.shutdown().await.unwrap();
    service.shutdown().await;
    server_task.await.unwrap();
}

async fn run_protocol_udp_outbound_chain(kind: ProtocolOutboundKind) {
    eprintln!(
        "starting protocol UDP outbound integration: {}",
        kind.name()
    );
    let expected_payload: &'static [u8] = match kind {
        ProtocolOutboundKind::Vless => b"runtime-vless-udp-outbound",
        ProtocolOutboundKind::VlessTlsWebsocket => b"runtime-vless-tls-websocket-udp-outbound",
        ProtocolOutboundKind::Vmess => b"runtime-vmess-udp-outbound",
        ProtocolOutboundKind::VmessTlsWebsocket => b"runtime-vmess-tls-websocket-udp-outbound",
        ProtocolOutboundKind::Trojan => b"runtime-trojan-udp-outbound",
        ProtocolOutboundKind::TrojanWebsocket | ProtocolOutboundKind::TrojanTlsWebsocket => {
            panic!("Trojan WebSocket does not expose a datagram transport")
        }
    };
    let protocol_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let protocol_server = protocol_listener.local_addr().unwrap();
    let server_task = tokio::spawn(protocol_udp_outbound_server(
        kind,
        protocol_listener,
        expected_payload,
    ));

    let _default_mixed_blocker = TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound = support::reserve_loopback().await;
    let root = integration_dir(&format!("service-{}-runtime-udp-outbound", kind.name()));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_protocol_outbound_chain(&service, kind, inbound, protocol_server, true).await;

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = vec![0, 0, 0, 1, 8, 8, 8, 8];
    packet.extend_from_slice(&5353u16.to_be_bytes());
    packet.extend_from_slice(expected_payload);

    let mut response = [0u8; 2048];
    // The UDP listener and the first protocol session are both created after
    // the API reload notification.  GitHub's shared runners can delay that
    // reload, or the TLS/HTTP2 handshake, well beyond the local happy path.
    // Keep retransmits bounded so a slow runner does not turn one flow into a
    // burst of concurrent outbound sessions, while leaving enough time for
    // the real end-to-end path to settle.
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    let mut next_send = std::time::Instant::now();
    let mut received = None;
    while std::time::Instant::now() < deadline {
        if std::time::Instant::now() >= next_send {
            client.send_to(&packet, inbound).await.unwrap();
            next_send = std::time::Instant::now() + Duration::from_millis(250);
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let wait = remaining.min(Duration::from_millis(250));
        if let Ok(Ok(result)) = tokio::time::timeout(wait, client.recv_from(&mut response)).await {
            received = Some(result);
            break;
        }
    }
    let (length, _) = received.unwrap_or_else(|| {
        panic!(
            "protocol UDP inbound timed out for {}; inbound={inbound}; outbound={protocol_server}; diagnostics={}",
            kind.name(),
            service.diagnostics()
        )
    });
    assert!(
        response[..length]
            .windows(expected_payload.len())
            .any(|window| window == expected_payload),
        "protocol UDP response did not contain payload: {:?}",
        &response[..length]
    );

    let connections = wait_for_connection(&service.client, &service.base_url).await;
    let item = connections["connections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["inboundName"] == kind.inbound_name())
        .expect("runtime protocol UDP connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
    assert_eq!(item["outbound"], protocol_server.to_string());
    assert_eq!(item["nodeId"], kind.node_id());
    assert_eq!(item["mode"], "proxy");
    assert!(item["matchHistory"].as_array().is_some_and(|history| {
        history
            .iter()
            .any(|entry| entry["ruleName"] == kind.rule_name())
    }));

    service.shutdown().await;
    server_task.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_protocol_outbounds_round_trip_through_http_router() {
    for kind in [
        ProtocolOutboundKind::Vless,
        ProtocolOutboundKind::VlessTlsWebsocket,
        ProtocolOutboundKind::Vmess,
        ProtocolOutboundKind::VmessTlsWebsocket,
        ProtocolOutboundKind::Trojan,
        ProtocolOutboundKind::TrojanWebsocket,
        ProtocolOutboundKind::TrojanTlsWebsocket,
    ] {
        run_protocol_outbound_chain(kind).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_protocol_outbounds_round_trip_through_http2_transport() {
    for kind in [
        ProtocolOutboundKind::Vless,
        ProtocolOutboundKind::Vmess,
        ProtocolOutboundKind::Trojan,
    ] {
        run_protocol_h2_outbound_chain(kind).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_protocol_outbounds_round_trip_through_ipv6_http2_transport() {
    for kind in [
        ProtocolOutboundKind::Vless,
        ProtocolOutboundKind::Vmess,
        ProtocolOutboundKind::Trojan,
    ] {
        run_protocol_h2_outbound_chain_on_host(kind, "::1").await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_protocol_udp_outbounds_round_trip_through_http2_transport() {
    for kind in [
        ProtocolOutboundKind::Vless,
        ProtocolOutboundKind::Vmess,
        ProtocolOutboundKind::Trojan,
    ] {
        run_protocol_h2_udp_outbound_chain(kind).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_protocol_outbounds_round_trip_through_mixed_udp_router() {
    for kind in [
        ProtocolOutboundKind::Vless,
        ProtocolOutboundKind::VlessTlsWebsocket,
        ProtocolOutboundKind::Vmess,
        ProtocolOutboundKind::VmessTlsWebsocket,
        ProtocolOutboundKind::Trojan,
    ] {
        run_protocol_udp_outbound_chain(kind).await;
    }
}

async fn yuubinsya_auth_is_rejected(
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
            yuhaiin_core::yuubinsya::derive_salt(password.as_bytes()),
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
                reqwest::Method::POST,
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
    let transport = yuhaiin_protocol::aead::client(
        Box::new(transport),
        b"runtime-aead-password",
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
    let transport = yuhaiin_protocol::aead::client(
        Box::new(tls),
        b"runtime-aead-password",
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
        .find(|item| item["inboundName"] == "HTTP chain inbound")
        .expect("central-auth HTTP inbound connection must be visible");
    assert_eq!(item["inbound"], inbound.to_string());
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
async fn central_basic_user_authenticates_socks5_and_yuubinsya_inbounds() {
    let fixture = ConnectFixture::start().await;
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

    let root = integration_dir("service-central-required-inbound-auth");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_http_chain(&service, http_inbound, fixture.outbound).await;
    add_socks5_inbound(
        &service,
        "central-auth-socks5-in",
        socks5_inbound,
        "inline-user",
        "inline-password",
    )
    .await;
    add_yuubinsya_inbound(&service, "central-auth-yuubinsya-in", yuubinsya_inbound).await;

    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/users",
        Some(&json!({
            "id":"central-required-user",
            "name":"Central required inbound user",
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

    let mut socks5_auth_ready = false;
    for _ in 0..100 {
        if socks5_auth_probe(socks5_inbound, "central-user", "wrong-password")
            .await
            .is_ok_and(|reply| reply == [1, 1])
        {
            socks5_auth_ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        socks5_auth_ready,
        "central SOCKS5 auth snapshot did not reload; logs={}",
        service.diagnostics()
    );

    let mut yuubinsya_auth_ready = false;
    for _ in 0..100 {
        if yuubinsya_auth_is_rejected(
            yuubinsya_inbound,
            YUUBINSYA_PASSWORD,
            "example.test",
            fixture.target.port(),
        )
        .await
        {
            yuubinsya_auth_ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        yuubinsya_auth_ready,
        "central Yuubinsya auth snapshot did not reload; logs={}",
        service.diagnostics()
    );

    let mut socks5 = connect_socks5_with_auth(
        socks5_inbound,
        "central-user",
        "central-password",
        "example.test",
        fixture.target.port(),
    )
    .await;
    let socks5_payload = b"central-socks5-auth-payload";
    socks5.write_all(socks5_payload).await.unwrap();
    let mut socks5_echo = vec![0u8; socks5_payload.len()];
    socks5.read_exact(&mut socks5_echo).await.unwrap();
    assert_eq!(&socks5_echo, socks5_payload);

    let yuubinsya_stream = connect_loopback(yuubinsya_inbound).await;
    let mut yuubinsya = AsyncYuubinsyaTcpSession::connect(
        yuubinsya_stream,
        yuhaiin_core::yuubinsya::derive_salt(b"central-password"),
        Endpoint::domain(
            Network::Tcp,
            DomainName::new("example.test").unwrap(),
            fixture.target.port(),
        ),
    )
    .await
    .unwrap();
    let yuubinsya_payload = b"central-yuubinsya-auth-payload";
    yuubinsya.write_all(yuubinsya_payload).await.unwrap();
    let mut yuubinsya_echo = vec![0u8; yuubinsya_payload.len()];
    yuubinsya.read_exact(&mut yuubinsya_echo).await.unwrap();
    assert_eq!(&yuubinsya_echo, yuubinsya_payload);

    let mut connections = None;
    for _ in 0..100 {
        let current = api_json(
            &service.client,
            &service.base_url,
            reqwest::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        let items = current["connections"].as_array().unwrap();
        if items
            .iter()
            .any(|item| item["inboundName"] == "SOCKS5 integration inbound")
            && items
                .iter()
                .any(|item| item["inboundName"] == "Yuubinsya integration inbound")
        {
            connections = Some(current);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let connections = connections.expect("both centrally authenticated inbounds must be visible");
    let items = connections["connections"].as_array().unwrap();
    for (inbound_name, inbound_address) in [
        ("SOCKS5 integration inbound", socks5_inbound),
        ("Yuubinsya integration inbound", yuubinsya_inbound),
    ] {
        let item = items
            .iter()
            .find(|item| item["inboundName"] == inbound_name)
            .unwrap_or_else(|| panic!("connection for {inbound_name} is missing"));
        assert_eq!(item["inbound"], inbound_address.to_string());
        assert_eq!(item["outbound"], fixture.outbound.to_string());
        assert_eq!(item["mode"], "proxy");
        assert!(item["matchHistory"].as_array().is_some_and(|history| {
            history
                .iter()
                .any(|entry| entry["ruleName"] == "proxy-example-test")
        }));
    }

    yuubinsya.shutdown().await.unwrap();
    socks5.shutdown().await.unwrap();
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
            b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), client.read_to_end(&mut response))
        .await
        .expect("absolute HTTPS proxy request timed out")
        .unwrap();
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
    let connections = wait_for_connection(&service.client, &service.base_url).await;
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
        reqwest::Method::POST,
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
            reqwest::Method::GET,
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

    let root = integration_dir("service-reverse-http-termination");
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
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
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
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules",
        Some(&json!({
            "name":"reverse-http-termination-proxy",
            "mode":"proxy",
            "match":{"cidr":"127.0.0.1/32"}
        })),
    )
    .await;
    let route_test = api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
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
