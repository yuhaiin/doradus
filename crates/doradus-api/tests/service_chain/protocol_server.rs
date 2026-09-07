use super::*;

#[derive(Clone, Copy)]
pub(super) enum ProtocolOutboundKind {
    Vless,
    VlessTlsWebsocket,
    Vmess,
    VmessTlsWebsocket,
    Trojan,
    TrojanWebsocket,
    TrojanTlsWebsocket,
}

impl ProtocolOutboundKind {
    pub(super) fn name(self) -> &'static str {
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

    pub(super) fn node_id(self) -> String {
        format!("{}-runtime-out", self.name())
    }

    pub(super) fn inbound_id(self) -> String {
        format!("{}-runtime-in", self.name())
    }

    pub(super) fn inbound_name(self) -> String {
        format!("{} runtime protocol inbound", self.name())
    }

    pub(super) fn rule_name(self) -> String {
        format!("proxy-example-test-over-{}", self.name())
    }
}

pub(super) async fn protocol_outbound_server(
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

pub(super) async fn protocol_h2_outbound_server(
    kind: ProtocolOutboundKind,
    listener: TcpListener,
    expected_payload: &'static [u8],
    udp: bool,
) {
    let connection_count = if udp { 1 } else { 2 };
    for connection_index in 0..connection_count {
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
            Endpoint::domain(
                Network::Tcp,
                DomainName::new("example.test").unwrap(),
                if connection_index == 0 { 443 } else { 80 },
            )
        };
        let protocol_task = tokio::spawn(async move {
            match kind {
                ProtocolOutboundKind::Vless => {
                    let mut application = application;
                    if udp {
                        serve_vless_udp_connection(&mut application, destination, expected_payload)
                            .await;
                    } else {
                        serve_vless_connection(
                            &mut application,
                            connection_index,
                            destination,
                            expected_payload,
                        )
                        .await;
                    }
                }
                ProtocolOutboundKind::Vmess => {
                    let mut application = application;
                    if udp {
                        serve_vmess_udp_connection(&mut application, destination, expected_payload)
                            .await;
                    } else {
                        serve_vmess_connection(
                            &mut application,
                            connection_index,
                            destination,
                            expected_payload,
                        )
                        .await;
                    }
                }
                ProtocolOutboundKind::Trojan => {
                    let mut application = application;
                    if udp {
                        serve_trojan_udp_connection(
                            &mut application,
                            destination,
                            expected_payload,
                        )
                        .await;
                    } else {
                        serve_trojan_connection(
                            &mut application,
                            connection_index,
                            destination,
                            expected_payload,
                        )
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
}

pub(super) async fn serve_vless_connection<S>(
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

pub(super) async fn serve_vmess_connection<S>(
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

pub(super) async fn serve_trojan_connection<S>(
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

pub(super) async fn serve_trojan_udp_connection<S>(
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

pub(super) async fn protocol_udp_outbound_server(
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

pub(super) async fn serve_vless_udp_connection<S>(
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

pub(super) async fn serve_vmess_udp_connection<S>(
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

pub(super) async fn read_http_headers<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
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

pub(super) fn sha256_key(input: &[u8; 16]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    Sha256::digest(input)[..16].try_into().unwrap()
}
