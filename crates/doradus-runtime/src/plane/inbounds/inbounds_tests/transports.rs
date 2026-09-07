use super::*;

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
                aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
                aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
                aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
            let password = doradus_protocol::yuubinsya::derive_salt(b"test-password");
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
                aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
                aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
                h2::client::handshake(doradus_protocol::websocket::WebSocketIo::new(websocket))
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
                aead_method: doradus_protocol::aead::CryptoMethod::XChacha20Poly1305,
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
            let transport = doradus_protocol::aead::client(
                Box::new(transport),
                b"secret",
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
                aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
            let transport = doradus_protocol::aead::client(
                Box::new(transport),
                b"secret",
                doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
                aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
