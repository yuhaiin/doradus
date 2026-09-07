use super::*;

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
                aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
                aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
                    aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
                doradus_protocol::socks5_server::encode_udp_packet(&target, b"udp-close").unwrap();
            client.send_to(&packet, server_address).await.unwrap();
            let mut reply = [0u8; 2048];
            let (length, _) = client.recv_from(&mut reply).await.unwrap();
            let (_, payload) = doradus_protocol::socks5_server::parse_udp_packet(&reply[..length])
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
                        aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
            doradus_protocol::socks5_server::encode_udp_packet(&target, b"udp-associate").unwrap();
        client.send_to(&packet, relay_address).await.unwrap();
        let mut reply = [0u8; 2048];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut reply))
                .await
                .unwrap()
                .unwrap();
        let (_, payload) = doradus_protocol::socks5_server::parse_udp_packet(&reply[..length])
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
