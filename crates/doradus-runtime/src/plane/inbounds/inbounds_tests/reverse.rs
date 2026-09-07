use super::*;

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
        aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
        aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
            doradus_core::DomainName::new("backend.example").unwrap(),
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
        aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
        aead_method: doradus_protocol::aead::CryptoMethod::XChacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: None,
        reverse_http: None,
    };
    let listener_task = tokio::spawn(serve_listener(listener, spec, selector, monitor, None));

    let raw = TcpStream::connect(address).await.unwrap();
    let mut client = doradus_protocol::aead::client(
        Box::new(raw),
        b"secret",
        doradus_protocol::aead::CryptoMethod::XChacha20Poly1305,
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
