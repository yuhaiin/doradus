use super::*;

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
        aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: None,
        reverse_http: None,
    };
    let task = tokio::spawn(async move {
        let inbound = InboundHandler::new(spec, selector, monitor);
        let hashes = crate::inbound::adapters::trojan::password_hashes(inbound.spec());
        let udp_inbound = Arc::clone(&inbound);
        doradus_protocol::trojan::handle(
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
        aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: None,
        reverse_http: None,
    };
    let task = tokio::spawn(async move {
        let inbound = InboundHandler::new(spec, selector, monitor);
        let uuid = doradus_protocol::vless::parse_uuid(&inbound.spec().password)?;
        let udp_inbound = Arc::clone(&inbound);
        doradus_protocol::vless::handle(
            Box::new(server) as BoxAsyncStream,
            "127.0.0.1:41003".parse().unwrap(),
            &uuid,
            inbound.selector().udp_buffer_size(),
            inbound.as_ref(),
            move |server| async move {
                let codec = crate::inbound::adapters::vless::VlessUdpCodec { server };
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
        aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: None,
        reverse_http: None,
    };
    let task = tokio::spawn(async move {
        let inbound = InboundHandler::new(spec, selector, monitor);
        let uuid = doradus_protocol::vless::parse_uuid(&inbound.spec().password)?;
        let udp_inbound = Arc::clone(&inbound);
        doradus_protocol::vless::handle(
            Box::new(server) as BoxAsyncStream,
            "127.0.0.1:41004".parse().unwrap(),
            &uuid,
            inbound.selector().udp_buffer_size(),
            inbound.as_ref(),
            move |server| async move {
                let codec = crate::inbound::adapters::vless::VlessUdpCodec { server };
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
        aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
        outbound_id: "direct".to_owned(),
        reverse_target: None,
        reverse_http: None,
    };
    let task = tokio::spawn(async move {
        let inbound = InboundHandler::new(spec, selector, monitor);
        let hashes = crate::inbound::adapters::trojan::password_hashes(inbound.spec());
        let udp_inbound = Arc::clone(&inbound);
        doradus_protocol::trojan::handle(
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
