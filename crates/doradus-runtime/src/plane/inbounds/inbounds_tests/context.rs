use super::*;

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
        aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
        aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
            aead_method: doradus_protocol::aead::CryptoMethod::Chacha20Poly1305,
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
