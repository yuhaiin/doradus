use super::*;

#[tokio::test(flavor = "current_thread")]
async fn runtime_builds_wireguard_from_go_layer() {
    let key = |value| base64::engine::general_purpose::STANDARD.encode([value; 32]);
    let config = GoProxyRuntimeConfig {
        id: "wireguard".to_owned(),
        name: "WireGuard".to_owned(),
        group_name: "default".to_owned(),
        origin: "go".to_owned(),
        enabled: true,
        chain_types: vec!["wireguard".to_owned()],
        layers: vec![GoProxyLayer {
            kind: "wireguard".to_owned(),
            config: serde_json::json!({
                "secretKey": key(1),
                "endpoint": ["10.0.0.2/32"],
                "reserved": "AAAA",
                "peers": [{
                    "publicKey": key(2),
                    "endpoint": "127.0.0.1:51820",
                    "allowedIps": ["0.0.0.0/0"]
                }]
            }),
        }],
        transport: GoProxyTransport::Wireguard,
        data_json: Vec::new(),
    };
    let built = snapshot(config)
        .build_proxy("wireguard", Duration::from_secs(1))
        .await
        .unwrap();
    built.proxy.close().await.unwrap();
}

pub(super) struct MappingResolver {
    pub(super) address: std::net::Ipv4Addr,
    pub(super) queries: Arc<Mutex<Vec<String>>>,
}

impl AsyncIpResolver for MappingResolver {
    fn resolve<'a>(
        &'a self,
        domain: &'a doradus_core::DomainName,
        _strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        self.queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(domain.to_string());
        let address = self.address;
        Box::pin(async move {
            Ok(IpSet {
                v4: vec![address],
                v6: Vec::new(),
            })
        })
    }
}

fn snapshot_with_localhost_resolver(config: GoProxyRuntimeConfig) -> RuntimeSnapshot {
    snapshot_with_resolver(
        config,
        Arc::new(MappingResolver {
            address: std::net::Ipv4Addr::LOCALHOST,
            queries: Arc::new(Mutex::new(Vec::new())),
        }),
    )
}

#[tokio::test(flavor = "current_thread")]
async fn runtime_wireguard_resolves_peer_and_domain_targets_with_configured_resolver() {
    let key = |value| base64::engine::general_purpose::STANDARD.encode([value; 32]);
    let config = GoProxyRuntimeConfig {
        id: "wireguard-domain".to_owned(),
        name: "WireGuard domain".to_owned(),
        group_name: "default".to_owned(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["wireguard".to_owned()],
        layers: vec![GoProxyLayer {
            kind: "wireguard".to_owned(),
            config: serde_json::json!({
                "secretKey": key(3),
                "endpoint": ["10.0.0.2/32"],
                "peers": [{
                    "publicKey": key(4),
                    "endpoint": "peer-resolver-only.invalid:51820",
                    "allowedIps": ["0.0.0.0/0"]
                }]
            }),
        }],
        transport: GoProxyTransport::Wireguard,
        data_json: Vec::new(),
    };
    let queries = Arc::new(Mutex::new(Vec::new()));
    let resolver = Arc::new(MappingResolver {
        address: std::net::Ipv4Addr::LOCALHOST,
        queries: Arc::clone(&queries),
    });
    let built = snapshot_with_resolver(config, resolver)
        .build_proxy("wireguard-domain", Duration::from_secs(1))
        .await
        .unwrap();
    let context = FlowContext::new(Endpoint::domain(
        doradus_core::Network::Tcp,
        doradus_core::DomainName::new("resolver-only.invalid").unwrap(),
        80,
    ));
    let _stream = built.proxy.connect(&context).await.unwrap();
    built.proxy.close().await.unwrap();

    assert_eq!(
        queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_slice(),
        ["peer-resolver-only.invalid", "resolver-only.invalid"]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn standalone_build_proxy_resolves_domain_destinations() {
    let config = GoProxyRuntimeConfig {
        id: "direct".to_owned(),
        name: "Direct".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let built = snapshot_with_localhost_resolver(config)
        .build_proxy("direct", Duration::from_secs(1))
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut payload = [0u8; 18];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
            .await
            .unwrap();
        payload
    });
    let context = FlowContext::new(doradus_core::Endpoint::domain(
        doradus_core::Network::Tcp,
        doradus_core::DomainName::new("localhost").unwrap(),
        address.port(),
    ));
    let mut stream = built.proxy.connect(&context).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"standalone-resolve")
        .await
        .unwrap();
    assert_eq!(server.await.unwrap(), *b"standalone-resolve");
}

#[tokio::test]
async fn fixed_many_uses_one_raw_happy_eyeballs_race() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let stale_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stale = stale_listener.local_addr().unwrap();
    drop(stale_listener);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reachable = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut payload = [0u8; 10];
        stream.read_exact(&mut payload).await.unwrap();
        payload
    });
    let config = GoProxyRuntimeConfig {
        id: "fixed-many".to_owned(),
        name: "Fixed many".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["fixedv2".to_owned()],
        layers: vec![GoProxyLayer {
            kind: "fixedv2".to_owned(),
            config: serde_json::json!({
                "addresses": [
                    {"host": stale.ip().to_string(), "port": stale.port()},
                    {"host": reachable.ip().to_string(), "port": reachable.port()}
                ]
            }),
        }],
        transport: GoProxyTransport::Fixed,
        data_json: Vec::new(),
    };
    let snapshot = snapshot(config);
    let metrics = Arc::clone(&snapshot.metrics);
    let proxy = snapshot
        .build_proxy("fixed-many", Duration::from_secs(1))
        .await
        .unwrap()
        .proxy;
    let context = FlowContext::new(Endpoint::ip(
        doradus_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    let mut stream = proxy.connect(&context).await.unwrap();
    stream.write_all(b"fixed-many").await.unwrap();
    assert_eq!(server.await.unwrap(), *b"fixed-many");

    let mut output = String::new();
    metrics.encode(&mut output).unwrap();
    assert!(output.contains("doradus_happy_eyeballs_addresses_attempted_total 2"));
    assert!(output.contains("doradus_happy_eyeballs_tcp_attempts_total 2"));
    assert!(output.contains("doradus_happy_eyeballs_tcp_failures_total 1"));
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn runtime_proxy_carries_node_network_interface_into_direct_socket() {
    let config = GoProxyRuntimeConfig {
        id: "direct-interface".to_owned(),
        name: "Direct interface".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: vec![GoProxyLayer {
            kind: "direct".to_owned(),
            config: serde_json::json!({ "network_interface": "lo" }),
        }],
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let built = snapshot(config)
        .build_proxy("direct-interface", Duration::from_secs(1))
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
    let context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
        address,
    ));
    let mut stream = built.proxy.connect(&context).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"interface")
        .await
        .unwrap();
    let mut accepted = server.await.unwrap();
    let mut payload = [0u8; 9];
    tokio::io::AsyncReadExt::read_exact(&mut accepted, &mut payload)
        .await
        .unwrap();
    assert_eq!(&payload, b"interface");
}

#[test]
fn proxy_selector_assembles_snapshot_proxies_and_safe_builtin_slots() {
    let config = GoProxyRuntimeConfig {
        id: "proxy".to_owned(),
        name: "Proxy".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let selector = block_on(snapshot(config).build_proxy_selector(
        "",
        "proxy",
        "",
        "",
        Duration::from_secs(1),
    ))
    .unwrap();

    let mut context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    context.route_mode = RouteMode::Proxy;
    context.skip_route = true;
    let selected = selector.select(&context);
    context.route_mode = RouteMode::Direct;
    let direct = selector.select(&context);
    assert!(!Arc::ptr_eq(&selected, &direct));
}

#[test]
fn proxy_selector_uses_independent_tcp_and_udp_selected_nodes() {
    let make_direct = |id: &str| GoProxyRuntimeConfig {
        id: id.to_owned(),
        name: id.to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let mut snapshot = snapshot(make_direct("tcp-node"));
    snapshot.proxies.push(make_direct("udp-node"));
    let selector = block_on(snapshot.build_proxy_selector_with_udp(
        "",
        "tcp-node",
        "udp-node",
        "",
        "",
        Duration::from_secs(1),
    ))
    .unwrap();

    let mut tcp = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    tcp.route_mode = RouteMode::Proxy;
    let mut udp = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Udp,
        "192.0.2.1:443".parse().unwrap(),
    ));
    udp.route_mode = RouteMode::Proxy;
    udp.skip_route = true;

    let tcp_proxy = selector.select(&tcp);
    let udp_proxy = selector.select(&udp);
    assert!(!Arc::ptr_eq(&tcp_proxy, &udp_proxy));
    assert!(selector.active_node_ids().contains(&"udp-node".to_owned()));
    selector.route_context(&mut udp);
    assert_eq!(udp.outbound.as_deref(), Some("udp-node"));
}

#[test]
fn runtime_selector_blocks_inbound_listener_cycle_before_route_rules() {
    let config = GoProxyRuntimeConfig {
        id: "proxy".to_owned(),
        name: "Proxy".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let selector = block_on(snapshot(config).build_proxy_selector(
        "",
        "proxy",
        "",
        "",
        Duration::from_secs(1),
    ))
    .unwrap();
    let address = "127.0.0.1:18080".parse().unwrap();
    let mut context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
        address,
    ));
    context.local_addr = Some(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
        address,
    ));

    selector.route_context(&mut context);

    assert_eq!(context.route_mode, RouteMode::Block);
    assert!(context.skip_route);
    assert_eq!(context.tag.as_deref(), Some("loopback cycle"));
}

#[tokio::test(flavor = "current_thread")]
async fn selector_resolves_domain_for_direct_socket_without_losing_protocol_domain() {
    let config = GoProxyRuntimeConfig {
        id: "proxy".to_owned(),
        name: "Proxy".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let selector = snapshot_with_localhost_resolver(config)
        .build_proxy_selector("", "proxy", "", "", Duration::from_secs(1))
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut payload = [0u8; 15];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
            .await
            .unwrap();
        payload
    });

    let mut context = FlowContext::new(doradus_core::Endpoint::domain(
        doradus_core::Network::Tcp,
        doradus_core::DomainName::new("localhost").unwrap(),
        address.port(),
    ));
    context.route_mode = RouteMode::Proxy;
    let selected = selector.select(&context);
    let mut stream = selected.connect(&context).await.unwrap();
    assert_eq!(
        context.effective_destination().host().unwrap().as_str(),
        "localhost"
    );
    assert!(context.resolved_destination.is_none());
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"resolved-domain")
        .await
        .unwrap();
    assert_eq!(server.await.unwrap(), *b"resolved-domain");
}

#[tokio::test(flavor = "current_thread")]
async fn tun_fakeip_domain_uses_non_fakeip_resolver_for_direct_socket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut payload = [0u8; 18];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
            .await
            .unwrap();
        payload
    });

    let fake_queries = Arc::new(Mutex::new(Vec::new()));
    let fake_resolver = Arc::new(MappingResolver {
        address: "198.18.0.1".parse().unwrap(),
        queries: Arc::clone(&fake_queries),
    });
    let real_queries = Arc::new(Mutex::new(Vec::new()));
    let real_resolver = Arc::new(MappingResolver {
        address: address.ip().to_string().parse().unwrap(),
        queries: Arc::clone(&real_queries),
    });
    let config = GoProxyRuntimeConfig {
        id: "direct".to_owned(),
        name: "Direct".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let mut snapshot = snapshot_with_resolver(config, fake_resolver);
    snapshot.dns_resolver = real_resolver;
    let selector = snapshot
        .build_proxy_selector("", "", "", "", Duration::from_secs(1))
        .await
        .unwrap();

    let fake_ip = "198.18.0.1".parse().unwrap();
    let domain = doradus_core::DomainName::new("ip.sb").unwrap();
    let mut context = FlowContext::new(Endpoint::ip(
        doradus_core::Network::Tcp,
        SocketAddr::new(fake_ip, address.port()),
    ));
    context.original_domain = Some(domain);
    context.fake_ip = Some(fake_ip.to_string());
    context.route_mode = RouteMode::Direct;
    let proxy = selector.select(&context);
    let mut stream = proxy.connect(&context).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"fakeip-real-target")
        .await
        .unwrap();

    assert_eq!(server.await.unwrap(), *b"fakeip-real-target");
    assert!(
        fake_queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
    );
    assert_eq!(
        real_queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_slice(),
        ["ip.sb", "ip.sb"]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn tagged_direct_node_uses_proxy_resolver_for_proxy_mode_tun_fakeip() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut payload = [0u8; 16];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
            .await
            .unwrap();
        payload
    });

    let fake_queries = Arc::new(Mutex::new(Vec::new()));
    let fake_resolver: Arc<dyn AsyncIpResolver> = Arc::new(MappingResolver {
        address: "198.18.0.1".parse().unwrap(),
        queries: Arc::clone(&fake_queries),
    });
    let real_queries = Arc::new(Mutex::new(Vec::new()));
    let real_resolver: Arc<dyn AsyncIpResolver> = Arc::new(MappingResolver {
        address: address.ip().to_string().parse().unwrap(),
        queries: Arc::clone(&real_queries),
    });
    let config = GoProxyRuntimeConfig {
        id: "direct-node".to_owned(),
        name: "Direct node".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let mut snapshot = snapshot_with_resolver(config, Arc::clone(&fake_resolver));
    snapshot.route = Some(doradus_store::GoRouteRuntimeConfig {
        direct_resolver: "direct".to_owned(),
        proxy_resolver: "proxy".to_owned(),
        resolve_locally: false,
        udp_proxy_fqdn: doradus_store::GoUdpProxyFqdnStrategy::Resolve,
    });
    snapshot
        .dns_resolver_by_id
        .insert("direct".to_owned(), Arc::clone(&fake_resolver));
    snapshot
        .dns_resolver_by_id
        .insert("proxy".to_owned(), real_resolver);
    snapshot.resolver_registry_enabled = true;
    snapshot.node_tags.push(doradus_store::GoNodeTagRecord {
        id: "edge".to_owned(),
        name: "edge".to_owned(),
        members_json: br#"{"type":"node","hash":["direct-node"]}"#.to_vec(),
        updated_at: 1,
    });

    let selector = snapshot
        .build_proxy_selector("", "", "", "", Duration::from_secs(1))
        .await
        .unwrap();
    let fake_ip = "198.18.0.1".parse().unwrap();
    let domain = doradus_core::DomainName::new("www.baidu.com").unwrap();
    let mut context = FlowContext::new(Endpoint::ip(
        doradus_core::Network::Tcp,
        SocketAddr::new(fake_ip, address.port()),
    ));
    context.original_domain = Some(domain);
    context.fake_ip = Some(fake_ip.to_string());
    // A node tag is selected in Proxy mode, while the selected node's
    // protocol is direct. This is the exact TUN route shape reported by
    // the UI and must still use the non-FakeIP Proxy resolver.
    context.route_mode = RouteMode::Proxy;
    context.tag = Some("edge".to_owned());

    let proxy = selector.select(&context);
    let mut stream = proxy.connect(&context).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"tagged-direct-ok")
        .await
        .unwrap();

    assert_eq!(server.await.unwrap(), *b"tagged-direct-ok");
    assert!(
        fake_queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty()
    );
    assert_eq!(
        real_queries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_slice(),
        ["www.baidu.com", "www.baidu.com"]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn selector_resolves_domain_for_direct_udp_even_when_proxy_dns_is_skipped() {
    let config = GoProxyRuntimeConfig {
        id: "proxy".to_owned(),
        name: "Proxy".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let selector = snapshot_with_localhost_resolver(config)
        .build_proxy_selector("", "proxy", "", "", Duration::from_secs(1))
        .await
        .unwrap();
    let destination = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = destination.local_addr().unwrap().port();
    let mut context = FlowContext::new(doradus_core::Endpoint::domain(
        doradus_core::Network::Udp,
        doradus_core::DomainName::new("localhost").unwrap(),
        port,
    ));
    context.route_mode = RouteMode::Proxy;
    context.resolver_policy.udp_skip_resolve_target = true;

    selector
        .select(&context)
        .open_datagram(&context)
        .await
        .expect("direct transport must resolve its own UDP target");
}

#[tokio::test(flavor = "current_thread")]
async fn live_selector_reload_replaces_data_plane_settings() {
    let config = GoProxyRuntimeConfig {
        id: "proxy".to_owned(),
        name: "Proxy".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let mut first = snapshot(config.clone());
    first.settings.udp_buffer_size = 4096;
    first.settings.relay_buffer_size = 8192;
    first.settings.udp_ringbuffer_size = 512;
    first.socket_bind_addresses =
        Arc::from(vec!["127.0.0.2".parse::<std::net::IpAddr>().unwrap()].into_boxed_slice());
    let selector = first
        .build_proxy_selector("", "proxy", "", "", Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(selector.udp_buffer_size(), 4096);
    assert_eq!(selector.relay_buffer_size(), 8192);
    assert_eq!(selector.udp_ringbuffer_size(), 512);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = std::thread::spawn(move || listener.accept().unwrap().0.peer_addr().unwrap());
    let context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
        address,
    ));
    let _stream = selector.select(&context).connect(&context).await.unwrap();
    assert_eq!(
        peer.join().unwrap().ip(),
        "127.0.0.2".parse::<std::net::IpAddr>().unwrap()
    );

    let mut next = snapshot(config);
    next.settings.udp_buffer_size = 2048;
    next.settings.relay_buffer_size = 2049;
    next.settings.udp_ringbuffer_size = 100;
    next.socket_bind_addresses =
        Arc::from(vec!["127.0.0.2".parse::<std::net::IpAddr>().unwrap()].into_boxed_slice());
    let prepared = selector.prepare(&next).await.unwrap();
    selector.replace(prepared);
    assert_eq!(selector.udp_buffer_size(), 2048);
    assert_eq!(selector.relay_buffer_size(), 2049);
    assert_eq!(selector.udp_ringbuffer_size(), 100);
}

struct TestGeo;

impl GeoLookup for TestGeo {
    fn country_code(&self, _address: std::net::IpAddr) -> doradus_core::Result<Option<String>> {
        Ok(Some("ZZ".to_owned()))
    }
}

#[test]
fn selector_populates_hosts_and_outbound_geo_before_proxy_connect() {
    let config = GoProxyRuntimeConfig {
        id: "proxy".to_owned(),
        name: "Proxy".to_owned(),
        group_name: String::new(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types: vec!["direct".to_owned()],
        layers: Vec::new(),
        transport: GoProxyTransport::Direct,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    let mut snapshot = snapshot(config);
    let domain = doradus_core::DomainName::new("hosts.example").unwrap();
    snapshot
        .hosts
        .insert_ip(domain.clone(), "192.0.2.44".parse().unwrap())
        .unwrap();
    snapshot.geo = Some(Arc::new(TestGeo));
    let selector =
        block_on(snapshot.build_proxy_selector("", "proxy", "", "", Duration::from_secs(1)))
            .unwrap();

    let mut context = FlowContext::new(doradus_core::Endpoint::ip(
        doradus_core::Network::Tcp,
        "192.0.2.44:443".parse().unwrap(),
    ));
    context.original_domain = Some(domain);
    context.route_mode = RouteMode::Direct;
    selector.route_context(&mut context);

    assert_eq!(context.hosts.as_deref(), Some("hosts.example:443"));
    assert_eq!(context.outbound_geo.as_deref(), Some("ZZ"));
    assert_eq!(
        context.outbound_addr,
        Some(Endpoint::ip(
            doradus_core::Network::Tcp,
            "192.0.2.44:443".parse().unwrap(),
        ))
    );
}
