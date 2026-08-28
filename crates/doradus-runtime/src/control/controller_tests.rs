use std::sync::Arc;

use doradus_core::dns_resolver::SystemAsyncIpResolver;
use doradus_core::proxy::AsyncProxySelector;
use doradus_core::{Endpoint, ErrorKind, FlowContext, Network, RouteMode};
use doradus_store::{
    ConfigMutation, ConfigStore, GoNodeRecord, GoRouteRuleRecord, MaxMindMetadataRecord,
};

use super::*;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(future)
}

fn controller() -> RuntimeController {
    block_on(RuntimeController::from_builder(RuntimeBuilder::new(
        block_on(ConfigStore::open_memory()).unwrap(),
        Arc::new(SystemAsyncIpResolver),
    )))
    .unwrap()
}

#[test]
fn apply_commits_config_and_publishes_a_new_shared_snapshot() {
    let controller = controller();
    let before = controller.handle().load_with_revision();
    let next = block_on(controller.apply(&[ConfigMutation::Put {
        key: "http.listen_port".to_owned(),
        value: b"1080".to_vec(),
    }]))
    .unwrap();

    assert_eq!(
        block_on(controller.store().get_config("http.listen_port")).unwrap(),
        Some(b"1080".to_vec())
    );
    assert_eq!(controller.handle().revision(), before.0 + 1);
    assert!(Arc::ptr_eq(&next, &controller.handle().load()));
}

#[test]
fn inbound_reload_notifications_are_reserved_for_listener_changes() {
    let controller = controller();
    let mut ordinary = controller.subscribe_reload();
    let mut inbound = controller.subscribe_inbound_reload();

    block_on(controller.reload()).unwrap();
    assert!(ordinary.try_recv().is_ok());
    assert!(matches!(
        inbound.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    block_on(
        controller.mutate_and_reload_inbound("test.inbound", |store| async move {
            store.put_config("test.inbound", b"changed").await
        }),
    )
    .unwrap();
    assert_eq!(
        inbound.try_recv().unwrap(),
        InboundReload::One("test.inbound".to_owned())
    );
}

#[test]
fn ordinary_reload_updates_dns_handler_without_restarting_dns_listener() {
    let controller = controller();
    let mut ordinary = controller.subscribe_reload();
    let mut dns = controller.subscribe_dns_reload();

    block_on(controller.mutate_and_reload(|store| async move {
        store.put_config("resolver.hosts", br#"{}"#).await
    }))
    .unwrap();
    assert!(ordinary.try_recv().is_ok());
    assert!(matches!(
        dns.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    block_on(controller.mutate_and_reload_dns(|store| async move {
        store
            .put_config("resolver.server", br#"{\"server\":\"127.0.0.1:5533\"}"#)
            .await
    }))
    .unwrap();
    assert!(dns.try_recv().is_ok());
}

#[test]
fn reload_failure_keeps_the_previous_snapshot_and_persisted_config() {
    let controller = controller();
    let before = controller.handle().load_with_revision();
    block_on(
        controller
            .store()
            .repository()
            .put_maxmind_metadata(&MaxMindMetadataRecord {
                id: "broken".to_owned(),
                path: ".cache/doradus/missing.mmdb".to_owned(),
                sha256: Vec::new(),
                size: 0,
                updated_at: 0,
            }),
    )
    .unwrap();

    assert!(block_on(controller.reload()).is_err());
    assert!(controller.last_reload_error().is_some());
    let after = controller.handle().load_with_revision();
    assert_eq!(after.0, before.0);
    assert!(Arc::ptr_eq(&before.1, &after.1));
    assert_eq!(
        block_on(controller.store().repository().list_maxmind_metadata())
            .unwrap()
            .len(),
        1
    );

    block_on(
        controller
            .store()
            .repository()
            .delete_maxmind_metadata("broken"),
    )
    .unwrap();
    block_on(controller.reload()).unwrap();
    assert_eq!(controller.last_reload_error(), None);
}

#[test]
fn typed_repository_mutation_reuses_the_same_reload_boundary() {
    let controller = controller();
    let record = GoRouteRuleRecord {
        id: "controller-rule".to_owned(),
        name: "controller-rule".to_owned(),
        priority: 10,
        disabled: false,
        action_mode: "direct".to_owned(),
        match_type: "domain".to_owned(),
        tag: "test".to_owned(),
        updated_at: 1,
        data_json: br#"{"match":{"domain":"example.com"},"mode":"direct"}"#.to_vec(),
    };

    let snapshot = block_on(controller.mutate_and_reload(move |store| async move {
        store.repository().put_go_route_rule(&record).await
    }))
    .unwrap();

    assert_eq!(snapshot.route_rules.len(), 2);
    assert!(
        snapshot
            .route_rules
            .iter()
            .any(|rule| rule.id == "controller-rule")
    );
}

#[test]
fn registered_proxy_selector_refreshes_only_after_a_successful_reload() {
    let controller = controller();
    let mut node = GoNodeRecord {
        id: "proxy".to_owned(),
        name: "proxy-v1".to_owned(),
        group_name: "default".to_owned(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types_json: br#"["direct"]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    };
    block_on(controller.store().repository().put_go_node(&node)).unwrap();
    block_on(controller.reload()).unwrap();

    let selector = block_on(controller.build_proxy_selector(
        "",
        "proxy",
        "",
        "",
        std::time::Duration::from_secs(1),
    ))
    .unwrap();
    let mut context =
        FlowContext::new(Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap()));
    context.route_mode = RouteMode::Proxy;
    context.skip_route = true;
    let before = selector.select(&context);
    let revision = controller.handle().revision();

    node.enabled = false;
    node.updated_at = 2;
    block_on(controller.store().repository().put_go_node(&node)).unwrap();
    assert!(block_on(controller.reload()).is_err());
    assert_eq!(controller.handle().revision(), revision);
    let after_failed_reload = selector.select(&context);
    assert!(Arc::ptr_eq(&before, &after_failed_reload));

    node.enabled = true;
    node.updated_at = 3;
    node.name = "proxy-v2".to_owned();
    block_on(controller.store().repository().put_go_node(&node)).unwrap();
    block_on(controller.reload()).unwrap();
    let after_successful_reload = selector.select(&context);
    assert!(!Arc::ptr_eq(&before, &after_successful_reload));
}

#[test]
fn close_node_closes_live_slots_without_deleting_config_and_reload_reopens_them() {
    let controller = controller();
    block_on(controller.store().repository().put_go_node(&GoNodeRecord {
        id: "proxy".to_owned(),
        name: "proxy".to_owned(),
        group_name: "default".to_owned(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types_json: br#"["direct"]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    }))
    .unwrap();
    block_on(controller.reload()).unwrap();
    let selector = block_on(controller.build_proxy_selector(
        "",
        "proxy",
        "",
        "",
        std::time::Duration::from_secs(1),
    ))
    .unwrap();
    assert_eq!(controller.active_proxy_ids(), vec!["proxy"]);

    let mut context =
        FlowContext::new(Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap()));
    context.route_mode = RouteMode::Proxy;
    context.skip_route = true;
    let old_proxy = selector.select(&context);

    block_on(controller.close_node("proxy")).unwrap();
    assert!(controller.active_proxy_ids().is_empty());
    let error = match block_on(selector.select(&context).connect(&context)) {
        Ok(_) => panic!("closed node unexpectedly accepted a new connection"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Closed);
    assert!(
        block_on(controller.store().repository().list_go_nodes())
            .unwrap()
            .iter()
            .any(|node| node.id == "proxy")
    );

    block_on(controller.close_node("")).unwrap();
    block_on(controller.close_node("missing")).unwrap();
    block_on(controller.reload()).unwrap();
    assert_eq!(controller.active_proxy_ids(), vec!["proxy"]);
    let reopened = selector.select(&context);
    assert!(!Arc::ptr_eq(&old_proxy, &reopened));
}

#[test]
fn registered_selector_refreshes_connection_metadata_with_snapshot() {
    let controller = controller();
    block_on(controller.store().repository().put_go_node(&GoNodeRecord {
        id: "proxy".to_owned(),
        name: "proxy".to_owned(),
        group_name: "default".to_owned(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types_json: br#"["direct"]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    }))
    .unwrap();
    block_on(controller.reload()).unwrap();
    let selector = block_on(controller.build_proxy_selector(
        "",
        "proxy",
        "",
        "",
        std::time::Duration::from_secs(1),
    ))
    .unwrap();

    block_on(controller.store().put_config(
        "resolver.hosts",
        br#"{"hosts":{"reload.example":"192.0.2.44"}}"#,
    ))
    .unwrap();
    block_on(controller.reload()).unwrap();

    let mut context = FlowContext::new(Endpoint::ip(
        Network::Tcp,
        "192.0.2.44:443".parse().unwrap(),
    ));
    context.original_domain = Some(doradus_core::DomainName::new("reload.example").unwrap());
    selector.route_context(&mut context);
    assert_eq!(context.hosts.as_deref(), Some("reload.example:443"));
}

#[test]
fn shared_selector_restores_ipv4_and_ipv6_fakeip_for_socket_inbounds() {
    let controller = controller();
    block_on(controller.store().put_config(
        "resolver.fakedns",
        br#"{"enabled":true,"ipv4Range":"198.18.2.0/30","ipv6Range":"fc00:2::/126"}"#,
    ))
    .unwrap();
    block_on(controller.store().put_config(
            "resolver.hosts",
            br#"{"hosts":{"socket-v4.example.com:443":"socket-target.example.com:9443","socket-v6.example.com":"socket-v6-target.example.com"}}"#,
        ))
        .unwrap();
    block_on(controller.store().repository().put_go_node(&GoNodeRecord {
        id: "direct".to_owned(),
        name: "direct".to_owned(),
        group_name: "default".to_owned(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types_json: br#"["direct"]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    }))
    .unwrap();
    block_on(controller.reload()).unwrap();

    let snapshot = controller.handle().load();
    let domain = doradus_core::DomainName::new("socket-v4.example.com").unwrap();
    let fake_ip = block_on(
        snapshot
            .fakeip
            .as_ref()
            .expect("FakeIP should be enabled")
            .ipv4
            .allocate(domain.clone()),
    )
    .unwrap();
    let v6_domain = doradus_core::DomainName::new("socket-v6.example.com").unwrap();
    let v6_fake_ip = block_on(
        snapshot
            .fakeip
            .as_ref()
            .expect("FakeIP should be enabled")
            .ipv6
            .allocate(v6_domain.clone()),
    )
    .unwrap();

    let selector = block_on(controller.build_proxy_selector(
        "direct",
        "direct",
        "",
        "",
        std::time::Duration::from_secs(1),
    ))
    .unwrap();
    let mut tcp = FlowContext::new(Endpoint::ip(
        Network::Tcp,
        std::net::SocketAddr::new(fake_ip.into(), 443),
    ));
    selector.route_context(&mut tcp);
    assert_eq!(tcp.original_domain, Some(domain));
    assert_eq!(tcp.fake_ip.as_deref(), Some(fake_ip.to_string().as_str()));
    assert_eq!(
        tcp.destination,
        Endpoint::domain(
            Network::Tcp,
            doradus_core::DomainName::new("socket-target.example.com").unwrap(),
            9443,
        )
    );
    assert_eq!(tcp.hosts.as_deref(), Some("socket-v4.example.com:443"));

    let mut udp = FlowContext::new(Endpoint::ip(
        Network::Udp,
        std::net::SocketAddr::new(v6_fake_ip.into(), 443),
    ));
    selector.route_context(&mut udp);
    assert_eq!(udp.original_domain, Some(v6_domain));
    assert_eq!(
        udp.fake_ip.as_deref(),
        Some(v6_fake_ip.to_string().as_str())
    );
    assert_eq!(
        udp.destination,
        Endpoint::domain(
            Network::Udp,
            doradus_core::DomainName::new("socket-v6-target.example.com").unwrap(),
            443,
        )
    );

    let mut unmapped = FlowContext::new(Endpoint::ip(
        Network::Udp,
        "[fc00:2::3]:443".parse().unwrap(),
    ));
    selector.route_context(&mut unmapped);
    assert_eq!(unmapped.route_mode, RouteMode::Block);
    assert!(unmapped.skip_route);
}

#[test]
fn shared_selector_dispatches_ip_hosts_for_socket_inbounds() {
    let controller = controller();
    block_on(controller.store().put_config(
            "resolver.hosts",
            br#"{"hosts":{"192.0.2.50:443":"host.example.com:8443","source.example:443":"target.example:9443"}}"#,
        ))
        .unwrap();
    block_on(controller.store().repository().put_go_node(&GoNodeRecord {
        id: "direct".to_owned(),
        name: "direct".to_owned(),
        group_name: "default".to_owned(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types_json: br#"["direct"]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    }))
    .unwrap();
    block_on(controller.reload()).unwrap();

    let selector = block_on(controller.build_proxy_selector(
        "direct",
        "direct",
        "",
        "",
        std::time::Duration::from_secs(1),
    ))
    .unwrap();
    let mut tcp = FlowContext::new(Endpoint::ip(
        Network::Tcp,
        "192.0.2.50:443".parse().unwrap(),
    ));
    selector.route_context(&mut tcp);
    assert_eq!(
        tcp.destination,
        Endpoint::domain(
            Network::Tcp,
            doradus_core::DomainName::new("host.example.com").unwrap(),
            8443,
        )
    );
    assert_eq!(
        tcp.original_domain,
        Some(doradus_core::DomainName::new("host.example.com").unwrap())
    );
    assert_eq!(tcp.hosts.as_deref(), Some("192.0.2.50:443"));

    let mut domain = FlowContext::new(Endpoint::domain(
        Network::Tcp,
        doradus_core::DomainName::new("source.example").unwrap(),
        443,
    ));
    domain.original_domain = domain.destination.host().cloned();
    selector.route_context(&mut domain);
    assert_eq!(
        domain.destination,
        Endpoint::domain(
            Network::Tcp,
            doradus_core::DomainName::new("target.example").unwrap(),
            9443,
        )
    );
    assert_eq!(domain.hosts.as_deref(), Some("source.example:443"));

    let mut udp = FlowContext::new(Endpoint::ip(
        Network::Udp,
        "192.0.2.50:443".parse().unwrap(),
    ));
    selector.route_context(&mut udp);
    assert_eq!(
        udp.original_domain,
        Some(doradus_core::DomainName::new("host.example.com").unwrap())
    );
    assert_eq!(udp.hosts.as_deref(), Some("192.0.2.50:443"));
}

#[cfg(feature = "tun")]
#[test]
fn controller_assembles_tun_runtime_from_one_full_cone_snapshot() {
    let controller = controller();
    block_on(controller.store().repository().put_go_node(&GoNodeRecord {
        id: "proxy".to_owned(),
        name: "proxy".to_owned(),
        group_name: "default".to_owned(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types_json: br#"["direct"]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    }))
    .unwrap();
    block_on(controller.reload()).unwrap();

    let runtime = block_on(controller.build_tun_proxy_runtime(
        "",
        "proxy",
        "",
        "",
        std::time::Duration::from_secs(1),
        8,
    ))
    .unwrap();
    assert_eq!(runtime.task_len(), 0);
}

#[cfg(feature = "tun")]
#[test]
fn tun_runtime_registers_selector_with_resolver_proxy_bridge() {
    let bridge = Arc::new(crate::resolver::ResolverProxyBridge::new());
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let controller = block_on(RuntimeController::from_builder(
        RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver))
            .with_resolver_proxy_bridge(bridge.clone()),
    ))
    .unwrap();
    block_on(controller.store().repository().put_go_node(&GoNodeRecord {
        id: "proxy".to_owned(),
        name: "proxy".to_owned(),
        group_name: "default".to_owned(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types_json: br#"["direct"]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    }))
    .unwrap();
    block_on(controller.reload()).unwrap();
    assert!(!bridge.has_selector());

    let runtime = block_on(controller.build_tun_proxy_runtime(
        "",
        "proxy",
        "",
        "",
        std::time::Duration::from_secs(1),
        8,
    ))
    .unwrap();
    assert_eq!(runtime.task_len(), 0);
    assert!(bridge.has_selector());
}

#[cfg(feature = "tun")]
#[test]
fn tun_runtime_restores_fakeip_domain_before_route_and_monitor_open() {
    let controller = controller();
    block_on(controller.store().put_config(
        "resolver.fakedns",
        br#"{"enabled":true,"ipv4Range":"198.18.2.0/30","ipv6Range":"fc00:2::/126"}"#,
    ))
    .unwrap();
    block_on(controller.store().repository().put_go_node(&GoNodeRecord {
        id: "direct".to_owned(),
        name: "direct".to_owned(),
        group_name: "default".to_owned(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types_json: br#"["direct"]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    }))
    .unwrap();
    block_on(controller.reload()).unwrap();

    let domain = doradus_core::DomainName::new("fake.example.com").unwrap();
    let fake_ip = block_on(
        controller
            .handle()
            .load()
            .fakeip
            .as_ref()
            .expect("FakeIP should be enabled")
            .ipv4
            .allocate(domain.clone()),
    )
    .unwrap();
    let v6_domain = doradus_core::DomainName::new("fake-v6.example.com").unwrap();
    let v6_fake_ip = block_on(
        controller
            .handle()
            .load()
            .fakeip
            .as_ref()
            .expect("FakeIP should be enabled")
            .ipv6
            .allocate(v6_domain.clone()),
    )
    .unwrap();
    let mut runtime = block_on(controller.build_tun_proxy_runtime(
        "direct",
        "direct",
        "",
        "",
        std::time::Duration::from_secs(1),
        8,
    ))
    .unwrap();
    let flow = doradus_core::flow::Flow {
        key: doradus_core::flow::FlowKey {
            network: Network::Tcp,
            source: "10.0.0.2:41000".parse().unwrap(),
            destination: std::net::SocketAddr::new(fake_ip.into(), 443),
        },
    };
    block_on(async {
        runtime
            .handle_proxy_input(doradus_tun::ProxyInput::TcpOpened { flow })
            .unwrap();

        let v6_flow = doradus_core::flow::Flow {
            key: doradus_core::flow::FlowKey {
                network: Network::Udp,
                source: "10.0.0.2:41001".parse().unwrap(),
                destination: std::net::SocketAddr::new(v6_fake_ip.into(), 443),
            },
        };
        runtime
            .handle_proxy_input(doradus_tun::ProxyInput::UdpDatagram {
                flow: v6_flow,
                payload: vec![0],
            })
            .unwrap();

        let connections = controller.monitor().connections_value();
        let connection = &connections["connections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|connection| connection["fakeIp"] == v6_fake_ip.to_string())
            .expect("IPv6 FakeIP connection should be monitored");
        assert_eq!(connection["domain"], v6_domain.to_string());
        assert_eq!(connection["fakeIp"], v6_fake_ip.to_string());
        let connection = &connections["connections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|connection| connection["fakeIp"] == fake_ip.to_string())
            .expect("IPv4 FakeIP connection should be monitored");
        assert_eq!(connection["domain"], domain.to_string());
        assert_eq!(connection["fakeIp"], fake_ip.to_string());
        assert_eq!(connection["destination"], format!("tcp://{fake_ip}:443"));
        runtime
            .close_graceful(std::time::Duration::from_millis(100))
            .await;
    });
}

#[cfg(feature = "tun")]
#[test]
fn controller_can_install_packet_dns_handler_during_tun_assembly() {
    struct RejectingDns;

    impl doradus_core::dns::AsyncDnsHandler for RejectingDns {
        fn answer<'a>(
            &'a self,
            _packet: &'a [u8],
        ) -> doradus_core::BoxFuture<'a, doradus_core::Result<Vec<u8>>> {
            Box::pin(async {
                Err(doradus_core::Error::new(
                    doradus_core::ErrorKind::Closed,
                    "controller DNS handler fixture",
                ))
            })
        }
    }

    let controller = controller();
    block_on(controller.store().repository().put_go_node(&GoNodeRecord {
        id: "proxy".to_owned(),
        name: "proxy".to_owned(),
        group_name: "default".to_owned(),
        origin: "test".to_owned(),
        enabled: true,
        chain_types_json: br#"["direct"]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    }))
    .unwrap();
    block_on(controller.reload()).unwrap();

    let runtime = block_on(controller.build_tun_proxy_runtime_with_dns(
        "",
        "proxy",
        "",
        "",
        std::time::Duration::from_secs(1),
        8,
        Some(Arc::new(RejectingDns)),
    ))
    .unwrap();
    assert_eq!(runtime.task_len(), 0);
}
