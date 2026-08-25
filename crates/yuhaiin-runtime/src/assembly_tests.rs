use super::*;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use yuhaiin_core::dns_resolver::SystemAsyncIpResolver;
use yuhaiin_core::{BoxFuture, DomainName, IpSet, ResolveStrategy};
use yuhaiin_store::{GoRouteListRecord, GoUdpProxyFqdnStrategy};
use yuhaiin_trie::router::Router;

fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

#[test]
fn system_hosts_parser_handles_comments_aliases_and_invalid_rows() {
    let entries = parse_system_hosts(
        "# comment\n192.0.2.10 example.test alias.example.test # trailing\n\
         2001:db8::10 v6.example.test\nnot-an-ip ignored.example.test\n",
    );
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].0, "192.0.2.10".parse::<IpAddr>().unwrap());
    assert_eq!(entries[0].1, DomainName::new("example.test").unwrap());
    assert_eq!(entries[1].1, DomainName::new("alias.example.test").unwrap());
    assert_eq!(entries[2].0, "2001:db8::10".parse::<IpAddr>().unwrap());
}

#[test]
fn fakeip_policy_loads_json_lists_with_go_field_names() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    block_on(store.put_config(
        "resolver.fakedns",
        br#"{"enabled":true,"whitelist":["example.com"],"skipCheckList":["*.skip.example.com"]}"#,
    ))
    .unwrap();

    let policy = block_on(load_fakeip_policy(&store, &store.repository())).unwrap();
    assert!(policy.is_whitelisted(&DomainName::new("api.example.com").unwrap()));
    assert!(policy.is_skip_check(&DomainName::new("one.skip.example.com").unwrap()));
    assert!(!policy.is_skip_check(&DomainName::new("deep.two.skip.example.com").unwrap()));
}

#[test]
fn fakeip_json_overlay_controls_runtime_enablement_over_legacy_settings() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    block_on(store.put_config(
        "resolver.fakedns",
        br#"{"enabled":true,"ipv4Range":"198.18.10.0/30","ipv6Range":"fc00:10::/126","whitelist":[],"skipCheckList":[]}"#,
    ))
    .unwrap();

    let snapshot = block_on(
        RuntimeBuilder::new(
            store,
            Arc::new(StaticResolver {
                address: Ipv4Addr::new(192, 0, 2, 55),
            }),
        )
        .build(),
    )
    .unwrap();
    let resolved = block_on(snapshot.resolver.resolve(
        &DomainName::new("overlay.example.com").unwrap(),
        ResolveStrategy::OnlyIpv4,
    ))
    .unwrap();
    assert_eq!(resolved.v4, vec![Ipv4Addr::new(198, 18, 10, 0)]);
}

#[test]
fn configured_hosts_overlay_system_hosts_in_one_snapshot() {
    let system = HostsTable::new();
    let configured = HostsTable::new();
    let domain = DomainName::new("example.test").unwrap();
    system
        .insert_ip(domain.clone(), "192.0.2.10".parse().unwrap())
        .unwrap();
    configured
        .insert_ip(domain.clone(), "192.0.2.20".parse().unwrap())
        .unwrap();
    system.overlay(&configured).unwrap();
    assert_eq!(
        system.resolve(&domain).unwrap().unwrap().v4,
        vec!["192.0.2.20".parse::<std::net::Ipv4Addr>().unwrap()]
    );
}

struct StaticResolver {
    address: Ipv4Addr,
}

impl AsyncIpResolver for StaticResolver {
    fn resolve<'a>(
        &'a self,
        _domain: &'a DomainName,
        _strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        Box::pin(async {
            Ok(IpSet {
                v4: vec![self.address],
                v6: Vec::new(),
            })
        })
    }
}

#[test]
fn builder_publishes_one_shared_resolver_snapshot() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let snapshot = block_on(
        RuntimeBuilder::new(
            store,
            Arc::new(StaticResolver {
                address: Ipv4Addr::new(192, 0, 2, 55),
            }),
        )
        .build(),
    )
    .unwrap();
    let domain = DomainName::new("example.com").unwrap();
    let resolved = block_on(
        snapshot
            .resolver
            .resolve(&domain, ResolveStrategy::OnlyIpv4),
    )
    .unwrap();
    assert_eq!(resolved.v4, vec![Ipv4Addr::new(192, 0, 2, 55)]);
    assert!(snapshot.fakeip.is_none());
    assert!(snapshot.proxies.is_empty());
    assert!(snapshot.resolver_by_id.is_empty());
}

#[test]
fn builder_loads_inbound_settings_from_the_frontend_overlay() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    block_on(store.put_config(
        "inbounds.config",
        br#"{"hijackDns":true,"hijackDnsFakeIp":false,"sniff":false}"#,
    ))
    .unwrap();
    let snapshot =
        block_on(RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver)).build()).unwrap();
    assert_eq!(
        snapshot.inbound_settings,
        yuhaiin_store::InboundSettings {
            hijack_dns: true,
            hijack_dns_fakeip: false,
            sniff: false,
        }
    );
}

struct DualStackResolver;

impl AsyncIpResolver for DualStackResolver {
    fn resolve<'a>(
        &'a self,
        _domain: &'a DomainName,
        _strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        Box::pin(async {
            Ok(IpSet {
                v4: vec![Ipv4Addr::new(192, 0, 2, 55)],
                v6: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 55)],
            })
        })
    }
}

#[test]
fn settings_ipv6_is_published_and_applied_to_the_shared_resolver() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    block_on(store.put_config("settings", br#"{"ipv6":false}"#)).unwrap();
    let snapshot =
        block_on(RuntimeBuilder::new(store.clone(), Arc::new(DualStackResolver)).build()).unwrap();
    assert!(!snapshot.settings.ipv6);
    let domain = DomainName::new("example.com").unwrap();
    let resolved = block_on(snapshot.resolver.resolve(&domain, ResolveStrategy::Default)).unwrap();
    assert_eq!(resolved.v4.len(), 1);
    assert!(resolved.v6.is_empty());

    block_on(store.put_config("settings", br#"{"ipv6":true}"#)).unwrap();
    let snapshot =
        block_on(RuntimeBuilder::new(store, Arc::new(DualStackResolver)).build()).unwrap();
    assert!(snapshot.settings.ipv6);
    assert_eq!(
        block_on(snapshot.resolver.resolve(&domain, ResolveStrategy::Default))
            .unwrap()
            .v6
            .len(),
        1
    );
}

#[test]
fn empty_store_keeps_system_resolver_as_an_explicit_compatible_input() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let builder = RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver));
    let snapshot = block_on(builder.build()).unwrap();
    assert_eq!(snapshot.resolvers.len(), 1);
    assert_eq!(snapshot.resolvers[0].id, "bootstrap");
    assert_eq!(
        snapshot.route.as_ref().unwrap().direct_resolver,
        "bootstrap"
    );
    assert_eq!(snapshot.route_lists.values("LAN").unwrap().len(), 18);
    assert_eq!(snapshot.route_rules.len(), 1);
}

#[test]
fn builder_publishes_route_list_contents_into_the_router_snapshot() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    block_on(
        store.repository().put_go_route_list(&GoRouteListRecord {
            name: "local-domains".to_owned(),
            list_type: "host".to_owned(),
            source_type: "local".to_owned(),
            updated_at: 1,
            data_json: br#"{
            "name":"local-domains",
            "type":"host",
            "source":{"type":"local","local":{"lists":["example.test"]}}
        }"#
            .to_vec(),
        }),
    )
    .unwrap();
    block_on(
        store.repository().put_go_route_rule(&GoRouteRuleRecord {
            id: "list-rule".to_owned(),
            name: "list-rule".to_owned(),
            priority: 1,
            disabled: false,
            action_mode: "proxy".to_owned(),
            match_type: "all".to_owned(),
            tag: "test".to_owned(),
            updated_at: 2,
            data_json: br#"{
            "mode":"proxy",
            "rules":[{"type":"host","host":{"list":"local-domains"}}]
        }"#
            .to_vec(),
        }),
    )
    .unwrap();
    let snapshot =
        block_on(RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver)).build()).unwrap();
    assert_eq!(
        snapshot.route_lists.values("local-domains").unwrap(),
        ["example.test"]
    );
    let endpoint = yuhaiin_core::Endpoint::domain(
        yuhaiin_core::Network::Tcp,
        DomainName::new("www.example.test").unwrap(),
        443,
    );
    assert_eq!(
        snapshot.router.decide(&endpoint).mode,
        yuhaiin_core::RouteMode::Proxy
    );
}

#[test]
fn apply_route_exposes_go_list_membership_to_rejected_nested_matchers() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    for (name, list_type, values) in [
        ("domains", "host", "example.test"),
        ("apps", "process", "/usr/bin/curl"),
    ] {
        block_on(store.repository().put_go_route_list(&GoRouteListRecord {
            name: name.to_owned(),
            list_type: list_type.to_owned(),
            source_type: "local".to_owned(),
            updated_at: 1,
            data_json: format!(
                r#"{{"type":"{list_type}","source":{{"type":"local","local":{{"lists":["{values}"]}}}}}}"#
            )
            .into_bytes(),
        }))
        .unwrap();
    }
    block_on(
        store.repository().put_go_route_rule(&GoRouteRuleRecord {
            id: "process-gated".to_owned(),
            name: "process-gated".to_owned(),
            priority: 1,
            disabled: false,
            action_mode: "direct".to_owned(),
            match_type: "all".to_owned(),
            tag: "test".to_owned(),
            updated_at: 1,
            data_json: br#"{
            "mode":"direct",
            "rules":[{"type":"all","all":[
                {"type":"host","host":{"list":"domains"}},
                {"type":"process","process":{"list":"apps"}}
            ]}]
        }"#
            .to_vec(),
        }),
    )
    .unwrap();
    block_on(
        store.repository().put_go_route_rule(&GoRouteRuleRecord {
            id: "host-fallback".to_owned(),
            name: "host-fallback".to_owned(),
            priority: 2,
            disabled: false,
            action_mode: "proxy".to_owned(),
            match_type: "host".to_owned(),
            tag: "test".to_owned(),
            updated_at: 2,
            data_json: br#"{
            "mode":"proxy",
            "rules":[{"type":"host","host":{"list":"domains"}}]
        }"#
            .to_vec(),
        }),
    )
    .unwrap();

    let snapshot =
        block_on(RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver)).build()).unwrap();
    let mut context = FlowContext::new(yuhaiin_core::Endpoint::domain(
        yuhaiin_core::Network::Tcp,
        DomainName::new("www.example.test").unwrap(),
        443,
    ));
    context.process = Some("/usr/bin/browser".to_owned());

    assert_eq!(snapshot.apply_route(&mut context).mode, RouteMode::Proxy);
    assert_eq!(context.lists, vec!["domains"]);
    let rejected = &context.match_history[0];
    assert_eq!(rejected.rule_name, "process-gated");
    assert!(
        rejected
            .history
            .iter()
            .any(|entry| entry.list_name == "List apps" && !entry.matched)
    );
    assert!(
        !rejected
            .history
            .iter()
            .any(|entry| entry.list_name == "List domains")
    );
}

#[test]
fn runtime_snapshot_loads_full_cone_nat_timeout_for_tun_assembly() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    block_on(store.repository().put_nat_config(&NatConfigRecord {
        key: "default".to_owned(),
        full_cone: true,
        idle_timeout_ms: 45_000,
    }))
    .unwrap();

    let snapshot =
        block_on(RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver)).build()).unwrap();
    assert!(snapshot.nat.full_cone);
    assert_eq!(snapshot.nat.idle_timeout_ms, 45_000);
    let (_table, timeout) = snapshot.new_full_cone_nat().unwrap();
    assert_eq!(timeout, Duration::from_secs(45));

    let mut restricted = snapshot.clone();
    restricted.nat.full_cone = false;
    assert!(restricted.new_full_cone_nat().is_err());
}

#[test]
fn builtin_resolver_factory_publishes_a_resolver_registry() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let snapshot = block_on(
        RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver))
            .with_resolver_factory(Arc::new(BuiltinResolverFactory::new(
                Duration::from_secs(1),
                8,
            )))
            .build(),
    )
    .unwrap();
    assert_eq!(snapshot.resolver_by_id.len(), 1);
    assert!(snapshot.resolver_by_id.contains_key("bootstrap"));
    assert_eq!(snapshot.dns_resolver_by_id.len(), 1);
    assert!(snapshot.dns_resolver_by_id.contains_key("bootstrap"));
}

#[test]
fn route_settings_select_resolver_from_the_same_snapshot() {
    let main = Arc::new(StaticResolver {
        address: Ipv4Addr::new(192, 0, 2, 1),
    }) as Arc<dyn AsyncIpResolver>;
    let direct = Arc::new(StaticResolver {
        address: Ipv4Addr::new(192, 0, 2, 2),
    }) as Arc<dyn AsyncIpResolver>;
    let proxy = Arc::new(StaticResolver {
        address: Ipv4Addr::new(192, 0, 2, 3),
    }) as Arc<dyn AsyncIpResolver>;
    let mut resolver_by_id = BTreeMap::new();
    resolver_by_id.insert("direct".to_owned(), direct);
    resolver_by_id.insert("proxy".to_owned(), proxy);
    let mut dns_resolver_by_id = BTreeMap::new();
    dns_resolver_by_id.insert(
        "direct".to_owned(),
        Arc::new(StaticResolver {
            address: Ipv4Addr::new(192, 0, 2, 12),
        }) as Arc<dyn AsyncIpResolver>,
    );
    dns_resolver_by_id.insert(
        "proxy".to_owned(),
        Arc::new(StaticResolver {
            address: Ipv4Addr::new(192, 0, 2, 13),
        }) as Arc<dyn AsyncIpResolver>,
    );
    let router = RouterRuntime::new(
        Router::compile(
            Vec::new(),
            RouteDecision {
                mode: RouteMode::Proxy,
                resolver_policy: ResolverPolicy::default(),
                priority: 0,
            },
        )
        .unwrap(),
    );
    let snapshot = RuntimeSnapshot {
        settings: RuntimeSettings::default(),
        connect_semaphore: Arc::new(Semaphore::new(250)),
        socket_bind_addresses: Arc::from(Vec::<IpAddr>::new().into_boxed_slice()),
        socket_bind_interface: None,
        resolver: main,
        inbound_resolver: Arc::new(SystemAsyncIpResolver),
        dns_resolver: Arc::new(SystemAsyncIpResolver),
        hosts: HostsTable::new(),
        fakeip: None,
        inbound_fakeip: None,
        inbound_settings: yuhaiin_store::InboundSettings::default(),
        resolvers: Vec::new(),
        route: Some(GoRouteRuntimeConfig {
            direct_resolver: "direct".to_owned(),
            proxy_resolver: "proxy".to_owned(),
            resolve_locally: true,
            udp_proxy_fqdn: GoUdpProxyFqdnStrategy::Resolve,
        }),
        route_rules: Vec::new(),
        node_tags: Vec::new(),
        route_lists: Arc::new(RouteListSnapshot::default()),
        router,
        resolver_by_id,
        inbound_resolver_by_id: BTreeMap::new(),
        dns_resolver_by_id,
        resolver_errors: BTreeMap::new(),
        resolver_registry_enabled: true,
        geo_metadata: Vec::new(),
        geo: None,
        proxies: Vec::new(),
        nat: NatConfigRecord::default(),
    };
    let domain = DomainName::new("example.com").unwrap();
    let mut context = FlowContext::new(yuhaiin_core::Endpoint::domain(
        yuhaiin_core::Network::Tcp,
        domain.clone(),
        443,
    ));
    let resolver = snapshot
        .apply_route_and_select_resolver(&mut context)
        .unwrap();
    assert_eq!(context.route_mode, RouteMode::Proxy);
    assert_eq!(
        block_on(resolver.resolve(&domain, ResolveStrategy::OnlyIpv4))
            .unwrap()
            .v4,
        vec![Ipv4Addr::new(192, 0, 2, 3)]
    );
    assert_eq!(
        block_on(
            snapshot
                .resolver_for_route_mode(RouteMode::Direct)
                .unwrap()
                .resolve(&domain, ResolveStrategy::OnlyIpv4,)
        )
        .unwrap()
        .v4,
        vec![Ipv4Addr::new(192, 0, 2, 2)]
    );
    assert_eq!(
        block_on(
            snapshot
                .dns_resolver_for_route_mode(RouteMode::Proxy)
                .unwrap()
                .resolve(&domain, ResolveStrategy::OnlyIpv4,)
        )
        .unwrap()
        .v4,
        vec![Ipv4Addr::new(192, 0, 2, 13)]
    );
}

#[test]
fn rebuilding_store_publishes_new_route_snapshot_without_mutating_old_flows() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let repository = store.repository();
    let mut record = GoRouteRuleRecord {
        id: "reload-rule".to_owned(),
        name: "reload-rule".to_owned(),
        priority: 10,
        disabled: false,
        action_mode: "direct".to_owned(),
        match_type: "domain".to_owned(),
        tag: "test".to_owned(),
        updated_at: 1,
        data_json: br#"{"match":{"domain":"example.com"},"mode":"direct"}"#.to_vec(),
    };
    block_on(repository.put_go_route_rule(&record)).unwrap();
    let first = block_on(
        RuntimeBuilder::new(
            store.clone(),
            Arc::new(StaticResolver {
                address: Ipv4Addr::new(192, 0, 2, 55),
            }),
        )
        .build(),
    )
    .unwrap();

    record.action_mode = "proxy".to_owned();
    record.updated_at = 2;
    record.data_json = br#"{"match":{"domain":"example.com"},"mode":"proxy"}"#.to_vec();
    block_on(repository.put_go_route_rule(&record)).unwrap();
    let second = block_on(
        RuntimeBuilder::new(
            store,
            Arc::new(StaticResolver {
                address: Ipv4Addr::new(192, 0, 2, 55),
            }),
        )
        .build(),
    )
    .unwrap();

    let endpoint = yuhaiin_core::Endpoint::domain(
        yuhaiin_core::Network::Tcp,
        DomainName::new("example.com").unwrap(),
        443,
    );
    let mut old_context = FlowContext::new(endpoint.clone());
    let mut new_context = FlowContext::new(endpoint);
    assert_eq!(first.apply_route(&mut old_context).mode, RouteMode::Direct);
    assert_eq!(second.apply_route(&mut new_context).mode, RouteMode::Proxy);
}

#[test]
fn route_settings_repository_rows_are_loaded_by_runtime_reload() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    block_on(
        store
            .repository()
            .put_go_route_settings(&yuhaiin_store::GoRouteSettingsRecord {
                id: 1,
                direct_resolver: "direct".to_owned(),
                proxy_resolver: "proxy".to_owned(),
                resolve_locally: true,
                udp_proxy_fqdn: 2,
            }),
    )
    .unwrap();
    let snapshot = block_on(
        RuntimeBuilder::new(
            store,
            Arc::new(StaticResolver {
                address: Ipv4Addr::new(192, 0, 2, 55),
            }),
        )
        .build(),
    )
    .unwrap();
    let route = snapshot.route.unwrap();
    assert_eq!(route.direct_resolver, "direct");
    assert_eq!(route.proxy_resolver, "proxy");
    assert!(route.resolve_locally);
    assert_eq!(route.udp_proxy_fqdn, GoUdpProxyFqdnStrategy::SkipResolve);
}
