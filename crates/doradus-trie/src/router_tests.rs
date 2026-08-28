//! Route router tests.

use super::*;
use doradus_core::{DomainName, ResolveStrategy, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

struct StaticGeo {
    code: Option<&'static str>,
}

impl GeoLookup for StaticGeo {
    fn country_code(&self, _address: IpAddr) -> Result<Option<String>> {
        Ok(self.code.map(str::to_owned))
    }
}

fn rule(pattern: &str, action: RuleAction, priority: i32) -> RouteRule {
    RouteRule {
        rule_name: String::new(),
        tag: String::new(),
        list_names: Vec::new(),
        pattern: pattern.to_owned(),
        host_lists: Vec::new(),
        required_patterns: Vec::new(),
        always_false: false,
        action,
        network: None,
        excluded_networks: Vec::new(),
        port: None,
        excluded_ports: Vec::new(),
        geo_country: None,
        excluded_geo_countries: Vec::new(),
        inbound_names: Vec::new(),
        excluded_inbound_names: Vec::new(),
        process_names: Vec::new(),
        excluded_process_names: Vec::new(),
        excluded_patterns: HostTrie::new(),
        excluded_host_lists: Vec::new(),
        resolver_policy: ResolverPolicy {
            strategy: ResolveStrategy::Default,
            use_fake_ip: action == RuleAction::Proxy,
            ..ResolverPolicy::default()
        },
        priority,
    }
}

#[test]
fn router_prefers_lower_priority_matching_rule() {
    let router = Router::compile(
        vec![
            rule("*.example.com", RuleAction::Direct, 1),
            rule("*.example.com", RuleAction::Proxy, 2),
        ],
        RouteDecision {
            mode: RouteMode::Block,
            resolver_policy: ResolverPolicy::default(),
            priority: -1,
        },
    )
    .unwrap();
    let endpoint = Endpoint::domain(
        Network::Tcp,
        DomainName::new("www.example.com").unwrap(),
        443,
    );
    let decision = router.decide(&endpoint);
    assert_eq!(decision.mode, RouteMode::Direct);
    assert!(!decision.resolver_policy.use_fake_ip);
}

#[test]
fn route_metadata_follows_the_selected_rule_and_geo_snapshot() {
    let mut selected = rule("198.51.100.0/24", RuleAction::Proxy, 10);
    selected.rule_name = "media-rule".to_owned();
    selected.tag = "streaming".to_owned();
    selected.list_names = vec!["media-hosts".to_owned(), "media-hosts".to_owned()];
    let router = Router::compile(
        vec![selected],
        RouteDecision {
            mode: RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 100,
        },
    )
    .unwrap()
    .with_geo_lookup(Arc::new(StaticGeo { code: Some("CN") }));
    let mut context = FlowContext::new(Endpoint::ip(
        Network::Tcp,
        "198.51.100.7:443".parse().unwrap(),
    ));
    context.lists = vec!["media-hosts".to_owned()];

    router.apply_to_context(&mut context);

    assert_eq!(context.route_mode, RouteMode::Proxy);
    assert_eq!(context.tag.as_deref(), Some("streaming"));
    assert_eq!(context.lists, vec!["media-hosts"]);
    assert_eq!(context.geo.as_deref(), Some("CN"));
    assert_eq!(context.match_history.len(), 1);
    assert_eq!(context.match_history[0].rule_name, "media-rule");
    assert_eq!(
        context.match_history[0].history[0].list_name,
        "List media-hosts"
    );
    assert!(context.match_history[0].history[0].matched);
}

#[test]
fn route_match_history_keeps_rejected_rules_before_the_selected_rule() {
    let mut rejected = rule("not-example.com", RuleAction::Direct, 1);
    rejected.rule_name = "rejected-rule".to_owned();
    rejected.list_names = vec!["not-example".to_owned()];
    let mut selected = rule("*.example.com", RuleAction::Proxy, 2);
    selected.rule_name = "selected-rule".to_owned();
    selected.list_names = vec!["example".to_owned()];
    let router = Router::compile(
        vec![rejected, selected],
        RouteDecision {
            mode: RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 100,
        },
    )
    .unwrap();
    let mut context = FlowContext::new(Endpoint::domain(
        Network::Tcp,
        DomainName::new("www.example.com").unwrap(),
        443,
    ));
    context.lists = vec!["example".to_owned()];
    router.apply_to_context(&mut context);

    assert_eq!(context.match_history.len(), 2);
    assert_eq!(context.match_history[0].rule_name, "rejected-rule");
    assert_eq!(
        context.match_history[0].history[0],
        MatchResult {
            list_name: "List not-example".to_owned(),
            matched: false,
        }
    );
    assert_eq!(context.match_history[1].rule_name, "selected-rule");
    assert!(context.match_history[1].history[0].matched);
}

#[test]
fn route_match_history_keeps_list_match_when_a_later_process_match_rejects_rule() {
    let mut rejected = rule("*.example.com", RuleAction::Direct, 1);
    rejected.rule_name = "process-rejected".to_owned();
    rejected.list_names = vec!["shared-hosts".to_owned()];
    rejected.process_names = vec!["curl".to_owned()];
    let mut selected = rule("*.example.com", RuleAction::Proxy, 2);
    selected.rule_name = "fallback-rule".to_owned();
    selected.list_names = vec!["selected-hosts".to_owned()];
    let router = Router::compile(
        vec![rejected, selected],
        RouteDecision {
            mode: RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 100,
        },
    )
    .unwrap();
    let mut context = FlowContext::new(Endpoint::domain(
        Network::Tcp,
        DomainName::new("www.example.com").unwrap(),
        443,
    ));
    context.process = Some("browser".to_owned());
    context.lists = vec!["shared-hosts".to_owned(), "selected-hosts".to_owned()];

    router.apply_to_context(&mut context);

    assert_eq!(context.match_history.len(), 2);
    assert_eq!(context.match_history[0].rule_name, "process-rejected");
    assert_eq!(
        context.match_history[0].history[0].list_name,
        "List shared-hosts"
    );
    assert!(context.match_history[0].history[0].matched);
    assert_eq!(context.match_history[1].rule_name, "fallback-rule");
    assert!(context.match_history[1].history[0].matched);
}

#[test]
fn runtime_selected_rule_name_ignores_last_rejected_rule_on_fallback() {
    let mut rejected = rule("example.com", RuleAction::Direct, 1);
    rejected.rule_name = "rejected-rule".to_owned();
    let router = RouterRuntime::new(
        Router::compile(
            vec![rejected],
            RouteDecision {
                mode: RouteMode::Proxy,
                resolver_policy: ResolverPolicy::default(),
                priority: 100,
            },
        )
        .unwrap(),
    );
    let mut context = FlowContext::new(Endpoint::domain(
        Network::Tcp,
        DomainName::new("other.example").unwrap(),
        443,
    ));

    assert_eq!(router.apply_to_context(&mut context).mode, RouteMode::Proxy);
    assert_eq!(context.match_history.len(), 1);
    assert!(router.selected_rule_name(&context).is_none());
}

#[test]
fn router_filters_network_and_port() {
    let mut udp_rule = rule("192.0.2.0/24", RuleAction::Proxy, 10);
    udp_rule.network = Some(Network::Udp);
    udp_rule.port = Some((53, 53));
    let router = Router::compile(
        vec![udp_rule],
        RouteDecision {
            mode: RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 0,
        },
    )
    .unwrap();
    let endpoint = Endpoint::ip(Network::Udp, SocketAddr::from(([192, 0, 2, 1], 53)));
    assert_eq!(router.decide(&endpoint).mode, RouteMode::Proxy);
    let other = Endpoint::ip(Network::Tcp, SocketAddr::from(([192, 0, 2, 1], 53)));
    assert_eq!(router.decide(&other).mode, RouteMode::Direct);
}

#[test]
fn router_applies_negative_pattern_network_port_and_context_constraints() {
    let mut negative = rule("", RuleAction::Proxy, 10);
    negative
        .excluded_patterns
        .insert("*.blocked.example", ())
        .unwrap();
    negative.excluded_networks.push(Network::Udp);
    negative.excluded_ports.push((80, 80));
    negative.excluded_inbound_names.push("http-main".to_owned());
    negative.excluded_process_names.push("browser".to_owned());
    let router = Router::compile(
        vec![negative],
        RouteDecision {
            mode: RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 0,
        },
    )
    .unwrap();
    let allowed = Endpoint::domain(
        Network::Tcp,
        DomainName::new("allowed.example").unwrap(),
        443,
    );
    let blocked_domain = Endpoint::domain(
        Network::Tcp,
        DomainName::new("www.blocked.example").unwrap(),
        443,
    );
    assert_eq!(router.decide(&allowed).mode, RouteMode::Proxy);
    assert_eq!(router.decide(&blocked_domain).mode, RouteMode::Direct);

    let udp = Endpoint::ip(Network::Udp, "192.0.2.1:443".parse().unwrap());
    let port = Endpoint::ip(Network::Tcp, "192.0.2.1:80".parse().unwrap());
    assert_eq!(router.decide(&udp).mode, RouteMode::Direct);
    assert_eq!(router.decide(&port).mode, RouteMode::Direct);

    let mut context = FlowContext::new(allowed.clone());
    context.inbound_name = Some("http-main".to_owned());
    assert_eq!(router.decide_context(&context).mode, RouteMode::Direct);
    context.inbound_name = Some("socks-main".to_owned());
    context.process = Some("browser".to_owned());
    assert_eq!(router.decide_context(&context).mode, RouteMode::Direct);
}

#[test]
fn geo_country_rule_changes_ip_route_dispatch() {
    let mut geo_rule = rule("198.51.100.0/24", RuleAction::Proxy, 20);
    geo_rule.geo_country = Some("cn".to_owned());
    let router = Router::compile(
        vec![geo_rule],
        RouteDecision {
            mode: RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 0,
        },
    )
    .unwrap()
    .with_geo_lookup(Arc::new(StaticGeo { code: Some("CN") }));
    let endpoint = Endpoint::ip(Network::Tcp, "198.51.100.7:443".parse().unwrap());
    assert_eq!(router.decide(&endpoint).mode, RouteMode::Proxy);
}

#[test]
fn geo_country_rule_falls_back_without_a_match_or_database() {
    let mut geo_rule = rule("198.51.100.0/24", RuleAction::Proxy, 20);
    geo_rule.geo_country = Some("CN".to_owned());
    let fallback = RouteDecision {
        mode: RouteMode::Direct,
        resolver_policy: ResolverPolicy::default(),
        priority: 0,
    };
    let without_db = Router::compile(vec![geo_rule.clone()], fallback.clone()).unwrap();
    let endpoint = Endpoint::ip(Network::Tcp, "198.51.100.7:443".parse().unwrap());
    assert_eq!(without_db.decide(&endpoint), fallback);

    let wrong_country = Router::compile(vec![geo_rule], fallback.clone())
        .unwrap()
        .with_geo_lookup(Arc::new(StaticGeo { code: Some("US") }));
    assert_eq!(wrong_country.decide(&endpoint), fallback);
}

#[test]
fn fakeip_context_routes_using_the_restored_domain() {
    let mut cidr = rule("198.18.0.0/15", RuleAction::Proxy, 10);
    cidr.network = Some(Network::Udp);
    cidr.port = Some((443, 443));
    let mut domain = rule("example.com", RuleAction::Direct, 20);
    domain.network = Some(Network::Udp);
    domain.port = Some((443, 443));
    let router = Router::compile(
        vec![cidr, domain],
        RouteDecision {
            mode: RouteMode::Block,
            resolver_policy: ResolverPolicy::default(),
            priority: 0,
        },
    )
    .unwrap();
    let mut context = doradus_core::FlowContext::new(Endpoint::ip(
        Network::Udp,
        "198.18.0.1:443".parse().unwrap(),
    ));
    context.original_domain = Some(DomainName::new("example.com").unwrap());
    assert_eq!(router.decide_context(&context).mode, RouteMode::Direct);
}

#[test]
fn fakeip_context_uses_proxy_fallback_when_only_virtual_cidr_matches() {
    let mut cidr = rule("198.18.0.0/15", RuleAction::Direct, 10);
    cidr.network = Some(Network::Udp);
    cidr.port = Some((443, 443));
    let router = Router::compile(
        vec![cidr],
        RouteDecision {
            mode: RouteMode::Proxy,
            resolver_policy: ResolverPolicy::default(),
            priority: 0,
        },
    )
    .unwrap();
    let mut context = doradus_core::FlowContext::new(Endpoint::ip(
        Network::Udp,
        "198.18.0.1:443".parse().unwrap(),
    ));
    context.original_domain = Some(DomainName::new("example.com").unwrap());
    assert_eq!(router.decide_context(&context).mode, RouteMode::Proxy);
}

#[test]
fn runtime_publishes_and_rolls_back_immutable_snapshots() {
    let fallback = RouteDecision {
        mode: RouteMode::Direct,
        resolver_policy: ResolverPolicy::default(),
        priority: 0,
    };
    let first = Router::compile(vec![], fallback.clone()).unwrap();
    let runtime = RouterRuntime::new(first);
    let endpoint = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
    assert_eq!(runtime.decide(&endpoint).mode, RouteMode::Direct);

    let previous = runtime
        .compile_and_publish(vec![rule("example.com", RuleAction::Proxy, 10)], fallback)
        .unwrap();
    assert_eq!(runtime.decide(&endpoint).mode, RouteMode::Proxy);
    runtime.rollback(previous);
    assert_eq!(runtime.decide(&endpoint).mode, RouteMode::Direct);
}

#[test]
fn failed_publish_keeps_the_previous_snapshot() {
    let fallback = RouteDecision {
        mode: RouteMode::Direct,
        resolver_policy: ResolverPolicy::default(),
        priority: 0,
    };
    let runtime = RouterRuntime::new(
        Router::compile(
            vec![rule("example.com", RuleAction::Proxy, 10)],
            fallback.clone(),
        )
        .unwrap(),
    );
    let endpoint = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
    assert_eq!(runtime.decide(&endpoint).mode, RouteMode::Proxy);

    let mut invalid = rule("bad..example.com", RuleAction::Direct, 20);
    invalid.network = Some(Network::Tcp);
    assert!(
        runtime
            .compile_and_publish(vec![invalid], fallback)
            .is_err()
    );
    assert_eq!(runtime.decide(&endpoint).mode, RouteMode::Proxy);
}

#[test]
fn hot_publish_can_replace_the_geo_reader_with_the_route_snapshot() {
    let fallback = RouteDecision {
        mode: RouteMode::Direct,
        resolver_policy: ResolverPolicy::default(),
        priority: 0,
    };
    let mut geo_rule = rule("198.51.100.0/24", RuleAction::Proxy, 10);
    geo_rule.geo_country = Some("CN".to_owned());
    let endpoint = Endpoint::ip(Network::Tcp, "198.51.100.7:443".parse().unwrap());
    let runtime = RouterRuntime::new(Router::compile(Vec::new(), fallback.clone()).unwrap());

    runtime
        .compile_and_publish_with_geo(
            vec![geo_rule.clone()],
            fallback.clone(),
            Arc::new(StaticGeo { code: Some("CN") }),
        )
        .unwrap();
    assert_eq!(runtime.decide(&endpoint).mode, RouteMode::Proxy);

    runtime
        .compile_and_publish_with_geo(
            vec![geo_rule],
            fallback,
            Arc::new(StaticGeo { code: Some("US") }),
        )
        .unwrap();
    assert_eq!(runtime.decide(&endpoint).mode, RouteMode::Direct);
}

#[test]
fn runtime_applies_resolver_policy_with_route_decision() {
    let rule = rule("example.com", RuleAction::Proxy, 10);
    let runtime = RouterRuntime::new(
        Router::compile(
            vec![rule],
            RouteDecision {
                mode: RouteMode::Direct,
                resolver_policy: ResolverPolicy::default(),
                priority: 0,
            },
        )
        .unwrap(),
    );
    let mut context = doradus_core::FlowContext::new(Endpoint::domain(
        Network::Udp,
        DomainName::new("example.com").unwrap(),
        53,
    ));
    let decision = runtime.apply_to_context(&mut context);
    assert_eq!(decision.mode, RouteMode::Proxy);
    assert_eq!(context.route_mode, RouteMode::Proxy);
    assert!(context.resolver_policy.use_fake_ip);
}

#[test]
fn runtime_hot_publish_keeps_readers_on_whole_snapshots() {
    let fallback = RouteDecision {
        mode: RouteMode::Direct,
        resolver_policy: ResolverPolicy::default(),
        priority: 0,
    };
    let runtime = RouterRuntime::new(Router::compile(Vec::new(), fallback.clone()).unwrap());
    let endpoint = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);

    std::thread::scope(|scope| {
        for _ in 0..8 {
            let runtime = runtime.clone();
            let endpoint = endpoint.clone();
            scope.spawn(move || {
                for _ in 0..50_000 {
                    let decision = runtime.decide(&endpoint);
                    assert_eq!(
                        decision.resolver_policy.use_fake_ip,
                        decision.mode == RouteMode::Proxy
                    );
                }
            });
        }
        for index in 0..50_000 {
            let action = if index % 2 == 0 {
                RuleAction::Proxy
            } else {
                RuleAction::Direct
            };
            runtime
                .compile_and_publish(vec![rule("example.com", action, 10)], fallback.clone())
                .unwrap();
        }
    });
    let snapshot = runtime.snapshot();
    let decision = snapshot.decide(&endpoint);
    assert!(decision.mode == RouteMode::Proxy || decision.mode == RouteMode::Direct);
}

#[test]
fn routed_proxy_selector_uses_snapshot_and_honors_skip_route() {
    use doradus_core::FlowContext;
    use doradus_core::proxy::AsyncProxySelector;
    use doradus_protocol::proxy::DropAsyncProxy;
    use std::sync::Arc;

    let router = Arc::new(
        Router::compile(
            vec![rule("example.com", RuleAction::Direct, 10)],
            RouteDecision {
                mode: RouteMode::Proxy,
                resolver_policy: ResolverPolicy::default(),
                priority: 0,
            },
        )
        .unwrap(),
    );
    let direct: Arc<dyn doradus_core::proxy::AsyncProxy> = Arc::new(DropAsyncProxy);
    let proxy: Arc<dyn doradus_core::proxy::AsyncProxy> = Arc::new(DropAsyncProxy);
    let bypass: Arc<dyn doradus_core::proxy::AsyncProxy> = Arc::new(DropAsyncProxy);
    let drop: Arc<dyn doradus_core::proxy::AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = RoutedProxySelector {
        router,
        direct: Arc::clone(&direct),
        proxy: Arc::clone(&proxy),
        bypass: Arc::clone(&bypass),
        drop: Arc::clone(&drop),
    };

    let domain = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
    let selected = selector.select(&FlowContext::new(domain));
    assert!(Arc::ptr_eq(&selected, &direct));

    let mut skipped =
        FlowContext::new(Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap()));
    skipped.route_mode = RouteMode::Bypass;
    skipped.skip_route = true;
    let selected = selector.select(&skipped);
    assert!(Arc::ptr_eq(&selected, &bypass));
}

#[test]
fn runtime_routed_proxy_selector_observes_new_snapshots_without_retargeting_old_flows() {
    use doradus_core::FlowContext;
    use doradus_core::proxy::AsyncProxySelector;
    use doradus_protocol::proxy::DropAsyncProxy;

    let fallback = RouteDecision {
        mode: RouteMode::Direct,
        resolver_policy: ResolverPolicy::default(),
        priority: 0,
    };
    let runtime = RouterRuntime::new(Router::compile(Vec::new(), fallback.clone()).unwrap());
    let direct: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let bypass: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let drop: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = RuntimeRoutedProxySelector {
        router: runtime.clone(),
        direct: Arc::clone(&direct),
        proxy: Arc::clone(&proxy),
        bypass: Arc::clone(&bypass),
        drop: Arc::clone(&drop),
    };
    let endpoint = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
    let old_snapshot = runtime.snapshot();
    let old_flow = FlowContext::new(endpoint.clone());
    assert!(Arc::ptr_eq(&selector.select(&old_flow), &direct));

    runtime
        .compile_and_publish(vec![rule("example.com", RuleAction::Proxy, 10)], fallback)
        .unwrap();
    assert!(Arc::ptr_eq(
        &selector.select(&FlowContext::new(endpoint.clone())),
        &proxy
    ));
    assert_eq!(old_snapshot.decide(&endpoint).mode, RouteMode::Direct);

    let mut skipped = FlowContext::new(endpoint);
    skipped.skip_route = true;
    skipped.route_mode = RouteMode::Bypass;
    assert!(Arc::ptr_eq(&selector.select(&skipped), &bypass));
}

#[test]
fn runtime_selector_keeps_old_flow_and_selects_whole_snapshots_under_pressure() {
    use doradus_core::FlowContext;
    use doradus_core::proxy::AsyncProxySelector;
    use doradus_protocol::proxy::DropAsyncProxy;

    let fallback = RouteDecision {
        mode: RouteMode::Direct,
        resolver_policy: ResolverPolicy::default(),
        priority: 0,
    };
    let runtime = RouterRuntime::new(Router::compile(Vec::new(), fallback.clone()).unwrap());
    let direct: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let proxy: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let bypass: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let drop: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = Arc::new(RuntimeRoutedProxySelector {
        router: runtime.clone(),
        direct: Arc::clone(&direct),
        proxy: Arc::clone(&proxy),
        bypass: Arc::clone(&bypass),
        drop: Arc::clone(&drop),
    });
    let endpoint = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
    let old_flow_proxy = selector.select(&FlowContext::new(endpoint.clone()));
    assert!(Arc::ptr_eq(&old_flow_proxy, &direct));

    std::thread::scope(|scope| {
        for _ in 0..8 {
            let selector = Arc::clone(&selector);
            let direct = Arc::clone(&direct);
            let proxy = Arc::clone(&proxy);
            let endpoint = endpoint.clone();
            scope.spawn(move || {
                for _ in 0..50_000 {
                    let selected = selector.select(&FlowContext::new(endpoint.clone()));
                    assert!(
                        Arc::ptr_eq(&selected, &direct) || Arc::ptr_eq(&selected, &proxy),
                        "selector returned a proxy not belonging to its published snapshot"
                    );
                }
            });
        }
        for index in 0..50_000 {
            let action = if index % 2 == 0 {
                RuleAction::Proxy
            } else {
                RuleAction::Direct
            };
            runtime
                .compile_and_publish(vec![rule("example.com", action, 10)], fallback.clone())
                .unwrap();
        }
    });

    // Selection is per-flow.  Publishing a new snapshot must not mutate
    // the proxy/session that an old flow already retained.
    assert!(Arc::ptr_eq(&old_flow_proxy, &direct));
}
