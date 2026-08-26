use super::*;
use std::sync::Arc;
use yuhaiin_core::dns_resolver::SystemAsyncIpResolver;
use yuhaiin_core::{Endpoint, Network};
use yuhaiin_protocol::proxy::FixedAsyncProxy;
use yuhaiin_store::GoRouteListRecord;

fn record(json: &str, mode: &str, match_type: &str) -> GoRouteRuleRecord {
    GoRouteRuleRecord {
        id: "rule-1".to_owned(),
        name: "rule-1".to_owned(),
        priority: 10,
        disabled: false,
        action_mode: mode.to_owned(),
        match_type: match_type.to_owned(),
        tag: String::new(),
        updated_at: 0,
        data_json: json.as_bytes().to_vec(),
    }
}

#[test]
fn production_domain_shape_compiles_to_router() {
    let rule = route_rule_from_go_record(&record(
        r#"{"name":"production-domain","match":{"domain":"example.com"},"mode":"proxy"}"#,
        "proxy",
        "domain",
    ))
    .unwrap()
    .unwrap();
    assert_eq!(rule.pattern, "example.com");
    assert_eq!(rule.action, RuleAction::Proxy);
    assert!(rule.resolver_policy.use_fake_ip);
    let router = Router::compile(
        vec![rule],
        RouteDecision {
            mode: yuhaiin_core::RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 0,
        },
    )
    .unwrap();
    let endpoint = Endpoint::domain(
        Network::Tcp,
        yuhaiin_core::DomainName::new("example.com").unwrap(),
        443,
    );
    assert_eq!(
        router.decide(&endpoint).mode,
        yuhaiin_core::RouteMode::Proxy
    );
}

#[test]
fn process_and_inbound_matchers_use_flow_context_metadata() {
    let lists = load_route_lists(&[GoRouteListRecord {
        name: "apps".to_owned(),
        list_type: "process".to_owned(),
        source_type: "local".to_owned(),
        updated_at: 0,
        data_json: br#"{
                "type":"process",
                "source":{"type":"local","local":{"lists":["/usr/bin/example-app"]}}
            }"#
        .to_vec(),
    }]);
    let rule = record(
        r#"{
                "mode":"proxy",
                "rules":[{"type":"all","all":[
                    {"type":"process","process":{"list":"apps"}},
                    {"type":"inbound","inbound":{"names":["socks-main"]}},
                    {"type":"network","network":{"network":"tcp"}}
                ]}]
            }"#,
        "proxy",
        "all",
    );
    let router = compile_go_route_rules_with_lists(
        &[rule],
        &lists,
        RouteDecision {
            mode: yuhaiin_core::RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 100,
        },
        None,
    )
    .unwrap();
    let mut context = yuhaiin_core::FlowContext::new(Endpoint::ip(
        Network::Tcp,
        "192.0.2.10:443".parse().unwrap(),
    ));
    context.inbound_name = Some("socks-main".to_owned());
    context.process = Some("/usr/bin/example-app".to_owned());
    assert_eq!(
        router.snapshot().decide_context(&context).mode,
        yuhaiin_core::RouteMode::Proxy
    );

    context.process = Some("/usr/bin/other-app".to_owned());
    assert_eq!(
        router.snapshot().decide_context(&context).mode,
        yuhaiin_core::RouteMode::Direct
    );
    context.process = Some("/usr/bin/example-app".to_owned());
    context.inbound_name = Some("http-main".to_owned());
    assert_eq!(
        router.snapshot().decide_context(&context).mode,
        yuhaiin_core::RouteMode::Direct
    );
}

#[test]
fn all_matcher_requires_every_positive_host_constraint() {
    let lists = load_route_lists(&[
        GoRouteListRecord {
            name: "parents".to_owned(),
            list_type: "host".to_owned(),
            source_type: "local".to_owned(),
            updated_at: 0,
            data_json: br#"{
                    "type":"host",
                    "source":{"type":"local","local":{"lists":["*.example.com"]}}
                }"#
            .to_vec(),
        },
        GoRouteListRecord {
            name: "children".to_owned(),
            list_type: "host".to_owned(),
            source_type: "local".to_owned(),
            updated_at: 0,
            data_json: br#"{
                    "type":"host",
                    "source":{"type":"local","local":{"lists":["blocked.example.com"]}}
                }"#
            .to_vec(),
        },
    ]);
    let router = compile_go_route_rules_with_lists(
        &[record(
            r#"{"mode":"proxy","rules":[{"type":"all","all":[
                    {"type":"host","host":{"list":"parents"}},
                    {"type":"host","host":{"list":"children"}}
                ]}]}"#,
            "proxy",
            "all",
        )],
        &lists,
        RouteDecision {
            mode: yuhaiin_core::RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 100,
        },
        None,
    )
    .unwrap();
    let matching = Endpoint::domain(
        Network::Tcp,
        yuhaiin_core::DomainName::new("blocked.example.com").unwrap(),
        443,
    );
    let parent_only = Endpoint::domain(
        Network::Tcp,
        yuhaiin_core::DomainName::new("other.example.com").unwrap(),
        443,
    );
    assert_eq!(
        router.decide(&matching).mode,
        yuhaiin_core::RouteMode::Proxy
    );
    assert_eq!(
        router.decide(&parent_only).mode,
        yuhaiin_core::RouteMode::Direct
    );
}

#[test]
fn disabled_and_cidr_policy_are_supported() {
    let mut disabled = record(
        r#"{"match":{"domain":"disabled.example"}}"#,
        "direct",
        "domain",
    );
    disabled.disabled = true;
    assert!(route_rule_from_go_record(&disabled).unwrap().is_none());

    let rule = route_rule_from_go_record(&record(
            r#"{"match":{"cidr":"192.0.2.0/24","network":"udp","port":"53-853"},"resolveStrategy":"only_ipv4","useFakeIp":false}"#,
            "direct",
            "cidr",
        ))
        .unwrap()
        .unwrap();
    assert_eq!(rule.pattern, "192.0.2.0/24");
    assert_eq!(rule.network, Some(Network::Udp));
    assert_eq!(rule.port, Some((53, 853)));
    assert_eq!(rule.resolver_policy.strategy, ResolveStrategy::OnlyIpv4);
    assert!(!rule.resolver_policy.use_fake_ip);
}

#[test]
fn go_single_port_string_is_a_single_port_range() {
    let router = compile_go_route_rules_with_lists(
        &[record(
            r#"{"mode":"proxy","rules":[{"type":"port","port":{"ports":"6969"}}]}"#,
            "proxy",
            "all",
        )],
        &RouteListSnapshot::default(),
        RouteDecision {
            mode: yuhaiin_core::RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 100,
        },
        None,
    )
    .unwrap();
    let matching = Endpoint::ip(Network::Tcp, "192.0.2.1:6969".parse().unwrap());
    let other = Endpoint::ip(Network::Tcp, "192.0.2.1:6970".parse().unwrap());
    assert_eq!(
        router.decide(&matching).mode,
        yuhaiin_core::RouteMode::Proxy
    );
    assert_eq!(router.decide(&other).mode, yuhaiin_core::RouteMode::Direct);
}

#[test]
fn unsupported_matcher_is_not_silently_dropped() {
    let error = route_rule_from_go_record(&record(
        r#"{"rules":[{"host":{"list":"domains"}}]}"#,
        "proxy",
        "all",
    ))
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Unsupported);
}

#[test]
fn geoip_accepts_go_country_string_and_list_forms() {
    let string_rule = expand_go_route_rule(
        &record(
            r#"{"mode":"proxy","rules":[{"type":"geoip","geoip":{"countries":"CN"}}]}"#,
            "proxy",
            "all",
        ),
        &RouteListSnapshot::default(),
    )
    .unwrap();
    assert_eq!(string_rule[0].geo_country.as_deref(), Some("CN"));

    let list_rule = expand_go_route_rule(
        &record(
            r#"{"mode":"proxy","rules":[{"type":"geoip","geoip":{"countries":["CN","US"]}}]}"#,
            "proxy",
            "all",
        ),
        &RouteListSnapshot::default(),
    )
    .unwrap();
    assert_eq!(
        list_rule
            .iter()
            .map(|rule| rule.geo_country.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("CN"), Some("US")]
    );
}

#[test]
fn local_host_list_keeps_one_router_rule_and_shares_the_index() {
    let list = GoRouteListRecord {
        name: "domains".to_owned(),
        list_type: "host".to_owned(),
        source_type: "local".to_owned(),
        updated_at: 1,
        data_json: br#"{
                "name":"domains",
                "type":"host",
                "source":{"type":"local","local":{"lists":["*.example.com","*.blocked.test"]}}
            }"#
        .to_vec(),
    };
    let lists = load_route_lists(&[list]);
    let expanded = expand_go_route_rule(
        &record(
            r#"{"mode":"proxy","rules":[{"type":"host","host":{"list":"domains"}}]}"#,
            "proxy",
            "all",
        ),
        &lists,
    )
    .unwrap();
    assert_eq!(expanded.len(), 1);
    assert_eq!(expanded[0].list_names, vec!["domains"]);
    assert_eq!(expanded[0].host_lists.len(), 1);
    assert!(lists.host_index("domains").unwrap().is_on_disk());
    let router = compile_go_route_rules_with_lists(
        &[record(
            r#"{"mode":"proxy","rules":[{"type":"host","host":{"list":"domains"}}]}"#,
            "proxy",
            "all",
        )],
        &lists,
        RouteDecision {
            mode: yuhaiin_core::RouteMode::Direct,
            resolver_policy: ResolverPolicy::default(),
            priority: 100,
        },
        None,
    )
    .unwrap();
    let endpoint = Endpoint::domain(
        Network::Tcp,
        yuhaiin_core::DomainName::new("www.example.com").unwrap(),
        443,
    );
    assert_eq!(
        router.decide(&endpoint).mode,
        yuhaiin_core::RouteMode::Proxy
    );
    let wildcard = Endpoint::domain(
        Network::Tcp,
        yuhaiin_core::DomainName::new("api.blocked.test").unwrap(),
        443,
    );
    assert_eq!(
        router.decide(&wildcard).mode,
        yuhaiin_core::RouteMode::Proxy
    );
    assert!(
        lists
            .values("domains")
            .unwrap()
            .contains(&"*.example.com".to_owned())
    );
}

#[test]
fn go_wildcard_host_list_matches_bilibili_base_and_subdomain() {
    let lists = load_route_lists(&[GoRouteListRecord {
        name: "china-domains".to_owned(),
        list_type: "host".to_owned(),
        source_type: "local".to_owned(),
        updated_at: 1,
        data_json: br#"{
                "type":"host",
                "source":{"type":"local","local":{"lists":["*.bilibili.com"]}}
            }"#
        .to_vec(),
    }]);

    for domain in ["bilibili.com", "www.bilibili.com"] {
        let context = FlowContext::new(Endpoint::domain(
            Network::Tcp,
            DomainName::new(domain).unwrap(),
            443,
        ));
        assert_eq!(lists.matching_names(&context), vec!["china-domains"]);
    }
}

#[test]
fn route_list_snapshot_reports_all_go_host_and_process_memberships() {
    let lists = load_route_lists(&[
        GoRouteListRecord {
            name: "domains".to_owned(),
            list_type: "host".to_owned(),
            source_type: "local".to_owned(),
            updated_at: 1,
            data_json: br#"{
                    "type":"host",
                    "source":{"type":"local","local":{"lists":["*.example.com","192.0.2.0/24"]}}
                }"#
            .to_vec(),
        },
        GoRouteListRecord {
            name: "apps".to_owned(),
            list_type: "process".to_owned(),
            source_type: "local".to_owned(),
            updated_at: 1,
            data_json: br#"{
                    "type":"process",
                    "source":{"type":"local","local":{"lists":["/usr/bin/example-app"]}}
                }"#
            .to_vec(),
        },
    ]);
    let mut context = FlowContext::new(Endpoint::domain(
        Network::Tcp,
        DomainName::new("www.example.com").unwrap(),
        443,
    ));
    context.process = Some("/usr/bin/example-app".to_owned());
    assert_eq!(lists.matching_names(&context), vec!["apps", "domains"]);

    context.destination = Endpoint::ip(Network::Udp, "192.0.2.10:53".parse().unwrap());
    context.network = Network::Udp;
    assert_eq!(lists.matching_names(&context), vec!["apps", "domains"]);

    context.process = Some("/usr/bin/other-app".to_owned());
    assert_eq!(lists.matching_names(&context), vec!["domains"]);
}

#[test]
fn route_list_snapshot_accepts_deleted_process_executable_suffix() {
    let lists = load_route_lists(&[GoRouteListRecord {
        name: "apps".to_owned(),
        list_type: "process".to_owned(),
        source_type: "local".to_owned(),
        updated_at: 1,
        data_json: br#"{
                "type":"process",
                "source":{"type":"local","local":{"lists":["/usr/bin/example-app"]}}
            }"#
        .to_vec(),
    }]);
    let mut context = FlowContext::new(Endpoint::domain(
        Network::Tcp,
        DomainName::new("example.com").unwrap(),
        443,
    ));
    context.process = Some("/usr/bin/example-app (deleted)".to_owned());
    assert_eq!(lists.matching_names(&context), vec!["apps"]);
}

#[test]
fn route_list_snapshot_matches_fakeip_flows_by_restored_domain() {
    let lists = load_route_lists(&[GoRouteListRecord {
        name: "LAN".to_owned(),
        list_type: "host".to_owned(),
        source_type: "local".to_owned(),
        updated_at: 1,
        data_json: br#"{
                "type":"host",
                "source":{"type":"local","local":{"lists":["198.18.0.0/15","example.com"]}}
            }"#
        .to_vec(),
    }]);
    let mut context = FlowContext::new(Endpoint::ip(
        Network::Tcp,
        "198.18.0.1:443".parse().unwrap(),
    ));
    context.original_domain = Some(DomainName::new("not-lan.example").unwrap());

    assert!(lists.matching_names(&context).is_empty());

    context.original_domain = Some(DomainName::new("example.com").unwrap());
    assert_eq!(lists.matching_names(&context), vec!["LAN"]);
}

#[test]
fn not_domain_expression_compiles_to_an_exclusion_trie() {
    let router = compile_go_route_rules_with_lists(
            &[record(
                r#"{"mode":"drop","rules":[{"type":"not","not":{"type":"domain","domain":"*.blocked.example"}}]}"#,
                "drop",
                "all",
            )],
            &RouteListSnapshot::default(),
            RouteDecision {
                mode: yuhaiin_core::RouteMode::Direct,
                resolver_policy: ResolverPolicy::default(),
                priority: 100,
            },
            None,
        )
        .unwrap();
    let blocked = Endpoint::domain(
        Network::Tcp,
        yuhaiin_core::DomainName::new("www.blocked.example").unwrap(),
        443,
    );
    let allowed = Endpoint::domain(
        Network::Tcp,
        yuhaiin_core::DomainName::new("other.example").unwrap(),
        443,
    );
    assert_eq!(
        router.decide(&blocked).mode,
        yuhaiin_core::RouteMode::Direct
    );
    assert_eq!(router.decide(&allowed).mode, yuhaiin_core::RouteMode::Block);
}

#[test]
fn not_any_uses_demorgan_and_preserves_network_and_port_constraints() {
    let router = compile_go_route_rules_with_lists(
            &[record(
                r#"{"mode":"drop","rules":[{"type":"not","not":{"type":"any","any":[{"type":"network","network":{"network":"udp"}},{"type":"port","port":{"ports":[53]}}]}}]}"#,
                "drop",
                "all",
            )],
            &RouteListSnapshot::default(),
            RouteDecision {
                mode: yuhaiin_core::RouteMode::Direct,
                resolver_policy: ResolverPolicy::default(),
                priority: 100,
            },
            None,
        )
        .unwrap();
    let tcp_80 = Endpoint::ip(Network::Tcp, "192.0.2.1:80".parse().unwrap());
    let tcp_53 = Endpoint::ip(Network::Tcp, "192.0.2.1:53".parse().unwrap());
    let udp_80 = Endpoint::ip(Network::Udp, "192.0.2.1:80".parse().unwrap());
    assert_eq!(router.decide(&tcp_80).mode, yuhaiin_core::RouteMode::Block);
    assert_eq!(router.decide(&tcp_53).mode, yuhaiin_core::RouteMode::Direct);
    assert_eq!(router.decide(&udp_80).mode, yuhaiin_core::RouteMode::Direct);
}

#[test]
fn hosts_as_host_and_global_network_rules_match_go_shapes() {
    let list = GoRouteListRecord {
        name: "hosts".to_owned(),
        list_type: "hosts_as_host".to_owned(),
        source_type: "local".to_owned(),
        updated_at: 1,
        data_json: br#"{
                "type":"hosts_as_host",
                "source":{"type":"local","local":{"lists":["0.0.0.0 local.example alias.example"]}}
            }"#
        .to_vec(),
    };
    let lists = load_route_lists(&[list]);
    assert_eq!(
        lists.values("hosts").unwrap(),
        ["alias.example".to_owned(), "local.example".to_owned()]
    );

    let router = compile_go_route_rules_with_lists(
            &[record(
                r#"{"mode":"drop","rules":[{"type":"all","all":[{"type":"network","network":{"network":"udp"}},{"type":"port","port":{"ports":[53]}}]}]}"#,
                "drop",
                "all",
            )],
            &lists,
            RouteDecision {
                mode: yuhaiin_core::RouteMode::Direct,
                resolver_policy: ResolverPolicy::default(),
                priority: 100,
            },
            None,
        )
        .unwrap();
    let udp = Endpoint::ip(Network::Udp, "192.0.2.1:53".parse().unwrap());
    assert_eq!(router.decide(&udp).mode, yuhaiin_core::RouteMode::Block);
    let tcp = Endpoint::ip(Network::Tcp, "192.0.2.1:53".parse().unwrap());
    assert_eq!(router.decide(&tcp).mode, yuhaiin_core::RouteMode::Direct);
}

#[test]
fn http_route_list_response_parser_handles_chunked_body() {
    let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nalpha\r\n4\r\nbeta\r\n0\r\n\r\n";
    assert_eq!(parse_http_response(response).unwrap(), b"alphabeta");
    assert_eq!(
        parse_http_url("http://127.0.0.1:8080/rules?x=1").unwrap(),
        (false, "127.0.0.1".to_owned(), 8080, "/rules?x=1".to_owned())
    );
}

#[test]
fn http_route_list_downloader_reads_a_local_http_server() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            stream
                .write_all(b"b\r\nexample.com\r\n0\r\n\r\n")
                .await
                .unwrap();
        });
        let body = download_route_url(&format!("http://{address}/rules"), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(body, b"example.com");
        server.await.unwrap();
    });
}

#[test]
fn http_route_list_downloader_uses_injected_outbound_proxy() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 1024];
                let length = stream.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..length]);
                assert!(request.starts_with("GET /rules HTTP/1.1"));
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nproxy-route\n",
                    )
                    .await
                    .unwrap();
            });
            let proxy = Arc::new(FixedAsyncProxy {
                address,
                timeout: Duration::from_secs(2),
            });
            let transport = Arc::new(ProxyRouteListTransport::new(
                proxy,
                Arc::new(SystemAsyncIpResolver),
            ));
            let body = download_route_url_with_transport(
                &format!("http://{address}/rules"),
                Duration::from_secs(2),
                Some(transport.as_ref()),
            )
            .await
            .unwrap();
            assert_eq!(body, b"proxy-route\n");
            server.await.unwrap();
        });
}

#[test]
fn remote_route_list_refresh_writes_atomic_cache_used_by_snapshot_loader() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await.unwrap();
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nremote.test\n"
                    )
                    .await
                    .unwrap();
            });
            let url = format!("http://{address}/rules");
            let record = GoRouteListRecord {
                name: "remote".to_owned(),
                list_type: "host".to_owned(),
                source_type: "remote".to_owned(),
                updated_at: 1,
                data_json: serde_json::json!({
                    "name":"remote",
                    "type":"host",
                    "source":{"type":"remote","remote":{"urls":[url.clone()]}}
                })
                .to_string()
                .into_bytes(),
            };
            let cache = route_list_cache_path(&url);
            let report = refresh_route_list_caches(&[record], Duration::from_secs(2)).await;
            assert_eq!(report.refreshed, 1);
            assert!(report.errors.is_empty());
            let loaded = load_route_lists(&[GoRouteListRecord {
                name: "remote".to_owned(),
                list_type: "host".to_owned(),
                source_type: "remote".to_owned(),
                updated_at: 1,
                data_json: serde_json::json!({
                    "name":"remote",
                    "type":"host",
                    "source":{"type":"remote","remote":{"urls":[url]}}
                })
                .to_string()
                .into_bytes(),
            }]);
            assert_eq!(loaded.values("remote").unwrap(), ["remote.test"]);
            server.await.unwrap();
            let _ = fs::remove_file(cache);
        });
}
