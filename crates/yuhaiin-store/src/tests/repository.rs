use super::super::*;
use super::*;

#[test]
fn typed_repository_round_trips_all_runtime_domains() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let repository = store.repository();
    block_on(repository.put_proxy_node(&ProxyNodeRecord {
        id: "proxy-1".to_owned(),
        kind: "yuubinsya".to_owned(),
        config: b"{\"password\":\"redacted\"}".to_vec(),
    }))
    .unwrap();
    block_on(repository.put_route_rule(&RouteRuleRecord {
        id: "rule-1".to_owned(),
        pattern: "example.com".to_owned(),
        action: "proxy".to_owned(),
        priority: 10,
        geo_country: Some("CN".to_owned()),
        resolver_policy: b"fakeip".to_vec(),
    }))
    .unwrap();
    block_on(repository.put_dns_resolver(&DnsResolverRecord {
        id: "dns-1".to_owned(),
        kind: "udp".to_owned(),
        config: b"127.0.0.1:53".to_vec(),
    }))
    .unwrap();
    block_on(repository.put_tun_config(&TunConfigRecord {
        key: "mtu".to_owned(),
        value: b"1500".to_vec(),
    }))
    .unwrap();
    block_on(repository.put_nat_config(&NatConfigRecord {
        key: "default".to_owned(),
        full_cone: true,
        idle_timeout_ms: 60_000,
    }))
    .unwrap();
    block_on(repository.put_maxmind_metadata(&MaxMindMetadataRecord {
        id: "geoip".to_owned(),
        path: "/var/lib/yuhaiin/GeoLite2-Country.mmdb".to_owned(),
        sha256: vec![1, 2, 3],
        size: 42,
        updated_at: 1_700_000_000,
    }))
    .unwrap();
    block_on(repository.put_go_route_settings(&GoRouteSettingsRecord {
        id: 1,
        direct_resolver: "direct".to_owned(),
        proxy_resolver: "proxy".to_owned(),
        resolve_locally: true,
        udp_proxy_fqdn: 1,
    }))
    .unwrap();

    assert_eq!(
        block_on(repository.list_proxy_nodes()).unwrap()[0].kind,
        "yuubinsya"
    );
    assert_eq!(
        block_on(repository.list_route_rules()).unwrap()[0].priority,
        10
    );
    assert_eq!(
        block_on(repository.list_route_rules()).unwrap()[0]
            .geo_country
            .as_deref(),
        Some("CN")
    );
    assert_eq!(
        block_on(repository.list_dns_resolvers()).unwrap()[0].config,
        b"127.0.0.1:53"
    );
    assert_eq!(
        block_on(repository.list_tun_config()).unwrap()[0].value,
        b"1500"
    );
    assert!(block_on(repository.list_nat_config()).unwrap()[0].full_cone);
    assert_eq!(
        block_on(repository.list_maxmind_metadata()).unwrap()[0].sha256,
        vec![1, 2, 3]
    );
    let route_settings = block_on(repository.list_go_route_settings()).unwrap();
    assert_eq!(route_settings[0].proxy_resolver, "proxy");
    assert!(block_on(repository.delete_go_route_settings(1)).unwrap());
    assert!(
        block_on(repository.list_go_route_settings())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn inbound_settings_use_go_defaults_and_rust_overlay() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let repository = store.repository();
    assert_eq!(
        block_on(repository.get_inbound_settings()).unwrap(),
        InboundSettings::default()
    );

    let settings = InboundSettings {
        hijack_dns: true,
        hijack_dns_fakeip: false,
        sniff: false,
    };
    block_on(repository.put_inbound_settings(settings)).unwrap();
    assert_eq!(
        block_on(repository.get_inbound_settings()).unwrap(),
        settings
    );
    assert_eq!(
        block_on(store.get_config("inbounds.config")).unwrap(),
        Some(serde_json::to_vec(&settings).unwrap())
    );
}

#[test]
fn inbound_settings_prefer_and_update_the_legacy_go_row() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    store
        .with_write_transaction(|connection| {
            connection
                .execute_batch(
                    "CREATE TABLE inbound_settings (
                         id INTEGER PRIMARY KEY NOT NULL,
                         hijack_dns INTEGER NOT NULL,
                         hijack_dns_fakeip INTEGER NOT NULL,
                         sniff_enabled INTEGER NOT NULL
                     );
                     INSERT INTO inbound_settings
                         (id, hijack_dns, hijack_dns_fakeip, sniff_enabled)
                     VALUES (1, 0, 1, 0);",
                )
                .map_err(storage_error)
        })
        .unwrap();
    let repository = store.repository();
    assert_eq!(
        block_on(repository.get_inbound_settings()).unwrap(),
        InboundSettings {
            hijack_dns: false,
            hijack_dns_fakeip: true,
            sniff: false,
        }
    );

    let settings = InboundSettings::default();
    block_on(repository.put_inbound_settings(settings)).unwrap();
    assert_eq!(
        block_on(repository.get_inbound_settings()).unwrap(),
        settings
    );
    assert!(
        block_on(store.get_config("inbounds.config"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn fresh_store_supports_go_v6_compatibility_writes() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let repository = store.repository();

    block_on(repository.put_go_inbound(&GoInboundRecord {
        id: "tun".to_owned(),
        name: "TUN".to_owned(),
        enabled: true,
        network_type: "tcpudp".to_owned(),
        protocol_type: "tun".to_owned(),
        transport_types_json: br#"["tun"]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{"mtu":1500}"#.to_vec(),
    }))
    .unwrap();
    block_on(repository.put_go_node(&GoNodeRecord {
        id: "node".to_owned(),
        name: "Node".to_owned(),
        group_name: "default".to_owned(),
        origin: "local".to_owned(),
        enabled: true,
        chain_types_json: br#"["direct"]"#.to_vec(),
        updated_at: 2,
        data_json: br#"{"protocol":"direct"}"#.to_vec(),
    }))
    .unwrap();
    block_on(repository.put_go_node_tag(&GoNodeTagRecord {
        id: "tag".to_owned(),
        name: "Default".to_owned(),
        members_json: br#"["node"]"#.to_vec(),
        updated_at: 3,
    }))
    .unwrap();
    block_on(repository.put_go_resolver(&GoResolverRecord {
        id: "dns".to_owned(),
        resolver_type: "udp".to_owned(),
        host: "1.1.1.1:53".to_owned(),
        updated_at: 4,
        data_json: br#"{"type":"udp"}"#.to_vec(),
    }))
    .unwrap();
    block_on(repository.put_go_route_rule(&GoRouteRuleRecord {
        id: "rule".to_owned(),
        name: "Rule".to_owned(),
        priority: 1,
        disabled: false,
        action_mode: "direct".to_owned(),
        match_type: "domain".to_owned(),
        tag: "default".to_owned(),
        updated_at: 5,
        data_json: br#"{"match":{"domain":"example.com"}}"#.to_vec(),
    }))
    .unwrap();
    block_on(repository.put_go_route_list(&GoRouteListRecord {
        name: "list".to_owned(),
        list_type: "domain".to_owned(),
        source_type: "local".to_owned(),
        updated_at: 6,
        data_json: br#"{"domains":["example.com"]}"#.to_vec(),
    }))
    .unwrap();

    assert_eq!(block_on(repository.list_go_inbounds()).unwrap().len(), 1);
    assert_eq!(block_on(repository.list_go_nodes()).unwrap().len(), 1);
    assert_eq!(block_on(repository.list_go_node_tags()).unwrap().len(), 1);
    assert_eq!(block_on(repository.list_go_resolvers()).unwrap().len(), 1);
    assert_eq!(block_on(repository.list_go_route_rules()).unwrap().len(), 1);
    assert_eq!(block_on(repository.list_go_route_lists()).unwrap().len(), 1);
}

#[test]
fn subscription_links_use_the_go_table_and_preserve_unknown_fields() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let repository = store.repository();
    block_on(
        repository.put_go_subscription_links(&[GoSubscriptionLinkRecord {
            name: "  prod  ".to_owned(),
            url: "  https://example.test/sub  ".to_owned(),
            link_type: String::new(),
            updated_at: 7,
            data_json: br#"{"name":"ignored","url":"ignored","future":true}"#.to_vec(),
        }]),
    )
    .unwrap();

    let links = block_on(repository.list_go_subscription_links()).unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].name, "prod");
    assert_eq!(links[0].url, "https://example.test/sub");
    assert_eq!(links[0].link_type, "reserve");
    let json: serde_json::Value = serde_json::from_slice(&links[0].data_json).unwrap();
    assert_eq!(json["future"], true);
    assert!(block_on(repository.delete_go_subscription_links(&["prod".to_owned()])).is_ok());
    assert!(
        block_on(repository.list_go_subscription_links())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn typed_repository_rejects_invalid_nat_metadata() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let repository = store.repository();
    assert!(
        block_on(repository.put_nat_config(&NatConfigRecord {
            key: "default".to_owned(),
            full_cone: true,
            idle_timeout_ms: 0,
        }))
        .is_err()
    );
    assert!(
        block_on(repository.put_proxy_node(&ProxyNodeRecord {
            id: "".to_owned(),
            kind: "direct".to_owned(),
            config: Vec::new(),
        }))
        .is_err()
    );
}

#[test]
fn go_route_rule_priority_reorders_and_renumbers_atomically() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let repository = store.repository();
    for (priority, name) in [(0, "alpha"), (1, "beta"), (2, "gamma")] {
        block_on(repository.put_go_route_rule(&GoRouteRuleRecord {
            id: format!("{name}:0"),
            name: name.to_owned(),
            priority,
            disabled: false,
            action_mode: "direct".to_owned(),
            match_type: "domain".to_owned(),
            tag: name.to_owned(),
            updated_at: 1,
            data_json: format!(r#"{{"name":"{name}"}}"#).into_bytes(),
        }))
        .unwrap();
    }

    block_on(repository.change_go_route_rule_priority("alpha", "gamma", "exchange")).unwrap();
    assert_eq!(
        block_on(repository.list_go_route_rules())
            .unwrap()
            .into_iter()
            .map(|record| record.name)
            .collect::<Vec<_>>(),
        ["gamma", "beta", "alpha"]
    );

    block_on(repository.change_go_route_rule_priority("alpha", "gamma", "insert_before")).unwrap();
    assert_eq!(
        block_on(repository.list_go_route_rules())
            .unwrap()
            .into_iter()
            .map(|record| record.name)
            .collect::<Vec<_>>(),
        ["alpha", "gamma", "beta"]
    );

    block_on(repository.change_go_route_rule_priority("alpha", "beta", "insert_after")).unwrap();
    let rules = block_on(repository.list_go_route_rules()).unwrap();
    assert_eq!(
        rules
            .iter()
            .map(|record| record.name.as_str())
            .collect::<Vec<_>>(),
        ["gamma", "beta", "alpha"]
    );
    assert_eq!(
        rules
            .iter()
            .map(|record| record.priority)
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert!(
        block_on(repository.change_go_route_rule_priority("missing", "beta", "exchange")).is_err()
    );
    assert!(
        block_on(repository.change_go_route_rule_priority("alpha", "beta", "invalid")).is_err()
    );
}

#[test]
fn nat_config_defaults_to_full_cone_across_missing_delete_and_raw_legacy_rows() {
    let path = test_database_path();
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let repository = store.repository();
        let missing = block_on(repository.get_nat_config_or_default("default")).unwrap();
        assert_eq!(missing, NatConfigRecord::default());
        assert!(
            block_on(repository.get_nat_config("default"))
                .unwrap()
                .is_none()
        );

        block_on(repository.put_nat_config(&NatConfigRecord {
            key: "default".to_owned(),
            full_cone: true,
            idle_timeout_ms: 45_000,
        }))
        .unwrap();
        assert_eq!(
            block_on(repository.get_nat_config("default"))
                .unwrap()
                .unwrap()
                .idle_timeout_ms,
            45_000
        );
        assert!(block_on(repository.delete_nat_config("default")).unwrap());
        assert!(
            block_on(repository.get_nat_config_or_default("default"))
                .unwrap()
                .full_cone
        );
    }

    // Go/legacy writers may omit columns that have stable SQL defaults.
    // Opening that row through the typed API must still produce full-cone
    // behavior rather than an implicit restricted-NAT mode.
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute("INSERT INTO nat_config (key) VALUES ('legacy-default')")
            .unwrap();
    }
    let store = block_on(ConfigStore::open(&path)).unwrap();
    let legacy = block_on(store.repository().get_nat_config("legacy-default"))
        .unwrap()
        .unwrap();
    assert!(legacy.full_cone);
    assert_eq!(legacy.idle_timeout_ms, DEFAULT_NAT_IDLE_TIMEOUT_MS);
    remove_database_artifacts(&path);
}

#[test]
fn nat_config_rejects_restricted_mode_on_write_and_read() {
    let path = test_database_path();
    let store = block_on(ConfigStore::open(&path)).unwrap();
    let repository = store.repository();
    let error = block_on(repository.put_nat_config(&NatConfigRecord {
        key: "restricted".to_owned(),
        full_cone: false,
        idle_timeout_ms: DEFAULT_NAT_IDLE_TIMEOUT_MS,
    }))
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidInput);
    assert!(error.message.contains("Full Cone NAT"));
    assert!(block_on(repository.list_nat_config()).unwrap().is_empty());
    drop(store);

    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "DROP TABLE nat_config;
                 CREATE TABLE nat_config (
                     key TEXT PRIMARY KEY NOT NULL,
                     full_cone INTEGER NOT NULL,
                     idle_timeout_ms INTEGER NOT NULL
                 );
                 INSERT INTO nat_config (key, full_cone, idle_timeout_ms)
                 VALUES ('legacy-restricted', 0, 30000)",
            )
            .unwrap();
    }
    let store = block_on(ConfigStore::open(&path)).unwrap();
    let error = block_on(store.repository().get_nat_config("legacy-restricted")).unwrap_err();
    assert_eq!(error.kind, ErrorKind::Storage);
    assert!(error.message.contains("Full Cone NAT"));
    remove_database_artifacts(&path);
}
