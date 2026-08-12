use super::super::*;
use super::*;

#[test]
fn failed_go_import_rolls_back_and_retries_after_schema_repair() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE metadata (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                );
                CREATE TABLE migrate (version INTEGER NOT NULL);
                INSERT INTO metadata (key, value) VALUES ('schema_version', '6');
                INSERT INTO migrate (version) VALUES (6);
                CREATE TABLE nodes_v2 (
                    id TEXT PRIMARY KEY NOT NULL,
                    chain_types_json TEXT NOT NULL,
                    data_json TEXT NOT NULL
                );
                INSERT INTO nodes_v2 (id, chain_types_json, data_json)
                    VALUES ('node-retry', '[\"direct\"]', '{\"kind\":\"direct\"}');
                CREATE TABLE route_rules_v2 (
                    id TEXT PRIMARY KEY NOT NULL,
                    match_type TEXT NOT NULL,
                    action_mode TEXT NOT NULL,
                    priority,
                    data_json TEXT NOT NULL
                );
                INSERT INTO route_rules_v2
                    (id, match_type, action_mode, priority, data_json)
                    VALUES ('rule-retry', 'domain', 'proxy', 'not-an-integer', '{}');",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open(&path)) {
        Ok(_) => panic!("invalid Go schema must fail closed during import"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert!(
            connection
                .query("SELECT id FROM proxy_nodes WHERE id = 'node-retry'")
                .unwrap()
                .is_empty()
        );
        connection
            .execute_with_params(
                "UPDATE route_rules_v2 SET priority = ?1 WHERE id = ?2",
                &[SqliteValue::from(10i64), SqliteValue::from("rule-retry")],
            )
            .unwrap();
    }

    let store = block_on(ConfigStore::open(&path)).unwrap();
    let repository = store.repository();
    assert_eq!(
        block_on(repository.list_proxy_nodes()).unwrap()[0].id,
        "node-retry"
    );
    assert_eq!(
        block_on(repository.list_route_rules()).unwrap()[0].priority,
        10
    );
    remove_database_artifacts(&path);
}

#[test]
fn additive_go_schema_v7_is_opened_without_dropping_subscription_tables() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
        connection
            .execute_batch(
                // Go v7 production snapshots can retain the plain-model
                // metadata value 6 while the additive link migration is
                // recorded in `migrate` as version 7.
                "UPDATE metadata SET value = '6' WHERE key = 'schema_version';
                 INSERT INTO migrate (version, name, applied_at)
                     VALUES (7, 'subscription_node_user_links', 0);
                 CREATE TABLE subscription_nodes_v2 (
                     subscription_name TEXT NOT NULL,
                     node_id TEXT NOT NULL,
                     PRIMARY KEY (subscription_name, node_id)
                 );
                 INSERT INTO subscription_nodes_v2 (subscription_name, node_id)
                     VALUES ('remote', 'node-1');",
            )
            .unwrap();
    }

    let store = block_on(ConfigStore::open(&path)).unwrap();
    assert_eq!(
        block_on(store.repository().list_proxy_nodes())
            .unwrap()
            .len(),
        1
    );
    drop(store);

    let connection = Connection::open(path.to_str().unwrap()).unwrap();
    assert!(table_exists(&connection, "subscription_nodes_v2"));
    assert_eq!(
        connection
            .query("SELECT COUNT(*) FROM subscription_nodes_v2")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Integer(1))
    );
    assert_eq!(
        connection
            .query("SELECT value FROM yuhaiin_meta WHERE key = 'go_schema_version'")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Integer(7))
    );
    remove_database_artifacts(&path);
}

#[test]
fn imports_go_v1_nodes_inbounds_lists_and_tags_into_v2_contracts() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE migrate (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL);
                INSERT INTO metadata(key, value) VALUES ('schema_version', '1');
                INSERT INTO migrate(version, name, applied_at) VALUES (1, 'initial_schema', 0);
                CREATE TABLE nodes (
                    id INTEGER PRIMARY KEY,
                    hash TEXT NOT NULL UNIQUE,
                    group_name TEXT NOT NULL,
                    name TEXT NOT NULL,
                    origin INTEGER NOT NULL,
                    selected_tcp INTEGER NOT NULL DEFAULT 0,
                    selected_udp INTEGER NOT NULL DEFAULT 0,
                    search_text TEXT NOT NULL DEFAULT '',
                    updated_at INTEGER NOT NULL,
                    data_json TEXT NOT NULL
                );
                INSERT INTO nodes(hash, group_name, name, origin, selected_tcp, selected_udp, updated_at, data_json)
                VALUES ('legacy-node', 'manual', 'Legacy node', 102, 1, 0, 42,
                    '{"hash":"legacy-node","name":"Legacy node","group":"manual","origin":"manual","protocols":[{"simple":{"host":"127.0.0.1","port":1080}},{"socks5":{"hostname":"127.0.0.1","user":"","password":"","override_port":0}}]}');
                CREATE TABLE inbounds (
                    name TEXT PRIMARY KEY,
                    enabled INTEGER NOT NULL,
                    inbound_type TEXT NOT NULL,
                    listen_host TEXT NOT NULL DEFAULT '',
                    updated_at INTEGER NOT NULL,
                    data_json TEXT NOT NULL
                );
                INSERT INTO inbounds(name, enabled, inbound_type, updated_at, data_json)
                VALUES ('mixed', 1, 'mixed', 43,
                    '{"name":"mixed","enabled":true,"tcpudp":{"host":"127.0.0.1:1080","control":"tcp_udp_control_all"},"transport":[],"mixed":{"username":"","password":""}}');
                CREATE TABLE route_lists (
                    name TEXT PRIMARY KEY,
                    kind TEXT NOT NULL DEFAULT '',
                    updated_at INTEGER NOT NULL,
                    data_json TEXT NOT NULL
                );
                INSERT INTO route_lists(name, kind, updated_at, data_json)
                VALUES ('legacy-list', 'host', 44,
                    '{"name":"legacy-list","list_type":"host","local":{"lists":["example.com"]}}');
                CREATE TABLE node_tags (
                    tag_name TEXT NOT NULL,
                    target_kind TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY(tag_name, target_kind, target_id)
                );
                INSERT INTO node_tags(tag_name, target_kind, target_id, updated_at)
                VALUES ('legacy-tag', 'node', 'legacy-node', 45);
                "#,
            )
            .unwrap();
    }

    let store = block_on(ConfigStore::open(&path)).unwrap();
    let repository = store.repository();
    let nodes = block_on(repository.list_go_nodes()).unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].id, "legacy-node");
    assert_eq!(nodes[0].origin, "manual");
    let node: serde_json::Value = serde_json::from_slice(&nodes[0].data_json).unwrap();
    assert_eq!(node["id"], "legacy-node");
    assert_eq!(node["chain"][0]["type"], "simple");
    assert_eq!(node["chain"][1]["type"], "socks5");
    assert_eq!(
        block_on(repository.get_go_selected_node_id("selected_tcp_node_v2")).unwrap(),
        Some("legacy-node".to_owned())
    );

    let inbounds = block_on(repository.list_go_inbounds()).unwrap();
    assert_eq!(inbounds.len(), 1);
    let inbound: serde_json::Value = serde_json::from_slice(&inbounds[0].data_json).unwrap();
    assert_eq!(inbound["network"]["type"], "tcp_udp");
    assert_eq!(inbound["network"]["tcp_udp"]["udp"], "enabled");
    assert_eq!(inbound["protocol"]["type"], "mixed");

    let lists = block_on(repository.list_go_route_lists()).unwrap();
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].name, "legacy-list");
    assert_eq!(lists[0].source_type, "local");
    let tags = block_on(repository.list_go_node_tags()).unwrap();
    assert_eq!(tags.len(), 1);
    let tag: serde_json::Value = serde_json::from_slice(&tags[0].members_json).unwrap();
    assert_eq!(tag["type"], "node");
    assert_eq!(tag["hash"][0], "legacy-node");
    drop(store);

    let reopened = block_on(ConfigStore::open(&path)).unwrap();
    assert_eq!(
        block_on(reopened.repository().list_go_nodes())
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        block_on(reopened.repository().list_go_inbounds())
            .unwrap()
            .len(),
        1
    );
    remove_database_artifacts(&path);
}

#[test]
#[ignore = "requires YUHAIIN_GO_LEGACY_PRODUCTION_DB pointing to a copied Go v1 state.db"]
fn imports_real_go_v1_snapshot_without_touching_source() {
    let source = std::env::var_os("YUHAIIN_GO_LEGACY_PRODUCTION_DB")
        .map(PathBuf::from)
        .expect("YUHAIIN_GO_LEGACY_PRODUCTION_DB must point to a Go v1 snapshot");
    assert!(source.is_file(), "Go v1 snapshot does not exist");
    let source_connection = Connection::open(source.to_str().unwrap()).unwrap();
    let expected = [
        (
            "nodes",
            table_row_count(&source_connection, "nodes").unwrap(),
        ),
        (
            "inbounds",
            table_row_count(&source_connection, "inbounds").unwrap(),
        ),
        (
            "dns_resolvers",
            table_row_count(&source_connection, "dns_resolvers").unwrap(),
        ),
        (
            "route_rules",
            table_row_count(&source_connection, "route_rules").unwrap(),
        ),
        (
            "route_lists",
            table_row_count(&source_connection, "route_lists").unwrap(),
        ),
        (
            "node_tags",
            table_row_count(&source_connection, "node_tags").unwrap(),
        ),
    ];
    drop(source_connection);

    let path = test_database_path().with_file_name(format!(
        "go-v1-production-import-{}-{}.db",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::copy(&source, &path).expect("copy Go v1 snapshot");
    let store = block_on(ConfigStore::open(&path)).expect("open Go v1 snapshot with Rust");
    let repository = store.repository();
    assert_eq!(
        block_on(repository.list_go_nodes()).unwrap().len() as i64,
        expected[0].1
    );
    assert_eq!(
        block_on(repository.list_go_inbounds()).unwrap().len() as i64,
        expected[1].1
    );
    assert_eq!(
        block_on(repository.list_go_resolvers()).unwrap().len() as i64,
        expected[2].1
    );
    assert_eq!(
        block_on(repository.list_go_route_rules()).unwrap().len() as i64,
        expected[3].1
    );
    assert_eq!(
        block_on(repository.list_go_route_lists()).unwrap().len() as i64,
        expected[4].1
    );
    assert_eq!(
        block_on(repository.list_go_node_tags()).unwrap().len() as i64,
        expected[5].1
    );
    remove_database_artifacts(&path);
}

#[test]
fn go_route_udp_proxy_fqdn_codes_preserve_known_and_unknown_semantics() {
    let base = GoRouteSettingsRecord {
        id: 1,
        direct_resolver: "system".to_owned(),
        proxy_resolver: "proxy-dns".to_owned(),
        resolve_locally: true,
        udp_proxy_fqdn: 0,
    };

    assert_eq!(
        base.to_runtime_config().udp_proxy_fqdn,
        GoUdpProxyFqdnStrategy::Default
    );
    assert_eq!(
        GoRouteSettingsRecord {
            udp_proxy_fqdn: 1,
            ..base.clone()
        }
        .to_runtime_config()
        .udp_proxy_fqdn,
        GoUdpProxyFqdnStrategy::Resolve
    );
    assert_eq!(
        GoRouteSettingsRecord {
            udp_proxy_fqdn: 2,
            ..base.clone()
        }
        .to_runtime_config()
        .udp_proxy_fqdn,
        GoUdpProxyFqdnStrategy::SkipResolve
    );
    assert_eq!(
        GoRouteSettingsRecord {
            udp_proxy_fqdn: 99,
            ..base
        }
        .to_runtime_config()
        .udp_proxy_fqdn,
        GoUdpProxyFqdnStrategy::Default
    );
}

#[test]
fn go_resolver_runtime_preserves_supported_transport_kinds() {
    let cases = [
        ("udp", GoResolverTransport::Udp),
        ("tcp", GoResolverTransport::Tcp),
        ("doh", GoResolverTransport::Doh),
        ("dot", GoResolverTransport::Dot),
        ("doq", GoResolverTransport::Doq),
        ("doh3", GoResolverTransport::Doh3),
        ("system", GoResolverTransport::System),
    ];
    for (kind, expected) in cases {
        let record = GoResolverRecord {
            id: format!("resolver-{kind}"),
            resolver_type: kind.to_owned(),
            host: if kind == "system" {
                String::new()
            } else {
                "127.0.0.1:53".to_owned()
            },
            updated_at: 0,
            data_json: format!(
                r#"{{"type":"{kind}","host":"{}","tlsServerName":"dns.example"}}"#,
                if kind == "system" { "" } else { "127.0.0.1:53" }
            )
            .into_bytes(),
        };
        let runtime = record.to_runtime_config().unwrap();
        assert_eq!(runtime.transport, expected);
        assert_eq!(runtime.id, format!("resolver-{kind}"));
    }
}

#[test]
fn go_node_runtime_preserves_proxy_layers_and_selects_supported_base() {
    let cases = [
        ("direct", GoProxyTransport::Direct),
        ("reject", GoProxyTransport::Reject),
        ("block", GoProxyTransport::Reject),
        ("drop", GoProxyTransport::Drop),
        ("fixed", GoProxyTransport::Fixed),
        ("http_mock", GoProxyTransport::HttpMock),
        ("http", GoProxyTransport::HttpProxy),
        ("http_proxy", GoProxyTransport::HttpProxy),
        ("socks5", GoProxyTransport::Socks5),
        ("shadowsocks", GoProxyTransport::Shadowsocks),
        ("shadowsocksr", GoProxyTransport::Shadowsocksr),
        ("trojan", GoProxyTransport::Trojan),
        ("vless", GoProxyTransport::Vless),
        ("vmess", GoProxyTransport::Vmess),
        ("yuubinsya", GoProxyTransport::Yuubinsya),
        ("aead", GoProxyTransport::Aead),
        ("tls", GoProxyTransport::Tls),
        ("http2", GoProxyTransport::Http2),
        // Go's `none` point is a no-op wrapper around the zero/direct proxy.
        ("none", GoProxyTransport::Direct),
    ];
    for (protocol, expected) in cases {
        let record = GoNodeRecord {
            id: format!("node-{protocol}"),
            name: protocol.to_owned(),
            group_name: "test".to_owned(),
            origin: "manual".to_owned(),
            enabled: true,
            chain_types_json: format!("[{protocol:?}]").into_bytes(),
            updated_at: 1,
            data_json: format!(r#"{{"protocol":"{protocol}","unknown":42}}"#).into_bytes(),
        };
        let runtime = record.to_proxy_runtime_config().unwrap();
        assert_eq!(runtime.transport, expected);
        assert_eq!(runtime.chain_types, vec![protocol]);
        assert!(String::from_utf8_lossy(&runtime.data_json).contains("unknown"));
        let wire = serde_json::to_value(&runtime).unwrap();
        assert_eq!(wire["groupName"], "test");
        assert_eq!(wire["chainTypes"][0], protocol);
        assert!(wire.get("data_json").is_none());
    }

    let layered = GoNodeRecord {
        id: "node-layered".to_owned(),
        name: "layered".to_owned(),
        group_name: "test".to_owned(),
        origin: "manual".to_owned(),
        enabled: true,
        chain_types_json: br#"["yuubinsya","tls","http2"]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{"chain":[{"type":"yuubinsya","yuubinsya":{"password":"redacted"}},{"type":"tls","tls":{"enable":true}}]}"#.to_vec(),
    };
    let runtime = layered.to_proxy_runtime_config().unwrap();
    assert_eq!(runtime.transport, GoProxyTransport::Yuubinsya);
    assert_eq!(runtime.chain_types, vec!["yuubinsya", "tls", "http2"]);
    assert_eq!(runtime.layers.len(), 2);
    assert_eq!(runtime.layers[0].kind, "yuubinsya");
    assert_eq!(runtime.layers[0].config["password"], "redacted");
    assert_eq!(runtime.layers[1].kind, "tls");
    let wire = serde_json::to_value(&runtime).unwrap();
    assert_eq!(wire["layers"][0]["config"]["password"], "***");

    let aead = GoNodeRecord {
        id: "node-aead".to_owned(),
        name: "aead".to_owned(),
        group_name: "test".to_owned(),
        origin: "manual".to_owned(),
        enabled: true,
        chain_types_json: br#"["fixedv2","aead"]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{"chain":[{"type":"fixedv2","fixedv2":{"addresses":[{"host":"127.0.0.1","port":443}]}},{"type":"aead","aead":{"password":"secret","cryptoMethod":"AeadCryptoMethod_XChacha20Poly1305"}}]}"#.to_vec(),
    };
    let aead_runtime = aead.to_proxy_runtime_config().unwrap();
    assert_eq!(aead_runtime.transport, GoProxyTransport::Aead);
    assert_eq!(aead_runtime.layers[1].kind, "aead");
    assert_eq!(aead_runtime.layers[1].config["password"], "secret");

    let wrapped_base = GoNodeRecord {
        chain_types_json: br#"["tls","fixed"]"#.to_vec(),
        data_json: br#"{"protocol":"tls"}"#.to_vec(),
        ..layered
    };
    assert_eq!(
        wrapped_base.to_proxy_runtime_config().unwrap().transport,
        GoProxyTransport::Fixed
    );

    let none_with_unknown = GoNodeRecord {
        id: "node-none-unknown".to_owned(),
        name: "none-unknown".to_owned(),
        group_name: "test".to_owned(),
        origin: "manual".to_owned(),
        enabled: true,
        chain_types_json: br#"["none","future_protocol"]"#.to_vec(),
        updated_at: 1,
        data_json: br#"{"chain":[{"type":"none","none":{}},{"type":"future_protocol","future_protocol":{}}]}"#.to_vec(),
    };
    assert_eq!(
        none_with_unknown
            .to_proxy_runtime_config()
            .unwrap()
            .transport,
        GoProxyTransport::Unknown {
            name: "future_protocol".to_owned()
        }
    );
}

#[test]
fn go_node_runtime_keeps_unknown_protocols_but_rejects_malformed_json() {
    let unknown = GoNodeRecord {
        id: "node-unknown".to_owned(),
        name: "unknown".to_owned(),
        group_name: String::new(),
        origin: "manual".to_owned(),
        enabled: false,
        chain_types_json: br#"["future_protocol"]"#.to_vec(),
        updated_at: 0,
        data_json: br#"{"protocol":"future_protocol"}"#.to_vec(),
    };
    assert_eq!(
        unknown.to_proxy_runtime_config().unwrap().transport,
        GoProxyTransport::Unknown {
            name: "future_protocol".to_owned()
        }
    );

    let malformed = GoNodeRecord {
        data_json: b"not-json".to_vec(),
        ..unknown
    };
    assert!(malformed.to_proxy_runtime_config().is_err());
}

#[cfg(feature = "async-proxy")]
#[test]
fn go_proxy_runtime_converts_core_base_transports_and_rejects_chain_layers() {
    use std::time::Duration;
    use yuhaiin_core::proxy_factory::BaseProxyKind;

    let direct = GoNodeRecord {
        id: "direct".to_owned(),
        name: "direct".to_owned(),
        group_name: String::new(),
        origin: "manual".to_owned(),
        enabled: true,
        chain_types_json: br#"["direct"]"#.to_vec(),
        updated_at: 0,
        data_json: br#"{"chain":[{"type":"direct","direct":{}}]}"#.to_vec(),
    };
    let runtime = direct.to_proxy_runtime_config().unwrap();
    assert!(matches!(
        runtime
            .to_base_proxy_config(Duration::from_secs(3))
            .unwrap()
            .kind,
        BaseProxyKind::Direct
    ));

    let http = GoNodeRecord {
        id: "http".to_owned(),
        name: "http".to_owned(),
        group_name: String::new(),
        origin: "manual".to_owned(),
        enabled: true,
        chain_types_json: br#"["fixed","http"]"#.to_vec(),
        updated_at: 0,
        data_json: br#"{"chain":[{"type":"fixed","fixed":{"host":"127.0.0.1","port":8080}},{"type":"http","http":{"user":"u","password":"p"}}]}"#.to_vec(),
    };
    let runtime = http.to_proxy_runtime_config().unwrap();
    let config = runtime
        .to_base_proxy_config(Duration::from_secs(3))
        .unwrap();
    assert!(matches!(
        config.kind,
        BaseProxyKind::Http {
            proxy,
            username: Some(_),
            password: Some(_)
        } if proxy == "127.0.0.1:8080".parse().unwrap()
    ));

    let yuubinsya = GoNodeRecord {
        chain_types_json: br#"["fixedv2","tls","http2","yuubinsya"]"#.to_vec(),
        data_json: br#"{"chain":[]}"#.to_vec(),
        ..http
    };
    let runtime = yuubinsya.to_proxy_runtime_config().unwrap();
    let error = match runtime.to_base_proxy_config(Duration::from_secs(3)) {
        Ok(_) => panic!("Yuubinsya must use chain construction"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Unsupported);
}

#[test]
fn malformed_go_schema_version_fails_closed_and_retries_after_repair() {
    for invalid_version in ["not-a-number", "-1"] {
        let path = test_database_path();
        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE metadata (
                        key TEXT PRIMARY KEY NOT NULL,
                        value TEXT NOT NULL
                    );
                    CREATE TABLE migrate (version INTEGER NOT NULL);
                    INSERT INTO migrate (version) VALUES (6);",
                )
                .unwrap();
            connection
                .execute_with_params(
                    "INSERT INTO metadata (key, value) VALUES ('schema_version', ?1)",
                    &[SqliteValue::from(invalid_version)],
                )
                .unwrap();
        }

        let error = match block_on(ConfigStore::open(&path)) {
            Ok(_) => panic!("malformed Go schema version must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Storage);
        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            assert!(!meta_flag(&connection, "go_schema_imported"));
            connection
                .execute_with_params(
                    "UPDATE metadata SET value = ?1 WHERE key = 'schema_version'",
                    &[SqliteValue::from("6")],
                )
                .unwrap();
        }

        let store = block_on(ConfigStore::open(&path)).unwrap();
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert!(meta_flag(&connection, "go_schema_imported"));
        assert_eq!(
            block_on(store.repository().list_proxy_nodes()).unwrap(),
            Vec::<ProxyNodeRecord>::new()
        );
        remove_database_artifacts(&path);
    }
}

#[test]
fn future_go_schema_version_fails_closed_and_retries_after_contract_upgrade() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
        connection
            .execute("UPDATE metadata SET value = '8' WHERE key = 'schema_version'")
            .unwrap();
    }

    let error = match block_on(ConfigStore::open(&path)) {
        Ok(_) => panic!("future Go schema must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    assert!(error.message.contains("unsupported Go schema version 8"));
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert!(!meta_flag(&connection, "go_schema_imported"));
        assert_eq!(table_row_count(&connection, "proxy_nodes").unwrap(), 0);
        assert_eq!(table_row_count(&connection, "dns_resolvers").unwrap(), 0);
        connection
            .execute("UPDATE metadata SET value = '6' WHERE key = 'schema_version'")
            .unwrap();
    }

    let store = block_on(ConfigStore::open(&path)).unwrap();
    let connection = Connection::open(path.to_str().unwrap()).unwrap();
    assert!(meta_flag(&connection, "go_schema_imported"));
    assert_eq!(
        block_on(store.repository().list_proxy_nodes())
            .unwrap()
            .len(),
        1
    );
    assert!(
        block_on(store.repository().get_nat_config_or_default("default"))
            .unwrap()
            .full_cone,
        "repairing a future Go schema must retain Full Cone NAT defaults"
    );
    remove_database_artifacts(&path);
}
#[test]
fn future_go_migration_version_without_metadata_fails_closed_and_retries() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
        connection
            .execute_batch(
                "DELETE FROM metadata WHERE key = 'schema_version';
                 UPDATE migrate SET version = 8 WHERE version = 6;",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open(&path)) {
        Ok(_) => panic!("future Go migration version must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    assert!(error.message.contains("unsupported Go schema version 8"));
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert!(!meta_flag(&connection, "go_schema_imported"));
        connection
            .execute("UPDATE migrate SET version = 6 WHERE version = 8")
            .unwrap();
    }

    let store = block_on(ConfigStore::open(&path)).unwrap();
    assert_eq!(
        block_on(store.repository().list_proxy_nodes())
            .unwrap()
            .len(),
        1
    );
    remove_database_artifacts(&path);
}

#[test]
fn hidden_negative_go_migration_version_fails_closed_and_retries() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
        connection
            .execute_batch(
                "INSERT INTO migrate (version, name, applied_at)
                     VALUES (-1, 'corrupt_negative_version', 0);",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open(&path)) {
        Ok(_) => panic!("a hidden negative Go migration version must fail closed"),
        Err(error) => error,
    };
    assert!(error.message.contains("must not be negative"));
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert!(!meta_flag(&connection, "go_schema_imported"));
        assert_eq!(table_row_count(&connection, "proxy_nodes").unwrap(), 0);
        connection
            .execute_batch("DELETE FROM migrate WHERE version = -1;")
            .unwrap();
    }

    let store = block_on(ConfigStore::open(&path)).unwrap();
    assert!(
        block_on(store.repository().get_nat_config_or_default("default"))
            .unwrap()
            .full_cone,
        "repairing a hidden negative Go migration version must retain Full Cone NAT defaults"
    );
    remove_database_artifacts(&path);
}

#[test]
fn go_metadata_and_migrate_versions_must_agree_and_be_supported() {
    let cases = [
        (
            "INSERT INTO migrate (version, name, applied_at)
                 VALUES (8, 'future_version', 0);",
            "DELETE FROM migrate WHERE version = 8;",
            "unsupported Go schema version 8",
        ),
        (
            "UPDATE metadata SET value = '5' WHERE key = 'schema_version';",
            "UPDATE metadata SET value = '6' WHERE key = 'schema_version';",
            "does not match migrate version",
        ),
    ];

    for (corrupt, repair, expected_message) in cases {
        let path = test_database_path();
        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            connection
                .execute_batch(include_str!(
                    "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
                ))
                .unwrap();
            connection.execute_batch(corrupt).unwrap();
        }

        let error = match block_on(ConfigStore::open(&path)) {
            Ok(_) => panic!("metadata/migrate version corruption must fail closed"),
            Err(error) => error,
        };
        assert!(
            error.message.contains(expected_message),
            "unexpected migration version error: {}",
            error.message
        );
        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            assert!(!meta_flag(&connection, "go_schema_imported"));
            assert_eq!(table_row_count(&connection, "proxy_nodes").unwrap(), 0);
            connection.execute_batch(repair).unwrap();
        }

        let store = block_on(ConfigStore::open(&path)).unwrap();
        assert!(
            block_on(store.repository().get_nat_config_or_default("default"))
                .unwrap()
                .full_cone,
            "repairing metadata/migrate version corruption must retain Full Cone NAT defaults"
        );
        remove_database_artifacts(&path);
    }
}

#[test]
fn malformed_go_migration_version_type_fails_closed_and_retries_after_repair() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
        connection
            .execute_batch(
                "DELETE FROM metadata WHERE key = 'schema_version';
                 DROP TABLE migrate;
                 CREATE TABLE migrate (version TEXT NOT NULL);
                 INSERT INTO migrate VALUES ('6');",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open(&path)) {
        Ok(_) => panic!("malformed Go migration version type must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    assert!(error.message.contains("migrate.version must be an integer"));
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert!(!meta_flag(&connection, "go_schema_imported"));
        connection
            .execute_batch(
                "DROP TABLE migrate;
                 CREATE TABLE migrate (version INTEGER NOT NULL);
                 INSERT INTO migrate VALUES (6);",
            )
            .unwrap();
    }

    let store = block_on(ConfigStore::open(&path)).unwrap();
    assert_eq!(
        block_on(store.repository().list_proxy_nodes())
            .unwrap()
            .len(),
        1
    );
    remove_database_artifacts(&path);
}

#[test]
fn each_go_v6_import_table_failure_rolls_back_all_typed_rows() {
    let cases = [
        (
            "nodes_v2",
            "UPDATE nodes_v2 SET id = X'01'",
            "UPDATE nodes_v2 SET id = 'node-prod'",
        ),
        (
            "resolvers_v2",
            "UPDATE resolvers_v2 SET resolver_type = X'01'",
            "UPDATE resolvers_v2 SET resolver_type = 'doh'",
        ),
        (
            "route_rules_v2",
            "UPDATE route_rules_v2 SET priority = 'not-an-integer'",
            "UPDATE route_rules_v2 SET priority = 10",
        ),
        (
            "inbounds_v2",
            "UPDATE inbounds_v2 SET id = X'01'",
            "UPDATE inbounds_v2 SET id = 'tun-main'",
        ),
        (
            "node_tags_v2",
            "UPDATE node_tags_v2 SET id = X'01'",
            "UPDATE node_tags_v2 SET id = 'tag-prod'",
        ),
        (
            "route_lists_v2",
            "UPDATE route_lists_v2 SET name = X'01'",
            "UPDATE route_lists_v2 SET name = 'remote-prod'",
        ),
    ];

    for (table, corrupt, repair) in cases {
        let path = test_database_path();
        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            connection
                .execute_batch(include_str!(
                    "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
                ))
                .unwrap();
            connection.execute(corrupt).unwrap();
        }

        assert!(
            block_on(ConfigStore::open(&path)).is_err(),
            "corrupt {table} row must fail closed"
        );
        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            assert!(!meta_flag(&connection, "go_schema_imported"));
            for typed_table in ["proxy_nodes", "dns_resolvers", "route_rules"] {
                assert_eq!(
                    table_row_count(&connection, typed_table).unwrap(),
                    0,
                    "{typed_table} must roll back after {table} failure"
                );
            }
            assert!(
                connection
                    .query("SELECT key FROM yuhaiin_config WHERE key LIKE 'go.%'")
                    .unwrap()
                    .is_empty(),
                "Go config rows must roll back after {table} failure"
            );
            connection.execute(repair).unwrap();
        }

        let store = block_on(ConfigStore::open(&path)).unwrap();
        assert!(meta_flag(
            &Connection::open(path.to_str().unwrap()).unwrap(),
            "go_schema_imported"
        ));
        assert!(
            !block_on(store.repository().list_proxy_nodes())
                .unwrap()
                .is_empty()
        );
        remove_database_artifacts(&path);
    }

    // TEXT affinity makes a malformed value hard to inject into the
    // production table, so exercise the same importer boundary with a
    // schema-compatible but incorrectly typed replacement table.
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
        connection
            .execute_batch(
                "DROP TABLE settings_json;
                 CREATE TABLE settings_json (
                     id INTEGER PRIMARY KEY,
                     version INTEGER NOT NULL,
                     data_json INTEGER NOT NULL,
                     updated_at INTEGER NOT NULL
                 );
                 INSERT INTO settings_json VALUES (1, 12, 7, 200);",
            )
            .unwrap();
    }
    assert!(block_on(ConfigStore::open(&path)).is_err());
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert!(!meta_flag(&connection, "go_schema_imported"));
        assert_eq!(table_row_count(&connection, "proxy_nodes").unwrap(), 0);
        connection
            .execute_batch(
                "DROP TABLE settings_json;
                 CREATE TABLE settings_json (
                     id INTEGER PRIMARY KEY,
                     version INTEGER NOT NULL,
                     data_json TEXT NOT NULL,
                     updated_at INTEGER NOT NULL
                 );
                 INSERT INTO settings_json VALUES
                     (1, 12, '{\"mode\":\"proxy\"}', 200);",
            )
            .unwrap();
    }
    let store = block_on(ConfigStore::open(&path)).unwrap();
    assert!(meta_flag(
        &Connection::open(path.to_str().unwrap()).unwrap(),
        "go_schema_imported"
    ));
    assert!(
        block_on(store.get_config("go.settings_json"))
            .unwrap()
            .is_some()
    );
    remove_database_artifacts(&path);
}

#[test]
fn go_v6_import_missing_column_fails_closed_and_retries_after_schema_repair() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
        connection
            .execute_batch(
                "ALTER TABLE nodes_v2 RENAME TO nodes_v2_broken;
                 CREATE TABLE nodes_v2 (
                     id TEXT PRIMARY KEY NOT NULL,
                     chain_types_json TEXT NOT NULL
                 );",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open(&path)) {
        Ok(_) => panic!("missing Go v6 compatibility column must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert!(!meta_flag(&connection, "go_schema_imported"));
        assert_eq!(table_row_count(&connection, "proxy_nodes").unwrap(), 0);
        connection
            .execute_batch(
                "DROP TABLE nodes_v2;
                 ALTER TABLE nodes_v2_broken RENAME TO nodes_v2;",
            )
            .unwrap();
    }

    let store = block_on(ConfigStore::open(&path)).unwrap();
    assert!(meta_flag(
        &Connection::open(path.to_str().unwrap()).unwrap(),
        "go_schema_imported"
    ));
    assert_eq!(
        block_on(store.repository().list_proxy_nodes())
            .unwrap()
            .len(),
        1
    );
    remove_database_artifacts(&path);
}

#[test]
fn each_go_v6_missing_required_column_fails_closed_and_retries() {
    let cases = [
        (
            "nodes_v2",
            "CREATE TABLE nodes_v2 (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, group_name TEXT NOT NULL,
                origin TEXT NOT NULL, enabled INTEGER NOT NULL,
                chain_types_json TEXT NOT NULL, updated_at INTEGER NOT NULL
            )",
        ),
        (
            "resolvers_v2",
            "CREATE TABLE resolvers_v2 (
                id TEXT PRIMARY KEY, resolver_type TEXT NOT NULL, host TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )",
        ),
        (
            "route_rules_v2",
            "CREATE TABLE route_rules_v2 (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, priority INTEGER NOT NULL,
                disabled INTEGER NOT NULL, action_mode TEXT NOT NULL,
                match_type TEXT NOT NULL, tag TEXT NOT NULL, updated_at INTEGER NOT NULL
            )",
        ),
        (
            "inbounds_v2",
            "CREATE TABLE inbounds_v2 (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, enabled INTEGER NOT NULL,
                network_type TEXT NOT NULL, protocol_type TEXT NOT NULL,
                transport_types_json TEXT NOT NULL, updated_at INTEGER NOT NULL
            )",
        ),
        (
            "node_tags_v2",
            "CREATE TABLE node_tags_v2 (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, updated_at INTEGER NOT NULL
            )",
        ),
        (
            "route_lists_v2",
            "CREATE TABLE route_lists_v2 (
                name TEXT PRIMARY KEY, list_type TEXT NOT NULL, source_type TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )",
        ),
        (
            "settings_json",
            "CREATE TABLE settings_json (
                id INTEGER PRIMARY KEY, version INTEGER NOT NULL, updated_at INTEGER NOT NULL
            )",
        ),
    ];

    for (table, broken_schema) in cases {
        let path = test_database_path();
        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            connection
                .execute_batch(include_str!(
                    "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
                ))
                .unwrap();
            connection
                .execute(&format!("ALTER TABLE {table} RENAME TO {table}_original"))
                .unwrap();
            connection.execute(broken_schema).unwrap();
        }

        let error = match block_on(ConfigStore::open(&path)) {
            Ok(_) => panic!("missing Go v6 {table} column must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Storage);
        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            assert!(!meta_flag(&connection, "go_schema_imported"));
            for typed_table in ["proxy_nodes", "dns_resolvers", "route_rules"] {
                assert_eq!(
                    table_row_count(&connection, typed_table).unwrap(),
                    0,
                    "{typed_table} must roll back after {table} missing-column failure"
                );
            }
            connection
                .execute_batch(&format!(
                    "DROP TABLE {table}; ALTER TABLE {table}_original RENAME TO {table}"
                ))
                .unwrap();
        }

        let store = block_on(ConfigStore::open(&path)).unwrap();
        assert!(meta_flag(
            &Connection::open(path.to_str().unwrap()).unwrap(),
            "go_schema_imported"
        ));
        assert!(
            block_on(store.repository().get_nat_config_or_default("default"))
                .unwrap()
                .full_cone,
            "repairing {table} must retain Full Cone NAT defaults"
        );
        drop(store);
        remove_database_artifacts(&path);
    }
}

#[test]
fn go_v6_unknown_sql_columns_are_ignored_without_losing_known_rows() {
    let cases = [
        ("nodes_v2", "nodes"),
        ("resolvers_v2", "resolvers"),
        ("route_rules_v2", "route_rules"),
        ("inbounds_v2", "inbounds"),
        ("node_tags_v2", "node_tags"),
        ("route_lists_v2", "route_lists"),
        ("settings_json", "settings"),
    ];

    for (table, logical_table) in cases {
        let path = test_database_path();
        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            connection
                .execute_batch(include_str!(
                    "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
                ))
                .unwrap();
            connection
                .execute(&format!(
                    "ALTER TABLE {table} ADD COLUMN unknown_future_field TEXT"
                ))
                .unwrap();
        }

        let store = block_on(ConfigStore::open(&path)).unwrap();
        assert!(meta_flag(
            &Connection::open(path.to_str().unwrap()).unwrap(),
            "go_schema_imported"
        ));
        let repository = store.repository();
        match logical_table {
            "nodes" => assert_eq!(block_on(repository.list_go_nodes()).unwrap().len(), 1),
            "resolvers" => {
                assert_eq!(block_on(repository.list_go_resolvers()).unwrap().len(), 1)
            }
            "route_rules" => {
                assert_eq!(block_on(repository.list_go_route_rules()).unwrap().len(), 1)
            }
            "inbounds" => {
                assert_eq!(block_on(repository.list_go_inbounds()).unwrap().len(), 1)
            }
            "node_tags" => {
                assert_eq!(block_on(repository.list_go_node_tags()).unwrap().len(), 1)
            }
            "route_lists" => {
                assert_eq!(block_on(repository.list_go_route_lists()).unwrap().len(), 1)
            }
            "settings" => {
                assert!(
                    block_on(store.get_config("go.settings_json"))
                        .unwrap()
                        .is_some()
                )
            }
            _ => unreachable!("unknown Go v6 test table"),
        }
        assert!(
            block_on(store.repository().get_nat_config_or_default("default"))
                .unwrap()
                .full_cone,
            "unknown {table} column must retain Full Cone NAT defaults"
        );
        drop(store);
        remove_database_artifacts(&path);
    }
}

#[test]
fn invalid_go_v6_json_fails_closed_and_retries_after_repair() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
        connection
            .execute_with_params(
                "UPDATE nodes_v2 SET data_json = ?1 WHERE id = ?2",
                &[
                    SqliteValue::from("{not-json"),
                    SqliteValue::from("node-prod"),
                ],
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open(&path)) {
        Ok(_) => panic!("invalid Go v6 JSON must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert!(!meta_flag(&connection, "go_schema_imported"));
        assert_eq!(table_row_count(&connection, "proxy_nodes").unwrap(), 0);
        connection
            .execute_with_params(
                "UPDATE nodes_v2 SET data_json = ?1 WHERE id = ?2",
                &[
                    SqliteValue::from(
                        r#"{"name":"Production node","unknown_field":{"repaired":true}}"#,
                    ),
                    SqliteValue::from("node-prod"),
                ],
            )
            .unwrap();
    }

    let store = block_on(ConfigStore::open(&path)).unwrap();
    let nodes = block_on(store.repository().list_proxy_nodes()).unwrap();
    assert_eq!(nodes.len(), 1);
    assert!(String::from_utf8_lossy(&nodes[0].config).contains("repaired"));
    remove_database_artifacts(&path);
}

#[test]
fn invalid_go_v6_scalar_fields_fail_closed_and_retry_after_repair() {
    let cases = [
        (
            "nodes_v2.id",
            "UPDATE nodes_v2 SET id = '' WHERE id = 'node-prod'",
            "UPDATE nodes_v2 SET id = 'node-prod' WHERE id = ''",
        ),
        (
            "resolvers_v2.resolver_type",
            "UPDATE resolvers_v2 SET resolver_type = '' WHERE id = 'dns-prod'",
            "UPDATE resolvers_v2 SET resolver_type = 'doh' WHERE id = 'dns-prod'",
        ),
        (
            "route_rules_v2.match_type",
            "UPDATE route_rules_v2 SET match_type = '' WHERE id = 'rule-prod'",
            "UPDATE route_rules_v2 SET match_type = 'domain' WHERE id = 'rule-prod'",
        ),
        (
            "inbounds_v2.updated_at",
            "UPDATE inbounds_v2 SET updated_at = -1 WHERE id = 'tun-main'",
            "UPDATE inbounds_v2 SET updated_at = 204 WHERE id = 'tun-main'",
        ),
    ];

    for (field, corrupt, repair) in cases {
        let path = test_database_path();
        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            connection
                .execute_batch(include_str!(
                    "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
                ))
                .unwrap();
            connection.execute(corrupt).unwrap();
        }

        let error = match block_on(ConfigStore::open(&path)) {
            Ok(_) => panic!("invalid Go v6 scalar field {field} must fail closed"),
            Err(error) => error,
        };
        assert!(
            error.message.contains(field) || error.message.contains("must not be negative"),
            "unexpected {field} error: {}",
            error.message
        );
        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            assert!(!meta_flag(&connection, "go_schema_imported"));
            assert_eq!(table_row_count(&connection, "proxy_nodes").unwrap(), 0);
            connection.execute(repair).unwrap();
        }

        let store = block_on(ConfigStore::open(&path)).unwrap();
        assert!(meta_flag(
            &Connection::open(path.to_str().unwrap()).unwrap(),
            "go_schema_imported"
        ));
        assert!(
            block_on(store.repository().get_nat_config_or_default("default"))
                .unwrap()
                .full_cone,
            "repairing {field} must retain Full Cone NAT defaults"
        );
        drop(store);
        remove_database_artifacts(&path);
    }
}

#[test]
fn every_go_v6_compatibility_json_boundary_fails_closed_and_retries() {
    let cases = [
        ("nodes_v2", "chain_types_json", "{not-json", "[\"direct\"]"),
        (
            "nodes_v2",
            "data_json",
            "{not-json",
            "{\"name\":\"repaired-node\"}",
        ),
        (
            "inbounds_v2",
            "transport_types_json",
            "{not-json",
            "[\"tun\"]",
        ),
        (
            "inbounds_v2",
            "data_json",
            "{not-json",
            "{\"network\":\"tcpudp\"}",
        ),
        (
            "node_tags_v2",
            "members_json",
            "{not-json",
            "[\"node-prod\"]",
        ),
        (
            "resolvers_v2",
            "data_json",
            "{not-json",
            "{\"type\":\"doh\"}",
        ),
        (
            "route_rules_v2",
            "data_json",
            "{not-json",
            "{\"mode\":\"proxy\"}",
        ),
        (
            "route_lists_v2",
            "data_json",
            "{not-json",
            "{\"url\":\"https://rules.example/list\"}",
        ),
        (
            "settings_json",
            "data_json",
            "{not-json",
            "{\"mode\":\"proxy\"}",
        ),
    ];

    for (table, column, invalid, repaired) in cases {
        let path = test_database_path();
        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            connection
                .execute_batch(include_str!(
                    "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
                ))
                .unwrap();
            connection
                .execute_with_params(
                    &format!("UPDATE {table} SET {column} = ?1"),
                    &[SqliteValue::from(invalid)],
                )
                .unwrap();
        }

        let error = match block_on(ConfigStore::open(&path)) {
            Ok(_) => panic!("invalid {table}.{column} must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Storage);
        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            assert!(!meta_flag(&connection, "go_schema_imported"));
            assert_eq!(table_row_count(&connection, "proxy_nodes").unwrap(), 0);
            connection
                .execute_with_params(
                    &format!("UPDATE {table} SET {column} = ?1"),
                    &[SqliteValue::from(repaired)],
                )
                .unwrap();
        }

        let store = block_on(ConfigStore::open(&path)).unwrap();
        assert!(meta_flag(
            &Connection::open(path.to_str().unwrap()).unwrap(),
            "go_schema_imported"
        ));
        drop(store);
        remove_database_artifacts(&path);
    }
}

#[test]
#[ignore = "requires YUHAIIN_GO_PRODUCTION_DB pointing to a consistent FTS-free Go SQLite export"]
fn imports_real_go_production_snapshot_without_touching_source() {
    let source = std::env::var_os("YUHAIIN_GO_PRODUCTION_DB")
        .map(PathBuf::from)
        .expect("YUHAIIN_GO_PRODUCTION_DB must point to a copied/consistent Go snapshot");
    assert!(
        source.is_file(),
        "Go production snapshot does not exist: {}",
        source.display()
    );

    let path = test_database_path().with_file_name(format!(
        "go-production-import-{}-{}.db",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::copy(&source, &path).expect("copy Go production snapshot");

    let store = block_on(ConfigStore::open(&path)).expect("open real Go snapshot with Rust");
    let repository = store.repository();
    assert_eq!(block_on(repository.list_go_nodes()).unwrap().len(), 206);
    assert_eq!(block_on(repository.list_go_resolvers()).unwrap().len(), 6);
    assert_eq!(block_on(repository.list_go_route_rules()).unwrap().len(), 6);
    assert_eq!(block_on(repository.list_go_inbounds()).unwrap().len(), 10);
    assert_eq!(block_on(repository.list_go_node_tags()).unwrap().len(), 9);
    assert_eq!(
        block_on(repository.list_go_route_lists()).unwrap().len(),
        10
    );

    let ipv4 = block_on(store.list_fakeip_entries(4, "10.0.0.0/16")).unwrap();
    let ipv6 = block_on(store.list_fakeip_entries(6, "fc00::/64")).unwrap();
    assert_eq!(ipv4.len(), 15_483);
    assert_eq!(ipv6.len(), 11_956);
    assert!(
        block_on(store.get_fakeip_cursor(4, "10.0.0.0/16"))
            .unwrap()
            .is_some()
    );
    assert!(
        block_on(store.get_fakeip_cursor(6, "fc00::/64"))
            .unwrap()
            .is_some()
    );
    remove_database_artifacts(&path);
}

#[test]
#[ignore = "requires a copied native Go v5 database"]
fn opens_native_go_v5_database_directly_and_keeps_source_unchanged() {
    let source = std::env::var_os("YUHAIIN_GO_NATIVE_DB")
        .map(PathBuf::from)
        .expect("YUHAIIN_GO_NATIVE_DB must point to a native Go database");
    assert!(source.is_file(), "native Go database does not exist");
    let source_hash = sha256_file(&source).expect("hash native Go source");
    let path = test_database_path().with_file_name(format!(
        "go-native-v5-direct-{}-{}.db",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::copy(&source, &path).expect("copy native Go database");

    let store = block_on(ConfigStore::open(&path)).expect("open native Go database directly");
    let repository = store.repository();
    assert!(!block_on(repository.list_go_nodes()).unwrap().is_empty());
    assert!(
        !block_on(store.list_fakeip_entries(4, "10.0.0.0/16"))
            .unwrap()
            .is_empty()
    );
    assert!(
        block_on(store.get_fakeip_cursor(4, "10.0.0.0/16"))
            .unwrap()
            .is_some()
    );
    assert_eq!(sha256_file(&source).unwrap(), source_hash);
    remove_database_artifacts(&path);
}

#[test]
#[ignore = "requires a freshly bootstrapped native Go v6 database"]
fn opens_native_go_v6_database_directly_and_keeps_source_unchanged() {
    let source = std::env::var_os("YUHAIIN_GO_NATIVE_V6_DB")
        .map(PathBuf::from)
        .expect("YUHAIIN_GO_NATIVE_V6_DB must point to a native Go v6 database");
    assert!(source.is_file(), "native Go v6 database does not exist");
    let source_hash = sha256_file(&source).expect("hash native Go v6 source");
    let path = test_database_path().with_file_name(format!(
        "go-native-v6-direct-{}-{}.db",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::copy(&source, &path).expect("copy native Go v6 database");

    let store = block_on(ConfigStore::open(&path)).expect("open native Go v6 database directly");
    let repository = store.repository();
    assert_eq!(block_on(repository.list_go_nodes()).unwrap().len(), 1);
    assert_eq!(block_on(repository.list_go_resolvers()).unwrap().len(), 1);
    assert_eq!(block_on(repository.list_go_route_rules()).unwrap().len(), 1);
    assert_eq!(
        block_on(store.list_fakeip_entries(4, "10.0.0.0/16"))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        block_on(store.list_fakeip_entries(6, "fd00::/16"))
            .unwrap()
            .len(),
        1
    );
    assert!(
        block_on(store.get_fakeip_cursor(4, "10.0.0.0/16"))
            .unwrap()
            .is_some()
    );
    assert!(
        block_on(store.get_fakeip_cursor(6, "fd00::/16"))
            .unwrap()
            .is_some()
    );
    assert_eq!(store.status().unwrap().go_schema_version, Some(6));
    assert_eq!(sha256_file(&source).unwrap(), source_hash);
    remove_database_artifacts(&path);
}

#[test]
fn imports_go_v6_fixture_into_typed_records_idempotently() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_minimal.sql"
            ))
            .unwrap();
    }

    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let repository = store.repository();
        let nodes = block_on(repository.list_proxy_nodes()).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "node-a");
        assert_eq!(nodes[0].kind, "go-node");
        assert!(String::from_utf8_lossy(&nodes[0].config).contains("yuubinsya"));

        let resolvers = block_on(repository.list_dns_resolvers()).unwrap();
        assert_eq!(resolvers[0].id, "dns-udp");
        assert_eq!(resolvers[0].kind, "udp");

        let rules = block_on(repository.list_route_rules()).unwrap();
        assert_eq!(rules[0].action, "proxy");
        assert_eq!(rules[0].priority, 10);

        assert!(
            block_on(store.get_config("go.inbound.tun-main"))
                .unwrap()
                .is_some()
        );
        assert!(
            block_on(store.get_config("go.settings_json"))
                .unwrap()
                .is_some()
        );
    }

    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        let rows = connection
            .query("SELECT value FROM yuhaiin_meta WHERE key = 'go_schema_version'")
            .unwrap();
        assert_eq!(rows[0].get(0), Some(&SqliteValue::Integer(6)));
    }
    remove_database_artifacts(&path);
}

#[test]
fn imports_production_shaped_go_snapshot_without_losing_legacy_tables() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
        connection
            .execute(
                "INSERT INTO settings_kv(section, key, value_json, updated_at)
                 VALUES ('general', 'ipv6', 'true', 210),
                        ('general', 'use_default_interface', 'false', 210),
                        ('general', 'net_interface', '\"eth0\"', 210),
                        ('advanced', 'relay_buffer_size', '8192', 210),
                        ('logcat', 'level', '3', 210)",
            )
            .unwrap();
        connection.close().unwrap();
    }

    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let repository = store.repository();
        let settings = block_on(repository.list_go_settings_kv()).unwrap();
        assert!(settings.iter().any(|value| {
            value.section == "general" && value.key == "ipv6" && value.value_json == "true"
        }));
        assert!(settings.iter().any(|value| {
            value.section == "advanced"
                && value.key == "relay_buffer_size"
                && value.value_json == "8192"
        }));
        block_on(repository.put_go_settings_kv(&[GoSettingsKvRecord {
            section: "general".to_owned(),
            key: "ipv6".to_owned(),
            value_json: "false".to_owned(),
        }]))
        .unwrap();
        assert!(
            block_on(repository.list_go_settings_kv())
                .unwrap()
                .iter()
                .any(|value| {
                    value.section == "general" && value.key == "ipv6" && value.value_json == "false"
                })
        );
        let imported_dns_settings = block_on(repository.list_go_dns_settings()).unwrap();
        assert_eq!(imported_dns_settings[0].server, "dns-udp");
        let nodes = block_on(repository.list_proxy_nodes()).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "node-prod");
        assert!(String::from_utf8_lossy(&nodes[0].config).contains("unknown_field"));

        let go_nodes = block_on(repository.list_go_nodes()).unwrap();
        assert_eq!(go_nodes.len(), 1);
        assert_eq!(go_nodes[0].name, "Production node");
        assert_eq!(go_nodes[0].group_name, "remote");
        assert!(go_nodes[0].enabled);
        assert_eq!(go_nodes[0].updated_at, 201);
        assert!(String::from_utf8_lossy(&go_nodes[0].data_json).contains("unknown_field"));
        let proxy_runtime = block_on(repository.list_go_proxy_runtime_configs()).unwrap();
        assert_eq!(proxy_runtime.len(), 1);
        assert_eq!(proxy_runtime[0].transport, GoProxyTransport::Yuubinsya);
        assert_eq!(proxy_runtime[0].chain_types, vec!["yuubinsya", "tls"]);

        let go_tags = block_on(repository.list_go_node_tags()).unwrap();
        assert_eq!(go_tags.len(), 1);
        assert_eq!(go_tags[0].name, "production");
        assert!(String::from_utf8_lossy(&go_tags[0].members_json).contains("node-prod"));

        let resolvers = block_on(repository.list_dns_resolvers()).unwrap();
        assert_eq!(resolvers.len(), 1);
        assert_eq!(resolvers[0].id, "dns-prod");
        assert_eq!(resolvers[0].kind, "doh");

        let go_resolvers = block_on(repository.list_go_resolvers()).unwrap();
        assert_eq!(go_resolvers.len(), 1);
        assert_eq!(go_resolvers[0].host, "https://dns.example/dns-query");
        assert_eq!(go_resolvers[0].updated_at, 203);
        let resolver_runtime = block_on(repository.list_go_resolver_runtime_configs()).unwrap();
        assert_eq!(resolver_runtime.len(), 1);
        assert_eq!(resolver_runtime[0].id, "dns-prod");
        assert_eq!(resolver_runtime[0].transport, GoResolverTransport::Doh);
        assert_eq!(resolver_runtime[0].host, "https://dns.example/dns-query");

        let go_hosts = block_on(repository.list_go_dns_hosts()).unwrap();
        assert_eq!(go_hosts.len(), 1);
        assert_eq!(go_hosts[0].host, "legacy.example");
        assert_eq!(go_hosts[0].target, "192.0.2.10");
        let hosts = block_on(repository.load_go_dns_hosts_table()).unwrap();
        assert_eq!(
            hosts
                .resolve(&yuhaiin_core::DomainName::new("legacy.example").unwrap())
                .unwrap()
                .unwrap()
                .v4,
            vec!["192.0.2.10".parse::<std::net::Ipv4Addr>().unwrap()]
        );

        let dns_settings = block_on(repository.list_go_dns_settings()).unwrap();
        assert_eq!(dns_settings.len(), 1);
        assert_eq!(dns_settings[0].server, "dns-udp");
        assert!(dns_settings[0].fakedns_enabled);
        assert_eq!(dns_settings[0].fakedns_ipv4_range, "198.18.0.0/15");
        assert_eq!(dns_settings[0].fakedns_ipv6_range, "fc00::/18");
        block_on(repository.put_go_dns_server("127.0.0.1:5353")).unwrap();
        let updated_dns_settings = block_on(repository.list_go_dns_settings()).unwrap();
        assert_eq!(updated_dns_settings[0].server, "127.0.0.1:5353");
        assert!(updated_dns_settings[0].fakedns_enabled);
        let fakeip = block_on(repository.load_go_fakeip_runtime_config())
            .unwrap()
            .unwrap();
        assert!(fakeip.enabled);
        assert_eq!(
            fakeip.ipv4.start,
            "198.18.0.0".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(
            fakeip.ipv4.end,
            "198.19.255.255".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(
            fakeip.ipv6.start,
            "fc00::".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert_eq!(
            fakeip.ipv6.end,
            "fc00:3fff:ffff:ffff:ffff:ffff:ffff:ffff"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
        );

        let fakedns_lists = block_on(repository.list_go_dns_fakedns_lists()).unwrap();
        assert_eq!(fakedns_lists.len(), 1);
        assert_eq!(fakedns_lists[0].kind, "ipv4");
        assert_eq!(fakedns_lists[0].value, "198.18.0.0/15");

        let route_settings = block_on(repository.list_go_route_settings()).unwrap();
        assert_eq!(route_settings.len(), 1);
        assert_eq!(route_settings[0].direct_resolver, "system");
        assert_eq!(route_settings[0].proxy_resolver, "dns-prod");
        assert!(route_settings[0].resolve_locally);
        assert_eq!(route_settings[0].udp_proxy_fqdn, 0);
        let route_runtime = block_on(repository.load_go_route_runtime_config())
            .unwrap()
            .unwrap();
        assert_eq!(route_runtime.direct_resolver, "system");
        assert_eq!(route_runtime.proxy_resolver, "dns-prod");
        assert!(route_runtime.resolve_locally);
        assert_eq!(
            route_runtime.udp_proxy_fqdn,
            GoUdpProxyFqdnStrategy::Default
        );

        let rules = block_on(repository.list_route_rules()).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "rule-prod");
        assert!(String::from_utf8_lossy(&rules[0].resolver_policy).contains("unknown_field"));

        let go_rules = block_on(repository.list_go_route_rules()).unwrap();
        assert_eq!(go_rules.len(), 1);
        assert_eq!(go_rules[0].name, "production-domain");
        assert_eq!(go_rules[0].match_type, "domain");
        assert_eq!(go_rules[0].tag, "production");
        assert!(!go_rules[0].disabled);
        assert!(String::from_utf8_lossy(&go_rules[0].data_json).contains("unknown_field"));

        let go_lists = block_on(repository.list_go_route_lists()).unwrap();
        assert_eq!(go_lists.len(), 1);
        assert_eq!(go_lists[0].name, "remote-prod");
        assert_eq!(go_lists[0].source_type, "remote");
        let go_inbounds = block_on(repository.list_go_inbounds()).unwrap();
        assert_eq!(go_inbounds.len(), 1);
        assert_eq!(go_inbounds[0].id, "tun-main");
        assert!(go_inbounds[0].enabled);
        assert_eq!(go_inbounds[0].protocol_type, "tun");
        assert_eq!(go_inbounds[0].updated_at, 204);
        assert!(String::from_utf8_lossy(&go_inbounds[0].data_json).contains("unknown_field"));
        assert!(
            block_on(store.get_config("go.inbound.tun-main"))
                .unwrap()
                .is_some()
        );
        assert!(
            block_on(store.get_config("go.settings_json"))
                .unwrap()
                .unwrap()
                .windows(b"unknown".len())
                .any(|value| value == b"unknown")
        );
    }

    let connection = Connection::open(path.to_str().unwrap()).unwrap();
    assert_eq!(
        connection
            .query("SELECT COUNT(*) FROM settings_kv")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Integer(6))
    );
    assert_eq!(
        connection
            .query("SELECT value FROM dns_fakedns_lists WHERE kind = 'ipv4'")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Text("198.18.0.0/15".to_owned().into()))
    );
    assert_eq!(
        connection
            .query("SELECT data_json FROM subscriptions WHERE name = 'production'")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Text(
            r#"{"url":"https://rules.example/sub","unknown_subscription_field":true}"#
                .to_owned()
                .into()
        ))
    );
    assert_eq!(
        connection
            .query("SELECT proxy_resolver FROM route_settings WHERE id = 1")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Text("dns-prod".to_owned().into()))
    );
    assert_eq!(
        connection
            .query("SELECT COUNT(*) FROM fakeip_entries")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Integer(2))
    );
    assert_eq!(
        connection
            .query("SELECT COUNT(*) FROM route_lists_v2")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Integer(1))
    );
    assert_eq!(
        connection
            .query("SELECT COUNT(*) FROM telemetry_dimension_values")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Integer(1))
    );
    assert!(table_exists(&connection, "go_legacy_dns_resolvers"));
    assert!(table_exists(&connection, "go_legacy_route_rules"));
    assert_eq!(
        connection
            .query("SELECT value FROM yuhaiin_meta WHERE key = 'go_schema_version'")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Integer(6))
    );
    remove_database_artifacts(&path);
}
