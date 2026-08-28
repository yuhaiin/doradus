use super::super::*;
use super::*;

#[test]
fn truncated_database_fails_closed_instead_of_reinitializing_state() {
    let path = test_database_path();
    fs::write(&path, b"SQLite format 3\0\x00\x01truncated").unwrap();

    let error = match block_on(ConfigStore::open_legacy(&path)) {
        Ok(_) => panic!("truncated database must not be reinitialized"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    assert_eq!(
        fs::read(&path).unwrap(),
        b"SQLite format 3\0\x00\x01truncated"
    );

    remove_database_artifacts(&path);
}
#[test]
fn schema_v1_migrates_to_typed_v3_without_losing_legacy_config() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE doradus_meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value INTEGER NOT NULL
                );
                CREATE TABLE doradus_config (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                );
                INSERT INTO doradus_meta (key, value)
                    VALUES ('schema_version', 1);
                INSERT INTO doradus_config (key, value)
                    VALUES ('legacy.listen_port', X'31303830');",
            )
            .unwrap();
    }

    {
        let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
        assert_eq!(
            block_on(store.get_config("legacy.listen_port")).unwrap(),
            Some(b"1080".to_vec())
        );
        let repository = store.repository();
        block_on(repository.put_nat_config(&NatConfigRecord {
            key: "default".to_owned(),
            full_cone: true,
            idle_timeout_ms: 60_000,
        }))
        .unwrap();
        assert!(block_on(repository.list_nat_config()).unwrap()[0].full_cone);
    }

    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        let rows = connection
            .query("SELECT value FROM doradus_meta WHERE key = 'schema_version'")
            .unwrap();
        assert_eq!(rows[0].get(0), Some(&SqliteValue::Integer(3)));
        assert!(table_has_column(&connection, "route_rules", "geo_country").unwrap());
    }
    remove_database_artifacts(&path);
}

#[test]
fn fresh_doradus_database_uses_doradus_metadata_only() {
    let path = test_database_path();
    let store = block_on(ConfigStore::open(&path)).unwrap();
    drop(store);

    let connection = Connection::open(path.to_str().unwrap()).unwrap();
    assert!(table_exists(&connection, "doradus_meta"));
    assert!(table_exists(&connection, "doradus_config"));
    assert!(!table_exists(&connection, "metadata"));
    assert!(!table_exists(&connection, "migrate"));
    assert!(table_exists(&connection, "inbound_settings"));
    assert!(
        connection
            .query("SELECT value FROM doradus_meta WHERE key = 'go_schema_imported'")
            .unwrap()
            .is_empty()
    );
    remove_database_artifacts(&path);
}

#[test]
fn normal_open_rejects_legacy_database_without_mutating_it() {
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
                INSERT INTO migrate (version) VALUES (6);",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open(&path)) {
        Ok(_) => panic!("normal Doradus startup must reject legacy databases"),
        Err(error) => error,
    };
    assert!(error.message.contains("legacy database detected"));
    let connection = Connection::open(path.to_str().unwrap()).unwrap();
    assert!(!table_exists(&connection, "doradus_meta"));
    assert!(!table_exists(&connection, "proxy_nodes"));
    remove_database_artifacts(&path);
}

#[test]
fn schema_v2_adds_geo_country_without_losing_existing_route_rules() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE doradus_meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value INTEGER NOT NULL
                );
                CREATE TABLE doradus_config (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                );
                INSERT INTO doradus_meta (key, value)
                    VALUES ('schema_version', 2);
                CREATE TABLE route_rules (
                    id TEXT PRIMARY KEY NOT NULL,
                    pattern TEXT NOT NULL,
                    action TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    resolver_policy BLOB NOT NULL
                );
                INSERT INTO route_rules
                    (id, pattern, action, priority, resolver_policy)
                    VALUES ('legacy-rule', 'example.com', 'proxy', 5, X'66616b656970');",
            )
            .unwrap();
    }

    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    let repository = store.repository();
    let old = block_on(repository.list_route_rules()).unwrap();
    assert_eq!(old[0].id, "legacy-rule");
    assert_eq!(old[0].geo_country, None);
    block_on(repository.put_route_rule(&RouteRuleRecord {
        id: "legacy-rule".to_owned(),
        pattern: "example.com".to_owned(),
        action: "proxy".to_owned(),
        priority: 5,
        geo_country: Some("CN".to_owned()),
        resolver_policy: b"fakeip".to_vec(),
    }))
    .unwrap();
    assert_eq!(
        block_on(repository.list_route_rules()).unwrap()[0]
            .geo_country
            .as_deref(),
        Some("CN")
    );
    let connection = Connection::open(path.to_str().unwrap()).unwrap();
    assert_eq!(
        connection
            .query("SELECT value FROM doradus_meta WHERE key = 'schema_version'")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Integer(3))
    );
    remove_database_artifacts(&path);
}

#[test]
fn schema_v2_geo_migration_failure_rolls_back_and_retries_after_repair() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE doradus_meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value INTEGER NOT NULL
                );
                CREATE TABLE doradus_config (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                );
                INSERT INTO doradus_meta (key, value)
                    VALUES ('schema_version', 2);
                CREATE VIEW route_rules AS
                    SELECT
                        'view-rule' AS id,
                        'example.com' AS pattern,
                        'proxy' AS action,
                        5 AS priority,
                        X'66616b656970' AS resolver_policy;
                INSERT INTO doradus_config (key, value)
                    VALUES ('legacy.keep', X'6f6b');",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open_legacy(&path)) {
        Ok(_) => panic!("schema v2 migration through a view must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert_eq!(
            connection
                .query("SELECT value FROM doradus_meta WHERE key = 'schema_version'")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Integer(2))
        );
        assert!(!table_exists(&connection, "route_rules"));
        assert!(
            !connection
                .query("SELECT 1 FROM sqlite_master WHERE type = 'view' AND name = 'route_rules'")
                .unwrap()
                .is_empty()
        );
        assert!(!table_has_column(&connection, "route_rules", "geo_country").unwrap());
        assert_eq!(
            connection
                .query("SELECT value FROM doradus_config WHERE key = 'legacy.keep'")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Blob(b"ok".to_vec().into()))
        );
        connection.execute("DROP VIEW route_rules").unwrap();
        connection
            .execute_batch(
                "CREATE TABLE route_rules (
                    id TEXT PRIMARY KEY NOT NULL,
                    pattern TEXT NOT NULL,
                    action TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    resolver_policy BLOB NOT NULL
                );
                INSERT INTO route_rules
                    (id, pattern, action, priority, resolver_policy)
                    VALUES ('repaired-rule', 'example.com', 'proxy', 5, X'66616b656970');",
            )
            .unwrap();
    }

    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    assert_eq!(
        block_on(store.get_config("legacy.keep")).unwrap(),
        Some(b"ok".to_vec())
    );
    let rules = block_on(store.repository().list_route_rules()).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, "repaired-rule");
    assert_eq!(rules[0].geo_country, None);
    assert!(
        block_on(store.repository().get_nat_config_or_default("default"))
            .unwrap()
            .full_cone,
        "schema repair must retain Full Cone NAT default semantics"
    );
    remove_database_artifacts(&path);
}

#[test]
fn legacy_table_rename_collision_rolls_back_and_retries_after_repair() {
    let path = test_database_path().with_file_name(format!(
        "legacy-dns-rename-collision-{}-{}.db",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE migrate (version INTEGER PRIMARY KEY, name TEXT NOT NULL);
                 INSERT INTO metadata VALUES ('schema_version', '1');
                 INSERT INTO migrate VALUES (1, 'initial_schema');
                 CREATE TABLE dns_resolvers (
                     name TEXT PRIMARY KEY, resolver_type INTEGER NOT NULL,
                     host TEXT NOT NULL, subnet TEXT NOT NULL,
                     tls_servername TEXT NOT NULL, data_json TEXT NOT NULL
                 );
                 INSERT INTO dns_resolvers VALUES
                     ('collision-dns', 1, '192.0.2.53:53', '', '',
                      '{\"type\":\"udp\",\"unknown\":true}');
                 CREATE TABLE go_legacy_dns_resolvers (marker TEXT);",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open_legacy(&path)) {
        Ok(_) => panic!("legacy table rename collision must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    assert!(error.message.contains("both legacy and prepared"));
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert!(table_exists(&connection, "dns_resolvers"));
        assert!(table_exists(&connection, "go_legacy_dns_resolvers"));
        assert!(!table_exists(&connection, "doradus_meta"));
        assert_eq!(table_row_count(&connection, "dns_resolvers").unwrap(), 1);
        assert_eq!(
            connection
                .query("SELECT value FROM metadata WHERE key = 'schema_version'")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Text("1".to_owned().into()))
        );
    }

    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute("DROP TABLE go_legacy_dns_resolvers")
            .unwrap();
    }
    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    let resolvers = block_on(store.repository().list_go_resolvers()).unwrap();
    assert_eq!(resolvers.len(), 1);
    assert_eq!(resolvers[0].id, "collision-dns");
    assert!(
        block_on(store.repository().get_nat_config_or_default("default"))
            .unwrap()
            .full_cone
    );
    remove_database_artifacts(&path);
}

#[test]
fn legacy_route_table_rename_collision_rolls_back_and_retries_after_repair() {
    let path = test_database_path().with_file_name(format!(
        "legacy-route-rename-collision-{}-{}.db",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE migrate (version INTEGER PRIMARY KEY, name TEXT NOT NULL);
                 INSERT INTO metadata VALUES ('schema_version', '1');
                 INSERT INTO migrate VALUES (1, 'initial_schema');
                 CREATE TABLE route_rules (
                     id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE,
                     priority INTEGER, disabled INTEGER, updated_at INTEGER,
                     data_json TEXT NOT NULL
                 );
                 INSERT INTO route_rules VALUES
                     (1, 'collision-route', 10, 0, 100,
                      '{\"name\":\"collision-route\",\"mode\":\"proxy\",\"rules\":[]}');
                 CREATE TABLE go_legacy_route_rules (marker TEXT);",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open_legacy(&path)) {
        Ok(_) => panic!("legacy route table rename collision must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    assert!(error.message.contains("both legacy and prepared"));
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert!(table_exists(&connection, "route_rules"));
        assert!(table_exists(&connection, "go_legacy_route_rules"));
        assert!(!table_exists(&connection, "doradus_meta"));
        assert_eq!(table_row_count(&connection, "route_rules").unwrap(), 1);
    }

    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute("DROP TABLE go_legacy_route_rules")
            .unwrap();
    }
    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    let rules = block_on(store.repository().list_go_route_rules()).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "collision-route");
    assert_eq!(rules[0].action_mode, "proxy");
    assert!(
        block_on(store.repository().get_nat_config_or_default("default"))
            .unwrap()
            .full_cone
    );
    remove_database_artifacts(&path);
}

#[test]
fn legacy_table_rename_is_atomic_when_second_table_collides_and_retries() {
    let path = test_database_path().with_file_name(format!(
        "legacy-table-rename-atomic-{}-{}.db",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE migrate (version INTEGER PRIMARY KEY, name TEXT NOT NULL);
                 INSERT INTO metadata VALUES ('schema_version', '1');
                 INSERT INTO migrate VALUES (1, 'initial_schema');
                 CREATE TABLE dns_resolvers (
                     name TEXT PRIMARY KEY, resolver_type INTEGER NOT NULL,
                     host TEXT NOT NULL, subnet TEXT NOT NULL,
                     tls_servername TEXT NOT NULL, data_json TEXT NOT NULL
                 );
                 INSERT INTO dns_resolvers VALUES
                     ('atomic-dns', 1, '192.0.2.53:53', '', '',
                      '{\"type\":\"udp\"}');
                 CREATE TABLE route_rules (
                     id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE,
                     priority INTEGER, disabled INTEGER, updated_at INTEGER,
                     data_json TEXT NOT NULL
                 );
                 INSERT INTO route_rules VALUES
                     (1, 'atomic-route', 10, 0, 100,
                      '{\"name\":\"atomic-route\",\"mode\":\"proxy\",\"rules\":[]}');
                 CREATE TABLE go_legacy_route_rules (marker TEXT);",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open_legacy(&path)) {
        Ok(_) => panic!("second legacy table collision must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    assert!(error.message.contains("both legacy and prepared"));
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert!(table_exists(&connection, "dns_resolvers"));
        assert!(!table_exists(&connection, "go_legacy_dns_resolvers"));
        assert!(table_exists(&connection, "route_rules"));
        assert!(table_exists(&connection, "go_legacy_route_rules"));
        assert!(!table_exists(&connection, "doradus_meta"));
        assert_eq!(table_row_count(&connection, "dns_resolvers").unwrap(), 1);
        assert_eq!(table_row_count(&connection, "route_rules").unwrap(), 1);
    }

    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute("DROP TABLE go_legacy_route_rules")
            .unwrap();
    }
    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    let resolvers = block_on(store.repository().list_go_resolvers()).unwrap();
    let rules = block_on(store.repository().list_go_route_rules()).unwrap();
    assert_eq!(resolvers.len(), 1);
    assert_eq!(resolvers[0].id, "atomic-dns");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "atomic-route");
    assert!(
        block_on(store.repository().get_nat_config_or_default("default"))
            .unwrap()
            .full_cone
    );
    remove_database_artifacts(&path);
}

#[test]
fn malformed_typed_schema_rolls_back_version_and_repairs_on_retry() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE doradus_meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value INTEGER NOT NULL
                );
                CREATE TABLE doradus_config (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                );
                INSERT INTO doradus_meta (key, value)
                    VALUES ('schema_version', 1);
                CREATE TABLE nat_config (
                    key TEXT PRIMARY KEY NOT NULL,
                    full_cone INTEGER NOT NULL
                );
                INSERT INTO nat_config (key, full_cone)
                    VALUES ('default', 1);",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open_legacy(&path)) {
        Ok(_) => panic!("incomplete typed table must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert_eq!(
            connection
                .query("SELECT value FROM doradus_meta WHERE key = 'schema_version'")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Integer(1))
        );
        assert!(table_exists(&connection, "nat_config"));
        assert!(!table_exists(&connection, "proxy_nodes"));
        connection
            .execute(
                "ALTER TABLE nat_config
                 ADD COLUMN idle_timeout_ms INTEGER NOT NULL DEFAULT 60000",
            )
            .unwrap();
    }

    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    let records = block_on(store.repository().list_nat_config()).unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].full_cone);
    assert_eq!(records[0].idle_timeout_ms, 60_000);
    remove_database_artifacts(&path);
}

#[test]
fn typed_schema_contract_mismatch_fails_closed_and_repairs_on_retry() {
    let cases = [
        (
            "proxy_nodes.id primary key",
            "CREATE TABLE proxy_nodes (
                id TEXT NOT NULL,
                kind TEXT NOT NULL,
                config BLOB NOT NULL
            );",
            "CREATE TABLE proxy_nodes (
                id TEXT PRIMARY KEY NOT NULL,
                kind TEXT NOT NULL,
                config BLOB NOT NULL
            );",
            "proxy_nodes",
            "id",
        ),
        (
            "proxy_nodes.config type",
            "CREATE TABLE proxy_nodes (
                id TEXT PRIMARY KEY NOT NULL,
                kind TEXT NOT NULL,
                config TEXT NOT NULL
            );",
            "CREATE TABLE proxy_nodes (
                id TEXT PRIMARY KEY NOT NULL,
                kind TEXT NOT NULL,
                config BLOB NOT NULL
            );",
            "proxy_nodes",
            "config",
        ),
        (
            "nat_config.full_cone type",
            "CREATE TABLE nat_config (
                key TEXT PRIMARY KEY NOT NULL,
                full_cone TEXT NOT NULL,
                idle_timeout_ms INTEGER NOT NULL
            );",
            "CREATE TABLE nat_config (
                key TEXT PRIMARY KEY NOT NULL,
                full_cone INTEGER NOT NULL,
                idle_timeout_ms INTEGER NOT NULL
            );",
            "nat_config",
            "full_cone",
        ),
        (
            "route_rules.geo_country nullability",
            "CREATE TABLE route_rules (
                id TEXT PRIMARY KEY NOT NULL,
                pattern TEXT NOT NULL,
                action TEXT NOT NULL,
                priority INTEGER NOT NULL,
                geo_country TEXT NOT NULL,
                resolver_policy BLOB NOT NULL
            );",
            "CREATE TABLE route_rules (
                id TEXT PRIMARY KEY NOT NULL,
                pattern TEXT NOT NULL,
                action TEXT NOT NULL,
                priority INTEGER NOT NULL,
                geo_country TEXT,
                resolver_policy BLOB NOT NULL
            );",
            "route_rules",
            "geo_country",
        ),
    ];

    for (label, broken_sql, repaired_sql, table, column) in cases {
        let path = test_database_path();
        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            connection
                .execute_batch(&format!(
                    "CREATE TABLE doradus_meta (
                        key TEXT PRIMARY KEY NOT NULL,
                        value INTEGER NOT NULL
                    );
                    CREATE TABLE doradus_config (
                        key TEXT PRIMARY KEY NOT NULL,
                        value BLOB NOT NULL
                    );
                    INSERT INTO doradus_meta (key, value)
                        VALUES ('schema_version', 1);
                    {broken_sql}"
                ))
                .unwrap();
        }

        let error = match block_on(ConfigStore::open_legacy(&path)) {
            Ok(_) => panic!("{label} must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Storage, "{label}");
        assert!(
            error.message.contains(table) && error.message.contains(column),
            "{label} error should identify the failing table/column: {}",
            error.message
        );

        {
            let connection = Connection::open(path.to_str().unwrap()).unwrap();
            assert_eq!(
                connection
                    .query("SELECT value FROM doradus_meta WHERE key = 'schema_version'")
                    .unwrap()[0]
                    .get(0),
                Some(&SqliteValue::Integer(1)),
                "{label} must leave the migration version unchanged"
            );
            assert!(
                table_exists(&connection, table),
                "{label} must preserve the pre-existing table for repair"
            );
            connection
                .execute_batch(&format!("DROP TABLE {table};\n{repaired_sql}"))
                .unwrap();
        }

        let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
        let nat = block_on(store.repository().get_nat_config_or_default("default")).unwrap();
        assert!(
            nat.full_cone,
            "{label} repair must retain Full Cone NAT defaults"
        );
        remove_database_artifacts(&path);
    }
}

#[test]
fn base_schema_contract_mismatch_fails_closed_and_repairs_on_retry() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE doradus_meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value INTEGER NOT NULL
                );
                CREATE TABLE doradus_config (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                );
                INSERT INTO doradus_meta (key, value)
                    VALUES ('schema_version', 1);
                INSERT INTO doradus_config (key, value)
                    VALUES ('keep', 'before-repair');",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open_legacy(&path)) {
        Ok(_) => panic!("base doradus_config contract mismatch must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    assert!(error.message.contains("doradus_config"));
    assert!(error.message.contains("value"));
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert_eq!(
            connection
                .query("SELECT value FROM doradus_meta WHERE key = 'schema_version'")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Integer(1))
        );
        connection
            .execute_batch(
                "DROP TABLE doradus_config;
                CREATE TABLE doradus_config (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                );",
            )
            .unwrap();
    }

    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    block_on(store.put_config("after-repair", b"ok")).unwrap();
    assert_eq!(
        block_on(store.get_config("after-repair")).unwrap(),
        Some(b"ok".to_vec())
    );
    remove_database_artifacts(&path);
}

#[test]
fn fakeip_index_contract_mismatch_fails_closed_and_repairs_on_retry() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE doradus_meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value INTEGER NOT NULL
                );
                CREATE TABLE doradus_config (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                );
                INSERT INTO doradus_meta (key, value)
                    VALUES ('schema_version', 1);
                CREATE TABLE fakeip_entries (
                    family INTEGER NOT NULL,
                    prefix TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    ip BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    last_used_at INTEGER NOT NULL,
                    PRIMARY KEY (family, prefix, domain)
                );",
            )
            .unwrap();
        connection
            .execute(
                "CREATE INDEX fakeip_entries_ip_idx
                 ON fakeip_entries(family, prefix, domain)",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open_legacy(&path)) {
        Ok(_) => panic!("incompatible FakeIP reverse index must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    assert!(error.message.contains("fakeip_entries"));
    assert!(
        error
            .message
            .contains("incompatible uniqueness or column contract")
    );
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert_eq!(
            connection
                .query("SELECT value FROM doradus_meta WHERE key = 'schema_version'")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Integer(1))
        );
        connection
            .execute_batch(
                "DROP TABLE fakeip_entries;
                CREATE TABLE fakeip_entries (
                    family INTEGER NOT NULL,
                    prefix TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    ip BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    last_used_at INTEGER NOT NULL,
                    PRIMARY KEY (family, prefix, domain),
                    UNIQUE (family, prefix, ip)
                );",
            )
            .unwrap();
    }

    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    assert!(
        block_on(store.repository().get_nat_config_or_default("default"))
            .unwrap()
            .full_cone
    );
    remove_database_artifacts(&path);
}

#[test]
fn negative_rust_schema_version_fails_closed_without_creating_typed_tables() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE doradus_meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value INTEGER NOT NULL
                );
                CREATE TABLE doradus_config (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                );
                INSERT INTO doradus_meta (key, value)
                    VALUES ('schema_version', -1);",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open_legacy(&path)) {
        Ok(_) => panic!("negative Rust schema version must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    assert!(error.message.contains("unsupported schema version -1"));
    let connection = Connection::open(path.to_str().unwrap()).unwrap();
    assert_eq!(
        connection
            .query("SELECT value FROM doradus_meta WHERE key = 'schema_version'")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Integer(-1))
    );
    assert!(!table_exists(&connection, "proxy_nodes"));
    remove_database_artifacts(&path);
}

#[test]
fn typed_schema_index_conflict_rolls_back_and_retries_after_repair() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE doradus_meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value INTEGER NOT NULL
                );
                CREATE TABLE doradus_config (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                );
                INSERT INTO doradus_meta (key, value)
                    VALUES ('schema_version', 1);
                CREATE TABLE fakeip_entries_ip_idx (legacy_marker TEXT);",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open_legacy(&path)) {
        Ok(_) => panic!("typed schema index conflict must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert_eq!(
            connection
                .query("SELECT value FROM doradus_meta WHERE key = 'schema_version'")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Integer(1))
        );
        assert!(
            !table_exists(&connection, "fakeip_entries"),
            "DDL failure must roll back the table created before the conflicting index"
        );
        connection
            .execute("DROP TABLE fakeip_entries_ip_idx")
            .unwrap();
    }

    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    let repository = store.repository();
    assert!(
        block_on(repository.get_nat_config_or_default("default"))
            .unwrap()
            .full_cone,
        "repaired typed schema must retain Full Cone NAT defaults"
    );
    remove_database_artifacts(&path);
}

#[test]
fn future_schema_version_fails_closed_without_creating_typed_tables() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE doradus_meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value INTEGER NOT NULL
                );
                CREATE TABLE doradus_config (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                );
                INSERT INTO doradus_meta (key, value)
                    VALUES ('schema_version', 99);
                INSERT INTO doradus_config (key, value)
                    VALUES ('future.keep', X'6f6b');",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open_legacy(&path)) {
        Ok(_) => panic!("future schema must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    let connection = Connection::open(path.to_str().unwrap()).unwrap();
    assert_eq!(
        connection
            .query("SELECT value FROM doradus_meta WHERE key = 'schema_version'")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Integer(99))
    );
    assert_eq!(
        connection
            .query("SELECT value FROM doradus_config WHERE key = 'future.keep'")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Blob(std::sync::Arc::from(b"ok".as_slice())))
    );
    assert!(!table_exists(&connection, "proxy_nodes"));
    remove_database_artifacts(&path);
}

#[test]
fn partial_typed_migration_is_repaired_on_next_open() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE doradus_meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value INTEGER NOT NULL
                );
                CREATE TABLE doradus_config (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                );
                INSERT INTO doradus_meta (key, value)
                    VALUES ('schema_version', 1);
                CREATE TABLE proxy_nodes (
                    id TEXT PRIMARY KEY NOT NULL,
                    kind TEXT NOT NULL,
                    config BLOB NOT NULL
                );
                INSERT INTO doradus_config (key, value)
                    VALUES ('legacy.keep', X'6f6b');",
            )
            .unwrap();
    }

    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    assert_eq!(
        block_on(store.get_config("legacy.keep")).unwrap(),
        Some(b"ok".to_vec())
    );
    let repository = store.repository();
    block_on(repository.put_nat_config(&NatConfigRecord {
        key: "default".to_owned(),
        full_cone: true,
        idle_timeout_ms: 30_000,
    }))
    .unwrap();
    assert_eq!(block_on(repository.list_nat_config()).unwrap().len(), 1);
    remove_database_artifacts(&path);
}
