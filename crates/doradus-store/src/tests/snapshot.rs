use super::super::*;
use super::*;

#[test]
fn installs_go_snapshot_atomically_and_keeps_source_unchanged() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let source = test_database_path().with_file_name(format!(
        "go-install-source-{}-{nonce}.db",
        std::process::id()
    ));
    let source_input = test_database_path().with_file_name(format!(
        "go-install-input-{}-{nonce}.db",
        std::process::id()
    ));
    let destination = test_database_path().with_file_name(format!(
        "go-install-destination-{}-{nonce}.db",
        std::process::id()
    ));
    let manifest = PathBuf::from(format!("{}.manifest.json", source.display()));
    {
        let connection = Connection::open(source_input.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
        let source_literal = source.to_string_lossy().replace('\'', "''");
        connection
            .execute(&format!("VACUUM INTO '{source_literal}'"))
            .unwrap();
        connection.close().unwrap();
    }
    let source_bytes = std::fs::metadata(&source).unwrap().len();
    let source_hash = sha256_file(&source).unwrap();
    std::fs::write(
        &manifest,
        serde_json::to_vec(&serde_json::json!({
            "format_version": 1,
            "tool": "doradus-export",
            "tool_version": "1",
            "source_schema_version": "6",
            "snapshot_sha256": source_hash,
            "snapshot_bytes": source_bytes,
            "fakeip_rows": 2,
            "removed_virtual_tables": null
        }))
        .unwrap(),
    )
    .unwrap();
    let report = block_on(install_go_snapshot_with_manifest(
        &source,
        &destination,
        &manifest,
    ))
    .unwrap();
    assert!(report.source_bytes > 0);
    assert!(report.destination_bytes > 0);
    assert!(destination.is_file());
    assert!(!PathBuf::from(format!("{}-wal", destination.display())).exists());

    {
        let source_connection = Connection::open(source.to_str().unwrap()).unwrap();
        assert!(!table_exists(&source_connection, "proxy_nodes"));
        assert_eq!(
            source_connection
                .query("SELECT value FROM metadata WHERE key = 'schema_version'")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Text("6".into()))
        );
    }

    {
        let store = block_on(ConfigStore::open_legacy(&destination)).unwrap();
        let nodes = block_on(store.repository().list_proxy_nodes()).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "node-prod");
        assert_eq!(
            block_on(store.list_fakeip_entries(4, "198.18.0.0/15"))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            block_on(store.list_fakeip_entries(6, "fc00::/18"))
                .unwrap()
                .len(),
            1
        );
    }
    assert!(
        block_on(install_go_snapshot(&source, &destination)).is_err(),
        "migration must not overwrite an existing destination"
    );
    let _ = std::fs::remove_file(&manifest);
    remove_database_artifacts(&source_input);
    remove_database_artifacts(&source);
    remove_database_artifacts(&destination);
}
#[test]
fn failed_go_snapshot_staging_cleans_up_and_retries_after_source_repair() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let source = test_database_path().with_file_name(format!(
        "go-install-retry-source-{}-{nonce}.db",
        std::process::id()
    ));
    let destination = test_database_path().with_file_name(format!(
        "go-install-retry-destination-{}-{nonce}.db",
        std::process::id()
    ));
    let manifest = PathBuf::from(format!("{}.manifest.json", source.display()));

    {
        let connection = Connection::open(source.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
        connection
            .execute("UPDATE nodes_v2 SET id = X'01'")
            .unwrap();
        connection.close().unwrap();
    }

    fn write_manifest(source: &Path, manifest: &Path) {
        let source_bytes = std::fs::metadata(source).unwrap().len();
        let source_hash = sha256_file(source).unwrap();
        std::fs::write(
            manifest,
            serde_json::to_vec(&GoSnapshotManifest {
                format_version: 1,
                tool: "doradus-export".to_owned(),
                tool_version: "1".to_owned(),
                source_schema_version: "6".to_owned(),
                snapshot_sha256: source_hash,
                snapshot_bytes: source_bytes,
                fakeip_rows: 2,
                removed_virtual_tables: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();
    }

    write_manifest(&source, &manifest);
    assert!(
        block_on(install_go_snapshot_with_manifest(
            &source,
            &destination,
            &manifest,
        ))
        .is_err()
    );
    assert!(!destination.exists());
    let staging_prefix = format!(
        ".{}.go-migration-",
        destination.file_name().unwrap().to_string_lossy()
    );
    assert!(
        !std::fs::read_dir(destination.parent().unwrap())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(&staging_prefix))
    );

    {
        let connection = Connection::open(source.to_str().unwrap()).unwrap();
        connection
            .execute("UPDATE nodes_v2 SET id = 'node-prod'")
            .unwrap();
        connection.close().unwrap();
    }
    write_manifest(&source, &manifest);
    let report = block_on(install_go_snapshot_with_manifest(
        &source,
        &destination,
        &manifest,
    ))
    .unwrap();
    assert!(report.destination_bytes > 0);
    assert!(destination.is_file());
    let store = block_on(ConfigStore::open_legacy(&destination)).unwrap();
    assert_eq!(
        block_on(store.repository().list_proxy_nodes())
            .unwrap()
            .len(),
        1
    );

    let _ = std::fs::remove_file(&manifest);
    remove_database_artifacts(&source);
    remove_database_artifacts(&destination);
}
#[test]
fn rejects_go_snapshot_with_manifest_hash_mismatch_before_copying() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let source = test_database_path().with_file_name(format!(
        "go-install-manifest-source-{}-{nonce}.db",
        std::process::id()
    ));
    let input = test_database_path().with_file_name(format!(
        "go-install-manifest-input-{}-{nonce}.db",
        std::process::id()
    ));
    let manifest = PathBuf::from(format!("{}.manifest.json", source.display()));
    let destination = test_database_path().with_file_name(format!(
        "go-install-manifest-destination-{}-{nonce}.db",
        std::process::id()
    ));
    {
        let connection = Connection::open(input.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
        let source_literal = source.to_string_lossy().replace('\'', "''");
        connection
            .execute(&format!("VACUUM INTO '{source_literal}'"))
            .unwrap();
        connection.close().unwrap();
    }
    let source_bytes = std::fs::metadata(&source).unwrap().len();
    std::fs::write(
        &manifest,
        serde_json::to_vec(&GoSnapshotManifest {
            format_version: 1,
            tool: "doradus-export".to_owned(),
            tool_version: "1".to_owned(),
            source_schema_version: "6".to_owned(),
            snapshot_sha256: "00".repeat(32),
            snapshot_bytes: source_bytes,
            fakeip_rows: 2,
            removed_virtual_tables: Vec::new(),
        })
        .unwrap(),
    )
    .unwrap();
    let error = block_on(install_go_snapshot_with_manifest(
        &source,
        &destination,
        &manifest,
    ))
    .unwrap_err();
    assert!(error.message.contains("SHA-256 mismatch"));
    assert!(!destination.exists());
    let _ = std::fs::remove_file(&manifest);
    remove_database_artifacts(&input);
    remove_database_artifacts(&source);
    remove_database_artifacts(&destination);
}

#[test]
fn rejects_go_snapshot_with_nonempty_wal_before_copying() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let source = test_database_path().with_file_name(format!(
        "go-install-wal-source-{}-{nonce}.db",
        std::process::id()
    ));
    let destination = test_database_path().with_file_name(format!(
        "go-install-wal-destination-{}-{nonce}.db",
        std::process::id()
    ));
    let connection = Connection::open(source.to_str().unwrap()).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO metadata VALUES ('schema_version', '6');",
        )
        .unwrap();
    connection.close().unwrap();
    // The installer rejects any non-empty WAL sidecar before copying. A
    // sentinel is sufficient here because the guard intentionally runs
    // before opening/replaying the source WAL.
    std::fs::write(
        format!("{}-wal", source.display()),
        b"non-empty WAL sentinel",
    )
    .unwrap();

    let error = block_on(install_go_snapshot(&source, &destination)).unwrap_err();
    assert!(error.message.contains("non-empty WAL"));
    assert!(!destination.exists());
    remove_database_artifacts(&source);
    remove_database_artifacts(&destination);
}

#[test]
fn failed_go_snapshot_does_not_remove_unrelated_destination_sidecar() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let source = test_database_path().with_file_name(format!(
        "go-install-invalid-source-{}-{nonce}.db",
        std::process::id()
    ));
    let destination = test_database_path().with_file_name(format!(
        "go-install-invalid-destination-{}-{nonce}.db",
        std::process::id()
    ));
    let destination_wal = PathBuf::from(format!("{}-wal", destination.display()));
    std::fs::write(&source, b"not a SQLite database").unwrap();
    std::fs::write(&destination_wal, b"external sidecar").unwrap();

    let error = block_on(install_go_snapshot(&source, &destination)).unwrap_err();
    assert!(error.message.contains("sidecar"));
    assert_eq!(
        std::fs::read(&destination_wal).unwrap(),
        b"external sidecar"
    );
    assert!(!destination.exists());

    remove_database_artifacts(&source);
    remove_database_artifacts(&destination);
}

#[test]
fn opens_go_v5_snapshot_without_discarding_unmodeled_telemetry() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v5_telemetry.sql"
            ))
            .unwrap();
    }

    {
        let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert_eq!(
            connection
                .query("SELECT value FROM doradus_meta WHERE key = 'go_schema_version'")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Integer(5))
        );
        assert_eq!(
            connection
                .query("SELECT COUNT(*) FROM traffic_dimension_hourly")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Integer(3))
        );
        assert_eq!(
            connection
                .query("SELECT COUNT(*) FROM failure_dimension_hourly")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Integer(1))
        );
        assert!(meta_flag(&connection, "go_schema_imported"));
        drop(store);
    }

    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    let connection = Connection::open(path.to_str().unwrap()).unwrap();
    assert_eq!(
        connection
            .query("SELECT value FROM doradus_meta WHERE key = 'go_schema_version'")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Integer(5))
    );
    assert!(meta_flag(&connection, "go_schema_imported"));
    drop(store);
    remove_database_artifacts(&path);
}

#[test]
fn opens_sparse_go_v5_fixture_preserving_empty_and_unmodeled_tables_across_reopen() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!("../../tests/fixtures/go_sqlite_v5_sparse.sql"))
            .unwrap();
    }

    for _ in 0..2 {
        let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert_eq!(
            connection
                .query("SELECT COUNT(*) FROM traffic_dimension_hourly")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Integer(0))
        );
        assert_eq!(
            connection
                .query("SELECT COUNT(*) FROM failure_dimension_hourly")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Integer(0))
        );
        assert_eq!(
            connection
                .query("SELECT payload FROM legacy_unmodeled WHERE key = 'sparse-row'")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Blob(vec![0x00, 0xff, 0x10, 0x65].into()))
        );
        let resolvers = block_on(store.repository().list_go_resolvers()).unwrap();
        assert_eq!(resolvers.len(), 1);
        assert!(String::from_utf8_lossy(&resolvers[0].data_json).contains("unknown_sparse_field"));
        drop(store);
    }
    remove_database_artifacts(&path);
}

#[test]
fn loads_statistics_from_go_v6_production_shape() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
    }

    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    let statistics = store.load_go_statistics().unwrap();
    assert_eq!(statistics.total_download, 0);
    assert_eq!(statistics.total_upload, 0);
    assert_eq!(statistics.traffic.len(), 0);
    assert_eq!(statistics.history.len(), 0);
    assert_eq!(statistics.failed_history.len(), 0);
    assert_eq!(statistics.telemetry.len(), 2);
    assert_eq!(statistics.telemetry[0].bucket, 0);
    assert_eq!(statistics.telemetry[0].download, 200);
    assert_eq!(statistics.telemetry[0].failures, 3);
    assert_eq!(statistics.telemetry[1].bucket, 1000);
    assert_eq!(statistics.telemetry[1].upload, 10);
    assert_eq!(statistics.telemetry[1].failures, 2);
    store.replace_go_statistics(&statistics).unwrap();
    // The Go projection keeps only recent hourly rows. Both fixture rows are
    // older than the 30-day retention window, so Rust must preserve their
    // values by folding them into the same UTC daily bucket on writeback.
    let projected = store.load_go_statistics().unwrap();
    assert_eq!(projected.telemetry.len(), 1);
    assert_eq!(projected.telemetry[0].bucket, 0);
    assert_eq!(projected.telemetry[0].download, 220);
    assert_eq!(projected.telemetry[0].upload, 110);
    assert_eq!(projected.telemetry[0].failures, 5);
    drop(store);
    remove_database_artifacts(&path);
}

#[test]
fn loads_and_replaces_legacy_go_v5_telemetry_tables() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v5_telemetry.sql"
            ))
            .unwrap();
    }

    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    let statistics = store.load_go_statistics().unwrap();
    assert_eq!(statistics.telemetry.len(), 3);
    assert_eq!(statistics.telemetry[0].dimension, "source");
    assert_eq!(statistics.telemetry[0].failures, 3);
    store.replace_go_statistics(&statistics).unwrap();
    let projected = store.load_go_statistics().unwrap();
    assert_eq!(projected.telemetry.len(), 3);
    assert!(
        projected
            .telemetry
            .iter()
            .all(|item| item.bucket == 1_699_920_000)
    );
    {
        let connection = store.lock_connection().unwrap();
        assert!(table_exists(&connection, "telemetry_dimension_values"));
        assert!(table_has_column(&connection, "traffic_dimension_hourly", "value_id").unwrap());
        assert!(!table_has_column(&connection, "traffic_dimension_hourly", "dimension").unwrap());
    }
    drop(store);
    remove_database_artifacts(&path);
}

#[test]
fn upgrades_go_v1_legacy_tables_with_explicit_mapping_and_archival_writeback() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!("../../tests/fixtures/go_sqlite_v1_legacy.sql"))
            .unwrap();
    }

    {
        let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
        let repository = store.repository();
        let resolvers = block_on(repository.list_go_resolvers()).unwrap();
        assert_eq!(resolvers.len(), 2);
        assert_eq!(resolvers[0].resolver_type, "system");
        assert_eq!(resolvers[0].host, "system default");
        assert_eq!(resolvers[1].resolver_type, "dot");
        assert!(
            String::from_utf8_lossy(&resolvers[1].data_json).contains("unknown_resolver_field")
        );

        let rules = block_on(repository.list_go_route_rules()).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "legacy-domain");
        assert_eq!(rules[0].priority, 1);
        assert_eq!(rules[0].action_mode, "proxy");
        assert_eq!(rules[0].match_type, "all");
        assert_eq!(rules[0].tag, "proxy-a");
        assert!(String::from_utf8_lossy(&rules[0].data_json).contains("unknown_route_field"));
        assert!(String::from_utf8_lossy(&rules[0].data_json).contains("\"type\":\"all\""));
        assert_eq!(rules[1].priority, 2);
        assert!(rules[1].disabled);

        let mut resolver = resolvers[1].clone();
        resolver.host = "dns.changed:853".to_owned();
        resolver.updated_at = 500;
        block_on(repository.put_go_resolver(&resolver)).unwrap();
        assert_eq!(
            block_on(repository.list_go_resolvers()).unwrap()[1].host,
            "dns.changed:853"
        );
    }

    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert!(table_exists(&connection, "go_legacy_dns_resolvers"));
        assert!(table_exists(&connection, "go_legacy_route_rules"));
        assert_eq!(
            connection
                .query("SELECT host FROM go_legacy_dns_resolvers WHERE name = 'legacy-dot'")
                .unwrap()[0]
                .get(0),
            Some(&SqliteValue::Text("dns.example:853".to_owned().into()))
        );
        assert!(meta_flag(&connection, "go_v1_resolvers_upgraded"));
        assert!(meta_flag(&connection, "go_v1_route_rules_upgraded"));
    }

    // A second open must not duplicate or rebuild the v2 rows, and the
    // archived v1 source remains unchanged after v2 writeback.
    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    let repository = store.repository();
    assert_eq!(block_on(repository.list_go_resolvers()).unwrap().len(), 2);
    assert_eq!(block_on(repository.list_go_route_rules()).unwrap().len(), 2);
    remove_database_artifacts(&path);
}

#[test]
fn failed_go_v1_upgrade_rolls_back_and_retries_after_json_repair() {
    let path = test_database_path();
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
                     host TEXT NOT NULL, subnet TEXT NOT NULL DEFAULT '',
                     tls_servername TEXT NOT NULL DEFAULT '', data_json TEXT NOT NULL
                 );
                 INSERT INTO dns_resolvers VALUES
                     ('dns-a', 1, '1.1.1.1:53', '', '', '{\"host\":\"1.1.1.1:53\"}');
                 CREATE TABLE route_rules (
                     id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE,
                     priority INTEGER, disabled INTEGER, updated_at INTEGER,
                     data_json TEXT NOT NULL
                 );
                 INSERT INTO route_rules VALUES
                     (1, 'bad', 1, 0, 100, '{\"mode\":\"invalid-mode\"}');",
            )
            .unwrap();
    }

    let error = match block_on(ConfigStore::open_legacy(&path)) {
        Ok(_) => panic!("invalid legacy route JSON must fail closed"),
        Err(error) => error,
    };
    assert_eq!(error.kind, ErrorKind::Storage);
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        assert!(
            connection
                .query("SELECT id FROM resolvers_v2")
                .unwrap()
                .is_empty()
        );
        connection
            .execute_with_params(
                "UPDATE go_legacy_route_rules SET data_json = ?1 WHERE name = ?2",
                &[
                    SqliteValue::from(br#"{"mode":"proxy","rules":[]}"#.as_slice()),
                    SqliteValue::from("bad"),
                ],
            )
            .unwrap();
    }

    let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
    let repository = store.repository();
    assert_eq!(block_on(repository.list_go_resolvers()).unwrap().len(), 1);
    assert_eq!(
        block_on(repository.list_go_route_rules()).unwrap()[0].action_mode,
        "proxy"
    );
    remove_database_artifacts(&path);
}

#[test]
fn go_v6_compatibility_views_support_typed_writeback_and_unknown_json() {
    let path = test_database_path();
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection
            .execute_batch(include_str!(
                "../../tests/fixtures/go_sqlite_v6_production_snapshot.sql"
            ))
            .unwrap();
    }

    let original_data;
    {
        let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
        let repository = store.repository();
        let mut inbound = block_on(repository.list_go_inbounds()).unwrap().remove(0);
        let mut node = block_on(repository.list_go_nodes()).unwrap().remove(0);
        let mut tag = block_on(repository.list_go_node_tags()).unwrap().remove(0);
        let mut resolver = block_on(repository.list_go_resolvers()).unwrap().remove(0);
        let mut rule = block_on(repository.list_go_route_rules())
            .unwrap()
            .remove(0);
        let mut list = block_on(repository.list_go_route_lists())
            .unwrap()
            .remove(0);
        original_data = (
            inbound.data_json.clone(),
            node.data_json.clone(),
            resolver.data_json.clone(),
            rule.data_json.clone(),
            list.data_json.clone(),
        );
        assert!(String::from_utf8_lossy(&original_data.2).contains("unknown_resolver_field"));
        assert!(String::from_utf8_lossy(&original_data.4).contains("unknown_list_field"));

        inbound.enabled = false;
        inbound.updated_at = 300;
        node.name = "Updated production node".to_owned();
        node.updated_at = 301;
        tag.members_json = br#"["node-prod","node-extra"]"#.to_vec();
        tag.updated_at = 302;
        resolver.host = "https://resolver.example/dns-query".to_owned();
        resolver.updated_at = 303;
        rule.priority = 20;
        rule.disabled = true;
        rule.updated_at = 304;
        list.source_type = "generated".to_owned();
        list.updated_at = 305;

        block_on(repository.put_go_inbound(&inbound)).unwrap();
        block_on(repository.put_go_node(&node)).unwrap();
        block_on(repository.put_go_node_tag(&tag)).unwrap();
        block_on(repository.put_go_resolver(&resolver)).unwrap();
        block_on(repository.put_go_route_rule(&rule)).unwrap();
        block_on(repository.put_go_route_list(&list)).unwrap();

        assert_eq!(block_on(repository.list_go_inbounds()).unwrap()[0], inbound);
        assert_eq!(block_on(repository.list_go_nodes()).unwrap()[0], node);
        assert_eq!(block_on(repository.list_go_node_tags()).unwrap()[0], tag);
        assert_eq!(
            block_on(repository.list_go_resolvers()).unwrap()[0],
            resolver
        );
        assert_eq!(block_on(repository.list_go_route_rules()).unwrap()[0], rule);
        assert_eq!(block_on(repository.list_go_route_lists()).unwrap()[0], list);

        let mut invalid = rule.clone();
        invalid.id.clear();
        assert_eq!(
            block_on(repository.put_go_route_rule(&invalid))
                .unwrap_err()
                .kind,
            ErrorKind::InvalidInput
        );

        let mut invalid_json = rule;
        invalid_json.data_json = b"not-json".to_vec();
        assert_eq!(
            block_on(repository.put_go_route_rule(&invalid_json))
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
    }

    {
        let store = block_on(ConfigStore::open_legacy(&path)).unwrap();
        let repository = store.repository();
        assert_eq!(
            block_on(repository.list_go_inbounds()).unwrap()[0].data_json,
            original_data.0
        );
        assert_eq!(
            block_on(repository.list_go_nodes()).unwrap()[0].data_json,
            original_data.1
        );
        assert_eq!(
            block_on(repository.list_go_resolvers()).unwrap()[0].data_json,
            original_data.2
        );
        assert_eq!(
            block_on(repository.list_go_route_rules()).unwrap()[0].data_json,
            original_data.3
        );
        assert_eq!(
            block_on(repository.list_go_route_lists()).unwrap()[0].data_json,
            original_data.4
        );

        assert!(block_on(repository.delete_go_inbound("tun-main")).unwrap());
        assert!(block_on(repository.delete_go_node("node-prod")).unwrap());
        assert!(block_on(repository.delete_go_node_tag("tag-prod")).unwrap());
        assert!(block_on(repository.delete_go_resolver("dns-prod")).unwrap());
        assert!(block_on(repository.delete_go_route_rule("rule-prod")).unwrap());
        assert!(block_on(repository.delete_go_route_list("remote-prod")).unwrap());
        assert!(!block_on(repository.delete_go_route_list("remote-prod")).unwrap());
        assert!(block_on(repository.list_go_inbounds()).unwrap().is_empty());
        assert!(block_on(repository.list_go_nodes()).unwrap().is_empty());
        assert!(block_on(repository.list_go_node_tags()).unwrap().is_empty());
        assert!(block_on(repository.list_go_resolvers()).unwrap().is_empty());
        assert!(
            block_on(repository.list_go_route_rules())
                .unwrap()
                .is_empty()
        );
        assert!(
            block_on(repository.list_go_route_lists())
                .unwrap()
                .is_empty()
        );
    }
    remove_database_artifacts(&path);
}

#[test]
fn go_writeback_rolls_back_when_compatibility_table_rejects_the_row() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    {
        let connection = store.lock_connection().unwrap();
        connection
            .execute_batch(
                "DROP TABLE route_lists_v2;
                CREATE TABLE route_lists_v2 (
                    name TEXT PRIMARY KEY NOT NULL,
                    list_type TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    data_json TEXT NOT NULL,
                    required_extra TEXT NOT NULL
                )",
            )
            .unwrap();
    }
    let repository = store.repository();
    let error = block_on(repository.put_go_route_list(&GoRouteListRecord {
        name: "rollback-list".to_owned(),
        list_type: "domain".to_owned(),
        source_type: "remote".to_owned(),
        updated_at: 1,
        data_json: b"{}".to_vec(),
    }))
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Storage);
    let connection = store.lock_connection().unwrap();
    assert!(
        connection
            .query("SELECT name FROM route_lists_v2")
            .unwrap()
            .is_empty()
    );
}
