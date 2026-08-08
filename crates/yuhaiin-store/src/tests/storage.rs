use super::super::*;
use super::*;
use std::sync::{Arc, Barrier};

#[test]
fn config_round_trips_and_deletes() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    assert_eq!(block_on(store.get_config("missing")).unwrap(), None);
    block_on(store.put_config("listen_port", b"1080")).unwrap();
    assert_eq!(
        block_on(store.get_config("listen_port")).unwrap(),
        Some(b"1080".to_vec())
    );
    assert!(block_on(store.delete_config("listen_port")).unwrap());
    assert!(!block_on(store.delete_config("listen_port")).unwrap());
}
#[test]
fn sqlite_backup_restore_is_consistent_and_atomic() {
    let source = test_database_path();
    let backup = source.with_file_name(format!(
        "{}-backup",
        source.file_name().unwrap().to_string_lossy()
    ));
    let invalid = source.with_file_name(format!(
        "{}-invalid",
        source.file_name().unwrap().to_string_lossy()
    ));

    {
        let store = block_on(ConfigStore::open(&source)).unwrap();
        block_on(store.put_config("restore.original", b"yes")).unwrap();
        let report = block_on(store.backup_to(&backup)).unwrap();
        assert_eq!(report.source_bytes, report.destination_bytes);
        assert!(block_on(store.backup_to(&backup)).is_err());
        store.close().unwrap();
    }

    {
        let backup_store = block_on(ConfigStore::open(&backup)).unwrap();
        assert_eq!(
            block_on(backup_store.get_config("restore.original")).unwrap(),
            Some(b"yes".to_vec())
        );
        backup_store.close().unwrap();
    }

    {
        let store = block_on(ConfigStore::open(&source)).unwrap();
        block_on(store.put_config("restore.uncommitted", b"before-restore")).unwrap();
        store.close().unwrap();
    }

    fs::write(&invalid, b"not a SQLite database").unwrap();
    assert!(block_on(restore_database(&invalid, &source)).is_err());
    {
        let store = block_on(ConfigStore::open(&source)).unwrap();
        assert_eq!(
            block_on(store.get_config("restore.uncommitted")).unwrap(),
            Some(b"before-restore".to_vec())
        );
        store.close().unwrap();
    }

    let report = block_on(restore_database(&backup, &source)).unwrap();
    assert_eq!(report.source_bytes, report.destination_bytes);
    {
        let store = block_on(ConfigStore::open(&source)).unwrap();
        assert_eq!(
            block_on(store.get_config("restore.original")).unwrap(),
            Some(b"yes".to_vec())
        );
        assert_eq!(
            block_on(store.get_config("restore.uncommitted")).unwrap(),
            None
        );
        store.close().unwrap();
    }

    let sidecar_destination = source.with_file_name(format!(
        "{}-missing-destination",
        source.file_name().unwrap().to_string_lossy()
    ));
    let sidecar_path = PathBuf::from(format!("{}-wal", sidecar_destination.display()));
    fs::write(&sidecar_path, b"external sidecar").unwrap();
    let error = block_on(restore_database(&backup, &sidecar_destination)).unwrap_err();
    assert!(error.message.contains("sidecar"));
    assert_eq!(fs::read(&sidecar_path).unwrap(), b"external sidecar");
    assert!(!sidecar_destination.exists());

    remove_database_artifacts(&source);
    remove_database_artifacts(&backup);
    remove_database_artifacts(&invalid);
    remove_database_artifacts(&sidecar_destination);
}

#[test]
fn sqlite_compact_is_thresholded_and_preserves_state() {
    let path = test_database_path();
    let store = block_on(ConfigStore::open(&path)).unwrap();
    assert!(!block_on(store.compact_if_needed(i64::MAX)).unwrap());
    for index in 0..96 {
        block_on(store.put_config(&format!("compact.{index}"), &vec![index as u8; 32 * 1024]))
            .unwrap();
    }
    for index in 0..96 {
        assert!(block_on(store.delete_config(&format!("compact.{index}"))).unwrap());
    }
    assert!(block_on(store.compact_if_needed(1)).unwrap());
    assert_eq!(block_on(store.get_config("compact.0")).unwrap(), None);
    store.close().unwrap();

    let reopened = block_on(ConfigStore::open(&path)).unwrap();
    assert_eq!(block_on(reopened.get_config("compact.95")).unwrap(), None);
    reopened.close().unwrap();
    remove_database_artifacts(&path);
}

#[test]
fn invalid_mutation_rolls_back_previous_mutations() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let error = block_on(store.apply(&[
        ConfigMutation::Put {
            key: "first".to_owned(),
            value: b"must rollback".to_vec(),
        },
        ConfigMutation::Put {
            key: "".to_owned(),
            value: b"invalid".to_vec(),
        },
    ]))
    .unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidInput);
    assert_eq!(block_on(store.get_config("first")).unwrap(), None);
}

#[test]
fn schema_is_idempotent() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let second = store.migrate();
    assert!(second.is_ok());
}

#[test]
fn storage_status_is_reusable_by_reload_and_management_callers() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let status = store.status().unwrap();
    assert_eq!(status.schema_version, 3);
    assert_eq!(status.quick_check, "ok");
    assert!(status.page_count > 0);
    assert!(status.freelist_pages >= 0);
    assert!(status.journal_mode == "memory" || status.journal_mode == "wal");
    assert!(!status.go_schema_imported);
    assert!(status.go_schema_version.is_none());
    assert!(status.full_cone_nat);
}

#[test]
fn config_survives_close_and_reopen() {
    let path = test_database_path();
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        block_on(store.put_config("persisted", b"after-restart")).unwrap();
    }
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        assert_eq!(
            block_on(store.get_config("persisted")).unwrap(),
            Some(b"after-restart".to_vec())
        );
    }
    remove_database_artifacts(&path);
}

#[test]
fn concurrent_file_connections_preserve_each_writer() {
    let path = test_database_path();
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        block_on(store.put_config("ready", b"yes")).unwrap();
    }
    std::thread::scope(|scope| {
        for worker in 0..8 {
            let path = path.clone();
            scope.spawn(move || {
                let store = block_on(ConfigStore::open(&path)).unwrap();
                for item in 0..32 {
                    let key = format!("writer-{worker}-{item}");
                    block_on(store.put_config(&key, key.as_bytes())).unwrap();
                }
            });
        }
    });
    let store = block_on(ConfigStore::open(&path)).unwrap();
    let values = block_on(store.list_config("writer-")).unwrap();
    assert_eq!(values.len(), 256);
    for (key, value) in values {
        assert_eq!(value, key.as_bytes());
    }
    remove_database_artifacts(&path);
}

#[test]
fn concurrent_reopen_and_read_pressure_preserves_file_store_state() {
    let path = test_database_path();
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        block_on(store.put_config("pressure-ready", b"yes")).unwrap();
    }

    let writers = 8;
    let readers = 4;
    let barrier = Arc::new(Barrier::new(writers + readers));
    std::thread::scope(|scope| {
        for worker in 0..writers {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                for batch in 0..4 {
                    let store = block_on(ConfigStore::open(&path)).unwrap();
                    for offset in 0..8 {
                        let item = batch * 8 + offset;
                        let key = format!("pressure-writer-{worker}-{item}");
                        block_on(store.put_config(&key, key.as_bytes())).unwrap();
                    }
                    // Reopen frequently to exercise WAL recovery, schema
                    // checks and busy retry together rather than keeping
                    // one connection alive for the entire writer.
                }
            });
        }
        for _ in 0..readers {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            scope.spawn(move || {
                barrier.wait();
                for _ in 0..24 {
                    let store = block_on(ConfigStore::open(&path)).unwrap();
                    let values = block_on(store.list_config("pressure-writer-")).unwrap();
                    for (key, value) in values {
                        assert_eq!(value, key.as_bytes());
                    }
                }
            });
        }
    });

    let store = block_on(ConfigStore::open(&path)).unwrap();
    let values = block_on(store.list_config("pressure-writer-")).unwrap();
    assert_eq!(values.len(), writers * 32);
    assert_eq!(
        block_on(store.get_config("pressure-ready")).unwrap(),
        Some(b"yes".to_vec())
    );
    remove_database_artifacts(&path);
}

#[test]
fn connection_configuration_bounds_page_cache() {
    let connection = Connection::open(":memory:").unwrap();
    configure_connection(&connection).unwrap();
    assert_eq!(
        connection.query("PRAGMA cache_size").unwrap()[0].get(0),
        Some(&SqliteValue::Integer(-32768))
    );
}

#[test]
fn wal_mode_and_uncommitted_force_stop_recover_on_reopen() {
    let path = test_database_path();
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        block_on(store.put_config("committed", b"yes")).unwrap();
    }
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        connection.execute("PRAGMA journal_mode = WAL").unwrap();
        connection.execute("BEGIN IMMEDIATE").unwrap();
        connection
            .execute_with_params(
                "INSERT OR REPLACE INTO yuhaiin_config (key, value) VALUES (?1, ?2)",
                &[
                    SqliteValue::from("wal-committed"),
                    SqliteValue::from(b"survive-recovery".as_slice()),
                ],
            )
            .unwrap();
        connection.execute("COMMIT").unwrap();
        connection.close_without_checkpoint().unwrap();
    }
    {
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        let journal = connection.query("PRAGMA journal_mode").unwrap();
        assert_eq!(journal[0].get(0), Some(&SqliteValue::Text("wal".into())));
        connection.execute("BEGIN IMMEDIATE").unwrap();
        connection
            .execute_with_params(
                "INSERT OR REPLACE INTO yuhaiin_config (key, value) VALUES (?1, ?2)",
                &[
                    SqliteValue::from("uncommitted"),
                    SqliteValue::from(b"must-not-survive".as_slice()),
                ],
            )
            .unwrap();
        // Dropping a connection with an active transaction models a
        // force-stop before COMMIT; recovery must discard that write.
    }
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        assert_eq!(
            block_on(store.get_config("committed")).unwrap(),
            Some(b"yes".to_vec())
        );
        assert_eq!(
            block_on(store.get_config("wal-committed")).unwrap(),
            Some(b"survive-recovery".to_vec())
        );
        assert_eq!(block_on(store.get_config("uncommitted")).unwrap(), None);
        let connection = Connection::open(path.to_str().unwrap()).unwrap();
        let integrity = connection.query("PRAGMA quick_check").unwrap();
        assert_eq!(integrity[0].get(0), Some(&SqliteValue::Text("ok".into())));
    }
    remove_database_artifacts(&path);
}

#[test]
fn typed_repository_delete_operations_are_idempotent() {
    let store = block_on(ConfigStore::open_memory()).unwrap();
    let repository = store.repository();
    block_on(repository.put_route_rule(&RouteRuleRecord {
        id: "rule".to_owned(),
        pattern: "example.com".to_owned(),
        action: "proxy".to_owned(),
        priority: 1,
        geo_country: None,
        resolver_policy: Vec::new(),
    }))
    .unwrap();
    block_on(repository.put_dns_resolver(&DnsResolverRecord {
        id: "dns".to_owned(),
        kind: "udp".to_owned(),
        config: Vec::new(),
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
        idle_timeout_ms: 1,
    }))
    .unwrap();
    block_on(repository.put_maxmind_metadata(&MaxMindMetadataRecord {
        id: "geo".to_owned(),
        path: "geo.mmdb".to_owned(),
        sha256: Vec::new(),
        size: 0,
        updated_at: 0,
    }))
    .unwrap();

    assert!(block_on(repository.delete_route_rule("rule")).unwrap());
    assert!(!block_on(repository.delete_route_rule("rule")).unwrap());
    assert!(block_on(repository.delete_dns_resolver("dns")).unwrap());
    assert!(block_on(repository.delete_tun_config("mtu")).unwrap());
    assert!(block_on(repository.delete_nat_config("default")).unwrap());
    assert!(block_on(repository.delete_maxmind_metadata("geo")).unwrap());
    assert!(block_on(repository.list_route_rules()).unwrap().is_empty());
    assert!(
        block_on(repository.list_dns_resolvers())
            .unwrap()
            .is_empty()
    );
    assert!(block_on(repository.list_tun_config()).unwrap().is_empty());
    assert!(block_on(repository.list_nat_config()).unwrap().is_empty());
    assert!(
        block_on(repository.list_maxmind_metadata())
            .unwrap()
            .is_empty()
    );
}
