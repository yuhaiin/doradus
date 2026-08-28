//! Go-compatible statistics projection tests.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::schema::table_has_column;

use super::*;

#[tokio::test]
async fn go_statistics_round_trip_creates_compatible_projection() {
    let store = ConfigStore::open_memory().await.unwrap();
    let recent_bucket = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        / 3_600
        * 3_600;
    let snapshot = GoStatisticsSnapshot {
        total_download: 11,
        total_upload: 7,
        traffic: vec![GoTrafficBucketRecord {
            bucket: recent_bucket,
            upload: 7,
            download: 11,
        }],
        history: vec![GoConnectionHistoryRecord {
            protocol: "tcp".to_owned(),
            addr: "example.com:443".to_owned(),
            process: "/usr/bin/test".to_owned(),
            count: 2,
            last_seen: 1_700_000_001,
            connection_json: br#"{"protocol":"tcp","addr":"example.com:443"}"#.to_vec(),
        }],
        failed_history: vec![GoFailedHistoryRecord {
            protocol: "http".to_owned(),
            host: "example.com".to_owned(),
            process: String::new(),
            count: 3,
            last_seen: 1_700_000_002,
            error: "timeout".to_owned(),
        }],
        telemetry: vec![GoTelemetryBucketRecord {
            bucket: recent_bucket,
            span_seconds: TELEMETRY_HOURLY_BUCKET_SECONDS,
            dimension: "protocol".to_owned(),
            value: "tcp".to_owned(),
            download: 11,
            upload: 7,
            failures: 1,
        }],
    };

    store.replace_go_statistics(&snapshot).unwrap();
    assert_eq!(store.load_go_statistics().unwrap(), snapshot);
}

#[tokio::test]
async fn go_statistics_delta_updates_projection_without_reloading_history() {
    let store = ConfigStore::open_memory().await.unwrap();
    let bucket = 1_700_000_000;
    let history = GoConnectionHistoryRecord {
        protocol: "tcp".to_owned(),
        addr: "example.com:443".to_owned(),
        process: "browser".to_owned(),
        count: 1,
        last_seen: bucket,
        connection_json: br#"{"addr":"example.com:443"}"#.to_vec(),
    };
    store
        .apply_go_statistics_delta(&GoStatisticsDelta {
            total_upload: 10,
            total_download: 20,
            traffic: vec![GoTrafficBucketRecord {
                bucket,
                upload: 10,
                download: 20,
            }],
            history: vec![history.clone()],
            ..GoStatisticsDelta::default()
        })
        .unwrap();
    store
        .apply_go_statistics_delta(&GoStatisticsDelta {
            total_upload: 15,
            total_download: 25,
            traffic: vec![GoTrafficBucketRecord {
                bucket,
                upload: 5,
                download: 5,
            }],
            history: vec![GoConnectionHistoryRecord {
                count: 2,
                last_seen: bucket + 1,
                ..history
            }],
            ..GoStatisticsDelta::default()
        })
        .unwrap();

    let snapshot = store.load_go_statistics().unwrap();
    assert_eq!(snapshot.total_upload, 15);
    assert_eq!(snapshot.total_download, 25);
    assert_eq!(snapshot.traffic[0].upload, 15);
    assert_eq!(snapshot.traffic[0].download, 25);
    assert_eq!(snapshot.history[0].count, 3);
    assert_eq!(snapshot.history[0].last_seen, bucket + 1);
}

#[tokio::test]
async fn go_statistics_projection_rolls_old_telemetry_into_daily_tables() {
    let store = ConfigStore::open_memory().await.unwrap();
    let current_hour = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        / 3_600
        * 3_600;
    let old_day = (current_hour - TELEMETRY_HOURLY_RETENTION_SECONDS - 86_400)
        .div_euclid(TELEMETRY_SECONDS_PER_DAY)
        * TELEMETRY_SECONDS_PER_DAY;
    let old_bucket_a = old_day + 3_600;
    let old_bucket_b = old_day + 7_200;
    let recent_bucket = current_hour - 3_600;
    let snapshot = GoStatisticsSnapshot {
        telemetry: vec![
            GoTelemetryBucketRecord {
                bucket: old_bucket_a,
                span_seconds: TELEMETRY_HOURLY_BUCKET_SECONDS,
                dimension: "protocol".to_owned(),
                value: "tcp".to_owned(),
                download: 11,
                upload: 7,
                failures: 2,
            },
            GoTelemetryBucketRecord {
                bucket: old_bucket_b,
                span_seconds: TELEMETRY_HOURLY_BUCKET_SECONDS,
                dimension: "protocol".to_owned(),
                value: "tcp".to_owned(),
                download: 13,
                upload: 5,
                failures: 3,
            },
            GoTelemetryBucketRecord {
                bucket: recent_bucket,
                span_seconds: TELEMETRY_HOURLY_BUCKET_SECONDS,
                dimension: "protocol".to_owned(),
                value: "tcp".to_owned(),
                download: 17,
                upload: 19,
                failures: 4,
            },
        ],
        ..GoStatisticsSnapshot::default()
    };

    store.replace_go_statistics(&snapshot).unwrap();

    {
        let connection = store.lock_connection().unwrap();
        for table in ["traffic_dimension_daily", "failure_dimension_daily"] {
            assert!(table_exists(&connection, table), "missing {table}");
        }
        let value_id = connection
            .query(
                "SELECT id FROM telemetry_dimension_values
                 WHERE dimension = 'protocol' AND value = 'tcp'",
            )
            .unwrap();
        let value_id = row_i64(&value_id[0], 0, "telemetry value id").unwrap();

        let traffic = connection
            .query_with_params(
                "SELECT upload_bytes, download_bytes
                 FROM traffic_dimension_daily
                 WHERE bucket_start_utc = ?1 AND value_id = ?2",
                &[SqliteValue::from(old_day), SqliteValue::from(value_id)],
            )
            .unwrap();
        assert_eq!(traffic.len(), 1);
        assert_eq!(row_i64(&traffic[0], 0, "daily upload").unwrap(), 12);
        assert_eq!(row_i64(&traffic[0], 1, "daily download").unwrap(), 24);

        let failures = connection
            .query_with_params(
                "SELECT failed_count
                 FROM failure_dimension_daily
                 WHERE bucket_start_utc = ?1 AND value_id = ?2",
                &[SqliteValue::from(old_day), SqliteValue::from(value_id)],
            )
            .unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(row_i64(&failures[0], 0, "daily failures").unwrap(), 5);

        let old_hourly = connection
            .query_with_params(
                "SELECT COUNT(*) FROM traffic_dimension_hourly
                 WHERE bucket_start_utc < ?1",
                &[SqliteValue::from(
                    current_hour - TELEMETRY_HOURLY_RETENTION_SECONDS,
                )],
            )
            .unwrap();
        assert_eq!(row_i64(&old_hourly[0], 0, "old hourly count").unwrap(), 0);
    }

    let loaded = store.load_go_statistics().unwrap();
    assert_eq!(loaded.telemetry.len(), 2);
    let daily = loaded
        .telemetry
        .iter()
        .find(|item| item.bucket == old_day)
        .unwrap();
    assert_eq!(daily.span_seconds, TELEMETRY_DAILY_BUCKET_SECONDS);
    assert_eq!(daily.download, 24);
    assert_eq!(daily.upload, 12);
    assert_eq!(daily.failures, 5);
    let hourly = loaded
        .telemetry
        .iter()
        .find(|item| item.bucket == recent_bucket)
        .unwrap();
    assert_eq!(hourly.span_seconds, TELEMETRY_HOURLY_BUCKET_SECONDS);
    assert_eq!(hourly.download, 17);
    assert_eq!(hourly.upload, 19);
    assert_eq!(hourly.failures, 4);
}

#[tokio::test]
async fn legacy_telemetry_projection_rolls_back_schema_conversion_on_error() {
    let store = ConfigStore::open_memory().await.unwrap();
    {
        let connection = store.lock_connection().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE traffic_dimension_hourly (
                     bucket_start_utc INTEGER NOT NULL,
                     dimension TEXT NOT NULL,
                     value TEXT NOT NULL,
                     upload_bytes INTEGER NOT NULL DEFAULT 0,
                     download_bytes INTEGER NOT NULL DEFAULT 0,
                     updated_at INTEGER NOT NULL,
                     PRIMARY KEY (bucket_start_utc, dimension, value)
                 );
                 CREATE TABLE failure_dimension_hourly (
                     bucket_start_utc INTEGER NOT NULL,
                     dimension TEXT NOT NULL,
                     value TEXT NOT NULL,
                     failed_count INTEGER NOT NULL DEFAULT 0,
                     updated_at INTEGER NOT NULL,
                     PRIMARY KEY (bucket_start_utc, dimension, value)
                 );
                 INSERT INTO traffic_dimension_hourly
                     VALUES (1, 'protocol', 'tcp', 7, 11, 1);",
            )
            .unwrap();
    }

    let result = store.replace_go_statistics(&GoStatisticsSnapshot {
        telemetry: vec![GoTelemetryBucketRecord {
            bucket: 1,
            span_seconds: TELEMETRY_HOURLY_BUCKET_SECONDS,
            dimension: "protocol".to_owned(),
            value: "tcp".to_owned(),
            download: u64::MAX,
            ..GoTelemetryBucketRecord::default()
        }],
        ..GoStatisticsSnapshot::default()
    });
    assert!(result.is_err());

    let connection = store.lock_connection().unwrap();
    assert!(!table_exists(&connection, "telemetry_dimension_values"));
    assert!(table_has_column(&connection, "traffic_dimension_hourly", "dimension").unwrap());
    assert_eq!(
        connection
            .query("SELECT download_bytes FROM traffic_dimension_hourly")
            .unwrap()
            .first()
            .and_then(|row| row.get(0)),
        Some(&SqliteValue::Integer(11))
    );
}

#[tokio::test]
async fn missing_go_statistics_tables_are_an_empty_snapshot() {
    let store = ConfigStore::open_memory().await.unwrap();
    assert_eq!(
        store.load_go_statistics().unwrap(),
        GoStatisticsSnapshot::default()
    );
}

#[tokio::test]
async fn legacy_go_migration_ledger_advances_with_telemetry_projection() {
    let store = ConfigStore::open_memory().await.unwrap();
    {
        let connection = store.lock_connection().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                 );
                 CREATE TABLE migrate (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at INTEGER NOT NULL
                 );
                 INSERT INTO metadata(key, value) VALUES ('schema_version', '4');
                 INSERT INTO migrate(version, name, applied_at) VALUES
                    (1, 'initial_schema', 0),
                    (2, 'fakeip_cache', 0),
                    (3, 'plain_contract_model', 0),
                    (4, 'plain_route_lists', 0);
                 DELETE FROM migrate WHERE version > 4;",
            )
            .unwrap();
    }

    store
        .replace_go_statistics(&GoStatisticsSnapshot::default())
        .unwrap();

    let connection = store.lock_connection().unwrap();
    assert_eq!(
        connection
            .query("SELECT value FROM metadata WHERE key = 'schema_version'")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Text("6".into()))
    );
    assert_eq!(
        connection
            .query("SELECT COUNT(*) FROM migrate WHERE version IN (5, 6)")
            .unwrap()[0]
            .get(0),
        Some(&SqliteValue::Integer(2))
    );
}
