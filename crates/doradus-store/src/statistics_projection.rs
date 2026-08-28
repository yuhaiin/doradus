//! Snapshot loading and replacement for the Go-compatible statistics projection.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;
use crate::schema::table_has_column;
use crate::sqlite::Connection;

pub(super) fn load(connection: &Connection) -> Result<GoStatisticsSnapshot> {
    let mut snapshot = GoStatisticsSnapshot::default();

    if table_exists(connection, "statistics_kv") {
        let rows = connection
            .query("SELECT key, value_int FROM statistics_kv")
            .map_err(storage_error)?;
        for row in rows {
            let key = row_text(&row, 0, "statistics_kv.key")?;
            let value = row_u64(&row, 1, "statistics_kv.value_int")?;
            match key.as_str() {
                "total_download" => snapshot.total_download = value,
                "total_upload" => snapshot.total_upload = value,
                _ => {}
            }
        }
    }

    if table_exists(connection, "traffic_hourly") {
        let rows = connection
            .query(
                "SELECT bucket_start_utc, upload_bytes, download_bytes
                 FROM traffic_hourly ORDER BY bucket_start_utc",
            )
            .map_err(storage_error)?;
        snapshot.traffic = rows
            .iter()
            .map(|row| {
                Ok(GoTrafficBucketRecord {
                    bucket: row_i64(row, 0, "traffic_hourly.bucket_start_utc")?,
                    upload: row_u64(row, 1, "traffic_hourly.upload_bytes")?,
                    download: row_u64(row, 2, "traffic_hourly.download_bytes")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
    }

    if table_exists(connection, "connection_history") {
        let rows = connection
            .query(
                "SELECT protocol, addr, process_name, hit_count, last_seen_at,
                        last_connection_json
                 FROM connection_history ORDER BY last_seen_at DESC",
            )
            .map_err(storage_error)?;
        snapshot.history = rows
            .iter()
            .map(|row| {
                Ok(GoConnectionHistoryRecord {
                    protocol: row_string(row, 0, "connection_history.protocol")?,
                    addr: row_text(row, 1, "connection_history.addr")?,
                    process: row_text(row, 2, "connection_history.process_name")?,
                    count: row_u64(row, 3, "connection_history.hit_count")?,
                    last_seen: row_i64(row, 4, "connection_history.last_seen_at")?,
                    connection_json: row_blob_or_text(
                        row,
                        5,
                        "connection_history.last_connection_json",
                    )?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
    }

    if table_exists(connection, "failed_connection_history") {
        let rows = connection
            .query(
                "SELECT protocol, host, process_name, failed_count, last_seen_at,
                        last_error
                 FROM failed_connection_history ORDER BY last_seen_at DESC",
            )
            .map_err(storage_error)?;
        snapshot.failed_history = rows
            .iter()
            .map(|row| {
                Ok(GoFailedHistoryRecord {
                    protocol: row_string(row, 0, "failed_connection_history.protocol")?,
                    host: row_text(row, 1, "failed_connection_history.host")?,
                    process: row_text(row, 2, "failed_connection_history.process_name")?,
                    count: row_u64(row, 3, "failed_connection_history.failed_count")?,
                    last_seen: row_i64(row, 4, "failed_connection_history.last_seen_at")?,
                    error: row_text(row, 5, "failed_connection_history.last_error")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
    }

    load_telemetry(connection, &mut snapshot.telemetry)?;
    Ok(snapshot)
}

fn load_telemetry(
    connection: &Connection,
    output: &mut Vec<GoTelemetryBucketRecord>,
) -> Result<()> {
    if !table_exists(connection, "telemetry_dimension_values") {
        return load_legacy_telemetry(connection, output);
    }
    let mut merged = BTreeMap::<(i64, i64, String, String), (u64, u64, u64)>::new();
    for (table, span_seconds) in [
        ("traffic_dimension_hourly", TELEMETRY_HOURLY_BUCKET_SECONDS),
        ("traffic_dimension_daily", TELEMETRY_DAILY_BUCKET_SECONDS),
    ] {
        if !table_exists(connection, table) {
            continue;
        }
        let sql = format!(
            "SELECT t.bucket_start_utc, v.dimension, v.value,
                    t.download_bytes, t.upload_bytes
             FROM {table} t
             JOIN telemetry_dimension_values v ON v.id = t.value_id"
        );
        for row in connection.query(&sql).map_err(storage_error)? {
            let key = (
                row_i64(&row, 0, "traffic_dimension.bucket_start_utc")?,
                span_seconds,
                row_text(&row, 1, "telemetry_dimension_values.dimension")?,
                row_text(&row, 2, "telemetry_dimension_values.value")?,
            );
            let entry = merged.entry(key).or_default();
            entry.0 = entry
                .0
                .saturating_add(row_u64(&row, 3, "traffic_dimension.download_bytes")?);
            entry.1 = entry
                .1
                .saturating_add(row_u64(&row, 4, "traffic_dimension.upload_bytes")?);
        }
    }
    for (table, span_seconds) in [
        ("failure_dimension_hourly", TELEMETRY_HOURLY_BUCKET_SECONDS),
        ("failure_dimension_daily", TELEMETRY_DAILY_BUCKET_SECONDS),
    ] {
        if !table_exists(connection, table) {
            continue;
        }
        let sql = format!(
            "SELECT t.bucket_start_utc, v.dimension, v.value, t.failed_count
             FROM {table} t
             JOIN telemetry_dimension_values v ON v.id = t.value_id"
        );
        for row in connection.query(&sql).map_err(storage_error)? {
            let key = (
                row_i64(&row, 0, "failure_dimension.bucket_start_utc")?,
                span_seconds,
                row_text(&row, 1, "telemetry_dimension_values.dimension")?,
                row_text(&row, 2, "telemetry_dimension_values.value")?,
            );
            let entry = merged.entry(key).or_default();
            entry.2 = entry
                .2
                .saturating_add(row_u64(&row, 3, "failure_dimension.failed_count")?);
        }
    }
    *output = merged
        .into_iter()
        .map(
            |((bucket, span_seconds, dimension, value), (download, upload, failures))| {
                GoTelemetryBucketRecord {
                    bucket,
                    span_seconds,
                    dimension,
                    value,
                    download,
                    upload,
                    failures,
                }
            },
        )
        .collect();
    Ok(())
}

fn load_legacy_telemetry(
    connection: &Connection,
    output: &mut Vec<GoTelemetryBucketRecord>,
) -> Result<()> {
    let mut merged = BTreeMap::<(i64, i64, String, String), (u64, u64, u64)>::new();
    if table_exists(connection, "traffic_dimension_hourly") {
        for row in connection
            .query(
                "SELECT bucket_start_utc, dimension, value,
                        download_bytes, upload_bytes
                 FROM traffic_dimension_hourly",
            )
            .map_err(storage_error)?
        {
            let key = (
                row_i64(&row, 0, "traffic_dimension_hourly.bucket_start_utc")?,
                TELEMETRY_HOURLY_BUCKET_SECONDS,
                row_text(&row, 1, "traffic_dimension_hourly.dimension")?,
                row_text(&row, 2, "traffic_dimension_hourly.value")?,
            );
            let entry = merged.entry(key).or_default();
            entry.0 = entry.0.saturating_add(row_u64(
                &row,
                3,
                "traffic_dimension_hourly.download_bytes",
            )?);
            entry.1 =
                entry
                    .1
                    .saturating_add(row_u64(&row, 4, "traffic_dimension_hourly.upload_bytes")?);
        }
    }
    if table_exists(connection, "failure_dimension_hourly") {
        for row in connection
            .query(
                "SELECT bucket_start_utc, dimension, value, failed_count
                 FROM failure_dimension_hourly",
            )
            .map_err(storage_error)?
        {
            let key = (
                row_i64(&row, 0, "failure_dimension_hourly.bucket_start_utc")?,
                TELEMETRY_HOURLY_BUCKET_SECONDS,
                row_text(&row, 1, "failure_dimension_hourly.dimension")?,
                row_text(&row, 2, "failure_dimension_hourly.value")?,
            );
            let entry = merged.entry(key).or_default();
            entry.2 =
                entry
                    .2
                    .saturating_add(row_u64(&row, 3, "failure_dimension_hourly.failed_count")?);
        }
    }
    *output = merged
        .into_iter()
        .map(
            |((bucket, span_seconds, dimension, value), (download, upload, failures))| {
                GoTelemetryBucketRecord {
                    bucket,
                    span_seconds,
                    dimension,
                    value,
                    download,
                    upload,
                    failures,
                }
            },
        )
        .collect();
    Ok(())
}

pub(super) fn replace(connection: &Connection, snapshot: &GoStatisticsSnapshot) -> Result<()> {
    connection
        .execute("BEGIN IMMEDIATE")
        .map_err(storage_error)?;
    let result = replace_in_transaction(connection, snapshot);
    match result {
        Ok(()) => connection
            .execute("COMMIT")
            .map_err(storage_error)
            .map(|_| ()),
        Err(error) => {
            let _ = connection.execute("ROLLBACK");
            Err(error)
        }
    }
}

fn replace_in_transaction(connection: &Connection, snapshot: &GoStatisticsSnapshot) -> Result<()> {
    let compact_telemetry = table_exists(connection, "telemetry_dimension_values");
    let legacy_telemetry = !compact_telemetry
        && table_exists(connection, "traffic_dimension_hourly")
        && table_has_column(connection, "traffic_dimension_hourly", "dimension")
            .map_err(storage_error)?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS statistics_kv (
                key TEXT PRIMARY KEY, value_int INTEGER NOT NULL, updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS traffic_hourly (
                bucket_start_utc INTEGER PRIMARY KEY, upload_bytes INTEGER NOT NULL,
                download_bytes INTEGER NOT NULL, updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS connection_history (
                protocol INTEGER NOT NULL, addr TEXT NOT NULL, process_name TEXT NOT NULL,
                hit_count INTEGER NOT NULL, last_seen_at INTEGER NOT NULL,
                last_connection_json TEXT NOT NULL,
                PRIMARY KEY (protocol, addr, process_name)
            );
            CREATE TABLE IF NOT EXISTS failed_connection_history (
                protocol INTEGER NOT NULL, host TEXT NOT NULL, process_name TEXT NOT NULL,
                failed_count INTEGER NOT NULL, last_seen_at INTEGER NOT NULL,
                last_error TEXT NOT NULL,
                PRIMARY KEY (protocol, host, process_name)
            );",
        )
        .map_err(storage_error)?;
    let traffic_hourly_table = if legacy_telemetry {
        "traffic_dimension_hourly_rust_v6"
    } else {
        "traffic_dimension_hourly"
    };
    let traffic_daily_table = if legacy_telemetry {
        "traffic_dimension_daily_rust_v6"
    } else {
        "traffic_dimension_daily"
    };
    let failure_hourly_table = if legacy_telemetry {
        "failure_dimension_hourly_rust_v6"
    } else {
        "failure_dimension_hourly"
    };
    let failure_daily_table = if legacy_telemetry {
        "failure_dimension_daily_rust_v6"
    } else {
        "failure_dimension_daily"
    };
    connection
        .execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS telemetry_dimension_values (
                    id INTEGER PRIMARY KEY, dimension TEXT NOT NULL, value TEXT NOT NULL,
                    UNIQUE (dimension, value)
                );
                CREATE TABLE IF NOT EXISTS {traffic_hourly_table} (
                    bucket_start_utc INTEGER NOT NULL, value_id INTEGER NOT NULL,
                    upload_bytes INTEGER NOT NULL, download_bytes INTEGER NOT NULL,
                    PRIMARY KEY (bucket_start_utc, value_id)
                );
                CREATE TABLE IF NOT EXISTS {failure_hourly_table} (
                    bucket_start_utc INTEGER NOT NULL, value_id INTEGER NOT NULL,
                    failed_count INTEGER NOT NULL,
                    PRIMARY KEY (bucket_start_utc, value_id)
                );
                CREATE TABLE IF NOT EXISTS {traffic_daily_table} (
                    bucket_start_utc INTEGER NOT NULL, value_id INTEGER NOT NULL,
                    upload_bytes INTEGER NOT NULL DEFAULT 0,
                    download_bytes INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (bucket_start_utc, value_id)
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS {failure_daily_table} (
                    bucket_start_utc INTEGER NOT NULL, value_id INTEGER NOT NULL,
                    failed_count INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (bucket_start_utc, value_id)
                ) WITHOUT ROWID;"
        ))
        .map_err(storage_error)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Error::new(ErrorKind::Storage, error.to_string()))?
        .as_secs() as i64;
    let hourly_cutoff = now.div_euclid(3_600) * 3_600 - TELEMETRY_HOURLY_RETENTION_SECONDS;

    for (key, value) in [
        ("total_download", snapshot.total_download),
        ("total_upload", snapshot.total_upload),
    ] {
        connection
            .execute_with_params(
                "INSERT INTO statistics_kv(key, value_int, updated_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET
                   value_int = excluded.value_int, updated_at = excluded.updated_at",
                &[
                    SqliteValue::from(key),
                    SqliteValue::from(u64_to_i64(value, key)?),
                    SqliteValue::from(now),
                ],
            )
            .map_err(storage_error)?;
    }

    connection
        .execute("DELETE FROM traffic_hourly")
        .map_err(storage_error)?;
    for bucket in &snapshot.traffic {
        connection
            .execute_with_params(
                "INSERT INTO traffic_hourly(
                    bucket_start_utc, upload_bytes, download_bytes, updated_at
                 ) VALUES (?1, ?2, ?3, ?4)",
                &[
                    SqliteValue::from(bucket.bucket),
                    SqliteValue::from(u64_to_i64(bucket.upload, "traffic upload")?),
                    SqliteValue::from(u64_to_i64(bucket.download, "traffic download")?),
                    SqliteValue::from(now),
                ],
            )
            .map_err(storage_error)?;
    }

    connection
        .execute("DELETE FROM connection_history")
        .map_err(storage_error)?;
    for history in &snapshot.history {
        let connection_json =
            String::from_utf8(history.connection_json.clone()).map_err(|error| {
                Error::new(
                    ErrorKind::Storage,
                    format!("history connection JSON is not UTF-8: {error}"),
                )
            })?;
        connection
            .execute_with_params(
                "INSERT INTO connection_history(
                    protocol, addr, process_name, hit_count, last_seen_at,
                    last_connection_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    SqliteValue::from(history.protocol.as_str()),
                    SqliteValue::from(history.addr.as_str()),
                    SqliteValue::from(history.process.as_str()),
                    SqliteValue::from(u64_to_i64(history.count, "history count")?),
                    SqliteValue::from(history.last_seen),
                    SqliteValue::from(connection_json),
                ],
            )
            .map_err(storage_error)?;
    }

    connection
        .execute("DELETE FROM failed_connection_history")
        .map_err(storage_error)?;
    for failure in &snapshot.failed_history {
        connection
            .execute_with_params(
                "INSERT INTO failed_connection_history(
                    protocol, host, process_name, failed_count, last_seen_at, last_error
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    SqliteValue::from(failure.protocol.as_str()),
                    SqliteValue::from(failure.host.as_str()),
                    SqliteValue::from(failure.process.as_str()),
                    SqliteValue::from(u64_to_i64(failure.count, "failure count")?),
                    SqliteValue::from(failure.last_seen),
                    SqliteValue::from(failure.error.as_str()),
                ],
            )
            .map_err(storage_error)?;
    }

    for table in [
        traffic_hourly_table,
        failure_hourly_table,
        traffic_daily_table,
        failure_daily_table,
        "telemetry_dimension_values",
    ] {
        if table_exists(connection, table) {
            connection
                .execute(&format!("DELETE FROM {table}"))
                .map_err(storage_error)?;
        }
    }
    {
        for item in &snapshot.telemetry {
            connection
                .execute_with_params(
                    "INSERT OR IGNORE INTO telemetry_dimension_values(dimension, value)
                 VALUES (?1, ?2)",
                    &[
                        SqliteValue::from(item.dimension.as_str()),
                        SqliteValue::from(item.value.as_str()),
                    ],
                )
                .map_err(storage_error)?;
            let rows = connection
                .query_with_params(
                    "SELECT id FROM telemetry_dimension_values
                 WHERE dimension = ?1 AND value = ?2",
                    &[
                        SqliteValue::from(item.dimension.as_str()),
                        SqliteValue::from(item.value.as_str()),
                    ],
                )
                .map_err(storage_error)?;
            let id = rows
                .first()
                .ok_or_else(|| Error::new(ErrorKind::Storage, "telemetry value was not created"))?;
            let id = row_i64(id, 0, "telemetry_dimension_values.id")?;
            if item.download != 0 || item.upload != 0 {
                let (table, bucket) = if item.bucket < hourly_cutoff {
                    (
                        traffic_daily_table,
                        item.bucket.div_euclid(TELEMETRY_SECONDS_PER_DAY)
                            * TELEMETRY_SECONDS_PER_DAY,
                    )
                } else {
                    (traffic_hourly_table, item.bucket)
                };
                connection
                    .execute_with_params(
                        &format!(
                            "INSERT INTO {table}(
                                bucket_start_utc, value_id, upload_bytes, download_bytes
                             ) VALUES (?1, ?2, ?3, ?4)
                             ON CONFLICT(bucket_start_utc, value_id) DO UPDATE SET
                               upload_bytes = {table}.upload_bytes + excluded.upload_bytes,
                               download_bytes = {table}.download_bytes + excluded.download_bytes"
                        ),
                        &[
                            SqliteValue::from(bucket),
                            SqliteValue::from(id),
                            SqliteValue::from(u64_to_i64(item.upload, "telemetry upload")?),
                            SqliteValue::from(u64_to_i64(item.download, "telemetry download")?),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            if item.failures != 0 {
                let (table, bucket) = if item.bucket < hourly_cutoff {
                    (
                        failure_daily_table,
                        item.bucket.div_euclid(TELEMETRY_SECONDS_PER_DAY)
                            * TELEMETRY_SECONDS_PER_DAY,
                    )
                } else {
                    (failure_hourly_table, item.bucket)
                };
                connection
                    .execute_with_params(
                        &format!(
                            "INSERT INTO {table}(
                                bucket_start_utc, value_id, failed_count
                             ) VALUES (?1, ?2, ?3)
                             ON CONFLICT(bucket_start_utc, value_id) DO UPDATE SET
                               failed_count = {table}.failed_count + excluded.failed_count"
                        ),
                        &[
                            SqliteValue::from(bucket),
                            SqliteValue::from(id),
                            SqliteValue::from(u64_to_i64(item.failures, "telemetry failures")?),
                        ],
                    )
                    .map_err(storage_error)?;
            }
        }
    }
    if legacy_telemetry {
        connection
            .execute_batch(&format!(
                "DROP TABLE traffic_dimension_hourly;
                 DROP TABLE failure_dimension_hourly;
                 DROP TABLE IF EXISTS traffic_dimension_daily;
                 DROP TABLE IF EXISTS failure_dimension_daily;
                 ALTER TABLE {traffic_hourly_table} RENAME TO traffic_dimension_hourly;
                 ALTER TABLE {traffic_daily_table} RENAME TO traffic_dimension_daily;
                 ALTER TABLE {failure_hourly_table} RENAME TO failure_dimension_hourly;
                 ALTER TABLE {failure_daily_table} RENAME TO failure_dimension_daily;"
            ))
            .map_err(storage_error)?;
    }
    connection
        .execute_batch(
            "CREATE INDEX IF NOT EXISTS traffic_dimension_hourly_lookup_idx
                 ON traffic_dimension_hourly(value_id, bucket_start_utc DESC);
             CREATE INDEX IF NOT EXISTS traffic_dimension_daily_lookup_idx
                 ON traffic_dimension_daily(value_id, bucket_start_utc DESC);
             CREATE INDEX IF NOT EXISTS failure_dimension_hourly_lookup_idx
                 ON failure_dimension_hourly(value_id, bucket_start_utc DESC);
             CREATE INDEX IF NOT EXISTS failure_dimension_daily_lookup_idx
                 ON failure_dimension_daily(value_id, bucket_start_utc DESC);",
        )
        .map_err(storage_error)?;
    mark_go_telemetry_migrations_applied(connection)?;
    Ok(())
}

/// Rust writes the final Go v6 telemetry schema directly. When the source was
/// an older Go database, keep Go's own migration ledger in sync so a rollback
/// or a temporary dual-process check does not replay CREATE TABLE statements
/// against the already projected tables.
fn mark_go_telemetry_migrations_applied(connection: &Connection) -> Result<()> {
    if !table_exists(connection, "metadata") || !table_exists(connection, "migrate") {
        return Ok(());
    }
    for (version, name) in [
        (5_i64, "telemetry_dimensions"),
        (6_i64, "compact_telemetry_dimensions"),
    ] {
        connection
            .execute_with_params(
                "INSERT OR IGNORE INTO migrate(version, name, applied_at)
                 VALUES (?1, ?2, CAST(strftime('%s', 'now') AS INTEGER))",
                &[SqliteValue::from(version), SqliteValue::from(name)],
            )
            .map_err(storage_error)?;
    }
    connection
        .execute_with_params(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES ('schema_version', ?1)",
            &[SqliteValue::from("6")],
        )
        .map_err(storage_error)?;
    Ok(())
}
