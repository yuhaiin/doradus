//! Go-compatible statistics tables.
//!
//! Runtime state is kept in memory for fast packet-path updates, while this
//! boundary makes the durable totals/history/traffic tables readable when a
//! Rust process takes over a Go state database. The runtime writes a full
//! compatibility snapshot during its final flush; the compact runtime JSON
//! remains the frequent checkpoint used for crash recovery.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{ConfigStore, Error, ErrorKind, Result, SqliteValue, storage_error, table_exists};
use crate::schema::table_has_column;
use crate::sqlite::{Connection, Row};

const TELEMETRY_HOURLY_RETENTION_SECONDS: i64 = 30 * 86_400;
const TELEMETRY_SECONDS_PER_DAY: i64 = 86_400;
pub const TELEMETRY_HOURLY_BUCKET_SECONDS: i64 = 3_600;
pub const TELEMETRY_DAILY_BUCKET_SECONDS: i64 = TELEMETRY_SECONDS_PER_DAY;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoTrafficBucketRecord {
    pub bucket: i64,
    pub upload: u64,
    pub download: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoConnectionHistoryRecord {
    pub protocol: String,
    pub addr: String,
    pub process: String,
    pub count: u64,
    pub last_seen: i64,
    pub connection_json: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoFailedHistoryRecord {
    pub protocol: String,
    pub host: String,
    pub process: String,
    pub count: u64,
    pub last_seen: i64,
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoTelemetryBucketRecord {
    pub bucket: i64,
    /// The span covered by this record: hourly or compacted daily.
    pub span_seconds: i64,
    pub dimension: String,
    pub value: String,
    pub download: u64,
    pub upload: u64,
    pub failures: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoStatisticsSnapshot {
    pub total_download: u64,
    pub total_upload: u64,
    pub traffic: Vec<GoTrafficBucketRecord>,
    pub history: Vec<GoConnectionHistoryRecord>,
    pub failed_history: Vec<GoFailedHistoryRecord>,
    pub telemetry: Vec<GoTelemetryBucketRecord>,
}

impl ConfigStore {
    /// Read the durable statistics written by the Go runtime, if those tables
    /// exist. Missing optional tables are treated as an empty snapshot so a
    /// fresh Rust database does not need a fake Go bootstrap migration.
    pub fn load_go_statistics(&self) -> Result<GoStatisticsSnapshot> {
        let connection = self.lock_connection()?;
        load(&connection)
    }

    /// Replace the Go-compatible statistics projection atomically. This is
    /// intentionally a final-flush operation; frequent crash checkpoints use
    /// the compact statistics.runtime record instead.
    pub fn replace_go_statistics(&self, snapshot: &GoStatisticsSnapshot) -> Result<()> {
        self.with_write_retry(|connection| replace(connection, snapshot))
    }

    /// Record one failed connection synchronously in Go's durable table.
    ///
    /// The runtime checkpoint is intentionally asynchronous, so it can be
    /// lost when the process receives SIGKILL.  Go increments this table on
    /// the failure path itself; keeping the same small UPSERT here preserves
    /// failed-history counts across an abnormal exit without blocking the
    /// packet path on a full statistics projection.
    pub fn record_failed_history(
        &self,
        protocol: &str,
        host: &str,
        process: &str,
        error: &str,
        last_seen: i64,
    ) -> Result<()> {
        self.with_write_retry(|connection| {
            connection
                .execute_batch(
                    "CREATE TABLE IF NOT EXISTS failed_connection_history (
                        protocol INTEGER NOT NULL, host TEXT NOT NULL,
                        process_name TEXT NOT NULL, failed_count INTEGER NOT NULL,
                        last_seen_at INTEGER NOT NULL, last_error TEXT NOT NULL,
                        PRIMARY KEY (protocol, host, process_name)
                    )",
                )
                .map_err(storage_error)?;
            connection
                .execute_with_params(
                    "INSERT INTO failed_connection_history(
                        protocol, host, process_name, failed_count, last_seen_at, last_error
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(protocol, host, process_name) DO UPDATE SET
                        failed_count = failed_connection_history.failed_count + excluded.failed_count,
                        last_seen_at = excluded.last_seen_at,
                        last_error = excluded.last_error",
                    &[
                        SqliteValue::from(protocol),
                        SqliteValue::from(host),
                        SqliteValue::from(process),
                        SqliteValue::from(1_i64),
                        SqliteValue::from(last_seen),
                        SqliteValue::from(error),
                    ],
                )
                .map_err(storage_error)
                .map(|_| ())
        })
    }
}

fn load(connection: &Connection) -> Result<GoStatisticsSnapshot> {
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

fn replace(connection: &Connection, snapshot: &GoStatisticsSnapshot) -> Result<()> {
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

fn u64_to_i64(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value).map_err(|_| {
        Error::new(
            ErrorKind::Storage,
            format!("{field} exceeds SQLite INTEGER range"),
        )
    })
}

fn row_string(row: &Row, index: usize, field: &str) -> Result<String> {
    match row.get(index) {
        Some(SqliteValue::Text(value)) => Ok(value.as_ref().to_owned()),
        Some(SqliteValue::Integer(value)) => Ok(value.to_string()),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("{field} is not TEXT/INTEGER"),
        )),
    }
}

fn row_text(row: &Row, index: usize, field: &str) -> Result<String> {
    match row.get(index) {
        Some(SqliteValue::Text(value)) => Ok(value.as_ref().to_owned()),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("{field} is not TEXT"),
        )),
    }
}

fn row_blob_or_text(row: &Row, index: usize, field: &str) -> Result<Vec<u8>> {
    match row.get(index) {
        Some(SqliteValue::Text(value)) => Ok(value.as_bytes().to_vec()),
        Some(SqliteValue::Blob(value)) => Ok(value.as_ref().to_vec()),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("{field} is not TEXT/BLOB"),
        )),
    }
}

fn row_i64(row: &Row, index: usize, field: &str) -> Result<i64> {
    match row.get(index) {
        Some(SqliteValue::Integer(value)) => Ok(*value),
        Some(SqliteValue::Text(value)) => value
            .parse()
            .map_err(|_| Error::new(ErrorKind::Storage, format!("{field} is not an integer"))),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("{field} is not INTEGER/TEXT"),
        )),
    }
}

fn row_u64(row: &Row, index: usize, field: &str) -> Result<u64> {
    let value = row_i64(row, index, field)?;
    u64::try_from(value).map_err(|_| Error::new(ErrorKind::Storage, format!("{field} is negative")))
}

#[cfg(test)]
mod tests {
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
                    "UPDATE metadata SET value = '4' WHERE key = 'schema_version';
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
}
