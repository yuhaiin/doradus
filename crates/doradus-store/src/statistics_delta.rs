//! Incremental writes for the Go-compatible statistics projection.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::schema::table_has_column;
use crate::sqlite::Connection;

use super::statistics_projection::{load, replace};
use super::*;

pub(super) fn apply_delta(connection: &Connection, delta: &GoStatisticsDelta) -> Result<()> {
    // Older Go databases used the pre-v6 dimension/value schema. Migrate it
    // once before the first incremental write so the steady-state path can
    // use the compact tables without retaining a compatibility snapshot.
    if !table_exists(connection, "telemetry_dimension_values")
        && table_exists(connection, "traffic_dimension_hourly")
        && table_has_column(connection, "traffic_dimension_hourly", "dimension")
            .map_err(storage_error)?
    {
        let existing = load(connection)?;
        replace(connection, &existing)?;
    }
    connection
        .execute("BEGIN IMMEDIATE")
        .map_err(storage_error)?;
    let result = apply_delta_in_transaction(connection, delta);
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

fn apply_delta_in_transaction(connection: &Connection, delta: &GoStatisticsDelta) -> Result<()> {
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
            );
            CREATE TABLE IF NOT EXISTS telemetry_dimension_values (
                id INTEGER PRIMARY KEY, dimension TEXT NOT NULL, value TEXT NOT NULL,
                UNIQUE (dimension, value)
            );
            CREATE TABLE IF NOT EXISTS traffic_dimension_hourly (
                bucket_start_utc INTEGER NOT NULL, value_id INTEGER NOT NULL,
                upload_bytes INTEGER NOT NULL, download_bytes INTEGER NOT NULL,
                PRIMARY KEY (bucket_start_utc, value_id)
            );
            CREATE TABLE IF NOT EXISTS failure_dimension_hourly (
                bucket_start_utc INTEGER NOT NULL, value_id INTEGER NOT NULL,
                failed_count INTEGER NOT NULL,
                PRIMARY KEY (bucket_start_utc, value_id)
            );
            CREATE TABLE IF NOT EXISTS traffic_dimension_daily (
                bucket_start_utc INTEGER NOT NULL, value_id INTEGER NOT NULL,
                upload_bytes INTEGER NOT NULL, download_bytes INTEGER NOT NULL,
                PRIMARY KEY (bucket_start_utc, value_id)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS failure_dimension_daily (
                bucket_start_utc INTEGER NOT NULL, value_id INTEGER NOT NULL,
                failed_count INTEGER NOT NULL,
                PRIMARY KEY (bucket_start_utc, value_id)
            ) WITHOUT ROWID;",
        )
        .map_err(storage_error)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Error::new(ErrorKind::Storage, error.to_string()))?
        .as_secs() as i64;
    for (key, value) in [
        ("total_download", delta.total_download),
        ("total_upload", delta.total_upload),
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

    for bucket in &delta.traffic {
        connection
            .execute_with_params(
                "INSERT INTO traffic_hourly(
                    bucket_start_utc, upload_bytes, download_bytes, updated_at
                 ) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(bucket_start_utc) DO UPDATE SET
                   upload_bytes = traffic_hourly.upload_bytes + excluded.upload_bytes,
                   download_bytes = traffic_hourly.download_bytes + excluded.download_bytes,
                   updated_at = excluded.updated_at",
                &[
                    SqliteValue::from(bucket.bucket),
                    SqliteValue::from(u64_to_i64(bucket.upload, "traffic upload")?),
                    SqliteValue::from(u64_to_i64(bucket.download, "traffic download")?),
                    SqliteValue::from(now),
                ],
            )
            .map_err(storage_error)?;
    }

    for history in &delta.history {
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
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(protocol, addr, process_name) DO UPDATE SET
                   hit_count = connection_history.hit_count + excluded.hit_count,
                   last_seen_at = excluded.last_seen_at,
                   last_connection_json = excluded.last_connection_json",
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

    for failure in &delta.failed_history {
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

    for item in &delta.telemetry {
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
        let Some(row) = rows.first() else {
            return Err(Error::new(
                ErrorKind::Storage,
                "telemetry dimension value was not created",
            ));
        };
        let value_id = row_i64(row, 0, "telemetry_dimension_values.id")?;
        let bucket = item.bucket.div_euclid(TELEMETRY_HOURLY_BUCKET_SECONDS)
            * TELEMETRY_HOURLY_BUCKET_SECONDS;
        connection
            .execute_with_params(
                "INSERT INTO traffic_dimension_hourly(
                    bucket_start_utc, value_id, upload_bytes, download_bytes
                 ) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(bucket_start_utc, value_id) DO UPDATE SET
                   upload_bytes = traffic_dimension_hourly.upload_bytes + excluded.upload_bytes,
                   download_bytes = traffic_dimension_hourly.download_bytes + excluded.download_bytes",
                &[
                    SqliteValue::from(bucket),
                    SqliteValue::from(value_id),
                    SqliteValue::from(u64_to_i64(item.upload, "telemetry upload")?),
                    SqliteValue::from(u64_to_i64(item.download, "telemetry download")?),
                ],
            )
            .map_err(storage_error)?;
        if item.failures != 0 {
            connection
                .execute_with_params(
                    "INSERT INTO failure_dimension_hourly(
                        bucket_start_utc, value_id, failed_count
                     ) VALUES (?1, ?2, ?3)
                     ON CONFLICT(bucket_start_utc, value_id) DO UPDATE SET
                       failed_count = failure_dimension_hourly.failed_count + excluded.failed_count",
                    &[
                        SqliteValue::from(bucket),
                        SqliteValue::from(value_id),
                        SqliteValue::from(u64_to_i64(item.failures, "telemetry failures")?),
                    ],
                )
                .map_err(storage_error)?;
        }
    }

    let telemetry_cutoff = now.div_euclid(3_600) * 3_600 - TELEMETRY_HOURLY_RETENTION_SECONDS;
    connection
        .execute_with_params(
            "INSERT INTO traffic_dimension_daily(
                 bucket_start_utc, value_id, upload_bytes, download_bytes
             )
             SELECT (bucket_start_utc / ?1) * ?1, value_id,
                    SUM(upload_bytes), SUM(download_bytes)
             FROM traffic_dimension_hourly
             WHERE bucket_start_utc < ?2
             GROUP BY (bucket_start_utc / ?1) * ?1, value_id
             ON CONFLICT(bucket_start_utc, value_id) DO UPDATE SET
               upload_bytes = traffic_dimension_daily.upload_bytes + excluded.upload_bytes,
               download_bytes = traffic_dimension_daily.download_bytes + excluded.download_bytes",
            &[
                SqliteValue::from(TELEMETRY_SECONDS_PER_DAY),
                SqliteValue::from(telemetry_cutoff),
            ],
        )
        .map_err(storage_error)?;
    connection
        .execute_with_params(
            "INSERT INTO failure_dimension_daily(bucket_start_utc, value_id, failed_count)
             SELECT (bucket_start_utc / ?1) * ?1, value_id, SUM(failed_count)
             FROM failure_dimension_hourly
             WHERE bucket_start_utc < ?2
             GROUP BY (bucket_start_utc / ?1) * ?1, value_id
             ON CONFLICT(bucket_start_utc, value_id) DO UPDATE SET
               failed_count = failure_dimension_daily.failed_count + excluded.failed_count",
            &[
                SqliteValue::from(TELEMETRY_SECONDS_PER_DAY),
                SqliteValue::from(telemetry_cutoff),
            ],
        )
        .map_err(storage_error)?;
    for table in ["traffic_dimension_hourly", "failure_dimension_hourly"] {
        connection
            .execute_with_params(
                &format!("DELETE FROM {table} WHERE bucket_start_utc < ?1"),
                &[SqliteValue::from(telemetry_cutoff)],
            )
            .map_err(storage_error)?;
    }
    Ok(())
}

pub(super) fn record_failed_history_row(
    connection: &Connection,
    protocol: &str,
    host: &str,
    process: &str,
    error: &str,
    last_seen: i64,
) -> Result<()> {
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
}
