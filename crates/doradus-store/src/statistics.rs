//! Go-compatible statistics tables.
//!
//! Runtime state is kept in memory for fast packet-path updates, while this
//! boundary owns the durable totals/history/traffic tables used by both the
//! Rust and Go runtimes. Runtime writers submit small additive batches rather
//! than loading the whole historical projection into a long-lived object.

use super::{ConfigStore, Error, ErrorKind, Result, SqliteValue, storage_error, table_exists};
use crate::sqlite::Row;

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

/// Runtime deltas that can be applied without loading the historical
/// statistics into the process. Counts in history, failures, traffic and
/// telemetry are additive; totals are absolute values from the live monitor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GoStatisticsDelta {
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

    /// Read only the two durable totals needed to initialise the live
    /// monitor. Historical rows stay in SQLite until an API asks for them.
    pub fn load_go_totals(&self) -> Result<(u64, u64)> {
        let connection = self.lock_connection()?;
        let mut total_download = 0;
        let mut total_upload = 0;
        if table_exists(&connection, "statistics_kv") {
            for row in connection
                .query("SELECT key, value_int FROM statistics_kv")
                .map_err(storage_error)?
            {
                match row_text(&row, 0, "statistics_kv.key")?.as_str() {
                    "total_download" => {
                        total_download = row_u64(&row, 1, "statistics_kv.value_int")?
                    }
                    "total_upload" => total_upload = row_u64(&row, 1, "statistics_kv.value_int")?,
                    _ => {}
                }
            }
        }
        Ok((total_download, total_upload))
    }

    /// Replace the Go-compatible statistics projection atomically. This is
    /// intentionally a final-flush operation; frequent crash checkpoints use
    /// the compact statistics.runtime record instead.
    pub fn replace_go_statistics(&self, snapshot: &GoStatisticsSnapshot) -> Result<()> {
        self.with_write_retry(|connection| replace(connection, snapshot))
    }

    /// Best-effort compatibility projection for shutdown/checkpoint paths.
    /// Runtime state is retained in memory when another writer owns SQLite;
    /// callers can retry it on the next periodic or final flush.
    pub fn try_replace_go_statistics(&self, snapshot: &GoStatisticsSnapshot) -> Result<()> {
        self.with_try_write(|connection| replace(connection, snapshot))
    }

    /// Record one failed connection in Go's durable table.
    ///
    /// The runtime owns the call from a single persistence worker. Keeping the
    /// small UPSERT here preserves Go's durable failed-history projection
    /// without making every inbound failure callback wait for SQLite.
    pub fn record_failed_history(
        &self,
        protocol: &str,
        host: &str,
        process: &str,
        error: &str,
        last_seen: i64,
    ) -> Result<()> {
        self.with_write_retry(|connection| {
            record_failed_history_row(connection, protocol, host, process, error, last_seen)
        })
    }

    /// Best-effort variant for the runtime failure-history queue. It does not
    /// wait for another process' repository lock and performs only one SQLite
    /// attempt. The runtime checkpoint contains the aggregate row, so a
    /// transiently busy database can safely defer this derived projection.
    pub fn try_record_failed_history(
        &self,
        protocol: &str,
        host: &str,
        process: &str,
        error: &str,
        last_seen: i64,
    ) -> Result<()> {
        self.with_try_write(|connection| {
            record_failed_history_row(connection, protocol, host, process, error, last_seen)
        })
    }

    /// Apply a batch of runtime observations directly to the Go-compatible
    /// SQLite tables. This is the steady-state path; unlike
    /// [`replace_go_statistics`](Self::replace_go_statistics), it never reads
    /// the historical tables into a Rust-owned snapshot first.
    pub fn try_apply_go_statistics_delta(&self, delta: &GoStatisticsDelta) -> Result<()> {
        self.with_try_write(|connection| apply_delta(connection, delta))
    }

    /// Apply a batch, waiting for the normal SQLite write retry policy. This
    /// is used by the explicit shutdown flush after the background worker has
    /// stopped.
    pub fn apply_go_statistics_delta(&self, delta: &GoStatisticsDelta) -> Result<()> {
        self.with_write_retry(|connection| apply_delta(connection, delta))
    }
}

#[path = "statistics_delta.rs"]
mod statistics_delta;
#[path = "statistics_projection.rs"]
mod statistics_projection;

use statistics_delta::{apply_delta, record_failed_history_row};
use statistics_projection::{load, replace};

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
#[cfg(test)]
#[path = "statistics_tests.rs"]
mod tests;
