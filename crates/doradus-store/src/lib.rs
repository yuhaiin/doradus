//! SQLite-compatible persistent configuration/state storage.
//!
//! The database engine is intentionally hidden behind this typed boundary.
//! The production backend uses the mature SQLite amalgamation through
//! `rusqlite`'s `bundled` feature; the rest of the crate does not expose that
//! FFI/API boundary and can be moved to another backend later.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

mod compat_proxy;

#[path = "backup.rs"]
mod backup;
mod compat_runtime;
#[path = "fakeip_store.rs"]
mod fakeip_store;
mod inbound_runtime;
#[path = "lifecycle.rs"]
mod lifecycle;
mod migration;
mod records;
mod repository;
mod resolver;
mod row;
mod schema;
#[path = "snapshot.rs"]
mod snapshot;
mod sqlite;
mod statistics;
mod status;
mod users;
use doradus_core::{Error, ErrorKind, Result};
use migration::{
    import_go_schema, recover_legacy_node_chains, require_go_table, table_exists,
    validate_go_compat_text, validate_go_texts, validate_go_timestamp,
};
#[cfg(test)]
use migration::{meta_flag, table_row_count};
use schema::{
    configure_connection, table_has_column, typed_schema_sql, validate_typed_schema,
    verify_integrity,
};
use sha2::{Digest, Sha256};
use sqlite::{Connection, Row, SqliteValue};

pub mod fakeip;
pub use compat_proxy::{
    GoBaseProxyConfig, GoBaseProxyEndpoint, GoBaseProxyKind, GoProxyLayer, GoProxyRuntimeConfig,
    GoProxyTransport,
};
pub use compat_runtime::{
    GoFakeIpRuntimeConfig, GoResolverRuntimeConfig, GoResolverTransport, GoRouteRuntimeConfig,
    GoUdpProxyFqdnStrategy,
};
pub use inbound_runtime::{InboundRuntimeEvent, InboundRuntimeEventInput, InboundStatisticsRecord};
pub use records::*;
pub use resolver::{FakeIpPolicy, FakeIpPools, FakeIpResolver};
pub(crate) use row::*;
#[cfg(test)]
pub(crate) use snapshot::sha256_file;
pub(crate) use snapshot::{
    database_destination_parts, database_staging_path, ensure_destination_absent,
    ensure_destination_sidecars_absent, remove_database_sidecars,
};
pub use snapshot::{install_go_snapshot, install_go_snapshot_with_manifest, restore_database};
pub use statistics::{
    GoConnectionHistoryRecord, GoFailedHistoryRecord, GoStatisticsDelta, GoStatisticsSnapshot,
    GoTelemetryBucketRecord, GoTrafficBucketRecord, TELEMETRY_DAILY_BUCKET_SECONDS,
    TELEMETRY_HOURLY_BUCKET_SECONDS,
};
pub use status::StorageStatus;
pub use users::{
    GoBasicCredential, GoCredential, GoCredentialView, GoTokenCredential, GoUserRecord, GoUserView,
    GoUserWrite, GoUuidCredential,
};

const SCHEMA_VERSION: i64 = 3;
// Go schema 7 is an additive user/subscription-link migration. Rust does not
// implement subscription refresh yet, but it can safely open the database,
// import the shared v2 tables, and preserve the extra Go tables untouched.
// Later versions still fail closed until their table/enum contracts are
// audited.
const MAX_SUPPORTED_GO_SCHEMA_VERSION: i64 = 7;
/// Matches Go's default `configuration.UDPIdleTimeout` (90 seconds).
pub const DEFAULT_NAT_IDLE_TIMEOUT_MS: i64 = 90_000;
const BUSY_RETRY_ATTEMPTS: usize = 64;
const BUSY_RETRY_MAX_SLEEP: std::time::Duration = std::time::Duration::from_millis(50);
const STARTUP_COMPACT_MIN_FREE_BYTES: i64 = 4 << 20;
const STARTUP_COMPACT_MIN_FREE_RATIO: i64 = 10;
// Go intentionally excludes runtime observations from portable backups. Keep
// this list at the storage boundary so statistics/FakeIP/connection tables do
// not accidentally become part of the user configuration snapshot.
const BACKUP_RUNTIME_TABLES: &[&str] = &[
    "statistics_kv",
    "traffic_hourly",
    "connection_sessions",
    "connection_history",
    "failed_connection_history",
    "fakeip_entries",
    "fakeip_cursors",
    "traffic_dimension_hourly",
    "traffic_dimension_daily",
    "failure_dimension_hourly",
    "failure_dimension_daily",
    "telemetry_dimension_values",
    "inbound_runtime_events",
    "inbound_statistics",
];

// SQLite file initialization and WAL bootstrap must not be raced by separate
// handles for the same path. Gates are keyed by path so unrelated databases
// can still initialize concurrently; normal reads and writes remain
// concurrent after a handle is returned.
static OPEN_GATES: OnceLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigMutation {
    Put { key: String, value: Vec<u8> },
    Delete { key: String },
}

#[derive(Clone)]
pub struct ConfigStore {
    connection: Arc<Mutex<Connection>>,
    write_lock_path: Option<PathBuf>,
}

#[derive(Clone)]
pub struct ConfigRepository {
    store: ConfigStore,
}

impl ConfigStore {
    pub fn open_sync(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_legacy_import_sync(path, false)
    }

    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_sync(path)
    }

    /// Open a legacy database for the explicit future migration helpers.
    /// Normal runtime startup deliberately refuses to adopt legacy state.
    #[doc(hidden)]
    pub fn open_legacy_sync(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_legacy_import_sync(path, true)
    }

    #[doc(hidden)]
    pub async fn open_legacy(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_legacy_sync(path)
    }

    fn open_with_legacy_import_sync(
        path: impl AsRef<Path>,
        allow_legacy_import: bool,
    ) -> Result<Self> {
        let path = path
            .as_ref()
            .to_str()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "database path is not valid UTF-8"))?
            .to_owned();
        for attempt in 0..=BUSY_RETRY_ATTEMPTS {
            match Self::open_once(&path, allow_legacy_import) {
                Ok(store) => return Ok(store),
                Err(error) if attempt < BUSY_RETRY_ATTEMPTS && is_busy_error(&error) => {
                    busy_retry_sleep(attempt);
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("busy retry loop returns on its final iteration")
    }

    pub fn open_memory_sync() -> Result<Self> {
        Self::open_sync(":memory:")
    }

    pub async fn open_memory() -> Result<Self> {
        Self::open_memory_sync()
    }

    /// Compact the database only when SQLite reports enough reusable space.
    /// This keeps the expensive `VACUUM` operation thresholded rather than
    /// imposing a full database rewrite on every open.
    pub fn compact_if_needed_sync(&self) -> Result<bool> {
        self.compact_if_needed_inner()
    }

    pub async fn compact_if_needed(&self) -> Result<bool> {
        self.compact_if_needed_sync()
    }

    fn compact_if_needed_inner(&self) -> Result<bool> {
        self.with_write_retry(|connection| {
            connection
                .execute("PRAGMA wal_checkpoint(TRUNCATE)")
                .map_err(storage_error)?;
            let page_count = pragma_integer(connection, "page_count")?;
            let page_size = pragma_integer(connection, "page_size")?;
            let rows = connection
                .query("PRAGMA freelist_count")
                .map_err(storage_error)?;
            let free_pages = match rows.first().and_then(|row| row.get(0)) {
                Some(SqliteValue::Integer(value)) => *value,
                _ => {
                    return Err(Error::new(
                        ErrorKind::Storage,
                        "SQLite freelist_count is not an integer",
                    ));
                }
            };
            let free_bytes = free_pages.saturating_mul(page_size);
            let free_ratio = if page_count > 0 {
                free_pages.saturating_mul(100) / page_count
            } else {
                0
            };
            if free_bytes < STARTUP_COMPACT_MIN_FREE_BYTES
                && free_ratio < STARTUP_COMPACT_MIN_FREE_RATIO
            {
                return Ok(false);
            }
            connection.execute("VACUUM").map_err(storage_error)?;
            connection
                .execute("PRAGMA wal_checkpoint(TRUNCATE)")
                .map_err(storage_error)?;
            Ok(true)
        })
    }

    pub fn get_config_sync(&self, key: &str) -> Result<Option<Vec<u8>>> {
        validate_key(key)?;
        let connection = self.lock_connection()?;
        let rows = connection
            .query_with_params(
                "SELECT value FROM doradus_config WHERE key = ?1",
                &[SqliteValue::from(key)],
            )
            .map_err(storage_error)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        match row.get(0) {
            Some(SqliteValue::Blob(value)) => Ok(Some(value.as_ref().to_vec())),
            _ => Err(Error::new(ErrorKind::Storage, "config value is not a BLOB")),
        }
    }

    pub async fn get_config(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.get_config_sync(key)
    }

    pub fn list_config_sync(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>> {
        // An empty prefix is the intentional "list all" form used by startup
        // migration guards. Non-empty prefixes retain key validation.
        if !prefix.is_empty() {
            validate_key(prefix)?;
        }
        let pattern = format!("{prefix}%");
        let connection = self.lock_connection()?;
        let rows = connection
            .query_with_params(
                "SELECT key, value FROM doradus_config WHERE key LIKE ?1 ORDER BY key",
                &[SqliteValue::from(pattern)],
            )
            .map_err(storage_error)?;
        let mut values = Vec::with_capacity(rows.len());
        for row in rows {
            let key = match row.get(0) {
                Some(SqliteValue::Text(key)) => key.as_ref().to_owned(),
                _ => return Err(Error::new(ErrorKind::Storage, "config key is not TEXT")),
            };
            let value = match row.get(1) {
                Some(SqliteValue::Blob(value)) => value.as_ref().to_vec(),
                _ => return Err(Error::new(ErrorKind::Storage, "config value is not a BLOB")),
            };
            values.push((key, value));
        }
        Ok(values)
    }

    pub async fn list_config(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>> {
        self.list_config_sync(prefix)
    }

    pub fn put_config_sync(&self, key: &str, value: &[u8]) -> Result<()> {
        self.apply_sync(&[ConfigMutation::Put {
            key: key.to_owned(),
            value: value.to_vec(),
        }])
    }

    pub async fn put_config(&self, key: &str, value: &[u8]) -> Result<()> {
        // Route single-key writes through the same explicit BEGIN IMMEDIATE /
        // COMMIT path as batched mutations. SQLite's autocommit INSERT can
        // otherwise report success while concurrent processes race the WAL
        // root-page cursor and lose a frame.
        self.put_config_sync(key, value)
    }

    /// Best-effort single-key write used by runtime checkpoints. It never
    /// waits for a different process' repository lock; the next checkpoint or
    /// final flush can retry the complete in-memory state.
    pub fn try_put_config(&self, key: &str, value: &[u8]) -> Result<()> {
        validate_key(key)?;
        self.with_try_write(|connection| {
            apply_transaction(
                connection,
                &[ConfigMutation::Put {
                    key: key.to_owned(),
                    value: value.to_vec(),
                }],
            )
        })
    }

    pub fn delete_config_sync(&self, key: &str) -> Result<bool> {
        validate_key(key)?;
        self.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "DELETE FROM doradus_config WHERE key = ?1",
                    &[SqliteValue::from(key)],
                )
                .map(|changed| changed != 0)
                .map_err(storage_error)
        })
    }

    pub async fn delete_config(&self, key: &str) -> Result<bool> {
        self.delete_config_sync(key)
    }

    /// Apply a group of mutations atomically. Any validation or SQL failure
    /// rolls the whole group back.
    pub fn apply_sync(&self, mutations: &[ConfigMutation]) -> Result<()> {
        self.with_write_retry(|connection| apply_transaction(connection, mutations))
    }

    pub async fn apply(&self, mutations: &[ConfigMutation]) -> Result<()> {
        self.apply_sync(mutations)
    }

    fn open_once(path: &str, allow_legacy_import: bool) -> Result<Self> {
        let open_gate = OPEN_GATES
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .map_err(|_| Error::new(ErrorKind::Storage, "database gate map is poisoned"))?
            .entry(path.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _open_guard = open_gate
            .lock()
            .map_err(|_| Error::new(ErrorKind::Storage, "database open mutex is poisoned"))?;
        let write_lock_path = write_lock_path(path);
        let _initialization_lock = write_lock_path
            .as_ref()
            .map(|path| lock_write_file(path.as_path()))
            .transpose()?;
        let connection = match Connection::open(path) {
            Ok(connection) => connection,
            Err(error) => {
                let message = error.to_string();
                if message.contains("fts5: corrupt %_data") {
                    return Err(Error::new(
                        ErrorKind::Storage,
                        format!(
                            "open SQLite connection: {message}; the Go database contains an FTS5 shadow index that this Rust migration path cannot import directly; create a consistent checkpoint/export with the derived FTS index rebuilt or omitted, then retry the Rust migration"
                        ),
                    ));
                }
                return Err(storage_error(format!("open SQLite connection: {message}")));
            }
        };
        configure_connection(&connection).map_err(|error| {
            Error::new(error.kind, format!("configure database: {}", error.message))
        })?;
        let store = Self {
            connection: Arc::new(Mutex::new(connection)),
            write_lock_path,
        };
        store.migrate(allow_legacy_import).map_err(|error| {
            Error::new(error.kind, format!("migrate database: {}", error.message))
        })?;
        drop(_initialization_lock);
        // Match Go's state-db startup policy: reclaim substantial reusable
        // space, but do not rewrite a healthy database on every launch.
        store.compact_if_needed_inner()?;
        Ok(store)
    }

    fn with_write_retry<T, F>(&self, mut operation: F) -> Result<T>
    where
        F: FnMut(&Connection) -> Result<T>,
    {
        // SQLite's internal busy handling prevents ordinary lock errors but
        // cannot prevent every high-frequency commit race, so serialize writes
        // at this repository boundary while leaving WAL readers concurrent.
        let _write_lock = self
            .write_lock_path
            .as_ref()
            .map(|path| lock_write_file(path.as_path()))
            .transpose()?;
        for attempt in 0..=BUSY_RETRY_ATTEMPTS {
            let result = {
                let connection = self.lock_connection()?;
                operation(&connection)
            };
            match result {
                Ok(value) => return Ok(value),
                Err(error) if attempt < BUSY_RETRY_ATTEMPTS && is_busy_error(&error) => {
                    busy_retry_sleep(attempt);
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("busy retry loop returns on its final iteration")
    }

    /// Run one best-effort write without waiting for another process which
    /// owns the repository lock. Runtime telemetry uses this path for
    /// per-failure observations: the in-memory checkpoint remains the source
    /// of truth, so an unavailable SQLite writer must not retain sockets or
    /// stall shutdown.
    pub(crate) fn with_try_write<T, F>(&self, operation: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let _write_lock = self
            .write_lock_path
            .as_ref()
            .map(|path| try_lock_write_file(path.as_path()))
            .transpose()?;
        let connection = self.lock_connection()?;
        operation(&connection)
    }

    fn with_write_transaction<T, F>(&self, mut operation: F) -> Result<T>
    where
        F: FnMut(&Connection) -> Result<T>,
    {
        self.with_write_retry(|connection| {
            connection
                .execute("BEGIN IMMEDIATE")
                .map_err(storage_error)?;
            match operation(connection) {
                Ok(value) => match connection.execute("COMMIT") {
                    Ok(_) => Ok(value),
                    Err(error) => {
                        let _ = connection.execute("ROLLBACK");
                        Err(storage_error(error))
                    }
                },
                Err(error) => {
                    let _ = connection.execute("ROLLBACK");
                    Err(error)
                }
            }
        })
    }

    fn lock_connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| Error::new(ErrorKind::Storage, "database mutex is poisoned"))
    }
}

/// Restore a previously validated Rust SQLite backup into `destination`.
/// Every `ConfigStore` handle for `destination` must be closed before calling
/// this function. The backup is copied to staging, opened, integrity-checked
/// through normal store startup, and only then atomically replaces the old
/// database. If validation or installation fails, the existing database file
/// remains in place.
fn apply_transaction(connection: &Connection, mutations: &[ConfigMutation]) -> Result<()> {
    if let Err(error) = connection.execute("BEGIN IMMEDIATE") {
        let _ = connection.execute("ROLLBACK");
        return Err(storage_error(error));
    }
    let result = apply_in_transaction(connection, mutations);
    match result {
        Ok(()) => match connection.execute("COMMIT") {
            Ok(_) => Ok(()),
            Err(error) => {
                let _ = connection.execute("ROLLBACK");
                Err(storage_error(error))
            }
        },
        Err(error) => {
            let _ = connection.execute("ROLLBACK");
            Err(error)
        }
    }
}

fn apply_in_transaction(connection: &Connection, mutations: &[ConfigMutation]) -> Result<()> {
    for mutation in mutations {
        match mutation {
            ConfigMutation::Put { key, value } => {
                validate_key(key)?;
                connection
                    .execute_with_params(
                        "INSERT OR REPLACE INTO doradus_config (key, value)
                         VALUES (?1, ?2)",
                        &[
                            SqliteValue::from(key.as_str()),
                            SqliteValue::from(value.as_slice()),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            ConfigMutation::Delete { key } => {
                validate_key(key)?;
                connection
                    .execute_with_params(
                        "DELETE FROM doradus_config WHERE key = ?1",
                        &[SqliteValue::from(key.as_str())],
                    )
                    .map_err(storage_error)?;
            }
        }
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 512 || key.chars().any(char::is_control) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "config key must be 1..=512 non-control characters",
        ));
    }
    Ok(())
}

fn write_lock_path(path: &str) -> Option<PathBuf> {
    (path != ":memory:").then(|| PathBuf::from(format!("{path}-doradus-write-lock")))
}

#[cfg(not(target_os = "android"))]
fn lock_write_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(storage_error)?;
    file.lock().map_err(storage_error)?;
    Ok(file)
}

#[cfg(not(target_os = "android"))]
fn try_lock_write_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(storage_error)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => Err(Error::new(
            ErrorKind::Storage,
            "database write lock is busy",
        )),
        Err(std::fs::TryLockError::Error(error)) => Err(storage_error(error)),
    }
}

#[cfg(target_os = "android")]
fn lock_write_file(path: &Path) -> Result<File> {
    // Android's std::fs::File exposes the lock API but its bionic-backed
    // implementation returns Unsupported. SQLite still provides the actual
    // cross-process database locking and the caller retries SQLITE_BUSY.
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(storage_error)
}

#[cfg(target_os = "android")]
fn try_lock_write_file(path: &Path) -> Result<File> {
    lock_write_file(path)
}

fn storage_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Storage, error.to_string())
}

fn is_busy_error(error: &Error) -> bool {
    if error.kind != ErrorKind::Storage {
        return false;
    }
    let message = error.message.to_ascii_lowercase();
    // A concurrent SQLite WAL/root-page collision can surface as an internal
    // OpenWrite error instead of the usual BUSY/LOCKED code. It is transient
    // during independent process opens/writes; retry it within the same bounded
    // backoff instead of treating it as file corruption. Integrity checks still
    // fail closed for persistent damage.
    [
        "busy",
        "locked",
        "openwrite failed",
        "could not open storage cursor",
    ]
    .iter()
    .any(|marker| message.contains(marker))
}

fn busy_retry_sleep(attempt: usize) {
    let exponent = attempt.min(5) as u32;
    let delay = std::time::Duration::from_millis(1u64 << exponent).min(BUSY_RETRY_MAX_SLEEP);
    std::thread::sleep(delay);
}

#[cfg(test)]
mod tests;
