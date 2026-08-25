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
#[path = "lifecycle.rs"]
mod lifecycle;
mod migration;
mod records;
mod repository;
mod resolver;
mod schema;
#[path = "snapshot.rs"]
mod snapshot;
mod sqlite;
mod statistics;
mod status;
mod users;
use migration::{
    import_go_schema, recover_legacy_node_chains, require_go_table, table_exists,
    validate_go_compat_text, validate_go_texts, validate_go_timestamp,
};
#[cfg(test)]
use migration::{meta_flag, table_row_count};
use schema::{
    bootstrap_go_compatibility_metadata, configure_connection, prepare_go_legacy_tables,
    table_has_column, typed_schema_sql, validate_typed_schema, verify_integrity,
};
use sha2::{Digest, Sha256};
use sqlite::{Connection, Row, SqliteValue};
use yuhaiin_core::{Error, ErrorKind, Result};

pub mod fakeip;
pub use compat_proxy::{GoProxyLayer, GoProxyRuntimeConfig, GoProxyTransport};
pub use compat_runtime::{
    GoFakeIpRuntimeConfig, GoResolverRuntimeConfig, GoResolverTransport, GoRouteRuntimeConfig,
    GoUdpProxyFqdnStrategy,
};
pub use records::*;
pub use resolver::{FakeIpPolicy, FakeIpPools, FakeIpResolver};
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
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path
            .as_ref()
            .to_str()
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "database path is not valid UTF-8"))?
            .to_owned();
        for attempt in 0..=BUSY_RETRY_ATTEMPTS {
            match Self::open_once(&path) {
                Ok(store) => return Ok(store),
                Err(error) if attempt < BUSY_RETRY_ATTEMPTS && is_busy_error(&error) => {
                    busy_retry_sleep(attempt);
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!("busy retry loop returns on its final iteration")
    }

    pub async fn open_memory() -> Result<Self> {
        Self::open(":memory:").await
    }

    /// Compact the database only when SQLite reports enough reusable space.
    /// This keeps the expensive `VACUUM` operation thresholded rather than
    /// imposing a full database rewrite on every open.
    pub async fn compact_if_needed(&self) -> Result<bool> {
        self.compact_if_needed_sync()
    }

    fn compact_if_needed_sync(&self) -> Result<bool> {
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

    pub async fn get_config(&self, key: &str) -> Result<Option<Vec<u8>>> {
        validate_key(key)?;
        let connection = self.lock_connection()?;
        let rows = connection
            .query_with_params(
                "SELECT value FROM yuhaiin_config WHERE key = ?1",
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

    pub async fn list_config(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>> {
        // An empty prefix is the intentional "list all" form used by startup
        // migration guards.  Non-empty prefixes retain the same key
        // validation as get/put/delete.
        if !prefix.is_empty() {
            validate_key(prefix)?;
        }
        let pattern = format!("{prefix}%");
        let connection = self.lock_connection()?;
        let rows = connection
            .query_with_params(
                "SELECT key, value FROM yuhaiin_config WHERE key LIKE ?1 ORDER BY key",
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

    pub async fn put_config(&self, key: &str, value: &[u8]) -> Result<()> {
        // Route single-key writes through the same explicit BEGIN IMMEDIATE /
        // COMMIT path as batched mutations. SQLite's autocommit INSERT can
        // otherwise report success while concurrent processes race the WAL
        // root-page cursor and lose a frame.
        self.apply(&[ConfigMutation::Put {
            key: key.to_owned(),
            value: value.to_vec(),
        }])
        .await
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

    pub async fn delete_config(&self, key: &str) -> Result<bool> {
        validate_key(key)?;
        self.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "DELETE FROM yuhaiin_config WHERE key = ?1",
                    &[SqliteValue::from(key)],
                )
                .map(|changed| changed != 0)
                .map_err(storage_error)
        })
    }

    /// Apply a group of mutations atomically. Any validation or SQL failure
    /// rolls the whole group back.
    pub async fn apply(&self, mutations: &[ConfigMutation]) -> Result<()> {
        self.with_write_retry(|connection| apply_transaction(connection, mutations))
    }

    fn open_once(path: &str) -> Result<Self> {
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
        store.migrate().map_err(|error| {
            Error::new(error.kind, format!("migrate database: {}", error.message))
        })?;
        drop(_initialization_lock);
        // Match Go's state-db startup policy: reclaim substantial reusable
        // space, but do not rewrite a healthy database on every launch.
        store.compact_if_needed_sync()?;
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
fn row_blob_or_text(row: &Row, index: usize, field: &str) -> Result<Vec<u8>> {
    match row.get(index) {
        Some(SqliteValue::Blob(value)) => Ok(value.as_ref().to_vec()),
        Some(SqliteValue::Text(value)) => Ok(value.as_bytes().to_vec()),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("Go schema field {field} is not TEXT or BLOB"),
        )),
    }
}

fn row_json_blob_or_text(row: &Row, index: usize, field: &str) -> Result<Vec<u8>> {
    let value = row_blob_or_text(row, index, field)?;
    validate_json_bytes(&value, field)?;
    Ok(value)
}

fn validate_json_bytes(value: &[u8], field: &str) -> Result<()> {
    serde_json::from_slice::<serde_json::Value>(value).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("decode {field} as JSON failed: {error}"),
        )
    })?;
    Ok(())
}

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
                        "INSERT OR REPLACE INTO yuhaiin_config (key, value)
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
                        "DELETE FROM yuhaiin_config WHERE key = ?1",
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
    (path != ":memory:").then(|| PathBuf::from(format!("{path}-yuhaiin-write-lock")))
}

fn database_destination_parts(destination: &Path) -> Result<(PathBuf, String)> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    std::fs::create_dir_all(&parent).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("create SQLite destination directory: {error}"),
        )
    })?;
    let name = destination
        .file_name()
        .and_then(|name| (!name.is_empty()).then(|| name.to_string_lossy().into_owned()))
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "SQLite destination must contain a file name",
            )
        })?;
    Ok((parent, name))
}

fn ensure_destination_absent(destination: &Path) -> Result<()> {
    match std::fs::symlink_metadata(destination) {
        Ok(_) => Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "refusing to overwrite SQLite destination: {}",
                destination.display()
            ),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::new(
            ErrorKind::Storage,
            format!("inspect SQLite destination: {error}"),
        )),
    }
}

fn ensure_destination_sidecars_absent(destination: &Path) -> Result<()> {
    for suffix in [
        "-journal",
        "-wal",
        "-shm",
        "-wal-fec",
        "-fsqlite-ns-use",
        "-fsqlite-ns-gate",
        "-yuhaiin-write-lock",
    ] {
        let sidecar = PathBuf::from(format!("{}{}", destination.display(), suffix));
        if sidecar.exists() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "refusing to use SQLite destination with an existing sidecar: {}",
                    sidecar.display()
                ),
            ));
        }
    }
    Ok(())
}

fn ensure_restore_destination_safe(destination: &Path) -> Result<()> {
    match std::fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(Error::new(
            ErrorKind::InvalidInput,
            "SQLite restore destination must be a regular file",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure_destination_sidecars_absent(destination)
        }
        Err(error) => Err(Error::new(
            ErrorKind::Storage,
            format!("inspect SQLite restore destination: {error}"),
        )),
    }
}

fn database_staging_path(parent: &Path, name: &str, kind: &str) -> Result<PathBuf> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Error::new(ErrorKind::Storage, format!("read system clock: {error}")))?
        .as_nanos();
    let staging = parent.join(format!(
        ".{name}.yuhaiin-{kind}-{}-{nonce}.tmp",
        std::process::id()
    ));
    if staging.exists() {
        return Err(Error::new(
            ErrorKind::Storage,
            format!("SQLite staging path already exists: {}", staging.display()),
        ));
    }
    Ok(staging)
}

fn remove_database_sidecars(path: &Path) {
    // The fsqlite namespace files are retained only as compatibility cleanup
    // for databases produced by the discarded experimental backend.
    for suffix in [
        "-journal",
        "-wal",
        "-shm",
        "-wal-fec",
        "-fsqlite-ns-use",
        "-fsqlite-ns-gate",
        "-yuhaiin-write-lock",
    ] {
        let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
        let _ = std::fs::remove_file(sidecar);
    }
}

fn verify_go_snapshot_manifest(
    source: &Path,
    manifest_path: &Path,
    source_bytes: u64,
) -> Result<()> {
    if !manifest_path.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "Go snapshot manifest does not exist: {}",
                manifest_path.display()
            ),
        ));
    }
    let mut file = File::open(manifest_path).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("open Go snapshot manifest: {error}"),
        )
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("read Go snapshot manifest: {error}"),
        )
    })?;
    let manifest: GoSnapshotManifest = serde_json::from_slice(&bytes).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("decode Go snapshot manifest: {error}"),
        )
    })?;
    if manifest.format_version != 1
        || manifest.tool != "yuhaiin-rust-export"
        || manifest.tool_version != "1"
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "unsupported Go snapshot manifest format or exporter version",
        ));
    }
    if manifest.source_schema_version.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Go snapshot manifest has no source schema version",
        ));
    }
    if manifest.snapshot_bytes != source_bytes {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "Go snapshot manifest byte count {} does not match source {}",
                manifest.snapshot_bytes, source_bytes
            ),
        ));
    }
    let actual_hash = sha256_file(source)?;
    if manifest.snapshot_sha256 != actual_hash {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "Go snapshot SHA-256 mismatch: manifest={}, actual={actual_hash}",
                manifest.snapshot_sha256
            ),
        ));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("open file for SHA-256: {error}"),
        )
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            Error::new(
                ErrorKind::Storage,
                format!("read file for SHA-256: {error}"),
            )
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
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

fn validate_id(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(Error::invalid(
            "typed store identifier must be 1..=512 non-control characters",
        ));
    }
    Ok(())
}

fn validate_fakeip_scope(family: i64, prefix: &str) -> Result<()> {
    if family != 4 && family != 6 {
        return Err(Error::invalid("FakeIP family must be 4 or 6"));
    }
    validate_id(prefix)
}

fn validate_fakeip_entry(entry: &FakeIpEntryRecord) -> Result<()> {
    validate_fakeip_scope(entry.family, &entry.prefix)?;
    validate_id(&entry.domain)?;
    let expected_len = if entry.family == 4 { 4 } else { 16 };
    if entry.ip.len() != expected_len {
        return Err(Error::invalid("FakeIP entry has an invalid IP length"));
    }
    if entry.created_at < 0 || entry.last_used_at < 0 {
        return Err(Error::invalid(
            "FakeIP entry timestamps must not be negative",
        ));
    }
    Ok(())
}

fn validate_fakeip_cursor(cursor: &FakeIpCursorRecord) -> Result<()> {
    validate_fakeip_scope(cursor.family, &cursor.prefix)?;
    let expected_len = if cursor.family == 4 { 4 } else { 16 };
    if cursor.cursor_ip.len() != expected_len {
        return Err(Error::invalid("FakeIP cursor has an invalid IP length"));
    }
    if cursor.cursor_idx < 0 || cursor.updated_at < 0 {
        return Err(Error::invalid("FakeIP cursor values must not be negative"));
    }
    Ok(())
}

fn row_text(row: &Row, index: usize, field: &str) -> Result<String> {
    match row.get(index) {
        Some(SqliteValue::Text(value)) => Ok(value.as_ref().to_owned()),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("typed store field {field} is not TEXT"),
        )),
    }
}

fn row_optional_text(row: &Row, index: usize, field: &str) -> Result<Option<String>> {
    match row.get(index) {
        Some(SqliteValue::Null) => Ok(None),
        Some(SqliteValue::Text(value)) => Ok(Some(value.as_ref().to_owned())),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("typed store field {field} is not nullable TEXT"),
        )),
    }
}

fn row_blob(row: &Row, index: usize, field: &str) -> Result<Vec<u8>> {
    match row.get(index) {
        Some(SqliteValue::Blob(value)) => Ok(value.as_ref().to_vec()),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("typed store field {field} is not BLOB"),
        )),
    }
}

fn row_integer(row: &Row, index: usize, field: &str) -> Result<i64> {
    match row.get(index) {
        Some(SqliteValue::Integer(value)) => Ok(*value),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("typed store field {field} is not INTEGER"),
        )),
    }
}

fn pragma_integer(connection: &Connection, name: &str) -> Result<i64> {
    let row = connection
        .query(&format!("PRAGMA {name}"))
        .map_err(storage_error)?
        .into_iter()
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Storage, format!("PRAGMA {name} returned no row")))?;
    row_integer(&row, 0, name)
}

fn fakeip_entry_from_row(row: &Row) -> Result<FakeIpEntryRecord> {
    Ok(FakeIpEntryRecord {
        family: row_integer(row, 0, "fakeip_entries.family")?,
        prefix: row_text(row, 1, "fakeip_entries.prefix")?,
        domain: row_text(row, 2, "fakeip_entries.domain")?,
        ip: row_blob(row, 3, "fakeip_entries.ip")?,
        created_at: row_integer(row, 4, "fakeip_entries.created_at")?,
        last_used_at: row_integer(row, 5, "fakeip_entries.last_used_at")?,
    })
}

fn fakeip_cursor_from_row(row: &Row) -> Result<FakeIpCursorRecord> {
    Ok(FakeIpCursorRecord {
        family: row_integer(row, 0, "fakeip_cursors.family")?,
        prefix: row_text(row, 1, "fakeip_cursors.prefix")?,
        cursor_ip: row_blob(row, 2, "fakeip_cursors.cursor_ip")?,
        cursor_idx: row_integer(row, 3, "fakeip_cursors.cursor_idx")?,
        updated_at: row_integer(row, 4, "fakeip_cursors.updated_at")?,
    })
}

fn proxy_node_from_row(row: &Row) -> Result<ProxyNodeRecord> {
    Ok(ProxyNodeRecord {
        id: row_text(row, 0, "proxy_nodes.id")?,
        kind: row_text(row, 1, "proxy_nodes.kind")?,
        config: row_blob(row, 2, "proxy_nodes.config")?,
    })
}

fn route_rule_from_row(row: &Row) -> Result<RouteRuleRecord> {
    Ok(RouteRuleRecord {
        id: row_text(row, 0, "route_rules.id")?,
        pattern: row_text(row, 1, "route_rules.pattern")?,
        action: row_text(row, 2, "route_rules.action")?,
        priority: row_integer(row, 3, "route_rules.priority")?,
        geo_country: row_optional_text(row, 4, "route_rules.geo_country")?,
        resolver_policy: row_blob(row, 5, "route_rules.resolver_policy")?,
    })
}

fn dns_resolver_from_row(row: &Row) -> Result<DnsResolverRecord> {
    Ok(DnsResolverRecord {
        id: row_text(row, 0, "dns_resolvers.id")?,
        kind: row_text(row, 1, "dns_resolvers.kind")?,
        config: row_blob(row, 2, "dns_resolvers.config")?,
    })
}

fn tun_config_from_row(row: &Row) -> Result<TunConfigRecord> {
    Ok(TunConfigRecord {
        key: row_text(row, 0, "tun_config.key")?,
        value: row_blob(row, 1, "tun_config.value")?,
    })
}

fn nat_config_from_row(row: &Row) -> Result<NatConfigRecord> {
    let full_cone = row_integer(row, 1, "nat_config.full_cone")?;
    if full_cone != 1 {
        return Err(Error::new(
            ErrorKind::Storage,
            "nat_config.full_cone must be enabled; only Full Cone NAT is supported",
        ));
    }
    Ok(NatConfigRecord {
        key: row_text(row, 0, "nat_config.key")?,
        full_cone: true,
        idle_timeout_ms: row_integer(row, 2, "nat_config.idle_timeout_ms")?,
    })
}

fn maxmind_from_row(row: &Row) -> Result<MaxMindMetadataRecord> {
    Ok(MaxMindMetadataRecord {
        id: row_text(row, 0, "maxmind_metadata.id")?,
        path: row_text(row, 1, "maxmind_metadata.path")?,
        sha256: row_blob(row, 2, "maxmind_metadata.sha256")?,
        size: row_integer(row, 3, "maxmind_metadata.size")?,
        updated_at: row_integer(row, 4, "maxmind_metadata.updated_at")?,
    })
}

#[cfg(test)]
mod tests;
