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
#[cfg(feature = "async-proxy")]
mod compat_proxy_async;
mod compat_runtime;
mod migration;
mod repository;
#[cfg(feature = "async-dns")]
mod resolver;
mod schema;
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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlite::{Connection, Row, SqliteValue};
use yuhaiin_core::{Error, ErrorKind, Result};

pub mod fakeip;
pub use compat_proxy::{GoProxyLayer, GoProxyRuntimeConfig, GoProxyTransport};
pub use compat_runtime::{
    GoFakeIpRuntimeConfig, GoResolverRuntimeConfig, GoResolverTransport, GoRouteRuntimeConfig,
    GoUdpProxyFqdnStrategy,
};
#[cfg(feature = "async-dns")]
pub use resolver::{FakeIpPools, FakeIpResolver};
pub use statistics::{
    GoConnectionHistoryRecord, GoFailedHistoryRecord, GoStatisticsSnapshot,
    GoTelemetryBucketRecord, GoTrafficBucketRecord,
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
pub const DEFAULT_NAT_IDLE_TIMEOUT_MS: i64 = 30_000;
const BUSY_RETRY_ATTEMPTS: usize = 64;
const BUSY_RETRY_MAX_SLEEP: std::time::Duration = std::time::Duration::from_millis(50);

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyNodeRecord {
    pub id: String,
    pub kind: String,
    pub config: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRuleRecord {
    pub id: String,
    pub pattern: String,
    pub action: String,
    pub priority: i64,
    pub geo_country: Option<String>,
    pub resolver_policy: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResolverRecord {
    pub id: String,
    pub kind: String,
    pub config: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunConfigRecord {
    pub key: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatConfigRecord {
    pub key: String,
    pub full_cone: bool,
    pub idle_timeout_ms: i64,
}

impl Default for NatConfigRecord {
    fn default() -> Self {
        Self {
            key: "default".to_owned(),
            full_cone: true,
            idle_timeout_ms: DEFAULT_NAT_IDLE_TIMEOUT_MS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaxMindMetadataRecord {
    pub id: String,
    pub path: String,
    pub sha256: Vec<u8>,
    pub size: i64,
    pub updated_at: i64,
}

/// Typed persistence boundary for one FakeIP mapping.  `family` is 4 or 6,
/// `prefix` is the canonical pool identity, and `ip` is stored in network
/// byte order (4 bytes for IPv4, 16 bytes for IPv6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeIpEntryRecord {
    pub family: i64,
    pub prefix: String,
    pub domain: String,
    pub ip: Vec<u8>,
    pub created_at: i64,
    pub last_used_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FakeIpCursorRecord {
    pub family: i64,
    pub prefix: String,
    pub cursor_ip: Vec<u8>,
    pub cursor_idx: i64,
    pub updated_at: i64,
}

/// Read-only views over the Go v6 plain-contract tables.  The known columns
/// are typed for migration/runtime code, while `data_json` remains byte-for-
/// byte recoverable so fields unknown to Rust are not discarded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoInboundRecord {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub network_type: String,
    pub protocol_type: String,
    pub transport_types_json: Vec<u8>,
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

/// Scalar settings preserved by Go's `settings_kv` table.  The Rust runtime
/// reads the known keys while leaving unknown platform/application keys in the
/// source table for forward compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoSettingsKvRecord {
    pub section: String,
    pub key: String,
    pub value_json: String,
}

/// The single-row Go `backup_settings` contract. Keep the original JSON so
/// Rust can round-trip S3 fields it does not actively use yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoBackupSettingsRecord {
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoNodeRecord {
    pub id: String,
    pub name: String,
    pub group_name: String,
    pub origin: String,
    pub enabled: bool,
    pub chain_types_json: Vec<u8>,
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoNodeTagRecord {
    pub id: String,
    pub name: String,
    pub members_json: Vec<u8>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoResolverRecord {
    pub id: String,
    pub resolver_type: String,
    pub host: String,
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

/// A Go `dns_hosts` row kept as a small compatibility record.  The runtime
/// can parse an IP `target` into `yuhaiin_core::dns_hosts::HostsTable` without
/// making the store depend on a resolver implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoDnsHostRecord {
    pub host: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoDnsSettingsRecord {
    pub id: i64,
    pub server: String,
    pub fakedns_enabled: bool,
    pub fakedns_ipv4_range: String,
    pub fakedns_ipv6_range: String,
}

/// Settings shared by every inbound owner (TUN, SOCKS5, HTTP proxy and
/// Yuubinsya).  The JSON names are the frontend contract; the serde aliases
/// also let older Rust overlays use the Go/SQLite snake_case spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundSettings {
    #[serde(rename = "hijackDns", alias = "hijack_dns", default = "default_true")]
    pub hijack_dns: bool,
    #[serde(
        rename = "hijackDnsFakeIp",
        alias = "hijack_dns_fakeip",
        default = "default_true"
    )]
    pub hijack_dns_fakeip: bool,
    #[serde(rename = "sniff", alias = "sniff_enabled", default = "default_true")]
    pub sniff: bool,
}

fn default_true() -> bool {
    true
}

impl Default for InboundSettings {
    fn default() -> Self {
        Self {
            hijack_dns: true,
            hijack_dns_fakeip: true,
            sniff: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoDnsFakednsListRecord {
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoRouteSettingsRecord {
    pub id: i64,
    pub direct_resolver: String,
    pub proxy_resolver: String,
    pub resolve_locally: bool,
    /// Go stores this as an integer enum: 0=default, 1=resolve,
    /// 2=skip_resolve. Keep the numeric value until compatibility parsing so
    /// an old snapshot does not silently turn strategy 2 into `true`.
    pub udp_proxy_fqdn: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoRouteRuleRecord {
    pub id: String,
    pub name: String,
    pub priority: i64,
    pub disabled: bool,
    pub action_mode: String,
    pub match_type: String,
    pub tag: String,
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoRouteListRecord {
    pub name: String,
    pub list_type: String,
    pub source_type: String,
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

/// A subscription link stored in Go's `subscriptions` table. Canonical fields
/// are exposed for validation while `data_json` preserves future fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoSubscriptionLinkRecord {
    pub name: String,
    pub url: String,
    pub link_type: String,
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

/// Raw Go `publishes` row.  The HTTP contract is decoded at the API boundary,
/// while the original JSON is retained here so future Go fields are not
/// silently discarded by the storage layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoPublishRecord {
    pub name: String,
    pub updated_at: i64,
    pub data_json: Vec<u8>,
}

#[derive(Clone)]
pub struct ConfigRepository {
    store: ConfigStore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoSnapshotInstallReport {
    pub source_bytes: u64,
    pub destination_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseFileReport {
    pub source_bytes: u64,
    pub destination_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoSnapshotManifest {
    pub format_version: i64,
    pub tool: String,
    pub tool_version: String,
    pub source_schema_version: String,
    pub snapshot_sha256: String,
    pub snapshot_bytes: u64,
    pub fakeip_rows: i64,
    #[serde(default, deserialize_with = "deserialize_manifest_string_vec")]
    pub removed_virtual_tables: Vec<String>,
}

fn deserialize_manifest_string_vec<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default())
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

    fn migrate(&self) -> Result<()> {
        let connection = self.lock_connection()?;
        let had_go_schema =
            table_exists(&connection, "metadata") && table_exists(&connection, "migrate");
        connection
            .execute("BEGIN IMMEDIATE")
            .map_err(storage_error)?;
        let result = (|| {
            connection
                .execute_batch(
                    "CREATE TABLE IF NOT EXISTS yuhaiin_meta (
                        key TEXT PRIMARY KEY NOT NULL,
                        value INTEGER NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS yuhaiin_config (
                        key TEXT PRIMARY KEY NOT NULL,
                        value BLOB NOT NULL
                    );
                    INSERT OR IGNORE INTO yuhaiin_meta (key, value)
                        VALUES ('schema_version', 1);",
                )
                .map_err(storage_error)?;

            let rows = connection
                .query("SELECT value FROM yuhaiin_meta WHERE key = 'schema_version'")
                .map_err(storage_error)?;
            let Some(row) = rows.first() else {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "schema version row was not created",
                ));
            };
            let version = match row.get(0) {
                Some(SqliteValue::Integer(value)) => *value,
                _ => {
                    return Err(Error::new(
                        ErrorKind::Storage,
                        "schema version is not an integer",
                    ));
                }
            };
            if !(1..=SCHEMA_VERSION).contains(&version) {
                return Err(Error::new(
                    ErrorKind::Storage,
                    format!("unsupported schema version {version}"),
                ));
            }
            prepare_go_legacy_tables(&connection)?;
            connection
                .execute_batch(typed_schema_sql())
                .map_err(storage_error)?;
            for (table, column, definition) in [
                ("route_rules", "name", "name TEXT"),
                ("route_rules", "disabled", "disabled INTEGER"),
                ("route_rules", "updated_at", "updated_at INTEGER"),
                ("route_rules", "data_json", "data_json TEXT"),
                ("dns_resolvers", "name", "name TEXT"),
                ("dns_resolvers", "resolver_type", "resolver_type INTEGER"),
                ("dns_resolvers", "host", "host TEXT"),
                ("dns_resolvers", "subnet", "subnet TEXT"),
                ("dns_resolvers", "tls_servername", "tls_servername TEXT"),
                ("dns_resolvers", "data_json", "data_json TEXT"),
            ] {
                if !table_has_column(&connection, table, column)? {
                    connection
                        .execute(&format!("ALTER TABLE {table} ADD COLUMN {definition}"))
                        .map_err(storage_error)?;
                }
            }
            if !table_has_column(&connection, "route_rules", "geo_country")? {
                connection
                    .execute("ALTER TABLE route_rules ADD COLUMN geo_country TEXT")
                    .map_err(storage_error)?;
            }
            validate_typed_schema(&connection)?;
            if !had_go_schema {
                bootstrap_go_compatibility_metadata(&connection)?;
            }
            connection
                .execute_with_params(
                    "UPDATE yuhaiin_meta SET value = ?1 WHERE key = 'schema_version'",
                    &[SqliteValue::from(SCHEMA_VERSION)],
                )
                .map_err(storage_error)?;
            verify_integrity(&connection)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                connection.execute("COMMIT").map_err(storage_error)?;
                // Go import has its own transaction because it may need to
                // report a malformed source row and be retried after the
                // caller repairs that row.  The Rust schema migration above
                // is already committed and remains valid in that case.
                import_go_schema(&connection)?;
                recover_legacy_node_chains(&connection)?;
                verify_integrity(&connection)
            }
            Err(error) => {
                let _ = connection.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    pub fn repository(&self) -> ConfigRepository {
        ConfigRepository {
            store: self.clone(),
        }
    }

    /// Read current SQLite/runtime storage state for reload and management
    /// callers. This does not mutate the database or create a second DTO tree.
    pub fn status(&self) -> Result<StorageStatus> {
        let connection = self.lock_connection()?;
        status::read(&connection)
    }

    /// Checkpoint all committed WAL frames so a migrated database can be
    /// atomically moved without carrying a sidecar WAL file with it.
    pub async fn checkpoint(&self) -> Result<()> {
        self.with_write_retry(|connection| {
            connection
                .execute("PRAGMA wal_checkpoint(TRUNCATE)")
                .map_err(storage_error)
                .map(|_| ())
        })
    }

    /// Close the only owner and let SQLite perform its normal passive WAL
    /// checkpoint.  Migration installers use this before moving a prepared
    /// file so committed rows cannot remain only in a sidecar WAL.
    pub fn close(self) -> Result<()> {
        let connection = Arc::try_unwrap(self.connection).map_err(|_| {
            Error::new(
                ErrorKind::Storage,
                "cannot close ConfigStore while another handle is alive",
            )
        })?;
        let connection = connection
            .into_inner()
            .map_err(|_| Error::new(ErrorKind::Storage, "database mutex is poisoned"))?;
        connection.close().map_err(storage_error)
    }

    /// Create a consistent SQLite backup without exposing the backend
    /// connection. `VACUUM INTO` observes committed WAL state while the
    /// store's file lock prevents concurrent writers, then the staged backup
    /// is opened and checkpointed before it is atomically installed.
    ///
    /// The destination must not already exist. Callers should place temporary
    /// and backup files under their cache/data directory rather than `/tmp`.
    pub async fn backup_to(&self, destination: impl AsRef<Path>) -> Result<DatabaseFileReport> {
        let destination = destination.as_ref();
        let (destination_parent, destination_name) = database_destination_parts(destination)?;
        ensure_destination_absent(destination)?;
        ensure_destination_sidecars_absent(destination)?;
        let temporary = database_staging_path(&destination_parent, &destination_name, "backup")?;
        let temporary_sql = temporary.to_str().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "SQLite backup path is not valid UTF-8",
            )
        })?;

        let result = async {
            self.with_write_retry(|connection| {
                connection
                    .execute_with_params("VACUUM INTO ?1", &[SqliteValue::from(temporary_sql)])
                    .map(|_| ())
                    .map_err(storage_error)
            })?;
            let source_bytes = std::fs::metadata(&temporary)
                .map_err(|error| {
                    Error::new(
                        ErrorKind::Storage,
                        format!("stat staged SQLite backup: {error}"),
                    )
                })?
                .len();

            let staged_store = ConfigStore::open(&temporary).await?;
            staged_store.checkpoint().await?;
            staged_store.close()?;
            ensure_destination_absent(destination)?;
            ensure_destination_sidecars_absent(destination)?;
            std::fs::rename(&temporary, destination).map_err(|error| {
                Error::new(
                    ErrorKind::Storage,
                    format!("atomically install SQLite backup: {error}"),
                )
            })?;
            let destination_bytes = std::fs::metadata(destination)
                .map_err(|error| {
                    Error::new(
                        ErrorKind::Storage,
                        format!("stat installed SQLite backup: {error}"),
                    )
                })?
                .len();
            Ok(DatabaseFileReport {
                source_bytes,
                destination_bytes,
            })
        }
        .await;
        remove_database_sidecars(&temporary);
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    /// Compact the database only when SQLite reports enough free pages. This
    /// keeps the expensive `VACUUM` operation explicit and thresholded rather
    /// than imposing a startup write/battery cost on every open.
    pub async fn compact_if_needed(&self, minimum_free_pages: i64) -> Result<bool> {
        if minimum_free_pages <= 0 {
            return Err(Error::invalid("minimum SQLite free pages must be positive"));
        }
        self.with_write_retry(|connection| {
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
            if free_pages < minimum_free_pages {
                return Ok(false);
            }
            connection
                .execute("PRAGMA wal_checkpoint(TRUNCATE)")
                .map_err(storage_error)?;
            connection.execute("VACUUM").map_err(storage_error)?;
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
        validate_key(prefix)?;
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
        self.with_write_retry(|connection| {
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
        })
    }

    pub async fn list_fakeip_entries(
        &self,
        family: i64,
        prefix: &str,
    ) -> Result<Vec<FakeIpEntryRecord>> {
        validate_fakeip_scope(family, prefix)?;
        let connection = self.lock_connection()?;
        let rows = connection
            .query_with_params(
                "SELECT family, prefix, domain, ip, created_at, last_used_at
                 FROM fakeip_entries
                 WHERE family = ?1 AND prefix = ?2
                 ORDER BY ip, domain",
                &[SqliteValue::from(family), SqliteValue::from(prefix)],
            )
            .map_err(storage_error)?;
        rows.iter().map(fakeip_entry_from_row).collect()
    }

    pub async fn get_fakeip_cursor(
        &self,
        family: i64,
        prefix: &str,
    ) -> Result<Option<FakeIpCursorRecord>> {
        validate_fakeip_scope(family, prefix)?;
        let connection = self.lock_connection()?;
        let rows = connection
            .query_with_params(
                "SELECT family, prefix, cursor_ip, cursor_idx, updated_at
                 FROM fakeip_cursors
                 WHERE family = ?1 AND prefix = ?2",
                &[SqliteValue::from(family), SqliteValue::from(prefix)],
            )
            .map_err(storage_error)?;
        rows.first().map(fakeip_cursor_from_row).transpose()
    }

    /// Commit an allocation/reuse as one transaction.  The old domain and
    /// any stale owner of the selected IP are removed before the new forward
    /// row and cursor are written, so a crash cannot leave a forward-only or
    /// reverse-only mapping.
    pub async fn replace_fakeip_entry(
        &self,
        entry: &FakeIpEntryRecord,
        cursor: &FakeIpCursorRecord,
        evicted_domain: Option<&str>,
    ) -> Result<()> {
        validate_fakeip_entry(entry)?;
        validate_fakeip_cursor(cursor)?;
        if entry.family != cursor.family || entry.prefix != cursor.prefix {
            return Err(Error::invalid(
                "FakeIP entry and cursor must use the same scope",
            ));
        }
        if let Some(domain) = evicted_domain {
            validate_id(domain)?;
        }
        self.with_write_transaction(|connection| {
            connection
                .execute_with_params(
                    "DELETE FROM fakeip_entries
                     WHERE family = ?1 AND prefix = ?2 AND domain = ?3",
                    &[
                        SqliteValue::from(entry.family),
                        SqliteValue::from(entry.prefix.as_str()),
                        SqliteValue::from(entry.domain.as_str()),
                    ],
                )
                .map_err(storage_error)?;
            if let Some(domain) = evicted_domain {
                connection
                    .execute_with_params(
                        "DELETE FROM fakeip_entries
                         WHERE family = ?1 AND prefix = ?2 AND domain = ?3",
                        &[
                            SqliteValue::from(entry.family),
                            SqliteValue::from(entry.prefix.as_str()),
                            SqliteValue::from(domain),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            // The UNIQUE scope/IP constraint makes this defensive delete
            // important when an older process left a row that is absent from
            // this process's in-memory snapshot.
            connection
                .execute_with_params(
                    "DELETE FROM fakeip_entries
                     WHERE family = ?1 AND prefix = ?2 AND ip = ?3",
                    &[
                        SqliteValue::from(entry.family),
                        SqliteValue::from(entry.prefix.as_str()),
                        SqliteValue::from(entry.ip.as_slice()),
                    ],
                )
                .map_err(storage_error)?;
            connection
                .execute_with_params(
                    "INSERT INTO fakeip_entries
                     (family, prefix, domain, ip, created_at, last_used_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    &[
                        SqliteValue::from(entry.family),
                        SqliteValue::from(entry.prefix.as_str()),
                        SqliteValue::from(entry.domain.as_str()),
                        SqliteValue::from(entry.ip.as_slice()),
                        SqliteValue::from(entry.created_at),
                        SqliteValue::from(entry.last_used_at),
                    ],
                )
                .map_err(storage_error)?;
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO fakeip_cursors
                     (family, prefix, cursor_ip, cursor_idx, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[
                        SqliteValue::from(cursor.family),
                        SqliteValue::from(cursor.prefix.as_str()),
                        SqliteValue::from(cursor.cursor_ip.as_slice()),
                        SqliteValue::from(cursor.cursor_idx),
                        SqliteValue::from(cursor.updated_at),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn delete_fakeip_entries(
        &self,
        family: i64,
        prefix: &str,
        domains: &[String],
    ) -> Result<usize> {
        validate_fakeip_scope(family, prefix)?;
        for domain in domains {
            validate_id(domain)?;
        }
        if domains.is_empty() {
            return Ok(0);
        }
        self.with_write_transaction(|connection| {
            let mut deleted = 0usize;
            for domain in domains {
                deleted += connection
                    .execute_with_params(
                        "DELETE FROM fakeip_entries
                         WHERE family = ?1 AND prefix = ?2 AND domain = ?3",
                        &[
                            SqliteValue::from(family),
                            SqliteValue::from(prefix),
                            SqliteValue::from(domain.as_str()),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            Ok(deleted)
        })
    }

    /// Persist delayed `last_used_at` touches in one bounded transaction.
    pub async fn touch_fakeip_entries(
        &self,
        family: i64,
        prefix: &str,
        touches: &[(String, i64)],
    ) -> Result<usize> {
        validate_fakeip_scope(family, prefix)?;
        for (domain, timestamp) in touches {
            validate_id(domain)?;
            if *timestamp < 0 {
                return Err(Error::invalid("FakeIP last_used_at must not be negative"));
            }
        }
        if touches.is_empty() {
            return Ok(0);
        }
        self.with_write_transaction(|connection| {
            let mut updated = 0usize;
            for (domain, timestamp) in touches {
                updated += connection
                    .execute_with_params(
                        "UPDATE fakeip_entries SET last_used_at = ?1
                         WHERE family = ?2 AND prefix = ?3 AND domain = ?4",
                        &[
                            SqliteValue::from(*timestamp),
                            SqliteValue::from(family),
                            SqliteValue::from(prefix),
                            SqliteValue::from(domain.as_str()),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            Ok(updated)
        })
    }

    /// Import a legacy snapshot into the typed tables atomically.  Legacy KV
    /// keys are removed only after all typed rows and the cursor are written.
    pub async fn import_fakeip_state(
        &self,
        entries: &[FakeIpEntryRecord],
        cursor: &FakeIpCursorRecord,
        legacy_keys: &[String],
        marker_key: Option<&str>,
    ) -> Result<()> {
        self.import_fakeip_state_inner(entries, cursor, legacy_keys, marker_key, false)
            .await
            .map(|_| ())
    }

    /// Import a legacy snapshot only if its marker has not already been
    /// committed. The marker check is inside the same IMMEDIATE transaction as
    /// the rows, so two concurrent importers cannot overwrite one another.
    pub async fn import_fakeip_state_if_unmarked(
        &self,
        entries: &[FakeIpEntryRecord],
        cursor: &FakeIpCursorRecord,
        legacy_keys: &[String],
        marker_key: &str,
    ) -> Result<bool> {
        self.import_fakeip_state_inner(entries, cursor, legacy_keys, Some(marker_key), true)
            .await
    }

    async fn import_fakeip_state_inner(
        &self,
        entries: &[FakeIpEntryRecord],
        cursor: &FakeIpCursorRecord,
        legacy_keys: &[String],
        marker_key: Option<&str>,
        skip_if_marked: bool,
    ) -> Result<bool> {
        validate_fakeip_cursor(cursor)?;
        for entry in entries {
            validate_fakeip_entry(entry)?;
            if entry.family != cursor.family || entry.prefix != cursor.prefix {
                return Err(Error::invalid(
                    "legacy FakeIP entries and cursor must use the same scope",
                ));
            }
        }
        for key in legacy_keys {
            validate_key(key)?;
        }
        if let Some(marker_key) = marker_key {
            validate_key(marker_key)?;
        }
        self.with_write_transaction(|connection| {
            if skip_if_marked {
                let marker_key = marker_key.expect("unmarked import requires a marker");
                let rows = connection
                    .query_with_params(
                        "SELECT 1 FROM yuhaiin_config WHERE key = ?1",
                        &[SqliteValue::from(marker_key)],
                    )
                    .map_err(storage_error)?;
                if !rows.is_empty() {
                    return Ok(false);
                }
            }
            for entry in entries {
                connection
                    .execute_with_params(
                        "INSERT OR REPLACE INTO fakeip_entries
                         (family, prefix, domain, ip, created_at, last_used_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        &[
                            SqliteValue::from(entry.family),
                            SqliteValue::from(entry.prefix.as_str()),
                            SqliteValue::from(entry.domain.as_str()),
                            SqliteValue::from(entry.ip.as_slice()),
                            SqliteValue::from(entry.created_at),
                            SqliteValue::from(entry.last_used_at),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO fakeip_cursors
                     (family, prefix, cursor_ip, cursor_idx, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[
                        SqliteValue::from(cursor.family),
                        SqliteValue::from(cursor.prefix.as_str()),
                        SqliteValue::from(cursor.cursor_ip.as_slice()),
                        SqliteValue::from(cursor.cursor_idx),
                        SqliteValue::from(cursor.updated_at),
                    ],
                )
                .map_err(storage_error)?;
            for key in legacy_keys {
                connection
                    .execute_with_params(
                        "DELETE FROM yuhaiin_config WHERE key = ?1",
                        &[SqliteValue::from(key.as_str())],
                    )
                    .map_err(storage_error)?;
            }
            if let Some(marker_key) = marker_key {
                connection
                    .execute_with_params(
                        "INSERT OR REPLACE INTO yuhaiin_config (key, value)
                         VALUES (?1, ?2)",
                        &[
                            SqliteValue::from(marker_key),
                            SqliteValue::from(b"1".as_slice()),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            Ok(true)
        })
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
        let write_lock_path = write_lock_path(&path);
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
pub async fn restore_database(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> Result<DatabaseFileReport> {
    let source = source.as_ref();
    let destination = destination.as_ref();
    if !source.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("SQLite backup does not exist: {}", source.display()),
        ));
    }
    let source_wal = PathBuf::from(format!("{}-wal", source.display()));
    if let Ok(metadata) = std::fs::metadata(&source_wal) {
        if metadata.len() != 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "SQLite backup has a non-empty WAL sidecar: {}",
                    source_wal.display()
                ),
            ));
        }
    }
    let (destination_parent, destination_name) = database_destination_parts(destination)?;
    std::fs::create_dir_all(&destination_parent).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("create SQLite restore destination directory: {error}"),
        )
    })?;
    let source_absolute = std::fs::canonicalize(source).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("resolve SQLite backup source: {error}"),
        )
    })?;
    let destination_parent_absolute =
        std::fs::canonicalize(&destination_parent).map_err(|error| {
            Error::new(
                ErrorKind::Storage,
                format!("resolve SQLite restore destination directory: {error}"),
            )
        })?;
    let destination_absolute = destination_parent_absolute.join(&destination_name);
    if source_absolute == destination_absolute {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "SQLite backup source and destination must differ",
        ));
    }
    let temporary = database_staging_path(&destination_parent, &destination_name, "restore")?;
    let old_destination =
        database_staging_path(&destination_parent, &destination_name, "restore-old")?;
    if temporary.exists() || old_destination.exists() {
        return Err(Error::new(
            ErrorKind::Storage,
            "SQLite restore staging path already exists",
        ));
    }
    ensure_restore_destination_safe(destination)?;
    let source_bytes = std::fs::metadata(source)
        .map_err(|error| Error::new(ErrorKind::Storage, format!("stat SQLite backup: {error}")))?
        .len();
    if let Err(error) = std::fs::copy(source, &temporary) {
        let _ = std::fs::remove_file(&temporary);
        remove_database_sidecars(&temporary);
        return Err(Error::new(
            ErrorKind::Storage,
            format!("copy SQLite backup to restore staging file: {error}"),
        ));
    }

    let result = async {
        let staged_store = ConfigStore::open(&temporary).await?;
        staged_store.checkpoint().await?;
        staged_store.close()?;

        let destination_exists = match std::fs::symlink_metadata(destination) {
            Ok(metadata) if metadata.file_type().is_file() => true,
            Ok(_) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "SQLite restore destination must be a regular file",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(Error::new(
                    ErrorKind::Storage,
                    format!("inspect SQLite restore destination: {error}"),
                ));
            }
        };
        if !destination_exists {
            ensure_destination_sidecars_absent(destination)?;
        }
        if destination_exists {
            std::fs::rename(destination, &old_destination).map_err(|error| {
                Error::new(
                    ErrorKind::Storage,
                    format!("stage existing SQLite database for restore: {error}"),
                )
            })?;
        }
        if let Err(error) = std::fs::rename(&temporary, destination) {
            if destination_exists {
                let _ = std::fs::rename(&old_destination, destination);
            }
            return Err(Error::new(
                ErrorKind::Storage,
                format!("atomically install restored SQLite database: {error}"),
            ));
        }
        if destination_exists {
            remove_database_sidecars(destination);
        }
        if destination_exists {
            let _ = std::fs::remove_file(&old_destination);
            remove_database_sidecars(&old_destination);
        }
        let destination_bytes = std::fs::metadata(destination)
            .map_err(|error| {
                Error::new(
                    ErrorKind::Storage,
                    format!("stat restored SQLite database: {error}"),
                )
            })?
            .len();
        Ok(DatabaseFileReport {
            source_bytes,
            destination_bytes,
        })
    }
    .await;
    remove_database_sidecars(&temporary);
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// Install an FTS-free Go SQLite snapshot as a Rust-owned state database.
///
/// The Go side must first produce a consistent snapshot with
/// `cmd/yuhaiin-rust-export`. This function copies that snapshot to a private
/// sibling, runs the complete Rust schema/import transaction there, checkpoints
/// the resulting WAL, and atomically renames the prepared file to
/// `destination`. Neither an existing destination nor the Go source is ever
/// overwritten.
pub async fn install_go_snapshot(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
) -> Result<GoSnapshotInstallReport> {
    install_go_snapshot_inner(source.as_ref(), destination.as_ref(), None).await
}

/// Install a Go snapshot after verifying the exporter-generated sidecar
/// manifest. The manifest is mandatory for the production CLI path; the
/// legacy two-argument function remains available for fixture/import callers
/// that already establish their own snapshot boundary.
pub async fn install_go_snapshot_with_manifest(
    source: impl AsRef<Path>,
    destination: impl AsRef<Path>,
    manifest: impl AsRef<Path>,
) -> Result<GoSnapshotInstallReport> {
    install_go_snapshot_inner(
        source.as_ref(),
        destination.as_ref(),
        Some(manifest.as_ref()),
    )
    .await
}

async fn install_go_snapshot_inner(
    source: &Path,
    destination: &Path,
    manifest: Option<&Path>,
) -> Result<GoSnapshotInstallReport> {
    if !source.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("Go snapshot does not exist: {}", source.display()),
        ));
    }
    match std::fs::symlink_metadata(destination) {
        Ok(_) => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "refusing to overwrite destination: {}",
                    destination.display()
                ),
            ));
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(Error::new(
                ErrorKind::Storage,
                format!("inspect Go snapshot destination: {error}"),
            ));
        }
        Err(_) => {}
    }
    ensure_destination_sidecars_absent(destination)?;
    let destination_name = destination.file_name().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "Go snapshot destination must contain a file name",
        )
    })?;
    let destination_parent = destination.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(destination_parent).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("create Go snapshot destination directory: {error}"),
        )
    })?;
    let source_absolute = std::fs::canonicalize(source).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("resolve Go snapshot source: {error}"),
        )
    })?;
    let destination_absolute = std::fs::canonicalize(destination_parent)
        .map_err(|error| {
            Error::new(
                ErrorKind::Storage,
                format!("resolve Go snapshot destination directory: {error}"),
            )
        })?
        .join(destination_name);
    if source_absolute == destination_absolute {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Go snapshot source and destination must differ",
        ));
    }
    let source_bytes = std::fs::metadata(source)
        .map_err(|error| Error::new(ErrorKind::Storage, format!("stat Go snapshot: {error}")))?
        .len();
    let source_wal = PathBuf::from(format!("{}-wal", source.display()));
    if let Ok(metadata) = std::fs::metadata(&source_wal) {
        if metadata.len() != 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Go snapshot has a non-empty WAL sidecar: {}; run the Go consistent exporter first",
                    source_wal.display()
                ),
            ));
        }
    }
    if let Some(manifest) = manifest {
        verify_go_snapshot_manifest(source, manifest, source_bytes)?;
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Error::new(ErrorKind::Storage, format!("read system clock: {error}")))?
        .as_nanos();
    let temporary = destination_parent.join(format!(
        ".{}.go-migration-{}-{nonce}.tmp",
        destination_name.to_string_lossy(),
        std::process::id()
    ));
    if temporary.exists() {
        return Err(Error::new(
            ErrorKind::Storage,
            format!(
                "temporary Go migration path already exists: {}",
                temporary.display()
            ),
        ));
    }

    if let Err(error) = std::fs::copy(source, &temporary) {
        let _ = std::fs::remove_file(&temporary);
        remove_database_sidecars(&temporary);
        return Err(Error::new(
            ErrorKind::Storage,
            format!("copy Go snapshot to migration staging file: {error}"),
        ));
    }
    let result = async {
        let store = ConfigStore::open(&temporary).await?;
        store.checkpoint().await?;
        store.close()?;
        let destination_bytes = std::fs::metadata(&temporary)
            .map_err(|error| {
                Error::new(
                    ErrorKind::Storage,
                    format!("stat prepared Rust state database: {error}"),
                )
            })?
            .len();
        std::fs::rename(&temporary, destination).map_err(|error| {
            Error::new(
                ErrorKind::Storage,
                format!("atomically install migrated Go snapshot: {error}"),
            )
        })?;
        Ok(GoSnapshotInstallReport {
            source_bytes,
            destination_bytes,
        })
    }
    .await;
    remove_database_sidecars(&temporary);
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

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

fn lock_write_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(path)
        .map_err(storage_error)?;
    file.lock().map_err(storage_error)?;
    Ok(file)
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
