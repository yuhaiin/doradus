//! Store opening, migration, and public lifecycle operations.

use super::*;
use crate::schema::prepare_go_legacy_tables;

impl ConfigStore {
    pub(super) fn migrate(&self, allow_legacy_import: bool) -> Result<()> {
        let connection = self.lock_connection()?;
        let had_go_schema =
            table_exists(&connection, "metadata") && table_exists(&connection, "migrate");
        if had_go_schema && !allow_legacy_import {
            return Err(Error::new(
                ErrorKind::Storage,
                "legacy database detected; use the explicit future migration workflow instead of normal Doradus startup",
            ));
        }
        connection
            .execute("BEGIN IMMEDIATE")
            .map_err(storage_error)?;
        let result = (|| {
            connection
                .execute_batch(
                    "CREATE TABLE IF NOT EXISTS doradus_meta (
                        key TEXT PRIMARY KEY NOT NULL,
                        value INTEGER NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS doradus_config (
                        key TEXT PRIMARY KEY NOT NULL,
                        value BLOB NOT NULL
                    );
                    INSERT OR IGNORE INTO doradus_meta (key, value)
                        VALUES ('schema_version', 1);",
                )
                .map_err(storage_error)?;

            let rows = connection
                .query("SELECT value FROM doradus_meta WHERE key = 'schema_version'")
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
            if had_go_schema {
                prepare_go_legacy_tables(&connection)?;
            }
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
            connection
                .execute_with_params(
                    "UPDATE doradus_meta SET value = ?1 WHERE key = 'schema_version'",
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
                if allow_legacy_import {
                    import_go_schema(&connection)?;
                    recover_legacy_node_chains(&connection)?;
                }
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
}
