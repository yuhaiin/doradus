//! Portable configuration backup lifecycle.

use super::*;

impl ConfigStore {
    /// Create a consistent SQLite backup without exposing the backend
    /// connection. `VACUUM INTO` observes committed WAL state while the
    /// store's file lock prevents concurrent writers, then the staged backup
    /// is sanitized like Go, checkpointed, and atomically installed.
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
            let staged_store = ConfigStore::open(&temporary).await?;
            staged_store.sanitize_backup_snapshot()?;
            staged_store.checkpoint().await?;
            staged_store.close()?;
            let source_bytes = std::fs::metadata(&temporary)
                .map_err(|error| {
                    Error::new(
                        ErrorKind::Storage,
                        format!("stat staged SQLite backup: {error}"),
                    )
                })?
                .len();
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

    /// Remove process/runtime state from a staged backup while retaining the
    /// configuration rows that Go restores. Missing optional runtime tables
    /// are ignored because a fresh Rust store creates statistics tables lazily.
    fn sanitize_backup_snapshot(&self) -> Result<()> {
        self.with_write_transaction(|connection| {
            for table in BACKUP_RUNTIME_TABLES {
                if table_exists(connection, table) {
                    connection
                        .execute(&format!("DELETE FROM {table}"))
                        .map_err(|error| {
                            Error::new(
                                ErrorKind::Storage,
                                format!(
                                    "clear runtime table {table} from backup snapshot: {error}"
                                ),
                            )
                        })?;
                }
            }

            if table_exists(connection, "route_list_refresh") {
                connection
                    .execute(
                        "UPDATE route_list_refresh
                         SET last_refresh_time = 0, last_error = ''",
                    )
                    .map_err(|error| {
                        Error::new(
                            ErrorKind::Storage,
                            format!(
                                "normalize route list refresh state in backup snapshot: {error}"
                            ),
                        )
                    })?;
            }

            if table_exists(connection, "backup_settings") {
                let rows = connection
                    .query("SELECT data_json FROM backup_settings WHERE id = 1")
                    .map_err(|error| {
                        Error::new(
                            ErrorKind::Storage,
                            format!("read backup settings from backup snapshot: {error}"),
                        )
                    })?;
                if let Some(row) = rows.first() {
                    let data_json = row_blob_or_text(row, 0, "backup_settings.data_json")?;
                    let mut value: serde_json::Value =
                        serde_json::from_slice(&data_json).map_err(|error| {
                            Error::new(
                                ErrorKind::Storage,
                                format!("decode backup settings from backup snapshot: {error}"),
                            )
                        })?;
                    let object = value.as_object_mut().ok_or_else(|| {
                        Error::new(
                            ErrorKind::Storage,
                            "backup settings in snapshot must be a JSON object",
                        )
                    })?;
                    object.insert(
                        "lastBackupHash".to_owned(),
                        serde_json::Value::String(String::new()),
                    );
                    let normalized = serde_json::to_vec(&value).map_err(|error| {
                        Error::new(
                            ErrorKind::Storage,
                            format!("encode normalized backup settings: {error}"),
                        )
                    })?;
                    connection
                        .execute_with_params(
                            "UPDATE backup_settings
                             SET updated_at = 0, data_json = ?1
                             WHERE id = 1",
                            &[SqliteValue::from(normalized)],
                        )
                        .map_err(|error| {
                            Error::new(
                                ErrorKind::Storage,
                                format!("normalize backup settings in snapshot: {error}"),
                            )
                        })?;
                }
            }
            Ok(())
        })?;

        self.with_write_retry(|connection| {
            connection.execute("VACUUM").map_err(|error| {
                Error::new(
                    ErrorKind::Storage,
                    format!("compact sanitized SQLite backup snapshot: {error}"),
                )
            })?;
            Ok(())
        })
    }
}
