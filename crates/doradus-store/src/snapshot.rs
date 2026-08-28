//! Go-compatible database restore and snapshot installation.

use super::*;

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
    if let Ok(metadata) = std::fs::metadata(&source_wal)
        && metadata.len() != 0
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "SQLite backup has a non-empty WAL sidecar: {}",
                source_wal.display()
            ),
        ));
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
/// `cmd/doradus-export`. This function copies that snapshot to a private
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
    if let Ok(metadata) = std::fs::metadata(&source_wal)
        && metadata.len() != 0
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "Go snapshot has a non-empty WAL sidecar: {}; run the Go consistent exporter first",
                source_wal.display()
            ),
        ));
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
        let store = ConfigStore::open_legacy(&temporary).await?;
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
