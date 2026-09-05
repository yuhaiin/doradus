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

// Shared database-file helpers used by backup/restore/snapshot installation.
pub(crate) fn database_destination_parts(destination: &Path) -> Result<(PathBuf, String)> {
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

pub(crate) fn ensure_destination_absent(destination: &Path) -> Result<()> {
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

pub(crate) fn ensure_destination_sidecars_absent(destination: &Path) -> Result<()> {
    for suffix in [
        "-journal",
        "-wal",
        "-shm",
        "-wal-fec",
        "-fsqlite-ns-use",
        "-fsqlite-ns-gate",
        "-doradus-write-lock",
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

pub(crate) fn ensure_restore_destination_safe(destination: &Path) -> Result<()> {
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

pub(crate) fn database_staging_path(parent: &Path, name: &str, kind: &str) -> Result<PathBuf> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| Error::new(ErrorKind::Storage, format!("read system clock: {error}")))?
        .as_nanos();
    let staging = parent.join(format!(
        ".{name}.doradus-{kind}-{}-{nonce}.tmp",
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

pub(crate) fn remove_database_sidecars(path: &Path) {
    // The fsqlite namespace files are retained only as compatibility cleanup
    // for databases produced by the discarded experimental backend.
    for suffix in [
        "-journal",
        "-wal",
        "-shm",
        "-wal-fec",
        "-fsqlite-ns-use",
        "-fsqlite-ns-gate",
        "-doradus-write-lock",
    ] {
        let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
        let _ = std::fs::remove_file(sidecar);
    }
}

pub(crate) fn verify_go_snapshot_manifest(
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
        || manifest.tool != "doradus-export"
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

pub(crate) fn sha256_file(path: &Path) -> Result<String> {
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
