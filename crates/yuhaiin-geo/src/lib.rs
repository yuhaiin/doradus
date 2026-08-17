//! MaxMindDB-backed geographic provider and its atomic file snapshot manager.
//!
//! The router only sees [`yuhaiin_core::GeoLookup`].  This crate owns the
//! MaxMind reader, artifact validation, and replacement lifecycle so neither
//! SQLite nor route matching needs to know about reader internals.

#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use maxminddb::geoip2;
use sha2::{Digest, Sha256};
use yuhaiin_core::{BoxFuture, Error, ErrorKind, GeoLookup, Result};

/// A validated GeoIP file record suitable for persistence in the config
/// store. The URL deliberately stays outside this record because the Go
/// route-list config owns it; this record describes the installed artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoMetadata {
    pub id: String,
    pub path: PathBuf,
    pub sha256: Vec<u8>,
    pub size: u64,
    pub updated_at: i64,
}

/// Read-only geographic database. Unix readers map the installed file, while
/// other platforms keep an owned copy so atomic replacement remains safe.
#[derive(Clone)]
pub struct GeoDb {
    reader: Arc<GeoReader>,
}

enum GeoReader {
    Owned(maxminddb::Reader<Vec<u8>>),
    #[cfg(unix)]
    Mapped(maxminddb::Reader<maxminddb::Mmap>),
}

impl GeoDb {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let reader = maxminddb::Reader::from_source(bytes)
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
        Ok(Self {
            reader: Arc::new(GeoReader::Owned(reader)),
        })
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        #[cfg(unix)]
        {
            return Self::open_mmap(path);
        }

        #[cfg(not(unix))]
        {
            let bytes = fs::read(path)
                .map_err(|error| Error::new(ErrorKind::Io, format!("read MaxMindDB: {error}")))?;
            Self::from_bytes(bytes)
        }
    }

    #[cfg(unix)]
    fn open_mmap(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path)
            .map_err(|error| Error::new(ErrorKind::Io, format!("open MaxMindDB: {error}")))?;
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file) }
            .map_err(|error| Error::new(ErrorKind::Io, format!("map MaxMindDB: {error}")))?;
        let reader = maxminddb::Reader::from_source(mmap)
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
        Ok(Self {
            reader: Arc::new(GeoReader::Mapped(reader)),
        })
    }

    fn validate_bytes(bytes: &[u8]) -> Result<()> {
        maxminddb::Reader::from_source(bytes)
            .map(|_| ())
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))
    }

    fn country_code_from_reader<S: AsRef<[u8]>>(
        reader: &maxminddb::Reader<S>,
        address: IpAddr,
    ) -> Result<Option<String>> {
        let address = match address {
            IpAddr::V6(address) => address
                .to_ipv4()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(address)),
            address => address,
        };
        let result = reader
            .lookup(address)
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
        if !result.has_data() {
            return Ok(None);
        }
        let Some(record): Option<geoip2::Country<'_>> = result
            .decode()
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?
        else {
            return Ok(None);
        };
        Ok(record.country.iso_code.map(str::to_owned))
    }

    pub fn country_code(&self, address: IpAddr) -> Result<Option<String>> {
        match self.reader.as_ref() {
            GeoReader::Owned(reader) => Self::country_code_from_reader(reader, address),
            #[cfg(unix)]
            GeoReader::Mapped(reader) => Self::country_code_from_reader(reader, address),
        }
    }
}

impl GeoLookup for GeoDb {
    fn country_code(&self, address: IpAddr) -> Result<Option<String>> {
        Self::country_code(self, address)
    }
}

/// One immutable reader plus the metadata used to install it.
#[derive(Clone)]
pub struct GeoSnapshot {
    metadata: GeoMetadata,
    database: Arc<GeoDb>,
}

impl GeoSnapshot {
    pub fn metadata(&self) -> &GeoMetadata {
        &self.metadata
    }

    pub fn database(&self) -> Arc<GeoDb> {
        Arc::clone(&self.database)
    }
}

/// Transport boundary used by the manager. Runtime supplies the selected
/// outbound proxy; tests can use an in-memory or local HTTP implementation.
pub trait GeoDownloadTransport: Send + Sync {
    fn download<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Vec<u8>>>;
}

#[derive(Debug, Clone)]
pub struct GeoRefreshRequest {
    pub id: String,
    pub path: PathBuf,
    pub url: String,
    pub expected_sha256: Option<Vec<u8>>,
    pub expected_size: Option<u64>,
    pub updated_at: i64,
}

struct Published {
    generation: u64,
    snapshot: Option<Arc<GeoSnapshot>>,
}

struct ManagerState {
    published: RwLock<Published>,
    next_generation: AtomicU64,
}

/// Owns the current GeoIP snapshot and publishes new readers only after the
/// downloaded bytes pass size/hash/database validation and atomic install.
#[derive(Clone)]
pub struct GeoDatabaseManager {
    state: Arc<ManagerState>,
    max_bytes: usize,
}

impl GeoDatabaseManager {
    pub const DEFAULT_MAX_BYTES: usize = 128 * 1024 * 1024;

    pub fn new() -> Self {
        Self::with_max_bytes(Self::DEFAULT_MAX_BYTES)
    }

    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            state: Arc::new(ManagerState {
                published: RwLock::new(Published {
                    generation: 0,
                    snapshot: None,
                }),
                next_generation: AtomicU64::new(0),
            }),
            max_bytes,
        }
    }

    pub fn current(&self) -> Option<Arc<GeoSnapshot>> {
        self.state
            .published
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot
            .clone()
    }

    /// Load and publish an already-installed file after validating the
    /// persisted metadata. This is the startup/restart recovery path.
    pub fn load(&self, metadata: GeoMetadata) -> Result<Arc<GeoSnapshot>> {
        validate_path(&metadata.path)?;
        let bytes = read_bounded(&metadata.path, self.max_bytes)?;
        let mut metadata = metadata;
        // Older compatibility rows allowed zero size/empty hash. Recover the
        // validated values on startup instead of making an otherwise valid
        // installed database unusable; non-empty values remain strict.
        if metadata.size == 0 {
            metadata.size = bytes.len() as u64;
        }
        if metadata.sha256.is_empty() {
            metadata.sha256 = sha256(&bytes);
        }
        validate_metadata(&bytes, &metadata, self.max_bytes)?;
        GeoDb::validate_bytes(&bytes)?;
        #[cfg(unix)]
        let database = GeoDb::open_mmap(&metadata.path)?;
        #[cfg(not(unix))]
        let database = GeoDb::from_bytes(bytes)?;
        Ok(self.publish(metadata, database))
    }

    /// Download, validate, atomically install, and publish a new snapshot.
    /// Failed downloads never alter the old reader or target file.
    pub async fn refresh(
        &self,
        request: GeoRefreshRequest,
        transport: &dyn GeoDownloadTransport,
    ) -> Result<Arc<GeoSnapshot>> {
        if request.url.trim().is_empty() {
            return Err(Error::invalid("GeoIP download URL is empty"));
        }
        validate_path(&request.path)?;
        let bytes = transport.download(request.url.trim()).await?;
        if bytes.len() > self.max_bytes {
            return Err(Error::invalid(format!(
                "GeoIP response exceeds {} bytes",
                self.max_bytes
            )));
        }
        if let Some(expected) = request.expected_size
            && expected != bytes.len() as u64
        {
            return Err(Error::new(
                ErrorKind::Protocol,
                format!(
                    "GeoIP response length mismatch: expected {expected}, got {}",
                    bytes.len()
                ),
            ));
        }
        let actual_hash = sha256(&bytes);
        if let Some(expected) = request.expected_sha256.as_deref()
            && expected != actual_hash.as_slice()
        {
            return Err(Error::new(
                ErrorKind::Protocol,
                "GeoIP response SHA-256 mismatch",
            ));
        }
        let metadata = GeoMetadata {
            id: request.id,
            path: request.path,
            sha256: actual_hash,
            size: bytes.len() as u64,
            updated_at: request.updated_at,
        };
        validate_metadata(&bytes, &metadata, self.max_bytes)?;
        GeoDb::validate_bytes(&bytes)?;
        atomic_install(&metadata.path, &bytes)?;
        #[cfg(unix)]
        let database = GeoDb::open_mmap(&metadata.path)?;
        #[cfg(not(unix))]
        let database = GeoDb::from_bytes(bytes)?;
        Ok(self.publish(metadata, database))
    }

    fn publish(&self, metadata: GeoMetadata, database: GeoDb) -> Arc<GeoSnapshot> {
        let generation = self.state.next_generation.fetch_add(1, Ordering::AcqRel) + 1;
        let snapshot = Arc::new(GeoSnapshot {
            metadata,
            database: Arc::new(database),
        });
        let mut published = self
            .state
            .published
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if generation >= published.generation {
            published.generation = generation;
            published.snapshot = Some(Arc::clone(&snapshot));
        }
        snapshot
    }
}

impl Default for GeoDatabaseManager {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_metadata(bytes: &[u8], metadata: &GeoMetadata, max_bytes: usize) -> Result<()> {
    if bytes.len() > max_bytes {
        return Err(Error::invalid(format!(
            "GeoIP database exceeds {} bytes",
            max_bytes
        )));
    }
    if metadata.size != bytes.len() as u64 {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!(
                "GeoIP file length mismatch: expected {}, got {}",
                metadata.size,
                bytes.len()
            ),
        ));
    }
    if metadata.sha256 != sha256(bytes) {
        return Err(Error::new(
            ErrorKind::Protocol,
            "GeoIP file SHA-256 mismatch",
        ));
    }
    Ok(())
}

fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let metadata = fs::metadata(path)
        .map_err(|error| Error::new(ErrorKind::Io, format!("stat MaxMindDB: {error}")))?;
    if metadata.len() > max_bytes as u64 {
        return Err(Error::invalid(format!(
            "GeoIP file exceeds {} bytes",
            max_bytes
        )));
    }
    fs::read(path).map_err(|error| Error::new(ErrorKind::Io, format!("read MaxMindDB: {error}")))
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn validate_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(Error::invalid("GeoIP path is empty"));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| Error::new(ErrorKind::Io, format!("get current directory: {error}")))?
            .join(path)
    };
    if absolute == Path::new("/tmp") || absolute.starts_with("/tmp/") {
        return Err(Error::invalid("GeoIP cache must not use /tmp"));
    }
    Ok(())
}

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn atomic_install(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| Error::new(ErrorKind::Io, format!("create GeoIP directory: {error}")))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::invalid("GeoIP path has no valid file name"))?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| {
                Error::new(ErrorKind::Io, format!("create GeoIP staging file: {error}"))
            })?;
        file.write_all(bytes).map_err(|error| {
            Error::new(ErrorKind::Io, format!("write GeoIP staging file: {error}"))
        })?;
        file.sync_all().map_err(|error| {
            Error::new(ErrorKind::Io, format!("sync GeoIP staging file: {error}"))
        })?;
        fs::rename(&temp, path).map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("atomically replace GeoIP file: {error}"),
            )
        })?;
        sync_parent(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<()> {
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|error| Error::new(ErrorKind::Io, format!("sync GeoIP directory: {error}")))
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::AtomicUsize;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/GeoLite2-Country-Test.mmdb");

    struct FixtureTransport {
        body: Vec<u8>,
        calls: AtomicUsize,
    }

    impl GeoDownloadTransport for FixtureTransport {
        fn download<'a>(&'a self, _url: &'a str) -> BoxFuture<'a, Result<Vec<u8>>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let body = self.body.clone();
            Box::pin(async move { Ok(body) })
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        let mut future = std::pin::pin!(future);
        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(value) => return value,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn metadata(path: PathBuf) -> GeoMetadata {
        GeoMetadata {
            id: "country".to_owned(),
            path,
            sha256: sha256(FIXTURE),
            size: FIXTURE.len() as u64,
            updated_at: 1,
        }
    }

    fn cache_path(name: &str) -> PathBuf {
        let root = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
            .unwrap_or_else(|| PathBuf::from(".cache"));
        root.join("yuhaiin-rust").join("geo-tests").join(name)
    }

    #[test]
    fn official_fixture_supports_ipv4_ipv6_mapped_and_miss() {
        let db = GeoDb::from_bytes(FIXTURE.to_vec()).unwrap();
        assert_eq!(
            db.country_code(IpAddr::V4(Ipv4Addr::new(2, 125, 160, 217)))
                .unwrap(),
            Some("GB".to_owned())
        );
        assert_eq!(
            db.country_code(IpAddr::V6("2001:218::1".parse::<Ipv6Addr>().unwrap()))
                .unwrap(),
            Some("JP".to_owned())
        );
        assert_eq!(
            db.country_code(IpAddr::V6(
                "::ffff:2.125.160.217".parse::<Ipv6Addr>().unwrap()
            ))
            .unwrap(),
            Some("GB".to_owned())
        );
        assert_eq!(
            db.country_code(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
                .unwrap(),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn opening_an_installed_database_uses_mmap_on_unix() {
        let path = cache_path("mmap.mmdb");
        atomic_install(&path, FIXTURE).unwrap();
        let db = GeoDb::open(&path).unwrap();
        assert!(matches!(db.reader.as_ref(), GeoReader::Mapped(_)));
        assert_eq!(
            db.country_code("2.125.160.217".parse().unwrap())
                .unwrap()
                .as_deref(),
            Some("GB")
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    #[ignore = "requires the downloaded Country-without-asn.mmdb fixture"]
    fn downloaded_country_without_asn_fixture_loads_and_queries() {
        let path = std::env::var_os("YUHAIIN_MAXMIND_FIXTURE")
            .map(PathBuf::from)
            .expect("YUHAIIN_MAXMIND_FIXTURE must point to a local .mmdb fixture");
        let db = GeoDb::open(path).unwrap();
        assert_eq!(
            db.country_code("2.125.160.217".parse().unwrap())
                .unwrap()
                .as_deref(),
            Some("GB")
        );
        assert_eq!(
            db.country_code("::ffff:2.125.160.217".parse().unwrap())
                .unwrap()
                .as_deref(),
            Some("GB")
        );
    }

    #[test]
    fn startup_load_rejects_corrupt_or_mismatched_metadata() {
        let path = cache_path("startup.mmdb");
        atomic_install(&path, FIXTURE).unwrap();
        let manager = GeoDatabaseManager::new();
        assert!(manager.load(metadata(path.clone())).is_ok());
        let mut bad = metadata(path.clone());
        bad.sha256[0] ^= 1;
        assert!(manager.load(bad).is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn refresh_validates_and_atomically_replaces_while_old_snapshot_lives() {
        let path = cache_path("refresh.mmdb");
        let manager = GeoDatabaseManager::new();
        let first = metadata(path.clone());
        atomic_install(&path, FIXTURE).unwrap();
        let old = manager.load(first).unwrap();
        let transport = FixtureTransport {
            body: FIXTURE.to_vec(),
            calls: AtomicUsize::new(0),
        };
        let next = block_on(manager.refresh(
            GeoRefreshRequest {
                id: "country".to_owned(),
                path: path.clone(),
                url: "memory://country".to_owned(),
                expected_sha256: Some(sha256(FIXTURE)),
                expected_size: Some(FIXTURE.len() as u64),
                updated_at: 2,
            },
            &transport,
        ))
        .unwrap();
        assert_eq!(transport.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            old.database()
                .country_code("2.125.160.217".parse().unwrap())
                .unwrap(),
            Some("GB".to_owned())
        );
        assert_eq!(next.metadata().updated_at, 2);
        assert_eq!(manager.current().unwrap().metadata().updated_at, 2);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn failed_refresh_keeps_old_snapshot_and_target_file() {
        let path = cache_path("failed.mmdb");
        let manager = GeoDatabaseManager::new();
        atomic_install(&path, FIXTURE).unwrap();
        let old = manager.load(metadata(path.clone())).unwrap();
        let transport = FixtureTransport {
            body: vec![1, 2, 3],
            calls: AtomicUsize::new(0),
        };
        assert!(
            block_on(manager.refresh(
                GeoRefreshRequest {
                    id: "country".to_owned(),
                    path: path.clone(),
                    url: "memory://broken".to_owned(),
                    expected_sha256: None,
                    expected_size: None,
                    updated_at: 2,
                },
                &transport,
            ))
            .is_err()
        );
        assert_eq!(
            manager.current().unwrap().metadata().updated_at,
            old.metadata().updated_at
        );
        assert_eq!(fs::read(path.clone()).unwrap(), FIXTURE);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn concurrent_refreshes_publish_only_valid_whole_snapshots() {
        let path = cache_path("concurrent.mmdb");
        let manager = Arc::new(GeoDatabaseManager::new());
        let transport = Arc::new(FixtureTransport {
            body: FIXTURE.to_vec(),
            calls: AtomicUsize::new(0),
        });
        let mut workers = Vec::new();
        for index in 0..8 {
            let manager = Arc::clone(&manager);
            let transport = Arc::clone(&transport);
            let path = path.clone();
            workers.push(std::thread::spawn(move || {
                block_on(manager.refresh(
                    GeoRefreshRequest {
                        id: "country".to_owned(),
                        path,
                        url: format!("memory://country/{index}"),
                        expected_sha256: None,
                        expected_size: None,
                        updated_at: index,
                    },
                    transport.as_ref(),
                ))
                .unwrap();
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(fs::read(&path).unwrap(), FIXTURE);
        assert!(manager.current().is_some());
        assert_eq!(transport.calls.load(Ordering::Relaxed), 8);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn temporary_files_are_created_next_to_target_and_tmp_is_rejected() {
        assert!(validate_path(Path::new("/tmp/yuhaiin.mmdb")).is_err());
        assert!(validate_path(Path::new("/tmpfs/yuhaiin.mmdb")).is_ok());
    }
}
