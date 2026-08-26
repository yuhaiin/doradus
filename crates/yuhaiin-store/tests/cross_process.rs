use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use yuhaiin_store::ConfigStore;
use yuhaiin_store::fakeip::{FakeIpConfig, FakeIpPool, FakeIpPoolOptions};

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    let waker = std::task::Waker::noop();
    let mut context = std::task::Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => return value,
            std::task::Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn database_path() -> PathBuf {
    let cache = std::env::var_os("YUHAIIN_CACHE_DIR")
        .map(PathBuf::from)
        .expect("a cache directory is required for the cross-process test");
    let directory = cache.join("yuhaiin-rust-check");
    fs::create_dir_all(&directory).unwrap();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    directory.join(format!(
        "store-cross-process-{}-{nonce}.db",
        std::process::id()
    ))
}

fn remove_database_artifacts(path: &Path) {
    for suffix in [
        "",
        "-journal",
        "-wal",
        "-shm",
        "-wal-fec",
        "-fsqlite-ns-use",
        "-fsqlite-ns-gate",
        "-yuhaiin-write-lock",
    ] {
        let target = if suffix.is_empty() {
            path.to_path_buf()
        } else {
            PathBuf::from(format!("{}{}", path.display(), suffix))
        };
        let _ = fs::remove_file(target);
    }
}

// Keep separate fixtures from reusing the same cache paths while retaining the
// actual writer/reader concurrency inside each fixture. The legacy fsqlite
// sidecars below are removed only for compatibility with old experimental runs.
static PROCESS_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn process_test_guard() -> std::sync::MutexGuard<'static, ()> {
    PROCESS_TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn worker_path() -> PathBuf {
    for variable in ["CARGO_BIN_EXE_store_worker", "CARGO_BIN_EXE_store-worker"] {
        if let Some(path) = std::env::var_os(variable) {
            return PathBuf::from(path);
        }
    }
    let test_executable = std::env::current_exe().unwrap();
    let target_debug = test_executable
        .parent()
        .and_then(Path::parent)
        .expect("integration test executable must be under target/debug/deps");
    let path = target_debug.join("store_worker");
    assert!(
        path.is_file(),
        "store_worker binary does not exist: {}",
        path.display()
    );
    path
}

fn spawn_writer(worker: &Path, path: &Path, id: usize, items: usize) -> Child {
    Command::new(worker)
        .args([
            "write",
            path.to_str().unwrap(),
            &id.to_string(),
            &items.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn spawn_reader(worker: &Path, path: &Path, loops: usize) -> Child {
    Command::new(worker)
        .args([
            "read",
            path.to_str().unwrap(),
            "cross-process-",
            &loops.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn spawn_batch_writer(worker: &Path, path: &Path, id: usize, items: usize) -> Child {
    Command::new(worker)
        .args([
            "batch",
            path.to_str().unwrap(),
            &id.to_string(),
            &items.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn spawn_hold_write_lock(worker: &Path, path: &Path, hold_ms: u64) -> Child {
    Command::new(worker)
        .args([
            "hold-write-lock",
            path.to_str().unwrap(),
            &hold_ms.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn spawn_statistics_projector(worker: &Path, path: &Path) -> Child {
    Command::new(worker)
        .args(["project-statistics", path.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_until_ready(child: &mut Child) {
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut ready = String::new();
    reader.read_line(&mut ready).unwrap();
    assert_eq!(ready.trim(), "READY");
}

#[test]
fn independent_processes_can_initialize_and_write_one_store() {
    let _test_guard = process_test_guard();
    let path = database_path();
    let worker = worker_path();
    let process_count = 8;
    let items_per_process = 24;
    let children = (0..process_count)
        .map(|id| spawn_writer(&worker, &path, id, items_per_process))
        .collect::<Vec<_>>();

    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "store worker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let store = block_on(ConfigStore::open(&path)).unwrap();
    let values = block_on(store.list_config("cross-process-")).unwrap();
    assert_eq!(values.len(), process_count * items_per_process);
    for (key, value) in values {
        assert_eq!(value, key.as_bytes());
    }
    remove_database_artifacts(&path);
}

#[test]
fn cross_process_initialization_waits_for_upgrade_write_lock() {
    let _test_guard = process_test_guard();
    let path = database_path();
    let worker = worker_path();
    let mut holder = spawn_hold_write_lock(&worker, &path, 500);
    wait_until_ready(&mut holder);

    let mut writer = spawn_writer(&worker, &path, 0, 1);
    std::thread::sleep(std::time::Duration::from_millis(120));
    assert!(
        writer.try_wait().unwrap().is_none(),
        "ConfigStore::open must wait for the upgrade write lock"
    );

    let holder_output = holder.wait_with_output().unwrap();
    assert!(
        holder_output.status.success(),
        "write-lock holder failed: {}",
        String::from_utf8_lossy(&holder_output.stderr)
    );
    let writer_output = writer.wait_with_output().unwrap();
    assert!(
        writer_output.status.success(),
        "writer did not recover after upgrade lock release: {}",
        String::from_utf8_lossy(&writer_output.stderr)
    );

    let store = block_on(ConfigStore::open(&path)).unwrap();
    assert_eq!(
        block_on(store.list_config("cross-process-")).unwrap().len(),
        1
    );
    remove_database_artifacts(&path);
}

#[test]
fn cross_process_statistics_projection_retries_after_sqlite_writer_releases() {
    let _test_guard = process_test_guard();
    let path = database_path();
    let worker = worker_path();
    let store = block_on(ConfigStore::open(&path)).unwrap();
    block_on(store.put_config("cross-process-ready", b"yes")).unwrap();

    let mut holder = Command::new(&worker)
        .args(["uncommitted", path.to_str().unwrap(), "700"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_until_ready(&mut holder);
    let mut projector = spawn_statistics_projector(&worker, &path);
    std::thread::sleep(std::time::Duration::from_millis(120));
    assert!(
        projector.try_wait().unwrap().is_none(),
        "statistics projection must remain pending while SQLite holds BEGIN IMMEDIATE"
    );

    let holder_output = holder.wait_with_output().unwrap();
    assert!(
        holder_output.status.success(),
        "SQLite lock holder failed: {}",
        String::from_utf8_lossy(&holder_output.stderr)
    );
    let projector_output = projector.wait_with_output().unwrap();
    assert!(
        projector_output.status.success(),
        "statistics projection did not recover after SQLite lock release: {}",
        String::from_utf8_lossy(&projector_output.stderr)
    );
    assert!(store.load_go_statistics().is_ok());
    remove_database_artifacts(&path);
}

#[test]
fn concurrent_process_readers_observe_writers_without_corrupting_wal() {
    let _test_guard = process_test_guard();
    let path = database_path();
    let worker = worker_path();
    let store = block_on(ConfigStore::open(&path)).unwrap();
    block_on(store.put_config("cross-process-ready", b"yes")).unwrap();

    let writer_count = 12;
    let items_per_writer = 48;
    let reader_count = 6;
    let reader_loops = 80;
    let readers = (0..reader_count)
        .map(|_| spawn_reader(&worker, &path, reader_loops))
        .collect::<Vec<_>>();
    let writers = (0..writer_count)
        .map(|id| spawn_batch_writer(&worker, &path, id, items_per_writer))
        .collect::<Vec<_>>();

    for child in writers.into_iter().chain(readers) {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "store pressure worker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let values = block_on(store.list_config("cross-process-")).unwrap();
    assert_eq!(
        values.len(),
        1 + writer_count * items_per_writer,
        "reader pressure must not hide committed rows"
    );
    let connection = Connection::open(path.to_str().unwrap()).unwrap();
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    assert!(
        block_on(store.repository().get_nat_config_or_default("default"))
            .unwrap()
            .full_cone,
        "cross-process pressure must preserve Full Cone NAT default semantics"
    );
    remove_database_artifacts(&path);
}

#[test]
#[ignore = "long cross-process SQLite WAL pressure; run explicitly"]
fn long_cross_process_wal_pressure_preserves_rows_and_full_cone_default() {
    let _test_guard = process_test_guard();
    let path = database_path();
    let worker = worker_path();
    let bootstrap = block_on(ConfigStore::open(&path)).unwrap();
    block_on(bootstrap.put_config("cross-process-ready", b"yes")).unwrap();
    assert!(
        block_on(bootstrap.repository().get_nat_config_or_default("default"))
            .unwrap()
            .full_cone
    );

    let writer_count = 24;
    let items_per_writer = 128;
    let reader_count = 10;
    let reader_loops = 240;
    let readers = (0..reader_count)
        .map(|_| spawn_reader(&worker, &path, reader_loops))
        .collect::<Vec<_>>();
    let writers = (0..writer_count)
        .map(|id| spawn_batch_writer(&worker, &path, id, items_per_writer))
        .collect::<Vec<_>>();

    for child in writers.into_iter().chain(readers) {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "long store pressure worker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let values = block_on(bootstrap.list_config("cross-process-")).unwrap();
    assert_eq!(
        values.len(),
        1 + writer_count * items_per_writer,
        "long pressure must retain every committed batch row"
    );
    let connection = Connection::open(path.to_str().unwrap()).unwrap();
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    assert!(
        block_on(bootstrap.repository().get_nat_config_or_default("default"))
            .unwrap()
            .full_cone,
        "long cross-process pressure must preserve Full Cone NAT default semantics"
    );
    remove_database_artifacts(&path);
}

#[test]
fn force_stopped_process_leaves_committed_rows_and_discards_open_transaction() {
    let _test_guard = process_test_guard();
    let path = database_path();
    let worker = worker_path();
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        block_on(store.put_config("cross-process-committed", b"survive")).unwrap();
    }

    let mut child = Command::new(&worker)
        .args(["uncommitted", path.to_str().unwrap(), "10000"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut ready = String::new();
    reader.read_line(&mut ready).unwrap();
    assert_eq!(ready.trim(), "READY");
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert!(
        !status.success(),
        "force-stopped worker unexpectedly succeeded"
    );

    let store = block_on(ConfigStore::open(&path)).unwrap();
    assert_eq!(
        block_on(store.get_config("cross-process-committed")).unwrap(),
        Some(b"survive".to_vec())
    );
    assert_eq!(
        block_on(store.get_config("cross-process-uncommitted")).unwrap(),
        None
    );
    let connection = Connection::open(path.to_str().unwrap()).unwrap();
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    remove_database_artifacts(&path);
}

#[test]
fn force_stopped_fakeip_transaction_keeps_committed_mapping_and_discards_row() {
    let _test_guard = process_test_guard();
    let path = database_path();
    let worker = worker_path();
    let committed_domain = yuhaiin_core::DomainName::new("committed.example").unwrap();
    let config =
        FakeIpConfig::new("198.18.0.1".parse().unwrap(), "198.18.0.3".parse().unwrap()).unwrap();
    let options = FakeIpPoolOptions::new(3, i64::MAX / 4).unwrap();
    {
        let store = block_on(ConfigStore::open(&path)).unwrap();
        let pool = block_on(FakeIpPool::open_with_prefix(
            store,
            config,
            "198.18.0.0/15",
            options,
        ))
        .unwrap();
        assert_eq!(
            block_on(pool.allocate_at(committed_domain.clone(), 100)),
            Ok("198.18.0.1".parse().unwrap())
        );
    }

    let mut child = Command::new(&worker)
        .args(["fakeip-uncommitted", path.to_str().unwrap(), "10000"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut ready = String::new();
    reader.read_line(&mut ready).unwrap();
    assert_eq!(ready.trim(), "READY");
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert!(!status.success());

    let store = block_on(ConfigStore::open(&path)).unwrap();
    let pool = block_on(FakeIpPool::open_with_prefix(
        store.clone(),
        config,
        "198.18.0.0/15",
        options,
    ))
    .unwrap();
    assert_eq!(
        block_on(pool.lookup_ip(&committed_domain)),
        Some("198.18.0.1".parse().unwrap())
    );
    assert_eq!(
        block_on(pool.lookup_ip(&yuhaiin_core::DomainName::new("uncommitted.example").unwrap())),
        None
    );
    let rows = block_on(store.list_fakeip_entries(4, "198.18.0.0/15")).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].domain, "committed.example");
    remove_database_artifacts(&path);
}
