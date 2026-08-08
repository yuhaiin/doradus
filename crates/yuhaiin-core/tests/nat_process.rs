#![cfg(unix)]

use std::fs;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn cache_directory() -> PathBuf {
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .expect("a cache directory is required for the process test");
    let directory = cache.join("yuhaiin-rust-check");
    fs::create_dir_all(&directory).unwrap();
    directory
}

fn test_paths() -> (PathBuf, PathBuf) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let prefix = cache_directory().join(format!("nat-process-{}-{nonce}", std::process::id()));
    (
        prefix.with_extension("ready"),
        prefix.with_extension("event"),
    )
}

fn worker_path() -> PathBuf {
    for variable in ["CARGO_BIN_EXE_nat_worker", "CARGO_BIN_EXE_nat-worker"] {
        if let Some(path) = std::env::var_os(variable) {
            return PathBuf::from(path);
        }
    }
    let test_executable = std::env::current_exe().unwrap();
    let target_debug = test_executable
        .parent()
        .and_then(Path::parent)
        .expect("integration test executable must be under target/debug/deps");
    let path = target_debug.join("nat-worker");
    assert!(
        path.is_file(),
        "nat worker binary does not exist: {}",
        path.display()
    );
    path
}

fn wait_for_file(path: &Path) {
    for _ in 0..200 {
        if path.is_file() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {}", path.display());
}

fn cleanup(paths: &[&Path]) {
    for path in paths {
        let _ = fs::remove_file(path);
    }
}

struct WorkerGuard {
    child: Child,
}

impl WorkerGuard {
    fn force_stop(&mut self) {
        self.child.kill().unwrap();
        let status = self.child.wait().unwrap();
        assert!(
            !status.success(),
            "force-stopped NAT worker unexpectedly succeeded"
        );
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn spawn_worker(
    worker: &Path,
    bind: &str,
    source: &str,
    destination: &str,
    ready: &Path,
    event: &Path,
) -> WorkerGuard {
    WorkerGuard {
        child: Command::new(worker)
            .args([
                bind,
                source,
                destination,
                ready.to_str().unwrap(),
                event.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    }
}

#[test]
fn force_stopped_full_cone_worker_restarts_and_accepts_unseen_peer() {
    let (ready_first, event_first) = test_paths();
    let (ready_second, event_second) = test_paths();
    let destination = UdpSocket::bind("127.0.0.1:0").unwrap();
    destination
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let source = "192.0.2.10:40000";
    let destination_address = destination.local_addr().unwrap().to_string();
    let worker = worker_path();
    let mut first = spawn_worker(
        &worker,
        "127.0.0.1:0",
        source,
        &destination_address,
        &ready_first,
        &event_first,
    );

    wait_for_file(&ready_first);
    let relay_address: std::net::SocketAddr = fs::read_to_string(&ready_first)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let mut bootstrap = [0u8; 64];
    let (length, _) = destination.recv_from(&mut bootstrap).unwrap();
    assert_eq!(&bootstrap[..length], b"bootstrap");

    let unseen_peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    unseen_peer
        .send_to(b"from-unseen-peer", relay_address)
        .unwrap();
    wait_for_file(&event_first);
    let record = fs::read_to_string(&event_first).unwrap();
    assert!(record.contains(&format!("source={source}")));
    assert!(record.contains("payload=from-unseen-peer"));

    first.force_stop();
    let rebound = UdpSocket::bind(relay_address).unwrap();
    drop(rebound);

    let mut second = spawn_worker(
        &worker,
        &relay_address.to_string(),
        source,
        &destination_address,
        &ready_second,
        &event_second,
    );
    wait_for_file(&ready_second);
    let restarted_address: std::net::SocketAddr = fs::read_to_string(&ready_second)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(restarted_address, relay_address);
    let (length, _) = destination.recv_from(&mut bootstrap).unwrap();
    assert_eq!(&bootstrap[..length], b"bootstrap");

    let second_unseen_peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    second_unseen_peer
        .send_to(b"after-runtime-restart", restarted_address)
        .unwrap();
    wait_for_file(&event_second);
    let restarted_record = fs::read_to_string(&event_second).unwrap();
    assert!(restarted_record.contains(&format!("source={source}")));
    assert!(restarted_record.contains("payload=after-runtime-restart"));

    second.force_stop();
    cleanup(&[&ready_first, &event_first, &ready_second, &event_second]);
}
