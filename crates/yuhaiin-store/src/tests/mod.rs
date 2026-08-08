use super::*;
use std::fs;
use std::future::Future;
use std::task::{Context, Poll, Waker};
use std::time::{SystemTime, UNIX_EPOCH};

fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn test_database_path() -> std::path::PathBuf {
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cache"))
        })
        .expect("a cache directory is required for the persistence test");
    let directory = cache.join("yuhaiin-rust-check");
    fs::create_dir_all(&directory).unwrap();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    directory.join(format!("store-{nonce}.db"))
}

fn remove_database_artifacts(path: &std::path::Path) {
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
            std::path::PathBuf::from(format!("{}{}", path.display(), suffix))
        };
        let _ = fs::remove_file(target);
    }
}

mod go_import;
mod repository;
mod schema;
mod snapshot;
mod storage;
