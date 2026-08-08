use std::env;
use std::future::Future;
use std::io::Write;
use std::path::Path;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use rusqlite::{Connection, params};
use yuhaiin_store::{ConfigMutation, ConfigStore};

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

fn usage() -> ! {
    eprintln!(
        "usage: store_worker write <database> <worker> <items> | \
         store_worker batch <database> <worker> <items> | \
         store_worker read <database> <prefix> <loops> | \
         store_worker uncommitted <database> <hold_ms> | \
         store_worker fakeip-uncommitted <database> <hold_ms>"
    );
    std::process::exit(2);
}

fn database_path(value: Option<String>) -> String {
    let path = value.unwrap_or_else(|| usage());
    if path.is_empty() {
        usage();
    }
    path
}

fn write_batch(path: &str, worker: &str, items: usize) {
    let store = block_on(ConfigStore::open(Path::new(path))).unwrap();
    for item in 0..items {
        let key = format!("cross-process-{worker}-{item}");
        block_on(store.put_config(&key, key.as_bytes())).unwrap();
    }
}

fn write_transaction(path: &str, worker: &str, items: usize) {
    let store = block_on(ConfigStore::open(Path::new(path))).unwrap();
    let mutations = (0..items)
        .map(|item| {
            let key = format!("cross-process-{worker}-{item}");
            ConfigMutation::Put {
                key: key.clone(),
                value: key.into_bytes(),
            }
        })
        .collect::<Vec<_>>();
    block_on(store.apply(&mutations)).unwrap();
}

fn hold_uncommitted(path: &str, hold_ms: u64) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch("PRAGMA journal_mode = WAL; BEGIN IMMEDIATE;")
        .unwrap();
    connection
        .execute(
            "INSERT OR REPLACE INTO yuhaiin_config (key, value) VALUES (?1, ?2)",
            params!["cross-process-uncommitted", b"must-not-survive".as_slice()],
        )
        .unwrap();
    println!("READY");
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_millis(hold_ms));
}

fn hold_fakeip_uncommitted(path: &str, hold_ms: u64) {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch("PRAGMA journal_mode = WAL; BEGIN IMMEDIATE;")
        .unwrap();
    connection
        .execute(
            "INSERT INTO fakeip_entries
             (family, prefix, domain, ip, created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                4i64,
                "198.18.0.0/15",
                "uncommitted.example",
                [198u8, 18, 0, 3].as_slice(),
                100i64,
                100i64
            ],
        )
        .unwrap();
    println!("READY");
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_millis(hold_ms));
}

fn read_batch(path: &str, prefix: &str, loops: usize) {
    let store = block_on(ConfigStore::open(Path::new(path))).unwrap();
    for _ in 0..loops {
        let values = block_on(store.list_config(prefix)).unwrap();
        for (key, value) in values {
            if key != "cross-process-ready" {
                assert_eq!(value, key.as_bytes());
            }
        }
        std::thread::yield_now();
    }
}

fn main() {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("write") => {
            let path = database_path(arguments.next());
            let worker = arguments.next().unwrap_or_else(|| usage());
            let items = arguments
                .next()
                .unwrap_or_else(|| usage())
                .parse::<usize>()
                .unwrap_or_else(|_| usage());
            write_batch(&path, &worker, items);
        }
        Some("batch") => {
            let path = database_path(arguments.next());
            let worker = arguments.next().unwrap_or_else(|| usage());
            let items = arguments
                .next()
                .unwrap_or_else(|| usage())
                .parse::<usize>()
                .unwrap_or_else(|_| usage());
            write_transaction(&path, &worker, items);
        }
        Some("uncommitted") => {
            let path = database_path(arguments.next());
            let hold_ms = arguments
                .next()
                .unwrap_or_else(|| usage())
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            hold_uncommitted(&path, hold_ms);
        }
        Some("fakeip-uncommitted") => {
            let path = database_path(arguments.next());
            let hold_ms = arguments
                .next()
                .unwrap_or_else(|| usage())
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            hold_fakeip_uncommitted(&path, hold_ms);
        }
        Some("read") => {
            let path = database_path(arguments.next());
            let prefix = arguments.next().unwrap_or_else(|| usage());
            let loops = arguments
                .next()
                .unwrap_or_else(|| usage())
                .parse::<usize>()
                .unwrap_or_else(|_| usage());
            read_batch(&path, &prefix, loops);
        }
        _ => usage(),
    }
}
