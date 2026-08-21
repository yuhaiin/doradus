use super::{RuntimeService, ServiceOptions};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn test_database() -> PathBuf {
    let root = std::env::var_os("YUHAIIN_CACHE_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("yuhaiin-rust/service-tests");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_nanos();
    root.join(format!("service-{}-{nonce}.sqlite", std::process::id()))
}

fn remove_database(path: &std::path::Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut candidate = path.as_os_str().to_os_string();
        candidate.push(suffix);
        let _ = std::fs::remove_file(candidate);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn service_start_exposes_api_and_shutdowns() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let database = test_database();
            let mut options = ServiceOptions::new(
                database.clone(),
                "127.0.0.1:0".parse().expect("loopback address"),
            );
            options.username = "".to_owned();
            options.password = "".to_owned();
            let service = RuntimeService::start(options).await.unwrap();
            let address = service.address();
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream
                .write_all(
                    format!(
                        "GET /api/v2/info HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            let response = String::from_utf8_lossy(&response);
            assert!(
                response.starts_with("HTTP/1.1 2"),
                "unexpected response: {response}"
            );
            service.shutdown().unwrap();
            service.wait().await.unwrap();
            remove_database(&database);
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_aborts_a_half_open_http_connection() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let database = test_database();
            let service = RuntimeService::start(ServiceOptions::new(
                database.clone(),
                "127.0.0.1:0".parse().expect("loopback address"),
            ))
            .await
            .unwrap();
            let _held_connection = tokio::net::TcpStream::connect(service.address())
                .await
                .unwrap();
            service.shutdown().unwrap();
            tokio::time::timeout(Duration::from_secs(6), service.wait())
                .await
                .expect("shutdown must not wait for a half-open HTTP connection")
                .unwrap();
            remove_database(&database);
        })
        .await;
}
