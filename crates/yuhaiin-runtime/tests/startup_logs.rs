#![allow(dead_code)]

mod support;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use support::{integration_dir, reserve_loopback, seed_empty_database};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreground_service_emits_startup_progress_by_default() {
    let root = integration_dir("startup-logs");
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let address = reserve_loopback().await;
    let runtime_binary = std::env::var_os("YUHAIIN_RUNTIME_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_yuhaiin").into());

    let mut child = Command::new(runtime_binary)
        .env("YUHAIIN_DB", &database)
        .env("YUHAIIN_HTTP", address.to_string())
        .env_remove("YUHAIIN_QUIET")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (lines_tx, lines_rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            match line {
                Ok(line) => {
                    if lines_tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let mut lines = Vec::new();
    let mut ready = false;
    for _ in 0..100 {
        while let Ok(line) = lines_rx.try_recv() {
            ready |= line.contains("runtime ready; DNS, inbound and HTTP API supervisors started");
            lines.push(line);
        }
        if ready {
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("runtime exited before startup completed ({status}); stderr={lines:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        panic!("foreground runtime did not emit readiness log; stderr={lines:?}");
    }

    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
    }
    #[cfg(not(unix))]
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "runtime did not shut down cleanly: {status}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("starting; database="))
    );
    assert!(
        lines
            .iter()
            .any(|line| line.contains("HTTP API listening on"))
    );
}
