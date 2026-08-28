//! Opt-in process benchmark for the shared inbound -> router -> outbound path.
//!
//! This is deliberately an integration test instead of a microbenchmark. It
//! starts the release runtime, configures the same SQLite/API boundary used by
//! the other process tests, sends a known amount of data through HTTP CONNECT
//! -> route rule -> fixed + HTTP CONNECT, and samples the runtime process.
//! Results are useful for regression tracking on the same machine; they are
//! not a Go-vs-Rust claim until both implementations use this exact harness.

#![allow(dead_code)]

mod support;

use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

use support::{
    ConnectFixture, H2YuubinsyaFixture, ServiceProcess, configure_http_chain,
    configure_tls_h2_yuubinsya_chain, connect_loopback, integration_dir, seed_empty_database,
};

#[derive(Default)]
struct ProcessUsage {
    peak_rss_kib: u64,
    samples: u64,
    first_cpu_ticks: Option<u64>,
    last_cpu_ticks: Option<u64>,
}

impl ProcessUsage {
    fn cpu_ticks(&self) -> u64 {
        self.last_cpu_ticks
            .unwrap_or_default()
            .saturating_sub(self.first_cpu_ticks.unwrap_or_default())
    }
}

#[derive(Clone, Copy)]
struct ProcessReading {
    rss_kib: u64,
    cpu_ticks: u64,
}

fn read_process_usage(pid: u32) -> Option<ProcessReading> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let rss_kib = status
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:")?.split_whitespace().next())?
            .parse()
            .ok()?;

        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let fields = stat
            .rsplit_once(") ")?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        // /proc/stat starts at field 3 after the command name. utime/stime
        // are fields 14/15, hence indexes 11/12 in this suffix.
        let user_ticks = fields.get(11)?.parse::<u64>().ok()?;
        let system_ticks = fields.get(12)?.parse::<u64>().ok()?;
        Some(ProcessReading {
            rss_kib,
            cpu_ticks: user_ticks.saturating_add(system_ticks),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

async fn sample_runtime(pid: u32, mut stop: watch::Receiver<bool>) -> ProcessUsage {
    let mut usage = ProcessUsage::default();
    loop {
        if let Some(reading) = read_process_usage(pid) {
            usage.peak_rss_kib = usage.peak_rss_kib.max(reading.rss_kib);
            usage.samples = usage.samples.saturating_add(1);
            usage.first_cpu_ticks.get_or_insert(reading.cpu_ticks);
            usage.last_cpu_ticks = Some(reading.cpu_ticks);
        }
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
    usage
}

fn benchmark_bytes() -> usize {
    std::env::var("DORADUS_BENCH_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(64 * 1024 * 1024)
        .max(1)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "opt-in release process benchmark; use scripts/benchmark/throughput.sh"]
async fn http_inbound_route_http_connect_throughput() {
    let total_bytes = benchmark_bytes();
    let fixture = ConnectFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound = support::reserve_loopback().await;
    let root = integration_dir(&format!("benchmark-http-throughput-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_http_chain(&service, inbound, fixture.outbound).await;

    let mut client = connect_loopback(inbound).await;
    let authority = format!("example.test:{}", fixture.target.port());
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut headers = Vec::new();
    let mut header_buffer = [0u8; 1024];
    while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        let length = client.read(&mut header_buffer).await.unwrap();
        assert!(length > 0, "HTTP inbound closed before CONNECT response");
        headers.extend_from_slice(&header_buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));

    let pid = service.pid();
    let (stop_tx, stop_rx) = watch::channel(false);
    let sampler = tokio::spawn(sample_runtime(pid, stop_rx));
    let (mut reader, mut writer) = client.into_split();
    let chunk = vec![0x5a; 64 * 1024];
    let started = Instant::now();
    let writer_task = tokio::spawn(async move {
        let mut remaining = total_bytes;
        while remaining > 0 {
            let length = remaining.min(chunk.len());
            writer.write_all(&chunk[..length]).await.unwrap();
            remaining -= length;
        }
        writer.shutdown().await.unwrap();
    });

    let mut received = 0usize;
    let mut buffer = vec![0u8; 64 * 1024];
    while received < total_bytes {
        let length = reader.read(&mut buffer).await.unwrap();
        assert!(length > 0, "HTTP outbound closed after {received} bytes");
        assert!(
            buffer[..length].iter().all(|byte| *byte == 0x5a),
            "loopback echo payload was corrupted"
        );
        received += length;
    }
    writer_task.await.unwrap();
    let elapsed = started.elapsed();

    let _ = stop_tx.send(true);
    let usage = sampler.await.unwrap();
    let mib_per_second = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
    let result = json!({
        "scenario": "http-inbound-route-http-connect-loopback",
        "bytes": total_bytes,
        "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        "mib_per_sec": mib_per_second,
        "runtime_pid": pid,
        "peak_rss_kib": usage.peak_rss_kib,
        "cpu_ticks": usage.cpu_ticks(),
        "proc_samples": usage.samples,
        "target": "loopback; one stream; debug/release selected by runner"
    });
    println!("BENCHMARK {result}");

    assert_eq!(received, total_bytes);
    assert!(
        fixture
            .connect_authorities
            .lock()
            .unwrap()
            .iter()
            .any(|value| value == &authority),
        "HTTP outbound did not receive the routed authority"
    );
    service.shutdown().await;
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "opt-in release process benchmark; use scripts/benchmark/throughput.sh"]
async fn http_inbound_route_tls_h2_yuubinsya_throughput() {
    let total_bytes = benchmark_bytes();
    let fixture = H2YuubinsyaFixture::start().await;
    let _default_mixed_blocker = tokio::net::TcpListener::bind("127.0.0.1:1080").await.ok();
    let inbound = support::reserve_loopback().await;
    let root = integration_dir(&format!(
        "benchmark-tls-h2-yuubinsya-throughput-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let database = root.join("state.sqlite");
    seed_empty_database(&database).await;
    let service = ServiceProcess::start(&database).await;
    configure_tls_h2_yuubinsya_chain(&service, inbound, fixture.outbound).await;

    let mut client = connect_loopback(inbound).await;
    let authority = format!("example.test:{}", fixture.target.port());
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut headers = Vec::new();
    let mut header_buffer = [0u8; 1024];
    while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
        let length = client.read(&mut header_buffer).await.unwrap();
        assert!(length > 0, "HTTP inbound closed before CONNECT response");
        headers.extend_from_slice(&header_buffer[..length]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 200"));

    let pid = service.pid();
    let (stop_tx, stop_rx) = watch::channel(false);
    let sampler = tokio::spawn(sample_runtime(pid, stop_rx));
    let (mut reader, mut writer) = client.into_split();
    let chunk = vec![0x6b; 64 * 1024];
    let started = Instant::now();
    let writer_task = tokio::spawn(async move {
        let mut remaining = total_bytes;
        while remaining > 0 {
            let length = remaining.min(chunk.len());
            writer.write_all(&chunk[..length]).await.unwrap();
            remaining -= length;
        }
    });

    let mut received = 0usize;
    let mut buffer = vec![0u8; 64 * 1024];
    while received < total_bytes {
        let length = reader.read(&mut buffer).await.unwrap();
        assert!(
            length > 0,
            "TLS/H2/Yuubinsya outbound closed after {received} bytes"
        );
        assert!(
            buffer[..length].iter().all(|byte| *byte == 0x6b),
            "TLS/H2/Yuubinsya loopback echo payload was corrupted"
        );
        received += length;
    }
    writer_task.await.unwrap();
    let elapsed = started.elapsed();

    let _ = stop_tx.send(true);
    let usage = sampler.await.unwrap();
    let mib_per_second = (total_bytes as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
    let result = json!({
        "scenario": "http-inbound-route-tls-h2-yuubinsya-loopback",
        "bytes": total_bytes,
        "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        "mib_per_sec": mib_per_second,
        "runtime_pid": pid,
        "peak_rss_kib": usage.peak_rss_kib,
        "cpu_ticks": usage.cpu_ticks(),
        "proc_samples": usage.samples,
        "target": "loopback; one stream; release; TLS + HTTP/2 + Yuubinsya",
    });
    println!("BENCHMARK {result}");

    assert_eq!(received, total_bytes);
    service.shutdown().await;
    fixture.shutdown().await;
}
