//! Process-level Linux smoke test for the runtime-owned TUN inbound.
//!
//! This is deliberately a small host fixture rather than a second TUN
//! implementation. It writes one Go-shaped TUN inbound into SQLite, starts
//! the same `RuntimeController` and `inbound::run_until` used by the service,
//! waits for the kernel device, and then exercises the shared shutdown path.
//! The Podman wrapper runs it privileged with `--network=none` so a test does
//! not alter the host routing table.

use std::io::Cursor;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use yuhaiin_chain::{YuubinsyaH2Server, YuubinsyaServerProxy};
use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream, DirectAsyncProxy};
use yuhaiin_core::{
    BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result, RouteMode,
};
use yuhaiin_runtime::{
    RuntimeBuildOptions, RuntimeBuilder, RuntimeController, inbound, load_tun_config,
};
use yuhaiin_store::{ConfigStore, GoInboundRecord, GoNodeRecord};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let result = tokio::task::LocalSet::new().run_until(run()).await;
    if let Err(error) = result {
        eprintln!("tun-service-smoke: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let database = std::env::var_os("YUHAIIN_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".cache/yuhaiin-rust/integration/tun-service/state.sqlite")
        });
    let name = std::env::var("YUHAIIN_TUN_NAME").unwrap_or_else(|_| "yuhaiin-smoke0".to_owned());
    let hold_ms = std::env::var("YUHAIIN_TUN_HOLD_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(750);
    let mtu = std::env::var("YUHAIIN_TUN_MTU")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1500);
    if !(576..=9216).contains(&mtu) {
        return Err(Error::invalid(format!(
            "YUHAIIN_TUN_MTU must be between 576 and 9216, got {mtu}"
        )));
    }
    let traffic = std::env::var_os("YUHAIIN_TUN_TRAFFIC").is_some();
    let traffic_bytes = std::env::var("YUHAIIN_TUN_TRAFFIC_BYTES")
        .ok()
        .map(|value| {
            value.parse::<usize>().map_err(|_| {
                Error::invalid(format!(
                    "YUHAIIN_TUN_TRAFFIC_BYTES must be a positive integer, got {value:?}"
                ))
            })
        })
        .transpose()?
        .unwrap_or(32);
    if traffic_bytes == 0 || traffic_bytes > 512 * 1024 * 1024 {
        return Err(Error::invalid(
            "YUHAIIN_TUN_TRAFFIC_BYTES must be between 1 and 536870912",
        ));
    }
    let connection_hold_ms = std::env::var("YUHAIIN_TUN_CONNECTION_HOLD_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default();
    let assert_connections = std::env::var_os("YUHAIIN_TUN_ASSERT_CONNECTIONS").is_some();
    let reload_inbound = std::env::var_os("YUHAIIN_TUN_RELOAD").is_some();
    let chain_mode = std::env::var("YUHAIIN_TUN_CHAIN")
        .ok()
        .filter(|value| !value.trim().is_empty());

    let (target_address, target_task, chain_fixture) = if chain_mode.is_some() {
        if !traffic {
            return Err(Error::invalid(
                "YUHAIIN_TUN_CHAIN requires YUHAIIN_TUN_TRAFFIC",
            ));
        }
        let fixture = ChainFixture::start().await?;
        (Some(fixture.target), None, Some(fixture))
    } else if traffic {
        let target = TcpListener::bind("127.0.0.1:0").await.map_err(io_error)?;
        let address = target.local_addr().map_err(io_error)?;
        let task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.map_err(io_error)?;
            let mut buffer = vec![0u8; 16 * 1024];
            let mut received = 0usize;
            loop {
                let length = stream.read(&mut buffer).await.map_err(io_error)?;
                if length == 0 {
                    break;
                }
                stream
                    .write_all(&buffer[..length])
                    .await
                    .map_err(io_error)?;
                received = received.saturating_add(length);
            }
            Ok::<usize, Error>(received)
        });
        (Some(address), Some(task), None)
    } else {
        (None, None, None)
    };

    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let store = ConfigStore::open(&database).await?;
    seed_runtime_fixture(
        &store,
        &name,
        target_address,
        chain_fixture.as_ref().map(|fixture| fixture.outbound),
        chain_mode.as_deref(),
        mtu,
    )
    .await?;

    let mut build_options = RuntimeBuildOptions::default();
    build_options.route_fallback.mode = RouteMode::Proxy;
    let controller = RuntimeController::from_builder(
        RuntimeBuilder::new(store.clone(), Arc::new(SystemAsyncIpResolver))
            .with_options(build_options),
    )
    .await?;
    if let Some(mode) = chain_mode.as_deref() {
        println!("runtime-tun-chain-ready mode={mode}");
    }
    let selected = inbound::selected_proxy_id(&controller).await?;
    let chain_types = controller
        .handle()
        .load()
        .proxy_config(&selected)
        .map(|config| config.chain_types.join(","))
        .unwrap_or_else(|| "missing".to_owned());
    println!("runtime-tun-selected-node id={selected} chain={chain_types}");
    let mut route_probe = FlowContext::new(Endpoint::ip(
        Network::Tcp,
        "198.18.0.2:18080"
            .parse()
            .expect("valid TUN smoke endpoint"),
    ));
    let route_mode = controller
        .handle()
        .load()
        .apply_route(&mut route_probe)
        .mode;
    println!("runtime-tun-route-mode mode={route_mode:?}");
    let config = load_tun_config(&store).await?;
    if !config.enabled {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "TUN fixture was not enabled",
        ));
    }
    let device_name = config
        .tun
        .name
        .clone()
        .ok_or_else(|| Error::invalid("TUN fixture has no device name"))?;
    let device_path = Path::new("/sys/class/net").join(&device_name);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let inbound_task =
        tokio::task::spawn_local(inbound::run_until(controller.clone(), shutdown_rx));
    eprintln!(
        "runtime-tun-opening name={device_name} database={}",
        database.display()
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    while !device_path.exists() {
        if inbound_task.is_finished() {
            let result = inbound_task.await.map_err(join_error)?;
            return Err(result
                .err()
                .unwrap_or_else(|| Error::new(ErrorKind::Io, "TUN owner stopped before opening")));
        }
        if Instant::now() >= deadline {
            eprintln!(
                "runtime-tun-logs {:?}",
                controller.monitor().logs().snapshot()
            );
            let _ = shutdown_tx.send(true);
            let _ = inbound_task.await;
            return Err(Error::new(
                ErrorKind::Io,
                format!("runtime TUN device did not appear: {device_name}"),
            ));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    println!("runtime-tun-opened name={device_name}");

    if reload_inbound {
        toggle_persisted_tun(&controller, &device_path, false).await?;
        println!("runtime-tun-disabled name={device_name}");
        if traffic {
            assert_tun_target_unreachable(Duration::from_millis(750)).map_err(io_error)?;
            println!("runtime-tun-disabled-no-route-ok name={device_name}");
        }
        toggle_persisted_tun(&controller, &device_path, true).await?;
        println!("runtime-tun-reload-ok name={device_name}");
    }

    if traffic {
        let connection_assertion = if assert_connections {
            Some(spawn_tun_connection_assertion(
                controller.monitor(),
                selected.clone(),
                Duration::from_secs(10),
            ))
        } else {
            None
        };
        let traffic_result = tokio::task::spawn_blocking(move || {
            run_tun_traffic_client(traffic_bytes, connection_hold_ms)
        })
        .await
        .map_err(join_error)?
        .map_err(io_error);
        if let Err(error) = &traffic_result {
            eprintln!(
                "runtime-tun-logs {:?}",
                controller.monitor().logs().snapshot()
            );
            let _ = shutdown_tx.send(true);
            let _ = inbound_task.await;
            if let Some(connection_assertion) = connection_assertion {
                connection_assertion.abort();
            }
            if let Some(target_task) = target_task {
                target_task.abort();
                let _ = target_task.await;
            }
            if let Some(chain_fixture) = chain_fixture {
                chain_fixture.abort();
            }
            return Err(error.clone());
        }
        if let Some(connection_assertion) = connection_assertion {
            let connection = connection_assertion.await.map_err(join_error)??;
            println!(
                "runtime-tun-connection-ok id={} inbound={} node={} outbound={} local={} protocol={}",
                connection
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default(),
                connection
                    .get("inboundName")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default(),
                connection
                    .get("nodeId")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default(),
                connection
                    .get("outbound")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default(),
                connection
                    .get("localAddr")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default(),
                connection
                    .pointer("/network/connType")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default(),
            );
        }
        println!("runtime-tun-traffic-ok bytes={traffic_bytes}");
    } else {
        tokio::time::sleep(Duration::from_millis(hold_ms)).await;
    }
    shutdown_tx
        .send(true)
        .map_err(|_| Error::new(ErrorKind::Closed, "TUN shutdown receiver closed"))?;
    inbound_task.await.map_err(join_error)??;
    if let Some(target_task) = target_task {
        let received = target_task.await.map_err(join_error)??;
        if received != traffic_bytes {
            return Err(Error::new(
                ErrorKind::Io,
                format!("runtime TUN traffic target received {received} of {traffic_bytes} bytes"),
            ));
        }
    }
    if let Some(chain_fixture) = chain_fixture {
        let received = chain_fixture.shutdown().await?;
        if received != traffic_bytes {
            return Err(Error::new(
                ErrorKind::Io,
                format!("runtime TUN chain target received {received} of {traffic_bytes} bytes"),
            ));
        }
    }
    controller.persist_monitor().await?;

    if device_path.exists() {
        return Err(Error::new(
            ErrorKind::Io,
            format!("runtime TUN device remained after shutdown: {device_name}"),
        ));
    }
    println!("runtime-tun-closed name={device_name}");
    Ok(())
}

async fn toggle_persisted_tun(
    controller: &RuntimeController,
    device_path: &Path,
    enabled: bool,
) -> Result<()> {
    let mut record = controller
        .store()
        .repository()
        .list_go_inbounds()
        .await?
        .into_iter()
        .find(|record| record.id == "tun-service-smoke")
        .ok_or_else(|| Error::invalid("TUN reload fixture record disappeared"))?;
    record.enabled = enabled;
    let mut data: serde_json::Value = serde_json::from_slice(&record.data_json)
        .map_err(|error| Error::invalid(format!("TUN reload fixture JSON: {error}")))?;
    data["enabled"] = serde_json::Value::Bool(enabled);
    record.data_json = serde_json::to_vec(&data).map_err(io_error)?;
    controller
        .mutate_and_reload(
            move |store| async move { store.repository().put_go_inbound(&record).await },
        )
        .await?;

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if device_path.exists() == enabled {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::new(
                ErrorKind::Timeout,
                format!(
                    "TUN reload did not reach enabled={enabled} for {}",
                    device_path.display()
                ),
            ));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn seed_runtime_fixture(
    store: &ConfigStore,
    name: &str,
    target_address: Option<SocketAddr>,
    chain_outbound: Option<SocketAddr>,
    chain_mode: Option<&str>,
    mtu: usize,
) -> Result<()> {
    if store.repository().list_go_nodes().await?.is_empty() {
        store
            .repository()
            .put_go_node(&GoNodeRecord {
                id: "direct".to_owned(),
                name: "Direct".to_owned(),
                group_name: "builtin".to_owned(),
                origin: "rust-smoke".to_owned(),
                enabled: true,
                chain_types_json: br##"["direct"]"##.to_vec(),
                updated_at: 0,
                data_json: br##"{"id":"direct","name":"Direct","group":"builtin","origin":"rust-smoke","enabled":true,"protocol":"direct","chain":[{"type":"direct","direct":{}}]}"##.to_vec(),
            })
            .await?;
    }

    let data = json!({
        "id": "tun-service-smoke",
        "name": "tun-service-smoke",
        "enabled": true,
        "network": {"type": "empty", "empty": {}},
        "transports": [],
        "protocol": {
            "type": "tun",
            "tun": {
                "name": format!("tun://{name}"),
                "mtu": mtu,
                "portal": "198.18.0.1/15",
                "routes": ["198.18.0.2/32"],
                "excludes": []
            }
        }
    });
    store
        .repository()
        .put_go_inbound(&GoInboundRecord {
            id: "tun-service-smoke".to_owned(),
            name: "tun-service-smoke".to_owned(),
            enabled: true,
            network_type: "empty".to_owned(),
            protocol_type: "tun".to_owned(),
            transport_types_json: br"[]".to_vec(),
            updated_at: 0,
            data_json: serde_json::to_vec(&data).map_err(io_error)?,
        })
        .await?;

    if let Some(target_address) = target_address {
        let (node_id, chain_types_json, chain) = if let Some(outbound) = chain_outbound {
            if !chain_mode.is_some_and(|mode| mode.eq_ignore_ascii_case("tls-h2-yuubinsya")) {
                return Err(Error::invalid(
                    "unsupported YUHAIIN_TUN_CHAIN; expected tls-h2-yuubinsya",
                ));
            }
            (
                "tun-tls-h2-yuubinsya",
                br##"["fixed","tls","http2","yuubinsya"]"##.to_vec(),
                json!([
                    {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
                    {"type":"tls","tls":{"enable":true,"insecure_skip_verify":true,"servernames":["localhost"],"next_protos":["h2"],"ca_cert":[]}},
                    {"type":"http2","http2":{"concurrency":1,"max_streams":16,"idle_timeout_secs":30}},
                    {"type":"yuubinsya","yuubinsya":{"password":YUUBINSYA_PASSWORD,"udp_over_stream":true,"udp_coalesce":false}}
                ]),
            )
        } else {
            (
                "tun-fixed",
                b"[\"fixed\"]".to_vec(),
                json!([{"type":"fixed","fixed":{"host":"127.0.0.1","port":target_address.port()}}]),
            )
        };
        store
            .repository()
            .put_go_node(&GoNodeRecord {
                id: node_id.to_owned(),
                name: "TUN smoke outbound".to_owned(),
                group_name: "rust-smoke".to_owned(),
                origin: "rust-smoke".to_owned(),
                enabled: true,
                chain_types_json,
                updated_at: 0,
                data_json: serde_json::to_vec(&json!({
                    "id":node_id,
                    "name":"TUN smoke outbound",
                    "group":"rust-smoke",
                    "origin":"rust-smoke",
                    "enabled":true,
                    "chain":chain
                }))
                .map_err(io_error)?,
            })
            .await?;
        store
            .put_config(
                "selected_tcp_node_v2",
                &serde_json::to_vec(&json!({"id":node_id})).map_err(io_error)?,
            )
            .await?;
    } else {
        store
            .put_config(
                "selected_tcp_node_v2",
                &serde_json::to_vec(&json!({"id":"direct"})).map_err(io_error)?,
            )
            .await?;
    }
    Ok(())
}

fn assert_tun_target_unreachable(timeout: Duration) -> std::io::Result<()> {
    let address = "198.18.0.2:18080";
    match TcpStream::connect_timeout(&address.parse().unwrap(), timeout) {
        Ok(stream) => {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            Err(std::io::Error::other(format!(
                "TUN target {address} remained reachable while the inbound was disabled"
            )))
        }
        Err(_) => Ok(()),
    }
}

fn traffic_byte(offset: usize) -> u8 {
    (offset as u64)
        .wrapping_mul(31)
        .wrapping_add(17)
        .to_le_bytes()[0]
}

fn fill_traffic_chunk(buffer: &mut [u8], offset: usize) {
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = traffic_byte(offset + index);
    }
}

fn spawn_tun_connection_assertion(
    monitor: Arc<yuhaiin_runtime::ConnectionMonitor>,
    selected_node: String,
    timeout: Duration,
) -> tokio::task::JoinHandle<Result<serde_json::Value>> {
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let connections = monitor
                .connections_value()
                .get("connections")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            if let Some(connection) = connections.into_iter().find(|connection| {
                connection
                    .get("component")
                    .and_then(serde_json::Value::as_str)
                    == Some("tun")
                    && connection.get("nodeId").and_then(serde_json::Value::as_str)
                        == Some(selected_node.as_str())
                    && connection
                        .get("outbound")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                    && connection
                        .get("localAddr")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|value| !value.is_empty())
            }) {
                return Ok(connection);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::new(
                    ErrorKind::Timeout,
                    format!(
                        "TUN connection metadata did not appear for selected node {selected_node}"
                    ),
                ));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
}

fn run_tun_traffic_client(total_bytes: usize, connection_hold_ms: u64) -> std::io::Result<()> {
    use std::io::{Read, Write};

    let address = "198.18.0.2:18080";
    let mut stream = TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_secs(10))
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("connect TUN traffic target {address}: {error}"),
            )
        })?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(120)))?;
    let mut writer_stream = stream.try_clone().map_err(|error| {
        std::io::Error::new(error.kind(), format!("clone TUN traffic stream: {error}"))
    })?;
    writer_stream.set_write_timeout(Some(Duration::from_secs(120)))?;
    let writer = std::thread::spawn(move || -> std::io::Result<()> {
        let mut payload = vec![0u8; 64 * 1024];
        let mut sent = 0usize;
        while sent < total_bytes {
            let length = (total_bytes - sent).min(payload.len());
            fill_traffic_chunk(&mut payload[..length], sent);
            writer_stream
                .write_all(&payload[..length])
                .map_err(|error| {
                    std::io::Error::new(
                        error.kind(),
                        format!("write TUN traffic payload at byte {sent}: {error}"),
                    )
                })?;
            sent += length;
        }
        if connection_hold_ms != 0 {
            std::thread::sleep(Duration::from_millis(connection_hold_ms));
        }
        writer_stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("shutdown TUN traffic writer: {error}"),
                )
            })
    });
    let mut echoed = vec![0u8; 64 * 1024];
    let mut received = 0usize;
    let mut read_result = Ok(());
    while received < total_bytes {
        let length = (total_bytes - received).min(echoed.len());
        if let Err(error) = stream.read_exact(&mut echoed[..length]) {
            read_result = Err(error);
            break;
        }
        for (index, byte) in echoed[..length].iter().enumerate() {
            if *byte != traffic_byte(received + index) {
                read_result = Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("runtime TUN echo mismatch at byte {}", received + index),
                ));
                break;
            }
        }
        if read_result.is_err() {
            break;
        }
        received += length;
    }
    if read_result.is_err() {
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
    let writer_result = writer
        .join()
        .map_err(|_| std::io::Error::other("runtime TUN traffic writer panicked"))?;
    read_result.map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("read TUN traffic echo after {received} bytes: {error}"),
        )
    })?;
    writer_result
}

const YUUBINSYA_PASSWORD: &str = "runtime-tun-smoke-yuubinsya";
const LEAF_CERTIFICATE_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUA6T+/U88N9aMPipK+MdNsAFRUAUwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNeXVoYWlpbi1wMC1jYTAeFw0yNjA4MDYxODIwNDlaFw0zNjA4
MDMxODIwNDlaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABLPnwlYFERi1MgbJNuBHZV/eSpTGdJCQIOyxBt8LlR1ZTEG06pWy
FnJVIzUS4oPuuHc0RcDEltGb/WolyQlM75SjbTBrMBQGA1UdEQQNMAuCCWxvY2Fs
aG9zdDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUZoMmXETR998IsWt1
UTBOVMIs7jMwHwYDVR0jBBgwFoAUhaYkOXheQ1JzLpIKK4I2FEcRMyMwCgYIKoZI
zj0EAwIDSAAwRQIgGEU+sldusbLVAE/kxzZYXaMpIt6l+CZ0cC2jm7lQBqoCIQCw
M5PhuwMhCCb+dUnK6ueJUMHwyK3l2pIAJTMp9+cwqw==
-----END CERTIFICATE-----
"#;
const PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqkH6SeIb9vVEJ6WecsMk5Pn/a8sQ+vdNS/ZSkl3KwfoAoGCCqGSM49
AwEHoUQDQgAEs+fCVgURGLUyBsk24EdlX95KlMZ0kJAg7LEG3wuVHVlMQbTqlbIW
clUjNRLig+64dzRFwMSW0Zv9aiXJCUzvlA==
-----END EC PRIVATE KEY-----
"#;

struct ChainFixture {
    target: SocketAddr,
    outbound: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server_task: tokio::task::JoinHandle<()>,
    target_task: tokio::task::JoinHandle<Result<usize>>,
}

impl ChainFixture {
    async fn start() -> Result<Self> {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.map_err(io_error)?;
        let target = target_listener.local_addr().map_err(io_error)?;
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.map_err(io_error)?;
            let mut buffer = vec![0u8; 16 * 1024];
            let mut received = 0usize;
            loop {
                let length = stream.read(&mut buffer).await.map_err(io_error)?;
                if length == 0 {
                    break;
                }
                stream
                    .write_all(&buffer[..length])
                    .await
                    .map_err(io_error)?;
                received = received.saturating_add(length);
            }
            Ok(received)
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(io_error)?;
        let outbound = listener.local_addr().map_err(io_error)?;
        let upstream: Arc<dyn AsyncProxy> = Arc::new(FixedTargetProxy {
            direct: DirectAsyncProxy {
                timeout: Duration::from_secs(3),
            },
            tcp_target: target,
            udp_target: target,
        });
        let proxy = Arc::new(YuubinsyaServerProxy::new(
            yuhaiin_core::yuubinsya::derive_salt(YUUBINSYA_PASSWORD.as_bytes()),
            upstream,
        ));
        let tls_config = chain_server_config()?;
        let tls_acceptor = TlsAcceptor::from(Arc::clone(&tls_config));
        let server = Arc::new(YuubinsyaH2Server::new(tls_config, proxy)?);
        let (shutdown, receiver) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            tokio::select! {
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            let stream = match tls_acceptor.accept(stream).await {
                                Ok(stream) => stream,
                                Err(_) => return,
                            };
                            let _ = server.serve_h2(stream).await;
                        }
                        Err(error) => eprintln!("runtime-tun-chain-listener: {error}"),
                    }
                }
                _ = receiver => {}
            }
        });
        Ok(Self {
            target,
            outbound,
            shutdown: Some(shutdown),
            server_task,
            target_task,
        })
    }

    async fn shutdown(mut self) -> Result<usize> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.server_task.await;
        self.target_task.await.map_err(join_error)?
    }

    fn abort(self) {
        self.server_task.abort();
        self.target_task.abort();
    }
}

fn chain_server_config() -> Result<Arc<rustls::ServerConfig>> {
    let certificate = rustls_pemfile::certs(&mut Cursor::new(LEAF_CERTIFICATE_PEM))
        .next()
        .ok_or_else(|| Error::invalid("TUN chain fixture certificate is empty"))?
        .map_err(|error| Error::invalid(format!("TUN chain fixture certificate: {error}")))?;
    let key = rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY_PEM))
        .map_err(|error| Error::invalid(format!("TUN chain fixture key: {error}")))?
        .ok_or_else(|| Error::invalid("TUN chain fixture key is empty"))?;
    let provider = Arc::new(rustls_rustcrypto::provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error.to_string()))?
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(
                certificate.to_vec(),
            )],
            key,
        )
        .map_err(|error| Error::invalid(format!("TUN chain fixture TLS config: {error}")))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

struct FixedTargetProxy {
    direct: DirectAsyncProxy,
    tcp_target: SocketAddr,
    udp_target: SocketAddr,
}

impl FixedTargetProxy {
    fn mapped_context(&self, context: &FlowContext) -> FlowContext {
        let mut mapped = context.clone();
        let target = if context.network == Network::Udp {
            self.udp_target
        } else {
            self.tcp_target
        };
        mapped.resolved_destination = Some(Endpoint::ip(context.network, target));
        mapped
    }
}

struct FixedTargetDatagram {
    inner: Box<dyn AsyncDatagram>,
    target: SocketAddr,
}

impl AsyncDatagram for FixedTargetDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], _target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        let target = Endpoint::ip(Network::Udp, self.target);
        Box::pin(async move { self.inner.send_to(payload, target).await })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        self.inner.recv_from(buffer)
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.inner.local_addr()
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

impl AsyncProxy for FixedTargetProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let mapped = self.mapped_context(context);
        Box::pin(async move { self.direct.connect(&mapped).await })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let mapped = self.mapped_context(context);
        let target = self.udp_target;
        Box::pin(async move {
            let datagram = self.direct.open_datagram(&mapped).await?;
            Ok(Box::new(FixedTargetDatagram {
                inner: datagram,
                target,
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        let mapped = self.mapped_context(context);
        Box::pin(async move { self.direct.ping(&mapped).await })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.direct.close()
    }
}

fn io_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

fn join_error(error: tokio::task::JoinError) -> Error {
    io_error(error)
}
