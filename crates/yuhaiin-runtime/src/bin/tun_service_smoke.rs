//! Process-level Linux smoke test for the runtime-owned TUN inbound.
//!
//! This is deliberately a small host fixture rather than a second TUN
//! implementation. It writes one Go-shaped TUN inbound into SQLite, starts
//! the same `RuntimeController` and `inbound::run_until` used by the service,
//! waits for the kernel device, and then exercises the shared shutdown path.
//! The Podman wrapper runs it privileged with `--network=none` so a test does
//! not alter the host routing table.

use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
use yuhaiin_core::{Error, ErrorKind, Result, RouteMode};
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
            PathBuf::from(
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(".")),
            )
            .join(".cache/yuhaiin-rust/integration/tun-service/state.sqlite")
        });
    let name = std::env::var("YUHAIIN_TUN_NAME").unwrap_or_else(|_| "yuhaiin-smoke0".to_owned());
    let hold_ms = std::env::var("YUHAIIN_TUN_HOLD_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(750);
    let traffic = std::env::var_os("YUHAIIN_TUN_TRAFFIC").is_some();

    let (target_address, target_task) = if traffic {
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
        (Some(address), Some(task))
    } else {
        (None, None)
    };

    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let store = ConfigStore::open(&database).await?;
    seed_runtime_fixture(&store, &name, target_address).await?;

    let mut build_options = RuntimeBuildOptions::default();
    build_options.route_fallback.mode = RouteMode::Proxy;
    let controller = RuntimeController::from_builder(
        RuntimeBuilder::new(store.clone(), Arc::new(SystemAsyncIpResolver))
            .with_options(build_options),
    )
    .await?;
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

    if traffic {
        let traffic_result = tokio::task::spawn_blocking(run_tun_traffic_client)
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
            if let Some(target_task) = target_task {
                target_task.abort();
                let _ = target_task.await;
            }
            return Err(error.clone());
        }
        println!("runtime-tun-traffic-ok");
    } else {
        tokio::time::sleep(Duration::from_millis(hold_ms)).await;
    }
    shutdown_tx
        .send(true)
        .map_err(|_| Error::new(ErrorKind::Closed, "TUN shutdown receiver closed"))?;
    inbound_task.await.map_err(join_error)??;
    if let Some(target_task) = target_task {
        let received = target_task.await.map_err(join_error)??;
        if received == 0 {
            return Err(Error::new(
                ErrorKind::Io,
                "runtime TUN traffic target received no bytes",
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

async fn seed_runtime_fixture(
    store: &ConfigStore,
    name: &str,
    target_address: Option<SocketAddr>,
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
                "mtu": 1500,
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
        store
            .repository()
            .put_go_node(&GoNodeRecord {
                id: "tun-fixed".to_owned(),
                name: "TUN fixed outbound".to_owned(),
                group_name: "rust-smoke".to_owned(),
                origin: "rust-smoke".to_owned(),
                enabled: true,
                chain_types_json: b"[\"fixed\"]".to_vec(),
                updated_at: 0,
                data_json: serde_json::to_vec(&json!({
                    "id":"tun-fixed",
                    "name":"TUN fixed outbound",
                    "group":"rust-smoke",
                    "origin":"rust-smoke",
                    "enabled":true,
                    "chain":[{"type":"fixed","fixed":{"host":"127.0.0.1","port":target_address.port()}}]
                }))
                .map_err(io_error)?,
            })
            .await?;
        store
            .put_config(
                "selected_tcp_node_v2",
                &serde_json::to_vec(&json!({"id":"tun-fixed"})).map_err(io_error)?,
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

fn run_tun_traffic_client() -> std::io::Result<()> {
    use std::io::{Read, Write};

    let address = "198.18.0.2:18080";
    let mut stream =
        TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_secs(10))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let payload = b"runtime-owned-tun-fixed-outbound";
    stream.write_all(payload)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed)?;
    if echoed != payload {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "runtime TUN fixed outbound echo mismatch",
        ));
    }
    Ok(())
}

fn io_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

fn join_error(error: tokio::task::JoinError) -> Error {
    io_error(error)
}
