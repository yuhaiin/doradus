//! Process-level Linux smoke test for the runtime-owned TUN inbound.
//!
//! This is deliberately a small host fixture rather than a second TUN
//! implementation. It writes one Go-shaped TUN inbound into SQLite, starts
//! the same `RuntimeController` and `inbound::run_until` used by the service,
//! waits for the kernel device, and then exercises the shared shutdown path.
//! The Podman wrapper runs it privileged with `--network=none` so a test does
//! not alter the host routing table.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::sync::watch;

use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
use yuhaiin_core::{Error, ErrorKind, Result};
use yuhaiin_runtime::{RuntimeBuilder, RuntimeController, inbound, load_tun_config};
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

    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let store = ConfigStore::open(&database).await?;
    seed_runtime_fixture(&store, &name).await?;

    let controller = RuntimeController::from_builder(RuntimeBuilder::new(
        store.clone(),
        Arc::new(SystemAsyncIpResolver),
    ))
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

    tokio::time::sleep(Duration::from_millis(hold_ms)).await;
    shutdown_tx
        .send(true)
        .map_err(|_| Error::new(ErrorKind::Closed, "TUN shutdown receiver closed"))?;
    inbound_task.await.map_err(join_error)??;
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

async fn seed_runtime_fixture(store: &ConfigStore, name: &str) -> Result<()> {
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
                "routes": [],
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
        .await
}

fn io_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

fn join_error(error: tokio::task::JoinError) -> Error {
    io_error(error)
}
