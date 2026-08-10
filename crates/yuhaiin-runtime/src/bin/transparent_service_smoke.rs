//! Process-level Linux smoke test for the transparent inbound owner.
//!
//! The surrounding script installs an isolated-namespace REDIRECT rule.  The
//! client runs as `nobody`, while the runtime and its direct outbound run as
//! root, so the outbound connection is not redirected back into the inbound.
//! This exercises the same `inbound::run_until` and selector path as the
//! service, including `SO_ORIGINAL_DST`, route selection, relay accounting,
//! and shutdown.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;

#[cfg(target_os = "linux")]
use nix::sys::socket::{setsockopt, sockopt};
#[cfg(target_os = "linux")]
use socket2::{Domain, Protocol, Socket, Type};
use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
use yuhaiin_core::{Error, ErrorKind, Result, RouteMode};
use yuhaiin_runtime::{RuntimeBuildOptions, RuntimeBuilder, RuntimeController, inbound};
use yuhaiin_store::{ConfigStore, GoInboundRecord, GoNodeRecord};

const PAYLOAD: &[u8] = b"transparent-redir-service-smoke";
const TCP_PAYLOADS: [&[u8]; 2] = [PAYLOAD, b"transparent-redir-service-second-flow"];
const UDP_PAYLOADS: [&[u8]; 2] = [
    b"transparent-tproxy-udp-flow-a",
    b"transparent-tproxy-udp-flow-b",
];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let result = tokio::task::LocalSet::new().run_until(run()).await;
    if let Err(error) = result {
        eprintln!("transparent-service-smoke: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    if std::env::args().any(|argument| argument == "--tproxy-probe") {
        return run_tproxy_probe().map_err(io_error);
    }
    if std::env::args().any(|argument| argument == "--client") {
        return run_client().map_err(io_error);
    }
    if std::env::args().any(|argument| argument == "--udp-client") {
        return run_udp_client().map_err(io_error);
    }
    if std::env::args().any(|argument| argument == "--udp-target") {
        return run_udp_target().await;
    }

    let database = std::env::var_os("YUHAIIN_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(".")),
            )
            .join(".cache/yuhaiin-rust/integration/transparent-service/state.sqlite")
        });
    let target = parse_addr_env("YUHAIIN_TARGET_ADDR", "127.0.0.2:18080")?;
    let udp_target = parse_addr_env("YUHAIIN_UDP_TARGET_ADDR", "127.0.0.2:18082")?;
    let redir = parse_addr_env("YUHAIIN_REDIR_ADDR", "127.0.0.1:18081")?;
    let tproxy = parse_addr_env("YUHAIIN_TPROXY_ADDR", "127.0.0.1:18083")?;
    let tproxy_enabled = std::env::var("YUHAIIN_TPROXY_ENABLED")
        .map(|value| value != "0")
        .unwrap_or(true);
    let done_file = std::env::var_os("YUHAIIN_CLIENT_DONE")
        .map(PathBuf::from)
        .unwrap_or_else(|| database.with_file_name("client.done"));
    let udp_done_file = std::env::var_os("YUHAIIN_UDP_CLIENT_DONE")
        .map(PathBuf::from)
        .unwrap_or_else(|| database.with_file_name("udp-client.done"));

    let target_listener = TcpListener::bind(target).await.map_err(io_error)?;
    let target_task = tokio::spawn(async move {
        let mut received = Vec::with_capacity(TCP_PAYLOADS.len());
        for _ in TCP_PAYLOADS {
            let (mut stream, _) = target_listener.accept().await.map_err(io_error)?;
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.map_err(io_error)?;
            stream.write_all(&payload).await.map_err(io_error)?;
            received.push(payload);
        }
        Ok::<Vec<Vec<u8>>, Error>(received)
    });

    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    if let Some(parent) = done_file.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let _ = std::fs::remove_file(&done_file);
    let _ = std::fs::remove_file(&udp_done_file);
    let store = ConfigStore::open(&database).await?;
    seed_fixture(&store, redir, tproxy_enabled.then_some(tproxy)).await?;

    let mut build_options = RuntimeBuildOptions::default();
    build_options.route_fallback.mode = RouteMode::Proxy;
    let controller = RuntimeController::from_builder(
        RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver)).with_options(build_options),
    )
    .await?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let service = tokio::task::spawn_local(inbound::run_until(controller.clone(), shutdown_rx));
    if tproxy_enabled {
        println!(
            "transparent-ready redir={} tproxy_udp={} target={} udp_target={} database={}",
            redir,
            tproxy,
            target,
            udp_target,
            database.display()
        );
    } else {
        println!(
            "transparent-ready redir={} tproxy_udp=disabled target={} database={}",
            redir,
            target,
            database.display()
        );
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !done_file.exists() || (tproxy_enabled && !udp_done_file.exists()) {
        if service.is_finished() {
            let result = service.await.map_err(join_error)?;
            return Err(result.err().unwrap_or_else(|| {
                Error::new(
                    ErrorKind::Io,
                    "transparent inbound stopped before client completed",
                )
            }));
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = shutdown_tx.send(true);
            let _ = service.await;
            target_task.abort();
            let _ = target_task.await;
            return Err(Error::new(
                ErrorKind::Timeout,
                "transparent client did not complete before timeout",
            ));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let total = controller.monitor().total_flow_value();
    let connections = controller.monitor().connections_value();
    let udp_connections = connections
        .get("connections")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| item.pointer("/network/connType") == Some(&json!("udp")))
                .count()
        })
        .unwrap_or_default();
    println!("transparent-monitor-connections {connections}");
    println!(
        "transparent-monitor-logs {:?}",
        controller.monitor().logs().snapshot()
    );
    let download = total
        .get("download")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default();
    let upload = total
        .get("upload")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default();
    if download == 0 || upload == 0 || (tproxy_enabled && udp_connections < UDP_PAYLOADS.len()) {
        let _ = shutdown_tx.send(true);
        let _ = service.await;
        target_task.abort();
        let _ = target_task.await;
        return Err(Error::new(
            ErrorKind::Io,
            format!(
                "transparent flow statistics incomplete: total={total} udp_connections={udp_connections}"
            ),
        ));
    }

    shutdown_tx
        .send(true)
        .map_err(|_| Error::new(ErrorKind::Closed, "transparent shutdown receiver closed"))?;
    service.await.map_err(join_error)??;
    let received = target_task.await.map_err(join_error)??;
    if received.len() != TCP_PAYLOADS.len()
        || received
            .iter()
            .zip(TCP_PAYLOADS)
            .any(|(received, expected)| received != expected)
    {
        return Err(Error::new(
            ErrorKind::Io,
            format!(
                "transparent outbound payload mismatch: received {} flows",
                received.len(),
            ),
        ));
    }
    controller.persist_monitor().await?;
    println!(
        "transparent-redir-tcp-ok flows={} bytes={} upload={} download={}",
        received.len(),
        received.iter().map(Vec::len).sum::<usize>(),
        upload,
        download
    );
    if tproxy_enabled {
        println!(
            "transparent-tproxy-udp-ok flows={} packets={}",
            udp_connections,
            UDP_PAYLOADS.len()
        );
    } else {
        println!("transparent-tproxy-udp-skipped reason=cap-net-admin");
    }
    println!("transparent-closed");
    Ok(())
}

async fn seed_fixture(
    store: &ConfigStore,
    redir: SocketAddr,
    tproxy: Option<SocketAddr>,
) -> Result<()> {
    store
        .repository()
        .put_go_node(&GoNodeRecord {
            id: "direct".to_owned(),
            name: "Direct".to_owned(),
            group_name: "builtin".to_owned(),
            origin: "rust-transparent-smoke".to_owned(),
            enabled: true,
            chain_types_json: br##"["direct"]"##.to_vec(),
            updated_at: 0,
            data_json: br##"{"id":"direct","name":"Direct","group":"builtin","origin":"rust-transparent-smoke","enabled":true,"protocol":"direct","chain":[{"type":"direct","direct":{}}]}"##.to_vec(),
        })
        .await?;
    store
        .put_config(
            "selected_tcp_node_v2",
            &serde_json::to_vec(&json!({"id":"direct"})).map_err(io_error)?,
        )
        .await?;

    let data = json!({
        "id":"transparent-service-smoke",
        "name":"transparent-service-smoke",
        "enabled":true,
        "network":{"type":"empty","empty":{}},
        "transports":[],
        "protocol":{"type":"redir","redir":{"host":redir.to_string()}}
    });
    store
        .repository()
        .put_go_inbound(&GoInboundRecord {
            id: "transparent-service-smoke".to_owned(),
            name: "transparent-service-smoke".to_owned(),
            enabled: true,
            network_type: "empty".to_owned(),
            protocol_type: "redir".to_owned(),
            transport_types_json: br"[]".to_vec(),
            updated_at: 0,
            data_json: serde_json::to_vec(&data).map_err(io_error)?,
        })
        .await?;
    if let Some(tproxy) = tproxy {
        let data = json!({
            "id":"transparent-tproxy-udp-smoke",
            "name":"transparent-tproxy-udp-smoke",
            "enabled":true,
            "network":{"type":"empty","empty":{}},
            "transports":[],
            "protocol":{"type":"tproxy","tproxy":{"host":tproxy.to_string()}}
        });
        store
            .repository()
            .put_go_inbound(&GoInboundRecord {
                id: "transparent-tproxy-udp-smoke".to_owned(),
                name: "transparent-tproxy-udp-smoke".to_owned(),
                enabled: true,
                network_type: "empty".to_owned(),
                protocol_type: "tproxy".to_owned(),
                transport_types_json: br"[]".to_vec(),
                updated_at: 0,
                data_json: serde_json::to_vec(&data).map_err(io_error)?,
            })
            .await?;
    }
    Ok(())
}

fn run_client() -> std::io::Result<()> {
    let target = std::env::var("YUHAIIN_TARGET_ADDR")
        .unwrap_or_else(|_| "127.0.0.2:18080".to_owned())
        .parse::<SocketAddr>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    for payload in TCP_PAYLOADS {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match TcpStream::connect_timeout(&target, Duration::from_millis(200)) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(error),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(payload)?;
        stream.shutdown(Shutdown::Write)?;
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed)?;
        if echoed != *payload {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "transparent echo payload mismatch",
            ));
        }
    }
    println!("transparent-client-ok flows={}", TCP_PAYLOADS.len());
    Ok(())
}

async fn run_udp_target() -> Result<()> {
    let target = parse_addr_env("YUHAIIN_UDP_TARGET_ADDR", "10.253.0.4:18082")?;
    let socket = UdpSocket::bind(target).await.map_err(io_error)?;
    println!("transparent-udp-target-ready target={target}");
    let mut payload = vec![0u8; 2048];
    loop {
        let (length, peer) = socket.recv_from(&mut payload).await.map_err(io_error)?;
        socket
            .send_to(&payload[..length], peer)
            .await
            .map_err(io_error)?;
    }
}

fn run_udp_client() -> std::io::Result<()> {
    let target = std::env::var("YUHAIIN_UDP_TARGET_ADDR")
        .unwrap_or_else(|_| "10.253.0.4:18082".to_owned())
        .parse::<SocketAddr>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    for payload in UDP_PAYLOADS {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let mut echoed = [0u8; 2048];
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            socket.send_to(payload, target)?;
            match socket.recv_from(&mut echoed) {
                Ok((length, _)) if &echoed[..length] == payload => break,
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "transparent UDP echo payload mismatch",
                    ));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) && Instant::now() < deadline => {}
                Err(error) => return Err(error),
            }
        }
    }
    println!("transparent-udp-client-ok flows={}", UDP_PAYLOADS.len());
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_tproxy_probe() -> std::io::Result<()> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_ip_transparent_v4(true)?;
    setsockopt(&socket, sockopt::Ipv4OrigDstAddr, &true)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    socket.bind(&"0.0.0.0:0".parse::<SocketAddr>().unwrap().into())?;
    println!("transparent-tproxy-socket-ok");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_tproxy_probe() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "TPROXY socket probe is Linux-only",
    ))
}

fn parse_addr_env(name: &str, default: &str) -> Result<SocketAddr> {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_owned())
        .parse()
        .map_err(|error| Error::invalid(format!("{name} is not a socket address: {error}")))
}

fn io_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

fn join_error(error: tokio::task::JoinError) -> Error {
    Error::new(
        ErrorKind::Io,
        format!("transparent task join failed: {error}"),
    )
}
