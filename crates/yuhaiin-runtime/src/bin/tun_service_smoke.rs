//! Process-level Linux smoke test for the runtime-owned TUN inbound.
//!
//! This is deliberately a small host fixture rather than a second TUN
//! implementation. It writes one Go-shaped TUN inbound into SQLite, starts
//! the same `RuntimeController` and `inbound::run_until` used by the service,
//! waits for the kernel device, and then exercises the shared shutdown path.
//! The Podman wrapper runs it privileged with `--network=none` so a test does
//! not alter the host routing table.

use std::io::Cursor;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use yuhaiin_chain::{YuubinsyaH2Server, YuubinsyaServerProxy};
use yuhaiin_core::dns::{
    DnsRecordType, DnsResponse, decode_response, encode_query, encode_response,
};
use yuhaiin_core::dns_resolver::SystemAsyncIpResolver;
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream, DirectAsyncProxy};
use yuhaiin_core::{
    BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, IpSet, Network, Result,
    RouteMode,
};
use yuhaiin_runtime::{
    BuiltinResolverFactory, RuntimeBuildOptions, RuntimeBuilder, RuntimeController, inbound,
    load_tun_config,
};
use yuhaiin_store::{
    ConfigStore, GoInboundRecord, GoNodeRecord, GoResolverRecord, GoRouteSettingsRecord,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if std::env::args().nth(1).as_deref() == Some("--traffic-client") {
        let total_bytes = match std::env::var("YUHAIIN_TUN_TRAFFIC_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
        {
            Some(value) => value,
            None => {
                eprintln!("tun-service-smoke: traffic client has invalid byte count");
                std::process::exit(2);
            }
        };
        let connection_hold_ms = std::env::var("YUHAIIN_TUN_CONNECTION_HOLD_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_default();
        if let Err(error) = run_tun_traffic_client(total_bytes, connection_hold_ms) {
            eprintln!("tun-service-smoke: traffic client: {error}");
            std::process::exit(1);
        }
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("--udp-traffic-client") {
        let total_bytes = std::env::var("YUHAIIN_TUN_UDP_TRAFFIC_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(32);
        if let Err(error) = run_tun_udp_traffic_client(total_bytes) {
            eprintln!("tun-service-smoke: UDP traffic client: {error}");
            std::process::exit(1);
        }
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("--dns-client") {
        if let Err(error) = run_tun_dns_client() {
            eprintln!("tun-service-smoke: DNS client: {error}");
            std::process::exit(1);
        }
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("--ipv6-extension-client") {
        let total_bytes = std::env::var("YUHAIIN_TUN_UDP_TRAFFIC_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(32);
        if let Err(error) = run_tun_ipv6_extension_client(total_bytes) {
            eprintln!("tun-service-smoke: IPv6 extension client: {error}");
            std::process::exit(1);
        }
        return;
    }
    if std::env::args().nth(1).as_deref() == Some("--reset-client") {
        if let Err(error) = run_tun_reset_client() {
            eprintln!("tun-service-smoke: reset client: {error}");
            std::process::exit(1);
        }
        return;
    }
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
    let dns_test = std::env::var_os("YUHAIIN_TUN_DNS_TEST").is_some();
    let udp_traffic = std::env::var_os("YUHAIIN_TUN_UDP_TRAFFIC").is_some();
    let ipv6_extension = std::env::var_os("YUHAIIN_TUN_IPV6_EXTENSION").is_some();
    let udp_first = udp_traffic && std::env::var_os("YUHAIIN_TUN_UDP_FIRST").is_some();
    if udp_traffic && !traffic {
        return Err(Error::invalid(
            "YUHAIIN_TUN_UDP_TRAFFIC requires YUHAIIN_TUN_TRAFFIC",
        ));
    }
    if udp_traffic && chain_mode_is_set() {
        return Err(Error::invalid(
            "YUHAIIN_TUN_UDP_TRAFFIC is currently supported by the direct TUN fixture only",
        ));
    }
    if ipv6_extension && (!traffic || !udp_traffic) {
        return Err(Error::invalid(
            "YUHAIIN_TUN_IPV6_EXTENSION requires both YUHAIIN_TUN_TRAFFIC and YUHAIIN_TUN_UDP_TRAFFIC",
        ));
    }
    if ipv6_extension && udp_first {
        return Err(Error::invalid(
            "YUHAIIN_TUN_IPV6_EXTENSION cannot be combined with YUHAIIN_TUN_UDP_FIRST",
        ));
    }
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
    let udp_traffic_bytes = std::env::var("YUHAIIN_TUN_UDP_TRAFFIC_BYTES")
        .ok()
        .map(|value| {
            value.parse::<usize>().map_err(|_| {
                Error::invalid(format!(
                    "YUHAIIN_TUN_UDP_TRAFFIC_BYTES must be a positive integer, got {value:?}"
                ))
            })
        })
        .transpose()?
        .unwrap_or(8192);
    if udp_traffic_bytes == 0 || udp_traffic_bytes > 65_507 {
        return Err(Error::invalid(
            "YUHAIIN_TUN_UDP_TRAFFIC_BYTES must be between 1 and 65507",
        ));
    }
    let connection_hold_ms = std::env::var("YUHAIIN_TUN_CONNECTION_HOLD_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or_default();
    let assert_connections = std::env::var_os("YUHAIIN_TUN_ASSERT_CONNECTIONS").is_some();
    let assert_process = std::env::var_os("YUHAIIN_TUN_ASSERT_PROCESS").is_some();
    let reload_inbound = std::env::var_os("YUHAIIN_TUN_RELOAD").is_some();
    let reload_cycles = std::env::var("YUHAIIN_TUN_RELOAD_CYCLES")
        .ok()
        .map(|value| {
            value.parse::<usize>().map_err(|_| {
                Error::invalid(format!(
                    "YUHAIIN_TUN_RELOAD_CYCLES must be a positive integer, got {value:?}"
                ))
            })
        })
        .transpose()?
        .unwrap_or(1);
    if reload_cycles == 0 || reload_cycles > 32 {
        return Err(Error::invalid(
            "YUHAIIN_TUN_RELOAD_CYCLES must be between 1 and 32",
        ));
    }
    let chain_mode = std::env::var("YUHAIIN_TUN_CHAIN")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let reset_reconnect = std::env::var_os("YUHAIIN_TUN_RESET_RECONNECT").is_some();
    if reset_reconnect && chain_mode.is_some() {
        return Err(Error::invalid(
            "YUHAIIN_TUN_RESET_RECONNECT is only supported by the direct TUN fixture",
        ));
    }

    if dns_test && chain_mode.is_some() {
        return Err(Error::invalid(
            "YUHAIIN_TUN_DNS_TEST is only supported by the direct TUN fixture",
        ));
    }

    // `--network=none` creates the loopback device in a down state.  The
    // fixture's fixed outbound intentionally targets a local echo listener,
    // so bring only this disposable namespace's loopback interface up before
    // opening the TUN.  Production does not need this test-only setup.
    if traffic || dns_test {
        yuhaiin_tun::enable_loopback().map_err(io_error)?;
    }

    let (target_address, target_task, udp_target_task, chain_fixture) = if chain_mode.is_some() {
        if !traffic {
            return Err(Error::invalid(
                "YUHAIIN_TUN_CHAIN requires YUHAIIN_TUN_TRAFFIC",
            ));
        }
        let fixture = ChainFixture::start().await?;
        (Some(fixture.target), None, None, Some(fixture))
    } else if traffic {
        let target = TcpListener::bind("127.0.0.1:0").await.map_err(io_error)?;
        let address = target.local_addr().map_err(io_error)?;
        let udp_target = if udp_traffic {
            Some(
                tokio::net::UdpSocket::bind(SocketAddr::new(address.ip(), address.port()))
                    .await
                    .map_err(io_error)?,
            )
        } else {
            None
        };
        let udp_target_task = udp_target.map(|target| {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 65_507];
                let (length, peer) = target.recv_from(&mut buffer).await.map_err(io_error)?;
                println!("runtime-tun-udp-target-received bytes={length}");
                target
                    .send_to(&buffer[..length], peer)
                    .await
                    .map_err(io_error)?;
                Ok::<usize, Error>(length)
            })
        });
        let task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 16 * 1024];
            let mut received = 0usize;
            let expected_connections = 1 + usize::from(reset_reconnect);
            for connection_index in 0..expected_connections {
                let (mut stream, _) = target.accept().await.map_err(io_error)?;
                loop {
                    let length = match stream.read(&mut buffer).await {
                        Ok(length) => length,
                        Err(error)
                            if reset_reconnect
                                && error.kind() == std::io::ErrorKind::ConnectionReset =>
                        {
                            break;
                        }
                        Err(error) => return Err(io_error(error)),
                    };
                    if length == 0 {
                        break;
                    }
                    stream
                        .write_all(&buffer[..length])
                        .await
                        .map_err(io_error)?;
                    if !(reset_reconnect && connection_index == 0) {
                        received = received.saturating_add(length);
                    }
                }
            }
            Ok::<usize, Error>(received)
        });
        (Some(address), Some(task), udp_target_task, None)
    } else {
        (None, None, None, None)
    };

    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let store = ConfigStore::open(&database).await?;
    let (dns_upstream, dns_upstream_task) = if dns_test {
        let socket = UdpSocket::bind("127.0.0.1:0").await.map_err(io_error)?;
        let address = socket.local_addr().map_err(io_error)?;
        let task = tokio::spawn(async move {
            let answer = DnsResponse {
                addresses: IpSet {
                    v4: vec!["203.0.113.7".parse().expect("fixture IPv4")],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(60),
            };
            let mut packet = vec![0u8; 4096];
            loop {
                let Ok((length, peer)) = socket.recv_from(&mut packet).await else {
                    break;
                };
                let Ok(response) = encode_response(&packet[..length], &answer) else {
                    continue;
                };
                let _ = socket.send_to(&response, peer).await;
            }
        });
        (Some(address), Some(task))
    } else {
        (None, None)
    };
    seed_runtime_fixture(
        &store,
        &name,
        target_address,
        chain_fixture.as_ref().map(|fixture| fixture.outbound),
        chain_mode.as_deref(),
        mtu,
    )
    .await?;
    if let Some(address) = dns_upstream {
        // The fixture resolver is intentionally loopback-only. Keep this
        // local test independent from the host's physical interface while
        // the production default-interface policy is exercised by real
        // outbound endpoints.
        store
            .put_config("settings", br#"{"useDefaultInterface":false}"#)
            .await?;
        let resolver = GoResolverRecord {
            id: "bootstrap".to_owned(),
            resolver_type: "udp".to_owned(),
            host: address.to_string(),
            updated_at: 1,
            data_json: serde_json::to_vec(&json!({
                "id": "bootstrap",
                "type": "udp",
                "host": address.to_string(),
                "system": false
            }))
            .map_err(io_error)?,
        };
        store.repository().put_go_resolver(&resolver).await?;
        store
            .repository()
            .put_go_route_settings(&GoRouteSettingsRecord {
                id: 1,
                direct_resolver: "bootstrap".to_owned(),
                proxy_resolver: "bootstrap".to_owned(),
                resolve_locally: false,
                udp_proxy_fqdn: 0,
            })
            .await?;
        store
            .put_config(
                "resolver.fakedns",
                br#"{"enabled":true,"ipv4Range":"198.18.0.0/15","ipv6Range":"fc00::/18"}"#,
            )
            .await?;
        store
            .put_config(
                "inbounds.config",
                br#"{"hijackDns":true,"hijackDnsFakeIp":true,"sniff":true}"#,
            )
            .await?;
    }
    if udp_traffic && udp_traffic_bytes > 2048 {
        let settings = json!({
            "useDefaultInterface": false,
            "advanced": {"udpBufferSize": udp_traffic_bytes.min(65_534)}
        });
        let settings = serde_json::to_vec(&settings).map_err(io_error)?;
        store.put_config("settings", &settings).await?;
    }

    let mut build_options = RuntimeBuildOptions::default();
    build_options.route_fallback.mode = RouteMode::Proxy;
    let mut builder = RuntimeBuilder::new(store.clone(), Arc::new(SystemAsyncIpResolver))
        .with_options(build_options);
    if dns_test {
        builder = builder.with_resolver_factory(Arc::new(BuiltinResolverFactory::new(
            Duration::from_secs(2),
            4096,
        )));
    }
    let controller = RuntimeController::from_builder(builder).await?;
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
        configured_tun_target().map_err(io_error)?,
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
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let inbound_task =
        tokio::task::spawn_local(inbound::run_until(controller.clone(), shutdown_rx));
    eprintln!(
        "runtime-tun-opening name={device_name} database={}",
        database.display()
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    while !device_is_present(&device_name) {
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

    if dns_test {
        eprintln!("runtime-tun-dns-client-start");
        let executable = std::env::current_exe().map_err(io_error)?;
        let mut dns_client = std::process::Command::new(executable)
            .arg("--dns-client")
            .spawn()
            .map_err(io_error)?;
        let status = tokio::task::spawn_blocking(move || dns_client.wait())
            .await
            .map_err(join_error)?
            .map_err(io_error)?;
        if !status.success() {
            let _ = shutdown_tx.send(true);
            let _ = inbound_task.await;
            return Err(io_error(std::io::Error::other(format!(
                "TUN DNS client exited with {status}"
            ))));
        }
        println!("runtime-tun-dns-ok");
    }

    if ipv6_extension {
        eprintln!("runtime-tun-ipv6-extension-client-start bytes={udp_traffic_bytes}");
        run_tun_ipv6_extension_child(udp_traffic_bytes).await?;
        println!("runtime-tun-ipv6-extension-ok bytes={udp_traffic_bytes}");
    }

    if udp_first {
        eprintln!("runtime-tun-udp-client-start bytes={udp_traffic_bytes}");
        run_tun_udp_traffic_child(udp_traffic_bytes).await?;
        println!("runtime-tun-udp-traffic-ok bytes={udp_traffic_bytes}");
    }

    if reload_inbound {
        for cycle in 1..=reload_cycles {
            toggle_persisted_tun(&controller, &device_name, false).await?;
            println!("runtime-tun-disabled name={device_name} cycle={cycle}");
            if traffic {
                assert_tun_target_unreachable(&device_name, Duration::from_millis(750))
                    .map_err(io_error)?;
                println!("runtime-tun-disabled-no-route-ok name={device_name} cycle={cycle}");
            }
            toggle_persisted_tun(&controller, &device_name, true).await?;
            println!("runtime-tun-reload-ok name={device_name} cycle={cycle}");
        }
    }

    if traffic {
        let connection_assertion = if assert_connections {
            Some(spawn_tun_connection_assertion(
                controller.monitor(),
                selected.clone(),
                Duration::from_secs(10),
                assert_process,
            ))
        } else {
            None
        };
        // Keep the TUN client in a separate process. The runtime deliberately
        // blocks flows originating from its own resolved process path to avoid
        // routing its listener/control connections back through itself. A
        // child process is the same shape as a real application using the TUN
        // device and lets this smoke exercise that guard without disabling it.
        let executable = std::env::current_exe().map_err(io_error)?;
        if reset_reconnect {
            let mut reset_client = std::process::Command::new(&executable)
                .arg("--reset-client")
                .spawn()
                .map_err(io_error)?;
            let reset_status = tokio::task::spawn_blocking(move || reset_client.wait())
                .await
                .map_err(join_error)?
                .map_err(io_error)?;
            if !reset_status.success() {
                return Err(io_error(std::io::Error::other(format!(
                    "TUN reset client exited with {reset_status}"
                ))));
            }
            println!("runtime-tun-reset-ok");
        }
        let mut traffic_client = std::process::Command::new(executable)
            .arg("--traffic-client")
            .env("YUHAIIN_TUN_TRAFFIC_BYTES", traffic_bytes.to_string())
            .env(
                "YUHAIIN_TUN_CONNECTION_HOLD_MS",
                connection_hold_ms.to_string(),
            )
            .spawn()
            .map_err(io_error)?;
        let traffic_result = tokio::task::spawn_blocking(move || traffic_client.wait())
            .await
            .map_err(join_error)?
            .map_err(io_error)
            .and_then(|status| {
                if status.success() {
                    Ok(())
                } else {
                    Err(io_error(std::io::Error::other(format!(
                        "TUN traffic client exited with {status}"
                    ))))
                }
            });
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
            if let Some(udp_target_task) = udp_target_task {
                udp_target_task.abort();
                let _ = udp_target_task.await;
            }
            if let Some(chain_fixture) = chain_fixture {
                chain_fixture.abort();
            }
            return Err(error.clone());
        }
        if udp_traffic && !udp_first && !ipv6_extension {
            eprintln!("runtime-tun-udp-client-start bytes={udp_traffic_bytes}");
            if let Err(error) = run_tun_udp_traffic_child(udp_traffic_bytes).await {
                eprintln!(
                    "runtime-tun-logs {:?}",
                    controller.monitor().logs().snapshot()
                );
                return Err(error);
            }
            println!("runtime-tun-udp-traffic-ok bytes={udp_traffic_bytes}");
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
            if assert_process {
                let process = connection
                    .get("process")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| Error::new(ErrorKind::Io, "TUN process metadata is empty"))?;
                let pid = connection
                    .get("pid")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        Error::new(ErrorKind::Io, "TUN process PID metadata is empty")
                    })?;
                let uid = connection
                    .get("uid")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        Error::new(ErrorKind::Io, "TUN process UID metadata is empty")
                    })?;
                println!("runtime-tun-process-ok process={process} pid={pid} uid={uid}");
            }
        }
        println!("runtime-tun-traffic-ok bytes={traffic_bytes}");
        if reset_reconnect {
            println!("runtime-tun-reconnect-ok");
        }
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
    if let Some(udp_target_task) = udp_target_task {
        let received = udp_target_task.await.map_err(join_error)??;
        if received != udp_traffic_bytes {
            return Err(Error::new(
                ErrorKind::Io,
                format!("runtime TUN UDP target received {received} of {udp_traffic_bytes} bytes"),
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

    if let Some(task) = dns_upstream_task {
        task.abort();
    }

    wait_for_tun_state(&device_name, false).await?;
    println!("runtime-tun-closed name={device_name}");
    Ok(())
}

fn run_tun_dns_client() -> std::io::Result<()> {
    use std::net::UdpSocket;

    let target = match std::env::var("YUHAIIN_TUN_DNS_TARGET") {
        Ok(value) => value.parse().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid YUHAIIN_TUN_DNS_TARGET: {error}"),
            )
        })?,
        Err(_) => {
            let configured = configured_tun_target()?;
            SocketAddr::new(configured.ip(), 53)
        }
    };
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;
    let domain = DomainName::new("tun-fakeip.example.test")
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let query = encode_query(0x5455, &domain, DnsRecordType::A)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    socket.send_to(&query, target)?;
    let mut response = vec![0u8; 4096];
    let length = socket.recv(&mut response)?;
    let response = decode_response(&response[..length], 0x5455, DnsRecordType::A)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let address = response.addresses.v4.first().copied().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "TUN DNS response did not contain an IPv4 address",
        )
    })?;
    let octets = address.octets();
    if octets[0] != 198 || octets[1] != 18 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("TUN DNS response was not FakeIP: {address}"),
        ));
    }
    println!("runtime-tun-dns-address={address}");
    Ok(())
}

fn chain_mode_is_set() -> bool {
    std::env::var("YUHAIIN_TUN_CHAIN")
        .ok()
        .is_some_and(|value| !value.trim().is_empty())
}

async fn toggle_persisted_tun(
    controller: &RuntimeController,
    device_name: &str,
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
        .mutate_and_reload_inbounds(move |store| async move {
            store.repository().put_go_inbound(&record).await
        })
        .await?;

    wait_for_tun_state(device_name, enabled).await
}

/// `/sys/class/net` is not guaranteed to expose the current network
/// namespace after entering an unshared user/network namespace.  `/proc/net/dev`
/// is namespace-aware and is the primary probe; sysfs remains a fallback for
/// normal containers and desktop hosts.
fn device_is_present(name: &str) -> bool {
    if std::fs::read_to_string("/proc/net/dev")
        .ok()
        .is_some_and(|contents| {
            contents.lines().any(|line| {
                line.split_once(':')
                    .is_some_and(|(interface, _)| interface.trim() == name)
            })
        })
    {
        return true;
    }
    Path::new("/sys/class/net").join(name).exists()
}

fn route_uses_device(name: &str, target: SocketAddr) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(output) = std::process::Command::new("ip")
            .args(["route", "get", &target.ip().to_string()])
            .output()
        else {
            return false;
        };
        if !output.status.success() {
            return false;
        }
        let route = String::from_utf8_lossy(&output.stdout);
        route
            .split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|parts| parts == ["dev", name])
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (name, target);
        false
    }
}

async fn wait_for_tun_state(device_name: &str, enabled: bool) -> Result<()> {
    let target = configured_tun_target().map_err(io_error)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let present = device_is_present(device_name);
        let route_present = !enabled && route_uses_device(device_name, target);
        if present == enabled && !route_present {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::new(
                ErrorKind::Timeout,
                format!(
                    "TUN state did not reach enabled={enabled} for {} (device_present={}, route_present={})",
                    device_name, present, route_present
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
                "portal": configured_tun_portal(),
                "portalV6": configured_tun_portal_v6(),
                "routes": configured_tun_routes(),
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
        store
            .put_config(
                "selected_udp_node_v2",
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
        store
            .put_config(
                "selected_udp_node_v2",
                &serde_json::to_vec(&json!({"id":"direct"})).map_err(io_error)?,
            )
            .await?;
    }
    Ok(())
}

fn assert_tun_target_unreachable(device_name: &str, timeout: Duration) -> std::io::Result<()> {
    let address = configured_tun_target()?;
    let deadline = Instant::now() + timeout;
    loop {
        if device_is_present(device_name) || route_uses_device(device_name, address) {
            if Instant::now() >= deadline {
                return Err(std::io::Error::other(format!(
                    "TUN device or route for {address} remained while the inbound was disabled"
                )));
            }
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        return Ok(());
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
    assert_process: bool,
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
                    && (!assert_process
                        || (connection
                            .get("process")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|value| !value.is_empty())
                            && connection
                                .get("pid")
                                .and_then(serde_json::Value::as_str)
                                .is_some_and(|value| !value.is_empty())
                            && connection
                                .get("uid")
                                .and_then(serde_json::Value::as_str)
                                .is_some_and(|value| !value.is_empty())))
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

    let address = configured_tun_target()?;
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(10)).map_err(|error| {
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

fn run_tun_udp_traffic_client(total_bytes: usize) -> std::io::Result<()> {
    let source = configured_tun_source()?;
    let socket = std::net::UdpSocket::bind(SocketAddr::new(source, 0))?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    let destination = configured_tun_udp_target()?;
    eprintln!(
        "runtime-tun-udp-client local={} destination={destination}",
        socket.local_addr()?
    );
    let mut payload = vec![0u8; total_bytes];
    fill_traffic_chunk(&mut payload, 0);
    let sent = socket.send_to(&payload, destination).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("write TUN UDP traffic payload to {destination}: {error}"),
        )
    })?;
    eprintln!("runtime-tun-udp-client-sent bytes={sent}");
    let mut echoed = vec![0u8; 65_507];
    let (length, _) = socket.recv_from(&mut echoed).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("read TUN UDP traffic echo from {destination}: {error}"),
        )
    })?;
    if length != total_bytes || echoed[..length] != payload {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("runtime TUN UDP echo mismatch: received {length} of {total_bytes} bytes"),
        ));
    }
    Ok(())
}

async fn run_tun_ipv6_extension_child(total_bytes: usize) -> Result<()> {
    let executable = std::env::current_exe().map_err(io_error)?;
    let mut child = std::process::Command::new(executable)
        .arg("--ipv6-extension-client")
        .env("YUHAIIN_TUN_UDP_TRAFFIC_BYTES", total_bytes.to_string())
        .spawn()
        .map_err(io_error)?;
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .map_err(join_error)?
        .map_err(io_error)?;
    if status.success() {
        Ok(())
    } else {
        Err(io_error(std::io::Error::other(format!(
            "TUN IPv6 extension client exited with {status}"
        ))))
    }
}

fn run_tun_ipv6_extension_client(total_bytes: usize) -> std::io::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = total_bytes;
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "raw IPv6 extension smoke is only available on Linux",
        ));
    }

    #[cfg(target_os = "linux")]
    {
        use socket2::{Domain, Protocol, SockAddr, Socket, Type};

        let source = configured_tun_ipv6_source()?;
        let target = configured_tun_ipv6_target()?;
        let source_port = 41_000;
        let receiver = std::net::UdpSocket::bind(SocketAddrV6::new(source, source_port, 0, 0))?;
        receiver.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut payload = vec![0u8; total_bytes];
        fill_traffic_chunk(&mut payload, 0);
        let packet = build_ipv6_extension_udp_packet(
            source,
            *target.ip(),
            source_port,
            target.port(),
            &payload,
        );
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::from(255)))?;
        socket.set_header_included_v6(true)?;
        // Raw IPv6 sockets do not accept a transport port in sockaddr_in6;
        // the UDP destination port is carried by the packet header above.
        let route_target = SocketAddrV6::new(*target.ip(), 0, target.flowinfo(), target.scope_id());
        let sent = socket.send_to(&packet, &SockAddr::from(route_target))?;
        if sent != packet.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                format!(
                    "raw IPv6 extension packet was truncated: sent {sent} of {}",
                    packet.len()
                ),
            ));
        }
        let mut echoed = vec![0u8; 65_507];
        let (length, peer) = receiver.recv_from(&mut echoed).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("read raw IPv6 extension echo from {target}: {error}"),
            )
        })?;
        if length != total_bytes || echoed[..length] != payload {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "raw IPv6 extension echo mismatch from {peer}: received {length} of {total_bytes} bytes"
                ),
            ));
        }
        eprintln!(
            "runtime-tun-ipv6-extension-client-roundtrip bytes={} source={source} destination={target}",
            payload.len(),
        );
        Ok(())
    }
}

fn build_ipv6_extension_udp_packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let extension_len = 16;
    let mut packet = vec![0u8; 40 + extension_len + udp_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(u16::try_from(extension_len + udp_len).unwrap()).to_be_bytes());
    packet[6] = 0; // Hop-by-Hop Options
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());

    // Two eight-byte extension headers. All option bytes are Pad1, which is
    // valid and keeps this fixture focused on extension-header traversal.
    packet[40] = 60; // Destination Options follows Hop-by-Hop Options.
    packet[48] = 17; // UDP follows Destination Options.

    let udp_offset = 56;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&source_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&destination_port.to_be_bytes());
    packet[udp_offset + 4..udp_offset + 6]
        .copy_from_slice(&(u16::try_from(udp_len).unwrap()).to_be_bytes());
    packet[udp_offset + 8..].copy_from_slice(payload);

    let checksum = ipv6_udp_checksum(source, destination, &packet[udp_offset..]);
    packet[udp_offset + 6..udp_offset + 8].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn ipv6_udp_checksum(source: Ipv6Addr, destination: Ipv6Addr, udp_packet: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(40 + udp_packet.len());
    pseudo_header.extend_from_slice(&source.octets());
    pseudo_header.extend_from_slice(&destination.octets());
    pseudo_header.extend_from_slice(&(u32::try_from(udp_packet.len()).unwrap()).to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, 17]);
    pseudo_header.extend_from_slice(udp_packet);
    internet_checksum(&pseudo_header)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in bytes.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let Some(&byte) = bytes.chunks_exact(2).remainder().first() {
        sum += u32::from(byte) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

async fn run_tun_udp_traffic_child(total_bytes: usize) -> Result<()> {
    let executable = std::env::current_exe().map_err(io_error)?;
    let mut child = std::process::Command::new(executable)
        .arg("--udp-traffic-client")
        .env("YUHAIIN_TUN_UDP_TRAFFIC_BYTES", total_bytes.to_string())
        .spawn()
        .map_err(io_error)?;
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .map_err(join_error)?
        .map_err(io_error)?;
    if status.success() {
        Ok(())
    } else {
        Err(io_error(std::io::Error::other(format!(
            "TUN UDP traffic client exited with {status}"
        ))))
    }
}

fn run_tun_reset_client() -> std::io::Result<()> {
    use std::io::Write;

    let address = configured_tun_target()?;
    let stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(10)).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("connect TUN reset target {address}: {error}"),
            )
        })?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let socket = socket2::SockRef::from(&stream);
    socket.set_linger(Some(Duration::ZERO))?;
    let mut stream = stream;
    stream.write_all(b"tun-reset-before-reconnect")?;
    // SO_LINGER=0 makes the close send RST, exercising the inbound's
    // connection-task cleanup before the normal reconnect below.
    drop(stream);
    Ok(())
}

fn configured_tun_portal() -> String {
    std::env::var("YUHAIIN_TUN_PORTAL").unwrap_or_else(|_| "198.18.0.1/15".to_owned())
}

fn configured_tun_portal_v6() -> Option<String> {
    std::env::var("YUHAIIN_TUN_PORTAL_V6")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn configured_tun_routes() -> Vec<String> {
    match std::env::var("YUHAIIN_TUN_ROUTE") {
        Ok(value) if value.eq_ignore_ascii_case("none") || value.trim().is_empty() => Vec::new(),
        Ok(value) => vec![value],
        Err(_) => vec!["198.18.0.2/32".to_owned()],
    }
}

fn configured_tun_source() -> std::io::Result<std::net::IpAddr> {
    std::env::var("YUHAIIN_TUN_SOURCE")
        .unwrap_or_else(|_| "198.18.0.1".to_owned())
        .parse()
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid YUHAIIN_TUN_SOURCE: {error}"),
            )
        })
}

fn configured_tun_ipv6_source() -> std::io::Result<Ipv6Addr> {
    std::env::var("YUHAIIN_TUN_IPV6_SOURCE")
        .unwrap_or_else(|_| "fd00:253::1".to_owned())
        .parse()
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid YUHAIIN_TUN_IPV6_SOURCE: {error}"),
            )
        })
}

fn configured_tun_target() -> std::io::Result<SocketAddr> {
    std::env::var("YUHAIIN_TUN_TARGET")
        .unwrap_or_else(|_| "198.18.0.2:18080".to_owned())
        .parse()
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid YUHAIIN_TUN_TARGET: {error}"),
            )
        })
}

fn configured_tun_udp_target() -> std::io::Result<SocketAddr> {
    std::env::var("YUHAIIN_TUN_UDP_TARGET").map_or_else(
        |_| configured_tun_target(),
        |value| {
            value.parse().map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid YUHAIIN_TUN_UDP_TARGET: {error}"),
                )
            })
        },
    )
}

fn configured_tun_ipv6_target() -> std::io::Result<SocketAddrV6> {
    let value = std::env::var("YUHAIIN_TUN_IPV6_TARGET")
        .unwrap_or_else(|_| "[fd00:253::2]:18080".to_owned());
    value.parse().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid YUHAIIN_TUN_IPV6_TARGET: {error}"),
        )
    })
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
            yuhaiin_protocol::yuubinsya::derive_salt(YUUBINSYA_PASSWORD.as_bytes()),
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
    let provider = Arc::new(rustls::crypto::ring::default_provider());
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

#[cfg(test)]
mod ipv6_extension_packet_tests {
    use super::*;

    #[test]
    fn builds_two_extension_headers_before_udp() {
        let source = "fd00:253::1".parse().unwrap();
        let destination = "fd00:253::2".parse().unwrap();
        let packet = build_ipv6_extension_udp_packet(source, destination, 41_000, 18_080, b"hello");

        assert_eq!(packet.len(), 40 + 16 + 8 + 5);
        assert_eq!(packet[6], 0);
        assert_eq!(packet[40..42], [60, 0]);
        assert_eq!(packet[48..50], [17, 0]);
        assert_eq!(u16::from_be_bytes([packet[56], packet[57]]), 41_000);
        assert_eq!(u16::from_be_bytes([packet[58], packet[59]]), 18_080);
        assert_eq!(u16::from_be_bytes([packet[60], packet[61]]), 13);
        assert_eq!(ipv6_udp_checksum(source, destination, &packet[56..]), 0);
    }

    #[test]
    fn checksum_handles_odd_length_payloads() {
        let source = "fd00:253::1".parse().unwrap();
        let destination = "fd00:253::2".parse().unwrap();
        let packet = build_ipv6_extension_udp_packet(source, destination, 1, 2, b"odd");

        assert_eq!(ipv6_udp_checksum(source, destination, &packet[56..]), 0);
    }
}
