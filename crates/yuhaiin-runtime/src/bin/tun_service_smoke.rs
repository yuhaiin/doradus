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

#[path = "tun_service_smoke/clients.rs"]
mod clients;
use clients::{
    assert_tun_target_unreachable, run_tun_dns_client, run_tun_ipv6_extension_child,
    run_tun_ipv6_extension_client, run_tun_reset_client, run_tun_traffic_client,
    run_tun_udp_traffic_child, run_tun_udp_traffic_client, spawn_tun_connection_assertion,
};
#[cfg(test)]
use clients::{build_ipv6_extension_udp_packet, ipv6_udp_checksum};

#[path = "tun_service_smoke/config.rs"]
mod config;
use config::{
    chain_mode_is_set, configured_tun_ipv6_source, configured_tun_ipv6_target,
    configured_tun_portal, configured_tun_portal_v6, configured_tun_routes, configured_tun_source,
    configured_tun_target, configured_tun_udp_target,
};

#[path = "tun_service_smoke/chain.rs"]
mod chain_fixture;
use chain_fixture::{ChainFixture, YUUBINSYA_PASSWORD};

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
