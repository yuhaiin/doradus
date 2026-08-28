//! TUN and DNS supervisors.

use super::*;

/// Run one already-created TUN device through the shared runtime snapshot.
/// The caller owns device creation and can therefore inject a mobile VPN fd;
/// this function owns dispatcher, proxy runtime, inbound input policy and
/// shutdown ordering only.
#[cfg(feature = "tun")]
pub async fn run_tun_device_until(
    controller: RuntimeController,
    tun: doradus_tun::TunRuntime,
    config: TunRuntimeConfig,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut tun = tun;
    run_tun_device_until_ref(controller, &mut tun, config, shutdown).await
}

/// Run a previously-created TUN device without taking ownership of it.
///
/// The reference form is used by mobile inbound supervisors: a VPN host owns
/// the fd-backed device for the lifetime of the service, while this function
/// can return at a configuration reload so the proxy runtime and dispatcher
/// are rebuilt from the new immutable snapshot. The device itself remains
/// open and is reused on the next iteration.
#[cfg(feature = "tun")]
pub async fn run_tun_device_until_ref(
    controller: RuntimeController,
    tun: &mut doradus_tun::TunRuntime,
    config: TunRuntimeConfig,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if !config.enabled {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "TUN runtime is disabled",
        ));
    }
    let (tcp_proxy_id, udp_proxy_id) = match config.proxy_id.clone() {
        Some(proxy_id) if !proxy_id.trim().is_empty() => (proxy_id.clone(), proxy_id),
        _ => crate::inbound::selected_proxy_ids(&controller).await?,
    };
    let mut proxy_runtime = controller
        .build_tun_proxy_runtime_with_dns_and_udp(
            &config.direct_id,
            &tcp_proxy_id,
            &udp_proxy_id,
            &config.bypass_id,
            &config.drop_id,
            // Go's inbound handler bounds proxy setup with configuration.Timeout
            // (16 seconds); the established TCP stream has no read idle deadline.
            Duration::from_secs(16),
            config.channel_capacity,
            None,
        )
        .await?;
    let inbound_id = config
        .inbound_id
        .clone()
        .or_else(|| config.tun.name.clone())
        .or_else(|| Some("tun".to_owned()));
    proxy_runtime.set_context_provider(move |flow| {
        let mut context = flow.context();
        context.inbound_id = inbound_id.clone();
        context
    });
    let mut inbound_interceptor =
        crate::inbound::InboundInputInterceptor::new(controller.monitor(), config.channel_capacity);
    controller.monitor().info("TUN inbound ready");
    let mut dispatcher = doradus_tun::TunDispatcher::new(
        config.socket_rx_buffer_size,
        config.socket_tx_buffer_size,
        config.udp_packet_capacity,
    )?
    .with_skip_multicast(config.tun.skip_multicast);
    let result = tun
        .run_dispatcher_until(
            &mut dispatcher,
            &mut proxy_runtime,
            Some(&mut inbound_interceptor),
            async {
                let _ = wait_for_shutdown_or_matching_inbound_reload(
                    &controller,
                    shutdown.clone(),
                    config.inbound_id.as_deref(),
                )
                .await;
            },
        )
        .await
        .map_err(io_error);
    if let Err(error) = &result {
        controller
            .monitor()
            .error(format!("TUN dispatcher stopped: {error}"));
    }
    result?;
    if *shutdown.borrow() {
        return Ok(());
    }
    Ok(())
}

/// Run the optional UDP and TCP DNS listeners with the same reload and
/// shutdown owner used by the executable service. Go exposes both transports
/// on the configured address, and clients commonly fall back to TCP when a
/// UDP response is truncated.
pub async fn run_dns_supervisor(
    controller: RuntimeController,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        // A reload and process shutdown can become ready at the same time.
        // Do not start another bind cycle after shutdown has already won.
        if *shutdown.borrow() {
            return Ok(());
        }
        let server = configured_dns_server(controller.store()).await?;
        let Some(server) = server else {
            if wait_for_shutdown_or_dns_reload(&controller, shutdown.clone()).await {
                return Ok(());
            }
            continue;
        };
        if *shutdown.borrow() {
            return Ok(());
        }
        let address = parse_dns_server(&server, 53, "api-dns")?;
        let snapshot = controller.handle().load();
        let handler = LoggedDnsHandler {
            inner: (*controller.dns_handler()).clone(),
            monitor: controller.monitor(),
        };
        // UDP and TCP are independent listeners in the Go server. A stale
        // process, another service, or a partial reload may occupy either
        // one, so keep the available transport alive instead of terminating
        // the whole DNS supervisor on the first bind error.
        let udp = match doradus_core::dns::AsyncUdpDnsServer::bind(
            address,
            handler.clone(),
            snapshot.settings.udp_buffer_size.max(512),
        )
        .await
        {
            Ok(server) => Some(server),
            Err(error) => {
                controller.monitor().warn(format!(
                    "DNS UDP listener unavailable on {address}: {error}"
                ));
                None
            }
        };
        let tcp =
            match AsyncTcpDnsServer::bind(address, handler, 65535, Duration::from_secs(5)).await {
                Ok(server) => Some(server),
                Err(error) => {
                    controller.monitor().warn(format!(
                        "DNS TCP listener unavailable on {address}: {error}"
                    ));
                    None
                }
            };
        if udp.is_none() && tcp.is_none() {
            if wait_for_shutdown_or_dns_reload(&controller, shutdown.clone()).await {
                return Ok(());
            }
            continue;
        }
        let udp_controller = controller.clone();
        let udp_shutdown_receiver = shutdown.clone();
        let udp_shutdown = async move {
            let _ = wait_for_shutdown_or_dns_reload(&udp_controller, udp_shutdown_receiver).await;
        };
        let tcp_controller = controller.clone();
        let tcp_shutdown_receiver = shutdown.clone();
        let tcp_shutdown = async move {
            let _ = wait_for_shutdown_or_dns_reload(&tcp_controller, tcp_shutdown_receiver).await;
        };
        match (udp, tcp) {
            (Some(udp), Some(tcp)) => {
                tokio::try_join!(udp.serve_until(udp_shutdown), tcp.serve_until(tcp_shutdown))?;
            }
            (Some(udp), None) => udp.serve_until(udp_shutdown).await?,
            (None, Some(tcp)) => tcp.serve_until(tcp_shutdown).await?,
            (None, None) => unreachable!("DNS listener availability checked above"),
        }
        if *shutdown.borrow() {
            return Ok(());
        }
    }
}

/// Resolve the DNS listener address with the same precedence as the Go
/// resolver config controller: Rust's live overlay wins, while an imported
/// Go `dns_settings.server` row is used when no overlay exists.
pub(super) async fn configured_dns_server(
    store: &doradus_store::ConfigStore,
) -> Result<Option<String>> {
    if let Some(bytes) = store.get_config("resolver.server").await? {
        return Ok(serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("server")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .filter(|server| !server.trim().is_empty()));
    }
    Ok(store
        .repository()
        .list_go_dns_settings()
        .await?
        .into_iter()
        .next()
        .map(|record| record.server)
        .filter(|server| !server.trim().is_empty())
        .or_else(|| Some(DEFAULT_DNS_SERVER.to_owned())))
}

/// Wait until either process shutdown or a successfully published runtime
/// reload.  Device supervisors use this while disabled so an API change can
/// enable them without restarting the service.
pub async fn wait_for_shutdown_or_reload(
    controller: &RuntimeController,
    mut shutdown: watch::Receiver<bool>,
) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    let mut reload = controller.subscribe_reload();
    tokio::select! {
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
        changed = reload.recv() => changed.is_err() && *shutdown.borrow(),
    }
}

pub async fn wait_for_shutdown_or_dns_reload(
    controller: &RuntimeController,
    mut shutdown: watch::Receiver<bool>,
) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    let mut reload = controller.subscribe_dns_reload();
    tokio::select! {
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
        changed = reload.recv() => changed.is_err() && *shutdown.borrow(),
    }
}

pub async fn wait_for_shutdown_or_inbound_reload(
    controller: &RuntimeController,
    mut shutdown: watch::Receiver<bool>,
) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    let mut reload = controller.subscribe_inbound_reload();
    tokio::select! {
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
        changed = reload.recv() => changed.is_err() && *shutdown.borrow(),
    }
}

pub async fn wait_for_shutdown_or_matching_inbound_reload(
    controller: &RuntimeController,
    mut shutdown: watch::Receiver<bool>,
    inbound_id: Option<&str>,
) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    let mut reload = controller.subscribe_inbound_reload();
    loop {
        tokio::select! {
            changed = shutdown.changed() => return changed.is_err() || *shutdown.borrow(),
            changed = reload.recv() => match changed {
                Ok(crate::controller::InboundReload::All) => return true,
                Ok(crate::controller::InboundReload::One(id))
                    if inbound_id == Some(id.as_str()) => return true,
                Ok(crate::controller::InboundReload::One(_)) => continue,
                Err(_) => return *shutdown.borrow(),
            },
        }
    }
}
