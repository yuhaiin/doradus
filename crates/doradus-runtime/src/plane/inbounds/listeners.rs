//! Socket-backed inbound listener factory.
//!
//! The supervisor owns every inbound by id. This module contains the socket
//! protocol branches; TUN is another factory branch in the same owner map.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use tokio::net::{TcpListener, UdpSocket};

use doradus_core::Result;

#[cfg(feature = "http2")]
use super::serve_h2_listener;
#[cfg(all(feature = "websocket", feature = "http2"))]
use super::serve_websocket_h2_listener;
#[cfg(feature = "websocket")]
use super::serve_websocket_listener;
use super::{
    ConnectionMonitor, InboundAuth, InboundHandler, InboundSpec, RuntimeController,
    build_inbound_tls_acceptor, has_transport, is_supported_inbound_transport,
    is_supported_transparent_transport, selected_proxy_ids, serve_listener, supports_socks5_udp,
};
use crate::inbound_runtime::InboundRuntimeState;

pub(super) type InboundOwners = HashMap<String, Vec<tokio::task::JoinHandle<()>>>;

#[derive(Default)]
pub(super) struct InboundStartOptions {
    #[cfg(feature = "tun")]
    injected_tun: Option<InjectedTun>,
    #[cfg(feature = "tun")]
    injected_id: Option<String>,
}

#[cfg(feature = "tun")]
struct InjectedTun {
    runtime: doradus_tun::TunRuntime,
    config: crate::TunRuntimeConfig,
}

impl InboundStartOptions {
    #[cfg(feature = "tun")]
    pub(super) fn with_injected_tun(
        runtime: doradus_tun::TunRuntime,
        config: crate::TunRuntimeConfig,
    ) -> Self {
        let injected_id = config
            .inbound_id
            .clone()
            .or_else(|| config.tun.name.clone())
            .or_else(|| Some("tun".to_owned()));
        Self {
            injected_tun: Some(InjectedTun { runtime, config }),
            injected_id,
        }
    }

    pub(super) fn injected_owner_id(&self) -> Option<String> {
        #[cfg(feature = "tun")]
        {
            self.injected_id.clone()
        }
        #[cfg(not(feature = "tun"))]
        {
            None
        }
    }

    pub(super) fn is_injected_owner(&self, id: &str) -> bool {
        self.injected_owner_id().as_deref() == Some(id)
    }
}

struct AbortOnDrop(Option<tokio::task::JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(listener) = self.0.take() {
            listener.abort();
        }
    }
}

async fn supervise_listener(
    id: String,
    runtime: InboundRuntimeState,
    listener: tokio::task::JoinHandle<()>,
) {
    let mut listener = AbortOnDrop(Some(listener));
    let result = listener.0.as_mut().expect("listener handle exists").await;
    if runtime.is_stopping(&id) || runtime.has_failed_listener(&id) {
        return;
    }
    let error = match result {
        Ok(()) => "listener exited unexpectedly".to_owned(),
        Err(error) => format!("listener task failed: {error}"),
    };
    runtime.listener_failed(&id, "listener", None, &error);
}

fn push_listener(
    listeners: &mut InboundOwners,
    id: &str,
    listener: tokio::task::JoinHandle<()>,
    runtime: &InboundRuntimeState,
) {
    let supervised = tokio::spawn(supervise_listener(id.to_owned(), runtime.clone(), listener));
    listeners.entry(id.to_owned()).or_default().push(supervised);
}

pub(super) async fn start_inbounds(
    controller: &RuntimeController,
    shutdown: &tokio::sync::watch::Receiver<bool>,
    only_id: Option<&str>,
    options: &mut InboundStartOptions,
) -> Result<InboundOwners> {
    let records = controller.store().repository().list_go_inbounds().await?;
    let inbound_auth = Arc::new(InboundAuth::from_users(
        controller
            .store()
            .repository()
            .list_go_user_records_for_runtime()
            .await?,
    ));
    let (tcp_proxy_id, udp_proxy_id) = selected_proxy_ids(controller).await?;
    let selector = controller
        .build_proxy_selector_with_udp(
            "",
            &tcp_proxy_id,
            &udp_proxy_id,
            "",
            "",
            Duration::from_secs(30),
        )
        .await?;
    let monitor = controller.monitor();
    let runtime = controller.inbound_runtime();
    for record in &records {
        if only_id.is_some_and(|id| id != record.id) {
            continue;
        }
        if !record.enabled {
            runtime.mark_disabled(&record.id);
        } else if !record.protocol_type.eq_ignore_ascii_case("tun") {
            runtime.mark_starting(&record.id, false);
        }
    }
    let socket_ids = records
        .iter()
        .filter(|record| {
            record.enabled
                && !record.protocol_type.eq_ignore_ascii_case("tun")
                && only_id.is_none_or(|id| id == record.id)
        })
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();
    let deferred_socket_ids = records
        .iter()
        .filter(|record| {
            record.enabled
                && !record.protocol_type.eq_ignore_ascii_case("tun")
                && (record.protocol_type.eq_ignore_ascii_case("tproxy")
                    || record.protocol_type.eq_ignore_ascii_case("redir"))
                && only_id.is_none_or(|id| id == record.id)
        })
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();
    let tun_ids = records
        .iter()
        .filter(|record| {
            record.enabled
                && record.protocol_type.eq_ignore_ascii_case("tun")
                && only_id.is_none_or(|id| id == record.id)
        })
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();
    let mut listeners = HashMap::new();

    async fn bind_tcp_listener(
        listen: SocketAddr,
        id: &str,
        monitor: &ConnectionMonitor,
        runtime: &InboundRuntimeState,
    ) -> Option<TcpListener> {
        match TcpListener::bind(listen).await {
            Ok(listener) => {
                runtime.listener_ready(
                    id,
                    "tcp",
                    Some(listener.local_addr().unwrap_or(listen).to_string()),
                );
                Some(listener)
            }
            Err(error) => {
                runtime.listener_failed(id, "tcp", Some(listen.to_string()), &error.to_string());
                monitor.error(format!("skip inbound {id}: bind TCP {listen}: {error}"));
                None
            }
        }
    }

    for record in records
        .into_iter()
        .filter(|record| record.enabled && !record.protocol_type.eq_ignore_ascii_case("tun"))
    {
        if only_id.is_some_and(|id| id != record.id) {
            continue;
        }
        let mut spec = match InboundSpec::from_record(record.clone()) {
            Ok(spec) => spec,
            Err(error) => {
                monitor.error(format!("skip inbound: {error}"));
                continue;
            }
        };
        spec.outbound_id = tcp_proxy_id.clone();
        if inbound_auth.has_basic_users() || !inbound_auth.inbound_passwords().is_empty() {
            spec.username.clear();
            if inbound_auth.has_basic_users() {
                spec.password.clear();
            }
            spec.auth = Some(Arc::clone(&inbound_auth));
        }
        if matches!(spec.protocol.as_str(), "yuubinsya" | "trojan")
            && spec
                .auth
                .as_ref()
                .is_some_and(|auth| auth.has_unrepresentable_password())
        {
            monitor.warn(format!(
                "skip inbound {}: central user allowAnyPassword cannot be represented by {} password hashes",
                spec.id, spec.protocol
            ));
            continue;
        }
        if !spec.transports.is_empty()
            && spec
                .transports
                .iter()
                .any(|transport| !is_supported_inbound_transport(transport))
        {
            monitor.warn(format!(
                "skip inbound {}: configured transport is not implemented",
                spec.id
            ));
            continue;
        }
        let tls_acceptor = match build_inbound_tls_acceptor(&record.data_json, &spec.transports) {
            Ok(acceptor) => acceptor,
            Err(error) => {
                monitor.error(format!("skip inbound {}: {error}", spec.id));
                continue;
            }
        };
        if spec.protocol.eq_ignore_ascii_case("tproxy")
            || spec.protocol.eq_ignore_ascii_case("redir")
        {
            if spec.udp_mode.udp_enabled() && spec.protocol.eq_ignore_ascii_case("tproxy") {
                monitor.warn(format!(
                    "start UDP inbound {}: Linux transparent UDP requires TPROXY ancillary data and CAP_NET_ADMIN",
                    spec.id
                ));
            } else if spec.udp_mode.udp_enabled() {
                monitor.warn(format!(
                    "ignore UDP inbound {}: Go redir contract disables UDP",
                    spec.id
                ));
            }
            if spec
                .transports
                .iter()
                .any(|transport| !is_supported_transparent_transport(transport))
            {
                monitor.warn(format!(
                    "skip inbound {}: transparent listener transport is not implemented",
                    spec.id
                ));
                continue;
            }
            #[cfg(target_os = "linux")]
            {
                let is_tproxy = spec.protocol.eq_ignore_ascii_case("tproxy");
                let udp_enabled = spec.udp_mode.udp_enabled();
                let udp_spec = spec.clone();
                let protocol = spec.protocol.clone();
                let listener_spec = spec;
                let listener_selector = selector.clone();
                let listener_monitor = monitor.clone();
                let listener_tls_acceptor = tls_acceptor.clone();
                let listener_runtime = runtime.clone();
                let logs = listener_monitor.logs();
                push_listener(
                    &mut listeners,
                    &listener_spec.id.clone(),
                    tokio::spawn(async move {
                        if let Err(error) = crate::inbound::adapters::transparent::serve_listener(
                            listener_spec.listen,
                            protocol,
                            listener_spec,
                            listener_selector,
                            listener_monitor,
                            listener_tls_acceptor,
                            listener_runtime,
                        )
                        .await
                        {
                            logs.error(format!("transparent inbound listener stopped: {error}"));
                        }
                    }),
                    &runtime,
                );
                if udp_enabled && is_tproxy {
                    let selector = selector.clone();
                    let monitor = monitor.clone();
                    let spec = udp_spec;
                    let listener_runtime = runtime.clone();
                    let logs = monitor.logs();
                    push_listener(
                        &mut listeners,
                        &spec.id.clone(),
                        tokio::spawn(async move {
                            if let Err(error) =
                                crate::inbound::adapters::transparent::serve_udp_listener(
                                    spec.listen,
                                    spec,
                                    selector,
                                    monitor,
                                    listener_runtime,
                                )
                                .await
                            {
                                logs.error(format!("transparent UDP listener stopped: {error}"));
                            }
                        }),
                        &runtime,
                    );
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let error = "tproxy/redir require Linux socket support";
                monitor.warn(format!("skip inbound {}: {error}", spec.id));
                runtime.listener_failed(&spec.id, "listener", Some(spec.listen.to_string()), error);
            }
            continue;
        }
        if has_transport(&spec.transports, "websocket") {
            if spec.udp_mode.udp_enabled() {
                monitor.warn(format!(
                    "skip UDP inbound {}: WebSocket transport only wraps TCP listeners",
                    spec.id
                ));
            }
            if spec.udp_mode.tcp_enabled() {
                let Some(listener) =
                    bind_tcp_listener(spec.listen, &spec.id, &monitor, &runtime).await
                else {
                    continue;
                };
                spec.listen = listener.local_addr().unwrap_or(spec.listen);
                let selector = selector.clone();
                let monitor = monitor.clone();
                let spec = spec.clone();
                let tls_acceptor = tls_acceptor.clone();
                let logs = monitor.logs();
                #[cfg(all(feature = "websocket", feature = "http2"))]
                {
                    if has_transport(&spec.transports, "http2") {
                        push_listener(
                            &mut listeners,
                            &spec.id.clone(),
                            tokio::spawn(async move {
                                if let Err(error) = serve_websocket_h2_listener(
                                    listener,
                                    spec,
                                    selector,
                                    monitor,
                                    tls_acceptor,
                                )
                                .await
                                {
                                    logs.error(format!(
                                        "WebSocket+HTTP/2 inbound listener stopped: {error}"
                                    ));
                                }
                            }),
                            &runtime,
                        );
                    } else {
                        push_listener(
                            &mut listeners,
                            &spec.id.clone(),
                            tokio::spawn(async move {
                                if let Err(error) = serve_websocket_listener(
                                    listener,
                                    spec,
                                    selector,
                                    monitor,
                                    tls_acceptor,
                                )
                                .await
                                {
                                    logs.error(format!(
                                        "WebSocket inbound listener stopped: {error}"
                                    ));
                                }
                            }),
                            &runtime,
                        );
                    }
                }
                #[cfg(all(feature = "websocket", not(feature = "http2")))]
                {
                    if has_transport(&spec.transports, "http2") {
                        let _ = (listener, spec, selector, monitor, tls_acceptor);
                        logs.warn(
                            "skip inbound: WebSocket+HTTP/2 requires both websocket and http2 features",
                        );
                    } else {
                        push_listener(
                            &mut listeners,
                            &spec.id.clone(),
                            tokio::spawn(async move {
                                if let Err(error) = serve_websocket_listener(
                                    listener,
                                    spec,
                                    selector,
                                    monitor,
                                    tls_acceptor,
                                )
                                .await
                                {
                                    logs.error(format!(
                                        "WebSocket inbound listener stopped: {error}"
                                    ));
                                }
                            }),
                            &runtime,
                        );
                    }
                }
                #[cfg(not(feature = "websocket"))]
                {
                    let _ = (listener, spec, selector, monitor, tls_acceptor);
                    logs.warn("skip inbound: WebSocket transport requires the websocket feature");
                }
            }
            continue;
        }
        if has_transport(&spec.transports, "http2") {
            if spec.udp_mode.udp_enabled() {
                monitor.warn(format!(
                    "skip UDP inbound {}: HTTP/2 transport only wraps TCP listeners",
                    spec.id
                ));
            }
            if spec.udp_mode.tcp_enabled() {
                let Some(listener) =
                    bind_tcp_listener(spec.listen, &spec.id, &monitor, &runtime).await
                else {
                    continue;
                };
                spec.listen = listener.local_addr().unwrap_or(spec.listen);
                let selector = selector.clone();
                let monitor = monitor.clone();
                let spec = spec.clone();
                let tls_acceptor = tls_acceptor.clone();
                let logs = monitor.logs();
                #[cfg(feature = "http2")]
                push_listener(
                    &mut listeners,
                    &spec.id.clone(),
                    tokio::spawn(async move {
                        if let Err(error) =
                            serve_h2_listener(listener, spec, selector, monitor, tls_acceptor).await
                        {
                            logs.error(format!("HTTP/2 inbound listener stopped: {error}"));
                        }
                    }),
                    &runtime,
                );
                #[cfg(not(feature = "http2"))]
                {
                    let _ = (listener, spec, selector, monitor, tls_acceptor);
                    logs.warn("skip inbound: HTTP/2 transport requires the http2 feature");
                }
            }
            continue;
        }
        if spec.udp_mode.tcp_enabled()
            || (spec.protocol.eq_ignore_ascii_case("vless") && spec.udp_mode.udp_enabled())
        {
            let Some(listener) = bind_tcp_listener(spec.listen, &spec.id, &monitor, &runtime).await
            else {
                continue;
            };
            spec.listen = listener.local_addr().unwrap_or(spec.listen);
            let selector = selector.clone();
            let monitor = monitor.clone();
            let spec = spec.clone();
            let tls_acceptor = tls_acceptor.clone();
            let logs = monitor.logs();
            push_listener(
                &mut listeners,
                &spec.id.clone(),
                tokio::spawn(async move {
                    if let Err(error) =
                        serve_listener(listener, spec, selector, monitor, tls_acceptor).await
                    {
                        logs.error(format!("inbound listener stopped: {error}"));
                    }
                }),
                &runtime,
            );
        }
        if spec.udp_mode.udp_enabled() {
            let selector = selector.clone();
            let monitor = monitor.clone();
            let spec = spec.clone();
            let protocol = spec.protocol.trim();
            if protocol.eq_ignore_ascii_case("yuubinsya") {
                if tls_acceptor.is_some() {
                    monitor.warn(format!(
                        "skip UDP inbound {}: TLS transport only wraps TCP listeners",
                        spec.id
                    ));
                    continue;
                }
                let password_hashes = spec
                    .auth
                    .as_ref()
                    .map(|auth| {
                        auth.inbound_passwords()
                            .into_iter()
                            .map(|password| doradus_protocol::yuubinsya::derive_salt(&password))
                            .collect::<Vec<_>>()
                    })
                    .filter(|passwords| !passwords.is_empty())
                    .unwrap_or_else(|| {
                        vec![doradus_protocol::yuubinsya::derive_salt(
                            spec.password.as_bytes(),
                        )]
                    });
                let socket = if let Some(password) = spec.aead_password.clone() {
                    let raw = match UdpSocket::bind(spec.listen).await {
                        Ok(socket) => socket,
                        Err(error) => {
                            runtime.listener_failed(
                                &spec.id,
                                "udp",
                                Some(spec.listen.to_string()),
                                &error.to_string(),
                            );
                            monitor.error(format!(
                                "skip UDP inbound {}: bind AEAD Yuubinsya UDP {}: {error}",
                                spec.id, spec.listen
                            ));
                            continue;
                        }
                    };
                    doradus_protocol::yuubinsya_udp::YuubinsyaUdpServer::new(
                        Box::new(doradus_protocol::aead::AeadUdpServer::new(
                            raw,
                            password,
                            spec.aead_method,
                        )),
                        password_hashes[0],
                        false,
                    )
                } else {
                    // Go's Yuubinsya inbound uses the native packet
                    // format without the SOCKS5 three-byte prefix.  The
                    // prefix is only used when Yuubinsya wraps a SOCKS5
                    // UDP association.
                    match doradus_protocol::yuubinsya_udp::YuubinsyaUdpServer::bind_with_password_hashes(
                        spec.listen,
                        password_hashes,
                        false,
                    )
                    .await
                    {
                        Ok(socket) => socket,
                        Err(error) => {
                            runtime.listener_failed(
                                &spec.id,
                                "udp",
                                Some(spec.listen.to_string()),
                                &error.to_string(),
                            );
                            monitor.error(format!(
                                "skip UDP inbound {}: bind Yuubinsya UDP {}: {error}",
                                spec.id, spec.listen
                            ));
                            continue;
                        }
                    }
                };
                let logs = monitor.logs();
                let inbound_handler =
                    InboundHandler::new(spec.clone(), Arc::clone(&selector), Arc::clone(&monitor));
                push_listener(
                    &mut listeners,
                    &spec.id.clone(),
                    tokio::spawn(async move {
                        if let Err(error) =
                            crate::inbound::adapters::yuubinsya::handle_udp(socket, inbound_handler)
                                .await
                        {
                            logs.error(format!("Yuubinsya UDP listener stopped: {error}"));
                        }
                    }),
                    &runtime,
                );
            } else if protocol.eq_ignore_ascii_case("socks5")
                || protocol.eq_ignore_ascii_case("mixed")
                || protocol.eq_ignore_ascii_case("mix")
            {
                if !supports_socks5_udp(&spec.protocol, spec.protocol_udp) {
                    monitor.warn(format!(
                        "skip UDP inbound {}: protocol {:?} has no UDP mode",
                        spec.id, spec.protocol
                    ));
                    continue;
                }
                if tls_acceptor.is_some() {
                    monitor.warn(format!(
                        "skip UDP inbound {}: TLS transport only wraps TCP listeners",
                        spec.id
                    ));
                    continue;
                }
                let socket = match UdpSocket::bind(spec.listen).await {
                    Ok(socket) => socket,
                    Err(error) => {
                        runtime.listener_failed(
                            &spec.id,
                            "udp",
                            Some(spec.listen.to_string()),
                            &error.to_string(),
                        );
                        monitor.error(format!(
                            "skip UDP inbound {}: bind SOCKS5 UDP {}: {error}",
                            spec.id, spec.listen
                        ));
                        continue;
                    }
                };
                let logs = monitor.logs();
                let inbound_handler =
                    InboundHandler::new(spec.clone(), Arc::clone(&selector), Arc::clone(&monitor));
                if let Some(password) = spec.aead_password.clone() {
                    let socket = doradus_protocol::socks5_server::AeadUdpTransport::new(
                        crate::inbound::socks5::RuntimeUdpTransport(Box::new(socket)),
                        password,
                        spec.aead_method,
                    );
                    push_listener(
                        &mut listeners,
                        &spec.id.clone(),
                        tokio::spawn(async move {
                            if let Err(error) = crate::inbound::socks5::serve_udp_socket(
                                Box::new(socket),
                                inbound_handler,
                            )
                            .await
                            {
                                logs.error(format!("AEAD SOCKS5 UDP listener stopped: {error}"));
                            }
                        }),
                        &runtime,
                    );
                } else {
                    let socket = crate::inbound::socks5::RuntimeUdpTransport(Box::new(socket));
                    push_listener(
                        &mut listeners,
                        &spec.id.clone(),
                        tokio::spawn(async move {
                            if let Err(error) = crate::inbound::socks5::serve_udp_socket(
                                Box::new(socket),
                                inbound_handler,
                            )
                            .await
                            {
                                logs.error(format!("SOCKS5 UDP listener stopped: {error}"));
                            }
                        }),
                        &runtime,
                    );
                }
            } else {
                monitor.warn(format!(
                    "skip UDP inbound {}: protocol {:?} has no UDP mode",
                    spec.id, spec.protocol
                ));
            }
        }
    }

    #[cfg(feature = "tun")]
    {
        let injected = options.injected_tun.take();
        let tun_configs = if let Some(injected) = injected {
            let config = match crate::data_plane::load_tun_config_for_supervisor(
                controller.store(),
                injected.config.clone(),
            )
            .await
            {
                Ok(config) => config,
                Err(error) => {
                    monitor.error(format!("load injected TUN inbound config failed: {error}"));
                    injected.config.clone()
                }
            };
            options.injected_id = Some(tun_owner_id(&config));
            if only_id.is_some_and(|id| id != tun_owner_id(&config)) {
                options.injected_tun = Some(injected);
                Vec::new()
            } else {
                spawn_tun_owner(
                    &mut listeners,
                    config,
                    TunSource::Injected(injected.runtime),
                    controller,
                    shutdown,
                );
                Vec::new()
            }
        } else if options.injected_id.is_some() {
            // An externally-owned TUN is already part of this owner map. Its
            // fd-backed task reloads itself; socket-only reloads must not
            // create a second desktop device for the same inbound id.
            Vec::new()
        } else {
            match crate::data_plane::load_tun_configs_for_desktop(controller.store()).await {
                Ok(configs) => configs,
                Err(error) => {
                    monitor.error(format!("load TUN inbound config failed: {error}"));
                    for id in &tun_ids {
                        runtime.listener_failed(id, "tun", None, &error.to_string());
                    }
                    Vec::new()
                }
            }
        };

        for config in tun_configs {
            if !config.enabled || only_id.is_some_and(|id| id != tun_owner_id(&config)) {
                continue;
            }
            spawn_tun_owner(
                &mut listeners,
                config,
                TunSource::Desktop,
                controller,
                shutdown,
            );
        }
        for id in tun_ids {
            if !listeners.contains_key(&id) && !runtime.has_failed_listener(&id) {
                runtime.mark_no_listener(&id, "no TUN inbound listener was started");
            }
        }
    }

    for id in socket_ids {
        if deferred_socket_ids.iter().any(|deferred| deferred == &id) {
            continue;
        }
        if listeners.contains_key(&id) {
            runtime.owner_started(&id);
        } else {
            runtime.mark_no_listener(&id, "no inbound listener was started");
        }
    }
    Ok(listeners)
}

#[cfg(feature = "tun")]
#[allow(clippy::large_enum_variant)]
enum TunSource {
    Desktop,
    Injected(doradus_tun::TunRuntime),
}

#[cfg(feature = "tun")]
fn tun_owner_id(config: &crate::TunRuntimeConfig) -> String {
    config
        .inbound_id
        .clone()
        .or_else(|| config.tun.name.clone())
        .unwrap_or_else(|| "tun".to_owned())
}

#[cfg(feature = "tun")]
fn spawn_tun_owner(
    owners: &mut InboundOwners,
    config: crate::TunRuntimeConfig,
    source: TunSource,
    controller: &RuntimeController,
    shutdown: &tokio::sync::watch::Receiver<bool>,
) {
    let id = tun_owner_id(&config);
    let monitor = controller.monitor();
    let runtime = controller.inbound_runtime();
    runtime.mark_starting(&id, false);
    let shutdown = shutdown.clone();
    let task = tokio::task::spawn_local(run_tun_owner(
        controller.clone(),
        shutdown,
        config,
        source,
        monitor,
    ));
    push_listener(owners, &id, task, &runtime);
}

#[cfg(feature = "tun")]
async fn run_tun_owner(
    controller: RuntimeController,
    shutdown: tokio::sync::watch::Receiver<bool>,
    mut config: crate::TunRuntimeConfig,
    mut source: TunSource,
    monitor: Arc<ConnectionMonitor>,
) {
    let runtime = controller.inbound_runtime();
    loop {
        let owner_id = tun_owner_id(&config);
        let mut reload_already_received = false;
        if config.enabled {
            let result = match &mut source {
                TunSource::Desktop => match crate::data_plane::open_tun(&config) {
                    Ok(tun) => {
                        runtime.listener_ready(&owner_id, "tun", config.tun.name.clone());
                        monitor.info(format!(
                            "TUN inbound started name={}",
                            tun.name()
                                .ok()
                                .or_else(|| config.tun.name.clone())
                                .unwrap_or_else(|| "<unnamed>".to_owned())
                        ));
                        crate::run_tun_device_until(
                            controller.clone(),
                            tun,
                            config.clone(),
                            shutdown.clone(),
                        )
                        .await
                    }
                    Err(error) => Err(error),
                },
                TunSource::Injected(tun) => {
                    runtime.listener_ready(&owner_id, "tun", config.tun.name.clone());
                    monitor.info(format!(
                        "TUN inbound started name={}",
                        tun.name()
                            .ok()
                            .or_else(|| config.tun.name.clone())
                            .unwrap_or_else(|| "<unnamed>".to_owned())
                    ));
                    crate::run_tun_device_until_ref(
                        controller.clone(),
                        tun,
                        config.clone(),
                        shutdown.clone(),
                    )
                    .await
                }
            };
            match result {
                Ok(()) => reload_already_received = true,
                Err(error) => {
                    runtime.listener_failed(
                        &owner_id,
                        "tun",
                        config.tun.name.clone(),
                        &error.to_string(),
                    );
                    monitor.error(format!("TUN inbound stopped: {error}; waiting for reload"));
                }
            }
        } else {
            runtime.mark_disabled(&owner_id);
            monitor.info("TUN inbound disabled");
        }

        if !reload_already_received
            && crate::data_plane::wait_for_shutdown_or_matching_inbound_reload(
                &controller,
                shutdown.clone(),
                Some(owner_id.as_str()),
            )
            .await
        {
            break;
        }
        if *shutdown.borrow() {
            break;
        }

        config = match crate::data_plane::load_tun_config_for_supervisor(
            controller.store(),
            config.clone(),
        )
        .await
        {
            Ok(config) => config,
            Err(error) => {
                monitor.error(format!("reload TUN inbound config failed: {error}"));
                continue;
            }
        };
    }
}
