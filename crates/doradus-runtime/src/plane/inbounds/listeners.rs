//! Socket-backed inbound listener factory.
//!
//! The supervisor owns every inbound by id. This module contains the socket
//! protocol branches; TUN is another factory branch in the same owner map.

use std::future::Future;
use std::pin::Pin;
use std::{collections::HashMap, sync::Arc, time::Duration};

use super::listener_stream::start_stream_listener;
use super::listener_transparent::start_transparent_listener;
#[cfg(feature = "tun")]
use super::listener_tun::{TunSource, spawn_tun_owner, tun_owner_id};
use super::listener_udp::start_udp_listener;
use super::{
    ConnectionMonitor, InboundAuth, InboundPlan, InboundProtocolKind, InboundProtocolPlan,
    InboundTlsAcceptor, InboundTransportPlan, RuntimeController, RuntimeProxySelector,
    selected_proxy_ids,
};
use crate::inbound_runtime::InboundRuntimeState;
use doradus_core::Result;

pub(super) type InboundOwners = HashMap<String, Vec<tokio::task::JoinHandle<()>>>;

pub(super) struct ListenerStartContext<'a> {
    pub(super) protocol: &'a InboundProtocolKind,
    pub(super) protocol_config: &'a InboundProtocolPlan,
    pub(super) transports: &'a InboundTransportPlan,
    pub(super) selector: Arc<RuntimeProxySelector>,
    pub(super) monitor: Arc<ConnectionMonitor>,
    pub(super) tls_acceptor: Option<InboundTlsAcceptor>,
    pub(super) runtime: Arc<InboundRuntimeState>,
}

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

pub(super) fn push_listener(
    listeners: &mut InboundOwners,
    id: &str,
    listener: tokio::task::JoinHandle<()>,
    runtime: &InboundRuntimeState,
) {
    let supervised = tokio::spawn(supervise_listener(id.to_owned(), runtime.clone(), listener));
    listeners.entry(id.to_owned()).or_default().push(supervised);
}

pub(super) fn start_inbounds<'a>(
    controller: &'a RuntimeController,
    shutdown: &'a tokio::sync::watch::Receiver<bool>,
    only_id: Option<&'a str>,
    options: &'a mut InboundStartOptions,
) -> Pin<Box<dyn Future<Output = Result<InboundOwners>> + 'a>> {
    Box::pin(start_inbounds_inner(controller, shutdown, only_id, options))
}

async fn start_inbounds_inner(
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
    let selector = Box::pin(controller.build_proxy_selector_with_udp(
        "",
        &tcp_proxy_id,
        &udp_proxy_id,
        "",
        "",
        Duration::from_secs(30),
    ))
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

    for record in records
        .into_iter()
        .filter(|record| record.enabled && !record.protocol_type.eq_ignore_ascii_case("tun"))
    {
        if only_id.is_some_and(|id| id != record.id) {
            continue;
        }
        let mut plan = match InboundPlan::compile(record) {
            Ok(plan) => plan,
            Err(error) => {
                monitor.error(format!("skip inbound: {error}"));
                continue;
            }
        };
        plan.prepare_runtime(&tcp_proxy_id, &inbound_auth);
        let InboundPlan {
            mut spec,
            protocol,
            protocol_config,
            transports,
            tls_acceptor,
        } = plan;
        if protocol.is_password_hash_protocol()
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
        if transports.unsupported {
            monitor.warn(format!(
                "skip inbound {}: configured transport is not implemented",
                spec.id
            ));
            continue;
        }
        let start = ListenerStartContext {
            protocol: &protocol,
            protocol_config: &protocol_config,
            transports: &transports,
            selector: selector.clone(),
            monitor: monitor.clone(),
            tls_acceptor,
            runtime: Arc::clone(&runtime),
        };
        if protocol.is_transparent() {
            start_transparent_listener(&mut listeners, spec, &start).await;
            continue;
        }
        if start_stream_listener(&mut listeners, &mut spec, &start).await {
            continue;
        }
        if spec.udp_mode.udp_enabled() {
            start_udp_listener(&mut listeners, spec.clone(), &start).await;
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
