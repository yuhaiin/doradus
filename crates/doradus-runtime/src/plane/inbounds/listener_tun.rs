#[cfg(feature = "tun")]
use std::sync::Arc;

#[cfg(feature = "tun")]
use super::listeners::{InboundOwners, push_listener};
#[cfg(feature = "tun")]
use super::{ConnectionMonitor, RuntimeController};

#[cfg(feature = "tun")]
#[allow(clippy::large_enum_variant)]
pub(super) enum TunSource {
    Desktop,
    Injected(doradus_tun::TunRuntime),
}

#[cfg(feature = "tun")]
pub(super) fn tun_owner_id(config: &crate::TunRuntimeConfig) -> String {
    config
        .inbound_id
        .clone()
        .or_else(|| config.tun.name.clone())
        .unwrap_or_else(|| "tun".to_owned())
}

#[cfg(feature = "tun")]
pub(super) fn spawn_tun_owner(
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
