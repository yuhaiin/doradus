//! Shared runtime data-plane owners.
//!
//! The binary is only one host for the runtime.  Android `VpnService`, iOS
//! `PacketTunnelProvider`, and future embedders can create their platform TUN
//! device themselves and hand the owned [`TunRuntime`] to the same runner.

#[cfg(feature = "tun")]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
#[cfg(feature = "tun")]
use std::time::Duration;

use serde_json::Value;
use tokio::sync::watch;
use yuhaiin_core::dns::{
    AsyncDnsHandler, DnsRecordType, DnsResponse, decode_query, encode_response,
};
use yuhaiin_core::dns_resolver_async::AsyncIpResolver;
#[cfg(feature = "tun")]
use yuhaiin_core::{Error, ErrorKind};
use yuhaiin_core::{LocalBoxFuture, ResolveStrategy, Result};

use crate::{RuntimeController, parse_dns_server};

/// DNS packet handler backed by the resolver in the current immutable
/// runtime snapshot.  TUN DNS hijacking and the optional UDP DNS listener use
/// the same handler, so a reload cannot make them disagree about resolver
/// policy.
pub struct RuntimeDnsHandler {
    pub resolver: Arc<dyn AsyncIpResolver>,
}

impl AsyncDnsHandler for RuntimeDnsHandler {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        let question = match decode_query(packet) {
            Ok(question) => question,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        Box::pin(async move {
            let addresses = self
                .resolver
                .resolve(
                    &question.domain,
                    match question.record_type {
                        DnsRecordType::A => ResolveStrategy::OnlyIpv4,
                        DnsRecordType::Aaaa => ResolveStrategy::OnlyIpv6,
                        _ => ResolveStrategy::Default,
                    },
                )
                .await?;
            encode_response(
                packet,
                &DnsResponse {
                    addresses,
                    ptr_names: Vec::new(),
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(30),
                },
            )
        })
    }
}

#[cfg(feature = "tun")]
#[derive(Debug, Clone)]
pub struct TunRuntimeConfig {
    pub enabled: bool,
    pub tun: yuhaiin_core::tun::TunConfig,
    pub direct_id: String,
    pub proxy_id: Option<String>,
    pub bypass_id: String,
    pub drop_id: String,
    pub channel_capacity: usize,
}

/// Load the persisted TUN settings without opening a platform device.  A
/// mobile host can use this to validate the shared config, create its
/// `AsyncDevice::from_fd`, then call [`run_tun_device_until`].
#[cfg(feature = "tun")]
pub async fn load_tun_config(store: &yuhaiin_store::ConfigStore) -> Result<TunRuntimeConfig> {
    let value = store
        .get_config("tun.runtime")
        .await?
        .map(|bytes| serde_json::from_slice::<Value>(&bytes))
        .transpose()
        .map_err(|error| Error::invalid(format!("tun.runtime is invalid JSON: {error}")))?
        .unwrap_or_else(|| serde_json::json!({}));
    let enabled = value
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || std::env::var("YUHAIIN_TUN").ok().as_deref() == Some("1");
    let tun = yuhaiin_core::tun::TunConfig {
        name: value.get("name").and_then(Value::as_str).map(str::to_owned),
        ipv4: value
            .get("ipv4")
            .and_then(parse_ipv4)
            .or_else(|| enabled.then_some((Ipv4Addr::new(10, 0, 0, 1), 24))),
        ipv6: value
            .get("ipv6")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(parse_ipv6).collect())
            .unwrap_or_default(),
        mtu: value.get("mtu").and_then(Value::as_u64).unwrap_or(1500) as usize,
        queue_capacity: value
            .get("queueCapacity")
            .and_then(Value::as_u64)
            .unwrap_or(256) as usize,
    };
    Ok(TunRuntimeConfig {
        enabled,
        tun,
        direct_id: value
            .get("directId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        proxy_id: value
            .get("proxyId")
            .and_then(Value::as_str)
            .map(str::to_owned),
        bypass_id: value
            .get("bypassId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        drop_id: value
            .get("dropId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        channel_capacity: value
            .get("channelCapacity")
            .and_then(Value::as_u64)
            .unwrap_or(256) as usize,
    })
}

/// Run one already-created TUN device through the shared runtime snapshot.
/// The caller owns device creation and can therefore inject a mobile VPN fd;
/// this function owns dispatcher, proxy runtime, DNS handler and shutdown
/// ordering only.
#[cfg(feature = "tun")]
pub async fn run_tun_device_until(
    controller: RuntimeController,
    mut tun: yuhaiin_core::tun::TunRuntime,
    config: TunRuntimeConfig,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if !config.enabled {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "TUN runtime is disabled",
        ));
    }
    let proxy_id = match config.proxy_id.clone() {
        Some(proxy_id) if !proxy_id.trim().is_empty() => proxy_id,
        _ => crate::inbound::selected_proxy_id(&controller).await?,
    };
    let mut proxy_runtime = controller
        .build_tun_proxy_runtime_with_dns(
            &config.direct_id,
            &proxy_id,
            &config.bypass_id,
            &config.drop_id,
            Duration::from_secs(30),
            config.channel_capacity,
            Some(Arc::new(RuntimeDnsHandler {
                resolver: controller.handle().load().resolver.clone(),
            })),
        )
        .await?;
    let mut dispatcher = yuhaiin_core::tun::TunDispatcher::new(64 * 1024, 64 * 1024, 2048)?;
    tun.run_dispatcher_until(
        &mut dispatcher,
        &mut proxy_runtime,
        Duration::from_millis(10),
        async {
            let _ = wait_for_shutdown_or_reload(&controller, shutdown.clone()).await;
        },
    )
    .await
    .map_err(io_error)?;
    if *shutdown.borrow() {
        return Ok(());
    }
    Ok(())
}

/// Run the optional UDP DNS listener with the same reload and shutdown owner
/// used by the executable service.
pub async fn run_dns_supervisor(
    controller: RuntimeController,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        let server = controller
            .store()
            .get_config("resolver.server")
            .await?
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|value| {
                value
                    .get("server")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .filter(|server| !server.trim().is_empty());
        let Some(server) = server else {
            if wait_for_shutdown_or_reload(&controller, shutdown.clone()).await {
                return Ok(());
            }
            continue;
        };
        let address = parse_dns_server(&server, 53, "api-dns")?;
        let handler = RuntimeDnsHandler {
            resolver: controller.handle().load().resolver.clone(),
        };
        let dns =
            yuhaiin_core::dns_udp_async::AsyncUdpDnsServer::bind(address, handler, 4096).await?;
        dns.serve_until(async {
            let _ = wait_for_shutdown_or_reload(&controller, shutdown.clone()).await;
        })
        .await?;
        if *shutdown.borrow() {
            return Ok(());
        }
    }
}

#[cfg(feature = "tun")]
fn parse_ipv4(value: &Value) -> Option<(Ipv4Addr, u8)> {
    if let Some(value) = value.as_str() {
        let (address, prefix) = value.split_once('/')?;
        return Some((address.parse().ok()?, prefix.parse().ok()?));
    }
    let object = value.as_object()?;
    Some((
        object.get("address")?.as_str()?.parse().ok()?,
        object.get("prefix")?.as_u64()?.try_into().ok()?,
    ))
}

#[cfg(feature = "tun")]
fn parse_ipv6(value: &Value) -> Option<(Ipv6Addr, u8)> {
    if let Some(value) = value.as_str() {
        let (address, prefix) = value.split_once('/')?;
        return Some((address.parse().ok()?, prefix.parse().ok()?));
    }
    let object = value.as_object()?;
    Some((
        object.get("address")?.as_str()?.parse().ok()?,
        object.get("prefix")?.as_u64()?.try_into().ok()?,
    ))
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

#[cfg(feature = "tun")]
fn io_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(all(test, feature = "tun"))]
mod tests {
    use super::*;
    use crate::RuntimeBuilder;
    use std::sync::Arc;
    use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
    use yuhaiin_store::ConfigStore;

    #[tokio::test]
    async fn injected_tun_host_can_load_shared_persisted_config_without_opening_device() {
        let store = ConfigStore::open_memory().await.unwrap();
        let value = serde_json::json!({
            "enabled": true,
            "name": "vpn0",
            "ipv4": "10.23.0.1/24",
            "ipv6": ["fd23::1/64", {"address": "fd23::2", "prefix": 128}],
            "mtu": 1400,
            "queueCapacity": 64,
            "directId": "direct",
            "proxyId": "proxy",
            "bypassId": "bypass",
            "dropId": "drop",
            "channelCapacity": 32
        });
        store
            .put_config("tun.runtime", &serde_json::to_vec(&value).unwrap())
            .await
            .unwrap();

        let config = load_tun_config(&store).await.unwrap();
        assert!(config.enabled);
        assert_eq!(config.tun.name.as_deref(), Some("vpn0"));
        assert_eq!(config.tun.ipv4, Some((Ipv4Addr::new(10, 23, 0, 1), 24)));
        assert_eq!(config.tun.ipv6.len(), 2);
        assert_eq!(config.tun.mtu, 1400);
        assert_eq!(config.tun.queue_capacity, 64);
        assert_eq!(config.channel_capacity, 32);
        assert_eq!(config.proxy_id.as_deref(), Some("proxy"));
    }

    #[tokio::test]
    async fn injected_tun_host_keeps_device_creation_disabled_by_default() {
        let store = ConfigStore::open_memory().await.unwrap();
        let config = load_tun_config(&store).await.unwrap();
        assert!(!config.enabled);
        assert!(config.tun.ipv4.is_none());
        assert!(config.tun.ipv6.is_empty());
    }

    #[tokio::test]
    async fn disabled_supervisor_waits_for_reload_instead_of_only_shutdown() {
        let store = ConfigStore::open_memory().await.unwrap();
        let controller = crate::RuntimeController::from_builder(RuntimeBuilder::new(
            store,
            Arc::new(SystemAsyncIpResolver),
        ))
        .await
        .unwrap();
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let waiting_controller = controller.clone();
        let waiting = tokio::spawn(async move {
            wait_for_shutdown_or_reload(&waiting_controller, shutdown_rx).await
        });
        tokio::task::yield_now().await;
        controller.reload().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        assert!(!result);
    }
}
