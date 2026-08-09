//! Shared runtime data-plane owners.
//!
//! The binary is only one host for the runtime.  Android `VpnService`, iOS
//! `PacketTunnelProvider`, and future embedders can create their platform TUN
//! device themselves and hand the owned [`TunRuntime`] to the same runner.

#[cfg(all(feature = "tun", feature = "tun-routes"))]
use std::net::IpAddr;
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
#[cfg(feature = "tun")]
use yuhaiin_store::GoInboundRecord;

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
    /// Go's `TunProtocol.routes` and `excludes`, kept together because Go
    /// installs both lists through the same device route boundary.
    pub routes: Vec<String>,
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
    if let Some(config) = load_go_tun_config(store).await? {
        return Ok(config);
    }
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
        routes: Vec::new(),
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

/// Read the Go v6 plain-contract TUN inbound first. `tun.runtime` remains a
/// compatibility fallback for older Rust-only settings and embedders that
/// have not migrated their host configuration into `inbounds_v2` yet.
#[cfg(feature = "tun")]
async fn load_go_tun_config(
    store: &yuhaiin_store::ConfigStore,
) -> Result<Option<TunRuntimeConfig>> {
    let records = store.repository().list_go_inbounds().await?;
    let mut tun_records = records.into_iter().filter(|record| {
        record.protocol_type.eq_ignore_ascii_case("tun")
            || serde_json::from_slice::<Value>(&record.data_json)
                .ok()
                .and_then(|value| {
                    value
                        .pointer("/protocol/type")
                        .and_then(Value::as_str)
                        .map(|protocol| protocol.eq_ignore_ascii_case("tun"))
                })
                .unwrap_or(false)
    });
    let Some(record) = tun_records.next() else {
        return Ok(None);
    };
    if tun_records.next().is_some() {
        return Err(Error::invalid(
            "multiple enabled/defined TUN inbounds are not supported by the single-device runtime",
        ));
    }
    Ok(Some(parse_go_tun_config(&record)?))
}

#[cfg(feature = "tun")]
fn parse_go_tun_config(record: &GoInboundRecord) -> Result<TunRuntimeConfig> {
    let value: Value = serde_json::from_slice(&record.data_json)
        .map_err(|error| Error::invalid(format!("TUN inbound JSON: {error}")))?;
    let protocol = value.pointer("/protocol/tun").unwrap_or(&value);
    let name = protocol
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .map(normalize_tun_name)
        .transpose()?;
    let mtu = protocol
        .get("mtu")
        .and_then(Value::as_i64)
        .filter(|mtu| *mtu > 0)
        .unwrap_or(1500) as usize;
    let ipv4 = protocol.get("portal").and_then(parse_ipv4_string);
    let ipv6 = protocol
        .get("portalV6")
        .and_then(parse_ipv6_string)
        .into_iter()
        .collect();
    let routes = ["routes", "excludes"]
        .into_iter()
        .flat_map(|key| {
            protocol
                .get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flat_map(|values| values.iter())
                .filter_map(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    Ok(TunRuntimeConfig {
        enabled: record.enabled,
        tun: yuhaiin_core::tun::TunConfig {
            name,
            ipv4,
            ipv6,
            mtu,
            queue_capacity: 256,
        },
        routes,
        direct_id: String::new(),
        proxy_id: None,
        bypass_id: String::new(),
        drop_id: String::new(),
        channel_capacity: 256,
    })
}

#[cfg(feature = "tun")]
fn normalize_tun_name(name: &str) -> Result<String> {
    let name = name.strip_prefix("tun://").unwrap_or(name).trim();
    if name.is_empty() {
        return Err(Error::invalid("TUN inbound name is empty"));
    }
    if name.starts_with("fd://") {
        return Err(Error::new(
            ErrorKind::Unsupported,
            "TUN inbound uses an injected fd; desktop supervisor cannot open fd:// names",
        ));
    }
    Ok(name.to_owned())
}

#[cfg(feature = "tun")]
fn parse_ipv4_string(value: &Value) -> Option<(Ipv4Addr, u8)> {
    let text = value.as_str()?;
    let (address, prefix) = text.split_once('/')?;
    Some((address.parse().ok()?, prefix.parse().ok()?))
}

#[cfg(feature = "tun")]
fn parse_ipv6_string(value: &Value) -> Option<(Ipv6Addr, u8)> {
    let text = value.as_str()?;
    let (address, prefix) = text.split_once('/')?;
    Some((address.parse().ok()?, prefix.parse().ok()?))
}

#[cfg(all(feature = "tun", feature = "tun-routes"))]
fn parse_tun_routes(routes: &[String]) -> Result<Vec<yuhaiin_core::tun::TunRoute>> {
    routes
        .iter()
        .map(|value| {
            let (address, prefix) = value
                .split_once('/')
                .ok_or_else(|| Error::invalid(format!("TUN route lacks prefix: {value:?}")))?;
            let address: IpAddr = address
                .parse()
                .map_err(|error| Error::invalid(format!("TUN route address {value:?}: {error}")))?;
            let prefix = prefix
                .parse()
                .map_err(|error| Error::invalid(format!("TUN route prefix {value:?}: {error}")))?;
            yuhaiin_core::tun::TunRoute::new(address, prefix)
                .map_err(|error| Error::invalid(format!("TUN route {value:?}: {error}")))
        })
        .collect()
}

#[cfg(feature = "tun")]
pub(crate) fn open_tun(config: &TunRuntimeConfig) -> Result<yuhaiin_core::tun::TunRuntime> {
    let tun = yuhaiin_core::tun::TunRuntime::open(config.tun.clone()).map_err(io_error)?;
    if config.routes.is_empty() {
        return Ok(tun);
    }
    #[cfg(all(feature = "tun-routes", target_os = "linux"))]
    {
        let mut tun = tun;
        let routes = parse_tun_routes(&config.routes)?;
        tun.install_linux_routes(&routes).map_err(io_error)?;
        return Ok(tun);
    }
    #[cfg(not(all(feature = "tun-routes", target_os = "linux")))]
    {
        let _ = tun.shutdown();
        Err(Error::new(
            ErrorKind::Unsupported,
            "TUN inbound routes require the Linux tun-routes feature",
        ))
    }
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
    async fn go_tun_inbound_is_the_primary_config_source() {
        let store = ConfigStore::open_memory().await.unwrap();
        let value = serde_json::json!({
            "id": "tun",
            "name": "tun",
            "enabled": true,
            "network": {"type": "empty", "empty": {}},
            "transports": [],
            "protocol": {
                "type": "tun",
                "tun": {
                    "name": "tun://yuhaiin0",
                    "mtu": 1400,
                    "portal": "10.24.0.1/24",
                    "portalV6": "fd24::1/64",
                    "routes": ["198.18.0.0/15"],
                    "excludes": ["10.0.0.0/8"]
                }
            }
        });
        store
            .repository()
            .put_go_inbound(&GoInboundRecord {
                id: "tun".to_owned(),
                name: "tun".to_owned(),
                enabled: true,
                network_type: "empty".to_owned(),
                protocol_type: "tun".to_owned(),
                transport_types_json: br"[]".to_vec(),
                updated_at: 1,
                data_json: serde_json::to_vec(&value).unwrap(),
            })
            .await
            .unwrap();

        let config = load_tun_config(&store).await.unwrap();
        assert!(config.enabled);
        assert_eq!(config.tun.name.as_deref(), Some("yuhaiin0"));
        assert_eq!(config.tun.ipv4, Some((Ipv4Addr::new(10, 24, 0, 1), 24)));
        assert_eq!(config.tun.ipv6, vec![("fd24::1".parse().unwrap(), 64)]);
        assert_eq!(config.tun.mtu, 1400);
        assert_eq!(config.routes, ["198.18.0.0/15", "10.0.0.0/8"]);
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
