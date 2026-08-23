//! Shared runtime data-plane owners.
//!
//! The binary is only one host for the runtime.  Android `VpnService`, iOS
//! `PacketTunnelProvider`, and future embedders can create their platform TUN
//! device themselves and hand the owned [`TunRuntime`] to the same runner.

#[cfg(all(
    feature = "tun",
    feature = "tun-routes",
    any(target_os = "linux", target_os = "macos")
))]
use std::net::IpAddr;
#[cfg(feature = "tun")]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::watch;
use yuhaiin_core::dns::{
    AsyncDnsHandler, DnsRecordType, DnsResponse, decode_query, encode_response,
};
use yuhaiin_core::dns_resolver::AsyncIpResolver;
use yuhaiin_core::dns_tcp::AsyncTcpDnsServer;
use yuhaiin_core::{BoxFuture, Result, RouteMode};
#[cfg(feature = "tun")]
use yuhaiin_core::{Error, ErrorKind};
#[cfg(feature = "tun")]
use yuhaiin_store::GoInboundRecord;

use crate::{RuntimeController, RuntimeSnapshot, parse_dns_server};

const DEFAULT_DNS_SERVER: &str = "127.0.0.1:5353";

/// DNS packet handler backed by the resolver in the current immutable
/// runtime snapshot. TUN DNS hijacking and both DNS listener transports use
/// the same handler, so a reload cannot make them disagree about resolver
/// policy.
#[derive(Clone)]
pub struct RuntimeDnsHandler {
    pub resolver: Arc<dyn AsyncIpResolver>,
    pub fakeip: Option<yuhaiin_store::FakeIpPools>,
}

/// A live DNS handler slot for long-lived TUN runtimes.
///
/// Ordinary resolver reloads must update DNS policy without rebuilding the
/// TUN device or interrupting existing flows. The slot snapshots the current
/// handler for each query, so an in-flight query can finish on the old
/// immutable snapshot while the next query observes the new one.
#[derive(Clone, Default)]
pub(crate) struct ReloadableAsyncDnsHandler {
    current: Arc<RwLock<Option<RuntimeDnsHandler>>>,
}

#[derive(Clone)]
struct LoggedDnsHandler<H> {
    inner: H,
    monitor: Arc<crate::ConnectionMonitor>,
}

impl<H> AsyncDnsHandler for LoggedDnsHandler<H>
where
    H: AsyncDnsHandler + Clone + Send + Sync + 'static,
{
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        let inner = self.inner.clone();
        let monitor = Arc::clone(&self.monitor);
        Box::pin(async move {
            let result = inner.answer(packet).await;
            if let Err(error) = &result {
                let target = decode_query(packet)
                    .map(|query| format!("{} {:?}", query.domain, query.record_type))
                    .unwrap_or_else(|_| format!("packet_len={}", packet.len()));
                monitor.error(format!(
                    "DNS listener query failed target={target}: {error}"
                ));
            }
            result
        })
    }
}

impl ReloadableAsyncDnsHandler {
    pub(crate) fn new(handler: Option<RuntimeDnsHandler>) -> Self {
        Self {
            current: Arc::new(RwLock::new(handler)),
        }
    }

    pub(crate) fn replace(&self, handler: Option<RuntimeDnsHandler>) {
        *self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = handler;
    }
}

impl AsyncDnsHandler for ReloadableAsyncDnsHandler {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        let handler = self
            .current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        Box::pin(async move {
            match handler {
                Some(handler) => handler.answer(packet).await,
                None => Err(yuhaiin_core::Error::new(
                    yuhaiin_core::ErrorKind::Closed,
                    "TUN DNS hijacking is disabled",
                )),
            }
        })
    }
}

impl AsyncDnsHandler for RuntimeDnsHandler {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(self.answer_impl(packet))
    }
}

impl RuntimeDnsHandler {
    async fn answer_impl(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let question = match decode_query(packet) {
            Ok(question) => question,
            Err(error) if error.kind == yuhaiin_core::ErrorKind::Unsupported => {
                return self.resolver.query_packet(packet).await;
            }
            Err(error) => return Err(error),
        };
        if question.record_type == DnsRecordType::Ptr
            && let Some(fakeip) = &self.fakeip
            && let Some(domain) = fakeip.lookup_ptr_domain(&question.domain).await
        {
            return encode_response(
                packet,
                &DnsResponse {
                    addresses: yuhaiin_core::IpSet::default(),
                    ptr_names: vec![domain],
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(60),
                },
            );
        }
        let response = self
            .resolver
            .query(&question.domain, question.record_type)
            .await?;
        encode_response(packet, &response)
    }
}

impl crate::monitor::SocketDnsHandler for RuntimeDnsHandler {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(self.answer_impl(packet))
    }
}

/// Build the one DNS handler used by all inbound owners. Keeping this at the
/// snapshot boundary makes reloads choose the same resolver/FakeIP policy for
/// socket DNS and TUN DNS instead of letting each protocol invent its own.
pub(crate) fn inbound_dns_handler(
    snapshot: &RuntimeSnapshot,
) -> Result<Option<Arc<RuntimeDnsHandler>>> {
    if !snapshot.inbound_settings.hijack_dns {
        return Ok(None);
    }
    let resolver = if snapshot.inbound_settings.hijack_dns_fakeip {
        snapshot.inbound_resolver_for_route_mode(RouteMode::Proxy)?
    } else {
        snapshot.dns_resolver_for_route_mode(RouteMode::Proxy)?
    };
    Ok(Some(Arc::new(RuntimeDnsHandler {
        resolver,
        fakeip: snapshot.inbound_fakeip.clone(),
    })))
}

#[cfg(feature = "tun")]
#[derive(Debug, Clone)]
pub struct TunRuntimeConfig {
    pub inbound_id: Option<String>,
    pub enabled: bool,
    pub tun: yuhaiin_tun::TunConfig,
    /// Optional Go-compatible macOS network service override. An empty value
    /// follows the current default route service.
    pub network_service: Option<String>,
    /// Go's `TunProtocol.routes` and `excludes`, kept together because Go
    /// installs both lists through the same device route boundary.
    pub routes: Vec<String>,
    pub direct_id: String,
    pub proxy_id: Option<String>,
    pub bypass_id: String,
    pub drop_id: String,
    pub channel_capacity: usize,
    /// Per-socket smoltcp receive buffer. These are deliberately separate
    /// from the proxy task channel because every active endpoint owns them.
    pub socket_rx_buffer_size: usize,
    /// Per-socket smoltcp transmit buffer.
    pub socket_tx_buffer_size: usize,
    /// Number of datagrams each smoltcp UDP socket can queue in either
    /// direction.
    pub udp_packet_capacity: usize,
}

const DEFAULT_TUN_SOCKET_RX_BUFFER_SIZE: usize = 8 * 1024;
const DEFAULT_TUN_SOCKET_TX_BUFFER_SIZE: usize = 8 * 1024;
const DEFAULT_TUN_UDP_PACKET_CAPACITY: usize = 64;

fn tun_socket_settings(value: &Value) -> (usize, usize, usize) {
    fn bounded(value: Option<&Value>, default: usize, min: usize, max: usize) -> usize {
        value
            .and_then(Value::as_u64)
            .map(|value| (value as usize).clamp(min, max))
            .unwrap_or(default)
    }

    (
        bounded(
            value
                .get("socketRxBufferSize")
                .or_else(|| value.get("socket_rx_buffer_size")),
            DEFAULT_TUN_SOCKET_RX_BUFFER_SIZE,
            4 * 1024,
            1024 * 1024,
        ),
        bounded(
            value
                .get("socketTxBufferSize")
                .or_else(|| value.get("socket_tx_buffer_size")),
            DEFAULT_TUN_SOCKET_TX_BUFFER_SIZE,
            4 * 1024,
            1024 * 1024,
        ),
        bounded(
            value
                .get("udpPacketCapacity")
                .or_else(|| value.get("udp_packet_capacity")),
            DEFAULT_TUN_UDP_PACKET_CAPACITY,
            4,
            4096,
        ),
    )
}

/// Load the persisted TUN settings without opening a platform device.  A
/// mobile host can use this to validate the shared config, create its
/// `AsyncDevice::from_fd`, then call [`run_tun_device_until`].
#[cfg(feature = "tun")]
pub async fn load_tun_config(store: &yuhaiin_store::ConfigStore) -> Result<TunRuntimeConfig> {
    if let Some(mut config) = load_go_tun_config(store).await? {
        if !crate::RuntimeSettings::load(store).await?.ipv6 {
            config.tun.ipv6.clear();
        }
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
    let (socket_rx_buffer_size, socket_tx_buffer_size, udp_packet_capacity) =
        tun_socket_settings(&value);
    let tun = yuhaiin_tun::TunConfig {
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
        skip_multicast: value
            .get("skipMulticast")
            .or_else(|| value.get("skip_multicast"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
    };
    let mut config = TunRuntimeConfig {
        inbound_id: None,
        enabled,
        tun,
        network_service: parse_network_service(&value),
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
        socket_rx_buffer_size,
        socket_tx_buffer_size,
        udp_packet_capacity,
    };
    if !crate::RuntimeSettings::load(store).await?.ipv6 {
        config.tun.ipv6.clear();
    }
    Ok(config)
}

/// Read the Go v6 plain-contract TUN inbound first. `tun.runtime` remains a
/// compatibility fallback for older Rust-only settings and embedders that
/// have not migrated their host configuration into `inbounds_v2` yet.
#[cfg(feature = "tun")]
async fn load_go_tun_config(
    store: &yuhaiin_store::ConfigStore,
) -> Result<Option<TunRuntimeConfig>> {
    let records = store.repository().list_go_inbounds().await?;
    let Some(record) = select_go_tun_record(records)? else {
        return Ok(None);
    };
    Ok(Some(parse_go_tun_config(&record)?))
}

/// Load every Go-shaped TUN inbound for the desktop supervisor.
///
/// The injected-FD/mobile entry point intentionally remains single-device,
/// but Go's desktop listener owner creates one TUN device per enabled inbound.
/// Keep the records sorted before assigning fallback names so a config reload
/// cannot swap `yrtun0`/`yrtun1` merely because SQLite returned rows in a
/// different order.
#[cfg(feature = "tun")]
pub(crate) async fn load_tun_configs_for_desktop(
    store: &yuhaiin_store::ConfigStore,
) -> Result<Vec<TunRuntimeConfig>> {
    if let Some(mut configs) = load_go_tun_configs(store).await? {
        if !crate::RuntimeSettings::load(store).await?.ipv6 {
            for config in &mut configs {
                config.tun.ipv6.clear();
            }
        }
        return Ok(configs);
    }
    Ok(vec![load_tun_config(store).await?])
}

#[cfg(feature = "tun")]
async fn load_go_tun_configs(
    store: &yuhaiin_store::ConfigStore,
) -> Result<Option<Vec<TunRuntimeConfig>>> {
    let mut records: Vec<_> = store
        .repository()
        .list_go_inbounds()
        .await?
        .into_iter()
        .filter(is_tun_record)
        .collect();
    if records.is_empty() {
        return Ok(None);
    }
    records.sort_by(|left, right| left.id.cmp(&right.id));

    let mut configs = Vec::with_capacity(records.len());
    for (index, record) in records.iter().enumerate() {
        let mut config = parse_go_tun_config(record)?;
        if config.tun.name.is_none() {
            config.tun.name = Some(format!("yrtun{index}"));
        }
        configs.push(config);
    }
    let mut names = Vec::with_capacity(configs.len());
    for config in &configs {
        if !config.enabled {
            continue;
        }
        let Some(name) = config.tun.name.as_deref() else {
            continue;
        };
        if names.iter().any(|known| known == name) {
            return Err(Error::invalid(format!(
                "multiple TUN inbounds use the same device name {name:?}"
            )));
        }
        names.push(name.to_owned());
    }
    Ok(Some(configs))
}

/// Select the one TUN device that an injected-FD/mobile runtime can own.
///
/// Go stores disabled inbound definitions alongside the active ones. In
/// particular, a fresh database contains a disabled `tun` default, so an API
/// client adding its own enabled TUN must not be rejected merely because that
/// compatibility row exists. Multiple enabled TUNs remain invalid for this
/// single-FD API; the desktop supervisor uses
/// [`load_tun_configs_for_desktop`] instead. When all TUNs are disabled we
/// keep the newest definition so editing a disabled inbound is reflected on
/// the next enable.
#[cfg(feature = "tun")]
fn select_go_tun_record(records: Vec<GoInboundRecord>) -> Result<Option<GoInboundRecord>> {
    let tun_records: Vec<_> = records.into_iter().filter(is_tun_record).collect();
    let enabled_count = tun_records.iter().filter(|record| record.enabled).count();
    if enabled_count > 1 {
        return Err(Error::invalid(
            "multiple enabled TUN inbounds cannot share one injected TUN device",
        ));
    }
    Ok(tun_records.into_iter().max_by(|left, right| {
        left.enabled
            .cmp(&right.enabled)
            .then_with(|| left.updated_at.cmp(&right.updated_at))
            .then_with(|| left.id.cmp(&right.id))
    }))
}

#[cfg(feature = "tun")]
fn is_tun_record(record: &GoInboundRecord) -> bool {
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
}

/// Reload the TUN switch for an externally-owned device without accidentally
/// disabling embedders that keep their TUN configuration outside SQLite.
///
/// Desktop service runs can always derive their device from the persisted Go
/// inbound, while Android/iOS hosts may pass a `TunRuntimeConfig` created by
/// the platform VPN API.  The latter uses the fallback until a persisted Go
/// TUN record or Rust overlay exists.  Once either source exists, the store is
/// authoritative, including `enabled = false`.
#[cfg(feature = "tun")]
pub(crate) async fn load_tun_config_for_supervisor(
    store: &yuhaiin_store::ConfigStore,
    fallback: TunRuntimeConfig,
) -> Result<TunRuntimeConfig> {
    let has_overlay = store.get_config("tun.runtime").await?.is_some();
    let has_go_tun = store
        .repository()
        .list_go_inbounds()
        .await?
        .iter()
        .any(is_tun_record);
    if has_overlay || has_go_tun {
        load_tun_config(store).await
    } else {
        Ok(fallback)
    }
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
    let skip_multicast = protocol
        .get("skipMulticast")
        .or_else(|| protocol.get("skip_multicast"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (socket_rx_buffer_size, socket_tx_buffer_size, udp_packet_capacity) =
        tun_socket_settings(protocol);
    Ok(TunRuntimeConfig {
        inbound_id: Some(record.id.clone()),
        enabled: record.enabled,
        tun: yuhaiin_tun::TunConfig {
            name,
            ipv4,
            ipv6,
            mtu,
            queue_capacity: 256,
            skip_multicast,
        },
        network_service: parse_network_service(protocol),
        routes,
        direct_id: String::new(),
        proxy_id: None,
        bypass_id: String::new(),
        drop_id: String::new(),
        channel_capacity: 256,
        socket_rx_buffer_size,
        socket_tx_buffer_size,
        udp_packet_capacity,
    })
}

#[cfg(feature = "tun")]
fn parse_network_service(value: &Value) -> Option<String> {
    [
        value.get("networkService"),
        value.get("network_service"),
        value.pointer("/platform/darwin/networkService"),
        value.pointer("/platform/darwin/network_service"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .map(str::trim)
    .find(|service| !service.is_empty())
    .map(str::to_owned)
}

#[cfg(feature = "tun")]
fn normalize_tun_name(name: &str) -> Result<String> {
    let name = name.strip_prefix("tun://").unwrap_or(name).trim();
    if name.is_empty() {
        return Err(Error::invalid("TUN inbound name is empty"));
    }
    if name.starts_with("fd://") {
        #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
        {
            return Ok(name.to_owned());
        }
        #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "TUN inbound uses an injected fd; desktop supervisor cannot open fd:// names",
            ));
        }
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

#[cfg(all(
    feature = "tun",
    feature = "tun-routes",
    any(target_os = "linux", target_os = "macos")
))]
fn parse_tun_routes(routes: &[String]) -> Result<Vec<yuhaiin_tun::TunRoute>> {
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
            yuhaiin_tun::TunRoute::new(address, prefix)
                .map_err(|error| Error::invalid(format!("TUN route {value:?}: {error}")))
        })
        .collect()
}

#[cfg(feature = "tun")]
pub(crate) fn open_tun(config: &TunRuntimeConfig) -> Result<yuhaiin_tun::TunRuntime> {
    let mut tun = yuhaiin_tun::TunRuntime::open(config.tun.clone()).map_err(io_error)?;
    #[cfg(target_os = "macos")]
    {
        tun.install_macos_dns(
            config.network_service.as_deref(),
            &tun_dns_servers(&config.tun),
        );
    }
    #[cfg(not(all(feature = "tun-routes", target_os = "macos")))]
    if config.routes.is_empty() {
        return Ok(tun);
    }
    #[cfg(all(feature = "tun-routes", target_os = "linux"))]
    {
        let routes = parse_tun_routes(&config.routes)?;
        for route in &routes {
            match route.destination {
                IpAddr::V4(address) => {
                    let prefix = config.tun.ipv4.map(|(_, prefix)| prefix).unwrap_or(32);
                    tun.prepend_ipv4_address(address, prefix)?;
                }
                IpAddr::V6(address) => {
                    let prefix = config
                        .tun
                        .ipv6
                        .iter()
                        .find(|(_, configured_prefix)| *configured_prefix <= route.prefix)
                        .map(|(_, prefix)| *prefix)
                        .unwrap_or(route.prefix);
                    tun.prepend_ipv6_address(address, prefix)?;
                }
            }
        }
        tun.install_linux_routes(&routes).map_err(io_error)?;
        Ok(tun)
    }
    #[cfg(all(feature = "tun-routes", target_os = "macos"))]
    {
        let mut routes = parse_tun_routes(&config.routes)?;
        // Go's Darwin route setup always adds the portal subnet as a route
        // for the DNS/virtual gateway, even when the user supplied no other
        // route. The address itself is the next hop on the utun interface.
        if let Some((address, prefix)) = config.tun.ipv4
            && let Some(destination) = u32::from(address).checked_add(1).map(Ipv4Addr::from)
        {
            let portal_route = yuhaiin_tun::TunRoute::new(IpAddr::V4(destination), prefix)?;
            if !routes.iter().any(|route| {
                route.network() == portal_route.network() && route.prefix == portal_route.prefix
            }) {
                routes.push(portal_route);
            }
        }
        if routes.is_empty() {
            return Ok(tun);
        }
        tun.install_macos_routes(
            &routes,
            config.tun.ipv4.map(|(address, _)| address),
            config.tun.ipv6.first().map(|(address, _)| *address),
        )
        .map_err(io_error)?;
        Ok(tun)
    }
    #[cfg(not(any(
        all(feature = "tun-routes", target_os = "linux"),
        all(feature = "tun-routes", target_os = "macos")
    )))]
    {
        let _ = tun.shutdown();
        Err(Error::new(
            ErrorKind::Unsupported,
            "TUN inbound routes require the Linux or macOS tun-routes feature",
        ))
    }
}

#[cfg(all(feature = "tun", any(target_os = "macos", test)))]
fn tun_dns_servers(config: &yuhaiin_tun::TunConfig) -> Vec<std::net::IpAddr> {
    let mut servers = Vec::with_capacity(1 + config.ipv6.len());
    if let Some((address, _)) = config.ipv4
        && let Some(next) = u32::from(address)
            .checked_add(1)
            .map(std::net::Ipv4Addr::from)
    {
        servers.push(std::net::IpAddr::V4(next));
    }
    for (address, _) in &config.ipv6 {
        if let Some(next) = u128::from(*address)
            .checked_add(1)
            .map(std::net::Ipv6Addr::from)
        {
            servers.push(std::net::IpAddr::V6(next));
        }
    }
    servers
}

/// Run one already-created TUN device through the shared runtime snapshot.
/// The caller owns device creation and can therefore inject a mobile VPN fd;
/// this function owns dispatcher, proxy runtime, inbound input policy and
/// shutdown ordering only.
#[cfg(feature = "tun")]
pub async fn run_tun_device_until(
    controller: RuntimeController,
    tun: yuhaiin_tun::TunRuntime,
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
    tun: &mut yuhaiin_tun::TunRuntime,
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
    let mut inbound_interceptor =
        crate::inbound::InboundInputInterceptor::new(controller.monitor(), config.channel_capacity);
    controller.monitor().info("TUN inbound ready");
    let mut dispatcher = yuhaiin_tun::TunDispatcher::new(
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
        let udp = match yuhaiin_core::dns::AsyncUdpDnsServer::bind(
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
async fn configured_dns_server(store: &yuhaiin_store::ConfigStore) -> Result<Option<String>> {
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

#[cfg(feature = "tun")]
fn io_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(all(test, feature = "tun"))]
mod tests {
    use super::*;
    use crate::RuntimeBuilder;
    use std::sync::Arc;
    use yuhaiin_core::dns::{
        AsyncDnsHandler, DnsRecordType, DnsResponse, DnsServiceBinding, DnsServiceParam,
        decode_query, decode_response, encode_query, encode_raw_query,
    };
    use yuhaiin_core::dns::{AsyncUdpDnsClient, AsyncUdpDnsServer};
    use yuhaiin_core::dns_resolver::{AsyncIpResolver, SystemAsyncIpResolver};
    use yuhaiin_core::dns_tcp::{AsyncTcpDnsClient, AsyncTcpDnsServer};
    use yuhaiin_core::{BoxFuture, DomainName, ErrorKind, IpSet, ResolveStrategy};
    use yuhaiin_store::fakeip::{FakeIpConfig, FakeIpPool, FakeIpV6Config, FakeIpV6Pool};
    use yuhaiin_store::{ConfigStore, FakeIpPools, FakeIpResolver};

    fn platform_tun_config(enabled: bool) -> TunRuntimeConfig {
        TunRuntimeConfig {
            inbound_id: None,
            enabled,
            tun: yuhaiin_tun::TunConfig {
                name: Some("platform-vpn".to_owned()),
                ipv4: Some((Ipv4Addr::new(10, 42, 0, 1), 24)),
                ..Default::default()
            },
            network_service: None,
            routes: Vec::new(),
            direct_id: "direct".to_owned(),
            proxy_id: Some("proxy".to_owned()),
            bypass_id: String::new(),
            drop_id: String::new(),
            channel_capacity: 256,
            socket_rx_buffer_size: DEFAULT_TUN_SOCKET_RX_BUFFER_SIZE,
            socket_tx_buffer_size: DEFAULT_TUN_SOCKET_TX_BUFFER_SIZE,
            udp_packet_capacity: DEFAULT_TUN_UDP_PACKET_CAPACITY,
        }
    }

    #[test]
    fn tun_socket_defaults_use_bounded_per_flow_buffers() {
        let config = platform_tun_config(true);
        assert_eq!(config.socket_rx_buffer_size, 8 * 1024);
        assert_eq!(config.socket_tx_buffer_size, 8 * 1024);
    }

    fn go_tun_record(id: &str, enabled: bool, updated_at: i64) -> GoInboundRecord {
        let data = serde_json::json!({
            "id": id,
            "name": id,
            "enabled": enabled,
            "network": {"type": "empty", "empty": {}},
            "transports": [],
            "protocol": {
                "type": "tun",
                "tun": {
                    "name": format!("tun://{id}"),
                    "portal": "10.42.0.1/24"
                }
            }
        });
        GoInboundRecord {
            id: id.to_owned(),
            name: id.to_owned(),
            enabled,
            network_type: "empty".to_owned(),
            protocol_type: "tun".to_owned(),
            transport_types_json: br"[]".to_vec(),
            updated_at,
            data_json: serde_json::to_vec(&data).unwrap(),
        }
    }

    #[test]
    fn go_tun_selection_ignores_disabled_default_when_custom_tun_is_enabled() {
        let selected = select_go_tun_record(vec![
            go_tun_record("tun", false, 0),
            go_tun_record("custom", true, 1),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(selected.id, "custom");
    }

    #[test]
    fn go_tun_selection_rejects_multiple_enabled_devices() {
        let error = select_go_tun_record(vec![
            go_tun_record("first", true, 1),
            go_tun_record("second", true, 2),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("multiple enabled TUN"));
    }

    #[test]
    fn go_tun_selection_keeps_newest_disabled_definition() {
        let selected = select_go_tun_record(vec![
            go_tun_record("older", false, 1),
            go_tun_record("newer", false, 2),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(selected.id, "newer");
    }

    #[tokio::test]
    async fn desktop_tun_loader_keeps_all_enabled_go_inbounds() {
        let store = ConfigStore::open_memory().await.unwrap();
        for (id, enabled) in [("default", false), ("alpha", true), ("beta", true)] {
            store
                .repository()
                .put_go_inbound(&go_tun_record(id, enabled, 1))
                .await
                .unwrap();
        }

        let configs = load_tun_configs_for_desktop(&store).await.unwrap();
        assert_eq!(configs.len(), 3);
        assert_eq!(
            configs
                .iter()
                .map(|config| config.tun.name.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("alpha"), Some("beta"), Some("default")]
        );
        assert_eq!(configs.iter().filter(|config| config.enabled).count(), 2);
    }

    #[tokio::test]
    async fn desktop_tun_loader_rejects_duplicate_enabled_device_names() {
        let store = ConfigStore::open_memory().await.unwrap();
        let mut first = go_tun_record("first", true, 1);
        let mut second = go_tun_record("second", true, 2);
        for record in [&mut first, &mut second] {
            let mut value: Value = serde_json::from_slice(&record.data_json).unwrap();
            value["protocol"]["tun"]["name"] = Value::String("tun://shared".to_owned());
            record.data_json = serde_json::to_vec(&value).unwrap();
            store.repository().put_go_inbound(record).await.unwrap();
        }

        let error = load_tun_configs_for_desktop(&store).await.unwrap_err();
        assert!(error.to_string().contains("same device name"));
    }

    #[tokio::test]
    async fn inbound_dns_handler_uses_the_route_resolver_for_hijacked_queries() {
        let store = ConfigStore::open_memory().await.unwrap();
        let mut snapshot = RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver))
            .build()
            .await
            .unwrap();
        snapshot.resolver = Arc::new(FixedAddressResolver {
            address: Ipv4Addr::new(192, 0, 2, 1),
        });
        snapshot.dns_resolver = Arc::new(FixedAddressResolver {
            address: Ipv4Addr::new(192, 0, 2, 2),
        });
        snapshot.inbound_resolver = Arc::new(FixedAddressResolver {
            address: Ipv4Addr::new(192, 0, 2, 3),
        });
        snapshot.resolver_by_id.insert(
            "bootstrap".to_owned(),
            Arc::new(FixedAddressResolver {
                address: Ipv4Addr::new(192, 0, 2, 53),
            }),
        );
        snapshot.dns_resolver_by_id.insert(
            "bootstrap".to_owned(),
            Arc::new(FixedAddressResolver {
                address: Ipv4Addr::new(192, 0, 2, 54),
            }),
        );
        snapshot.inbound_resolver_by_id.insert(
            "bootstrap".to_owned(),
            Arc::new(FixedAddressResolver {
                address: Ipv4Addr::new(192, 0, 2, 53),
            }),
        );
        snapshot.resolver_registry_enabled = true;
        snapshot.route.as_mut().unwrap().proxy_resolver = "bootstrap".to_owned();
        snapshot.inbound_settings.hijack_dns = true;

        let domain = DomainName::new("route-selected.example.test").unwrap();
        let packet = encode_query(0x5353, &domain, DnsRecordType::A).unwrap();

        snapshot.inbound_settings.hijack_dns_fakeip = true;
        let handler = inbound_dns_handler(&snapshot).unwrap().unwrap();
        let response = handler.answer(&packet).await.unwrap();
        assert_eq!(
            decode_response(&response, 0x5353, DnsRecordType::A)
                .unwrap()
                .addresses
                .v4,
            vec![Ipv4Addr::new(192, 0, 2, 53)]
        );

        snapshot.inbound_settings.hijack_dns_fakeip = false;
        let handler = inbound_dns_handler(&snapshot).unwrap().unwrap();
        let response = handler.answer(&packet).await.unwrap();
        assert_eq!(
            decode_response(&response, 0x5353, DnsRecordType::A)
                .unwrap()
                .addresses
                .v4,
            vec![Ipv4Addr::new(192, 0, 2, 54)]
        );
    }

    #[tokio::test]
    async fn inbound_dns_handler_reports_a_missing_route_resolver() {
        let store = ConfigStore::open_memory().await.unwrap();
        let mut snapshot = RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver))
            .build()
            .await
            .unwrap();
        snapshot.inbound_settings.hijack_dns = true;
        snapshot.resolver_registry_enabled = true;
        snapshot.route.as_mut().unwrap().proxy_resolver = "missing".to_owned();

        let error = match inbound_dns_handler(&snapshot) {
            Ok(_) => panic!("missing route resolver unexpectedly produced a DNS handler"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::NotFound);
        assert!(error.message.contains("missing"));
    }

    #[tokio::test]
    async fn inbound_fakeip_is_available_when_global_fakedns_is_disabled() {
        let store = ConfigStore::open_memory().await.unwrap();
        let mut snapshot = RuntimeBuilder::new(store, Arc::new(SystemAsyncIpResolver))
            .build()
            .await
            .unwrap();
        assert!(snapshot.fakeip.is_none());
        let pools = snapshot
            .inbound_fakeip
            .clone()
            .expect("inbound FakeIP should not depend on global FakeDNS");
        snapshot.inbound_settings.hijack_dns = true;
        snapshot.inbound_settings.hijack_dns_fakeip = true;
        snapshot.inbound_resolver = Arc::new(FakeIpResolver::new(
            Arc::new(FixedAddressResolver {
                address: Ipv4Addr::new(192, 0, 2, 7),
            }),
            pools.clone(),
            false,
        ));

        let domain = DomainName::new("inbound-only-fakeip.example.test").unwrap();
        let packet = encode_query(0x5454, &domain, DnsRecordType::A).unwrap();
        let handler = inbound_dns_handler(&snapshot).unwrap().unwrap();
        let response = handler.answer(&packet).await.unwrap();
        let address = decode_response(&response, 0x5454, DnsRecordType::A)
            .unwrap()
            .addresses
            .v4[0];
        assert_eq!(address.octets()[0], 10);
        assert_eq!(
            pools.view_store().lookup_domain_ip(address.into()),
            Some(domain)
        );
    }

    struct ServiceBindingResolver;

    struct FixedAddressResolver {
        address: Ipv4Addr,
    }

    struct RawPacketResolver;

    impl AsyncIpResolver for RawPacketResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            Box::pin(async { Ok(IpSet::default()) })
        }

        fn query_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
            Box::pin(async move {
                assert_eq!(
                    decode_query(packet).unwrap_err().kind,
                    ErrorKind::Unsupported
                );
                let mut response = packet.to_vec();
                response[2] |= 0x80;
                Ok(response)
            })
        }
    }

    impl AsyncIpResolver for FixedAddressResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            Box::pin(async move {
                Ok(IpSet {
                    v4: vec![self.address],
                    v6: Vec::new(),
                })
            })
        }
    }

    impl AsyncIpResolver for ServiceBindingResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            Box::pin(async { Ok(IpSet::default()) })
        }

        fn query<'a>(
            &'a self,
            _domain: &'a DomainName,
            _record_type: DnsRecordType,
        ) -> BoxFuture<'a, Result<DnsResponse>> {
            Box::pin(async {
                Ok(DnsResponse {
                    addresses: IpSet::default(),
                    ptr_names: Vec::new(),
                    service_bindings: vec![DnsServiceBinding {
                        priority: 1,
                        target: Some(DomainName::new("origin.example.test").unwrap()),
                        params: vec![
                            DnsServiceParam::Alpn(vec!["h2".to_owned()]),
                            DnsServiceParam::Port(8443),
                        ],
                    }],
                    minimum_ttl: Some(42),
                })
            })
        }
    }

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
            "channelCapacity": 32,
            "socketRxBufferSize": 8192,
            "socketTxBufferSize": 12288,
            "udpPacketCapacity": 32
        });
        store
            .put_config("tun.runtime", &serde_json::to_vec(&value).unwrap())
            .await
            .unwrap();
        store
            .put_config("settings", br#"{"ipv6":true}"#)
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
        assert_eq!(config.socket_rx_buffer_size, 8192);
        assert_eq!(config.socket_tx_buffer_size, 12288);
        assert_eq!(config.udp_packet_capacity, 32);
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
                    "platform": {"darwin": {"network_service": "Wi-Fi"}},
                    "skipMulticast": true,
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
        store
            .put_config("settings", br#"{"ipv6":true}"#)
            .await
            .unwrap();

        let config = load_tun_config(&store).await.unwrap();
        assert!(config.enabled);
        assert_eq!(config.tun.name.as_deref(), Some("yuhaiin0"));
        assert_eq!(config.tun.ipv4, Some((Ipv4Addr::new(10, 24, 0, 1), 24)));
        assert_eq!(config.tun.ipv6, vec![("fd24::1".parse().unwrap(), 64)]);
        assert_eq!(config.network_service.as_deref(), Some("Wi-Fi"));
        assert!(config.tun.skip_multicast);
        assert_eq!(config.tun.mtu, 1400);
        assert_eq!(config.routes, ["198.18.0.0/15", "10.0.0.0/8"]);
    }

    #[test]
    fn macos_tun_dns_servers_follow_go_gateway_next_addresses() {
        let config = yuhaiin_tun::TunConfig {
            ipv4: Some((Ipv4Addr::new(10, 24, 0, 1), 24)),
            ipv6: vec![("fd24::1".parse().unwrap(), 64)],
            ..Default::default()
        };
        assert_eq!(
            tun_dns_servers(&config),
            vec![
                "10.24.0.2".parse::<std::net::IpAddr>().unwrap(),
                "fd24::2".parse::<std::net::IpAddr>().unwrap(),
            ]
        );
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
    async fn injected_tun_supervisor_keeps_platform_config_without_persisted_tun() {
        let store = ConfigStore::open_memory().await.unwrap();
        let fallback = platform_tun_config(true);
        let config = load_tun_config_for_supervisor(&store, fallback.clone())
            .await
            .unwrap();
        assert_eq!(config.enabled, fallback.enabled);
        assert_eq!(config.tun.name, fallback.tun.name);
    }

    #[tokio::test]
    async fn injected_tun_supervisor_honors_persisted_disable_after_reload() {
        let store = ConfigStore::open_memory().await.unwrap();
        store
            .put_config(
                "tun.runtime",
                br#"{"enabled":false,"name":"platform-vpn","ipv4":"10.42.0.1/24"}"#,
            )
            .await
            .unwrap();
        let config = load_tun_config_for_supervisor(&store, platform_tun_config(true))
            .await
            .unwrap();
        assert!(!config.enabled);
        assert_eq!(config.tun.name.as_deref(), Some("platform-vpn"));
    }

    #[tokio::test]
    async fn dns_server_overlay_is_used_before_legacy_database_fallback() {
        let store = ConfigStore::open_memory().await.unwrap();
        store
            .put_config("resolver.server", br#"{"server":"127.0.0.1:5353"}"#)
            .await
            .unwrap();
        assert_eq!(
            configured_dns_server(&store).await.unwrap().as_deref(),
            Some("127.0.0.1:5353")
        );
    }

    #[tokio::test]
    async fn empty_store_uses_go_default_dns_server() {
        let store = ConfigStore::open_memory().await.unwrap();
        assert_eq!(
            configured_dns_server(&store).await.unwrap().as_deref(),
            Some(DEFAULT_DNS_SERVER)
        );
    }

    #[tokio::test]
    async fn dns_server_binds_udp_and_tcp_on_the_same_configured_address() {
        let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = probe.local_addr().unwrap();
        drop(probe);
        let handler = RuntimeDnsHandler {
            resolver: Arc::new(SystemAsyncIpResolver),
            fakeip: None,
        };
        let udp = yuhaiin_core::dns::AsyncUdpDnsServer::bind(address, handler.clone(), 4096)
            .await
            .unwrap();
        let tcp = AsyncTcpDnsServer::bind(address, handler, 65535, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(udp.local_addr().unwrap(), address);
        assert_eq!(tcp.local_addr().unwrap(), address);
    }

    #[tokio::test]
    async fn runtime_dns_preserves_https_service_bindings() {
        let domain = DomainName::new("service.example.test").unwrap();
        let packet = encode_query(0x5151, &domain, DnsRecordType::Https).unwrap();
        let handler = RuntimeDnsHandler {
            resolver: Arc::new(ServiceBindingResolver),
            fakeip: None,
        };

        let response = handler.answer(&packet).await.unwrap();
        let decoded = decode_response(&response, 0x5151, DnsRecordType::Https).unwrap();
        assert_eq!(decoded.minimum_ttl, Some(42));
        assert_eq!(decoded.service_bindings.len(), 1);
        assert_eq!(
            decoded.service_bindings[0].target,
            Some(DomainName::new("origin.example.test").unwrap())
        );
        assert!(
            decoded.service_bindings[0]
                .params
                .contains(&DnsServiceParam::Alpn(vec!["h2".to_owned()]))
        );
        assert!(
            decoded.service_bindings[0]
                .params
                .contains(&DnsServiceParam::Port(8443))
        );
    }

    #[tokio::test]
    async fn runtime_dns_forwards_unmodeled_qtypes_to_the_resolver() {
        use yuhaiin_core::dns::{decode_query, encode_raw_query};

        struct RawResolver;

        impl AsyncIpResolver for RawResolver {
            fn resolve<'a>(
                &'a self,
                _domain: &'a DomainName,
                _strategy: ResolveStrategy,
            ) -> BoxFuture<'a, Result<IpSet>> {
                Box::pin(async { Ok(IpSet::default()) })
            }

            fn query_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
                Box::pin(async move {
                    assert_eq!(
                        decode_query(packet).unwrap_err().kind,
                        ErrorKind::Unsupported
                    );
                    let mut response = packet.to_vec();
                    response[2] |= 0x80;
                    Ok(response)
                })
            }
        }

        let query =
            encode_raw_query(0x6161, &DomainName::new("example.test").unwrap(), 16).unwrap();
        let handler = RuntimeDnsHandler {
            resolver: Arc::new(RawResolver),
            fakeip: None,
        };
        let response = handler.answer(&query).await.unwrap();
        assert_eq!(response, {
            let mut expected = query.clone();
            expected[2] |= 0x80;
            expected
        });
    }

    #[tokio::test]
    async fn runtime_dns_servers_forward_unmodeled_qtypes_over_udp_and_tcp() {
        let query =
            encode_raw_query(0x7171, &DomainName::new("example.test").unwrap(), 16).unwrap();
        let handler = RuntimeDnsHandler {
            resolver: Arc::new(RawPacketResolver),
            fakeip: None,
        };

        let udp_server =
            AsyncUdpDnsServer::bind("127.0.0.1:0".parse().unwrap(), handler.clone(), 2048)
                .await
                .unwrap();
        let udp_client = AsyncUdpDnsClient::new(
            udp_server.local_addr().unwrap(),
            Duration::from_secs(1),
            2048,
            Arc::from(Vec::new().into_boxed_slice()),
            None,
        );
        let (udp_server_result, udp_response) =
            tokio::join!(udp_server.serve_once(), udp_client.query_packet(&query));
        assert!(udp_server_result.unwrap() > 0);
        let mut expected = query.clone();
        expected[2] |= 0x80;
        assert_eq!(udp_response.unwrap(), expected);

        let tcp_server = AsyncTcpDnsServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            handler,
            2048,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let tcp_client = AsyncTcpDnsClient {
            server: tcp_server.local_addr().unwrap(),
            timeout: Duration::from_secs(1),
            max_packet_size: 2048,
            local_bind_addresses: Arc::from(Vec::new().into_boxed_slice()),
            bind_interface: None,
        };
        let (tcp_server_result, tcp_response) =
            tokio::join!(tcp_server.serve_once(), tcp_client.query_packet(&query));
        assert!(tcp_server_result.unwrap() > 2);
        assert_eq!(tcp_response.unwrap(), expected);
    }

    #[tokio::test]
    async fn runtime_dns_returns_preloaded_fakeip_ptr_mapping() {
        let store = ConfigStore::open_memory().await.unwrap();
        let pool = Arc::new(
            FakeIpPool::open(
                store.clone(),
                FakeIpConfig::new("198.18.0.1".parse().unwrap(), "198.18.0.8".parse().unwrap())
                    .unwrap(),
            )
            .await
            .unwrap(),
        );
        let ipv6 = Arc::new(
            FakeIpV6Pool::open(
                store,
                FakeIpV6Config::new("fc00::1".parse().unwrap(), "fc00::8".parse().unwrap())
                    .unwrap(),
            )
            .await
            .unwrap(),
        );
        let pools = FakeIpPools::new(pool, ipv6);
        let original = DomainName::new("ptr.example.test").unwrap();
        let address = pools.ipv4.allocate(original.clone()).await.unwrap();
        let octets = address.octets();
        let reverse_name = format!(
            "{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]
        );
        let reverse = DomainName::new(&reverse_name).unwrap();
        let packet = encode_query(0x4242, &reverse, DnsRecordType::Ptr).unwrap();
        let handler = RuntimeDnsHandler {
            resolver: Arc::new(SystemAsyncIpResolver),
            fakeip: Some(pools),
        };

        let response = handler.answer(&packet).await.unwrap();
        let decoded = decode_response(&response, 0x4242, DnsRecordType::Ptr).unwrap();
        assert_eq!(decoded.ptr_names, vec![original]);
        assert_eq!(decoded.minimum_ttl, Some(60));
    }

    #[tokio::test]
    async fn reloadable_tun_dns_handler_switches_snapshots_without_rebuilding_owner() {
        let domain = DomainName::new("reload.example.test").unwrap();
        let packet = encode_query(0x1212, &domain, DnsRecordType::A).unwrap();
        let handler = ReloadableAsyncDnsHandler::new(Some(RuntimeDnsHandler {
            resolver: Arc::new(FixedAddressResolver {
                address: Ipv4Addr::new(192, 0, 2, 10),
            }),
            fakeip: None,
        }));
        let response = handler.answer(&packet).await.unwrap();
        assert_eq!(
            decode_response(&response, 0x1212, DnsRecordType::A)
                .unwrap()
                .addresses
                .v4,
            vec![Ipv4Addr::new(192, 0, 2, 10)]
        );

        handler.replace(Some(RuntimeDnsHandler {
            resolver: Arc::new(FixedAddressResolver {
                address: Ipv4Addr::new(192, 0, 2, 11),
            }),
            fakeip: None,
        }));
        let response = handler.answer(&packet).await.unwrap();
        assert_eq!(
            decode_response(&response, 0x1212, DnsRecordType::A)
                .unwrap()
                .addresses
                .v4,
            vec![Ipv4Addr::new(192, 0, 2, 11)]
        );

        handler.replace(None);
        let error = handler.answer(&packet).await.unwrap_err();
        assert!(error.to_string().contains("DNS hijacking is disabled"));
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
