//! TUN configuration loading and parsing.

use super::*;

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

pub(super) const DEFAULT_TUN_SOCKET_RX_BUFFER_SIZE: usize = 8 * 1024;
pub(super) const DEFAULT_TUN_SOCKET_TX_BUFFER_SIZE: usize = 8 * 1024;
pub(super) const DEFAULT_TUN_UDP_PACKET_CAPACITY: usize = 64;

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
pub(super) fn select_go_tun_record(
    records: Vec<GoInboundRecord>,
) -> Result<Option<GoInboundRecord>> {
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
pub(super) fn tun_dns_servers(config: &yuhaiin_tun::TunConfig) -> Vec<std::net::IpAddr> {
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
