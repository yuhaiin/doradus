//! Store-backed runtime input loading and compatibility parsing.

use super::*;

/// Store-backed inputs loaded before any resolver, FakeIP or route runtime is
/// constructed. Keeping this phase typed makes fallback precedence explicit
/// and lets `build` focus on assembling immutable runtime components.
pub(super) struct RuntimeInputs {
    pub(super) settings: RuntimeSettings,
    pub(super) inbound_settings: InboundSettings,
    pub(super) socket_bind_addresses: Arc<[IpAddr]>,
    pub(super) socket_bind_interface: Option<String>,
    pub(super) nat: NatConfigRecord,
    pub(super) hosts: HostsTable,
    pub(super) resolvers: Vec<GoResolverRuntimeConfig>,
    pub(super) route: Option<GoRouteRuntimeConfig>,
    pub(super) route_rules: Vec<GoRouteRuleRecord>,
    pub(super) node_tags: Vec<GoNodeTagRecord>,
    pub(super) route_lists: Arc<RouteListSnapshot>,
    pub(super) proxies: Vec<GoProxyRuntimeConfig>,
    pub(super) geo_metadata: Vec<MaxMindMetadataRecord>,
    pub(super) geo: Option<Arc<dyn GeoLookup>>,
    pub(super) fakeip_config: Option<doradus_store::GoFakeIpRuntimeConfig>,
    pub(super) fakeip_policy: FakeIpPolicy,
}

struct BlockingRuntimeInputs {
    settings: RuntimeSettings,
    inbound_settings: InboundSettings,
    nat: NatConfigRecord,
    hosts: HostsTable,
    resolvers: Vec<GoResolverRuntimeConfig>,
    route: Option<GoRouteRuntimeConfig>,
    route_rules: Vec<GoRouteRuleRecord>,
    node_tags: Vec<GoNodeTagRecord>,
    route_list_records: Vec<doradus_store::GoRouteListRecord>,
    proxies: Vec<GoProxyRuntimeConfig>,
    geo_metadata: Vec<MaxMindMetadataRecord>,
    fakeip_config: Option<doradus_store::GoFakeIpRuntimeConfig>,
    fakeip_policy: FakeIpPolicy,
}

async fn run_blocking_store<T, F>(operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    if tokio::runtime::Handle::try_current().is_err() {
        return operation();
    }
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("blocking runtime store task failed: {error}"),
            )
        })?
}

impl RuntimeBuilder {
    pub(super) async fn load_inputs(&self) -> Result<RuntimeInputs> {
        crate::defaults::ensure_go_defaults(&self.store).await?;
        let repository = self.store.repository();
        let blocking_store = self.store.clone();
        let blocking_repository = repository.clone();
        let BlockingRuntimeInputs {
            settings,
            inbound_settings,
            nat,
            hosts,
            resolvers,
            route,
            route_rules,
            node_tags,
            route_list_records,
            proxies,
            geo_metadata,
            fakeip_config,
            fakeip_policy,
        } = run_blocking_store(move || {
            let settings = match blocking_store.get_config_sync("settings")? {
                Some(bytes) => {
                    let value =
                        serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|error| {
                            Error::invalid(format!("settings is invalid JSON: {error}"))
                        })?;
                    RuntimeSettings::from_value(&value)
                }
                None => RuntimeSettings::from_go_settings_kv(
                    &blocking_repository.list_go_settings_kv_sync()?,
                ),
            };
            Ok::<_, doradus_core::Error>(BlockingRuntimeInputs {
                settings,
                inbound_settings: blocking_repository.get_inbound_settings_sync()?,
                nat: blocking_repository.get_nat_config_or_default_sync("default")?,
                hosts: load_hosts_sync(&blocking_repository, &blocking_store)?,
                resolvers: blocking_repository.list_go_resolver_runtime_configs_sync()?,
                route: blocking_repository.load_go_route_runtime_config_sync()?,
                route_rules: blocking_repository.list_go_route_rules_sync()?,
                node_tags: blocking_repository.list_go_node_tags_sync()?,
                route_list_records: blocking_repository.list_go_route_lists_sync()?,
                proxies: blocking_repository.list_go_proxy_runtime_configs_sync()?,
                geo_metadata: blocking_repository.list_maxmind_metadata_sync()?,
                fakeip_config: load_fakeip_config_sync(&blocking_store, &blocking_repository)?,
                fakeip_policy: load_fakeip_policy_sync(&blocking_store, &blocking_repository)?,
            })
        })
        .await?;
        let socket_bind_addresses =
            Arc::from(interfaces::bind_addresses_for_settings(&settings).into_boxed_slice());
        let socket_bind_interface = interfaces::bind_interface_for_settings(&settings);
        if let Some(bridge) = &self.resolver_proxy_bridge {
            bridge
                .set_configured_resolver_ids(resolvers.iter().map(|resolver| resolver.id.as_str()));
            bridge.set_proxy_resolver_id(route.as_ref().map(|route| route.proxy_resolver.as_str()));
        }
        let route_lists = Arc::new(load_route_lists(&route_list_records));
        let geo_manager = GeoDatabaseManager::new();
        let geo = geo_metadata
            .first()
            .map(|metadata| {
                geo_manager
                    .load(GeoMetadata {
                        id: metadata.id.clone(),
                        path: metadata.path.clone().into(),
                        sha256: metadata.sha256.clone(),
                        size: u64::try_from(metadata.size).map_err(|_| {
                            Error::invalid("MaxMind metadata size cannot be negative")
                        })?,
                        updated_at: metadata.updated_at,
                    })
                    .map(|snapshot| snapshot.database())
            })
            .transpose()?
            .map(|database| database as Arc<dyn GeoLookup>);

        Ok(RuntimeInputs {
            settings,
            inbound_settings,
            socket_bind_addresses,
            socket_bind_interface,
            nat,
            hosts,
            resolvers,
            route,
            route_rules,
            node_tags,
            route_lists,
            proxies,
            geo_metadata,
            geo,
            fakeip_config,
            fakeip_policy,
        })
    }
}

fn load_hosts_sync(
    repository: &doradus_store::ConfigRepository,
    store: &ConfigStore,
) -> Result<HostsTable> {
    let hosts = HostsTable::new();
    load_system_hosts(&hosts);

    let persisted = repository.list_go_dns_hosts_sync()?;
    if !persisted.is_empty() {
        let configured = repository.load_go_dns_hosts_table_sync()?;
        hosts.overlay(&configured)?;
        return Ok(hosts);
    }
    let Some(bytes) = store.get_config_sync("resolver.hosts")? else {
        return Ok(hosts);
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("resolver.hosts is invalid JSON: {error}"),
        )
    })?;
    let object = value
        .get("hosts")
        .and_then(serde_json::Value::as_object)
        .or_else(|| value.as_object())
        .ok_or_else(|| Error::invalid("resolver.hosts must be a JSON object"))?;
    let configured = HostsTable::new();
    for (host, target) in object {
        let Some(target) = target.as_str() else {
            return Err(Error::invalid("resolver.hosts targets must be strings"));
        };
        configured.insert_host_target(host, target)?;
    }
    hosts.overlay(&configured)?;
    Ok(hosts)
}

/// Load the host file used by the platform resolver as the lowest-priority
/// hosts layer.  A missing/unreadable file is normal on some targets and must
/// not prevent the service from starting; malformed individual rows are
/// ignored with the same fail-soft behavior as libc-style hosts parsing.
fn load_system_hosts(hosts: &HostsTable) {
    let Ok(contents) = std::fs::read_to_string(system_hosts_path()) else {
        return;
    };
    for (address, domain) in parse_system_hosts(&contents) {
        let _ = hosts.insert_ip(domain, address);
    }
}

#[cfg(not(windows))]
fn system_hosts_path() -> &'static str {
    "/etc/hosts"
}

#[cfg(windows)]
fn system_hosts_path() -> &'static str {
    r"C:\Windows\System32\drivers\etc\hosts"
}

pub(super) fn parse_system_hosts(contents: &str) -> Vec<(IpAddr, DomainName)> {
    let mut entries = Vec::new();
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or_default();
        let mut fields = line.split_whitespace();
        let Some(address) = fields.next().and_then(|value| value.parse::<IpAddr>().ok()) else {
            continue;
        };
        for host in fields {
            let host = host.trim_end_matches('.');
            if host.is_empty() {
                continue;
            }
            if let Ok(domain) = DomainName::new(host) {
                entries.push((address, domain));
            }
        }
    }
    entries
}

fn load_fakeip_config_sync(
    store: &ConfigStore,
    repository: &ConfigRepository,
) -> Result<Option<doradus_store::GoFakeIpRuntimeConfig>> {
    if let Some(bytes) = store.get_config_sync("resolver.fakedns")? {
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("resolver.fakedns is invalid JSON: {error}"),
            )
        })?;
        let enabled = value
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let ipv4_range = value
            .get("ipv4Range")
            .or_else(|| value.get("ipv4_range"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("10.2.0.1/24");
        let ipv6_range = value
            .get("ipv6Range")
            .or_else(|| value.get("ipv6_range"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("fc00::/64");
        let record = doradus_store::GoDnsSettingsRecord {
            id: 0,
            server: String::new(),
            fakedns_enabled: enabled,
            fakedns_ipv4_range: ipv4_range.to_owned(),
            fakedns_ipv6_range: ipv6_range.to_owned(),
        };
        return record.to_fakeip_runtime_config().map(Some);
    }
    repository.load_go_fakeip_runtime_config_sync()
}

fn load_fakeip_policy_sync(
    store: &ConfigStore,
    repository: &ConfigRepository,
) -> Result<FakeIpPolicy> {
    if let Some(bytes) = store.get_config_sync("resolver.fakedns")? {
        let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("resolver.fakedns is invalid JSON: {error}"),
            )
        })?;
        let object = value
            .as_object()
            .ok_or_else(|| Error::invalid("resolver.fakedns must be a JSON object"))?;
        let whitelist = parse_fakeip_list(object, &["whitelist"], "whitelist")?;
        let skip_check = parse_fakeip_list(
            object,
            &["skipCheckList", "skip_check_list"],
            "skipCheckList",
        )?;
        if whitelist.is_some() || skip_check.is_some() {
            return FakeIpPolicy::from_lists(
                whitelist.as_deref().unwrap_or_default(),
                skip_check.as_deref().unwrap_or_default(),
            );
        }
    }

    let mut whitelist = Vec::new();
    let mut skip_check = Vec::new();
    for record in repository.list_go_dns_fakedns_lists_sync()? {
        match record.kind.as_str() {
            "whitelist" => whitelist.push(record.value),
            "skip_check" => skip_check.push(record.value),
            _ => {}
        }
    }
    FakeIpPolicy::from_lists(&whitelist, &skip_check)
}

#[cfg(test)]
pub(super) async fn load_fakeip_policy(
    store: &ConfigStore,
    repository: &ConfigRepository,
) -> Result<FakeIpPolicy> {
    load_fakeip_policy_sync(store, repository)
}

fn parse_fakeip_list(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
    field: &str,
) -> Result<Option<Vec<String>>> {
    let Some(value) = keys.iter().find_map(|key| object.get(*key)) else {
        return Ok(None);
    };
    let values = value
        .as_array()
        .ok_or_else(|| Error::invalid(format!("resolver.fakedns.{field} must be an array")))?;
    values
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                Error::invalid(format!("resolver.fakedns.{field} entries must be strings"))
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}
