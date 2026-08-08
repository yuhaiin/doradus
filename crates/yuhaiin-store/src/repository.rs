//! Typed and Go compatibility repositories.

use super::*;
use yuhaiin_core::DomainName;
use yuhaiin_core::dns_hosts::HostsTable;

fn validate_route_resolver_name(value: &str, field: &str) -> Result<()> {
    if value.len() > 512 || value.chars().any(char::is_control) {
        return Err(Error::invalid(format!(
            "route settings {field} must be at most 512 non-control bytes"
        )));
    }
    Ok(())
}

impl ConfigRepository {
    /// Read the Go v6 inbound metadata without taking ownership of the source
    /// table. The paired `put_go_inbound` method writes only the known columns
    /// and preserves `data_json` supplied by the caller.
    pub async fn list_go_inbounds(&self) -> Result<Vec<GoInboundRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "inbounds_v2") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query(
                "SELECT id, name, enabled, network_type, protocol_type,
                        transport_types_json, updated_at, data_json
                 FROM inbounds_v2 ORDER BY id",
            )
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                let transport_types_json =
                    row_blob_or_text(row, 5, "inbounds_v2.transport_types_json")?;
                validate_json_bytes(&transport_types_json, "inbounds_v2.transport_types_json")?;
                let data_json = row_blob_or_text(row, 7, "inbounds_v2.data_json")?;
                validate_json_bytes(&data_json, "inbounds_v2.data_json")?;
                Ok(GoInboundRecord {
                    id: row_text(row, 0, "inbounds_v2.id")?,
                    name: row_text(row, 1, "inbounds_v2.name")?,
                    enabled: row_integer(row, 2, "inbounds_v2.enabled")? != 0,
                    network_type: row_text(row, 3, "inbounds_v2.network_type")?,
                    protocol_type: row_text(row, 4, "inbounds_v2.protocol_type")?,
                    transport_types_json,
                    updated_at: row_integer(row, 6, "inbounds_v2.updated_at")?,
                    data_json,
                })
            })
            .collect()
    }

    pub async fn list_go_nodes(&self) -> Result<Vec<GoNodeRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "nodes_v2") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query(
                "SELECT id, name, group_name, origin, enabled, chain_types_json,
                        updated_at, data_json
                 FROM nodes_v2 ORDER BY id",
            )
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                let chain_types_json = row_blob_or_text(row, 5, "nodes_v2.chain_types_json")?;
                validate_json_bytes(&chain_types_json, "nodes_v2.chain_types_json")?;
                let data_json = row_blob_or_text(row, 7, "nodes_v2.data_json")?;
                validate_json_bytes(&data_json, "nodes_v2.data_json")?;
                Ok(GoNodeRecord {
                    id: row_text(row, 0, "nodes_v2.id")?,
                    name: row_text(row, 1, "nodes_v2.name")?,
                    group_name: row_text(row, 2, "nodes_v2.group_name")?,
                    origin: row_text(row, 3, "nodes_v2.origin")?,
                    enabled: row_integer(row, 4, "nodes_v2.enabled")? != 0,
                    chain_types_json,
                    updated_at: row_integer(row, 6, "nodes_v2.updated_at")?,
                    data_json,
                })
            })
            .collect()
    }

    pub async fn list_go_proxy_runtime_configs(&self) -> Result<Vec<GoProxyRuntimeConfig>> {
        self.list_go_nodes()
            .await?
            .iter()
            .map(GoNodeRecord::to_proxy_runtime_config)
            .collect()
    }

    pub async fn list_go_node_tags(&self) -> Result<Vec<GoNodeTagRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "node_tags_v2") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query("SELECT id, name, members_json, updated_at FROM node_tags_v2 ORDER BY id")
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                let members_json = row_blob_or_text(row, 2, "node_tags_v2.members_json")?;
                validate_json_bytes(&members_json, "node_tags_v2.members_json")?;
                Ok(GoNodeTagRecord {
                    id: row_text(row, 0, "node_tags_v2.id")?,
                    name: row_text(row, 1, "node_tags_v2.name")?,
                    members_json,
                    updated_at: row_integer(row, 3, "node_tags_v2.updated_at")?,
                })
            })
            .collect()
    }

    pub async fn list_go_resolvers(&self) -> Result<Vec<GoResolverRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "resolvers_v2") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query("SELECT id, resolver_type, host, updated_at, data_json FROM resolvers_v2 ORDER BY id")
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                let data_json = row_blob_or_text(row, 4, "resolvers_v2.data_json")?;
                validate_json_bytes(&data_json, "resolvers_v2.data_json")?;
                Ok(GoResolverRecord {
                    id: row_text(row, 0, "resolvers_v2.id")?,
                    resolver_type: row_text(row, 1, "resolvers_v2.resolver_type")?,
                    host: row_text(row, 2, "resolvers_v2.host")?,
                    updated_at: row_integer(row, 3, "resolvers_v2.updated_at")?,
                    data_json,
                })
            })
            .collect()
    }

    pub async fn list_go_resolver_runtime_configs(&self) -> Result<Vec<GoResolverRuntimeConfig>> {
        self.list_go_resolvers()
            .await?
            .iter()
            .map(GoResolverRecord::to_runtime_config)
            .collect()
    }

    /// Read Go's static DNS host overrides without rewriting the source table.
    /// Targets are intentionally returned as text: Go permits an address or a
    /// hostname target, and the resolver layer decides how to apply aliases.
    pub async fn list_go_dns_hosts(&self) -> Result<Vec<GoDnsHostRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "dns_hosts") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query("SELECT host, target FROM dns_hosts ORDER BY host")
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                let host = row_text(row, 0, "dns_hosts.host")?;
                let target = row_text(row, 1, "dns_hosts.target")?;
                validate_id(&host)?;
                validate_id(&target)?;
                Ok(GoDnsHostRecord { host, target })
            })
            .collect()
    }

    /// Build the runtime hosts table from the persisted Go compatibility
    /// rows.  This keeps SQLite access out of the resolver while supporting
    /// both IP targets and hostname aliases.
    pub async fn load_go_dns_hosts_table(&self) -> Result<HostsTable> {
        let records = self.list_go_dns_hosts().await?;
        let hosts = HostsTable::new();
        for record in records {
            hosts.insert_target(DomainName::new(&record.host)?, &record.target)?;
        }
        Ok(hosts)
    }

    pub async fn list_go_dns_settings(&self) -> Result<Vec<GoDnsSettingsRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "dns_settings") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query(
                "SELECT id, server, fakedns_enabled, fakedns_ipv4_range,
                        fakedns_ipv6_range
                 FROM dns_settings ORDER BY id",
            )
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                Ok(GoDnsSettingsRecord {
                    id: row_integer(row, 0, "dns_settings.id")?,
                    server: row_text(row, 1, "dns_settings.server")?,
                    fakedns_enabled: row_integer(row, 2, "dns_settings.fakedns_enabled")? != 0,
                    fakedns_ipv4_range: row_text(row, 3, "dns_settings.fakedns_ipv4_range")?,
                    fakedns_ipv6_range: row_text(row, 4, "dns_settings.fakedns_ipv6_range")?,
                })
            })
            .collect()
    }

    pub async fn load_go_fakeip_runtime_config(&self) -> Result<Option<GoFakeIpRuntimeConfig>> {
        let records = self.list_go_dns_settings().await?;
        records
            .first()
            .map(GoDnsSettingsRecord::to_fakeip_runtime_config)
            .transpose()
    }

    pub async fn list_go_dns_fakedns_lists(&self) -> Result<Vec<GoDnsFakednsListRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "dns_fakedns_lists") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query("SELECT kind, value FROM dns_fakedns_lists ORDER BY kind, value")
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                Ok(GoDnsFakednsListRecord {
                    kind: row_text(row, 0, "dns_fakedns_lists.kind")?,
                    value: row_text(row, 1, "dns_fakedns_lists.value")?,
                })
            })
            .collect()
    }

    pub async fn list_go_route_settings(&self) -> Result<Vec<GoRouteSettingsRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "route_settings") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query(
                "SELECT id, direct_resolver, proxy_resolver, resolve_locally,
                        udp_proxy_fqdn
                 FROM route_settings ORDER BY id",
            )
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                Ok(GoRouteSettingsRecord {
                    id: row_integer(row, 0, "route_settings.id")?,
                    direct_resolver: row_text(row, 1, "route_settings.direct_resolver")?,
                    proxy_resolver: row_text(row, 2, "route_settings.proxy_resolver")?,
                    resolve_locally: row_integer(row, 3, "route_settings.resolve_locally")? != 0,
                    udp_proxy_fqdn: row_integer(row, 4, "route_settings.udp_proxy_fqdn")?,
                })
            })
            .collect()
    }

    pub async fn load_go_route_runtime_config(&self) -> Result<Option<GoRouteRuntimeConfig>> {
        Ok(self
            .list_go_route_settings()
            .await?
            .into_iter()
            .next()
            .map(|settings| settings.to_runtime_config()))
    }

    pub async fn put_go_route_settings(&self, record: &GoRouteSettingsRecord) -> Result<()> {
        if record.id < 0 {
            return Err(Error::invalid("route settings id cannot be negative"));
        }
        validate_route_resolver_name(&record.direct_resolver, "direct_resolver")?;
        validate_route_resolver_name(&record.proxy_resolver, "proxy_resolver")?;
        self.store.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO route_settings
                     (id, direct_resolver, proxy_resolver, resolve_locally, udp_proxy_fqdn)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[
                        SqliteValue::from(record.id),
                        SqliteValue::from(record.direct_resolver.as_str()),
                        SqliteValue::from(record.proxy_resolver.as_str()),
                        SqliteValue::from(i64::from(record.resolve_locally)),
                        SqliteValue::from(record.udp_proxy_fqdn),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn delete_go_route_settings(&self, id: i64) -> Result<bool> {
        if id < 0 {
            return Err(Error::invalid("route settings id cannot be negative"));
        }
        self.store.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "DELETE FROM route_settings WHERE id = ?1",
                    &[SqliteValue::from(id)],
                )
                .map(|changed| changed != 0)
                .map_err(storage_error)
        })
    }

    pub async fn list_go_route_rules(&self) -> Result<Vec<GoRouteRuleRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "route_rules_v2") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query(
                "SELECT id, name, priority, disabled, action_mode, match_type,
                        tag, updated_at, data_json
                 FROM route_rules_v2 ORDER BY priority, id",
            )
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                let data_json = row_blob_or_text(row, 8, "route_rules_v2.data_json")?;
                validate_json_bytes(&data_json, "route_rules_v2.data_json")?;
                Ok(GoRouteRuleRecord {
                    id: row_text(row, 0, "route_rules_v2.id")?,
                    name: row_text(row, 1, "route_rules_v2.name")?,
                    priority: row_integer(row, 2, "route_rules_v2.priority")?,
                    disabled: row_integer(row, 3, "route_rules_v2.disabled")? != 0,
                    action_mode: row_text(row, 4, "route_rules_v2.action_mode")?,
                    match_type: row_text(row, 5, "route_rules_v2.match_type")?,
                    tag: row_text(row, 6, "route_rules_v2.tag")?,
                    updated_at: row_integer(row, 7, "route_rules_v2.updated_at")?,
                    data_json,
                })
            })
            .collect()
    }

    pub async fn list_go_route_lists(&self) -> Result<Vec<GoRouteListRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "route_lists_v2") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query(
                "SELECT name, list_type, source_type, updated_at, data_json
                 FROM route_lists_v2 ORDER BY name",
            )
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                let data_json = row_blob_or_text(row, 4, "route_lists_v2.data_json")?;
                validate_json_bytes(&data_json, "route_lists_v2.data_json")?;
                Ok(GoRouteListRecord {
                    name: row_text(row, 0, "route_lists_v2.name")?,
                    list_type: row_text(row, 1, "route_lists_v2.list_type")?,
                    source_type: row_text(row, 2, "route_lists_v2.source_type")?,
                    updated_at: row_integer(row, 3, "route_lists_v2.updated_at")?,
                    data_json,
                })
            })
            .collect()
    }

    /// Write one Go v6 compatibility row without normalizing or dropping the
    /// original `data_json`.  These methods intentionally target the explicit
    /// `_v2` contract tables only; a Go v1 table renamed to
    /// `go_legacy_*` must first be migrated by an explicit schema migration.
    pub async fn put_go_inbound(&self, record: &GoInboundRecord) -> Result<()> {
        validate_go_texts(&[
            ("inbound id", &record.id),
            ("inbound name", &record.name),
            ("inbound network_type", &record.network_type),
            ("inbound protocol_type", &record.protocol_type),
        ])?;
        validate_go_timestamp(record.updated_at)?;
        validate_json_bytes(
            &record.transport_types_json,
            "inbounds_v2.transport_types_json",
        )?;
        validate_json_bytes(&record.data_json, "inbounds_v2.data_json")?;
        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "inbounds_v2",
                &[
                    "id",
                    "name",
                    "enabled",
                    "network_type",
                    "protocol_type",
                    "transport_types_json",
                    "updated_at",
                    "data_json",
                ],
            )?;
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO inbounds_v2
                     (id, name, enabled, network_type, protocol_type,
                      transport_types_json, updated_at, data_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    &[
                        SqliteValue::from(record.id.as_str()),
                        SqliteValue::from(record.name.as_str()),
                        SqliteValue::from(i64::from(record.enabled)),
                        SqliteValue::from(record.network_type.as_str()),
                        SqliteValue::from(record.protocol_type.as_str()),
                        SqliteValue::from(record.transport_types_json.as_slice()),
                        SqliteValue::from(record.updated_at),
                        SqliteValue::from(record.data_json.as_slice()),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn put_go_node(&self, record: &GoNodeRecord) -> Result<()> {
        validate_go_texts(&[
            ("node id", &record.id),
            ("node name", &record.name),
            ("node group_name", &record.group_name),
            ("node origin", &record.origin),
        ])?;
        validate_go_timestamp(record.updated_at)?;
        validate_json_bytes(&record.chain_types_json, "nodes_v2.chain_types_json")?;
        validate_json_bytes(&record.data_json, "nodes_v2.data_json")?;
        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "nodes_v2",
                &[
                    "id",
                    "name",
                    "group_name",
                    "origin",
                    "enabled",
                    "chain_types_json",
                    "updated_at",
                    "data_json",
                ],
            )?;
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO nodes_v2
                     (id, name, group_name, origin, enabled, chain_types_json,
                      updated_at, data_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    &[
                        SqliteValue::from(record.id.as_str()),
                        SqliteValue::from(record.name.as_str()),
                        SqliteValue::from(record.group_name.as_str()),
                        SqliteValue::from(record.origin.as_str()),
                        SqliteValue::from(i64::from(record.enabled)),
                        SqliteValue::from(record.chain_types_json.as_slice()),
                        SqliteValue::from(record.updated_at),
                        SqliteValue::from(record.data_json.as_slice()),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn put_go_node_tag(&self, record: &GoNodeTagRecord) -> Result<()> {
        validate_go_texts(&[("node tag id", &record.id), ("node tag name", &record.name)])?;
        validate_go_timestamp(record.updated_at)?;
        validate_json_bytes(&record.members_json, "node_tags_v2.members_json")?;
        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "node_tags_v2",
                &["id", "name", "members_json", "updated_at"],
            )?;
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO node_tags_v2
                     (id, name, members_json, updated_at) VALUES (?1, ?2, ?3, ?4)",
                    &[
                        SqliteValue::from(record.id.as_str()),
                        SqliteValue::from(record.name.as_str()),
                        SqliteValue::from(record.members_json.as_slice()),
                        SqliteValue::from(record.updated_at),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn put_go_resolver(&self, record: &GoResolverRecord) -> Result<()> {
        validate_go_texts(&[
            ("resolver id", &record.id),
            ("resolver type", &record.resolver_type),
            ("resolver host", &record.host),
        ])?;
        validate_go_timestamp(record.updated_at)?;
        validate_json_bytes(&record.data_json, "resolvers_v2.data_json")?;
        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "resolvers_v2",
                &["id", "resolver_type", "host", "updated_at", "data_json"],
            )?;
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO resolvers_v2
                     (id, resolver_type, host, updated_at, data_json)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[
                        SqliteValue::from(record.id.as_str()),
                        SqliteValue::from(record.resolver_type.as_str()),
                        SqliteValue::from(record.host.as_str()),
                        SqliteValue::from(record.updated_at),
                        SqliteValue::from(record.data_json.as_slice()),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn put_go_route_rule(&self, record: &GoRouteRuleRecord) -> Result<()> {
        validate_go_texts(&[
            ("route rule id", &record.id),
            ("route rule name", &record.name),
            ("route rule action_mode", &record.action_mode),
            ("route rule match_type", &record.match_type),
            ("route rule tag", &record.tag),
        ])?;
        validate_go_timestamp(record.updated_at)?;
        validate_json_bytes(&record.data_json, "route_rules_v2.data_json")?;
        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "route_rules_v2",
                &[
                    "id",
                    "name",
                    "priority",
                    "disabled",
                    "action_mode",
                    "match_type",
                    "tag",
                    "updated_at",
                    "data_json",
                ],
            )?;
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO route_rules_v2
                     (id, name, priority, disabled, action_mode, match_type,
                      tag, updated_at, data_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    &[
                        SqliteValue::from(record.id.as_str()),
                        SqliteValue::from(record.name.as_str()),
                        SqliteValue::from(record.priority),
                        SqliteValue::from(i64::from(record.disabled)),
                        SqliteValue::from(record.action_mode.as_str()),
                        SqliteValue::from(record.match_type.as_str()),
                        SqliteValue::from(record.tag.as_str()),
                        SqliteValue::from(record.updated_at),
                        SqliteValue::from(record.data_json.as_slice()),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn put_go_route_list(&self, record: &GoRouteListRecord) -> Result<()> {
        validate_go_texts(&[
            ("route list name", &record.name),
            ("route list type", &record.list_type),
            ("route list source_type", &record.source_type),
        ])?;
        validate_go_timestamp(record.updated_at)?;
        validate_json_bytes(&record.data_json, "route_lists_v2.data_json")?;
        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "route_lists_v2",
                &[
                    "name",
                    "list_type",
                    "source_type",
                    "updated_at",
                    "data_json",
                ],
            )?;
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO route_lists_v2
                     (name, list_type, source_type, updated_at, data_json)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[
                        SqliteValue::from(record.name.as_str()),
                        SqliteValue::from(record.list_type.as_str()),
                        SqliteValue::from(record.source_type.as_str()),
                        SqliteValue::from(record.updated_at),
                        SqliteValue::from(record.data_json.as_slice()),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn delete_go_inbound(&self, id: &str) -> Result<bool> {
        self.delete_go_compatibility_row("inbounds_v2", "id", id)
    }

    pub async fn delete_go_node(&self, id: &str) -> Result<bool> {
        self.delete_go_compatibility_row("nodes_v2", "id", id)
    }

    pub async fn delete_go_node_tag(&self, id: &str) -> Result<bool> {
        self.delete_go_compatibility_row("node_tags_v2", "id", id)
    }

    pub async fn delete_go_resolver(&self, id: &str) -> Result<bool> {
        self.delete_go_compatibility_row("resolvers_v2", "id", id)
    }

    pub async fn delete_go_route_rule(&self, id: &str) -> Result<bool> {
        self.delete_go_compatibility_row("route_rules_v2", "id", id)
    }

    pub async fn delete_go_route_list(&self, name: &str) -> Result<bool> {
        self.delete_go_compatibility_row("route_lists_v2", "name", name)
    }

    fn delete_go_compatibility_row(
        &self,
        table: &'static str,
        key_column: &'static str,
        key: &str,
    ) -> Result<bool> {
        validate_id(key)?;
        self.store.with_write_transaction(|connection| {
            require_go_table(connection, table, &[key_column])?;
            connection
                .execute_with_params(
                    &format!("DELETE FROM {table} WHERE {key_column} = ?1"),
                    &[SqliteValue::from(key)],
                )
                .map(|changed| changed != 0)
                .map_err(storage_error)
        })
    }

    pub async fn put_proxy_node(&self, record: &ProxyNodeRecord) -> Result<()> {
        validate_id(&record.id)?;
        validate_id(&record.kind)?;
        self.store.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO proxy_nodes (id, kind, config) VALUES (?1, ?2, ?3)",
                    &[
                        SqliteValue::from(record.id.as_str()),
                        SqliteValue::from(record.kind.as_str()),
                        SqliteValue::from(record.config.as_slice()),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn list_proxy_nodes(&self) -> Result<Vec<ProxyNodeRecord>> {
        let connection = self.store.lock_connection()?;
        let rows = connection
            .query("SELECT id, kind, config FROM proxy_nodes ORDER BY id")
            .map_err(storage_error)?;
        rows.iter().map(proxy_node_from_row).collect()
    }

    pub async fn delete_proxy_node(&self, id: &str) -> Result<bool> {
        validate_id(id)?;
        self.store.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "DELETE FROM proxy_nodes WHERE id = ?1",
                    &[SqliteValue::from(id)],
                )
                .map(|changed| changed != 0)
                .map_err(storage_error)
        })
    }

    pub async fn put_route_rule(&self, record: &RouteRuleRecord) -> Result<()> {
        validate_id(&record.id)?;
        validate_id(&record.pattern)?;
        validate_id(&record.action)?;
        self.store.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO route_rules
                 (id, pattern, action, priority, geo_country, resolver_policy)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    &[
                        SqliteValue::from(record.id.as_str()),
                        SqliteValue::from(record.pattern.as_str()),
                        SqliteValue::from(record.action.as_str()),
                        SqliteValue::from(record.priority),
                        record
                            .geo_country
                            .as_deref()
                            .map_or(SqliteValue::Null, |value| SqliteValue::from(value)),
                        SqliteValue::from(record.resolver_policy.as_slice()),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn list_route_rules(&self) -> Result<Vec<RouteRuleRecord>> {
        let connection = self.store.lock_connection()?;
        let rows = connection
            .query(
                "SELECT id, pattern, action, priority, geo_country, resolver_policy
                 FROM route_rules ORDER BY priority, id",
            )
            .map_err(storage_error)?;
        rows.iter().map(route_rule_from_row).collect()
    }

    pub async fn delete_route_rule(&self, id: &str) -> Result<bool> {
        validate_id(id)?;
        self.store.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "DELETE FROM route_rules WHERE id = ?1",
                    &[SqliteValue::from(id)],
                )
                .map(|changed| changed != 0)
                .map_err(storage_error)
        })
    }

    pub async fn put_dns_resolver(&self, record: &DnsResolverRecord) -> Result<()> {
        validate_id(&record.id)?;
        validate_id(&record.kind)?;
        self.store.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO dns_resolvers (id, kind, config)
                 VALUES (?1, ?2, ?3)",
                    &[
                        SqliteValue::from(record.id.as_str()),
                        SqliteValue::from(record.kind.as_str()),
                        SqliteValue::from(record.config.as_slice()),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn list_dns_resolvers(&self) -> Result<Vec<DnsResolverRecord>> {
        let connection = self.store.lock_connection()?;
        let rows = connection
            .query("SELECT id, kind, config FROM dns_resolvers ORDER BY id")
            .map_err(storage_error)?;
        rows.iter().map(dns_resolver_from_row).collect()
    }

    pub async fn delete_dns_resolver(&self, id: &str) -> Result<bool> {
        validate_id(id)?;
        self.store.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "DELETE FROM dns_resolvers WHERE id = ?1",
                    &[SqliteValue::from(id)],
                )
                .map(|changed| changed != 0)
                .map_err(storage_error)
        })
    }

    pub async fn put_tun_config(&self, record: &TunConfigRecord) -> Result<()> {
        validate_id(&record.key)?;
        self.store.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO tun_config (key, value) VALUES (?1, ?2)",
                    &[
                        SqliteValue::from(record.key.as_str()),
                        SqliteValue::from(record.value.as_slice()),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn list_tun_config(&self) -> Result<Vec<TunConfigRecord>> {
        let connection = self.store.lock_connection()?;
        let rows = connection
            .query("SELECT key, value FROM tun_config ORDER BY key")
            .map_err(storage_error)?;
        rows.iter().map(tun_config_from_row).collect()
    }

    pub async fn delete_tun_config(&self, key: &str) -> Result<bool> {
        validate_id(key)?;
        self.store.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "DELETE FROM tun_config WHERE key = ?1",
                    &[SqliteValue::from(key)],
                )
                .map(|changed| changed != 0)
                .map_err(storage_error)
        })
    }

    pub async fn put_nat_config(&self, record: &NatConfigRecord) -> Result<()> {
        validate_id(&record.key)?;
        if !record.full_cone {
            return Err(Error::invalid(
                "only endpoint-independent Full Cone NAT is supported",
            ));
        }
        if record.idle_timeout_ms <= 0 {
            return Err(Error::invalid("NAT idle timeout must be positive"));
        }
        self.store.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO nat_config (key, full_cone, idle_timeout_ms)
                 VALUES (?1, ?2, ?3)",
                    &[
                        SqliteValue::from(record.key.as_str()),
                        SqliteValue::from(i64::from(record.full_cone)),
                        SqliteValue::from(record.idle_timeout_ms),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn list_nat_config(&self) -> Result<Vec<NatConfigRecord>> {
        let connection = self.store.lock_connection()?;
        let rows = connection
            .query("SELECT key, full_cone, idle_timeout_ms FROM nat_config ORDER BY key")
            .map_err(storage_error)?;
        rows.iter().map(nat_config_from_row).collect()
    }

    pub async fn get_nat_config(&self, key: &str) -> Result<Option<NatConfigRecord>> {
        validate_id(key)?;
        let connection = self.store.lock_connection()?;
        let rows = connection
            .query_with_params(
                "SELECT key, full_cone, idle_timeout_ms FROM nat_config WHERE key = ?1",
                &[SqliteValue::from(key)],
            )
            .map_err(storage_error)?;
        rows.first().map(nat_config_from_row).transpose()
    }

    /// Return a persisted NAT profile when present, otherwise the safe
    /// migration default.  This is deliberately read-only: callers can
    /// decide when a default should become durable configuration.
    pub async fn get_nat_config_or_default(&self, key: &str) -> Result<NatConfigRecord> {
        if let Some(record) = self.get_nat_config(key).await? {
            return Ok(record);
        }
        validate_id(key)?;
        Ok(NatConfigRecord {
            key: key.to_owned(),
            ..NatConfigRecord::default()
        })
    }

    pub async fn delete_nat_config(&self, key: &str) -> Result<bool> {
        validate_id(key)?;
        self.store.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "DELETE FROM nat_config WHERE key = ?1",
                    &[SqliteValue::from(key)],
                )
                .map(|changed| changed != 0)
                .map_err(storage_error)
        })
    }

    pub async fn put_maxmind_metadata(&self, record: &MaxMindMetadataRecord) -> Result<()> {
        validate_id(&record.id)?;
        validate_id(&record.path)?;
        if record.size < 0 || record.updated_at < 0 {
            return Err(Error::invalid(
                "MaxMind metadata numbers cannot be negative",
            ));
        }
        self.store.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO maxmind_metadata
                 (id, path, sha256, size, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[
                        SqliteValue::from(record.id.as_str()),
                        SqliteValue::from(record.path.as_str()),
                        SqliteValue::from(record.sha256.as_slice()),
                        SqliteValue::from(record.size),
                        SqliteValue::from(record.updated_at),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn list_maxmind_metadata(&self) -> Result<Vec<MaxMindMetadataRecord>> {
        let connection = self.store.lock_connection()?;
        let rows = connection
            .query("SELECT id, path, sha256, size, updated_at FROM maxmind_metadata ORDER BY id")
            .map_err(storage_error)?;
        rows.iter().map(maxmind_from_row).collect()
    }

    pub async fn delete_maxmind_metadata(&self, id: &str) -> Result<bool> {
        validate_id(id)?;
        self.store.with_write_retry(|connection| {
            connection
                .execute_with_params(
                    "DELETE FROM maxmind_metadata WHERE id = ?1",
                    &[SqliteValue::from(id)],
                )
                .map(|changed| changed != 0)
                .map_err(storage_error)
        })
    }
}
