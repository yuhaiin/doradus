//! Typed and Go compatibility repositories.

use super::*;
use yuhaiin_core::DomainName;
use yuhaiin_core::dns_hosts::{HostsTable, host_without_port};

fn validate_route_resolver_name(value: &str, field: &str) -> Result<()> {
    if value.len() > 512 || value.chars().any(char::is_control) {
        return Err(Error::invalid(format!(
            "route settings {field} must be at most 512 non-control bytes"
        )));
    }
    Ok(())
}

impl ConfigRepository {
    /// Read a selected node id from Go's raw compatibility metadata.
    ///
    /// Go stores these values as plain strings in `metadata`, while the
    /// native Rust configuration uses JSON objects in `yuhaiin_config`.
    /// Keeping the compatibility lookup here prevents the API layer from
    /// depending on SQLite table details and allows fresh Rust databases
    /// (where the table is still bootstrapped) and imported Go databases to
    /// share the same behavior.
    pub async fn get_go_selected_node_id(&self, key: &str) -> Result<Option<String>> {
        if !matches!(key, "selected_tcp_node_v2" | "selected_udp_node_v2") {
            return Err(Error::invalid(format!(
                "unsupported Go selected-node metadata key {key:?}"
            )));
        }
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "metadata") {
            return Ok(None);
        }
        let rows = connection
            .query_with_params(
                "SELECT value FROM metadata WHERE key = ?1",
                &[SqliteValue::from(key)],
            )
            .map_err(storage_error)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let value = row_text(row, 0, "metadata.value")?;
        if value.trim().is_empty() {
            return Ok(None);
        }
        validate_id(&value)?;
        Ok(Some(value))
    }

    /// Keep Go's selected-node metadata in sync when the frontend changes
    /// the active node. Go uses one id for both TCP and UDP selection.
    pub async fn put_go_selected_node_ids(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "metadata") {
            return Ok(());
        }
        drop(connection);
        self.store.with_write_transaction(|connection| {
            require_go_table(connection, "metadata", &["key", "value"])?;
            for key in ["selected_tcp_node_v2", "selected_udp_node_v2"] {
                connection
                    .execute_with_params(
                        "INSERT OR REPLACE INTO metadata(key, value) VALUES (?1, ?2)",
                        &[SqliteValue::from(key), SqliteValue::from(id)],
                    )
                    .map_err(storage_error)?;
            }
            Ok(())
        })
    }

    /// Read Go's global settings KV table without converting it into a second
    /// lossy settings schema. Unknown sections remain available to future
    /// callers and malformed JSON is rejected for the same fail-closed
    /// startup behavior as the other Go compatibility tables.
    pub async fn list_go_settings_kv(&self) -> Result<Vec<GoSettingsKvRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "settings_kv") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query(
                "SELECT section, key, value_json
                 FROM settings_kv ORDER BY section, key",
            )
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                let section = row_text(row, 0, "settings_kv.section")?;
                let key = row_text(row, 1, "settings_kv.key")?;
                let value_json = row_text(row, 2, "settings_kv.value_json")?;
                serde_json::from_str::<serde_json::Value>(&value_json).map_err(|error| {
                    Error::invalid(format!(
                        "settings_kv {section}.{key} contains invalid JSON: {error}"
                    ))
                })?;
                Ok(GoSettingsKvRecord {
                    section,
                    key,
                    value_json,
                })
            })
            .collect()
    }

    /// Upsert only the scalar settings understood by the shared Go contract.
    /// Unknown/platform rows are intentionally untouched. Fresh Rust stores
    /// do not have this legacy table, so the operation is a no-op there.
    pub async fn put_go_settings_kv(&self, values: &[GoSettingsKvRecord]) -> Result<()> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "settings_kv") {
            return Ok(());
        }
        drop(connection);
        let values = values.to_vec();
        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "settings_kv",
                &["section", "key", "value_json", "updated_at"],
            )?;
            for value in &values {
                validate_go_texts(&[
                    ("settings_kv.section", &value.section),
                    ("settings_kv.key", &value.key),
                    ("settings_kv.value_json", &value.value_json),
                ])?;
                serde_json::from_str::<serde_json::Value>(&value.value_json).map_err(|error| {
                    Error::invalid(format!(
                        "settings_kv {}.{} contains invalid JSON: {error}",
                        value.section, value.key
                    ))
                })?;
                connection
                    .execute_with_params(
                        "INSERT INTO settings_kv(section, key, value_json, updated_at)
                         VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(section, key) DO UPDATE SET
                           value_json = excluded.value_json,
                           updated_at = excluded.updated_at",
                        &[
                            SqliteValue::from(value.section.as_str()),
                            SqliteValue::from(value.key.as_str()),
                            SqliteValue::from(value.value_json.as_str()),
                            SqliteValue::from(0_i64),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            Ok(())
        })
    }

    /// Read Go's single-row backup contract without projecting away S3 or
    /// future fields. Older databases may not have the table yet, in which
    /// case callers use their private compatibility fallback.
    pub async fn get_go_backup_settings(&self) -> Result<Option<GoBackupSettingsRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "backup_settings") {
            return Ok(None);
        }
        let rows = connection
            .query(
                "SELECT updated_at, data_json
                 FROM backup_settings WHERE id = 1",
            )
            .map_err(storage_error)?;
        rows.first()
            .map(|row| {
                let data_json = row_blob_or_text(row, 1, "backup_settings.data_json")?;
                validate_json_bytes(&data_json, "backup_settings.data_json")?;
                Ok(GoBackupSettingsRecord {
                    updated_at: row_integer(row, 0, "backup_settings.updated_at")?,
                    data_json,
                })
            })
            .transpose()
    }

    /// Persist the Go backup option as one atomic row while retaining fields
    /// that are currently only understood by the Go implementation.
    pub async fn put_go_backup_settings(&self, record: &GoBackupSettingsRecord) -> Result<()> {
        validate_go_timestamp(record.updated_at)?;
        validate_json_bytes(&record.data_json, "backup_settings.data_json")?;
        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "backup_settings",
                &["id", "updated_at", "data_json"],
            )?;
            connection
                .execute_with_params(
                    "INSERT INTO backup_settings(id, updated_at, data_json)
                     VALUES (1, ?1, ?2)
                     ON CONFLICT(id) DO UPDATE SET
                       updated_at = excluded.updated_at,
                       data_json = excluded.data_json",
                    &[
                        SqliteValue::from(record.updated_at),
                        SqliteValue::from(record.data_json.as_slice()),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

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

    /// Count remote nodes owned by the named subscription groups.  Go removes
    /// only remote subscription nodes, leaving locally configured nodes with
    /// the same display group untouched.
    pub async fn count_go_nodes_by_groups(&self, groups: &[String]) -> Result<usize> {
        for group in groups {
            validate_id(group)?;
        }
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "nodes_v2") {
            return Ok(0);
        }
        let mut total = 0usize;
        for group in groups {
            let rows = connection
                .query_with_params(
                    "SELECT COUNT(*) FROM nodes_v2
                     WHERE group_name = ?1 AND origin = 'remote'",
                    &[SqliteValue::from(group.as_str())],
                )
                .map_err(storage_error)?;
            let count = rows
                .first()
                .map(|row| row_integer(row, 0, "nodes_v2.count"))
                .transpose()?
                .unwrap_or(0);
            total = total.saturating_add(
                usize::try_from(count)
                    .map_err(|_| Error::new(ErrorKind::Storage, "nodes_v2 count is negative"))?,
            );
        }
        Ok(total)
    }

    pub async fn delete_go_nodes_by_groups(&self, groups: &[String]) -> Result<usize> {
        for group in groups {
            validate_id(group)?;
        }
        let groups = groups.to_vec();
        self.store.with_write_transaction(|connection| {
            require_go_table(connection, "nodes_v2", &["group_name", "origin"])?;
            let mut deleted = 0usize;
            for group in &groups {
                let changed = connection
                    .execute_with_params(
                        "DELETE FROM nodes_v2
                         WHERE group_name = ?1 AND origin = 'remote'",
                        &[SqliteValue::from(group.as_str())],
                    )
                    .map_err(storage_error)?;
                deleted = deleted.saturating_add(changed);
            }
            Ok(deleted)
        })
    }

    pub async fn list_go_proxy_runtime_configs(&self) -> Result<Vec<GoProxyRuntimeConfig>> {
        let nodes = self.list_go_nodes().await?;
        self.resolve_go_node_runtime_records(&nodes)?
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
            .query("SELECT id, name, members_json, updated_at FROM node_tags_v2 ORDER BY name")
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
            // Go's hosts dispatcher is fail-soft: malformed rows are skipped
            // and valid `host:port` compatibility entries are indexed by
            // hostname.  A single stale row must not prevent the service
            // from starting with an otherwise usable production database.
            let Ok(domain) = DomainName::new(host_without_port(&record.host)) else {
                continue;
            };
            if hosts.insert_target(domain, &record.target).is_err() {
                continue;
            }
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

    fn read_legacy_inbound_settings(&self) -> Result<Option<InboundSettings>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "inbound_settings") {
            return Ok(None);
        }
        let rows = connection
            .query(
                "SELECT hijack_dns, hijack_dns_fakeip, sniff_enabled
                 FROM inbound_settings WHERE id = 1",
            )
            .map_err(storage_error)?;
        rows.first()
            .map(|row| {
                Ok(InboundSettings {
                    hijack_dns: row_integer(row, 0, "inbound_settings.hijack_dns")? != 0,
                    hijack_dns_fakeip: row_integer(row, 1, "inbound_settings.hijack_dns_fakeip")?
                        != 0,
                    sniff: row_integer(row, 2, "inbound_settings.sniff_enabled")? != 0,
                })
            })
            .transpose()
    }

    fn has_legacy_inbound_settings(&self) -> Result<bool> {
        let connection = self.store.lock_connection()?;
        Ok(table_exists(&connection, "inbound_settings"))
    }

    /// Load the inbound-wide policy from Go's `inbound_settings` row. Fresh
    /// Rust stores use the same JSON contract under `inbounds.config`, so the
    /// frontend and runtime have one source of truth on both database shapes.
    pub async fn get_inbound_settings(&self) -> Result<InboundSettings> {
        if let Some(settings) = self.read_legacy_inbound_settings()? {
            return Ok(settings);
        }

        let Some(bytes) = self.store.get_config("inbounds.config").await? else {
            return Ok(InboundSettings::default());
        };
        serde_json::from_slice(&bytes)
            .map_err(|error| Error::invalid(format!("inbounds.config is invalid JSON: {error}")))
    }

    /// Persist the policy in the native Go row when present, otherwise in
    /// the Rust config overlay. Existing Go databases are not altered with a
    /// second competing settings table.
    pub async fn put_inbound_settings(&self, settings: InboundSettings) -> Result<()> {
        let has_legacy_table = self.has_legacy_inbound_settings()?;
        if !has_legacy_table {
            let bytes = serde_json::to_vec(&settings)
                .map_err(|error| Error::invalid(format!("encode inbound settings: {error}")))?;
            return self.store.put_config("inbounds.config", &bytes).await;
        }

        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "inbound_settings",
                &["id", "hijack_dns", "hijack_dns_fakeip", "sniff_enabled"],
            )?;
            connection
                .execute_with_params(
                    "INSERT INTO inbound_settings(
                         id, hijack_dns, hijack_dns_fakeip, sniff_enabled
                     ) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(id) DO UPDATE SET
                         hijack_dns = excluded.hijack_dns,
                         hijack_dns_fakeip = excluded.hijack_dns_fakeip,
                         sniff_enabled = excluded.sniff_enabled",
                    &[
                        SqliteValue::from(1_i64),
                        SqliteValue::from(i64::from(settings.hijack_dns)),
                        SqliteValue::from(i64::from(settings.hijack_dns_fakeip)),
                        SqliteValue::from(i64::from(settings.sniff)),
                    ],
                )
                .map_err(storage_error)?;
            Ok(())
        })
    }

    /// Update only the Go resolver server field, preserving FakeDNS columns
    /// in `dns_settings`. Fresh Rust stores do not have this compatibility
    /// table and continue using the Rust config overlay.
    pub async fn put_go_dns_server(&self, server: &str) -> Result<()> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "dns_settings") {
            return Ok(());
        }
        drop(connection);
        validate_go_texts(&[("dns_settings.server", &server.to_owned())])?;
        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "dns_settings",
                &[
                    "id",
                    "server",
                    "fakedns_enabled",
                    "fakedns_ipv4_range",
                    "fakedns_ipv6_range",
                ],
            )?;
            connection
                .execute_with_params(
                    "INSERT INTO dns_settings(
                         id, server, fakedns_enabled, fakedns_ipv4_range, fakedns_ipv6_range
                     ) VALUES (?1, ?2, 0, '', '')
                     ON CONFLICT(id) DO UPDATE SET server = excluded.server",
                    &[SqliteValue::from(1_i64), SqliteValue::from(server)],
                )
                .map_err(storage_error)?;
            Ok(())
        })
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
            // Go exposes the insertion order of these lists through its
            // resolver store, and callers rely on that order when comparing
            // or round-tripping configuration.
            .query("SELECT kind, value FROM dns_fakedns_lists ORDER BY rowid")
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

    /// Read the Go subscription-link contract from its native table.  The
    /// JSON object is normalized at the boundary just like Go's store, while
    /// unknown fields remain in `data_json` for round-trip compatibility.
    pub async fn list_go_subscription_links(&self) -> Result<Vec<GoSubscriptionLinkRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "subscriptions") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query(
                "SELECT name, updated_at, data_json
                 FROM subscriptions ORDER BY name",
            )
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                let name = row_text(row, 0, "subscriptions.name")?;
                let updated_at = row_integer(row, 1, "subscriptions.updated_at")?;
                let data_json = row_blob_or_text(row, 2, "subscriptions.data_json")?;
                decode_subscription_link(name, updated_at, data_json)
            })
            .collect()
    }

    /// Upsert subscription links atomically.  This intentionally accepts the
    /// shared compatibility record instead of a second HTTP-only DTO tree.
    pub async fn put_go_subscription_links(
        &self,
        records: &[GoSubscriptionLinkRecord],
    ) -> Result<()> {
        let normalized = records
            .iter()
            .map(|record| {
                let name = record.name.trim().to_owned();
                let url = record.url.trim().to_owned();
                let link_type = if record.link_type.trim().is_empty() {
                    "reserve".to_owned()
                } else {
                    record.link_type.trim().to_owned()
                };
                if name.is_empty() {
                    return Err(Error::invalid("subscription name is empty"));
                }
                if url.is_empty() {
                    return Err(Error::invalid(format!(
                        "subscription {name:?} url is empty"
                    )));
                }
                validate_go_texts(&[("subscription name", &name), ("subscription url", &url)])?;
                validate_json_bytes(&record.data_json, "subscriptions.data_json")?;
                let mut value: serde_json::Value = serde_json::from_slice(&record.data_json)
                    .map_err(|error| {
                        Error::invalid(format!("subscription {name:?} JSON is invalid: {error}"))
                    })?;
                let object = value.as_object_mut().ok_or_else(|| {
                    Error::invalid(format!("subscription {name:?} JSON must be an object"))
                })?;
                object.insert("name".to_owned(), serde_json::Value::String(name.clone()));
                object.insert("url".to_owned(), serde_json::Value::String(url));
                object.insert(
                    "type".to_owned(),
                    serde_json::Value::String(link_type.clone()),
                );
                let data_json = serde_json::to_vec(&value).map_err(|error| {
                    Error::invalid(format!("encode subscription {name:?} failed: {error}"))
                })?;
                let updated_at = if record.updated_at == 0 {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |duration| duration.as_secs() as i64)
                } else {
                    record.updated_at
                };
                validate_go_timestamp(updated_at)?;
                Ok((name, updated_at, data_json))
            })
            .collect::<Result<Vec<_>>>()?;

        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "subscriptions",
                &["name", "updated_at", "data_json"],
            )?;
            for (name, updated_at, data_json) in &normalized {
                connection
                    .execute_with_params(
                        "INSERT INTO subscriptions(name, updated_at, data_json)
                         VALUES (?1, ?2, ?3)
                         ON CONFLICT(name) DO UPDATE SET
                           updated_at = excluded.updated_at,
                           data_json = excluded.data_json",
                        &[
                            SqliteValue::from(name.as_str()),
                            SqliteValue::from(*updated_at),
                            SqliteValue::from(data_json.as_slice()),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            Ok(())
        })
    }

    pub async fn delete_go_subscription_links(&self, names: &[String]) -> Result<()> {
        for name in names {
            validate_id(name)?;
        }
        let names = names.to_vec();
        self.store.with_write_transaction(|connection| {
            require_go_table(connection, "subscriptions", &["name"])?;
            for name in &names {
                connection
                    .execute_with_params(
                        "DELETE FROM subscriptions WHERE name = ?1",
                        &[SqliteValue::from(name.as_str())],
                    )
                    .map_err(storage_error)?;
            }
            Ok(())
        })
    }

    /// Read Go's publish contracts from the native `publishes` table.  Go
    /// orders these rows by their primary-key name and leaves contract
    /// normalization to the decode boundary.
    pub async fn list_go_publishes(&self) -> Result<Vec<GoPublishRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "publishes") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query(
                "SELECT name, updated_at, data_json
                 FROM publishes ORDER BY name",
            )
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                let data_json = row_blob_or_text(row, 2, "publishes.data_json")?;
                validate_json_bytes(&data_json, "publishes.data_json")?;
                Ok(GoPublishRecord {
                    name: row_text(row, 0, "publishes.name")?,
                    updated_at: row_integer(row, 1, "publishes.updated_at")?,
                    data_json,
                })
            })
            .collect()
    }

    /// Upsert one Go publish contract without exposing SQLite to the API
    /// layer.  The caller supplies the already-normalized JSON contract.
    pub async fn put_go_publish(&self, record: &GoPublishRecord) -> Result<()> {
        let name = record.name.trim().to_owned();
        if name.is_empty() {
            return Err(Error::invalid("publish name is empty"));
        }
        validate_go_texts(&[("publish name", &name)])?;
        let updated_at = if record.updated_at == 0 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs() as i64)
        } else {
            record.updated_at
        };
        validate_go_timestamp(updated_at)?;
        validate_json_bytes(&record.data_json, "publishes.data_json")?;
        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "publishes",
                &["name", "updated_at", "data_json"],
            )?;
            connection
                .execute_with_params(
                    "INSERT INTO publishes(name, updated_at, data_json)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(name) DO UPDATE SET
                       updated_at = excluded.updated_at,
                       data_json = excluded.data_json",
                    &[
                        SqliteValue::from(name.as_str()),
                        SqliteValue::from(updated_at),
                        SqliteValue::from(record.data_json.as_slice()),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    /// Delete one publish and report whether the Go row existed.  The HTTP
    /// layer maps `false` to Go's 404/not_found response.
    pub async fn delete_go_publish(&self, name: &str) -> Result<bool> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::invalid("publish name is empty"));
        }
        validate_go_texts(&[("publish name", &name.to_owned())])?;
        self.store.with_write_retry(|connection| {
            require_go_table(connection, "publishes", &["name"])?;
            connection
                .execute_with_params(
                    "DELETE FROM publishes WHERE name = ?1",
                    &[SqliteValue::from(name)],
                )
                .map(|changed| changed != 0)
                .map_err(storage_error)
        })
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
            ("node origin", &record.origin),
        ])?;
        // Go's node contract permits an empty group_name for manually saved
        // nodes. It is still bounded and control-character-free, but unlike
        // identifiers it is not required to contain one character.
        validate_go_compat_text(&record.group_name, "node group_name")?;
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

    /// Delete a Go route-tag contract by its public name.  The current Go
    /// store addresses tags by `name`; older imported rows may have a
    /// compatibility `id` that is not identical to that name.
    pub async fn delete_go_node_tag_by_name(&self, name: &str) -> Result<bool> {
        validate_id(name)?;
        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "node_tags_v2",
                &["id", "name", "members_json", "updated_at"],
            )?;
            connection
                .execute_with_params(
                    "DELETE FROM node_tags_v2 WHERE name = ?1",
                    &[SqliteValue::from(name)],
                )
                .map(|changed| changed != 0)
                .map_err(storage_error)
        })
    }

    pub async fn delete_go_resolver(&self, id: &str) -> Result<bool> {
        self.delete_go_compatibility_row("resolvers_v2", "id", id)
    }

    pub async fn delete_go_route_rule(&self, id: &str) -> Result<bool> {
        self.delete_go_compatibility_row("route_rules_v2", "id", id)
    }

    /// Delete a Go route-rule contract by its public name and renumber the
    /// remaining priorities, matching the v2 Go store.  The API addresses a
    /// rule by name; the compatibility row id is an import detail and may not
    /// equal that name in older snapshots.
    pub async fn delete_go_route_rule_by_name(&self, name: &str) -> Result<bool> {
        validate_id(name)?;
        self.store.with_write_transaction(|connection| {
            require_go_table(connection, "route_rules_v2", &["id", "name", "priority"])?;
            let changed = connection
                .execute_with_params(
                    "DELETE FROM route_rules_v2 WHERE name = ?1",
                    &[SqliteValue::from(name)],
                )
                .map_err(storage_error)?;
            if changed == 0 {
                return Ok(false);
            }

            let rows = connection
                .query("SELECT name FROM route_rules_v2 ORDER BY priority, id")
                .map_err(storage_error)?;
            let names = rows
                .iter()
                .map(|row| row_text(row, 0, "route_rules_v2.name"))
                .collect::<Result<Vec<_>>>()?;
            for (index, rule_name) in names.iter().enumerate() {
                connection
                    .execute_with_params(
                        "UPDATE route_rules_v2 SET priority = ?1 WHERE name = ?2",
                        &[
                            SqliteValue::from(-((index as i64) + 1)),
                            SqliteValue::from(rule_name.as_str()),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            for (index, rule_name) in names.iter().enumerate() {
                connection
                    .execute_with_params(
                        "UPDATE route_rules_v2 SET priority = ?1 WHERE name = ?2",
                        &[
                            SqliteValue::from((index as i64) + 1),
                            SqliteValue::from(rule_name.as_str()),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            Ok(true)
        })
    }

    /// Reorder Go route rules atomically and renumber their persisted
    /// priorities.  The web API addresses rules by their user-visible name,
    /// matching Go's v2 contract; IDs and JSON payloads remain untouched.
    pub async fn change_go_route_rule_priority(
        &self,
        source_name: &str,
        target_name: &str,
        operate: &str,
    ) -> Result<()> {
        validate_id(source_name)?;
        validate_id(target_name)?;
        if !matches!(operate, "" | "exchange" | "insert_before" | "insert_after") {
            return Err(Error::invalid(format!(
                "unknown priority operate {operate:?}"
            )));
        }

        self.store.with_write_transaction(|connection| {
            require_go_table(connection, "route_rules_v2", &["id", "name", "priority"])?;
            let rows = connection
                .query("SELECT id, name FROM route_rules_v2 ORDER BY priority, id")
                .map_err(storage_error)?;
            let mut entries = rows
                .iter()
                .map(|row| {
                    Ok((
                        row_text(row, 0, "route_rules_v2.id")?,
                        row_text(row, 1, "route_rules_v2.name")?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;

            let source_index = entries
                .iter()
                .position(|(_, name)| name == source_name)
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::NotFound,
                        format!("route rule {source_name} not found"),
                    )
                })?;
            let target_index = entries
                .iter()
                .position(|(_, name)| name == target_name)
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::NotFound,
                        format!("route rule {target_name} not found"),
                    )
                })?;

            match operate {
                "" | "exchange" => entries.swap(source_index, target_index),
                "insert_before" | "insert_after" => {
                    let source = entries.remove(source_index);
                    let target_index = entries
                        .iter()
                        .position(|(_, name)| name == target_name)
                        .ok_or_else(|| {
                            Error::new(
                                ErrorKind::NotFound,
                                format!("route rule {target_name} not found"),
                            )
                        })?;
                    let insert_at = if operate == "insert_after" {
                        target_index + 1
                    } else {
                        target_index
                    };
                    entries.insert(insert_at, source);
                }
                _ => unreachable!("priority operation was validated above"),
            }

            for (priority, (id, _)) in entries.iter().enumerate() {
                connection
                    .execute_with_params(
                        "UPDATE route_rules_v2 SET priority = ?1 WHERE id = ?2",
                        &[
                            SqliteValue::from(priority as i64),
                            SqliteValue::from(id.as_str()),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            Ok(())
        })
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
                            .map_or(SqliteValue::Null, SqliteValue::from),
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

fn decode_subscription_link(
    name: String,
    updated_at: i64,
    data_json: Vec<u8>,
) -> Result<GoSubscriptionLinkRecord> {
    validate_go_timestamp(updated_at)?;
    validate_json_bytes(&data_json, "subscriptions.data_json")?;
    let mut value: serde_json::Value = serde_json::from_slice(&data_json)
        .map_err(|error| Error::invalid(format!("decode subscription {name:?} failed: {error}")))?;
    let object = value.as_object_mut().ok_or_else(|| {
        Error::invalid(format!(
            "stored subscription {name:?} JSON must be an object"
        ))
    })?;
    let normalized_name = object
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(name.as_str())
        .to_owned();
    let url = object
        .get("url")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    if normalized_name.is_empty() {
        return Err(Error::invalid("subscription name is empty"));
    }
    if url.is_empty() {
        return Err(Error::invalid(format!(
            "subscription {normalized_name:?} url is empty"
        )));
    }
    let link_type = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("reserve")
        .to_owned();
    object.insert(
        "name".to_owned(),
        serde_json::Value::String(normalized_name.clone()),
    );
    object.insert("url".to_owned(), serde_json::Value::String(url.clone()));
    object.insert(
        "type".to_owned(),
        serde_json::Value::String(link_type.clone()),
    );
    let data_json = serde_json::to_vec(&value).map_err(|error| {
        Error::invalid(format!(
            "normalize subscription {normalized_name:?} failed: {error}"
        ))
    })?;
    validate_go_texts(&[
        ("subscription name", &normalized_name),
        ("subscription url", &url),
    ])?;
    Ok(GoSubscriptionLinkRecord {
        name: normalized_name,
        url,
        link_type,
        updated_at,
        data_json,
    })
}
