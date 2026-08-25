//! Go compatibility configuration and DNS operations.

use super::*;

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
            if hosts
                .insert_host_target(&record.host, &record.target)
                .is_err()
            {
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
}
