//! Native typed repository operations.

use super::*;

impl ConfigRepository {
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
