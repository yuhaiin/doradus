//! Go compatibility entity operations.

use super::*;

impl ConfigRepository {
    /// Write one Go v6 compatibility row without normalizing or dropping the
    /// original `data_json`.  These methods intentionally target the explicit
    /// `_v2` contract tables only; a Go v1 table renamed to
    /// `go_legacy_*` must first be migrated by an explicit schema migration.
    pub fn put_go_inbound_sync(&self, record: &GoInboundRecord) -> Result<()> {
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

    pub async fn put_go_inbound(&self, record: &GoInboundRecord) -> Result<()> {
        self.put_go_inbound_sync(record)
    }

    pub fn put_go_node_sync(&self, record: &GoNodeRecord) -> Result<()> {
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

    pub async fn put_go_node(&self, record: &GoNodeRecord) -> Result<()> {
        self.put_go_node_sync(record)
    }

    pub fn put_go_node_tag_sync(&self, record: &GoNodeTagRecord) -> Result<()> {
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

    pub async fn put_go_node_tag(&self, record: &GoNodeTagRecord) -> Result<()> {
        self.put_go_node_tag_sync(record)
    }

    pub fn put_go_resolver_sync(&self, record: &GoResolverRecord) -> Result<()> {
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

    pub async fn put_go_resolver(&self, record: &GoResolverRecord) -> Result<()> {
        self.put_go_resolver_sync(record)
    }
}
