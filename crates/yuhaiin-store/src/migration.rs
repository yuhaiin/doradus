//! Go schema import, legacy upgrades, and migration validation.

use std::collections::BTreeMap;

use super::*;

pub(super) fn import_go_schema(connection: &Connection) -> Result<()> {
    if !table_exists(connection, "metadata") || !table_exists(connection, "migrate") {
        return Ok(());
    }
    let already_imported = connection
        .query_with_params(
            "SELECT value FROM yuhaiin_meta WHERE key = ?1",
            &[SqliteValue::from("go_schema_imported")],
        )
        .map_err(storage_error)?
        .first()
        .and_then(|row| row.get(0))
        .and_then(|value| match value {
            SqliteValue::Integer(value) => Some(*value != 0),
            _ => None,
        })
        .unwrap_or(false);
    let legacy_upgrade_pending = [
        ("go_legacy_dns_resolvers", "go_v1_resolvers_upgraded"),
        ("go_legacy_route_rules", "go_v1_route_rules_upgraded"),
        ("nodes", "go_v1_nodes_upgraded"),
        ("inbounds", "go_v1_inbounds_upgraded"),
        ("route_lists", "go_v1_route_lists_upgraded"),
        ("node_tags", "go_v1_node_tags_upgraded"),
    ]
    .into_iter()
    .any(|(table, marker)| table_exists(connection, table) && !meta_flag(connection, marker));
    if already_imported && !legacy_upgrade_pending {
        return Ok(());
    }

    let source_version = read_go_schema_version(connection)?;

    connection
        .execute("BEGIN IMMEDIATE")
        .map_err(storage_error)?;
    let result = (|| {
        if table_exists(connection, "nodes_v2") {
            let rows = connection
                .query("SELECT id, chain_types_json, data_json FROM nodes_v2 ORDER BY id")
                .map_err(storage_error)?;
            for row in rows {
                let id = row_text(&row, 0, "nodes_v2.id")?;
                validate_go_texts(&[("nodes_v2.id", &id)])?;
                row_json_blob_or_text(&row, 1, "nodes_v2.chain_types_json")?;
                let data_json = row_json_blob_or_text(&row, 2, "nodes_v2.data_json")?;
                connection
                    .execute_with_params(
                        "INSERT OR REPLACE INTO proxy_nodes (id, kind, config)
                         VALUES (?1, ?2, ?3)",
                        &[
                            SqliteValue::from(id),
                            SqliteValue::from("go-node"),
                            SqliteValue::from(data_json),
                        ],
                    )
                    .map_err(storage_error)?;
            }
        }
        if table_exists(connection, "resolvers_v2") {
            let rows = connection
                .query("SELECT id, resolver_type, data_json FROM resolvers_v2 ORDER BY id")
                .map_err(storage_error)?;
            for row in rows {
                let id = row_text(&row, 0, "resolvers_v2.id")?;
                let resolver_type = row_text(&row, 1, "resolvers_v2.resolver_type")?;
                validate_go_texts(&[
                    ("resolvers_v2.id", &id),
                    ("resolvers_v2.resolver_type", &resolver_type),
                ])?;
                let data_json = row_json_blob_or_text(&row, 2, "resolvers_v2.data_json")?;
                connection
                    .execute_with_params(
                        "INSERT OR REPLACE INTO dns_resolvers (id, kind, config)
                         VALUES (?1, ?2, ?3)",
                        &[
                            SqliteValue::from(id),
                            SqliteValue::from(resolver_type),
                            SqliteValue::from(data_json),
                        ],
                    )
                    .map_err(storage_error)?;
            }
        }
        if table_exists(connection, "route_rules_v2") {
            let rows = connection
                .query(
                    "SELECT id, match_type, action_mode, priority, data_json
                     FROM route_rules_v2 ORDER BY priority, id",
                )
                .map_err(storage_error)?;
            for row in rows {
                let id = row_text(&row, 0, "route_rules_v2.id")?;
                let match_type = row_text(&row, 1, "route_rules_v2.match_type")?;
                let action_mode = row_text(&row, 2, "route_rules_v2.action_mode")?;
                validate_go_texts(&[
                    ("route_rules_v2.id", &id),
                    ("route_rules_v2.match_type", &match_type),
                    ("route_rules_v2.action_mode", &action_mode),
                ])?;
                let data_json = row_json_blob_or_text(&row, 4, "route_rules_v2.data_json")?;
                connection
                    .execute_with_params(
                        "INSERT OR REPLACE INTO route_rules
                         (id, pattern, action, priority, resolver_policy)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        &[
                            SqliteValue::from(id),
                            SqliteValue::from(match_type),
                            SqliteValue::from(action_mode),
                            SqliteValue::from(row_integer(&row, 3, "route_rules_v2.priority")?),
                            SqliteValue::from(data_json),
                        ],
                    )
                    .map_err(storage_error)?;
            }
        }
        if table_exists(connection, "inbounds_v2") {
            let rows = connection
                .query(
                    "SELECT id, transport_types_json, updated_at, data_json
                     FROM inbounds_v2 ORDER BY id",
                )
                .map_err(storage_error)?;
            for row in rows {
                let id = row_text(&row, 0, "inbounds_v2.id")?;
                validate_go_texts(&[("inbounds_v2.id", &id)])?;
                row_json_blob_or_text(&row, 1, "inbounds_v2.transport_types_json")?;
                validate_go_timestamp(row_integer(&row, 2, "inbounds_v2.updated_at")?)?;
                let data_json = row_json_blob_or_text(&row, 3, "inbounds_v2.data_json")?;
                connection
                    .execute_with_params(
                        "INSERT OR REPLACE INTO yuhaiin_config (key, value)
                         VALUES (?1, ?2)",
                        &[
                            SqliteValue::from(format!("go.inbound.{id}")),
                            SqliteValue::from(data_json),
                        ],
                    )
                    .map_err(storage_error)?;
            }
        }
        if table_exists(connection, "node_tags_v2") {
            let rows = connection
                .query(
                    "SELECT id, name, members_json, updated_at
                     FROM node_tags_v2 ORDER BY id",
                )
                .map_err(storage_error)?;
            for row in rows {
                validate_id(&row_text(&row, 0, "node_tags_v2.id")?)?;
                validate_id(&row_text(&row, 1, "node_tags_v2.name")?)?;
                row_json_blob_or_text(&row, 2, "node_tags_v2.members_json")?;
                validate_go_timestamp(row_integer(&row, 3, "node_tags_v2.updated_at")?)?;
            }
        }
        if table_exists(connection, "route_lists_v2") {
            let rows = connection
                .query(
                    "SELECT name, list_type, source_type, updated_at, data_json
                     FROM route_lists_v2 ORDER BY name",
                )
                .map_err(storage_error)?;
            for row in rows {
                validate_id(&row_text(&row, 0, "route_lists_v2.name")?)?;
                validate_go_compat_text(
                    &row_text(&row, 1, "route_lists_v2.list_type")?,
                    "route_lists_v2.list_type",
                )?;
                validate_go_compat_text(
                    &row_text(&row, 2, "route_lists_v2.source_type")?,
                    "route_lists_v2.source_type",
                )?;
                validate_go_timestamp(row_integer(&row, 3, "route_lists_v2.updated_at")?)?;
                row_json_blob_or_text(&row, 4, "route_lists_v2.data_json")?;
            }
        }
        if table_exists(connection, "settings_json") {
            let rows = connection
                .query("SELECT data_json FROM settings_json WHERE id = 1")
                .map_err(storage_error)?;
            if let Some(row) = rows.first() {
                let data_json = row_json_blob_or_text(row, 0, "settings_json.data_json")?;
                connection
                    .execute_with_params(
                        "INSERT OR REPLACE INTO yuhaiin_config (key, value)
                         VALUES (?1, ?2)",
                        &[
                            SqliteValue::from("go.settings_json"),
                            SqliteValue::from(data_json),
                        ],
                    )
                    .map_err(storage_error)?;
            }
        }
        upgrade_go_v1_legacy_tables(connection, source_version)?;
        connection
            .execute_with_params(
                "INSERT OR REPLACE INTO yuhaiin_meta (key, value) VALUES (?1, ?2)",
                &[
                    SqliteValue::from("go_schema_imported"),
                    SqliteValue::from(1i64),
                ],
            )
            .map_err(storage_error)?;
        connection
            .execute_with_params(
                "INSERT OR REPLACE INTO yuhaiin_meta (key, value) VALUES (?1, ?2)",
                &[
                    SqliteValue::from("go_schema_version"),
                    SqliteValue::from(source_version),
                ],
            )
            .map_err(storage_error)?;
        Ok(())
    })();
    match result {
        Ok(()) => connection
            .execute("COMMIT")
            .map(|_| ())
            .map_err(storage_error),
        Err(error) => {
            let _ = connection.execute("ROLLBACK");
            Err(error)
        }
    }
}

/// Reproduce Go's one-time recovery for old legacy nodes whose plain
/// migration dropped a partially populated `network_split` step. The v2
/// node rows remain authoritative for existing steps; only the missing legacy
/// split is inserted in its original position.
pub(super) fn recover_legacy_node_chains(connection: &Connection) -> Result<()> {
    if !table_exists(connection, "nodes")
        || !table_exists(connection, "nodes_v2")
        || meta_flag(connection, "plain_node_chain_recovery_v1_done")
    {
        return Ok(());
    }

    let legacy_rows = connection
        .query("SELECT hash, data_json FROM nodes ORDER BY hash")
        .map_err(storage_error)?;
    let mut recovery = Vec::new();
    for row in &legacy_rows {
        let id = row_text(row, 0, "nodes.hash")?;
        let legacy = row_json_blob_or_text(row, 1, "nodes.data_json")?;
        let legacy: serde_json::Value = serde_json::from_slice(&legacy).map_err(|error| {
            Error::new(
                ErrorKind::Storage,
                format!("decode legacy node {id:?} for chain recovery: {error}"),
            )
        })?;
        let Some(protocols) = legacy.get("protocols").and_then(|value| value.as_array()) else {
            continue;
        };
        let partials = protocols
            .iter()
            .filter_map(partial_network_split)
            .collect::<Vec<_>>();
        if partials.is_empty() {
            continue;
        }
        let current_rows = connection
            .query_with_params(
                "SELECT data_json, updated_at FROM nodes_v2 WHERE id = ?1",
                &[SqliteValue::from(id.as_str())],
            )
            .map_err(storage_error)?;
        let Some(current_row) = current_rows.first() else {
            continue;
        };
        let current_json = row_json_blob_or_text(current_row, 0, "nodes_v2.data_json")?;
        let current: serde_json::Value =
            serde_json::from_slice(&current_json).map_err(|error| {
                Error::new(
                    ErrorKind::Storage,
                    format!("decode node {id:?} for chain recovery: {error}"),
                )
            })?;
        let Some(current_chain) = current.get("chain").and_then(|value| value.as_array()) else {
            continue;
        };
        let recovered = recover_partial_network_splits(current_chain, protocols);
        if recovered != *current_chain {
            let mut value = current;
            value["chain"] = serde_json::Value::Array(recovered.clone());
            let chain_types = recovered
                .iter()
                .filter_map(|node| node.get("type").and_then(|value| value.as_str()))
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let data_json = serde_json::to_vec(&value).map_err(|error| {
                Error::new(
                    ErrorKind::Storage,
                    format!("encode recovered node {id:?}: {error}"),
                )
            })?;
            let chain_types_json = serde_json::to_vec(&chain_types).map_err(|error| {
                Error::new(
                    ErrorKind::Storage,
                    format!("encode recovered node types {id:?}: {error}"),
                )
            })?;
            recovery.push((
                id,
                data_json,
                chain_types_json,
                row_integer(current_row, 1, "nodes_v2.updated_at")?,
            ));
        }
    }

    connection
        .execute("BEGIN IMMEDIATE")
        .map_err(storage_error)?;
    let result = (|| {
        for (id, data_json, chain_types_json, updated_at) in &recovery {
            connection
                .execute_with_params(
                    "UPDATE nodes_v2
                     SET data_json = ?1, chain_types_json = ?2, updated_at = ?3
                     WHERE id = ?4",
                    &[
                        SqliteValue::from(data_json.as_slice()),
                        SqliteValue::from(chain_types_json.as_slice()),
                        SqliteValue::from(*updated_at),
                        SqliteValue::from(id.as_str()),
                    ],
                )
                .map_err(storage_error)?;
        }
        set_meta_flag(connection, "plain_node_chain_recovery_v1_done")
    })();
    match result {
        Ok(()) => connection
            .execute("COMMIT")
            .map(|_| ())
            .map_err(storage_error),
        Err(error) => {
            let _ = connection.execute("ROLLBACK");
            Err(error)
        }
    }
}

fn recover_partial_network_splits(
    current: &[serde_json::Value],
    legacy_protocols: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let mut recovered = Vec::with_capacity(current.len() + 1);
    let mut current_index = 0;
    for legacy in legacy_protocols {
        let Some(expected_type) = legacy_protocol_type(legacy) else {
            continue;
        };
        if current_index < current.len()
            && current[current_index]
                .get("type")
                .and_then(|value| value.as_str())
                == Some(expected_type.as_str())
        {
            recovered.push(current[current_index].clone());
            current_index += 1;
            continue;
        }
        if expected_type == "network_split"
            && let Some(protocol) = legacy_network_split_contract(legacy)
        {
            recovered.push(protocol);
        }
    }
    recovered.extend(current.iter().skip(current_index).cloned());
    recovered
}

fn partial_network_split(value: &serde_json::Value) -> Option<()> {
    let split = value.get("networkSplit")?.as_object()?;
    (split.contains_key("tcp") != split.contains_key("udp")).then_some(())
}

fn legacy_protocol_type(value: &serde_json::Value) -> Option<String> {
    value
        .as_object()?
        .keys()
        .next()
        .map(|key| canonical_protocol_name(key))
}

fn legacy_network_split_contract(value: &serde_json::Value) -> Option<serde_json::Value> {
    let split = value.get("networkSplit")?.as_object()?;
    if split.contains_key("tcp") == split.contains_key("udp") {
        return None;
    }
    let branch = if split.contains_key("tcp") {
        "tcp"
    } else {
        "udp"
    };
    let protocol = legacy_protocol_contract(split.get(branch)?)?;
    let mut branches = serde_json::Map::new();
    branches.insert(branch.to_owned(), protocol);
    let mut result = serde_json::Map::new();
    result.insert(
        "type".to_owned(),
        serde_json::Value::String("network_split".to_owned()),
    );
    result.insert(
        "network_split".to_owned(),
        serde_json::Value::Object(branches),
    );
    Some(serde_json::Value::Object(result))
}

fn legacy_protocol_contract(value: &serde_json::Value) -> Option<serde_json::Value> {
    let object = value.as_object()?;
    let (kind, config) = object.iter().next()?;
    let kind = canonical_protocol_name(kind);
    let mut protocol = serde_json::Map::new();
    protocol.insert("type".to_owned(), serde_json::Value::String(kind.clone()));
    protocol.insert(
        kind.clone(),
        normalize_legacy_protocol_config(&kind, config)?,
    );
    Some(serde_json::Value::Object(protocol))
}

fn normalize_legacy_protocol_config(
    kind: &str,
    config: &serde_json::Value,
) -> Option<serde_json::Value> {
    if kind != "aead" {
        return Some(config.clone());
    }
    let mut config = config.as_object()?.clone();
    if let Some(method) = config.get_mut("crypto_method") {
        let normalized = match method {
            serde_json::Value::Number(number) => match number.as_i64()? {
                0 => "Chacha20Poly1305",
                1 => "XChacha20Poly1305",
                _ => return None,
            },
            serde_json::Value::String(value) => value.as_str(),
            _ => return None,
        };
        *method = serde_json::Value::String(normalized.to_owned());
    }
    Some(serde_json::Value::Object(config))
}

fn canonical_protocol_name(value: &str) -> String {
    match value {
        "networkSplit" => "network_split".to_owned(),
        "httpProxy" => "http_proxy".to_owned(),
        "reverseHttp" => "reverse_http".to_owned(),
        "reverseTcp" => "reverse_tcp".to_owned(),
        "tlsTermination" => "tls_termination".to_owned(),
        "pointAsEndpoint" => "point_as_endpoint".to_owned(),
        "fixedV2" => "fixedv2".to_owned(),
        other => other.to_owned(),
    }
}

fn read_go_schema_version(connection: &Connection) -> Result<i64> {
    let metadata_rows = connection
        .query_with_params(
            "SELECT value FROM metadata WHERE key = ?1",
            &[SqliteValue::from("schema_version")],
        )
        .map_err(storage_error)?;
    let metadata_version = metadata_rows
        .first()
        .map(|row| {
            let version = match row.get(0) {
                Some(SqliteValue::Text(value)) => {
                    value.as_ref().parse::<i64>().map_err(|error| {
                        Error::new(
                            ErrorKind::Storage,
                            format!("Go schema_version is not an integer: {error}"),
                        )
                    })?
                }
                Some(SqliteValue::Integer(value)) => *value,
                _ => {
                    return Err(Error::new(
                        ErrorKind::Storage,
                        "Go schema_version has an unsupported value type",
                    ));
                }
            };
            if version < 0 {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "Go schema_version must not be negative",
                ));
            }
            validate_go_schema_version(version)
        })
        .transpose()?;

    let rows = connection
        .query("SELECT version FROM migrate ORDER BY version")
        .map_err(storage_error)?;
    let mut version = 0;
    for row in rows {
        let value = match row.get(0) {
            Some(SqliteValue::Integer(value)) => *value,
            Some(SqliteValue::Null) | None => {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "Go migrate.version must be an integer",
                ));
            }
            Some(_) => {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "Go migrate.version must be an integer",
                ));
            }
        };
        if value < 0 {
            return Err(Error::new(
                ErrorKind::Storage,
                "Go migration version must not be negative",
            ));
        }
        version = version.max(value);
    }
    let migration_version = validate_go_schema_version(version)?;
    if let Some(metadata_version) = metadata_version {
        if metadata_version != migration_version {
            // Some current Go production databases contain the additive
            // subscription/user-link migration (version 7) while retaining
            // metadata.schema_version = 6. Go treats `migrate` as the source
            // of applied migrations and opens this shape successfully. Keep
            // the compatibility exception narrow: only the known v7 tables
            // may make a 6 -> 7 mismatch valid; arbitrary mismatches still
            // fail closed below.
            let known_additive_v7 = metadata_version == 6
                && migration_version == 7
                && (table_exists(connection, "subscription_nodes_v2")
                    || table_exists(connection, "subscription_users_v2"));
            if known_additive_v7 {
                return Ok(migration_version);
            }
            return Err(Error::new(
                ErrorKind::Storage,
                format!(
                    "Go metadata schema_version {metadata_version} does not match migrate version {migration_version}"
                ),
            ));
        }
        return Ok(metadata_version);
    }
    Ok(migration_version)
}

fn validate_go_schema_version(version: i64) -> Result<i64> {
    if version > MAX_SUPPORTED_GO_SCHEMA_VERSION {
        return Err(Error::new(
            ErrorKind::Storage,
            format!(
                "unsupported Go schema version {version}; maximum supported version is {MAX_SUPPORTED_GO_SCHEMA_VERSION}"
            ),
        ));
    }
    Ok(version)
}

pub(super) fn meta_flag(connection: &Connection, key: &str) -> bool {
    connection
        .query_with_params(
            "SELECT value FROM yuhaiin_meta WHERE key = ?1",
            &[SqliteValue::from(key)],
        )
        .ok()
        .and_then(|rows| rows.first().cloned())
        .and_then(|row| row.get(0).cloned())
        .is_some_and(|value| matches!(value, SqliteValue::Integer(value) if value != 0))
}

/// Upgrade the two tables that existed before the Go plain-contract schema.
///
/// The old tables are deliberately kept under `go_legacy_*` names.  If a Go
/// `_v2` table already contains rows, it is authoritative and the old table
/// is only archived.  Otherwise this function maps the old scalar columns and
/// the legacy JSON into the `_v2` contract table in the same transaction as
/// the rest of the Go import.  The raw legacy object is retained as the base
/// of the generated JSON, so fields unknown to Rust remain recoverable.
fn upgrade_go_v1_legacy_tables(connection: &Connection, _source_version: i64) -> Result<()> {
    if table_exists(connection, "nodes") && !meta_flag(connection, "go_v1_nodes_upgraded") {
        upgrade_go_v1_nodes(connection)?;
        set_meta_flag(connection, "go_v1_nodes_upgraded")?;
    }
    if table_exists(connection, "inbounds") && !meta_flag(connection, "go_v1_inbounds_upgraded") {
        upgrade_go_v1_inbounds(connection)?;
        set_meta_flag(connection, "go_v1_inbounds_upgraded")?;
    }
    if table_exists(connection, "route_lists")
        && !meta_flag(connection, "go_v1_route_lists_upgraded")
    {
        upgrade_go_v1_route_lists(connection)?;
        set_meta_flag(connection, "go_v1_route_lists_upgraded")?;
    }
    if table_exists(connection, "node_tags") && !meta_flag(connection, "go_v1_node_tags_upgraded") {
        upgrade_go_v1_node_tags(connection)?;
        set_meta_flag(connection, "go_v1_node_tags_upgraded")?;
    }
    if table_exists(connection, "go_legacy_dns_resolvers")
        && !meta_flag(connection, "go_v1_resolvers_upgraded")
    {
        upgrade_go_v1_resolvers(connection)?;
        set_meta_flag(connection, "go_v1_resolvers_upgraded")?;
    }
    if table_exists(connection, "go_legacy_route_rules")
        && !meta_flag(connection, "go_v1_route_rules_upgraded")
    {
        upgrade_go_v1_route_rules(connection)?;
        set_meta_flag(connection, "go_v1_route_rules_upgraded")?;
    }
    Ok(())
}

fn upgrade_go_v1_nodes(connection: &Connection) -> Result<()> {
    require_go_table(
        connection,
        "nodes",
        &[
            "hash",
            "group_name",
            "name",
            "origin",
            "selected_tcp",
            "selected_udp",
            "updated_at",
            "data_json",
        ],
    )?;
    if table_row_count(connection, "nodes_v2")? != 0 {
        return Ok(());
    }

    let rows = connection
        .query(
            "SELECT hash, group_name, name, origin, selected_tcp, selected_udp,
                    updated_at, data_json
             FROM nodes ORDER BY hash",
        )
        .map_err(storage_error)?;
    for row in &rows {
        let id = row_text(row, 0, "nodes.hash")?;
        let group_name = row_text(row, 1, "nodes.group_name")?;
        let name = row_text(row, 2, "nodes.name")?;
        let origin_value = row_integer(row, 3, "nodes.origin")?;
        let updated_at = row_integer(row, 6, "nodes.updated_at")?;
        validate_id(&id)?;
        validate_id(&name)?;
        validate_go_compat_text(&group_name, "nodes.group_name")?;
        validate_go_timestamp(updated_at)?;

        let mut object = legacy_json_object(
            &row_blob_or_text(row, 7, "nodes.data_json")?,
            "nodes.data_json",
        )?;
        let chain = object
            .remove("protocols")
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|protocol| legacy_protocol_contract(&protocol))
            .collect::<Vec<_>>();
        let chain = if chain.is_empty() {
            vec![serde_json::json!({"type": "direct", "direct": {}})]
        } else {
            chain
        };
        let origin = json_string(&object, &["origin"])
            .or_else(|| match origin_value {
                101 => Some("remote".to_owned()),
                102 => Some("manual".to_owned()),
                _ => Some("reserve".to_owned()),
            })
            .unwrap_or_else(|| "reserve".to_owned());
        let chain_types = chain
            .iter()
            .filter_map(|protocol| protocol.get("type").and_then(serde_json::Value::as_str))
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        object.insert("id".to_owned(), serde_json::Value::String(id.clone()));
        object.insert("name".to_owned(), serde_json::Value::String(name.clone()));
        object.insert(
            "group".to_owned(),
            serde_json::Value::String(group_name.clone()),
        );
        object.insert(
            "origin".to_owned(),
            serde_json::Value::String(origin.clone()),
        );
        object.insert("enabled".to_owned(), serde_json::Value::Bool(true));
        object.insert("chain".to_owned(), serde_json::Value::Array(chain));
        let data_json = json_object_bytes(object, "legacy node")?;
        let chain_types_json = serde_json::to_vec(&chain_types).map_err(|error| {
            Error::new(
                ErrorKind::Storage,
                format!("encode legacy node chain types {id:?} failed: {error}"),
            )
        })?;
        connection
            .execute_with_params(
                "INSERT INTO nodes_v2
                 (id, name, group_name, origin, enabled, chain_types_json, updated_at, data_json)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7)",
                &[
                    SqliteValue::from(id),
                    SqliteValue::from(name),
                    SqliteValue::from(group_name),
                    SqliteValue::from(origin),
                    SqliteValue::from(chain_types_json),
                    SqliteValue::from(updated_at),
                    SqliteValue::from(data_json),
                ],
            )
            .map_err(storage_error)?;
    }

    for (metadata_key, selected_column) in [
        ("selected_tcp_node_v2", "selected_tcp"),
        ("selected_udp_node_v2", "selected_udp"),
    ] {
        connection
            .execute_with_params(
                &format!(
                    "INSERT INTO metadata(key, value)
                     SELECT ?1, hash FROM nodes
                     WHERE {selected_column} = 1
                       AND EXISTS (SELECT 1 FROM nodes_v2 WHERE id = nodes.hash)
                     LIMIT 1
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value
                     WHERE metadata.value = ''
                        OR NOT EXISTS (SELECT 1 FROM nodes_v2 WHERE id = metadata.value)"
                ),
                &[SqliteValue::from(metadata_key)],
            )
            .map_err(storage_error)?;
    }
    Ok(())
}

fn upgrade_go_v1_inbounds(connection: &Connection) -> Result<()> {
    require_go_table(
        connection,
        "inbounds",
        &["name", "enabled", "inbound_type", "updated_at", "data_json"],
    )?;
    if table_row_count(connection, "inbounds_v2")? != 0 {
        return Ok(());
    }
    let rows = connection
        .query(
            "SELECT name, enabled, inbound_type, updated_at, data_json
             FROM inbounds ORDER BY name",
        )
        .map_err(storage_error)?;
    for row in &rows {
        let id = row_text(row, 0, "inbounds.name")?;
        let enabled = row_integer(row, 1, "inbounds.enabled")? != 0;
        let inbound_type = row_text(row, 2, "inbounds.inbound_type")?;
        let updated_at = row_integer(row, 3, "inbounds.updated_at")?;
        validate_id(&id)?;
        validate_id(&inbound_type)?;
        validate_go_timestamp(updated_at)?;
        let legacy = legacy_json_object(
            &row_blob_or_text(row, 4, "inbounds.data_json")?,
            "inbounds.data_json",
        )?;
        let name = json_string(&legacy, &["name"])
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| id.clone());
        let (network_type, network) = legacy_inbound_network(&legacy);
        let protocol_type = canonical_inbound_name(&inbound_type);
        let protocol_config = legacy
            .get(&inbound_type)
            .or_else(|| legacy.get(&protocol_type))
            .or_else(|| {
                legacy.iter().find_map(|(key, value)| {
                    (!matches!(
                        key.as_str(),
                        "name" | "enabled" | "tcpudp" | "empty" | "transport"
                    ))
                    .then_some(value)
                })
            })
            .cloned()
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        let protocol_type =
            if legacy.contains_key(&inbound_type) || legacy.contains_key(&protocol_type) {
                protocol_type
            } else {
                "none".to_owned()
            };
        let mut protocol = serde_json::Map::new();
        protocol.insert(
            "type".to_owned(),
            serde_json::Value::String(protocol_type.clone()),
        );
        protocol.insert(protocol_type.clone(), protocol_config);

        let transports = legacy
            .get("transport")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(legacy_protocol_contract)
            .collect::<Vec<_>>();
        let transport_types = transports
            .iter()
            .filter_map(|transport| transport.get("type").cloned())
            .collect::<Vec<_>>();
        let mut contract = serde_json::Map::new();
        contract.insert("id".to_owned(), serde_json::Value::String(id.clone()));
        contract.insert("name".to_owned(), serde_json::Value::String(name.clone()));
        contract.insert("enabled".to_owned(), serde_json::Value::Bool(enabled));
        contract.insert("network".to_owned(), network);
        contract.insert(
            "transports".to_owned(),
            serde_json::Value::Array(transports),
        );
        contract.insert("protocol".to_owned(), serde_json::Value::Object(protocol));
        let data_json = json_object_bytes(contract, "legacy inbound")?;
        let transport_types_json = serde_json::to_vec(&transport_types).map_err(|error| {
            Error::new(
                ErrorKind::Storage,
                format!("encode legacy inbound transport types {id:?} failed: {error}"),
            )
        })?;
        connection
            .execute_with_params(
                "INSERT INTO inbounds_v2
                 (id, name, enabled, network_type, protocol_type,
                  transport_types_json, updated_at, data_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                &[
                    SqliteValue::from(id.clone()),
                    SqliteValue::from(name),
                    SqliteValue::from(i64::from(enabled)),
                    SqliteValue::from(network_type),
                    SqliteValue::from(protocol_type),
                    SqliteValue::from(transport_types_json),
                    SqliteValue::from(updated_at),
                    SqliteValue::from(data_json),
                ],
            )
            .map_err(storage_error)?;
    }
    Ok(())
}

fn legacy_inbound_network(
    legacy: &serde_json::Map<String, serde_json::Value>,
) -> (String, serde_json::Value) {
    if let Some(tcpudp) = legacy.get("tcpudp") {
        let mut config = tcpudp.as_object().cloned().unwrap_or_default();
        let udp = match config.get("control").and_then(serde_json::Value::as_str) {
            Some("disable_tcp") => "udp_only",
            Some("disable_udp") => "tcp_only",
            _ => "enabled",
        };
        config.insert("udp".to_owned(), serde_json::Value::String(udp.to_owned()));
        let mut network = serde_json::Map::new();
        network.insert(
            "type".to_owned(),
            serde_json::Value::String("tcp_udp".to_owned()),
        );
        network.insert("tcp_udp".to_owned(), serde_json::Value::Object(config));
        ("tcp_udp".to_owned(), serde_json::Value::Object(network))
    } else {
        (
            "empty".to_owned(),
            serde_json::json!({"type": "empty", "empty": {}}),
        )
    }
}

fn upgrade_go_v1_route_lists(connection: &Connection) -> Result<()> {
    require_go_table(
        connection,
        "route_lists",
        &["name", "kind", "updated_at", "data_json"],
    )?;
    if table_row_count(connection, "route_lists_v2")? != 0 {
        return Ok(());
    }
    let rows = connection
        .query("SELECT name, kind, updated_at, data_json FROM route_lists ORDER BY name")
        .map_err(storage_error)?;
    for row in &rows {
        let fallback_name = row_text(row, 0, "route_lists.name")?;
        let kind = row_text(row, 1, "route_lists.kind")?;
        let updated_at = row_integer(row, 2, "route_lists.updated_at")?;
        validate_id(&fallback_name)?;
        validate_go_timestamp(updated_at)?;
        let mut legacy = legacy_json_object(
            &row_blob_or_text(row, 3, "route_lists.data_json")?,
            "route_lists.data_json",
        )?;
        let name = json_string(&legacy, &["name"])
            .filter(|value| !value.is_empty())
            .unwrap_or(fallback_name);
        let list_type = json_string(&legacy, &["type", "listType", "list_type"])
            .or_else(|| (!kind.is_empty()).then_some(kind))
            .unwrap_or_else(|| "host".to_owned());
        let source_type = if legacy.contains_key("remote") {
            "remote"
        } else {
            "local"
        };
        let source_config = legacy
            .remove(source_type)
            .unwrap_or_else(|| serde_json::json!({}));
        let mut source = serde_json::Map::new();
        source.insert(
            "type".to_owned(),
            serde_json::Value::String(source_type.to_owned()),
        );
        source.insert(source_type.to_owned(), source_config);
        let mut contract = serde_json::Map::new();
        contract.insert("name".to_owned(), serde_json::Value::String(name.clone()));
        contract.insert(
            "type".to_owned(),
            serde_json::Value::String(list_type.clone()),
        );
        contract.insert(
            "errorMsgs".to_owned(),
            legacy
                .remove("errorMsgs")
                .unwrap_or_else(|| serde_json::json!([])),
        );
        contract.insert("source".to_owned(), serde_json::Value::Object(source));
        let data_json = json_object_bytes(contract, "legacy route list")?;
        connection
            .execute_with_params(
                "INSERT INTO route_lists_v2
                 (name, list_type, source_type, updated_at, data_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    SqliteValue::from(name),
                    SqliteValue::from(list_type),
                    SqliteValue::from(source_type),
                    SqliteValue::from(updated_at),
                    SqliteValue::from(data_json),
                ],
            )
            .map_err(storage_error)?;
    }
    Ok(())
}

fn upgrade_go_v1_node_tags(connection: &Connection) -> Result<()> {
    require_go_table(
        connection,
        "node_tags",
        &["tag_name", "target_kind", "target_id", "updated_at"],
    )?;
    if table_row_count(connection, "node_tags_v2")? != 0 {
        return Ok(());
    }
    let rows = connection
        .query(
            "SELECT tag_name, target_kind, target_id, updated_at
             FROM node_tags ORDER BY tag_name, target_kind, target_id",
        )
        .map_err(storage_error)?;
    let mut tags: BTreeMap<String, (String, Vec<String>, i64)> = BTreeMap::new();
    for row in &rows {
        let name = row_text(row, 0, "node_tags.tag_name")?;
        let target_kind = row_text(row, 1, "node_tags.target_kind")?;
        let target_id = row_text(row, 2, "node_tags.target_id")?;
        let updated_at = row_integer(row, 3, "node_tags.updated_at")?;
        validate_id(&name)?;
        validate_id(&target_id)?;
        validate_go_timestamp(updated_at)?;
        let entry = tags
            .entry(name)
            .or_insert_with(|| ("node".to_owned(), Vec::new(), updated_at));
        if target_kind == "tag" {
            entry.0 = "mirror".to_owned();
        }
        entry.1.push(target_id);
        entry.2 = entry.2.max(updated_at);
    }
    for (name, (tag_type, members, updated_at)) in tags {
        let data_json = json_object_bytes(
            serde_json::Map::from_iter([
                ("name".to_owned(), serde_json::Value::String(name.clone())),
                ("type".to_owned(), serde_json::Value::String(tag_type)),
                (
                    "hash".to_owned(),
                    serde_json::Value::Array(
                        members.into_iter().map(serde_json::Value::String).collect(),
                    ),
                ),
            ]),
            "legacy node tag",
        )?;
        connection
            .execute_with_params(
                "INSERT INTO node_tags_v2(id, name, members_json, updated_at)
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    SqliteValue::from(name.clone()),
                    SqliteValue::from(name),
                    SqliteValue::from(data_json),
                    SqliteValue::from(updated_at),
                ],
            )
            .map_err(storage_error)?;
    }
    Ok(())
}

fn canonical_inbound_name(value: &str) -> String {
    match value {
        "mix" => "mixed".to_owned(),
        other => canonical_protocol_name(other),
    }
}

fn set_meta_flag(connection: &Connection, key: &str) -> Result<()> {
    connection
        .execute_with_params(
            "INSERT OR REPLACE INTO yuhaiin_meta (key, value) VALUES (?1, 1)",
            &[SqliteValue::from(key)],
        )
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) fn table_row_count(connection: &Connection, table: &str) -> Result<i64> {
    connection
        .query(&format!("SELECT COUNT(*) FROM {table}"))
        .map_err(storage_error)?
        .first()
        .and_then(|row| row.get(0))
        .and_then(|value| match value {
            SqliteValue::Integer(value) => Some(*value),
            _ => None,
        })
        .ok_or_else(|| Error::new(ErrorKind::Storage, format!("counting {table} failed")))
}

fn upgrade_go_v1_resolvers(connection: &Connection) -> Result<()> {
    require_go_table(
        connection,
        "go_legacy_dns_resolvers",
        &[
            "name",
            "resolver_type",
            "host",
            "subnet",
            "tls_servername",
            "data_json",
        ],
    )?;
    if table_row_count(connection, "resolvers_v2")? != 0 {
        return Ok(());
    }
    let rows = connection
        .query(
            "SELECT name, resolver_type, host, subnet, tls_servername, data_json
             FROM go_legacy_dns_resolvers ORDER BY name",
        )
        .map_err(storage_error)?;
    for row in rows {
        let id = row_text(&row, 0, "go_legacy_dns_resolvers.name")?;
        validate_id(&id)?;
        let resolver_type = legacy_resolver_type(row_integer(
            &row,
            1,
            "go_legacy_dns_resolvers.resolver_type",
        )?)?;
        let mut object = legacy_json_object(
            &row_blob_or_text(&row, 5, "go_legacy_dns_resolvers.data_json")?,
            "go_legacy_dns_resolvers.data_json",
        )?;
        let host = row_text(&row, 2, "go_legacy_dns_resolvers.host")?;
        let subnet = row_text(&row, 3, "go_legacy_dns_resolvers.subnet")?;
        let tls_servername = row_text(&row, 4, "go_legacy_dns_resolvers.tls_servername")?;
        let system = id == "bootstrap" && host.is_empty();
        let host = if system {
            "system default".to_owned()
        } else {
            host
        };
        object.insert("id".to_owned(), serde_json::Value::String(id.clone()));
        object.insert(
            "type".to_owned(),
            serde_json::Value::String(if system {
                "system".to_owned()
            } else {
                resolver_type.to_owned()
            }),
        );
        object.insert("host".to_owned(), serde_json::Value::String(host.clone()));
        object.insert("subnet".to_owned(), serde_json::Value::String(subnet));
        object.insert(
            "tlsServerName".to_owned(),
            serde_json::Value::String(tls_servername),
        );
        if system {
            object.insert("system".to_owned(), serde_json::Value::Bool(true));
        }
        let data_json = json_object_bytes(object, "legacy resolver")?;
        connection
            .execute_with_params(
                "INSERT INTO resolvers_v2
                 (id, resolver_type, host, updated_at, data_json)
                 VALUES (?1, ?2, ?3, 0, ?4)",
                &[
                    SqliteValue::from(id),
                    SqliteValue::from(if system { "system" } else { resolver_type }),
                    SqliteValue::from(host),
                    SqliteValue::from(data_json),
                ],
            )
            .map_err(storage_error)?;
    }
    Ok(())
}

fn legacy_resolver_type(value: i64) -> Result<&'static str> {
    Ok(match value {
        2 => "tcp",
        3 => "doh",
        4 => "dot",
        5 => "doq",
        6 => "doh3",
        // Go's legacy converter intentionally maps reserve and unknown enum
        // values to UDP.  Keep that compatibility behavior explicit.
        _ => "udp",
    })
}

fn upgrade_go_v1_route_rules(connection: &Connection) -> Result<()> {
    require_go_table(
        connection,
        "go_legacy_route_rules",
        &[
            "id",
            "name",
            "priority",
            "disabled",
            "updated_at",
            "data_json",
        ],
    )?;
    if table_row_count(connection, "route_rules_v2")? != 0 {
        return Ok(());
    }
    let rows = connection
        .query(
            "SELECT id, name, priority, disabled, updated_at, data_json
             FROM go_legacy_route_rules ORDER BY priority, name",
        )
        .map_err(storage_error)?;
    for (index, row) in rows.iter().enumerate() {
        let fallback_name = row_text(row, 1, "go_legacy_route_rules.name")?;
        validate_id(&fallback_name)?;
        let mut object = legacy_json_object(
            &row_blob_or_text(row, 5, "go_legacy_route_rules.data_json")?,
            "go_legacy_route_rules.data_json",
        )?;
        let name = json_string(&object, &["name"])
            .filter(|value| !value.is_empty())
            .unwrap_or(fallback_name);
        validate_id(&name)?;
        let mode = json_enum_string(
            &object,
            &["mode"],
            &["bypass", "direct", "proxy", "block"],
            0,
        )?;
        let tag = json_string(&object, &["tag"]).unwrap_or_default();
        let resolve_strategy = json_enum_string(
            &object,
            &["resolve_strategy", "resolveStrategy"],
            &[
                "default",
                "prefer_ipv4",
                "only_ipv4",
                "prefer_ipv6",
                "only_ipv6",
            ],
            0,
        )?;
        let udp_strategy = json_enum_string(
            &object,
            &[
                "udp_proxy_fqdn",
                "udp_proxy_fqdn_strategy",
                "udpProxyFqdnStrategy",
            ],
            &["udp_proxy_fqdn_strategy_default", "resolve", "skip_resolve"],
            0,
        )?;
        let resolver = json_string(&object, &["resolver"]).unwrap_or_default();
        let disabled = row_integer(row, 3, "go_legacy_route_rules.disabled")? != 0;
        let (rules, match_type) = convert_legacy_route_groups(&object)?;
        object.insert("name".to_owned(), serde_json::Value::String(name.clone()));
        object.insert("mode".to_owned(), serde_json::Value::String(mode.clone()));
        object.insert("tag".to_owned(), serde_json::Value::String(tag.clone()));
        object.insert(
            "resolveStrategy".to_owned(),
            serde_json::Value::String(resolve_strategy),
        );
        object.insert(
            "udpProxyFqdnStrategy".to_owned(),
            serde_json::Value::String(udp_strategy),
        );
        object.insert("resolver".to_owned(), serde_json::Value::String(resolver));
        object.insert("rules".to_owned(), rules);
        object.insert("disabled".to_owned(), serde_json::Value::Bool(disabled));
        let data_json = json_object_bytes(object, "legacy route rule")?;
        let updated_at = row_integer(row, 4, "go_legacy_route_rules.updated_at")?;
        validate_go_timestamp(updated_at)?;
        connection
            .execute_with_params(
                "INSERT INTO route_rules_v2
                 (id, name, priority, disabled, action_mode, match_type, tag, updated_at, data_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                &[
                    SqliteValue::from(name.clone()),
                    SqliteValue::from(name),
                    SqliteValue::from((index + 1) as i64),
                    SqliteValue::from(if disabled { 1i64 } else { 0 }),
                    SqliteValue::from(mode),
                    SqliteValue::from(match_type),
                    SqliteValue::from(tag),
                    SqliteValue::from(updated_at),
                    SqliteValue::from(data_json),
                ],
            )
            .map_err(storage_error)?;
    }
    Ok(())
}

fn legacy_json_object(
    data: &[u8],
    field: &str,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    let value: serde_json::Value = serde_json::from_slice(data).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("decode {field} failed: {error}"),
        )
    })?;
    value.as_object().cloned().ok_or_else(|| {
        Error::new(
            ErrorKind::Storage,
            format!("{field} must contain a JSON object"),
        )
    })
}

fn json_object_bytes(
    object: serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::Value::Object(object)).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("encode {field} failed: {error}"),
        )
    })
}

fn json_string(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter().find_map(|key| {
        object.get(*key).and_then(|value| match value {
            serde_json::Value::String(value) => Some(value.clone()),
            _ => None,
        })
    })
}

fn json_enum_string(
    object: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
    names: &[&str],
    default: usize,
) -> Result<String> {
    let Some(value) = keys.iter().find_map(|key| object.get(*key)) else {
        return Ok(names[default].to_owned());
    };
    if let Some(value) = value.as_str() {
        if let Some(name) = names.iter().find(|name| **name == value) {
            return Ok((*name).to_owned());
        }
        if let Some(name) = names.iter().find(|name| value.ends_with(*name)) {
            return Ok((*name).to_owned());
        }
        return Err(Error::new(
            ErrorKind::Storage,
            format!("unknown legacy enum value {value:?}"),
        ));
    }
    let Some(value) = value.as_i64() else {
        return Err(Error::new(
            ErrorKind::Storage,
            "legacy enum value must be a string or integer",
        ));
    };
    names
        .get(value as usize)
        .map(|name| (*name).to_owned())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Storage,
                format!("unknown legacy enum value {value}"),
            )
        })
}

fn convert_legacy_route_groups(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<(serde_json::Value, &'static str)> {
    let Some(groups) = object.get("rules") else {
        return Ok((serde_json::Value::Array(Vec::new()), "empty"));
    };
    let Some(groups) = groups.as_array() else {
        return Err(Error::new(
            ErrorKind::Storage,
            "legacy route rule rules must be an array",
        ));
    };
    let mut converted = Vec::with_capacity(groups.len());
    for group in groups {
        let Some(group) = group.as_object() else {
            return Err(Error::new(
                ErrorKind::Storage,
                "legacy route rule group must be an object",
            ));
        };
        let Some(leaves) = group.get("rules") else {
            return Err(Error::new(
                ErrorKind::Storage,
                "legacy route rule group is missing rules",
            ));
        };
        let Some(leaves) = leaves.as_array() else {
            return Err(Error::new(
                ErrorKind::Storage,
                "legacy route rule group rules must be an array",
            ));
        };
        let mut all = Vec::with_capacity(leaves.len());
        for leaf in leaves {
            let Some(leaf) = leaf.as_object() else {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "legacy route rule leaf must be an object",
                ));
            };
            let Some((kind, value)) = ["host", "process", "inbound", "network", "port", "geoip"]
                .iter()
                .find_map(|kind| leaf.get(*kind).map(|value| (*kind, value.clone())))
            else {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "legacy route rule leaf has no supported discriminator",
                ));
            };
            let mut expression = serde_json::Map::new();
            expression.insert(
                "type".to_owned(),
                serde_json::Value::String(kind.to_owned()),
            );
            expression.insert(kind.to_owned(), value);
            all.push(serde_json::Value::Object(expression));
        }
        let mut expression = serde_json::Map::new();
        expression.insert(
            "type".to_owned(),
            serde_json::Value::String("all".to_owned()),
        );
        expression.insert("all".to_owned(), serde_json::Value::Array(all));
        converted.push(serde_json::Value::Object(expression));
    }
    let match_type = if converted.is_empty() { "empty" } else { "all" };
    Ok((serde_json::Value::Array(converted), match_type))
}

pub(super) fn table_exists(connection: &Connection, table: &str) -> bool {
    connection
        .query_with_params(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            &[SqliteValue::from(table)],
        )
        .map(|rows| !rows.is_empty())
        .unwrap_or(false)
}

pub(super) fn require_go_table(
    connection: &Connection,
    table: &str,
    columns: &[&str],
) -> Result<()> {
    if !table_exists(connection, table) {
        return Err(Error::new(
            ErrorKind::Storage,
            format!("Go compatibility table {table} does not exist"),
        ));
    }
    for column in columns {
        if !table_has_column(connection, table, column)? {
            return Err(Error::new(
                ErrorKind::Storage,
                format!("Go compatibility table {table} is missing column {column}"),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_go_texts(values: &[(&str, &String)]) -> Result<()> {
    for (field, value) in values {
        validate_id(value).map_err(|error| {
            Error::new(
                error.kind,
                format!("invalid Go compatibility {field}: {}", error.message),
            )
        })?;
    }
    Ok(())
}

pub(super) fn validate_go_compat_text(value: &str, field: &str) -> Result<()> {
    if value.len() > 512 || value.chars().any(char::is_control) {
        return Err(Error::new(
            ErrorKind::Storage,
            format!("invalid Go compatibility {field}"),
        ));
    }
    Ok(())
}

pub(super) fn validate_go_timestamp(value: i64) -> Result<()> {
    if value < 0 {
        return Err(Error::invalid(
            "Go compatibility updated_at must not be negative",
        ));
    }
    Ok(())
}
