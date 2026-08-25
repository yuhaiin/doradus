//! Legacy proxy-chain recovery and protocol normalization.

use super::*;

pub fn recover_legacy_node_chains(connection: &Connection) -> Result<()> {
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

pub fn legacy_protocol_contract(value: &serde_json::Value) -> Option<serde_json::Value> {
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

pub fn canonical_protocol_name(value: &str) -> String {
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
