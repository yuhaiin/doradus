//! Legacy Go node-table upgrade.

use super::*;

pub fn upgrade_go_v1_nodes(connection: &Connection) -> Result<()> {
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
