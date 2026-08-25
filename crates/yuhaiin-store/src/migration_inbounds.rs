//! Legacy Go inbound-table upgrade.

use super::*;

pub fn upgrade_go_v1_inbounds(connection: &Connection) -> Result<()> {
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
