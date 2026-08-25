//! Legacy route-list and node-tag upgrades.

use std::collections::BTreeMap;

use super::*;

pub fn upgrade_go_v1_route_lists(connection: &Connection) -> Result<()> {
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

pub fn upgrade_go_v1_node_tags(connection: &Connection) -> Result<()> {
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

pub fn canonical_inbound_name(value: &str) -> String {
    match value {
        "mix" => "mixed".to_owned(),
        other => canonical_protocol_name(other),
    }
}

pub fn set_meta_flag(connection: &Connection, key: &str) -> Result<()> {
    connection
        .execute_with_params(
            "INSERT OR REPLACE INTO yuhaiin_meta (key, value) VALUES (?1, 1)",
            &[SqliteValue::from(key)],
        )
        .map(|_| ())
        .map_err(storage_error)
}

pub fn table_row_count(connection: &Connection, table: &str) -> Result<i64> {
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
