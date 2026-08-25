//! Go v2 compatibility-table import.

use super::*;

pub fn import_go_schema(connection: &Connection) -> Result<()> {
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
