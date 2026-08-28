//! Go compatibility route operations.

use super::*;

impl ConfigRepository {
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

    /// Write the Go route-rule contract to its native table while preserving
    /// unknown fields in `data_json` for round-trip compatibility.
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
}
