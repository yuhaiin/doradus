//! Go compatibility subscription and publish operations.

use super::*;

impl ConfigRepository {
    pub async fn list_go_subscription_links(&self) -> Result<Vec<GoSubscriptionLinkRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "subscriptions") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query(
                "SELECT name, updated_at, data_json
                 FROM subscriptions ORDER BY name",
            )
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                let name = row_text(row, 0, "subscriptions.name")?;
                let updated_at = row_integer(row, 1, "subscriptions.updated_at")?;
                let data_json = row_blob_or_text(row, 2, "subscriptions.data_json")?;
                decode_subscription_link(name, updated_at, data_json)
            })
            .collect()
    }

    /// Upsert subscription links atomically.  This intentionally accepts the
    /// shared compatibility record instead of a second HTTP-only DTO tree.
    pub fn put_go_subscription_links_sync(
        &self,
        records: &[GoSubscriptionLinkRecord],
    ) -> Result<()> {
        let normalized = records
            .iter()
            .map(|record| {
                let name = record.name.trim().to_owned();
                let url = record.url.trim().to_owned();
                let link_type = if record.link_type.trim().is_empty() {
                    "reserve".to_owned()
                } else {
                    record.link_type.trim().to_owned()
                };
                if name.is_empty() {
                    return Err(Error::invalid("subscription name is empty"));
                }
                if url.is_empty() {
                    return Err(Error::invalid(format!(
                        "subscription {name:?} url is empty"
                    )));
                }
                validate_go_texts(&[("subscription name", &name), ("subscription url", &url)])?;
                validate_json_bytes(&record.data_json, "subscriptions.data_json")?;
                let mut value: serde_json::Value = serde_json::from_slice(&record.data_json)
                    .map_err(|error| {
                        Error::invalid(format!("subscription {name:?} JSON is invalid: {error}"))
                    })?;
                let object = value.as_object_mut().ok_or_else(|| {
                    Error::invalid(format!("subscription {name:?} JSON must be an object"))
                })?;
                object.insert("name".to_owned(), serde_json::Value::String(name.clone()));
                object.insert("url".to_owned(), serde_json::Value::String(url));
                object.insert(
                    "type".to_owned(),
                    serde_json::Value::String(link_type.clone()),
                );
                let data_json = serde_json::to_vec(&value).map_err(|error| {
                    Error::invalid(format!("encode subscription {name:?} failed: {error}"))
                })?;
                let updated_at = if record.updated_at == 0 {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |duration| duration.as_secs() as i64)
                } else {
                    record.updated_at
                };
                validate_go_timestamp(updated_at)?;
                Ok((name, updated_at, data_json))
            })
            .collect::<Result<Vec<_>>>()?;

        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "subscriptions",
                &["name", "updated_at", "data_json"],
            )?;
            for (name, updated_at, data_json) in &normalized {
                connection
                    .execute_with_params(
                        "INSERT INTO subscriptions(name, updated_at, data_json)
                         VALUES (?1, ?2, ?3)
                         ON CONFLICT(name) DO UPDATE SET
                           updated_at = excluded.updated_at,
                           data_json = excluded.data_json",
                        &[
                            SqliteValue::from(name.as_str()),
                            SqliteValue::from(*updated_at),
                            SqliteValue::from(data_json.as_slice()),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            Ok(())
        })
    }

    pub async fn put_go_subscription_links(
        &self,
        records: &[GoSubscriptionLinkRecord],
    ) -> Result<()> {
        self.put_go_subscription_links_sync(records)
    }

    pub fn delete_go_subscription_links_sync(&self, names: &[String]) -> Result<()> {
        for name in names {
            validate_id(name)?;
        }
        let names = names.to_vec();
        self.store.with_write_transaction(|connection| {
            require_go_table(connection, "subscriptions", &["name"])?;
            for name in &names {
                connection
                    .execute_with_params(
                        "DELETE FROM subscriptions WHERE name = ?1",
                        &[SqliteValue::from(name.as_str())],
                    )
                    .map_err(storage_error)?;
            }
            Ok(())
        })
    }

    pub async fn delete_go_subscription_links(&self, names: &[String]) -> Result<()> {
        self.delete_go_subscription_links_sync(names)
    }

    /// Read Go's publish contracts from the native `publishes` table.  Go
    /// orders these rows by their primary-key name and leaves contract
    /// normalization to the decode boundary.
    pub async fn list_go_publishes(&self) -> Result<Vec<GoPublishRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "publishes") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query(
                "SELECT name, updated_at, data_json
                 FROM publishes ORDER BY name",
            )
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                let data_json = row_blob_or_text(row, 2, "publishes.data_json")?;
                validate_json_bytes(&data_json, "publishes.data_json")?;
                Ok(GoPublishRecord {
                    name: row_text(row, 0, "publishes.name")?,
                    updated_at: row_integer(row, 1, "publishes.updated_at")?,
                    data_json,
                })
            })
            .collect()
    }

    /// Upsert one Go publish contract without exposing SQLite to the API
    /// layer.  The caller supplies the already-normalized JSON contract.
    pub async fn put_go_publish(&self, record: &GoPublishRecord) -> Result<()> {
        let name = record.name.trim().to_owned();
        if name.is_empty() {
            return Err(Error::invalid("publish name is empty"));
        }
        validate_go_texts(&[("publish name", &name)])?;
        let updated_at = if record.updated_at == 0 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs() as i64)
        } else {
            record.updated_at
        };
        validate_go_timestamp(updated_at)?;
        validate_json_bytes(&record.data_json, "publishes.data_json")?;
        self.store.with_write_transaction(|connection| {
            require_go_table(
                connection,
                "publishes",
                &["name", "updated_at", "data_json"],
            )?;
            connection
                .execute_with_params(
                    "INSERT INTO publishes(name, updated_at, data_json)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(name) DO UPDATE SET
                       updated_at = excluded.updated_at,
                       data_json = excluded.data_json",
                    &[
                        SqliteValue::from(name.as_str()),
                        SqliteValue::from(updated_at),
                        SqliteValue::from(record.data_json.as_slice()),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    /// Delete one publish and report whether the Go row existed.  The HTTP
    /// layer maps `false` to Go's 404/not_found response.
    pub async fn delete_go_publish(&self, name: &str) -> Result<bool> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::invalid("publish name is empty"));
        }
        validate_go_texts(&[("publish name", &name.to_owned())])?;
        self.store.with_write_retry(|connection| {
            require_go_table(connection, "publishes", &["name"])?;
            connection
                .execute_with_params(
                    "DELETE FROM publishes WHERE name = ?1",
                    &[SqliteValue::from(name)],
                )
                .map(|changed| changed != 0)
                .map_err(storage_error)
        })
    }
}

fn decode_subscription_link(
    name: String,
    updated_at: i64,
    data_json: Vec<u8>,
) -> Result<GoSubscriptionLinkRecord> {
    validate_go_timestamp(updated_at)?;
    validate_json_bytes(&data_json, "subscriptions.data_json")?;
    let mut value: serde_json::Value = serde_json::from_slice(&data_json)
        .map_err(|error| Error::invalid(format!("decode subscription {name:?} failed: {error}")))?;
    let object = value.as_object_mut().ok_or_else(|| {
        Error::invalid(format!(
            "stored subscription {name:?} JSON must be an object"
        ))
    })?;
    let normalized_name = object
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(name.as_str())
        .to_owned();
    let url = object
        .get("url")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    if normalized_name.is_empty() {
        return Err(Error::invalid("subscription name is empty"));
    }
    if url.is_empty() {
        return Err(Error::invalid(format!(
            "subscription {normalized_name:?} url is empty"
        )));
    }
    let link_type = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("reserve")
        .to_owned();
    object.insert(
        "name".to_owned(),
        serde_json::Value::String(normalized_name.clone()),
    );
    object.insert("url".to_owned(), serde_json::Value::String(url.clone()));
    object.insert(
        "type".to_owned(),
        serde_json::Value::String(link_type.clone()),
    );
    let data_json = serde_json::to_vec(&value).map_err(|error| {
        Error::invalid(format!(
            "normalize subscription {normalized_name:?} failed: {error}"
        ))
    })?;
    validate_go_texts(&[
        ("subscription name", &normalized_name),
        ("subscription url", &url),
    ])?;
    Ok(GoSubscriptionLinkRecord {
        name: normalized_name,
        url,
        link_type,
        updated_at,
        data_json,
    })
}
