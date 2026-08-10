//! Native persistence for Go's schema-v6 central user management.
//!
//! The proxy runtime can continue to consume the protocol-specific fields in
//! a node record, while the management plane owns credentials in these typed
//! tables.  Keeping the credential variants normalized here avoids putting
//! SQL details or secret-shaping rules in the HTTP API.

use super::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static USER_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoBasicCredential {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(rename = "allowAnyUsername", default, skip_serializing_if = "is_false")]
    pub allow_any_username: bool,
    #[serde(rename = "allowAnyPassword", default, skip_serializing_if = "is_false")]
    pub allow_any_password: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoUuidCredential {
    pub uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoTokenCredential {
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoCredential {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic: Option<GoBasicCredential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<GoUuidCredential>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<GoTokenCredential>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GoCredentialView {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub uuid: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub token: String,
    #[serde(rename = "hasUsername", skip_serializing_if = "is_false")]
    pub has_username: bool,
    #[serde(rename = "hasSecret")]
    pub has_secret: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GoUserView {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub origin: String,
    pub usage: String,
    pub credential: GoCredentialView,
    #[serde(rename = "outboundReferences", skip_serializing_if = "is_zero")]
    pub outbound_references: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GoUserWrite {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub usage: String,
    pub credential: GoCredential,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoUserRecord {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub origin: String,
    pub usage: String,
    pub credential: GoCredential,
    pub updated_at: i64,
}

impl GoCredential {
    fn validate(&self) -> Result<()> {
        let variants = [
            self.basic.is_some(),
            self.uuid.is_some(),
            self.token.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if variants != 1 {
            return Err(Error::invalid(
                "credential must contain exactly one variant",
            ));
        }
        match self.kind.as_str() {
            "basic" => {
                let Some(basic) = self.basic.as_ref() else {
                    return Err(Error::invalid("basic credential is missing"));
                };
                if basic.username.is_none()
                    && basic.password.is_none()
                    && !basic.allow_any_username
                    && !basic.allow_any_password
                {
                    return Err(Error::invalid("basic credential has no usable field"));
                }
            }
            "uuid" => {
                let Some(uuid) = self.uuid.as_ref() else {
                    return Err(Error::invalid("uuid credential is missing"));
                };
                if !is_uuid(&uuid.uuid) {
                    return Err(Error::invalid("invalid uuid credential"));
                }
            }
            "token" => {
                if self
                    .token
                    .as_ref()
                    .is_none_or(|token| token.token.is_empty())
                {
                    return Err(Error::invalid("token credential is empty"));
                }
            }
            other => {
                return Err(Error::invalid(format!("unknown credential type {other:?}")));
            }
        }
        Ok(())
    }

    fn view(&self) -> GoCredentialView {
        let mut view = GoCredentialView {
            kind: self.kind.clone(),
            username: String::new(),
            password: String::new(),
            uuid: String::new(),
            token: String::new(),
            has_username: false,
            has_secret: false,
        };
        match self.kind.as_str() {
            "basic" => {
                if let Some(basic) = self.basic.as_ref() {
                    if let Some(username) = basic.username.as_ref() {
                        view.username = username.clone();
                        view.has_username = true;
                    }
                    if let Some(password) = basic.password.as_ref() {
                        view.password = password.clone();
                        view.has_secret = true;
                    }
                }
            }
            "uuid" => {
                if let Some(uuid) = self.uuid.as_ref() {
                    view.uuid = uuid.uuid.clone();
                    view.has_secret = !uuid.uuid.is_empty();
                }
            }
            "token" => {
                if let Some(token) = self.token.as_ref() {
                    view.token = token.token.clone();
                    view.has_secret = !token.token.is_empty();
                }
            }
            _ => {}
        }
        view
    }
}

impl GoUserRecord {
    fn validate(&self) -> Result<()> {
        validate_id(&self.id)?;
        validate_user_text(&self.name, "user name")?;
        validate_user_usage(&self.usage)?;
        let origin = if self.origin.is_empty() {
            "manual"
        } else {
            self.origin.as_str()
        };
        if !matches!(origin, "manual" | "migrated") {
            return Err(Error::invalid(format!("invalid user origin {origin:?}")));
        }
        if self.updated_at < 0 {
            return Err(Error::invalid("user updated_at must not be negative"));
        }
        self.credential.validate()
    }

    fn view(&self, outbound_references: i64) -> GoUserView {
        GoUserView {
            id: self.id.clone(),
            name: self.name.clone(),
            enabled: self.enabled,
            origin: if self.origin.is_empty() {
                "manual".to_owned()
            } else {
                self.origin.clone()
            },
            usage: self.usage.clone(),
            credential: self.credential.view(),
            outbound_references,
        }
    }
}

impl From<GoUserWrite> for GoUserRecord {
    fn from(write: GoUserWrite) -> Self {
        Self {
            id: generate_user_id(),
            name: write.name,
            enabled: write.enabled,
            origin: if write.origin.is_empty() {
                "manual".to_owned()
            } else {
                write.origin
            },
            usage: write.usage,
            credential: write.credential,
            updated_at: unix_seconds(),
        }
    }
}

impl ConfigRepository {
    /// Return the credential-bearing user records needed by inbound runtime
    /// authentication. The runtime receives an owned snapshot and never
    /// keeps the SQLite connection or exposes these records through the API.
    pub async fn list_go_user_records_for_runtime(&self) -> Result<Vec<GoUserRecord>> {
        self.list_go_user_records()
    }

    /// Resolve central outbound credentials into an ephemeral node snapshot.
    ///
    /// Go stores only `userId` in `nodes_v2`.  Runtime builders still consume
    /// protocol-shaped JSON, so inject the selected credential into a clone of
    /// the node payload immediately before building the proxy.  The returned
    /// record is never persisted; API reads continue to expose the original
    /// user reference and cannot accidentally write secrets back to SQLite.
    pub fn resolve_go_node_runtime_records(
        &self,
        nodes: &[GoNodeRecord],
    ) -> Result<Vec<GoNodeRecord>> {
        let users = self.list_go_user_records()?;
        let users = users
            .into_iter()
            .map(|user| (user.id.clone(), user))
            .collect::<HashMap<_, _>>();
        nodes
            .iter()
            .map(|node| resolve_go_node_runtime_record(node, &users))
            .collect()
    }

    pub async fn list_go_user_views(
        &self,
        query: Option<&str>,
        page: usize,
        page_size: usize,
    ) -> Result<(Vec<GoUserView>, usize)> {
        let records = self.list_go_user_records()?;
        let references = self.go_user_outbound_references()?;
        let query = query
            .map(str::trim)
            .filter(|query| !query.is_empty())
            .map(str::to_ascii_lowercase);
        let filtered = records
            .into_iter()
            .filter(|record| {
                query.as_ref().is_none_or(|query| {
                    record.id.to_ascii_lowercase().contains(query)
                        || record.name.to_ascii_lowercase().contains(query)
                        || record.credential.kind.to_ascii_lowercase().contains(query)
                })
            })
            .collect::<Vec<_>>();
        let total = filtered.len();
        let page = page.max(1);
        let start = page.saturating_sub(1).saturating_mul(page_size);
        let views = filtered
            .into_iter()
            .skip(start)
            .take(if page_size == 0 {
                usize::MAX
            } else {
                page_size
            })
            .map(|record| {
                let references = references.get(&record.id).copied().unwrap_or_default();
                record.view(references)
            })
            .collect();
        Ok((views, total))
    }

    pub async fn get_go_user(&self, id: &str) -> Result<GoUserRecord> {
        validate_id(id)?;
        self.list_go_user_records()?
            .into_iter()
            .find(|record| record.id == id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("user {id} was not found")))
    }

    pub async fn get_go_user_view(&self, id: &str) -> Result<GoUserView> {
        let record = self.get_go_user(id).await?;
        let references = self.go_user_outbound_references()?;
        Ok(record.view(references.get(id).copied().unwrap_or_default()))
    }

    pub async fn create_go_user(&self, write: GoUserWrite) -> Result<GoUserView> {
        let record = GoUserRecord::from(write);
        record.validate()?;
        self.save_go_user(&record).await?;
        Ok(record.view(0))
    }

    pub async fn save_go_user(&self, record: &GoUserRecord) -> Result<()> {
        record.validate()?;
        let record = record.clone();
        self.store.with_write_transaction(move |connection| {
            require_go_table(
                connection,
                "users_v2",
                &[
                    "id",
                    "name",
                    "enabled",
                    "origin",
                    "usage",
                    "credential_type",
                    "updated_at",
                ],
            )?;
            connection
                .execute_with_params(
                    "INSERT INTO users_v2
                     (id, name, enabled, origin, usage, credential_type, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(id) DO UPDATE SET
                       name = excluded.name,
                       enabled = excluded.enabled,
                       origin = excluded.origin,
                       usage = excluded.usage,
                       credential_type = excluded.credential_type,
                       updated_at = excluded.updated_at",
                    &[
                        SqliteValue::from(record.id.as_str()),
                        SqliteValue::from(record.name.as_str()),
                        SqliteValue::from(i64::from(record.enabled)),
                        SqliteValue::from(record.origin.as_str()),
                        SqliteValue::from(record.usage.as_str()),
                        SqliteValue::from(record.credential.kind.as_str()),
                        SqliteValue::from(record.updated_at),
                    ],
                )
                .map_err(storage_error)?;
            for table in ["user_basic_v2", "user_uuid_v2", "user_token_v2"] {
                connection
                    .execute_with_params(
                        &format!("DELETE FROM {table} WHERE user_id = ?1"),
                        &[SqliteValue::from(record.id.as_str())],
                    )
                    .map_err(storage_error)?;
            }
            match record.credential.kind.as_str() {
                "basic" => {
                    let basic = record
                        .credential
                        .basic
                        .as_ref()
                        .ok_or_else(|| Error::invalid("basic credential is missing"))?;
                    connection
                        .execute_with_params(
                            "INSERT INTO user_basic_v2
                             (user_id, username, password, allow_any_username, allow_any_password)
                             VALUES (?1, ?2, ?3, ?4, ?5)",
                            &[
                                SqliteValue::from(record.id.as_str()),
                                basic
                                    .username
                                    .as_deref()
                                    .map_or(SqliteValue::Null, SqliteValue::from),
                                basic
                                    .password
                                    .as_deref()
                                    .map_or(SqliteValue::Null, SqliteValue::from),
                                SqliteValue::from(i64::from(basic.allow_any_username)),
                                SqliteValue::from(i64::from(basic.allow_any_password)),
                            ],
                        )
                        .map_err(storage_error)?;
                }
                "uuid" => {
                    let uuid = record
                        .credential
                        .uuid
                        .as_ref()
                        .ok_or_else(|| Error::invalid("uuid credential is missing"))?;
                    connection
                        .execute_with_params(
                            "INSERT INTO user_uuid_v2(user_id, uuid) VALUES (?1, ?2)",
                            &[
                                SqliteValue::from(record.id.as_str()),
                                SqliteValue::from(uuid.uuid.as_str()),
                            ],
                        )
                        .map_err(storage_error)?;
                }
                "token" => {
                    let token = record
                        .credential
                        .token
                        .as_ref()
                        .ok_or_else(|| Error::invalid("token credential is missing"))?;
                    connection
                        .execute_with_params(
                            "INSERT INTO user_token_v2(user_id, token) VALUES (?1, ?2)",
                            &[
                                SqliteValue::from(record.id.as_str()),
                                SqliteValue::from(token.token.as_str()),
                            ],
                        )
                        .map_err(storage_error)?;
                }
                _ => return Err(Error::invalid("unknown credential type")),
            }
            Ok(())
        })
    }

    pub async fn delete_go_user(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        let references = self
            .go_user_outbound_references()?
            .get(id)
            .copied()
            .unwrap_or(0);
        if references > 0 || self.go_user_migration_references(id)? > 0 {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!("user {id} is referenced by a node or migration mapping"),
            ));
        }
        self.store.with_write_transaction(|connection| {
            require_go_table(connection, "users_v2", &["id"])?;
            let deleted = connection
                .execute_with_params(
                    "DELETE FROM users_v2 WHERE id = ?1",
                    &[SqliteValue::from(id)],
                )
                .map_err(storage_error)?;
            if deleted == 0 {
                return Err(Error::new(
                    ErrorKind::NotFound,
                    format!("user {id} was not found"),
                ));
            }
            Ok(())
        })
    }

    fn list_go_user_records(&self) -> Result<Vec<GoUserRecord>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "users_v2") {
            return Ok(Vec::new());
        }
        let rows = connection
            .query(
                "SELECT u.id, u.name, u.enabled, u.origin, u.usage, u.credential_type,
                        b.username, b.password, b.allow_any_username, b.allow_any_password,
                        uuid.uuid, token.token, u.updated_at
                 FROM users_v2 u
                 LEFT JOIN user_basic_v2 b
                   ON b.user_id = u.id AND u.credential_type = 'basic'
                 LEFT JOIN user_uuid_v2 uuid
                   ON uuid.user_id = u.id AND u.credential_type = 'uuid'
                 LEFT JOIN user_token_v2 token
                   ON token.user_id = u.id AND u.credential_type = 'token'
                 ORDER BY u.name, u.id",
            )
            .map_err(storage_error)?;
        rows.iter().map(user_from_row).collect()
    }

    fn go_user_outbound_references(&self) -> Result<HashMap<String, i64>> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "nodes_v2") {
            return Ok(HashMap::new());
        }
        let rows = connection
            .query("SELECT data_json FROM nodes_v2")
            .map_err(storage_error)?;
        let mut references = HashMap::new();
        for row in rows {
            let data = row_blob_or_text(&row, 0, "nodes_v2.data_json")?;
            let value: Value = serde_json::from_slice(&data).map_err(|error| {
                Error::new(
                    ErrorKind::Storage,
                    format!("decode node user references failed: {error}"),
                )
            })?;
            count_user_ids(&value, &mut references);
        }
        Ok(references)
    }

    fn go_user_migration_references(&self, id: &str) -> Result<i64> {
        let connection = self.store.lock_connection()?;
        if !table_exists(&connection, "user_migration_sources_v2")
            || !table_exists(&connection, "user_migration_dedup_v2")
        {
            return Ok(0);
        }
        let rows = connection
            .query_with_params(
                "SELECT
                   (SELECT COUNT(*) FROM user_migration_sources_v2 WHERE user_id = ?1) +
                   (SELECT COUNT(*) FROM user_migration_dedup_v2 WHERE user_id = ?1)",
                &[SqliteValue::from(id)],
            )
            .map_err(storage_error)?;
        rows.first()
            .map(|row| row_integer(row, 0, "user migration references"))
            .unwrap_or(Ok(0))
    }
}

fn resolve_go_node_runtime_record(
    node: &GoNodeRecord,
    users: &HashMap<String, GoUserRecord>,
) -> Result<GoNodeRecord> {
    let mut payload: Value = serde_json::from_slice(&node.data_json).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("node {} has invalid data_json: {error}", node.id),
        )
    })?;
    inject_go_user_credentials(&mut payload, None, users)?;
    let mut resolved = node.clone();
    resolved.data_json = serde_json::to_vec(&payload).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("encode resolved node {} data_json: {error}", node.id),
        )
    })?;
    Ok(resolved)
}

fn inject_go_user_credentials(
    value: &mut Value,
    inherited_protocol: Option<&str>,
    users: &HashMap<String, GoUserRecord>,
) -> Result<()> {
    let Value::Object(object) = value else {
        if let Value::Array(values) = value {
            for value in values {
                inject_go_user_credentials(value, inherited_protocol, users)?;
            }
        }
        return Ok(());
    };

    let protocol = object
        .get("type")
        .and_then(Value::as_str)
        .or(inherited_protocol)
        .or_else(|| object.get("protocol").and_then(Value::as_str))
        .map(str::to_owned);
    if let Some(user_id) = object.get("userId").and_then(Value::as_str) {
        let user = users.get(user_id).ok_or_else(|| {
            Error::new(
                ErrorKind::NotFound,
                format!("outbound user {user_id} referenced by node was not found"),
            )
        })?;
        if !user.enabled || !matches!(user.usage.as_str(), "outbound" | "both") {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("outbound user {user_id} is disabled or not enabled for outbound use"),
            ));
        }
        apply_go_user_credential(object, protocol.as_deref().unwrap_or_default(), user)?;
    }

    for (key, child) in object.iter_mut() {
        if key != "userId" {
            inject_go_user_credentials(child, protocol.as_deref(), users)?;
        }
    }
    Ok(())
}

fn apply_go_user_credential(
    object: &mut serde_json::Map<String, Value>,
    protocol: &str,
    user: &GoUserRecord,
) -> Result<()> {
    let protocol = protocol.to_ascii_lowercase();
    match protocol.as_str() {
        "http" | "http_proxy" | "socks5" => {
            let basic = basic_credential(user, &protocol)?;
            object.remove("user");
            object.remove("username");
            object.remove("password");
            if let Some(username) = basic.username.as_ref() {
                object.insert("user".to_owned(), Value::String(username.clone()));
            }
            if let Some(password) = basic.password.as_ref() {
                object.insert("password".to_owned(), Value::String(password.clone()));
            }
        }
        "shadowsocks" | "shadowsocksr" | "ssr" | "trojan" | "yuubinsya" | "aead" => {
            let basic = basic_credential(user, &protocol)?;
            object.remove("password");
            if let Some(password) = basic.password.as_ref() {
                object.insert("password".to_owned(), Value::String(password.clone()));
            }
        }
        "vmess" => {
            let uuid = uuid_credential(user, &protocol)?;
            object.insert("id".to_owned(), Value::String(uuid.to_owned()));
        }
        "vless" => {
            let uuid = uuid_credential(user, &protocol)?;
            object.insert("uuid".to_owned(), Value::String(uuid.to_owned()));
        }
        "tailscale" => {
            let token = token_credential(user, &protocol)?;
            object.insert("token".to_owned(), Value::String(token.to_owned()));
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("central user credentials are unsupported for protocol {protocol:?}"),
            ));
        }
    }
    Ok(())
}

fn basic_credential<'a>(user: &'a GoUserRecord, protocol: &str) -> Result<&'a GoBasicCredential> {
    user.credential.basic.as_ref().ok_or_else(|| {
        Error::invalid(format!(
            "user {} has no basic credential for {protocol}",
            user.id
        ))
    })
}

fn uuid_credential<'a>(user: &'a GoUserRecord, protocol: &str) -> Result<&'a str> {
    user.credential
        .uuid
        .as_ref()
        .map(|uuid| uuid.uuid.as_str())
        .ok_or_else(|| {
            Error::invalid(format!(
                "user {} has no UUID credential for {protocol}",
                user.id
            ))
        })
}

fn token_credential<'a>(user: &'a GoUserRecord, protocol: &str) -> Result<&'a str> {
    user.credential
        .token
        .as_ref()
        .map(|token| token.token.as_str())
        .ok_or_else(|| {
            Error::invalid(format!(
                "user {} has no token credential for {protocol}",
                user.id
            ))
        })
}

fn user_from_row(row: &Row) -> Result<GoUserRecord> {
    let kind = row_text(row, 5, "users_v2.credential_type")?;
    let credential = match kind.as_str() {
        "basic" => GoCredential {
            kind,
            basic: Some(GoBasicCredential {
                username: row_optional_text(row, 6, "user_basic_v2.username")?,
                password: row_optional_text(row, 7, "user_basic_v2.password")?,
                allow_any_username: row_integer(row, 8, "user_basic_v2.allow_any_username")? != 0,
                allow_any_password: row_integer(row, 9, "user_basic_v2.allow_any_password")? != 0,
            }),
            uuid: None,
            token: None,
        },
        "uuid" => GoCredential {
            kind,
            basic: None,
            uuid: Some(GoUuidCredential {
                uuid: row_optional_text(row, 10, "user_uuid_v2.uuid")?.unwrap_or_default(),
            }),
            token: None,
        },
        "token" => GoCredential {
            kind,
            basic: None,
            uuid: None,
            token: Some(GoTokenCredential {
                token: row_optional_text(row, 11, "user_token_v2.token")?.unwrap_or_default(),
            }),
        },
        _ => {
            return Err(Error::new(
                ErrorKind::Storage,
                format!("users_v2 has unknown credential type {kind:?}"),
            ));
        }
    };
    Ok(GoUserRecord {
        id: row_text(row, 0, "users_v2.id")?,
        name: row_text(row, 1, "users_v2.name")?,
        enabled: row_integer(row, 2, "users_v2.enabled")? != 0,
        origin: row_text(row, 3, "users_v2.origin")?,
        usage: row_text(row, 4, "users_v2.usage")?,
        credential,
        updated_at: row_integer(row, 12, "users_v2.updated_at")?,
    })
}

fn count_user_ids(value: &Value, references: &mut HashMap<String, i64>) {
    match value {
        Value::Object(object) => {
            if let Some(Value::String(user_id)) = object.get("userId") {
                if !user_id.is_empty() {
                    *references.entry(user_id.clone()).or_default() += 1;
                }
            }
            for value in object.values() {
                count_user_ids(value, references);
            }
        }
        Value::Array(values) => {
            for value in values {
                count_user_ids(value, references);
            }
        }
        _ => {}
    }
}

fn validate_user_text(value: &str, field: &str) -> Result<()> {
    if value.len() > 512 || value.chars().any(char::is_control) {
        return Err(Error::invalid(format!(
            "{field} contains invalid characters"
        )));
    }
    Ok(())
}

fn validate_user_usage(value: &str) -> Result<()> {
    if matches!(value, "inbound" | "outbound" | "both") {
        Ok(())
    } else {
        Err(Error::invalid(format!("invalid user usage {value:?}")))
    }
}

fn is_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| {
        matches!(index, 8 | 13 | 18 | 23)
            .then_some(byte == b'-')
            .unwrap_or_else(|| byte.is_ascii_hexdigit())
    })
}

fn generate_user_id() -> String {
    let counter = USER_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let seed = format!("{now}:{}:{counter}", std::process::id());
    let mut bytes = *blake3::hash(seed.as_bytes()).as_bytes();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format_uuid(&bytes[..16])
}

fn format_uuid(bytes: &[u8]) -> String {
    let hex = |byte: u8| -> [char; 2] {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        [
            DIGITS[(byte >> 4) as usize] as char,
            DIGITS[(byte & 0x0f) as usize] as char,
        ]
    };
    let mut output = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            output.push('-');
        }
        output.extend(hex(*byte));
    }
    output
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_password(password: &str) -> GoCredential {
        GoCredential {
            kind: "basic".to_owned(),
            basic: Some(GoBasicCredential {
                username: None,
                password: Some(password.to_owned()),
                allow_any_username: true,
                allow_any_password: false,
            }),
            uuid: None,
            token: None,
        }
    }

    #[test]
    fn credential_validation_and_view_follow_go_contract() {
        let credential = basic_password("secret");
        credential.validate().unwrap();
        let view = credential.view();
        assert_eq!(view.kind, "basic");
        assert_eq!(view.password, "secret");
        assert!(view.has_secret);
        assert!(!view.has_username);

        let invalid = GoCredential {
            kind: "uuid".to_owned(),
            basic: Some(GoBasicCredential {
                username: None,
                password: Some("secret".to_owned()),
                allow_any_username: false,
                allow_any_password: false,
            }),
            uuid: None,
            token: None,
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn generated_user_ids_are_canonical_uuid_values() {
        let id = generate_user_id();
        assert!(is_uuid(&id));
        assert_eq!(id.as_bytes()[14], b'4');
    }

    #[test]
    fn central_credentials_fill_supported_outbound_protocol_shapes() {
        let basic = GoUserRecord {
            id: "basic-user".to_owned(),
            name: String::new(),
            enabled: true,
            origin: "manual".to_owned(),
            usage: "outbound".to_owned(),
            credential: GoCredential {
                kind: "basic".to_owned(),
                basic: Some(GoBasicCredential {
                    username: Some("u".to_owned()),
                    password: Some("p".to_owned()),
                    allow_any_username: false,
                    allow_any_password: false,
                }),
                uuid: None,
                token: None,
            },
            updated_at: 0,
        };
        let uuid = GoUserRecord {
            id: "uuid-user".to_owned(),
            credential: GoCredential {
                kind: "uuid".to_owned(),
                basic: None,
                uuid: Some(GoUuidCredential {
                    uuid: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
                }),
                token: None,
            },
            ..basic.clone()
        };
        let token = GoUserRecord {
            id: "token-user".to_owned(),
            credential: GoCredential {
                kind: "token".to_owned(),
                basic: None,
                uuid: None,
                token: Some(GoTokenCredential {
                    token: "token".to_owned(),
                }),
            },
            ..basic.clone()
        };
        let users = HashMap::from([
            (basic.id.clone(), basic),
            (uuid.id.clone(), uuid),
            (token.id.clone(), token),
        ]);

        let mut http = serde_json::json!({
            "chain": [{ "type": "http", "http": {
                "userId": "basic-user", "user": "old", "password": "old"
            }}]
        });
        inject_go_user_credentials(&mut http, None, &users).unwrap();
        assert_eq!(http["chain"][0]["http"]["user"], "u");
        assert_eq!(http["chain"][0]["http"]["password"], "p");

        let mut vmess = serde_json::json!({
            "chain": [{ "type": "vmess", "vmess": {
                "userId": "uuid-user", "id": "old"
            }}]
        });
        inject_go_user_credentials(&mut vmess, None, &users).unwrap();
        assert_eq!(
            vmess["chain"][0]["vmess"]["id"],
            "123e4567-e89b-42d3-a456-426614174000"
        );

        let mut tailscale = serde_json::json!({
            "type": "tailscale", "userId": "token-user", "token": "old"
        });
        inject_go_user_credentials(&mut tailscale, None, &users).unwrap();
        assert_eq!(tailscale["token"], "token");

        let mut yuubinsya = serde_json::json!({
            "type": "yuubinsya", "userId": "basic-user", "password": "old"
        });
        inject_go_user_credentials(&mut yuubinsya, None, &users).unwrap();
        assert_eq!(yuubinsya["password"], "p");

        let mut ssr = serde_json::json!({
            "chain": [{ "type": "shadowsocksr", "shadowsocksr": {
                "userId": "basic-user", "protocol": "auth_aes128_sha1", "password": "old"
            }}]
        });
        inject_go_user_credentials(&mut ssr, None, &users).unwrap();
        assert_eq!(ssr["chain"][0]["shadowsocksr"]["password"], "p");

        let mut missing = serde_json::json!({
            "type": "http", "userId": "missing-user"
        });
        assert_eq!(
            inject_go_user_credentials(&mut missing, None, &users)
                .unwrap_err()
                .kind,
            ErrorKind::NotFound
        );

        let mut disabled = users["basic-user"].clone();
        disabled.enabled = false;
        let disabled_users = HashMap::from([(disabled.id.clone(), disabled)]);
        let mut disabled_payload = serde_json::json!({
            "type": "http", "userId": "basic-user"
        });
        assert_eq!(
            inject_go_user_credentials(&mut disabled_payload, None, &disabled_users)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidInput
        );
    }
}
