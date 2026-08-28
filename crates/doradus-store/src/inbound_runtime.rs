//! Durable runtime observations for inbound listeners.

use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundStatisticsRecord {
    pub inbound_id: String,
    #[serde(default)]
    pub active_tcp: u64,
    #[serde(default)]
    pub active_udp: u64,
    pub total_tcp_flows: u64,
    pub total_udp_flows: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundRuntimeEvent {
    pub id: i64,
    pub inbound_id: String,
    pub event_type: String,
    pub state: String,
    pub error: Option<String>,
    pub detail_json: Vec<u8>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundRuntimeEventInput {
    pub inbound_id: String,
    pub event_type: String,
    pub state: String,
    pub error: Option<String>,
    pub detail_json: Vec<u8>,
    pub created_at: i64,
}

fn sqlite_counter(value: u64) -> SqliteValue {
    SqliteValue::from(value.min(i64::MAX as u64) as i64)
}

fn row_counter(row: &Row, index: usize, field: &str) -> Result<u64> {
    let value = row_integer(row, index, field)?;
    u64::try_from(value).map_err(|_| {
        Error::new(
            ErrorKind::Storage,
            format!("{field} must be a non-negative integer"),
        )
    })
}

fn optional_row_text(row: &Row, index: usize, field: &str) -> Result<Option<String>> {
    match row.get(index) {
        Some(SqliteValue::Null) => Ok(None),
        Some(SqliteValue::Text(value)) => Ok(Some(value.to_string())),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("{field} is not nullable TEXT"),
        )),
    }
}

impl ConfigStore {
    pub fn load_inbound_statistics(&self) -> Result<Vec<InboundStatisticsRecord>> {
        let connection = self.lock_connection()?;
        let rows = connection
            .query(
                "SELECT inbound_id, total_tcp_flows, total_udp_flows,
                        upload_bytes, download_bytes, updated_at
                 FROM inbound_statistics ORDER BY inbound_id",
            )
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                Ok(InboundStatisticsRecord {
                    inbound_id: row_text(row, 0, "inbound_statistics.inbound_id")?,
                    active_tcp: 0,
                    active_udp: 0,
                    total_tcp_flows: row_counter(row, 1, "inbound_statistics.total_tcp_flows")?,
                    total_udp_flows: row_counter(row, 2, "inbound_statistics.total_udp_flows")?,
                    upload_bytes: row_counter(row, 3, "inbound_statistics.upload_bytes")?,
                    download_bytes: row_counter(row, 4, "inbound_statistics.download_bytes")?,
                    updated_at: row_integer(row, 5, "inbound_statistics.updated_at")?,
                })
            })
            .collect()
    }

    pub fn replace_inbound_statistics(&self, records: &[InboundStatisticsRecord]) -> Result<()> {
        self.with_write_retry(|connection| {
            connection
                .execute("BEGIN IMMEDIATE")
                .map_err(storage_error)?;
            let result = (|| {
                for record in records {
                    connection
                        .execute_with_params(
                            "INSERT INTO inbound_statistics
                                (inbound_id, total_tcp_flows, total_udp_flows,
                                 upload_bytes, download_bytes, updated_at)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                             ON CONFLICT(inbound_id) DO UPDATE SET
                                total_tcp_flows = excluded.total_tcp_flows,
                                total_udp_flows = excluded.total_udp_flows,
                                upload_bytes = excluded.upload_bytes,
                                download_bytes = excluded.download_bytes,
                                updated_at = excluded.updated_at",
                            &[
                                SqliteValue::from(record.inbound_id.as_str()),
                                sqlite_counter(record.total_tcp_flows),
                                sqlite_counter(record.total_udp_flows),
                                sqlite_counter(record.upload_bytes),
                                sqlite_counter(record.download_bytes),
                                SqliteValue::from(record.updated_at),
                            ],
                        )
                        .map_err(storage_error)?;
                }
                Ok(())
            })();
            match result {
                Ok(()) => connection
                    .execute("COMMIT")
                    .map_err(storage_error)
                    .map(|_| ()),
                Err(error) => {
                    let _ = connection.execute("ROLLBACK");
                    Err(error)
                }
            }
        })
    }

    pub fn append_inbound_runtime_event(&self, event: &InboundRuntimeEventInput) -> Result<i64> {
        self.with_write_retry(|connection| {
            let detail_json = std::str::from_utf8(&event.detail_json).map_err(|error| {
                Error::new(
                    ErrorKind::Storage,
                    format!("inbound runtime event detail is not UTF-8: {error}"),
                )
            })?;
            connection
                .execute_with_params(
                    "INSERT INTO inbound_runtime_events
                        (inbound_id, event_type, state, error, detail_json, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    &[
                        SqliteValue::from(event.inbound_id.as_str()),
                        SqliteValue::from(event.event_type.as_str()),
                        SqliteValue::from(event.state.as_str()),
                        event
                            .error
                            .as_deref()
                            .map_or(SqliteValue::Null, SqliteValue::from),
                        SqliteValue::from(detail_json),
                        SqliteValue::from(event.created_at),
                    ],
                )
                .map_err(storage_error)?;
            let rows = connection
                .query("SELECT last_insert_rowid()")
                .map_err(storage_error)?;
            let id = rows
                .first()
                .map(|row| row_integer(row, 0, "last_insert_rowid()"))
                .transpose()?
                .ok_or_else(|| Error::new(ErrorKind::Storage, "missing event row id"))?;
            connection
                .execute_with_params(
                    "DELETE FROM inbound_runtime_events
                     WHERE id IN (
                         SELECT id FROM inbound_runtime_events
                         WHERE inbound_id = ?2
                         ORDER BY created_at DESC, id DESC
                         LIMIT -1 OFFSET 1000
                     )
                     OR created_at < ?1",
                    &[
                        SqliteValue::from(event.created_at.saturating_sub(30 * 86_400)),
                        SqliteValue::from(event.inbound_id.as_str()),
                    ],
                )
                .map_err(storage_error)?;
            Ok(id)
        })
    }

    pub fn list_inbound_runtime_events(
        &self,
        inbound_id: &str,
        limit: usize,
    ) -> Result<Vec<InboundRuntimeEvent>> {
        let connection = self.lock_connection()?;
        let rows = connection
            .query_with_params(
                "SELECT id, inbound_id, event_type, state, error, detail_json, created_at
                 FROM inbound_runtime_events
                 WHERE inbound_id = ?1
                 ORDER BY created_at DESC, id DESC
                 LIMIT ?2",
                &[
                    SqliteValue::from(inbound_id),
                    SqliteValue::from(limit.clamp(1, 1000) as i64),
                ],
            )
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| {
                let detail_json = match row.get(5) {
                    Some(SqliteValue::Text(value)) => value.as_bytes().to_vec(),
                    Some(SqliteValue::Blob(value)) => value.to_vec(),
                    _ => {
                        return Err(Error::new(
                            ErrorKind::Storage,
                            "inbound_runtime_events.detail_json is not JSON text",
                        ));
                    }
                };
                Ok(InboundRuntimeEvent {
                    id: row_integer(row, 0, "inbound_runtime_events.id")?,
                    inbound_id: row_text(row, 1, "inbound_runtime_events.inbound_id")?,
                    event_type: row_text(row, 2, "inbound_runtime_events.event_type")?,
                    state: row_text(row, 3, "inbound_runtime_events.state")?,
                    error: optional_row_text(row, 4, "inbound_runtime_events.error")?,
                    detail_json,
                    created_at: row_integer(row, 6, "inbound_runtime_events.created_at")?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inbound_statistics_and_events_survive_store_round_trip() {
        let store = ConfigStore::open_memory().await.unwrap();
        let statistics = InboundStatisticsRecord {
            inbound_id: "socks".to_owned(),
            active_tcp: 2,
            active_udp: 1,
            total_tcp_flows: 9,
            total_udp_flows: 4,
            upload_bytes: 123,
            download_bytes: 456,
            updated_at: 1_700_000_000,
        };
        store
            .replace_inbound_statistics(std::slice::from_ref(&statistics))
            .unwrap();
        store
            .append_inbound_runtime_event(&InboundRuntimeEventInput {
                inbound_id: "socks".to_owned(),
                event_type: "ready".to_owned(),
                state: "running".to_owned(),
                error: None,
                detail_json: br#"{"listener":"tcp"}"#.to_vec(),
                created_at: 1_700_000_000,
            })
            .unwrap();

        let loaded = store.load_inbound_statistics().unwrap();
        assert_eq!(
            loaded,
            vec![InboundStatisticsRecord {
                active_tcp: 0,
                active_udp: 0,
                ..statistics
            }]
        );
        let events = store.list_inbound_runtime_events("socks", 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "ready");
        assert_eq!(events[0].detail_json, br#"{"listener":"tcp"}"#);
    }

    #[tokio::test]
    async fn event_retention_is_per_inbound() {
        let store = ConfigStore::open_memory().await.unwrap();
        for index in 0..1001 {
            store
                .append_inbound_runtime_event(&InboundRuntimeEventInput {
                    inbound_id: "busy".to_owned(),
                    event_type: "ready".to_owned(),
                    state: "running".to_owned(),
                    error: None,
                    detail_json: b"{}".to_vec(),
                    created_at: index,
                })
                .unwrap();
        }
        store
            .append_inbound_runtime_event(&InboundRuntimeEventInput {
                inbound_id: "quiet".to_owned(),
                event_type: "start".to_owned(),
                state: "starting".to_owned(),
                error: None,
                detail_json: b"{}".to_vec(),
                created_at: 1001,
            })
            .unwrap();

        assert_eq!(
            store
                .list_inbound_runtime_events("busy", 2000)
                .unwrap()
                .len(),
            1000
        );
        assert_eq!(
            store
                .list_inbound_runtime_events("quiet", 10)
                .unwrap()
                .len(),
            1
        );
    }
}
