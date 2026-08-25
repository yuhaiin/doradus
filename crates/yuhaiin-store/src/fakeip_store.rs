//! Persistent FakeIP allocation and legacy-state import operations.

use super::*;

impl ConfigStore {
    pub async fn list_fakeip_entries(
        &self,
        family: i64,
        prefix: &str,
    ) -> Result<Vec<FakeIpEntryRecord>> {
        validate_fakeip_scope(family, prefix)?;
        let connection = self.lock_connection()?;
        let rows = connection
            .query_with_params(
                "SELECT family, prefix, domain, ip, created_at, last_used_at
                 FROM fakeip_entries
                 WHERE family = ?1 AND prefix = ?2
                 ORDER BY ip, domain",
                &[SqliteValue::from(family), SqliteValue::from(prefix)],
            )
            .map_err(storage_error)?;
        rows.iter().map(fakeip_entry_from_row).collect()
    }

    /// Find live-address candidates from other FakeIP prefixes that overlap
    /// the currently active range.  Prefix is part of the persistence key,
    /// but it is not present in packets, so reusing an address across two
    /// ranges can make a stale client packet resolve to the wrong domain.
    pub async fn list_fakeip_entries_in_range(
        &self,
        family: i64,
        prefix: &str,
        start_ip: &[u8],
        end_ip: &[u8],
    ) -> Result<Vec<FakeIpEntryRecord>> {
        validate_fakeip_scope(family, prefix)?;
        let expected_len = if family == 4 { 4 } else { 16 };
        if start_ip.len() != expected_len || end_ip.len() != expected_len || start_ip > end_ip {
            return Err(Error::invalid("invalid FakeIP address range"));
        }
        let connection = self.lock_connection()?;
        let rows = connection
            .query_with_params(
                "SELECT family, prefix, domain, ip, created_at, last_used_at
                 FROM fakeip_entries
                 WHERE family = ?1 AND prefix <> ?2 AND length(ip) = ?3
                   AND ip >= ?4 AND ip <= ?5
                 ORDER BY ip, prefix, domain",
                &[
                    SqliteValue::from(family),
                    SqliteValue::from(prefix),
                    SqliteValue::from(expected_len as i64),
                    SqliteValue::from(start_ip),
                    SqliteValue::from(end_ip),
                ],
            )
            .map_err(storage_error)?;
        rows.iter().map(fakeip_entry_from_row).collect()
    }

    pub async fn get_fakeip_cursor(
        &self,
        family: i64,
        prefix: &str,
    ) -> Result<Option<FakeIpCursorRecord>> {
        validate_fakeip_scope(family, prefix)?;
        let connection = self.lock_connection()?;
        let rows = connection
            .query_with_params(
                "SELECT family, prefix, cursor_ip, cursor_idx, updated_at
                 FROM fakeip_cursors
                 WHERE family = ?1 AND prefix = ?2",
                &[SqliteValue::from(family), SqliteValue::from(prefix)],
            )
            .map_err(storage_error)?;
        rows.first().map(fakeip_cursor_from_row).transpose()
    }

    /// Commit an allocation/reuse as one transaction.  The old domain and
    /// any stale owner of the selected IP are removed before the new forward
    /// row and cursor are written, so a crash cannot leave a forward-only or
    /// reverse-only mapping.
    pub async fn replace_fakeip_entry(
        &self,
        entry: &FakeIpEntryRecord,
        cursor: &FakeIpCursorRecord,
        evicted_domain: Option<&str>,
    ) -> Result<()> {
        validate_fakeip_entry(entry)?;
        validate_fakeip_cursor(cursor)?;
        if entry.family != cursor.family || entry.prefix != cursor.prefix {
            return Err(Error::invalid(
                "FakeIP entry and cursor must use the same scope",
            ));
        }
        if let Some(domain) = evicted_domain {
            validate_id(domain)?;
        }
        self.with_write_transaction(|connection| {
            connection
                .execute_with_params(
                    "DELETE FROM fakeip_entries
                     WHERE family = ?1 AND prefix = ?2 AND domain = ?3",
                    &[
                        SqliteValue::from(entry.family),
                        SqliteValue::from(entry.prefix.as_str()),
                        SqliteValue::from(entry.domain.as_str()),
                    ],
                )
                .map_err(storage_error)?;
            if let Some(domain) = evicted_domain {
                connection
                    .execute_with_params(
                        "DELETE FROM fakeip_entries
                         WHERE family = ?1 AND prefix = ?2 AND domain = ?3",
                        &[
                            SqliteValue::from(entry.family),
                            SqliteValue::from(entry.prefix.as_str()),
                            SqliteValue::from(domain),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            // The UNIQUE scope/IP constraint makes this defensive delete
            // important when an older process left a row that is absent from
            // this process's in-memory snapshot.
            connection
                .execute_with_params(
                    "DELETE FROM fakeip_entries
                     WHERE family = ?1 AND prefix = ?2 AND ip = ?3",
                    &[
                        SqliteValue::from(entry.family),
                        SqliteValue::from(entry.prefix.as_str()),
                        SqliteValue::from(entry.ip.as_slice()),
                    ],
                )
                .map_err(storage_error)?;
            connection
                .execute_with_params(
                    "INSERT INTO fakeip_entries
                     (family, prefix, domain, ip, created_at, last_used_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    &[
                        SqliteValue::from(entry.family),
                        SqliteValue::from(entry.prefix.as_str()),
                        SqliteValue::from(entry.domain.as_str()),
                        SqliteValue::from(entry.ip.as_slice()),
                        SqliteValue::from(entry.created_at),
                        SqliteValue::from(entry.last_used_at),
                    ],
                )
                .map_err(storage_error)?;
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO fakeip_cursors
                     (family, prefix, cursor_ip, cursor_idx, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[
                        SqliteValue::from(cursor.family),
                        SqliteValue::from(cursor.prefix.as_str()),
                        SqliteValue::from(cursor.cursor_ip.as_slice()),
                        SqliteValue::from(cursor.cursor_idx),
                        SqliteValue::from(cursor.updated_at),
                    ],
                )
                .map(|_| ())
                .map_err(storage_error)
        })
    }

    pub async fn delete_fakeip_entries(
        &self,
        family: i64,
        prefix: &str,
        domains: &[String],
    ) -> Result<usize> {
        validate_fakeip_scope(family, prefix)?;
        for domain in domains {
            validate_id(domain)?;
        }
        if domains.is_empty() {
            return Ok(0);
        }
        self.with_write_transaction(|connection| {
            let mut deleted = 0usize;
            for domain in domains {
                deleted += connection
                    .execute_with_params(
                        "DELETE FROM fakeip_entries
                         WHERE family = ?1 AND prefix = ?2 AND domain = ?3",
                        &[
                            SqliteValue::from(family),
                            SqliteValue::from(prefix),
                            SqliteValue::from(domain.as_str()),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            Ok(deleted)
        })
    }

    /// Persist delayed `last_used_at` touches in one bounded transaction.
    pub async fn touch_fakeip_entries(
        &self,
        family: i64,
        prefix: &str,
        touches: &[(String, i64)],
    ) -> Result<usize> {
        validate_fakeip_scope(family, prefix)?;
        for (domain, timestamp) in touches {
            validate_id(domain)?;
            if *timestamp < 0 {
                return Err(Error::invalid("FakeIP last_used_at must not be negative"));
            }
        }
        if touches.is_empty() {
            return Ok(0);
        }
        self.with_write_transaction(|connection| {
            let mut updated = 0usize;
            for (domain, timestamp) in touches {
                updated += connection
                    .execute_with_params(
                        "UPDATE fakeip_entries SET last_used_at = ?1
                         WHERE family = ?2 AND prefix = ?3 AND domain = ?4",
                        &[
                            SqliteValue::from(*timestamp),
                            SqliteValue::from(family),
                            SqliteValue::from(prefix),
                            SqliteValue::from(domain.as_str()),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            Ok(updated)
        })
    }

    /// Import a legacy snapshot into the typed tables atomically.  Legacy KV
    /// keys are removed only after all typed rows and the cursor are written.
    pub async fn import_fakeip_state(
        &self,
        entries: &[FakeIpEntryRecord],
        cursor: &FakeIpCursorRecord,
        legacy_keys: &[String],
        marker_key: Option<&str>,
    ) -> Result<()> {
        self.import_fakeip_state_inner(entries, cursor, legacy_keys, marker_key, false)
            .await
            .map(|_| ())
    }

    /// Import a legacy snapshot only if its marker has not already been
    /// committed. The marker check is inside the same IMMEDIATE transaction as
    /// the rows, so two concurrent importers cannot overwrite one another.
    pub async fn import_fakeip_state_if_unmarked(
        &self,
        entries: &[FakeIpEntryRecord],
        cursor: &FakeIpCursorRecord,
        legacy_keys: &[String],
        marker_key: &str,
    ) -> Result<bool> {
        self.import_fakeip_state_inner(entries, cursor, legacy_keys, Some(marker_key), true)
            .await
    }

    async fn import_fakeip_state_inner(
        &self,
        entries: &[FakeIpEntryRecord],
        cursor: &FakeIpCursorRecord,
        legacy_keys: &[String],
        marker_key: Option<&str>,
        skip_if_marked: bool,
    ) -> Result<bool> {
        validate_fakeip_cursor(cursor)?;
        for entry in entries {
            validate_fakeip_entry(entry)?;
            if entry.family != cursor.family || entry.prefix != cursor.prefix {
                return Err(Error::invalid(
                    "legacy FakeIP entries and cursor must use the same scope",
                ));
            }
        }
        for key in legacy_keys {
            validate_key(key)?;
        }
        if let Some(marker_key) = marker_key {
            validate_key(marker_key)?;
        }
        self.with_write_transaction(|connection| {
            if skip_if_marked {
                let marker_key = marker_key.expect("unmarked import requires a marker");
                let rows = connection
                    .query_with_params(
                        "SELECT 1 FROM yuhaiin_config WHERE key = ?1",
                        &[SqliteValue::from(marker_key)],
                    )
                    .map_err(storage_error)?;
                if !rows.is_empty() {
                    return Ok(false);
                }
            }
            for entry in entries {
                connection
                    .execute_with_params(
                        "INSERT OR REPLACE INTO fakeip_entries
                         (family, prefix, domain, ip, created_at, last_used_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        &[
                            SqliteValue::from(entry.family),
                            SqliteValue::from(entry.prefix.as_str()),
                            SqliteValue::from(entry.domain.as_str()),
                            SqliteValue::from(entry.ip.as_slice()),
                            SqliteValue::from(entry.created_at),
                            SqliteValue::from(entry.last_used_at),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            connection
                .execute_with_params(
                    "INSERT OR REPLACE INTO fakeip_cursors
                     (family, prefix, cursor_ip, cursor_idx, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[
                        SqliteValue::from(cursor.family),
                        SqliteValue::from(cursor.prefix.as_str()),
                        SqliteValue::from(cursor.cursor_ip.as_slice()),
                        SqliteValue::from(cursor.cursor_idx),
                        SqliteValue::from(cursor.updated_at),
                    ],
                )
                .map_err(storage_error)?;
            for key in legacy_keys {
                connection
                    .execute_with_params(
                        "DELETE FROM yuhaiin_config WHERE key = ?1",
                        &[SqliteValue::from(key.as_str())],
                    )
                    .map_err(storage_error)?;
            }
            if let Some(marker_key) = marker_key {
                connection
                    .execute_with_params(
                        "INSERT OR REPLACE INTO yuhaiin_config (key, value)
                         VALUES (?1, ?2)",
                        &[
                            SqliteValue::from(marker_key),
                            SqliteValue::from(b"1".as_slice()),
                        ],
                    )
                    .map_err(storage_error)?;
            }
            Ok(true)
        })
    }
}
