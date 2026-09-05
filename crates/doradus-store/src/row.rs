//! Shared SQLite row decoding and typed record validation.

use super::*;

pub(crate) fn row_blob_or_text(row: &Row, index: usize, field: &str) -> Result<Vec<u8>> {
    match row.get(index) {
        Some(SqliteValue::Blob(value)) => Ok(value.as_ref().to_vec()),
        Some(SqliteValue::Text(value)) => Ok(value.as_bytes().to_vec()),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("Go schema field {field} is not TEXT or BLOB"),
        )),
    }
}

pub(crate) fn row_json_blob_or_text(row: &Row, index: usize, field: &str) -> Result<Vec<u8>> {
    let value = row_blob_or_text(row, index, field)?;
    validate_json_bytes(&value, field)?;
    Ok(value)
}

pub(crate) fn validate_json_bytes(value: &[u8], field: &str) -> Result<()> {
    serde_json::from_slice::<serde_json::Value>(value).map_err(|error| {
        Error::new(
            ErrorKind::Storage,
            format!("decode {field} as JSON failed: {error}"),
        )
    })?;
    Ok(())
}

pub(crate) fn validate_id(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(Error::invalid(
            "typed store identifier must be 1..=512 non-control characters",
        ));
    }
    Ok(())
}

pub(crate) fn validate_fakeip_scope(family: i64, prefix: &str) -> Result<()> {
    if family != 4 && family != 6 {
        return Err(Error::invalid("FakeIP family must be 4 or 6"));
    }
    validate_id(prefix)
}

pub(crate) fn validate_fakeip_entry(entry: &FakeIpEntryRecord) -> Result<()> {
    validate_fakeip_scope(entry.family, &entry.prefix)?;
    validate_id(&entry.domain)?;
    let expected_len = if entry.family == 4 { 4 } else { 16 };
    if entry.ip.len() != expected_len {
        return Err(Error::invalid("FakeIP entry has an invalid IP length"));
    }
    if entry.created_at < 0 || entry.last_used_at < 0 {
        return Err(Error::invalid(
            "FakeIP entry timestamps must not be negative",
        ));
    }
    Ok(())
}

pub(crate) fn validate_fakeip_cursor(cursor: &FakeIpCursorRecord) -> Result<()> {
    validate_fakeip_scope(cursor.family, &cursor.prefix)?;
    let expected_len = if cursor.family == 4 { 4 } else { 16 };
    if cursor.cursor_ip.len() != expected_len {
        return Err(Error::invalid("FakeIP cursor has an invalid IP length"));
    }
    if cursor.cursor_idx < 0 || cursor.updated_at < 0 {
        return Err(Error::invalid("FakeIP cursor values must not be negative"));
    }
    Ok(())
}

pub(crate) fn row_text(row: &Row, index: usize, field: &str) -> Result<String> {
    match row.get(index) {
        Some(SqliteValue::Text(value)) => Ok(value.as_ref().to_owned()),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("typed store field {field} is not TEXT"),
        )),
    }
}

pub(crate) fn row_optional_text(row: &Row, index: usize, field: &str) -> Result<Option<String>> {
    match row.get(index) {
        Some(SqliteValue::Null) => Ok(None),
        Some(SqliteValue::Text(value)) => Ok(Some(value.as_ref().to_owned())),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("typed store field {field} is not nullable TEXT"),
        )),
    }
}

pub(crate) fn row_blob(row: &Row, index: usize, field: &str) -> Result<Vec<u8>> {
    match row.get(index) {
        Some(SqliteValue::Blob(value)) => Ok(value.as_ref().to_vec()),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("typed store field {field} is not BLOB"),
        )),
    }
}

pub(crate) fn row_integer(row: &Row, index: usize, field: &str) -> Result<i64> {
    match row.get(index) {
        Some(SqliteValue::Integer(value)) => Ok(*value),
        _ => Err(Error::new(
            ErrorKind::Storage,
            format!("typed store field {field} is not INTEGER"),
        )),
    }
}

pub(crate) fn pragma_integer(connection: &Connection, name: &str) -> Result<i64> {
    let row = connection
        .query(&format!("PRAGMA {name}"))
        .map_err(storage_error)?
        .into_iter()
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Storage, format!("PRAGMA {name} returned no row")))?;
    row_integer(&row, 0, name)
}

pub(crate) fn fakeip_entry_from_row(row: &Row) -> Result<FakeIpEntryRecord> {
    Ok(FakeIpEntryRecord {
        family: row_integer(row, 0, "fakeip_entries.family")?,
        prefix: row_text(row, 1, "fakeip_entries.prefix")?,
        domain: row_text(row, 2, "fakeip_entries.domain")?,
        ip: row_blob(row, 3, "fakeip_entries.ip")?,
        created_at: row_integer(row, 4, "fakeip_entries.created_at")?,
        last_used_at: row_integer(row, 5, "fakeip_entries.last_used_at")?,
    })
}

pub(crate) fn fakeip_cursor_from_row(row: &Row) -> Result<FakeIpCursorRecord> {
    Ok(FakeIpCursorRecord {
        family: row_integer(row, 0, "fakeip_cursors.family")?,
        prefix: row_text(row, 1, "fakeip_cursors.prefix")?,
        cursor_ip: row_blob(row, 2, "fakeip_cursors.cursor_ip")?,
        cursor_idx: row_integer(row, 3, "fakeip_cursors.cursor_idx")?,
        updated_at: row_integer(row, 4, "fakeip_cursors.updated_at")?,
    })
}

pub(crate) fn proxy_node_from_row(row: &Row) -> Result<ProxyNodeRecord> {
    Ok(ProxyNodeRecord {
        id: row_text(row, 0, "proxy_nodes.id")?,
        kind: row_text(row, 1, "proxy_nodes.kind")?,
        config: row_blob(row, 2, "proxy_nodes.config")?,
    })
}

pub(crate) fn route_rule_from_row(row: &Row) -> Result<RouteRuleRecord> {
    Ok(RouteRuleRecord {
        id: row_text(row, 0, "route_rules.id")?,
        pattern: row_text(row, 1, "route_rules.pattern")?,
        action: row_text(row, 2, "route_rules.action")?,
        priority: row_integer(row, 3, "route_rules.priority")?,
        geo_country: row_optional_text(row, 4, "route_rules.geo_country")?,
        resolver_policy: row_blob(row, 5, "route_rules.resolver_policy")?,
    })
}

pub(crate) fn dns_resolver_from_row(row: &Row) -> Result<DnsResolverRecord> {
    Ok(DnsResolverRecord {
        id: row_text(row, 0, "dns_resolvers.id")?,
        kind: row_text(row, 1, "dns_resolvers.kind")?,
        config: row_blob(row, 2, "dns_resolvers.config")?,
    })
}

pub(crate) fn tun_config_from_row(row: &Row) -> Result<TunConfigRecord> {
    Ok(TunConfigRecord {
        key: row_text(row, 0, "tun_config.key")?,
        value: row_blob(row, 1, "tun_config.value")?,
    })
}

pub(crate) fn nat_config_from_row(row: &Row) -> Result<NatConfigRecord> {
    let full_cone = row_integer(row, 1, "nat_config.full_cone")?;
    if full_cone != 1 {
        return Err(Error::new(
            ErrorKind::Storage,
            "nat_config.full_cone must be enabled; only Full Cone NAT is supported",
        ));
    }
    Ok(NatConfigRecord {
        key: row_text(row, 0, "nat_config.key")?,
        full_cone: true,
        idle_timeout_ms: row_integer(row, 2, "nat_config.idle_timeout_ms")?,
    })
}

pub(crate) fn maxmind_from_row(row: &Row) -> Result<MaxMindMetadataRecord> {
    Ok(MaxMindMetadataRecord {
        id: row_text(row, 0, "maxmind_metadata.id")?,
        path: row_text(row, 1, "maxmind_metadata.path")?,
        sha256: row_blob(row, 2, "maxmind_metadata.sha256")?,
        size: row_integer(row, 3, "maxmind_metadata.size")?,
        updated_at: row_integer(row, 4, "maxmind_metadata.updated_at")?,
    })
}
