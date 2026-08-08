//! Rust-owned SQLite schema and migration contract checks.

use std::collections::HashMap;

use super::{
    Connection, Error, ErrorKind, Result, SqliteValue, row_integer, row_text, storage_error,
    table_exists,
};

pub(super) fn configure_connection(connection: &Connection) -> Result<()> {
    connection
        .execute_batch(
            "-- Apply memory limits before a legacy DELETE-journal database is
             -- switched to WAL during migration.
             PRAGMA cache_size = -32768;
             PRAGMA temp_store = FILE;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(storage_error)
}

pub(super) fn verify_integrity(connection: &Connection) -> Result<()> {
    // Do not run a database-wide quick_check here.  Go production databases
    // contain FTS5 shadow tables that are valid to the system SQLite used by
    // Go but are not fully understood by every SQLite engine configuration. A
    // database-wide check can therefore reject an otherwise readable config
    // file before the Rust migration gets a chance to preserve it.  Check the
    // Rust-owned and migration-critical tables explicitly instead; this still
    // fails closed on corruption of the state the Rust runtime will consume.
    const CRITICAL_TABLES: &[&str] = &[
        "metadata",
        "migrate",
        "yuhaiin_meta",
        "yuhaiin_config",
        "proxy_nodes",
        "route_rules",
        "dns_resolvers",
        "route_settings",
        "tun_config",
        "nat_config",
        "maxmind_metadata",
        "fakeip_entries",
        "fakeip_cursors",
        "resolvers_v2",
        "route_rules_v2",
    ];
    for table in CRITICAL_TABLES {
        if !table_exists(connection, table) {
            continue;
        }
        let rows = connection
            .query(&format!("PRAGMA quick_check('{table}')"))
            .map_err(storage_error)?;
        let result = rows
            .first()
            .and_then(|row| row.get(0))
            .and_then(|value| match value {
                SqliteValue::Text(value) => Some(value.as_ref()),
                _ => None,
            });
        if result != Some("ok") {
            return Err(Error::new(
                ErrorKind::Storage,
                format!(
                    "SQLite quick_check for {table} failed: {}",
                    result.unwrap_or("missing result")
                ),
            ));
        }
    }
    Ok(())
}

pub(super) fn typed_schema_sql() -> &'static str {
    "CREATE TABLE IF NOT EXISTS proxy_nodes (
        id TEXT PRIMARY KEY NOT NULL,
        kind TEXT NOT NULL,
        config BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS nodes_v2 (
        id TEXT PRIMARY KEY NOT NULL,
        name TEXT NOT NULL,
        group_name TEXT NOT NULL,
        origin TEXT NOT NULL,
        enabled INTEGER NOT NULL,
        chain_types_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        data_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS inbounds_v2 (
        id TEXT PRIMARY KEY NOT NULL,
        name TEXT NOT NULL,
        enabled INTEGER NOT NULL,
        network_type TEXT NOT NULL,
        protocol_type TEXT NOT NULL,
        transport_types_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        data_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS node_tags_v2 (
        id TEXT PRIMARY KEY NOT NULL,
        name TEXT NOT NULL,
        members_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS route_rules (
        id TEXT PRIMARY KEY NOT NULL,
        pattern TEXT NOT NULL,
        action TEXT NOT NULL,
        priority INTEGER NOT NULL,
        geo_country TEXT,
        resolver_policy BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS dns_resolvers (
        id TEXT PRIMARY KEY NOT NULL,
        kind TEXT NOT NULL,
        config BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS route_settings (
        id INTEGER PRIMARY KEY NOT NULL,
        direct_resolver TEXT NOT NULL,
        proxy_resolver TEXT NOT NULL,
        resolve_locally INTEGER NOT NULL,
        udp_proxy_fqdn INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tun_config (
        key TEXT PRIMARY KEY NOT NULL,
        value BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS nat_config (
        key TEXT PRIMARY KEY NOT NULL,
        full_cone INTEGER NOT NULL DEFAULT 1,
        idle_timeout_ms INTEGER NOT NULL DEFAULT 30000,
        CHECK (full_cone = 1)
    );
    CREATE TABLE IF NOT EXISTS maxmind_metadata (
        id TEXT PRIMARY KEY NOT NULL,
        path TEXT NOT NULL,
        sha256 BLOB NOT NULL,
        size INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS fakeip_entries (
        family INTEGER NOT NULL,
        prefix TEXT NOT NULL,
        domain TEXT NOT NULL,
        ip BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER NOT NULL,
        PRIMARY KEY (family, prefix, domain),
        UNIQUE (family, prefix, ip)
    );
    CREATE INDEX IF NOT EXISTS fakeip_entries_ip_idx
        ON fakeip_entries(family, prefix, ip);
    CREATE INDEX IF NOT EXISTS fakeip_entries_lru_idx
        ON fakeip_entries(family, prefix, last_used_at);
    CREATE UNIQUE INDEX IF NOT EXISTS fakeip_entries_reverse_unique
        ON fakeip_entries(family, prefix, ip);
    CREATE TABLE IF NOT EXISTS fakeip_cursors (
        family INTEGER NOT NULL,
        prefix TEXT NOT NULL,
        cursor_ip BLOB NOT NULL,
        cursor_idx INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (family, prefix)
    );
    CREATE TABLE IF NOT EXISTS resolvers_v2 (
        id TEXT PRIMARY KEY NOT NULL,
        resolver_type TEXT NOT NULL,
        host TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        data_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS route_rules_v2 (
        id TEXT PRIMARY KEY NOT NULL,
        name TEXT NOT NULL,
        priority INTEGER NOT NULL,
        disabled INTEGER NOT NULL,
        action_mode TEXT NOT NULL,
        match_type TEXT NOT NULL,
        tag TEXT NOT NULL DEFAULT '',
        updated_at INTEGER NOT NULL,
        data_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS route_lists_v2 (
        name TEXT PRIMARY KEY NOT NULL,
        list_type TEXT NOT NULL,
        source_type TEXT NOT NULL,
        updated_at INTEGER NOT NULL,
        data_json TEXT NOT NULL
    );"
}

#[derive(Debug, Clone)]
struct TypedColumnInfo {
    declared_type: String,
    not_null: bool,
    primary_key_position: i64,
}

#[derive(Debug, Clone)]
struct TypedIndexInfo {
    unique: bool,
    columns: Vec<String>,
}

pub(super) fn validate_typed_schema(connection: &Connection) -> Result<()> {
    // These tables are owned by the Rust store.  Checking only column names
    // would let a pre-existing table with an incompatible SQLite affinity or
    // nullability pass CREATE TABLE IF NOT EXISTS and fail later, after a
    // migration had already been committed.  Keep this contract explicit so
    // schema drift fails inside the migration transaction.
    let contracts: &[(&str, &[(&str, &str, bool, i64)])] = &[
        (
            "yuhaiin_meta",
            &[("key", "TEXT", true, 1), ("value", "INTEGER", true, 0)],
        ),
        (
            "yuhaiin_config",
            &[("key", "TEXT", true, 1), ("value", "BLOB", true, 0)],
        ),
        (
            "proxy_nodes",
            &[
                ("id", "TEXT", true, 1),
                ("kind", "TEXT", true, 0),
                ("config", "BLOB", true, 0),
            ],
        ),
        (
            "route_rules",
            &[
                ("id", "TEXT", true, 1),
                ("pattern", "TEXT", true, 0),
                ("action", "TEXT", true, 0),
                ("priority", "INTEGER", true, 0),
                ("geo_country", "TEXT", false, 0),
                ("resolver_policy", "BLOB", true, 0),
            ],
        ),
        (
            "dns_resolvers",
            &[
                ("id", "TEXT", true, 1),
                ("kind", "TEXT", true, 0),
                ("config", "BLOB", true, 0),
            ],
        ),
        (
            "tun_config",
            &[("key", "TEXT", true, 1), ("value", "BLOB", true, 0)],
        ),
        (
            "nat_config",
            &[
                ("key", "TEXT", true, 1),
                ("full_cone", "INTEGER", true, 0),
                ("idle_timeout_ms", "INTEGER", true, 0),
            ],
        ),
        (
            "maxmind_metadata",
            &[
                ("id", "TEXT", true, 1),
                ("path", "TEXT", true, 0),
                ("sha256", "BLOB", true, 0),
                ("size", "INTEGER", true, 0),
                ("updated_at", "INTEGER", true, 0),
            ],
        ),
        (
            "fakeip_entries",
            &[
                ("family", "INTEGER", true, 1),
                ("prefix", "TEXT", true, 2),
                ("domain", "TEXT", true, 3),
                ("ip", "BLOB", true, 0),
                ("created_at", "INTEGER", true, 0),
                ("last_used_at", "INTEGER", true, 0),
            ],
        ),
        (
            "fakeip_cursors",
            &[
                ("family", "INTEGER", true, 1),
                ("prefix", "TEXT", true, 2),
                ("cursor_ip", "BLOB", true, 0),
                ("cursor_idx", "INTEGER", true, 0),
                ("updated_at", "INTEGER", true, 0),
            ],
        ),
    ];
    for (table, columns) in contracts {
        let actual_columns = table_columns(connection, table)?;
        for &(column, expected_type, expected_not_null, expected_primary_key_position) in *columns {
            let Some(actual) = actual_columns.get(column) else {
                return Err(Error::new(
                    ErrorKind::Storage,
                    format!("typed schema table {table} is missing column {column}"),
                ));
            };
            if !actual.declared_type.eq_ignore_ascii_case(expected_type) {
                return Err(Error::new(
                    ErrorKind::Storage,
                    format!(
                        "typed schema table {table} column {column} has type {}, expected {expected_type}",
                        actual.declared_type
                    ),
                ));
            }
            if actual.not_null != expected_not_null {
                let expected = if expected_not_null {
                    "NOT NULL"
                } else {
                    "nullable"
                };
                return Err(Error::new(
                    ErrorKind::Storage,
                    format!(
                        "typed schema table {table} column {column} has unexpected nullability; expected {expected}"
                    ),
                ));
            }
            if actual.primary_key_position != expected_primary_key_position {
                return Err(Error::new(
                    ErrorKind::Storage,
                    format!(
                        "typed schema table {table} column {column} has primary-key position {}, expected {expected_primary_key_position}",
                        actual.primary_key_position
                    ),
                ));
            }
        }
    }

    let index_contracts: &[(&str, &str, bool, &[&str])] = &[
        (
            "fakeip_entries",
            "fakeip_entries_ip_idx",
            false,
            &["family", "prefix", "ip"],
        ),
        (
            "fakeip_entries",
            "fakeip_entries_lru_idx",
            false,
            &["family", "prefix", "last_used_at"],
        ),
    ];
    for (table, index, expected_unique, expected_columns) in index_contracts {
        let indexes = table_indexes(connection, table)?;
        let Some(actual) = indexes.get(*index) else {
            return Err(Error::new(
                ErrorKind::Storage,
                format!("typed schema table {table} is missing index {index}"),
            ));
        };
        let columns_match = actual.columns.len() == expected_columns.len()
            && actual
                .columns
                .iter()
                .zip(expected_columns.iter())
                .all(|(actual, expected)| actual == *expected);
        if actual.unique != *expected_unique || !columns_match {
            return Err(Error::new(
                ErrorKind::Storage,
                format!(
                    "typed schema index {table}.{index} has an incompatible uniqueness or column contract"
                ),
            ));
        }
    }

    let fakeip_indexes = table_indexes(connection, "fakeip_entries")?;
    let has_fakeip_reverse_unique = fakeip_indexes.values().any(|index| {
        index.unique
            && index
                .columns
                .iter()
                .map(String::as_str)
                .eq(["family", "prefix", "ip"].iter().copied())
    });
    if !has_fakeip_reverse_unique {
        return Err(Error::new(
            ErrorKind::Storage,
            "typed schema table fakeip_entries is missing UNIQUE(family, prefix, ip)",
        ));
    }
    Ok(())
}

/// Import the stable, plain-contract tables written by the Go store.  The
/// import deliberately keeps the original JSON in the typed record/config
/// blob: fields that Rust does not understand yet remain recoverable instead
/// of being silently discarded.  A marker in our metadata table makes the
/// operation idempotent across restart and also records the source schema
/// version used for the field-difference report.

pub(super) fn prepare_go_legacy_tables(connection: &Connection) -> Result<()> {
    if !table_exists(connection, "metadata") || !table_exists(connection, "migrate") {
        return Ok(());
    }
    for (source, target, typed_column) in [
        ("dns_resolvers", "go_legacy_dns_resolvers", "id"),
        ("route_rules", "go_legacy_route_rules", "pattern"),
    ] {
        if !table_exists(connection, source) || table_has_column(connection, source, typed_column)?
        {
            continue;
        }
        if table_exists(connection, target) {
            return Err(Error::new(
                ErrorKind::Storage,
                format!(
                    "both legacy and prepared Go compatibility tables exist: {source}, {target}"
                ),
            ));
        }
        connection
            .execute(&format!("ALTER TABLE {source} RENAME TO {target}"))
            .map_err(storage_error)?;
    }
    Ok(())
}

pub(super) fn table_has_column(connection: &Connection, table: &str, column: &str) -> Result<bool> {
    Ok(table_columns(connection, table)?.contains_key(column))
}

fn table_columns(connection: &Connection, table: &str) -> Result<HashMap<String, TypedColumnInfo>> {
    let rows = connection
        .query(&format!("PRAGMA table_info({table})"))
        .map_err(storage_error)?;
    let mut columns = HashMap::with_capacity(rows.len());
    for row in &rows {
        let name = row_text(row, 1, &format!("{table}.name"))?;
        let declared_type = row_text(row, 2, &format!("{table}.{name}.type"))?;
        let not_null = row_integer(row, 3, &format!("{table}.{name}.notnull"))? != 0;
        let primary_key_position = row_integer(row, 5, &format!("{table}.{name}.pk"))?;
        columns.insert(
            name,
            TypedColumnInfo {
                declared_type,
                not_null,
                primary_key_position,
            },
        );
    }
    Ok(columns)
}

fn table_indexes(connection: &Connection, table: &str) -> Result<HashMap<String, TypedIndexInfo>> {
    let rows = connection
        .query(&format!("PRAGMA index_list({table})"))
        .map_err(storage_error)?;
    let mut indexes = HashMap::with_capacity(rows.len());
    for row in &rows {
        let name = row_text(row, 1, &format!("{table}.index_name"))?;
        let unique = row_integer(row, 2, &format!("{table}.{name}.unique"))? != 0;
        let escaped_name = name.replace('\'', "''");
        let info_rows = connection
            .query(&format!("PRAGMA index_info('{escaped_name}')"))
            .map_err(storage_error)?;
        let mut columns = Vec::with_capacity(info_rows.len());
        for info_row in &info_rows {
            columns.push(row_text(info_row, 2, &format!("{table}.{name}.column"))?);
        }
        indexes.insert(name, TypedIndexInfo { unique, columns });
    }
    Ok(indexes)
}
