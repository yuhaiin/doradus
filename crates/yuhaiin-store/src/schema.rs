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
        "subscriptions",
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
        resolver_policy BLOB NOT NULL,
        -- Nullable Go v1 projection columns. They keep Go's legacy readers
        -- harmless on a native Rust database without changing Rust's typed
        -- contract.
        name TEXT,
        disabled INTEGER,
        updated_at INTEGER,
        data_json TEXT
    );
    CREATE TABLE IF NOT EXISTS dns_resolvers (
        id TEXT PRIMARY KEY NOT NULL,
        kind TEXT NOT NULL,
        config BLOB NOT NULL,
        -- Nullable Go v1 projection columns; Rust's canonical resolver
        -- contract remains id/kind/config.
        name TEXT,
        resolver_type INTEGER,
        host TEXT,
        subnet TEXT,
        tls_servername TEXT,
        data_json TEXT
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
    );
    CREATE TABLE IF NOT EXISTS subscriptions (
        name TEXT PRIMARY KEY,
        updated_at INTEGER NOT NULL,
        data_json TEXT NOT NULL CHECK (json_valid(data_json))
    );
    CREATE TABLE IF NOT EXISTS inbound_settings (
        id                INTEGER PRIMARY KEY CHECK (id = 1),
        hijack_dns        INTEGER NOT NULL,
        hijack_dns_fakeip INTEGER NOT NULL,
        sniff_enabled     INTEGER NOT NULL
    );
    -- Go's completed node migration still compares this legacy table with
    -- nodes_v2 on startup. Keep an empty, correctly shaped compatibility
    -- table in a native Rust database so that check is deterministic.
    CREATE TABLE IF NOT EXISTS nodes (
        id           INTEGER PRIMARY KEY,
        hash         TEXT NOT NULL UNIQUE,
        group_name   TEXT NOT NULL,
        name         TEXT NOT NULL,
        origin       INTEGER NOT NULL,
        selected_tcp INTEGER NOT NULL DEFAULT 0 CHECK (selected_tcp IN (0, 1)),
        selected_udp INTEGER NOT NULL DEFAULT 0 CHECK (selected_udp IN (0, 1)),
        search_text  TEXT NOT NULL DEFAULT '',
        updated_at   INTEGER NOT NULL,
        data_json    TEXT NOT NULL CHECK (json_valid(data_json))
    );
    CREATE TABLE IF NOT EXISTS android_extra_preferences (
        key         TEXT PRIMARY KEY,
        value_json  TEXT NOT NULL,
        updated_at  INTEGER NOT NULL,
        CHECK (json_valid(value_json))
    );
    CREATE TABLE IF NOT EXISTS settings_kv (
        section      TEXT NOT NULL,
        key          TEXT NOT NULL,
        value_json   TEXT NOT NULL CHECK (json_valid(value_json)),
        updated_at   INTEGER NOT NULL,
        PRIMARY KEY (section, key)
    );
    CREATE TABLE IF NOT EXISTS dns_settings (
        id                       INTEGER PRIMARY KEY CHECK (id = 1),
        server                   TEXT NOT NULL DEFAULT '',
        fakedns_enabled          INTEGER NOT NULL,
        fakedns_ipv4_range       TEXT NOT NULL DEFAULT '',
        fakedns_ipv6_range       TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS dns_hosts (
        host   TEXT PRIMARY KEY,
        target TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS dns_fakedns_lists (
        kind  TEXT NOT NULL,
        value TEXT NOT NULL,
        PRIMARY KEY (kind, value)
    );
    CREATE TABLE IF NOT EXISTS inbounds (
        name          TEXT PRIMARY KEY,
        enabled       INTEGER NOT NULL,
        inbound_type  TEXT NOT NULL,
        listen_host   TEXT NOT NULL DEFAULT '',
        updated_at    INTEGER NOT NULL,
        data_json     TEXT NOT NULL CHECK (json_valid(data_json))
    );
    CREATE TABLE IF NOT EXISTS node_tags (
        tag_name    TEXT NOT NULL,
        target_kind TEXT NOT NULL CHECK (target_kind IN ('node', 'tag')),
        target_id   TEXT NOT NULL,
        updated_at  INTEGER NOT NULL,
        PRIMARY KEY (tag_name, target_kind, target_id)
    );
    CREATE TABLE IF NOT EXISTS route_lists (
        name       TEXT PRIMARY KEY,
        kind       TEXT NOT NULL DEFAULT '',
        updated_at INTEGER NOT NULL,
        data_json  TEXT NOT NULL CHECK (json_valid(data_json))
    );
    CREATE TABLE IF NOT EXISTS route_list_refresh (
        name              TEXT PRIMARY KEY,
        refresh_interval  INTEGER NOT NULL,
        last_refresh_time INTEGER NOT NULL DEFAULT 0,
        last_error        TEXT NOT NULL DEFAULT '',
        FOREIGN KEY (name) REFERENCES route_lists(name) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS backup_settings (
        id         INTEGER PRIMARY KEY CHECK (id = 1),
        updated_at INTEGER NOT NULL,
        data_json  TEXT NOT NULL CHECK (json_valid(data_json))
    );
    CREATE TABLE IF NOT EXISTS connection_sessions (
        id             INTEGER PRIMARY KEY,
        opened_at      INTEGER NOT NULL,
        last_seen_at   INTEGER NOT NULL,
        closed_at      INTEGER,
        state          TEXT NOT NULL CHECK (state IN ('open', 'closed', 'interrupted')),
        protocol       INTEGER NOT NULL,
        process_name   TEXT NOT NULL DEFAULT '',
        inbound        TEXT NOT NULL DEFAULT '',
        inbound_name   TEXT NOT NULL DEFAULT '',
        outbound       TEXT NOT NULL DEFAULT '',
        network        TEXT NOT NULL DEFAULT '',
        destination    TEXT NOT NULL DEFAULT '',
        host           TEXT NOT NULL DEFAULT '',
        upload_bytes   INTEGER NOT NULL DEFAULT 0,
        download_bytes INTEGER NOT NULL DEFAULT 0,
        summary_json   TEXT NOT NULL CHECK (json_valid(summary_json))
    );
    CREATE TABLE IF NOT EXISTS settings_json (
        id         INTEGER PRIMARY KEY CHECK (id = 1),
        version    INTEGER NOT NULL,
        data_json  TEXT NOT NULL CHECK (json_valid(data_json)),
        updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS publishes (
        name       TEXT PRIMARY KEY,
        updated_at INTEGER NOT NULL,
        data_json  TEXT NOT NULL CHECK (json_valid(data_json))
    );
    CREATE TABLE IF NOT EXISTS users_v2 (
        id                TEXT PRIMARY KEY,
        name              TEXT NOT NULL DEFAULT '',
        enabled           INTEGER NOT NULL CHECK (enabled IN (0, 1)),
        origin            TEXT NOT NULL DEFAULT 'manual',
        usage             TEXT NOT NULL CHECK (usage IN ('inbound', 'outbound', 'both')),
        credential_type   TEXT NOT NULL CHECK (credential_type IN ('basic', 'uuid', 'token')),
        updated_at        INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS users_v2_name_idx ON users_v2(name, id);
    CREATE INDEX IF NOT EXISTS users_v2_enabled_type_usage_idx
        ON users_v2(enabled, credential_type, usage);
    CREATE TABLE IF NOT EXISTS user_basic_v2 (
        user_id             TEXT PRIMARY KEY,
        username            TEXT,
        password            TEXT,
        allow_any_username  INTEGER NOT NULL DEFAULT 0 CHECK (allow_any_username IN (0, 1)),
        allow_any_password  INTEGER NOT NULL DEFAULT 0 CHECK (allow_any_password IN (0, 1)),
        FOREIGN KEY (user_id) REFERENCES users_v2(id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS user_basic_v2_username_idx ON user_basic_v2(username);
    CREATE TABLE IF NOT EXISTS user_uuid_v2 (
        user_id TEXT PRIMARY KEY,
        uuid    TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users_v2(id) ON DELETE CASCADE
    );
    CREATE UNIQUE INDEX IF NOT EXISTS user_uuid_v2_uuid_idx ON user_uuid_v2(uuid);
    CREATE TABLE IF NOT EXISTS user_token_v2 (
        user_id TEXT PRIMARY KEY,
        token   TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users_v2(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS user_migration_state_v2 (
        migration_name TEXT PRIMARY KEY,
        status         TEXT NOT NULL CHECK (status IN ('running', 'completed')),
        completed_at   INTEGER
    );
    CREATE TABLE IF NOT EXISTS user_migration_sources_v2 (
        migration_name TEXT NOT NULL,
        source_kind    TEXT NOT NULL,
        source_id      TEXT NOT NULL,
        source_path    TEXT NOT NULL,
        dedup_scope    TEXT NOT NULL,
        dedup_key      BLOB NOT NULL,
        user_id        TEXT NOT NULL,
        migrated_at    INTEGER NOT NULL,
        PRIMARY KEY (migration_name, source_kind, source_id, source_path),
        FOREIGN KEY (user_id) REFERENCES users_v2(id) ON DELETE RESTRICT
    );
    CREATE INDEX IF NOT EXISTS user_migration_sources_user_idx
        ON user_migration_sources_v2(user_id);
    CREATE TABLE IF NOT EXISTS user_migration_dedup_v2 (
        migration_name TEXT NOT NULL,
        dedup_scope    TEXT NOT NULL,
        dedup_key      BLOB NOT NULL,
        user_id        TEXT NOT NULL,
        PRIMARY KEY (migration_name, dedup_scope, dedup_key),
        FOREIGN KEY (user_id) REFERENCES users_v2(id) ON DELETE RESTRICT
    );
    CREATE TABLE IF NOT EXISTS traffic_dimension_daily (
        bucket_start_utc INTEGER NOT NULL,
        value_id          INTEGER NOT NULL,
        upload_bytes      INTEGER NOT NULL DEFAULT 0,
        download_bytes    INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket_start_utc, value_id)
    ) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS failure_dimension_daily (
        bucket_start_utc INTEGER NOT NULL,
        value_id          INTEGER NOT NULL,
        failed_count      INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket_start_utc, value_id)
    ) WITHOUT ROWID;"
}

/// Mark a native Rust database as already having Go's plain-contract
/// migrations. Rust creates the v2 contract tables directly; replaying Go's
/// v1-v6 DDL during a rollback would try to recreate names such as
/// `dns_resolvers` with an incompatible shape.
pub(super) fn bootstrap_go_compatibility_metadata(connection: &Connection) -> Result<()> {
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS migrate (
                version    INTEGER PRIMARY KEY,
                name       TEXT NOT NULL,
                applied_at INTEGER NOT NULL
            );",
        )
        .map_err(storage_error)?;

    connection
        .execute_with_params(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES (?1, ?2)",
            &[SqliteValue::from("schema_version"), SqliteValue::from("6")],
        )
        .map_err(storage_error)?;

    for (version, name) in [
        (1_i64, "initial_schema"),
        (2, "fakeip_cache"),
        (3, "plain_contract_model"),
        (4, "plain_route_lists"),
        (5, "telemetry_dimensions"),
        (6, "compact_telemetry_dimensions"),
    ] {
        connection
            .execute_with_params(
                "INSERT OR REPLACE INTO migrate(version, name, applied_at)
                 VALUES (?1, ?2, 0)",
                &[SqliteValue::from(version), SqliteValue::from(name)],
            )
            .map_err(storage_error)?;
    }

    for key in [
        "plain_model_migration_done",
        "plain_inbounds_migration_done",
        "plain_nodes_migration_done",
        "plain_subscriptions_migration_done",
        "plain_resolvers_migration_done",
        "plain_route_rules_migration_done",
        "plain_route_lists_migration_done",
        "plain_route_tags_migration_done",
        "legacy_config_import_done",
        "legacy_android_protobuf_config_repair_done",
        "legacy_android_preferences_import_done",
        "legacy_node_import_done",
        "plain_inbound_transport_recovery_v1_done",
        "plain_node_chain_recovery_v1_done",
        "plain_backup_migration_done",
        "plain_statistic_json_migration_done",
        "legacy_settings_kv_normalization_done",
    ] {
        connection
            .execute_with_params(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES (?1, '1')",
                &[SqliteValue::from(key)],
            )
            .map_err(storage_error)?;
    }

    for (key, value) in [("go_schema_imported", 1_i64), ("go_schema_version", 6)] {
        connection
            .execute_with_params(
                "INSERT OR REPLACE INTO yuhaiin_meta(key, value) VALUES (?1, ?2)",
                &[SqliteValue::from(key), SqliteValue::from(value)],
            )
            .map_err(storage_error)?;
    }
    Ok(())
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
        (
            "subscriptions",
            &[
                ("name", "TEXT", false, 1),
                ("updated_at", "INTEGER", true, 0),
                ("data_json", "TEXT", true, 0),
            ],
        ),
        (
            "users_v2",
            &[
                ("id", "TEXT", false, 1),
                ("name", "TEXT", true, 0),
                ("enabled", "INTEGER", true, 0),
                ("origin", "TEXT", true, 0),
                ("usage", "TEXT", true, 0),
                ("credential_type", "TEXT", true, 0),
                ("updated_at", "INTEGER", true, 0),
            ],
        ),
        (
            "user_basic_v2",
            &[
                ("user_id", "TEXT", false, 1),
                ("username", "TEXT", false, 0),
                ("password", "TEXT", false, 0),
                ("allow_any_username", "INTEGER", true, 0),
                ("allow_any_password", "INTEGER", true, 0),
            ],
        ),
        (
            "user_uuid_v2",
            &[("user_id", "TEXT", false, 1), ("uuid", "TEXT", true, 0)],
        ),
        (
            "user_token_v2",
            &[("user_id", "TEXT", false, 1), ("token", "TEXT", true, 0)],
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
