//! Go schema-version validation and migration flags.

use super::*;

pub fn read_go_schema_version(connection: &Connection) -> Result<i64> {
    let metadata_rows = connection
        .query_with_params(
            "SELECT value FROM metadata WHERE key = ?1",
            &[SqliteValue::from("schema_version")],
        )
        .map_err(storage_error)?;
    let metadata_version = metadata_rows
        .first()
        .map(|row| {
            let version = match row.get(0) {
                Some(SqliteValue::Text(value)) => {
                    value.as_ref().parse::<i64>().map_err(|error| {
                        Error::new(
                            ErrorKind::Storage,
                            format!("Go schema_version is not an integer: {error}"),
                        )
                    })?
                }
                Some(SqliteValue::Integer(value)) => *value,
                _ => {
                    return Err(Error::new(
                        ErrorKind::Storage,
                        "Go schema_version has an unsupported value type",
                    ));
                }
            };
            if version < 0 {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "Go schema_version must not be negative",
                ));
            }
            validate_go_schema_version(version)
        })
        .transpose()?;

    let rows = connection
        .query("SELECT version FROM migrate ORDER BY version")
        .map_err(storage_error)?;
    let mut version = 0;
    for row in rows {
        let value = match row.get(0) {
            Some(SqliteValue::Integer(value)) => *value,
            Some(SqliteValue::Null) | None => {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "Go migrate.version must be an integer",
                ));
            }
            Some(_) => {
                return Err(Error::new(
                    ErrorKind::Storage,
                    "Go migrate.version must be an integer",
                ));
            }
        };
        if value < 0 {
            return Err(Error::new(
                ErrorKind::Storage,
                "Go migration version must not be negative",
            ));
        }
        version = version.max(value);
    }
    let migration_version = validate_go_schema_version(version)?;
    if let Some(metadata_version) = metadata_version {
        if metadata_version != migration_version {
            // Some current Go production databases contain the additive
            // subscription/user-link migration (version 7) while retaining
            // metadata.schema_version = 6. Go treats `migrate` as the source
            // of applied migrations and opens this shape successfully. Keep
            // the compatibility exception narrow: only the known v7 tables
            // may make a 6 -> 7 mismatch valid; arbitrary mismatches still
            // fail closed below.
            let known_additive_v7 = metadata_version == 6
                && migration_version == 7
                && (table_exists(connection, "subscription_nodes_v2")
                    || table_exists(connection, "subscription_users_v2"));
            if known_additive_v7 {
                return Ok(migration_version);
            }
            return Err(Error::new(
                ErrorKind::Storage,
                format!(
                    "Go metadata schema_version {metadata_version} does not match migrate version {migration_version}"
                ),
            ));
        }
        return Ok(metadata_version);
    }
    Ok(migration_version)
}

fn validate_go_schema_version(version: i64) -> Result<i64> {
    if version > MAX_SUPPORTED_GO_SCHEMA_VERSION {
        return Err(Error::new(
            ErrorKind::Storage,
            format!(
                "unsupported Go schema version {version}; maximum supported version is {MAX_SUPPORTED_GO_SCHEMA_VERSION}"
            ),
        ));
    }
    Ok(version)
}

pub fn meta_flag(connection: &Connection, key: &str) -> bool {
    connection
        .query_with_params(
            "SELECT value FROM doradus_meta WHERE key = ?1",
            &[SqliteValue::from(key)],
        )
        .ok()
        .and_then(|rows| rows.first().cloned())
        .and_then(|row| row.get(0).cloned())
        .is_some_and(|value| matches!(value, SqliteValue::Integer(value) if value != 0))
}
