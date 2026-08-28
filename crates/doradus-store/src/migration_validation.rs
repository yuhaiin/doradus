//! Shared validation for Go compatibility tables.

use super::*;

pub fn table_exists(connection: &Connection, table: &str) -> bool {
    connection
        .query_with_params(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            &[SqliteValue::from(table)],
        )
        .map(|rows| !rows.is_empty())
        .unwrap_or(false)
}

pub fn require_go_table(connection: &Connection, table: &str, columns: &[&str]) -> Result<()> {
    if !table_exists(connection, table) {
        return Err(Error::new(
            ErrorKind::Storage,
            format!("Go compatibility table {table} does not exist"),
        ));
    }
    for column in columns {
        if !table_has_column(connection, table, column)? {
            return Err(Error::new(
                ErrorKind::Storage,
                format!("Go compatibility table {table} is missing column {column}"),
            ));
        }
    }
    Ok(())
}

pub fn validate_go_texts(values: &[(&str, &String)]) -> Result<()> {
    for (field, value) in values {
        validate_id(value).map_err(|error| {
            Error::new(
                error.kind,
                format!("invalid Go compatibility {field}: {}", error.message),
            )
        })?;
    }
    Ok(())
}

pub fn validate_go_compat_text(value: &str, field: &str) -> Result<()> {
    if value.len() > 512 || value.chars().any(char::is_control) {
        return Err(Error::new(
            ErrorKind::Storage,
            format!("invalid Go compatibility {field}"),
        ));
    }
    Ok(())
}

pub fn validate_go_timestamp(value: i64) -> Result<()> {
    if value < 0 {
        return Err(Error::invalid(
            "Go compatibility updated_at must not be negative",
        ));
    }
    Ok(())
}
