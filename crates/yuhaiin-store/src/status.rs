use crate::sqlite::Connection;
use crate::{Error, ErrorKind, Result, row_integer, row_text};

/// Operational state shared by storage, reload and a future HTTP management
/// endpoint. It describes the actual SQLite connection without introducing a
/// second configuration DTO tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageStatus {
    pub schema_version: i64,
    pub go_schema_version: Option<i64>,
    pub go_schema_imported: bool,
    pub journal_mode: String,
    pub page_count: i64,
    pub freelist_pages: i64,
    pub quick_check: String,
    pub full_cone_nat: bool,
}

pub(crate) fn read(connection: &Connection) -> Result<StorageStatus> {
    let page_count = pragma_integer(connection, "page_count")?;
    let schema_version = metadata_integer(connection, "schema_version")?.ok_or_else(|| {
        Error::new(
            ErrorKind::Storage,
            "storage status is missing schema_version",
        )
    })?;
    let go_schema_version = metadata_integer(connection, "go_schema_version")?;
    let go_schema_imported = metadata_integer(connection, "go_schema_imported")?
        .map(|value| value != 0)
        .unwrap_or(false);
    let journal_mode = pragma_text(connection, "journal_mode")?;
    let freelist_pages = pragma_integer(connection, "freelist_count")?;
    let quick_check = pragma_text(connection, "quick_check")?;
    let full_cone_nat = match connection
        .query("SELECT COALESCE(MIN(full_cone), 1) FROM nat_config")
        .map_err(crate::storage_error)?
        .first()
    {
        Some(row) => row_integer(row, 0, "nat_config.full_cone")? == 1,
        None => true,
    };
    Ok(StorageStatus {
        schema_version,
        go_schema_version,
        go_schema_imported,
        journal_mode,
        page_count,
        freelist_pages,
        quick_check,
        full_cone_nat,
    })
}

fn metadata_integer(connection: &Connection, key: &str) -> Result<Option<i64>> {
    let rows = connection
        .query_with_params(
            "SELECT value FROM yuhaiin_meta WHERE key = ?1",
            &[key.into()],
        )
        .map_err(crate::storage_error)?;
    rows.first()
        .map(|row| row_integer(row, 0, "yuhaiin_meta.value"))
        .transpose()
}

fn pragma_integer(connection: &Connection, name: &str) -> Result<i64> {
    let row = connection
        .query(&format!("PRAGMA {name}"))
        .map_err(crate::storage_error)?
        .into_iter()
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Storage, format!("PRAGMA {name} returned no row")))?;
    row_integer(&row, 0, name)
}

fn pragma_text(connection: &Connection, name: &str) -> Result<String> {
    let row = connection
        .query(&format!("PRAGMA {name}"))
        .map_err(crate::storage_error)?
        .into_iter()
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Storage, format!("PRAGMA {name} returned no row")))?;
    row_text(&row, 0, name)
}
