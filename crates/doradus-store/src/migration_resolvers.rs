//! Legacy resolver-table upgrade.

use super::*;

pub fn upgrade_go_v1_resolvers(connection: &Connection) -> Result<()> {
    require_go_table(
        connection,
        "go_legacy_dns_resolvers",
        &[
            "name",
            "resolver_type",
            "host",
            "subnet",
            "tls_servername",
            "data_json",
        ],
    )?;
    if table_row_count(connection, "resolvers_v2")? != 0 {
        return Ok(());
    }
    let rows = connection
        .query(
            "SELECT name, resolver_type, host, subnet, tls_servername, data_json
             FROM go_legacy_dns_resolvers ORDER BY name",
        )
        .map_err(storage_error)?;
    for row in rows {
        let id = row_text(&row, 0, "go_legacy_dns_resolvers.name")?;
        validate_id(&id)?;
        let resolver_type = legacy_resolver_type(row_integer(
            &row,
            1,
            "go_legacy_dns_resolvers.resolver_type",
        )?)?;
        let mut object = legacy_json_object(
            &row_blob_or_text(&row, 5, "go_legacy_dns_resolvers.data_json")?,
            "go_legacy_dns_resolvers.data_json",
        )?;
        let host = row_text(&row, 2, "go_legacy_dns_resolvers.host")?;
        let subnet = row_text(&row, 3, "go_legacy_dns_resolvers.subnet")?;
        let tls_servername = row_text(&row, 4, "go_legacy_dns_resolvers.tls_servername")?;
        let system = id == "bootstrap" && host.is_empty();
        let host = if system {
            "system default".to_owned()
        } else {
            host
        };
        object.insert("id".to_owned(), serde_json::Value::String(id.clone()));
        object.insert(
            "type".to_owned(),
            serde_json::Value::String(if system {
                "system".to_owned()
            } else {
                resolver_type.to_owned()
            }),
        );
        object.insert("host".to_owned(), serde_json::Value::String(host.clone()));
        object.insert("subnet".to_owned(), serde_json::Value::String(subnet));
        object.insert(
            "tlsServerName".to_owned(),
            serde_json::Value::String(tls_servername),
        );
        if system {
            object.insert("system".to_owned(), serde_json::Value::Bool(true));
        }
        let data_json = json_object_bytes(object, "legacy resolver")?;
        connection
            .execute_with_params(
                "INSERT INTO resolvers_v2
                 (id, resolver_type, host, updated_at, data_json)
                 VALUES (?1, ?2, ?3, 0, ?4)",
                &[
                    SqliteValue::from(id),
                    SqliteValue::from(if system { "system" } else { resolver_type }),
                    SqliteValue::from(host),
                    SqliteValue::from(data_json),
                ],
            )
            .map_err(storage_error)?;
    }
    Ok(())
}

fn legacy_resolver_type(value: i64) -> Result<&'static str> {
    Ok(match value {
        2 => "tcp",
        3 => "doh",
        4 => "dot",
        5 => "doq",
        6 => "doh3",
        // Go's legacy converter intentionally maps reserve and unknown enum
        // values to UDP.  Keep that compatibility behavior explicit.
        _ => "udp",
    })
}
