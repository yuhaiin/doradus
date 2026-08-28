//! Typed and Go compatibility repositories.

use super::*;
use doradus_core::dns_hosts::HostsTable;

fn validate_route_resolver_name(value: &str, field: &str) -> Result<()> {
    if value.len() > 512 || value.chars().any(char::is_control) {
        return Err(Error::invalid(format!(
            "route settings {field} must be at most 512 non-control bytes"
        )));
    }
    Ok(())
}

#[path = "repository_go.rs"]
mod repository_go;
#[path = "repository_typed.rs"]
mod repository_typed;
