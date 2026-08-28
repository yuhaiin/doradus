//! Orchestration for the legacy Go v1 table upgrades.

use super::*;

pub fn upgrade_go_v1_legacy_tables(connection: &Connection, _source_version: i64) -> Result<()> {
    if table_exists(connection, "nodes") && !meta_flag(connection, "go_v1_nodes_upgraded") {
        upgrade_go_v1_nodes(connection)?;
        set_meta_flag(connection, "go_v1_nodes_upgraded")?;
    }
    if table_exists(connection, "inbounds") && !meta_flag(connection, "go_v1_inbounds_upgraded") {
        upgrade_go_v1_inbounds(connection)?;
        set_meta_flag(connection, "go_v1_inbounds_upgraded")?;
    }
    if table_exists(connection, "route_lists")
        && !meta_flag(connection, "go_v1_route_lists_upgraded")
    {
        upgrade_go_v1_route_lists(connection)?;
        set_meta_flag(connection, "go_v1_route_lists_upgraded")?;
    }
    if table_exists(connection, "node_tags") && !meta_flag(connection, "go_v1_node_tags_upgraded") {
        upgrade_go_v1_node_tags(connection)?;
        set_meta_flag(connection, "go_v1_node_tags_upgraded")?;
    }
    if table_exists(connection, "go_legacy_dns_resolvers")
        && !meta_flag(connection, "go_v1_resolvers_upgraded")
    {
        upgrade_go_v1_resolvers(connection)?;
        set_meta_flag(connection, "go_v1_resolvers_upgraded")?;
    }
    if table_exists(connection, "go_legacy_route_rules")
        && !meta_flag(connection, "go_v1_route_rules_upgraded")
    {
        upgrade_go_v1_route_rules(connection)?;
        set_meta_flag(connection, "go_v1_route_rules_upgraded")?;
    }
    Ok(())
}
