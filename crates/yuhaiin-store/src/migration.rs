//! Go schema import, legacy upgrades, and migration validation.

use super::*;

#[path = "migration_chain.rs"]
mod migration_chain;
#[path = "migration_import.rs"]
mod migration_import;
#[path = "migration_inbounds.rs"]
mod migration_inbounds;
#[path = "migration_nodes.rs"]
mod migration_nodes;
#[path = "migration_resolvers.rs"]
mod migration_resolvers;
#[path = "migration_route_rules.rs"]
mod migration_route_rules;
#[path = "migration_routes.rs"]
mod migration_routes;
#[path = "migration_v1.rs"]
mod migration_v1;
#[path = "migration_validation.rs"]
mod migration_validation;
#[path = "migration_version.rs"]
mod migration_version;

pub(super) use migration_chain::{
    canonical_protocol_name, legacy_protocol_contract, recover_legacy_node_chains,
};
pub(super) use migration_import::import_go_schema;
pub(super) use migration_inbounds::upgrade_go_v1_inbounds;
pub(super) use migration_nodes::upgrade_go_v1_nodes;
pub(super) use migration_resolvers::upgrade_go_v1_resolvers;
pub(super) use migration_route_rules::{
    json_object_bytes, json_string, legacy_json_object, upgrade_go_v1_route_rules,
};
pub(super) use migration_routes::{
    canonical_inbound_name, set_meta_flag, table_row_count, upgrade_go_v1_node_tags,
    upgrade_go_v1_route_lists,
};
pub(super) use migration_v1::upgrade_go_v1_legacy_tables;
pub(super) use migration_validation::{
    require_go_table, table_exists, validate_go_compat_text, validate_go_texts,
    validate_go_timestamp,
};
pub(super) use migration_version::{meta_flag, read_go_schema_version};
