use super::*;

#[path = "projection_common.rs"]
mod common;
#[path = "projection_query.rs"]
mod query;
#[path = "projection_resources.rs"]
mod resources;
#[path = "projection_routes.rs"]
mod routes;
#[path = "projection_settings.rs"]
mod settings;

pub(crate) use common::*;
pub(crate) use query::*;
pub(crate) use resources::*;
pub(crate) use routes::*;
pub(crate) use settings::*;
