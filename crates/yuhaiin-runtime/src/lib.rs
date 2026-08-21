//! Application-neutral runtime facade.
//!
//! Implementation code is grouped by responsibility in sibling directories;
//! this file keeps the crate's existing public API and feature gates stable.

use yuhaiin_core::Result;

// Control plane: snapshot publication, reload coordination and persistence.
#[path = "control/controller.rs"]
mod controller;
#[path = "control/handle.rs"]
mod handle;
#[path = "control/monitor.rs"]
pub mod monitor;

// Data plane: inbound ownership, DNS/TUN execution and outbound proxy flows.
#[path = "plane/data_plane.rs"]
mod data_plane;
#[path = "plane/inbounds/mod.rs"]
pub mod inbound;
#[path = "plane/outbound.rs"]
mod proxy;

// Policy/runtime assembly inputs: defaults, resolvers, routes and settings.
#[path = "policy/defaults.rs"]
mod defaults;
#[path = "policy/resolver.rs"]
mod resolver;
#[cfg(feature = "doh-tls")]
#[path = "policy/resolver_registry.rs"]
mod resolver_registry;
#[path = "policy/route.rs"]
mod route;
#[path = "policy/settings.rs"]
mod settings;

// Runtime support shared by the control and data planes.
#[path = "support/interfaces.rs"]
pub mod interfaces;
#[path = "support/latency.rs"]
pub mod latency;
#[path = "support/loopback.rs"]
mod loopback;
#[cfg(feature = "doh-tls")]
#[path = "support/tls.rs"]
mod tls;

// Optional management-side maintenance features.
#[path = "maintenance/log.rs"]
pub mod log;
#[cfg(feature = "update")]
#[path = "maintenance/update.rs"]
pub mod update;

mod assembly;

pub use assembly::*;
