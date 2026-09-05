//! Application-neutral runtime facade.
//!
//! Implementation code is grouped by responsibility in sibling directories;
//! this file keeps the crate's existing public API and feature gates stable.

use doradus_core::Result;

mod control;
mod maintenance;
mod plane;
mod policy;
mod support;

// Preserve the crate's existing internal module names while the physical
// layout follows the responsibility-based directory tree.
pub use control::monitor;
pub(crate) use control::{controller, handle, inbound_runtime};
pub use maintenance::log;
#[cfg(feature = "update")]
pub use maintenance::update;
pub use plane::inbounds as inbound;
pub(crate) use plane::{data_plane, outbound as proxy};
#[cfg(feature = "doh-tls")]
pub(crate) use policy::resolver_registry;
pub(crate) use policy::{defaults, resolver, route, settings};
#[cfg(feature = "doh-tls")]
pub(crate) use support::tls;
pub use support::{interfaces, latency};
pub(crate) use support::{loopback, monitoring};

mod assembly;

pub use assembly::*;
