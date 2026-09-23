//! Runtime proxy adapters grouped by the boundary they own.

use super::*;

#[path = "proxy_adapters/network_split.rs"]
mod network_split;
#[path = "proxy_adapters/node_set.rs"]
mod node_set;
#[path = "proxy_adapters/resolving.rs"]
mod resolving;
#[path = "proxy_adapters/tracking.rs"]
mod tracking;

pub use network_split::*;
pub use node_set::*;
pub use resolving::*;
pub use tracking::*;
