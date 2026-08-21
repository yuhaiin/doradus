//! Runtime adapters for inbound protocol servers.
//!
//! The protocol crate owns wire parsing and protocol loops. These adapters
//! connect accepted protocol streams to the shared runtime route, connect,
//! relay, monitor and listener-lifecycle services.

pub(crate) mod common;
pub(crate) mod http;
pub(crate) mod reverse;
#[cfg(target_os = "linux")]
pub(crate) mod transparent;
pub(crate) mod trojan;
pub(crate) mod vless;
pub(crate) mod yuubinsya;
