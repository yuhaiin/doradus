//! Management HTTP API and native service host for doradus.
//!
//! The data plane lives in [`doradus_runtime`]. This crate owns the
//! application boundary: the Go-compatible HTTP contract, the service
//! lifecycle that starts the runtime supervisors, and the desktop executable.

pub mod api;
mod backup_transport;
pub mod service;

pub use api::{ApiAuth, ApiState, router, serve, serve_until};
pub use service::{RuntimeService, ServiceOptions};
