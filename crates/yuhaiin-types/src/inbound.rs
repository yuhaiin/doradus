//! Inbound capability contracts independent of listener implementations.

use crate::{BoxFuture, Result};

/// Shared DNS interception policy for socket and packet inbounds.
pub trait InboundDnsHandler: Send + Sync {
    fn should_hijack(&self, destination_port: Option<u16>, packet: &[u8]) -> bool;

    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Option<Result<Vec<u8>>>>;
}
