//! Common geographic lookup contract.

use std::net::IpAddr;

use crate::Result;

/// Read-only geographic lookup boundary used by routing.
///
/// The trait deliberately returns an owned country code so an implementation
/// can keep its backing database behind an `Arc` and replace the whole reader
/// atomically at a higher layer without exposing MaxMindDB lifetimes to the
/// router crate.
pub trait GeoLookup: Send + Sync {
    fn country_code(&self, address: IpAddr) -> Result<Option<String>>;
}
