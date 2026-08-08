//! MaxMindDB-backed geographic lookup with an application-owned error boundary.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use maxminddb::geoip2;

use crate::{Error, ErrorKind, Result};

/// Read-only geographic lookup boundary used by routing.
///
/// The trait deliberately returns an owned country code so an implementation
/// can keep its backing database behind an `Arc` and replace the whole reader
/// atomically at a higher layer without exposing MaxMindDB lifetimes to the
/// router crate.
pub trait GeoLookup: Send + Sync {
    fn country_code(&self, address: IpAddr) -> Result<Option<String>>;
}

#[derive(Clone)]
pub struct GeoDb {
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
}
impl GeoDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let bytes = std::fs::read(path)
            .map_err(|error| Error::new(ErrorKind::Io, format!("read MaxMindDB: {error}")))?;
        Self::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let reader = maxminddb::Reader::from_source(bytes)
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
        Ok(Self {
            reader: Arc::new(reader),
        })
    }

    pub fn country_code(&self, address: IpAddr) -> Result<Option<String>> {
        let address = match address {
            IpAddr::V6(address) => address
                .to_ipv4()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(address)),
            address => address,
        };
        let result = self
            .reader
            .lookup(address)
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
        if !result.has_data() {
            return Ok(None);
        }
        let Some(record): Option<geoip2::Country<'_>> = result
            .decode()
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?
        else {
            return Ok(None);
        };
        Ok(record.country.iso_code.map(str::to_owned))
    }
}

impl GeoLookup for GeoDb {
    fn country_code(&self, address: IpAddr) -> Result<Option<String>> {
        Self::country_code(self, address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_database_is_rejected() {
        assert!(GeoDb::from_bytes(vec![0, 1, 2, 3]).is_err());
    }
}
