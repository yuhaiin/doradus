use std::net::{IpAddr, SocketAddr};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use smoltcp::wire::{IpCidr, Ipv4Cidr, Ipv6Cidr};
use yuhaiin_core::{Error, Result};

/// The configuration written by usque-rs and the Cloudflare WARP tooling.
///
/// The account metadata fields are retained for import compatibility.  The
/// initial tunnel implementation intentionally uses only the private key,
/// endpoint pin, endpoint addresses, and assigned tunnel addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarpMasqueConfig {
    pub private_key: String,
    pub endpoint_v4: String,
    pub endpoint_v6: String,
    pub endpoint_pub_key: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub access_token: String,
    pub ipv4: String,
    pub ipv6: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedWarpMasqueConfig {
    pub(crate) private_key: Vec<u8>,
    pub(crate) endpoint_v4: Option<SocketAddr>,
    pub(crate) endpoint_v6: Option<SocketAddr>,
    pub(crate) endpoint_pub_key: Vec<u8>,
    pub(crate) local_addresses: Vec<IpCidr>,
}

impl WarpMasqueConfig {
    pub fn from_json(input: &[u8]) -> Result<Self> {
        serde_json::from_slice(input)
            .map_err(|error| Error::invalid(format!("invalid WARP MASQUE configuration: {error}")))
    }

    pub(crate) fn parse(&self) -> Result<ParsedWarpMasqueConfig> {
        let private_key = STANDARD.decode(self.private_key.trim()).map_err(|error| {
            Error::invalid(format!("WARP MASQUE private_key is not base64: {error}"))
        })?;
        if private_key.is_empty() {
            return Err(Error::invalid("WARP MASQUE private_key is empty"));
        }

        let endpoint_pub_key = pem::parse(self.endpoint_pub_key.trim())
            .map_err(|error| {
                Error::invalid(format!("invalid WARP MASQUE endpoint_pub_key: {error}"))
            })?
            .into_contents();
        if endpoint_pub_key.is_empty() {
            return Err(Error::invalid("WARP MASQUE endpoint_pub_key is empty"));
        }

        let endpoint_v4 = parse_endpoint(&self.endpoint_v4, false)?;
        let endpoint_v6 = parse_endpoint(&self.endpoint_v6, true)?;
        if endpoint_v4.is_none() && endpoint_v6.is_none() {
            return Err(Error::invalid(
                "WARP MASQUE requires endpoint_v4 or endpoint_v6",
            ));
        }

        let mut local_addresses = Vec::with_capacity(2);
        if let Some(address) = parse_optional_ip(&self.ipv4, "ipv4")? {
            match address {
                IpAddr::V4(address) => {
                    local_addresses.push(IpCidr::Ipv4(Ipv4Cidr::new(address, 32)))
                }
                IpAddr::V6(_) => return Err(Error::invalid("WARP MASQUE ipv4 is IPv6")),
            }
        }
        if let Some(address) = parse_optional_ip(&self.ipv6, "ipv6")? {
            match address {
                IpAddr::V4(_) => return Err(Error::invalid("WARP MASQUE ipv6 is IPv4")),
                IpAddr::V6(address) => {
                    local_addresses.push(IpCidr::Ipv6(Ipv6Cidr::new(address, 128)))
                }
            }
        }
        if local_addresses.is_empty() {
            return Err(Error::invalid(
                "WARP MASQUE requires an ipv4 or ipv6 tunnel address",
            ));
        }

        Ok(ParsedWarpMasqueConfig {
            private_key,
            endpoint_v4,
            endpoint_v6,
            endpoint_pub_key,
            local_addresses,
        })
    }
}

fn parse_endpoint(value: &str, ipv6: bool) -> Result<Option<SocketAddr>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let address: IpAddr = value
        .parse()
        .map_err(|error| Error::invalid(format!("invalid WARP MASQUE endpoint: {error}")))?;
    if address.is_ipv6() != ipv6 {
        return Err(Error::invalid(format!(
            "WARP MASQUE endpoint has the wrong address family: {value}"
        )));
    }
    Ok(Some(SocketAddr::new(address, 443)))
}

fn parse_optional_ip(value: &str, name: &str) -> Result<Option<IpAddr>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse()
        .map(Some)
        .map_err(|error| Error::invalid(format!("invalid WARP MASQUE {name}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINT_KEY: &str = "-----BEGIN PUBLIC KEY-----\nAQ==\n-----END PUBLIC KEY-----";

    #[test]
    fn parses_usque_field_names_and_assignments() {
        let config = WarpMasqueConfig {
            private_key: STANDARD.encode([7u8; 32]),
            endpoint_v4: "162.159.192.1".to_owned(),
            endpoint_v6: "".to_owned(),
            endpoint_pub_key: ENDPOINT_KEY.to_owned(),
            license: "license".to_owned(),
            id: "id".to_owned(),
            access_token: "token".to_owned(),
            ipv4: "172.16.0.2".to_owned(),
            ipv6: "2606:4700:110:8765::2".to_owned(),
        };
        let parsed = config.parse().unwrap();
        assert_eq!(parsed.endpoint_v4.unwrap().port(), 443);
        assert_eq!(parsed.local_addresses.len(), 2);
        assert_eq!(parsed.private_key, [7u8; 32]);
    }
}
