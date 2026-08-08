//! Conversion from persisted Go compatibility settings to runtime-owned types.

use std::net::{Ipv4Addr, Ipv6Addr};

use yuhaiin_core::{Error, ErrorKind, Result};

use crate::fakeip::{FakeIpConfig, FakeIpV6Config};
use crate::{GoDnsSettingsRecord, GoResolverRecord, GoRouteSettingsRecord};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoFakeIpRuntimeConfig {
    pub enabled: bool,
    pub ipv4: FakeIpConfig,
    pub ipv6: FakeIpV6Config,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoUdpProxyFqdnStrategy {
    Default,
    Resolve,
    SkipResolve,
}

impl GoUdpProxyFqdnStrategy {
    /// Match Go's forward-compatible parser: unknown enum values use the
    /// default behavior instead of making an otherwise readable snapshot
    /// unusable.
    pub fn from_code(value: i64) -> Self {
        match value {
            1 => Self::Resolve,
            2 => Self::SkipResolve,
            _ => Self::Default,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoRouteRuntimeConfig {
    pub direct_resolver: String,
    pub proxy_resolver: String,
    pub resolve_locally: bool,
    pub udp_proxy_fqdn: GoUdpProxyFqdnStrategy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoResolverTransport {
    Udp,
    Tcp,
    Doh,
    Dot,
    Doq,
    Doh3,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoResolverRuntimeConfig {
    pub id: String,
    pub transport: GoResolverTransport,
    pub host: String,
    pub subnet: Option<String>,
    pub tls_server_name: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct GoResolverContract {
    #[serde(rename = "type")]
    resolver_type: Option<String>,
    host: Option<String>,
    subnet: Option<String>,
    #[serde(rename = "tlsServerName")]
    tls_server_name: Option<String>,
    #[serde(default)]
    system: bool,
}

impl GoDnsSettingsRecord {
    pub fn to_fakeip_runtime_config(&self) -> Result<GoFakeIpRuntimeConfig> {
        Ok(GoFakeIpRuntimeConfig {
            enabled: self.fakedns_enabled,
            ipv4: parse_ipv4_cidr(&self.fakedns_ipv4_range, "dns_settings.fakedns_ipv4_range")?,
            ipv6: parse_ipv6_cidr(&self.fakedns_ipv6_range, "dns_settings.fakedns_ipv6_range")?,
        })
    }
}

impl GoRouteSettingsRecord {
    pub fn to_runtime_config(&self) -> GoRouteRuntimeConfig {
        GoRouteRuntimeConfig {
            direct_resolver: self.direct_resolver.clone(),
            proxy_resolver: self.proxy_resolver.clone(),
            resolve_locally: self.resolve_locally,
            udp_proxy_fqdn: GoUdpProxyFqdnStrategy::from_code(self.udp_proxy_fqdn),
        }
    }
}

impl GoResolverRecord {
    pub fn to_runtime_config(&self) -> Result<GoResolverRuntimeConfig> {
        let contract: GoResolverContract =
            serde_json::from_slice(&self.data_json).map_err(|error| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("resolver {} has invalid data_json: {error}", self.id),
                )
            })?;
        let resolver_type = contract
            .resolver_type
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| self.resolver_type.clone());
        let transport = parse_resolver_transport(&resolver_type)?;
        let system = transport == GoResolverTransport::System || contract.system;
        let host = contract
            .host
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| self.host.clone());
        let host = if system && host.trim().is_empty() {
            "system default".to_owned()
        } else {
            host
        };
        if !system && host.trim().is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("resolver {} has an empty host", self.id),
            ));
        }
        Ok(GoResolverRuntimeConfig {
            id: self.id.clone(),
            transport,
            host,
            subnet: contract.subnet,
            tls_server_name: contract.tls_server_name,
        })
    }
}

fn parse_resolver_transport(value: &str) -> Result<GoResolverTransport> {
    match value.trim() {
        "udp" => Ok(GoResolverTransport::Udp),
        "tcp" => Ok(GoResolverTransport::Tcp),
        "doh" => Ok(GoResolverTransport::Doh),
        "dot" => Ok(GoResolverTransport::Dot),
        "doq" => Ok(GoResolverTransport::Doq),
        "doh3" => Ok(GoResolverTransport::Doh3),
        "system" => Ok(GoResolverTransport::System),
        value => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("unsupported resolver type {value:?}"),
        )),
    }
}

fn parse_ipv4_cidr(value: &str, field: &str) -> Result<FakeIpConfig> {
    let (address, prefix) = split_cidr(value, field)?;
    let address = address.parse::<Ipv4Addr>().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("{field} has invalid IPv4 address: {error}"),
        )
    })?;
    let prefix = parse_prefix(prefix, 32, field)?;
    let address = u32::from(address);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let start = address & mask;
    let end = start | !mask;
    FakeIpConfig::new(Ipv4Addr::from(start), Ipv4Addr::from(end))
}

fn parse_ipv6_cidr(value: &str, field: &str) -> Result<FakeIpV6Config> {
    let (address, prefix) = split_cidr(value, field)?;
    let address = address.parse::<Ipv6Addr>().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("{field} has invalid IPv6 address: {error}"),
        )
    })?;
    let prefix = parse_prefix(prefix, 128, field)?;
    let address = u128::from(address);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    let start = address & mask;
    let end = start | !mask;
    FakeIpV6Config::new(Ipv6Addr::from(start), Ipv6Addr::from(end))
}

fn split_cidr<'a>(value: &'a str, field: &str) -> Result<(&'a str, &'a str)> {
    value.trim().split_once('/').ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("{field} must be an address/prefix CIDR"),
        )
    })
}

fn parse_prefix(value: &str, max: u8, field: &str) -> Result<u8> {
    let prefix = value.parse::<u8>().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("{field} has invalid prefix: {error}"),
        )
    })?;
    if prefix > max {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("{field} prefix must be <= {max}"),
        ));
    }
    Ok(prefix)
}
