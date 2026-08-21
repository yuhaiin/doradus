use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::DEFAULT_MTU;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Deserialize;
use smoltcp::wire::{IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use yuhaiin_core::dns_resolver::AsyncIpResolver;
use yuhaiin_core::{DomainName, Endpoint, Error, ErrorKind, Network, ResolveStrategy, Result};

/// Go-compatible WireGuard node configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardConfig {
    pub secret_key: String,
    #[serde(default)]
    pub endpoint: Vec<String>,
    #[serde(default)]
    pub peers: Vec<WireGuardPeerConfig>,
    #[serde(default)]
    pub mtu: i32,
    #[serde(
        default,
        deserialize_with = "deserialize_reserved",
        serialize_with = "serialize_reserved"
    )]
    pub reserved: Vec<u8>,
}

/// One peer in a WireGuard node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardPeerConfig {
    pub public_key: String,
    #[serde(default)]
    pub pre_shared_key: String,
    pub endpoint: String,
    #[serde(default)]
    pub keep_alive: i32,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
}

fn deserialize_reserved<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Null => Ok(Vec::new()),
        serde_json::Value::String(value) => {
            STANDARD.decode(value).map_err(serde::de::Error::custom)
        }
        serde_json::Value::Array(values) => values
            .into_iter()
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|value| u8::try_from(value).ok())
                    .ok_or_else(|| {
                        serde::de::Error::custom("WireGuard reserved array must contain bytes")
                    })
            })
            .collect(),
        _ => Err(serde::de::Error::custom(
            "WireGuard reserved must be base64 or byte array",
        )),
    }
}

fn serialize_reserved<S>(value: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&STANDARD.encode(value))
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedPeer {
    pub(crate) endpoint: SocketAddr,
    pub(crate) allowed_ips: Vec<IpCidr>,
    pub(crate) public_key: [u8; 32],
    pub(crate) pre_shared_key: Option<[u8; 32]>,
    pub(crate) keep_alive: Option<u16>,
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedConfig {
    pub(crate) local_addresses: Vec<IpCidr>,
    pub(crate) peers: Vec<ParsedPeer>,
    pub(crate) mtu: usize,
    pub(crate) reserved: Vec<u8>,
}

impl WireGuardConfig {
    /// Parse either the Go JSON contract or a standard `wg-quick`/WARP
    /// profile.  The runtime still receives the typed Go contract, while this
    /// entry point makes the external validation path useful with the files
    /// Cloudflare and WireGuard tooling actually export.
    pub fn from_json_or_ini(input: &[u8]) -> Result<Self> {
        let input = std::str::from_utf8(input)
            .map_err(|error| Error::invalid(format!("WireGuard config is not UTF-8: {error}")))?;
        if input.trim_start().starts_with('{') {
            return serde_json::from_str(input).map_err(|error| {
                Error::invalid(format!("invalid WireGuard JSON configuration: {error}"))
            });
        }
        Self::from_wireguard_ini(input)
    }

    /// Parse a standard `[Interface]`/`[Peer]` WireGuard profile.
    ///
    /// Unknown keys are ignored intentionally: WARP profiles commonly carry
    /// `DNS`, `Table`, and `SaveConfig` fields that are meaningful to
    /// `wg-quick` but not to a userspace outbound proxy.
    pub fn from_wireguard_ini(input: &str) -> Result<Self> {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Section {
            None,
            Interface,
            Peer,
            Other,
        }

        let mut section = Section::None;
        let mut secret_key = None;
        let mut endpoint = Vec::new();
        let mut mtu = 0;
        let mut reserved = Vec::new();
        let mut peers = Vec::new();
        let mut current_peer: Option<WireGuardPeerConfig> = None;

        let push_peer = |current_peer: &mut Option<WireGuardPeerConfig>, peers: &mut Vec<_>| {
            if let Some(peer) = current_peer.take() {
                peers.push(peer);
            }
        };

        for (line_number, raw_line) in input.lines().enumerate() {
            let line = raw_line
                .split('#')
                .next()
                .unwrap_or(raw_line)
                .split(';')
                .next()
                .unwrap_or(raw_line)
                .trim();
            if line.is_empty() {
                continue;
            }
            if let Some(header) = line
                .strip_prefix('[')
                .and_then(|line| line.strip_suffix(']'))
            {
                let header = header.trim().to_ascii_lowercase();
                push_peer(&mut current_peer, &mut peers);
                section = match header.as_str() {
                    "interface" => Section::Interface,
                    "peer" => {
                        current_peer = Some(WireGuardPeerConfig {
                            public_key: String::new(),
                            pre_shared_key: String::new(),
                            endpoint: String::new(),
                            keep_alive: 0,
                            allowed_ips: Vec::new(),
                        });
                        Section::Peer
                    }
                    _ => Section::Other,
                };
                continue;
            }

            let (key, value) = line.split_once('=').ok_or_else(|| {
                Error::invalid(format!(
                    "WireGuard config line {} is missing '='",
                    line_number + 1
                ))
            })?;
            let key = key.trim().to_ascii_lowercase().replace('_', "");
            let value = value.trim();
            match section {
                Section::Interface => match key.as_str() {
                    "privatekey" => secret_key = Some(value.to_owned()),
                    "address" => endpoint.extend(split_ini_list(value)),
                    "mtu" => {
                        mtu = value.parse::<i32>().map_err(|error| {
                            Error::invalid(format!("invalid WireGuard MTU: {error}"))
                        })?;
                    }
                    "reserved" => reserved = parse_ini_reserved(value)?,
                    _ => {}
                },
                Section::Peer => {
                    let peer = current_peer.as_mut().ok_or_else(|| {
                        Error::invalid(format!(
                            "WireGuard config line {} is outside a peer",
                            line_number + 1
                        ))
                    })?;
                    match key.as_str() {
                        "publickey" => peer.public_key = value.to_owned(),
                        "presharedkey" => peer.pre_shared_key = value.to_owned(),
                        "endpoint" => peer.endpoint = value.to_owned(),
                        "persistentkeepalive" => {
                            peer.keep_alive = if value.eq_ignore_ascii_case("off") {
                                0
                            } else {
                                value.parse::<i32>().map_err(|error| {
                                    Error::invalid(format!(
                                        "invalid WireGuard persistent keepalive: {error}"
                                    ))
                                })?
                            };
                        }
                        "allowedips" => peer.allowed_ips = split_ini_list(value),
                        _ => {}
                    }
                }
                Section::None | Section::Other => {}
            }
        }
        push_peer(&mut current_peer, &mut peers);

        let secret_key = secret_key
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::invalid("WireGuard [Interface] is missing PrivateKey"))?;
        if endpoint.is_empty() {
            return Err(Error::invalid("WireGuard [Interface] is missing Address"));
        }
        if peers.is_empty() {
            return Err(Error::invalid("WireGuard config is missing [Peer]"));
        }
        for (index, peer) in peers.iter().enumerate() {
            if peer.public_key.is_empty() || peer.endpoint.is_empty() || peer.allowed_ips.is_empty()
            {
                return Err(Error::invalid(format!(
                    "WireGuard [Peer] {index} is missing PublicKey, Endpoint, or AllowedIPs"
                )));
            }
        }
        Ok(Self {
            secret_key,
            endpoint,
            peers,
            mtu,
            reserved,
        })
    }

    pub(crate) fn parse(&self, peers: Vec<ParsedPeer>) -> Result<ParsedConfig> {
        let local_addresses = self
            .endpoint
            .iter()
            .map(|value| parse_cidr_or_host(value))
            .collect::<Result<Vec<_>>>()?;
        if local_addresses.is_empty() {
            return Err(Error::invalid(
                "WireGuard endpoint must contain a local IP address",
            ));
        }
        if peers.is_empty() {
            return Err(Error::invalid("WireGuard requires at least one peer"));
        }
        if !self.reserved.is_empty() && self.reserved.len() != 3 {
            return Err(Error::invalid(
                "WireGuard reserved must contain exactly three bytes",
            ));
        }
        let mtu = if self.mtu == 0 {
            DEFAULT_MTU
        } else {
            usize::try_from(self.mtu).map_err(|_| Error::invalid("WireGuard MTU is invalid"))?
        };
        if !(576..=9216).contains(&mtu) {
            return Err(Error::invalid("WireGuard MTU must be in 576..=9216"));
        }
        Ok(ParsedConfig {
            local_addresses,
            peers,
            mtu,
            reserved: self.reserved.clone(),
        })
    }
}

fn split_ini_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_ini_reserved(value: &str) -> Result<Vec<u8>> {
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    if value.contains(',') {
        return value
            .split(',')
            .map(str::trim)
            .map(|value| {
                value.parse::<u8>().map_err(|error| {
                    Error::invalid(format!("invalid WireGuard reserved byte: {error}"))
                })
            })
            .collect();
    }
    STANDARD
        .decode(value.trim())
        .map_err(|error| Error::invalid(format!("invalid WireGuard reserved value: {error}")))
}

impl WireGuardPeerConfig {
    pub(crate) async fn parse(
        &self,
        timeout: Duration,
        resolver: Option<&dyn AsyncIpResolver>,
    ) -> Result<ParsedPeer> {
        let endpoint = resolve_endpoint(&self.endpoint, timeout, resolver).await?;
        let allowed_ips = self
            .allowed_ips
            .iter()
            .map(|value| parse_cidr(value))
            .collect::<Result<Vec<_>>>()?;
        if allowed_ips.is_empty() {
            return Err(Error::invalid(
                "WireGuard peer allowedIps must not be empty",
            ));
        }
        let public_key = decode_key(&self.public_key, "publicKey")?;
        let pre_shared_key = if self.pre_shared_key.trim().is_empty() {
            None
        } else {
            Some(decode_key(&self.pre_shared_key, "preSharedKey")?)
        };
        let keep_alive = if self.keep_alive == 0 {
            None
        } else {
            Some(
                u16::try_from(self.keep_alive)
                    .map_err(|_| Error::invalid("WireGuard keepAlive must be in 1..=65535"))?,
            )
        };
        Ok(ParsedPeer {
            endpoint,
            allowed_ips,
            public_key,
            pre_shared_key,
            keep_alive,
        })
    }
}

pub(crate) fn decode_key(value: &str, name: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD
        .decode(value.trim())
        .or_else(|_| URL_SAFE_NO_PAD.decode(value.trim()))
        .map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("WireGuard {name} is not base64: {error}"),
            )
        })?;
    bytes
        .try_into()
        .map_err(|_| Error::invalid(format!("WireGuard {name} must decode to 32 bytes")))
}

pub(crate) fn parse_cidr(value: &str) -> Result<IpCidr> {
    let (address, prefix) = value
        .trim()
        .split_once('/')
        .ok_or_else(|| Error::invalid(format!("WireGuard CIDR is missing prefix: {value}")))?;
    let address = address.parse::<IpAddr>().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("invalid WireGuard IP {address}: {error}"),
        )
    })?;
    let prefix = prefix.parse::<u8>().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("invalid WireGuard prefix {prefix}: {error}"),
        )
    })?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err(Error::invalid(format!(
            "WireGuard prefix {prefix} exceeds {max}"
        )));
    }
    Ok(IpCidr::new(IpAddress::from(address), prefix))
}

pub(crate) fn parse_cidr_or_host(value: &str) -> Result<IpCidr> {
    if value.contains('/') {
        return parse_cidr(value);
    }
    let address = value.trim().parse::<IpAddr>().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("invalid WireGuard local IP {value}: {error}"),
        )
    })?;
    Ok(IpCidr::new(
        IpAddress::from(address),
        if address.is_ipv4() { 32 } else { 128 },
    ))
}

pub(crate) async fn resolve_endpoint(
    value: &str,
    timeout: Duration,
    resolver: Option<&dyn AsyncIpResolver>,
) -> Result<SocketAddr> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }
    let (host, port) = split_host_port(value)?;
    if let Some(resolver) = resolver {
        let domain = DomainName::new(&host)?;
        let addresses =
            tokio::time::timeout(timeout, resolver.resolve(&domain, ResolveStrategy::Default))
                .await
                .map_err(|_| {
                    Error::new(
                        ErrorKind::Timeout,
                        format!("resolve WireGuard endpoint {value} timed out"),
                    )
                })??;
        let address = addresses
            .v4
            .first()
            .copied()
            .map(IpAddr::V4)
            .or_else(|| addresses.v6.first().copied().map(IpAddr::V6))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Io,
                    format!("WireGuard endpoint {value} resolved to no address"),
                )
            })?;
        return Ok(SocketAddr::new(address, port));
    }
    let mut addresses =
        tokio::time::timeout(timeout, tokio::net::lookup_host((host.as_str(), port)))
            .await
            .map_err(|_| {
                Error::new(
                    ErrorKind::Timeout,
                    format!("resolve WireGuard endpoint {value} timed out"),
                )
            })?
            .map_err(|error| {
                Error::new(
                    ErrorKind::Io,
                    format!("resolve WireGuard endpoint {value}: {error}"),
                )
            })?;
    addresses.next().ok_or_else(|| {
        Error::new(
            ErrorKind::Io,
            format!("WireGuard endpoint {value} resolved to no address"),
        )
    })
}

pub(crate) fn split_host_port(value: &str) -> Result<(String, u16)> {
    if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").ok_or_else(|| {
            Error::invalid(format!("WireGuard endpoint is missing port: {value}"))
        })?;
        return Ok((
            host.to_owned(),
            port.parse()
                .map_err(|_| Error::invalid("WireGuard endpoint port is invalid"))?,
        ));
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| Error::invalid(format!("WireGuard endpoint is missing port: {value}")))?;
    Ok((
        host.to_owned(),
        port.parse()
            .map_err(|_| Error::invalid("WireGuard endpoint port is invalid"))?,
    ))
}

pub(crate) fn ip_endpoint(address: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(IpAddress::from(address.ip()), address.port())
}

pub(crate) fn listen_endpoint(port: u16) -> IpListenEndpoint {
    IpListenEndpoint { addr: None, port }
}

pub(crate) fn core_endpoint(network: Network, address: SocketAddr) -> Endpoint {
    Endpoint::ip(network, address)
}

pub(crate) fn error_io(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

pub(crate) fn error_protocol(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Protocol, error.to_string())
}

pub(crate) fn error_protocol_debug(error: impl std::fmt::Debug) -> Error {
    Error::new(ErrorKind::Protocol, format!("{error:?}"))
}

pub(crate) fn error_unsupported(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Unsupported, message.into())
}
