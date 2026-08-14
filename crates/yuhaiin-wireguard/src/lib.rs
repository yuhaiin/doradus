//! Cloudflare BoringTun based WireGuard outbound support.
//!
//! BoringTun intentionally stops at the WireGuard protocol boundary. This
//! crate supplies the missing yuhaiin adapter: a small smoltcp IP stack feeds
//! packets to BoringTun and exposes TCP/UDP sockets through `AsyncProxy`.
//! The OS-facing TUN implementation remains in `yuhaiin-core`; this is the
//! virtual stack required by a WireGuard *outbound* node.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use serde::Deserialize;
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{
    Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
};
use smoltcp::socket::udp::{
    PacketBuffer as UdpSocketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
    UdpMetadata,
};
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::{mpsc, oneshot};

use yuhaiin_core::dns_resolver_async::AsyncIpResolver;
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{
    BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, Network, ResolveStrategy,
    Result,
};

const DEFAULT_MTU: usize = 1_420;
const DEFAULT_QUEUE_CAPACITY: usize = 256;
const SOCKET_BUFFER_SIZE: usize = 64 * 1024;
const WIREGUARD_OVERHEAD: usize = 32;
const HANDSHAKE_BUFFER_SIZE: usize = 2_048;
const MAX_PACKET_SIZE: usize = 65_535;
const MAX_STREAM_OUTPUT_BYTES: usize = SOCKET_BUFFER_SIZE * 4;
const MAX_PENDING_IP_PACKETS: usize = 256;
const PORT_MIN: u16 = 32_768;
const PORT_MAX: u16 = 60_000;
static NEXT_TUNNEL_INDEX: AtomicU32 = AtomicU32::new(1);

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
struct ParsedPeer {
    endpoint: SocketAddr,
    allowed_ips: Vec<IpCidr>,
    public_key: [u8; 32],
    pre_shared_key: Option<[u8; 32]>,
    keep_alive: Option<u16>,
}

#[derive(Debug, Clone)]
struct ParsedConfig {
    local_addresses: Vec<IpCidr>,
    peers: Vec<ParsedPeer>,
    mtu: usize,
    reserved: Vec<u8>,
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

    fn parse(&self, peers: Vec<ParsedPeer>) -> Result<ParsedConfig> {
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
    async fn parse(
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

fn decode_key(value: &str, name: &str) -> Result<[u8; 32]> {
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

fn parse_cidr(value: &str) -> Result<IpCidr> {
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

fn parse_cidr_or_host(value: &str) -> Result<IpCidr> {
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

async fn resolve_endpoint(
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

fn split_host_port(value: &str) -> Result<(String, u16)> {
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

fn ip_endpoint(address: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(IpAddress::from(address.ip()), address.port())
}

fn listen_endpoint(port: u16) -> IpListenEndpoint {
    IpListenEndpoint { addr: None, port }
}

fn core_endpoint(network: Network, address: SocketAddr) -> Endpoint {
    Endpoint::ip(network, address)
}

fn error_io(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

fn error_protocol(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Protocol, error.to_string())
}

fn error_protocol_debug(error: impl std::fmt::Debug) -> Error {
    Error::new(ErrorKind::Protocol, format!("{error:?}"))
}

fn error_unsupported(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Unsupported, message.into())
}

struct PeerTunnel {
    endpoint: SocketAddr,
    allowed_ips: Vec<IpCidr>,
    tunnel: Tunn,
    pending_packets: VecDeque<Vec<u8>>,
}

impl PeerTunnel {
    fn new(private_key: [u8; 32], peer: ParsedPeer) -> Self {
        let private = StaticSecret::from(private_key);
        Self {
            endpoint: peer.endpoint,
            allowed_ips: peer.allowed_ips,
            tunnel: Tunn::new(
                private,
                PublicKey::from(peer.public_key),
                peer.pre_shared_key,
                peer.keep_alive,
                NEXT_TUNNEL_INDEX.fetch_add(1, Ordering::Relaxed),
                None,
            ),
            pending_packets: VecDeque::new(),
        }
    }
}

/// A protocol-level WireGuard engine useful for unit tests and future packet
/// consumers. It deliberately does not open sockets or spawn tasks.
pub struct WireGuardEngine {
    peers: Vec<PeerTunnel>,
    reserved: Vec<u8>,
}

impl WireGuardEngine {
    pub fn from_config(
        config: &WireGuardConfig,
        timeout: Duration,
    ) -> BoxFuture<'static, Result<Self>> {
        let config = config.clone();
        Box::pin(async move {
            let private_key = decode_key(&config.secret_key, "secretKey")?;
            let mut peers = Vec::with_capacity(config.peers.len());
            for peer in &config.peers {
                peers.push(peer.parse(timeout, None).await?);
            }
            Ok(Self::new(config.parse(peers)?, private_key))
        })
    }

    fn new(parsed: ParsedConfig, private_key: [u8; 32]) -> Self {
        Self {
            peers: parsed
                .peers
                .into_iter()
                .map(|peer| PeerTunnel::new(private_key, peer))
                .collect(),
            reserved: parsed.reserved,
        }
    }

    fn peer_for_packet(&self, packet: &[u8]) -> Result<usize> {
        let destination = Tunn::dst_address(packet).ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidInput,
                "WireGuard packet has no destination IP",
            )
        })?;
        let destination = IpAddress::from(destination);
        self.peers
            .iter()
            .enumerate()
            .filter(|(_, peer)| {
                peer.allowed_ips
                    .iter()
                    .any(|cidr| cidr.contains_addr(&destination))
            })
            .max_by_key(|(_, peer)| {
                peer.allowed_ips
                    .iter()
                    .filter(|cidr| cidr.contains_addr(&destination))
                    .map(IpCidr::prefix_len)
                    .max()
                    .unwrap_or(0)
            })
            .map(|(index, _)| index)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("no WireGuard peer allowed IP matches {destination}"),
                )
            })
    }

    fn packet_capacity(packet_len: usize) -> usize {
        (packet_len + WIREGUARD_OVERHEAD).max(HANDSHAKE_BUFFER_SIZE)
    }

    fn apply_reserved(&self, packet: &mut [u8]) {
        if self.reserved.len() == 3 && packet.len() >= 4 {
            packet[1..4].copy_from_slice(&self.reserved);
        }
    }

    fn encapsulate(&mut self, packet: &[u8]) -> Result<(usize, Vec<u8>)> {
        let peer_index = self.peer_for_packet(packet)?;
        let output = self.encapsulate_for_peer(peer_index, packet, true)?;
        Ok((peer_index, output))
    }

    fn encapsulate_for_peer(
        &mut self,
        peer_index: usize,
        packet: &[u8],
        queue_during_handshake: bool,
    ) -> Result<Vec<u8>> {
        let reserved = self.reserved.clone();
        let peer = &mut self.peers[peer_index];
        let mut output = vec![0; Self::packet_capacity(packet.len())];
        match peer.tunnel.encapsulate(packet, &mut output) {
            TunnResult::WriteToNetwork(bytes) => {
                let length = bytes.len();
                if queue_during_handshake
                    && is_handshake_initiation(&output[..length])
                    && peer.pending_packets.len() < MAX_PENDING_IP_PACKETS
                {
                    peer.pending_packets.push_back(packet.to_vec());
                }
                if reserved.len() == 3 && length >= 4 {
                    output[1..4].copy_from_slice(&reserved);
                }
                Ok(output[..length].to_vec())
            }
            TunnResult::Done => Err(error_protocol("WireGuard encapsulation produced no packet")),
            TunnResult::Err(error) => Err(error_protocol_debug(error)),
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => Err(
                error_protocol("WireGuard encapsulation returned a tunnel packet"),
            ),
        }
    }

    fn flush_pending_packets(&mut self, peer_index: usize) -> Vec<(usize, Vec<u8>)> {
        let mut pending = std::mem::take(&mut self.peers[peer_index].pending_packets);
        let mut outputs = Vec::new();
        while let Some(packet) = pending.pop_front() {
            match self.encapsulate_for_peer(peer_index, &packet, false) {
                Ok(output) if is_handshake_initiation(&output) => {
                    pending.push_front(packet);
                    break;
                }
                Ok(output) => outputs.push((peer_index, output)),
                Err(_) => break,
            }
        }
        self.peers[peer_index].pending_packets = pending;
        outputs
    }

    fn decapsulate(
        &mut self,
        peer_index: usize,
        source: SocketAddr,
        packet: &[u8],
    ) -> Result<DecapsulatedPacket> {
        let reserved = self.reserved.clone();
        let peer = self
            .peers
            .get_mut(peer_index)
            .ok_or_else(|| Error::invalid("WireGuard peer index is invalid"))?;
        // Cloudflare WARP uses the three reserved bytes as an outer marker.
        // BoringTun validates the standard zero fields, so strip the marker
        // before handing a received datagram to the protocol engine, just as
        // the Go bind implementation does.
        let mut normalized_packet = packet.to_vec();
        if normalized_packet.len() >= 4 {
            normalized_packet[1..4].fill(0);
        }
        let mut output = vec![0; MAX_PACKET_SIZE];
        let result = peer
            .tunnel
            .decapsulate(Some(source.ip()), &normalized_packet, &mut output);
        match result {
            // Only move the endpoint after BoringTun accepted the packet.
            // Updating it before authentication would let an unauthenticated
            // datagram redirect subsequent handshakes (and would break the
            // WireGuard roaming/NAT contract).
            TunnResult::Err(error) => Err(error_protocol_debug(error)),
            TunnResult::WriteToNetwork(bytes) => {
                peer.endpoint = source;
                let length = bytes.len();
                if reserved.len() == 3 && length >= 4 {
                    output[1..4].copy_from_slice(&reserved);
                }
                Ok(DecapsulatedPacket::Network(output[..length].to_vec()))
            }
            TunnResult::WriteToTunnelV4(bytes, _) => {
                peer.endpoint = source;
                Ok(DecapsulatedPacket::Tunnel(bytes.to_vec()))
            }
            TunnResult::WriteToTunnelV6(bytes, _) => {
                peer.endpoint = source;
                Ok(DecapsulatedPacket::Tunnel(bytes.to_vec()))
            }
            TunnResult::Done => {
                peer.endpoint = source;
                Ok(DecapsulatedPacket::Done)
            }
        }
    }

    fn update_timers(&mut self) -> Vec<(usize, Vec<u8>)> {
        let reserved = self.reserved.clone();
        let mut outputs = Vec::new();
        for (index, peer) in self.peers.iter_mut().enumerate() {
            let mut output = vec![0; HANDSHAKE_BUFFER_SIZE];
            if let TunnResult::WriteToNetwork(bytes) = peer.tunnel.update_timers(&mut output) {
                let length = bytes.len();
                if reserved.len() == 3 && length >= 4 {
                    output[1..4].copy_from_slice(&reserved);
                }
                outputs.push((index, output[..length].to_vec()));
            }
        }
        outputs
    }
}

fn is_handshake_initiation(packet: &[u8]) -> bool {
    packet
        .get(..4)
        .is_some_and(|header| u32::from_le_bytes(header.try_into().unwrap()) == 1)
}

#[derive(Debug)]
enum DecapsulatedPacket {
    Done,
    Network(Vec<u8>),
    Tunnel(Vec<u8>),
}

/// Construct the running WireGuard proxy. The returned proxy owns one
/// userspace IP stack and one UDP underlay; individual yuhaiin flows become
/// smoltcp TCP or UDP sockets on that stack.
pub async fn build_proxy(config: WireGuardConfig, timeout: Duration) -> Result<WireGuardProxy> {
    build_proxy_with_interface_and_resolver(config, timeout, None, None).await
}

/// Construct a WireGuard proxy while constraining its UDP underlay to an
/// operating-system interface when the platform supports that operation.
/// Keeping this option at the underlay boundary is important: the BoringTun
/// virtual stack does not create the socket used by the outer proxy wrapper.
pub async fn build_proxy_with_interface(
    config: WireGuardConfig,
    timeout: Duration,
    bind_interface: Option<&str>,
) -> Result<WireGuardProxy> {
    build_proxy_with_interface_and_resolver(config, timeout, bind_interface, None).await
}

/// Construct a WireGuard proxy using the runtime's resolver for peer endpoint
/// hostnames. This keeps hosts/FakeIP/DNS policy consistent with the rest of
/// the proxy graph; the no-resolver wrappers retain the standalone API and
/// use the system resolver for compatibility.
pub async fn build_proxy_with_interface_and_resolver(
    config: WireGuardConfig,
    timeout: Duration,
    bind_interface: Option<&str>,
    resolver: Option<Arc<dyn AsyncIpResolver>>,
) -> Result<WireGuardProxy> {
    let private_key = decode_key(&config.secret_key, "secretKey")?;
    let mut parsed_peers = Vec::with_capacity(config.peers.len());
    for peer in &config.peers {
        parsed_peers.push(peer.parse(timeout, resolver.as_deref()).await?);
    }
    let parsed = config.parse(parsed_peers)?;
    WireGuardProxy::start(ParsedConfig { ..parsed }, private_key, bind_interface).await
}

pub struct WireGuardProxy {
    command_tx: mpsc::Sender<DriverCommand>,
    closed: Arc<AtomicBool>,
}

impl WireGuardProxy {
    async fn start(
        config: ParsedConfig,
        private_key: [u8; 32],
        bind_interface: Option<&str>,
    ) -> Result<Self> {
        let bind_address = if config.peers.iter().any(|peer| peer.endpoint.is_ipv6()) {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let underlay = bind_udp_underlay(bind_address, bind_interface).await?;
        let (command_tx, command_rx) = mpsc::channel(64);
        let (ready_tx, ready_rx) = oneshot::channel();
        let closed = Arc::new(AtomicBool::new(false));
        let task_closed = Arc::clone(&closed);
        tokio::spawn(async move {
            Driver::new(config, private_key, underlay, command_rx, task_closed)
                .run(Some(ready_tx))
                .await;
        });
        ready_rx.await.map_err(|_| {
            Error::new(
                ErrorKind::Closed,
                "WireGuard driver exited before it became ready",
            )
        })??;
        Ok(Self { command_tx, closed })
    }
}

async fn bind_udp_underlay(
    bind_address: &str,
    bind_interface: Option<&str>,
) -> Result<TokioUdpSocket> {
    let Some(interface) = bind_interface
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return TokioUdpSocket::bind(bind_address).await.map_err(error_io);
    };
    let address: SocketAddr = bind_address.parse().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("invalid WireGuard bind address: {error}"),
        )
    })?;
    let socket = Socket::new(
        if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        Some(Protocol::UDP),
    )
    .map_err(error_io)?;
    bind_udp_socket_to_interface(&socket, interface)?;
    socket.bind(&address.into()).map_err(error_io)?;
    socket.set_nonblocking(true).map_err(error_io)?;
    TokioUdpSocket::from_std(socket.into()).map_err(error_io)
}

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
fn bind_udp_socket_to_interface(socket: &Socket, interface: &str) -> Result<()> {
    socket
        .bind_device(Some(interface.as_bytes()))
        .map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("bind WireGuard UDP underlay to interface {interface:?}: {error}"),
            )
        })
}

#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
fn bind_udp_socket_to_interface(_socket: &Socket, _interface: &str) -> Result<()> {
    // Other desktop platforms use the source-address snapshot fallback. Their
    // native interface-index socket options are intentionally not pulled into
    // this shared WireGuard crate.
    Ok(())
}

impl AsyncProxy for WireGuardProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            if context.network != Network::Tcp {
                return Err(error_unsupported(
                    "WireGuard TCP proxy received a non-TCP flow",
                ));
            }
            let destination = resolve_flow_destination(context).await?;
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DriverCommand::OpenTcp {
                    destination,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "WireGuard driver is closed"))?;
            Ok(Box::new(reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "WireGuard driver dropped TCP request")
            })??) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            if context.network != Network::Udp && context.network != Network::Any {
                return Err(error_unsupported(
                    "WireGuard UDP proxy received a non-UDP flow",
                ));
            }
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DriverCommand::OpenUdp { reply: reply_tx })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "WireGuard driver is closed"))?;
            Ok(Box::new(reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "WireGuard driver dropped UDP request")
            })??) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let _ = self.command_tx.try_send(DriverCommand::Close);
        }
        Box::pin(async { Ok(()) })
    }
}

async fn resolve_flow_destination(context: &FlowContext) -> Result<SocketAddr> {
    let endpoint = context
        .resolved_destination
        .as_ref()
        .unwrap_or(&context.destination);
    if let Some(address) = endpoint.addr() {
        return Ok(address);
    }
    let host = endpoint
        .host()
        .ok_or_else(|| Error::invalid("WireGuard destination has no host"))?;
    let port = endpoint
        .port()
        .ok_or_else(|| Error::invalid("WireGuard destination has no port"))?;
    tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(error_io)?
        .next()
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Io,
                format!("WireGuard destination {host}:{port} resolved to no address"),
            )
        })
}

type StreamWriteFuture = Pin<
    Box<dyn Future<Output = std::result::Result<(), mpsc::error::SendError<StreamCommand>>> + Send>,
>;
type DatagramReceiveReply = oneshot::Sender<Result<(Vec<u8>, SocketAddr)>>;

struct WireGuardStream {
    command_tx: mpsc::Sender<StreamCommand>,
    output_rx: mpsc::Receiver<Vec<u8>>,
    pending_read: VecDeque<u8>,
    pending_write: Option<StreamWriteFuture>,
    shutdown_sent: bool,
}

impl AsyncRead for WireGuardStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.pending_read.is_empty() {
            let amount = buffer.remaining().min(self.pending_read.len());
            let mut data = self.pending_read.drain(..amount).collect::<Vec<_>>();
            buffer.put_slice(&data);
            data.clear();
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.output_rx).poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let amount = buffer.remaining().min(data.len());
                buffer.put_slice(&data[..amount]);
                self.pending_read.extend(data.into_iter().skip(amount));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WireGuardStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending_write.is_none() {
            let sender = self.command_tx.clone();
            let payload = data.to_vec();
            self.pending_write = Some(Box::pin(async move {
                sender.send(StreamCommand::Write(payload)).await
            }));
        }
        match self
            .pending_write
            .as_mut()
            .expect("write future was installed")
            .as_mut()
            .poll(cx)
        {
            Poll::Ready(Ok(())) => {
                self.pending_write = None;
                Poll::Ready(Ok(data.len()))
            }
            Poll::Ready(Err(_)) => {
                self.pending_write = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "WireGuard TCP session is closed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown_sent {
            self.shutdown_sent = true;
            let _ = self.command_tx.try_send(StreamCommand::Close);
        }
        Poll::Ready(Ok(()))
    }
}

struct WireGuardDatagram {
    command_tx: mpsc::Sender<DatagramCommand>,
    local_addr: Endpoint,
}

impl AsyncDatagram for WireGuardDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            if target.network() != Network::Udp {
                return Err(Error::invalid("WireGuard UDP target has wrong network"));
            }
            let target = resolve_endpoint_value(&target).await?;
            let length = payload.len();
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DatagramCommand::Send {
                    payload: payload.to_vec(),
                    target,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "WireGuard UDP session is closed"))?;
            reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "WireGuard UDP driver dropped send")
            })??;
            Ok(length)
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DatagramCommand::Recv { reply: reply_tx })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "WireGuard UDP session is closed"))?;
            let (payload, target) = reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "WireGuard UDP driver dropped receive")
            })??;
            if buffer.len() < payload.len() {
                return Err(Error::invalid(
                    "WireGuard UDP payload exceeds receive buffer",
                ));
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            Ok((payload.len(), core_endpoint(Network::Udp, target)))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(self.local_addr.clone())
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        let _ = self.command_tx.try_send(DatagramCommand::Close);
        Box::pin(async { Ok(()) })
    }
}

async fn resolve_endpoint_value(endpoint: &Endpoint) -> Result<SocketAddr> {
    if let Some(address) = endpoint.addr() {
        return Ok(address);
    }
    let host = endpoint
        .host()
        .ok_or_else(|| Error::invalid("WireGuard UDP target has no host"))?;
    let port = endpoint
        .port()
        .ok_or_else(|| Error::invalid("WireGuard UDP target has no port"))?;
    tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(error_io)?
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Io, "WireGuard UDP target resolved to no address"))
}

enum DriverCommand {
    OpenTcp {
        destination: SocketAddr,
        reply: oneshot::Sender<Result<WireGuardStream>>,
    },
    OpenUdp {
        reply: oneshot::Sender<Result<WireGuardDatagram>>,
    },
    Close,
}

enum StreamCommand {
    Write(Vec<u8>),
    Close,
}

enum DatagramCommand {
    Send {
        payload: Vec<u8>,
        target: SocketAddr,
        reply: oneshot::Sender<Result<()>>,
    },
    Recv {
        reply: oneshot::Sender<Result<(Vec<u8>, SocketAddr)>>,
    },
    Close,
}

struct TcpSession {
    command_rx: mpsc::Receiver<StreamCommand>,
    output_tx: mpsc::Sender<Vec<u8>>,
    pending_writes: VecDeque<Vec<u8>>,
    pending_output: VecDeque<Vec<u8>>,
    pending_output_bytes: usize,
    close_requested: bool,
}

struct UdpSession {
    command_rx: mpsc::Receiver<DatagramCommand>,
    pending_recv: Option<DatagramReceiveReply>,
    queued_recv: VecDeque<(Vec<u8>, SocketAddr)>,
}

struct Driver {
    config: ParsedConfig,
    engine: WireGuardEngine,
    underlay: TokioUdpSocket,
    command_rx: mpsc::Receiver<DriverCommand>,
    closed: Arc<AtomicBool>,
    next_port: u16,
    tcp_sessions: HashMap<SocketHandle, TcpSession>,
    udp_sessions: HashMap<SocketHandle, UdpSession>,
}

impl Driver {
    fn new(
        config: ParsedConfig,
        private_key: [u8; 32],
        underlay: TokioUdpSocket,
        command_rx: mpsc::Receiver<DriverCommand>,
        closed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            engine: WireGuardEngine::new(config.clone(), private_key),
            config,
            underlay,
            command_rx,
            closed,
            next_port: PORT_MIN,
            tcp_sessions: HashMap::new(),
            udp_sessions: HashMap::new(),
        }
    }

    async fn run(mut self, ready: Option<oneshot::Sender<Result<()>>>) {
        let mut device =
            match yuhaiin_core::tun::SmoltcpTunDevice::new(self.config.mtu, DEFAULT_QUEUE_CAPACITY)
            {
                Ok(device) => device,
                Err(error) => {
                    if let Some(ready) = ready {
                        let _ = ready.send(Err(error_io(error)));
                    }
                    self.closed.store(true, Ordering::Release);
                    return;
                }
            };
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            Instant::from_millis(0),
        );
        interface.set_any_ip(true);
        interface.update_ip_addrs(|addresses| {
            for address in &self.config.local_addresses {
                let _ = addresses.push(*address);
            }
        });
        if self
            .config
            .local_addresses
            .iter()
            .any(|address| matches!(address, IpCidr::Ipv4(_)))
        {
            let _ = interface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 0));
        }
        if self
            .config
            .local_addresses
            .iter()
            .any(|address| matches!(address, IpCidr::Ipv6(_)))
        {
            let _ = interface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::UNSPECIFIED);
        }
        if let Some(ready) = ready {
            let _ = ready.send(Ok(()));
        }
        let mut sockets = SocketSet::new(vec![]);
        let mut underlay_buffer = vec![0; MAX_PACKET_SIZE + HANDSHAKE_BUFFER_SIZE];
        loop {
            if self.closed.load(Ordering::Acquire) {
                break;
            }
            self.process_commands(&mut interface, &mut sockets).await;
            self.process_sessions(&mut sockets).await;
            interface.poll(
                Instant::from_millis(current_millis()),
                &mut device,
                &mut sockets,
            );
            self.flush_ip_packets(&device).await;
            self.flush_timers().await;
            tokio::select! {
                command = self.command_rx.recv() => {
                    match command {
                        Some(command) => self.handle_command(command, &mut interface, &mut sockets).await,
                        None => break,
                    }
                }
                received = self.underlay.recv_from(&mut underlay_buffer) => {
                    if let Ok((length, source)) = received {
                        self.process_underlay(&device, source, &underlay_buffer[..length]).await;
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(2)) => {}
            }
        }
        self.closed.store(true, Ordering::Release);
    }

    async fn process_commands(&mut self, interface: &mut Interface, sockets: &mut SocketSet<'_>) {
        while let Ok(command) = self.command_rx.try_recv() {
            self.handle_command(command, interface, sockets).await;
        }
    }

    async fn handle_command(
        &mut self,
        command: DriverCommand,
        interface: &mut Interface,
        sockets: &mut SocketSet<'_>,
    ) {
        match command {
            DriverCommand::OpenTcp { destination, reply } => {
                let local_port = self.allocate_port();
                let socket = TcpSocket::new(
                    TcpSocketBuffer::new(vec![0; SOCKET_BUFFER_SIZE]),
                    TcpSocketBuffer::new(vec![0; SOCKET_BUFFER_SIZE]),
                );
                let handle = sockets.add(socket);
                let result = sockets.get_mut::<TcpSocket>(handle).connect(
                    interface.context(),
                    ip_endpoint(destination),
                    listen_endpoint(local_port),
                );
                if let Err(error) = result {
                    let _ = sockets.remove(handle);
                    let _ = reply.send(Err(error_protocol(error)));
                    return;
                }
                let (command_tx, command_rx) = mpsc::channel(64);
                let (output_tx, output_rx) = mpsc::channel(64);
                self.tcp_sessions.insert(
                    handle,
                    TcpSession {
                        command_rx,
                        output_tx,
                        pending_writes: VecDeque::new(),
                        pending_output: VecDeque::new(),
                        pending_output_bytes: 0,
                        close_requested: false,
                    },
                );
                let _ = reply.send(Ok(WireGuardStream {
                    command_tx,
                    output_rx,
                    pending_read: VecDeque::new(),
                    pending_write: None,
                    shutdown_sent: false,
                }));
            }
            DriverCommand::OpenUdp { reply } => {
                let local_port = self.allocate_port();
                let mut socket = UdpSocket::new(
                    UdpSocketBuffer::new(
                        vec![UdpPacketMetadata::EMPTY; 64],
                        vec![0; SOCKET_BUFFER_SIZE],
                    ),
                    UdpSocketBuffer::new(
                        vec![UdpPacketMetadata::EMPTY; 64],
                        vec![0; SOCKET_BUFFER_SIZE],
                    ),
                );
                if let Err(error) = socket.bind(listen_endpoint(local_port)) {
                    let _ = reply.send(Err(error_protocol(error)));
                    return;
                }
                let handle = sockets.add(socket);
                let (command_tx, command_rx) = mpsc::channel(64);
                let local_ip = self
                    .config
                    .local_addresses
                    .first()
                    .map(|cidr| IpAddr::from(cidr.address()))
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                self.udp_sessions.insert(
                    handle,
                    UdpSession {
                        command_rx,
                        pending_recv: None,
                        queued_recv: VecDeque::new(),
                    },
                );
                let _ = reply.send(Ok(WireGuardDatagram {
                    command_tx,
                    local_addr: core_endpoint(Network::Udp, SocketAddr::new(local_ip, local_port)),
                }));
            }
            DriverCommand::Close => self.closed.store(true, Ordering::Release),
        }
    }

    async fn process_sessions(&mut self, sockets: &mut SocketSet<'_>) {
        let tcp_handles = self.tcp_sessions.keys().copied().collect::<Vec<_>>();
        for handle in tcp_handles {
            let Some(session) = self.tcp_sessions.get_mut(&handle) else {
                continue;
            };
            while let Ok(command) = session.command_rx.try_recv() {
                match command {
                    StreamCommand::Write(data) => session.pending_writes.push_back(data),
                    StreamCommand::Close => session.close_requested = true,
                }
            }
            let socket = sockets.get_mut::<TcpSocket>(handle);
            if session.close_requested {
                socket.close();
            }
            while socket.can_send() {
                let Some(data) = session.pending_writes.pop_front() else {
                    break;
                };
                match socket.send_slice(&data) {
                    Ok(written) if written < data.len() => {
                        session.pending_writes.push_front(data[written..].to_vec())
                    }
                    Ok(_) => {}
                    Err(_) => {
                        session.pending_writes.push_front(data);
                        break;
                    }
                }
            }
            while let Some(data) = session.pending_output.pop_front() {
                session.pending_output_bytes -= data.len();
                match session.output_tx.try_send(data) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(data)) => {
                        session.pending_output_bytes += data.len();
                        session.pending_output.push_front(data);
                        break;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        session.close_requested = true;
                        session.pending_output.clear();
                        session.pending_output_bytes = 0;
                        break;
                    }
                }
            }
            // `may_recv` is true for every established socket, including an
            // empty receive buffer. Only forward an actual payload; an empty
            // async read is EOF to the inbound relay.
            if socket.can_recv() && !session.close_requested {
                let mut data = vec![0; SOCKET_BUFFER_SIZE.min(self.config.mtu.saturating_mul(8))];
                if let Ok(length) = socket.recv_slice(&mut data) {
                    data.truncate(length);
                    match session.output_tx.try_send(data) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(data)) => {
                            if session.pending_output_bytes + data.len() > MAX_STREAM_OUTPUT_BYTES {
                                session.close_requested = true;
                                session.pending_output.clear();
                                session.pending_output_bytes = 0;
                            } else {
                                session.pending_output_bytes += data.len();
                                session.pending_output.push_back(data);
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            session.close_requested = true;
                        }
                    }
                }
            }
            if socket.state() == TcpState::Closed
                && session.pending_writes.is_empty()
                && session.pending_output.is_empty()
            {
                self.tcp_sessions.remove(&handle);
                let _ = sockets.remove(handle);
            }
        }

        let udp_handles = self.udp_sessions.keys().copied().collect::<Vec<_>>();
        for handle in udp_handles {
            let mut remove = false;
            let Some(session) = self.udp_sessions.get_mut(&handle) else {
                continue;
            };
            while let Ok(command) = session.command_rx.try_recv() {
                match command {
                    DatagramCommand::Send {
                        payload,
                        target,
                        reply,
                    } => {
                        let result = sockets
                            .get_mut::<UdpSocket>(handle)
                            .send_slice(&payload, UdpMetadata::from(ip_endpoint(target)));
                        let _ = reply.send(result.map_err(error_protocol));
                    }
                    DatagramCommand::Recv { reply } => {
                        if let Some((payload, target)) = session.queued_recv.pop_front() {
                            let _ = reply.send(Ok((payload, target)));
                        } else {
                            session.pending_recv = Some(reply);
                        }
                    }
                    DatagramCommand::Close => {
                        remove = true;
                        break;
                    }
                }
            }
            if remove {
                self.udp_sessions.remove(&handle);
                let _ = sockets.remove(handle);
                continue;
            }
            let socket = sockets.get_mut::<UdpSocket>(handle);
            while socket.can_recv() {
                let mut payload = vec![0; SOCKET_BUFFER_SIZE];
                let Ok((length, metadata)) = socket.recv_slice(&mut payload) else {
                    break;
                };
                payload.truncate(length);
                let target: SocketAddr = metadata.endpoint.into();
                if let Some(reply) = session.pending_recv.take() {
                    let _ = reply.send(Ok((payload, target)));
                } else {
                    session.queued_recv.push_back((payload, target));
                }
            }
        }
    }

    async fn flush_ip_packets(&mut self, device: &yuhaiin_core::tun::SmoltcpTunDevice) {
        while let Ok(Some(packet)) = device.take_tx() {
            let Ok((peer, packet)) = self.engine.encapsulate(&packet) else {
                continue;
            };
            let _ = self.send_to_peer(peer, packet).await;
        }
    }

    async fn flush_timers(&mut self) {
        for (peer, packet) in self.engine.update_timers() {
            let _ = self.send_to_peer(peer, packet).await;
        }
    }

    async fn process_underlay(
        &mut self,
        device: &yuhaiin_core::tun::SmoltcpTunDevice,
        source: SocketAddr,
        packet: &[u8],
    ) {
        for peer_index in 0..self.engine.peers.len() {
            let Ok(result) = self.engine.decapsulate(peer_index, source, packet) else {
                continue;
            };
            match result {
                DecapsulatedPacket::Tunnel(payload) => {
                    let _ = device.enqueue_rx(payload);
                    let mut output = vec![0; HANDSHAKE_BUFFER_SIZE];
                    while let TunnResult::WriteToNetwork(bytes) = self.engine.peers[peer_index]
                        .tunnel
                        .decapsulate(Some(source.ip()), &[], &mut output)
                    {
                        let length = bytes.len();
                        self.engine.apply_reserved(&mut output[..length]);
                        let _ = self
                            .send_to_peer(peer_index, output[..length].to_vec())
                            .await;
                    }
                    for (_, packet) in self.engine.flush_pending_packets(peer_index) {
                        let _ = self.send_to_peer(peer_index, packet).await;
                    }
                    break;
                }
                DecapsulatedPacket::Network(payload) => {
                    let _ = self.send_to_peer(peer_index, payload).await;
                    for (_, packet) in self.engine.flush_pending_packets(peer_index) {
                        let _ = self.send_to_peer(peer_index, packet).await;
                    }
                    break;
                }
                DecapsulatedPacket::Done => {
                    for (_, packet) in self.engine.flush_pending_packets(peer_index) {
                        let _ = self.send_to_peer(peer_index, packet).await;
                    }
                    break;
                }
            }
        }
    }

    async fn send_to_peer(&self, peer_index: usize, mut packet: Vec<u8>) -> Result<()> {
        let endpoint = self
            .engine
            .peers
            .get(peer_index)
            .ok_or_else(|| Error::invalid("WireGuard peer index is invalid"))?
            .endpoint;
        if self.engine.reserved.len() == 3 && packet.len() >= 4 {
            packet[1..4].copy_from_slice(&self.engine.reserved);
        }
        self.underlay
            .send_to(&packet, endpoint)
            .await
            .map_err(error_io)?;
        Ok(())
    }

    fn allocate_port(&mut self) -> u16 {
        let port = self.next_port;
        self.next_port = if self.next_port >= PORT_MAX {
            PORT_MIN
        } else {
            self.next_port + 1
        };
        port
    }
}

fn current_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use yuhaiin_core::IpSet;

    struct FixedResolver;

    impl AsyncIpResolver for FixedResolver {
        fn resolve<'a>(
            &'a self,
            domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            assert_eq!(domain.as_str(), "peer.invalid");
            Box::pin(async {
                Ok(IpSet {
                    v4: vec![std::net::Ipv4Addr::LOCALHOST],
                    v6: Vec::new(),
                })
            })
        }
    }

    fn key(byte: u8) -> String {
        STANDARD.encode([byte; 32])
    }

    #[test]
    fn parses_go_wireguard_config() {
        let config = WireGuardConfig {
            secret_key: key(1),
            endpoint: vec!["10.0.0.2/32".to_owned()],
            peers: vec![WireGuardPeerConfig {
                public_key: key(2),
                pre_shared_key: String::new(),
                endpoint: "127.0.0.1:51820".to_owned(),
                keep_alive: 25,
                allowed_ips: vec!["0.0.0.0/0".to_owned()],
            }],
            mtu: 1_420,
            reserved: vec![0, 0, 0],
        };
        let parsed = futures_lite::future::block_on(async {
            let peer = config.peers[0]
                .parse(Duration::from_secs(1), None)
                .await
                .unwrap();
            config.parse(vec![peer]).unwrap()
        });
        assert_eq!(parsed.local_addresses.len(), 1);
        assert_eq!(parsed.peers[0].allowed_ips[0].prefix_len(), 0);
        assert_eq!(parsed.peers[0].keep_alive, Some(25));

        let json = serde_json::json!({
            "secretKey": key(1),
            "endpoint": ["10.0.0.2/32"],
            "reserved": "AAAA",
            "peers": [{
                "publicKey": key(2),
                "endpoint": "127.0.0.1:51820",
                "allowedIps": ["0.0.0.0/0"]
            }]
        });
        let json_bytes = serde_json::to_vec(&json).unwrap();
        let decoded = WireGuardConfig::from_json_or_ini(&json_bytes).unwrap();
        assert_eq!(decoded.reserved, vec![0, 0, 0]);
    }

    #[test]
    fn parses_cloudflare_warp_wireguard_ini() {
        let config = WireGuardConfig::from_json_or_ini(
            br#"
                [Interface]
                PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
                Address = 172.16.0.2/32, 2606:4700:110:8765:1111:2222:3333:4444/128
                DNS = 1.1.1.1
                MTU = 1280
                Reserved = 1, 2, 3

                [Peer]
                PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
                AllowedIPs = 0.0.0.0/0, ::/0
                Endpoint = engage.cloudflareclient.com:2408
                PersistentKeepalive = 25
            "#,
        )
        .unwrap();

        assert_eq!(config.endpoint.len(), 2);
        assert_eq!(config.mtu, 1_280);
        assert_eq!(config.reserved, vec![1, 2, 3]);
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].allowed_ips, ["0.0.0.0/0", "::/0"]);
        assert_eq!(config.peers[0].keep_alive, 25);
        assert_eq!(config.peers[0].endpoint, "engage.cloudflareclient.com:2408");
    }

    #[test]
    fn rejects_incomplete_wireguard_ini() {
        let error = WireGuardConfig::from_wireguard_ini(
            "[Interface]\nPrivateKey = invalid\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = invalid\n",
        )
        .unwrap_err();
        assert!(
            error
                .message
                .contains("missing PublicKey, Endpoint, or AllowedIPs")
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn wireguard_underlay_applies_linux_network_interface() {
        let socket = bind_udp_underlay("0.0.0.0:0", Some("lo")).await.unwrap();
        assert_eq!(
            socket.local_addr().unwrap().ip(),
            "0.0.0.0".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn rejects_non_32_byte_keys() {
        let error = decode_key("AQ==", "secretKey").unwrap_err();
        assert_eq!(error.kind, ErrorKind::InvalidInput);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn peer_endpoint_uses_injected_runtime_resolver() {
        let peer = WireGuardPeerConfig {
            public_key: key(2),
            pre_shared_key: String::new(),
            endpoint: "peer.invalid:51820".to_owned(),
            keep_alive: 0,
            allowed_ips: vec!["0.0.0.0/0".to_owned()],
        };
        let parsed = peer
            .parse(Duration::from_secs(1), Some(&FixedResolver))
            .await
            .unwrap();
        assert_eq!(parsed.endpoint, "127.0.0.1:51820".parse().unwrap());
    }

    #[test]
    fn boringtun_round_trip_is_authenticated() {
        let first_private = StaticSecret::from([3; 32]);
        let second_private = StaticSecret::from([4; 32]);
        let first_public = PublicKey::from(&first_private);
        let second_public = PublicKey::from(&second_private);
        let mut first = Tunn::new(first_private, second_public, None, None, 1, None);
        let mut second = Tunn::new(second_private, first_public, None, None, 2, None);
        let packet = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
        ];
        let mut first_out = vec![0; 2_048];
        let handshake = first.encapsulate(&packet, &mut first_out);
        let handshake = match handshake {
            TunnResult::WriteToNetwork(value) => value.to_vec(),
            other => panic!("unexpected {other:?}"),
        };
        let mut second_out = vec![0; 2_048];
        let response = second.decapsulate(
            Some("127.0.0.1".parse().unwrap()),
            &handshake,
            &mut second_out,
        );
        let response = match response {
            TunnResult::WriteToNetwork(value) => value.to_vec(),
            other => panic!("unexpected {other:?}"),
        };
        let mut first_out2 = vec![0; 2_048];
        let keepalive = first.decapsulate(
            Some("127.0.0.1".parse().unwrap()),
            &response,
            &mut first_out2,
        );
        assert!(matches!(keepalive, TunnResult::WriteToNetwork(_)));

        let data = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
        ];
        let mut data_out = vec![0; 2_048];
        let encrypted = first.encapsulate(&data, &mut data_out);
        let encrypted = match encrypted {
            TunnResult::WriteToNetwork(value) => value.to_vec(),
            other => panic!("unexpected {other:?}"),
        };
        let mut plain_out = vec![0; 2_048];
        let plain = second.decapsulate(
            Some("127.0.0.1".parse().unwrap()),
            &encrypted,
            &mut plain_out,
        );
        match plain {
            TunnResult::WriteToTunnelV4(value, source) => {
                assert_eq!(value, data);
                assert_eq!(source, "10.0.0.2".parse::<std::net::Ipv4Addr>().unwrap());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn allowed_ips_use_the_longest_prefix_match() {
        let all_v4 = IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0);
        let broad_peer = ParsedPeer {
            endpoint: "127.0.0.1:51820".parse().unwrap(),
            allowed_ips: vec![all_v4],
            public_key: *PublicKey::from(&StaticSecret::from([12; 32])).as_bytes(),
            pre_shared_key: None,
            keep_alive: None,
        };
        let specific_peer = ParsedPeer {
            endpoint: "127.0.0.1:51821".parse().unwrap(),
            allowed_ips: vec![parse_cidr("10.23.0.0/16").unwrap()],
            public_key: *PublicKey::from(&StaticSecret::from([13; 32])).as_bytes(),
            pre_shared_key: None,
            keep_alive: None,
        };
        let engine = WireGuardEngine::new(
            ParsedConfig {
                local_addresses: vec![IpCidr::new(IpAddress::v4(10, 0, 0, 2), 32)],
                peers: vec![broad_peer, specific_peer],
                mtu: DEFAULT_MTU,
                reserved: Vec::new(),
            },
            [11; 32],
        );

        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[10, 23, 4, 5]);
        assert_eq!(engine.peer_for_packet(&packet).unwrap(), 1);

        packet[16..20].copy_from_slice(&[192, 0, 2, 5]);
        assert_eq!(engine.peer_for_packet(&packet).unwrap(), 0);
    }

    #[test]
    fn persistent_keepalive_is_emitted_by_the_engine() {
        let first_private = [14; 32];
        let second_private = [15; 32];
        let first_public = *PublicKey::from(&StaticSecret::from(first_private)).as_bytes();
        let second_public = *PublicKey::from(&StaticSecret::from(second_private)).as_bytes();
        let all_v4 = IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0);
        let make_config =
            |endpoint: &str, public_key: [u8; 32], keep_alive: Option<u16>| ParsedConfig {
                local_addresses: vec![IpCidr::new(IpAddress::v4(10, 0, 0, 2), 32)],
                peers: vec![ParsedPeer {
                    endpoint: endpoint.parse().unwrap(),
                    allowed_ips: vec![all_v4],
                    public_key,
                    pre_shared_key: None,
                    keep_alive,
                }],
                mtu: DEFAULT_MTU,
                reserved: Vec::new(),
            };
        let mut first = WireGuardEngine::new(
            make_config("127.0.0.1:51820", second_public, Some(1)),
            first_private,
        );
        let mut second = WireGuardEngine::new(
            make_config("127.0.0.1:51821", first_public, None),
            second_private,
        );
        let source: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let packet = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
        ];
        let (_, handshake) = first.encapsulate(&packet).unwrap();
        let response = match second.decapsulate(0, source, &handshake).unwrap() {
            DecapsulatedPacket::Network(packet) => packet,
            other => panic!("expected handshake response, got {other:?}"),
        };
        let acknowledgement = match first.decapsulate(0, source, &response).unwrap() {
            DecapsulatedPacket::Network(packet) => packet,
            other => panic!("expected handshake acknowledgement, got {other:?}"),
        };
        assert!(matches!(
            second.decapsulate(0, source, &acknowledgement).unwrap(),
            DecapsulatedPacket::Done
        ));

        std::thread::sleep(Duration::from_millis(1_100));
        let keepalive = first.update_timers();
        assert_eq!(keepalive.len(), 1);
        assert!(matches!(
            second.decapsulate(0, source, &keepalive[0].1).unwrap(),
            DecapsulatedPacket::Done
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn userspace_proxy_crosses_two_local_wireguard_peers() {
        use tokio::io::AsyncReadExt;

        let first_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_endpoint = first_socket.local_addr().unwrap();
        let second_endpoint = second_socket.local_addr().unwrap();
        let first_private = [5; 32];
        let second_private = [6; 32];
        let first_public = *PublicKey::from(&StaticSecret::from(first_private)).as_bytes();
        let second_public = *PublicKey::from(&StaticSecret::from(second_private)).as_bytes();
        let all_v4 = IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0);
        let first_config = ParsedConfig {
            local_addresses: vec![IpCidr::new(IpAddress::v4(10, 0, 0, 2), 32)],
            peers: vec![ParsedPeer {
                endpoint: second_endpoint,
                allowed_ips: vec![all_v4],
                public_key: second_public,
                pre_shared_key: None,
                keep_alive: None,
            }],
            mtu: DEFAULT_MTU,
            reserved: Vec::new(),
        };
        let second_config = ParsedConfig {
            local_addresses: vec![IpCidr::new(IpAddress::v4(10, 0, 0, 1), 32)],
            peers: vec![ParsedPeer {
                endpoint: first_endpoint,
                allowed_ips: vec![all_v4],
                public_key: first_public,
                pre_shared_key: None,
                keep_alive: None,
            }],
            mtu: DEFAULT_MTU,
            reserved: Vec::new(),
        };
        let (first_tx, first_rx) = mpsc::channel(64);
        let (second_tx, second_rx) = mpsc::channel(64);
        let first_closed = Arc::new(AtomicBool::new(false));
        let second_closed = Arc::new(AtomicBool::new(false));
        let first_task = tokio::spawn(
            Driver::new(
                first_config,
                first_private,
                first_socket,
                first_rx,
                Arc::clone(&first_closed),
            )
            .run(None),
        );
        let second_task = tokio::spawn(
            Driver::new(
                second_config,
                second_private,
                second_socket,
                second_rx,
                Arc::clone(&second_closed),
            )
            .run(None),
        );

        let proxy = WireGuardProxy {
            command_tx: first_tx.clone(),
            closed: Arc::clone(&first_closed),
        };
        let context = FlowContext::new(Endpoint::ip(Network::Tcp, "192.0.2.1:80".parse().unwrap()));
        let mut stream = proxy.connect(&context).await.unwrap();
        let mut buffer = [0; 1];
        let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            result, 0,
            "a peer without a listener must close the TCP stream"
        );

        let first_datagram = proxy
            .open_datagram(&FlowContext::new(Endpoint::ip(
                Network::Udp,
                "192.0.2.1:53".parse().unwrap(),
            )))
            .await
            .unwrap();
        let second_proxy = WireGuardProxy {
            command_tx: second_tx.clone(),
            closed: Arc::clone(&second_closed),
        };
        let second_datagram = second_proxy
            .open_datagram(&FlowContext::new(Endpoint::ip(
                Network::Udp,
                "192.0.2.2:53".parse().unwrap(),
            )))
            .await
            .unwrap();
        let second_target = second_datagram.local_addr().unwrap();
        let payload = b"wireguard-udp";
        assert_eq!(
            first_datagram
                .send_to(payload, second_target)
                .await
                .unwrap(),
            payload.len()
        );
        let mut received = [0; 64];
        let (length, first_target) = tokio::time::timeout(
            Duration::from_secs(2),
            second_datagram.recv_from(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&received[..length], payload);
        assert_eq!(first_target.network(), Network::Udp);
        assert_eq!(
            second_datagram
                .send_to(&received[..length], first_target)
                .await
                .unwrap(),
            payload.len()
        );
        let (length, second_target) = tokio::time::timeout(
            Duration::from_secs(2),
            first_datagram.recv_from(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&received[..length], payload);
        assert_eq!(second_target.network(), Network::Udp);
        first_datagram.close().await.unwrap();
        second_datagram.close().await.unwrap();

        first_closed.store(true, Ordering::Release);
        second_closed.store(true, Ordering::Release);
        let _ = first_tx.send(DriverCommand::Close).await;
        let _ = second_tx.send(DriverCommand::Close).await;
        let _ = first_task.await;
        let _ = second_task.await;
    }

    #[test]
    fn reserved_bytes_are_stripped_before_boringtun_decode() {
        let first_private = [7; 32];
        let second_private = [8; 32];
        let first_public = *PublicKey::from(&StaticSecret::from(first_private)).as_bytes();
        let second_public = *PublicKey::from(&StaticSecret::from(second_private)).as_bytes();
        let all_v4 = IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0);
        let mut first = WireGuardEngine::new(
            ParsedConfig {
                local_addresses: vec![IpCidr::new(IpAddress::v4(10, 0, 0, 2), 32)],
                peers: vec![ParsedPeer {
                    endpoint: "127.0.0.1:51820".parse().unwrap(),
                    allowed_ips: vec![all_v4],
                    public_key: second_public,
                    pre_shared_key: None,
                    keep_alive: None,
                }],
                mtu: DEFAULT_MTU,
                reserved: vec![1, 2, 3],
            },
            first_private,
        );
        let mut second = WireGuardEngine::new(
            ParsedConfig {
                local_addresses: vec![IpCidr::new(IpAddress::v4(10, 0, 0, 1), 32)],
                peers: vec![ParsedPeer {
                    endpoint: "127.0.0.1:51821".parse().unwrap(),
                    allowed_ips: vec![all_v4],
                    public_key: first_public,
                    pre_shared_key: None,
                    keep_alive: None,
                }],
                mtu: DEFAULT_MTU,
                reserved: vec![1, 2, 3],
            },
            second_private,
        );
        let packet = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
        ];
        let (_, handshake) = first.encapsulate(&packet).unwrap();
        assert_eq!(&handshake[1..4], &[1, 2, 3]);
        let roaming_source: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let response = match second.decapsulate(0, roaming_source, &handshake).unwrap() {
            DecapsulatedPacket::Network(response) => response,
            _ => panic!("expected handshake response"),
        };
        assert_eq!(second.peers[0].endpoint, roaming_source);
        let response_source: SocketAddr = "127.0.0.1:40002".parse().unwrap();
        let _ = first.decapsulate(0, response_source, &response).unwrap();
        assert_eq!(first.peers[0].endpoint, response_source);
    }

    #[test]
    #[ignore = "opt-in packet encryption benchmark; run scripts/benchmark/wireguard.sh"]
    fn wireguard_packet_throughput_benchmark() {
        use std::time::Instant;

        let bytes = std::env::var("YUHAIIN_WIREGUARD_BENCH_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(64 * 1024 * 1024);
        let first_private = [9; 32];
        let second_private = [10; 32];
        let first_public = *PublicKey::from(&StaticSecret::from(first_private)).as_bytes();
        let second_public = *PublicKey::from(&StaticSecret::from(second_private)).as_bytes();
        let all_v4 = IpCidr::new(IpAddress::v4(0, 0, 0, 0), 0);
        let config = |endpoint: SocketAddr, public_key: [u8; 32], reserved: Vec<u8>| ParsedConfig {
            local_addresses: vec![IpCidr::new(IpAddress::v4(10, 0, 0, 2), 32)],
            peers: vec![ParsedPeer {
                endpoint,
                allowed_ips: vec![all_v4],
                public_key,
                pre_shared_key: None,
                keep_alive: None,
            }],
            mtu: DEFAULT_MTU,
            reserved,
        };
        let source: SocketAddr = "127.0.0.1:40000"
            .parse()
            .expect("benchmark source must include a UDP port");
        let mut first = WireGuardEngine::new(
            config(
                "127.0.0.1:51820".parse().unwrap(),
                second_public,
                vec![1, 2, 3],
            ),
            first_private,
        );
        let mut second = WireGuardEngine::new(
            config(
                "127.0.0.1:51821".parse().unwrap(),
                first_public,
                vec![1, 2, 3],
            ),
            second_private,
        );
        let handshake_packet = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
        ];
        let (_, handshake) = first.encapsulate(&handshake_packet).unwrap();
        let response = match second.decapsulate(0, source, &handshake).unwrap() {
            DecapsulatedPacket::Network(packet) => packet,
            other => panic!("expected handshake response, got {other:?}"),
        };
        let _ = first.decapsulate(0, source, &response).unwrap();

        let payload_size = 1_400;
        let mut packet = vec![0; 20 + payload_size];
        packet[0] = 0x45;
        let packet_length = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);

        let read_rss_kib = || {
            std::fs::read_to_string("/proc/self/status")
                .ok()
                .and_then(|status| {
                    status.lines().find_map(|line| {
                        line.strip_prefix("VmRSS:")
                            .and_then(|value| value.split_whitespace().next())
                            .and_then(|value| value.parse::<u64>().ok())
                    })
                })
        };
        let read_cpu_ticks = || {
            std::fs::read_to_string("/proc/self/stat")
                .ok()
                .and_then(|stat| {
                    let (_, fields) = stat.rsplit_once(") ")?;
                    let mut fields = fields.split_whitespace();
                    let user = fields.nth(11)?.parse::<u64>().ok()?;
                    let system = fields.next()?.parse::<u64>().ok()?;
                    Some(user.saturating_add(system))
                })
        };
        let mut peak_rss_kib = None;
        let mut proc_samples = 0u64;
        let mut sample_usage = || {
            let rss_kib = read_rss_kib();
            if let Some(rss_kib) = rss_kib {
                peak_rss_kib = Some(peak_rss_kib.unwrap_or(0).max(rss_kib));
            }
            let cpu_ticks = read_cpu_ticks();
            if rss_kib.is_some() || cpu_ticks.is_some() {
                proc_samples += 1;
            }
            cpu_ticks
        };
        let cpu_start = sample_usage();
        let started = Instant::now();
        let mut transferred = 0usize;
        while transferred < bytes {
            let length = (bytes - transferred).min(payload_size);
            packet.truncate(20 + length);
            let packet_length = packet.len() as u16;
            packet[2..4].copy_from_slice(&packet_length.to_be_bytes());
            let (_, encrypted) = first.encapsulate(&packet).unwrap();
            match second.decapsulate(0, source, &encrypted).unwrap() {
                DecapsulatedPacket::Tunnel(received) => assert_eq!(received, packet),
                other => panic!("expected tunnel packet, got {other:?}"),
            }
            transferred += length;
            packet.resize(20 + payload_size, 0);
            if transferred % (payload_size * 256) < length || transferred == bytes {
                let _ = sample_usage();
            }
        }
        let elapsed = started.elapsed();
        let seconds = elapsed.as_secs_f64().max(f64::EPSILON);
        let cpu_end = sample_usage();
        let cpu_ticks = cpu_start
            .zip(cpu_end)
            .map(|(start, end)| end.saturating_sub(start));
        println!(
            "BENCHMARK {}",
            serde_json::json!({
                "scenario": "wireguard-boringtun-packet",
                "bytes": bytes,
                "seconds": seconds,
                "mib_per_sec": bytes as f64 / seconds / (1024.0 * 1024.0),
                "peak_rss_kib": peak_rss_kib,
                "cpu_ticks": cpu_ticks,
                "proc_samples": proc_samples,
            })
        );
    }
}
