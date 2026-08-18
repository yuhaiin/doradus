use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use smoltcp::wire::{IpAddress, IpCidr};
use yuhaiin_core::{BoxFuture, Error, ErrorKind, Result};

use crate::config::{
    ParsedConfig, ParsedPeer, WireGuardConfig, decode_key, error_protocol, error_protocol_debug,
};
use crate::{
    HANDSHAKE_BUFFER_SIZE, MAX_PACKET_SIZE, MAX_PENDING_IP_PACKETS, NEXT_TUNNEL_INDEX,
    WIREGUARD_OVERHEAD,
};

pub(crate) struct PeerTunnel {
    pub(crate) endpoint: SocketAddr,
    pub(crate) allowed_ips: Vec<IpCidr>,
    pub(crate) tunnel: Tunn,
    pub(crate) pending_packets: VecDeque<Vec<u8>>,
}

impl PeerTunnel {
    pub(crate) fn new(private_key: [u8; 32], peer: ParsedPeer) -> Self {
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
    pub(crate) peers: Vec<PeerTunnel>,
    pub(crate) reserved: Vec<u8>,
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

    pub(crate) fn new(parsed: ParsedConfig, private_key: [u8; 32]) -> Self {
        Self {
            peers: parsed
                .peers
                .into_iter()
                .map(|peer| PeerTunnel::new(private_key, peer))
                .collect(),
            reserved: parsed.reserved,
        }
    }

    pub(crate) fn peer_for_packet(&self, packet: &[u8]) -> Result<usize> {
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

    pub(crate) fn apply_reserved(&self, packet: &mut [u8]) {
        if self.reserved.len() == 3 && packet.len() >= 4 {
            packet[1..4].copy_from_slice(&self.reserved);
        }
    }

    pub(crate) fn encapsulate(&mut self, packet: &[u8]) -> Result<(usize, Vec<u8>)> {
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

    pub(crate) fn flush_pending_packets(&mut self, peer_index: usize) -> Vec<(usize, Vec<u8>)> {
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

    pub(crate) fn decapsulate(
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

    pub(crate) fn update_timers(&mut self) -> Vec<(usize, Vec<u8>)> {
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
pub(crate) enum DecapsulatedPacket {
    Done,
    Network(Vec<u8>),
    Tunnel(Vec<u8>),
}
