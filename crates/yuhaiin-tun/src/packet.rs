//! Packet parsing, fragmentation, reassembly, and the smoltcp device.

use super::*;
#[path = "packet_device.rs"]
mod device;
#[path = "packet_reassembly.rs"]
mod reassembly;

pub use device::{QueueRxToken, QueueTxToken, SmoltcpTunDevice};
pub use reassembly::Ipv6FragmentReassembler;
pub(crate) use reassembly::ipv6_has_fragment_header;

#[derive(Debug, Clone, Copy)]
pub(crate) struct TransportTuple {
    pub(crate) protocol: IpProtocol,
    pub(crate) source: SocketAddr,
    pub(crate) destination: SocketAddr,
    pub(crate) tcp_syn: bool,
}

pub(crate) fn parse_icmp_echo_request(packet: &[u8]) -> Result<Option<(SocketAddr, SocketAddr)>> {
    let version = IpVersion::of_packet(packet)
        .map_err(|_| Error::invalid("TUN packet is not IPv4 or IPv6"))?;
    match version {
        IpVersion::Ipv4 => {
            let packet = Ipv4Packet::new_checked(packet)
                .map_err(|_| Error::invalid("malformed IPv4 packet"))?;
            if packet.next_header() != IpProtocol::Icmp {
                return Ok(None);
            }
            let icmp = Icmpv4Packet::new_checked(packet.payload())
                .map_err(|_| Error::invalid("malformed TUN ICMPv4 packet"))?;
            let repr = Icmpv4Repr::parse(&icmp, &ChecksumCapabilities::default())
                .map_err(|_| Error::invalid("invalid TUN ICMPv4 checksum or message"))?;
            if !matches!(repr, Icmpv4Repr::EchoRequest { .. }) {
                return Ok(None);
            }
            Ok(Some((
                SocketAddr::new(IpAddr::V4(packet.src_addr()), 0),
                SocketAddr::new(IpAddr::V4(packet.dst_addr()), 0),
            )))
        }
        IpVersion::Ipv6 => {
            let packet = Ipv6Packet::new_checked(packet)
                .map_err(|_| Error::invalid("malformed IPv6 packet"))?;
            if packet.next_header() != IpProtocol::Icmpv6 {
                return Ok(None);
            }
            let source = packet.src_addr();
            let destination = packet.dst_addr();
            let icmp = Icmpv6Packet::new_checked(packet.payload())
                .map_err(|_| Error::invalid("malformed TUN ICMPv6 packet"))?;
            let repr = Icmpv6Repr::parse(
                &source,
                &destination,
                &icmp,
                &ChecksumCapabilities::default(),
            )
            .map_err(|_| Error::invalid("invalid TUN ICMPv6 checksum or message"))?;
            if !matches!(repr, Icmpv6Repr::EchoRequest { .. }) {
                return Ok(None);
            }
            Ok(Some((
                SocketAddr::new(IpAddr::V6(source), 0),
                SocketAddr::new(IpAddr::V6(destination), 0),
            )))
        }
    }
}

pub(crate) fn should_proxy_icmp_request(
    interface: &Interface,
    source: SocketAddr,
    destination: SocketAddr,
) -> bool {
    if destination.ip().is_loopback() {
        return false;
    }
    let source = IpAddress::from(source.ip());
    let destination = IpAddress::from(destination.ip());
    let source_is_local = interface
        .ip_addrs()
        .iter()
        .any(|cidr| cidr.contains_addr(&source));
    let destination_is_local = interface
        .ip_addrs()
        .iter()
        .any(|cidr| cidr.contains_addr(&destination));
    source_is_local && !destination_is_local
}

pub(crate) fn rewrite_icmp_echo_reply(packet: Vec<u8>, success: bool) -> Result<Vec<u8>> {
    let version = IpVersion::of_packet(&packet)
        .map_err(|_| Error::invalid("TUN ICMP packet is not IPv4 or IPv6"))?;
    match version {
        IpVersion::Ipv4 => {
            let (source, destination) = {
                let ip = Ipv4Packet::new_checked(&packet)
                    .map_err(|_| Error::invalid("malformed TUN ICMPv4 packet"))?;
                if ip.next_header() != IpProtocol::Icmp {
                    return Err(Error::invalid("TUN packet is not ICMPv4"));
                }
                let icmp = Icmpv4Packet::new_checked(ip.payload())
                    .map_err(|_| Error::invalid("malformed TUN ICMPv4 payload"))?;
                let repr = Icmpv4Repr::parse(&icmp, &ChecksumCapabilities::default())
                    .map_err(|_| Error::invalid("invalid TUN ICMPv4 echo request"))?;
                if !matches!(repr, Icmpv4Repr::EchoRequest { .. }) {
                    return Err(Error::invalid("TUN packet is not an ICMPv4 echo request"));
                }
                (ip.src_addr(), ip.dst_addr())
            };
            let mut output = packet;
            let mut ip = Ipv4Packet::new_unchecked(&mut output);
            ip.set_src_addr(destination);
            ip.set_dst_addr(source);
            {
                let mut icmp = Icmpv4Packet::new_unchecked(ip.payload_mut());
                icmp.set_msg_type(if success {
                    Icmpv4Message::EchoReply
                } else {
                    Icmpv4Message::DstUnreachable
                });
                icmp.fill_checksum();
            }
            ip.fill_checksum();
            Ok(output)
        }
        IpVersion::Ipv6 => {
            let (source, destination) = {
                let ip = Ipv6Packet::new_checked(&packet)
                    .map_err(|_| Error::invalid("malformed TUN ICMPv6 packet"))?;
                if ip.next_header() != IpProtocol::Icmpv6 {
                    return Err(Error::invalid("TUN packet is not ICMPv6"));
                }
                let source = ip.src_addr();
                let destination = ip.dst_addr();
                let icmp = Icmpv6Packet::new_checked(ip.payload())
                    .map_err(|_| Error::invalid("malformed TUN ICMPv6 payload"))?;
                let repr = Icmpv6Repr::parse(
                    &source,
                    &destination,
                    &icmp,
                    &ChecksumCapabilities::default(),
                )
                .map_err(|_| Error::invalid("invalid TUN ICMPv6 echo request"))?;
                if !matches!(repr, Icmpv6Repr::EchoRequest { .. }) {
                    return Err(Error::invalid("TUN packet is not an ICMPv6 echo request"));
                }
                (source, destination)
            };
            let mut output = packet;
            let mut ip = Ipv6Packet::new_unchecked(&mut output);
            ip.set_src_addr(destination);
            ip.set_dst_addr(source);
            {
                let mut icmp = Icmpv6Packet::new_unchecked(ip.payload_mut());
                icmp.set_msg_type(if success {
                    Icmpv6Message::EchoReply
                } else {
                    Icmpv6Message::DstUnreachable
                });
                icmp.fill_checksum(&destination, &source);
            }
            Ok(output)
        }
    }
}

pub(crate) fn parse_transport_tuple(packet: &[u8]) -> Result<Option<TransportTuple>> {
    let version = IpVersion::of_packet(packet)
        .map_err(|_| Error::invalid("TUN packet is not IPv4 or IPv6"))?;
    let normalized = if version == IpVersion::Ipv6 {
        normalize_ipv6_extension_headers(packet)?
    } else {
        Cow::Borrowed(packet)
    };
    let packet = normalized.as_ref();
    let (source, destination, protocol, payload) = match version {
        IpVersion::Ipv4 => {
            let packet = smoltcp::wire::Ipv4Packet::new_checked(packet)
                .map_err(|_| Error::invalid("malformed IPv4 packet"))?;
            (
                SocketAddr::new(IpAddr::V4(packet.src_addr()), 0),
                SocketAddr::new(IpAddr::V4(packet.dst_addr()), 0),
                packet.next_header(),
                packet.payload(),
            )
        }
        IpVersion::Ipv6 => {
            let packet = smoltcp::wire::Ipv6Packet::new_checked(packet)
                .map_err(|_| Error::invalid("malformed IPv6 packet"))?;
            (
                SocketAddr::new(IpAddr::V6(packet.src_addr()), 0),
                SocketAddr::new(IpAddr::V6(packet.dst_addr()), 0),
                packet.next_header(),
                packet.payload(),
            )
        }
    };
    match protocol {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(payload)
                .map_err(|_| Error::invalid("malformed TUN TCP packet"))?;
            Ok(Some(TransportTuple {
                protocol,
                source: SocketAddr::new(source.ip(), tcp.src_port()),
                destination: SocketAddr::new(destination.ip(), tcp.dst_port()),
                tcp_syn: tcp.syn(),
            }))
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(payload)
                .map_err(|_| Error::invalid("malformed TUN UDP packet"))?;
            Ok(Some(TransportTuple {
                protocol,
                source: SocketAddr::new(source.ip(), udp.src_port()),
                destination: SocketAddr::new(destination.ip(), udp.dst_port()),
                tcp_syn: false,
            }))
        }
        _ => Ok(None),
    }
}

pub fn inspect_ip_packet(packet: &[u8]) -> Result<PacketInfo> {
    if packet.is_empty() {
        return Err(Error::invalid("TUN packet is empty"));
    }
    let version = IpVersion::of_packet(packet)
        .map_err(|_| Error::invalid("TUN packet is not IPv4 or IPv6"))?;
    let fragmented = match version {
        IpVersion::Ipv4 => {
            let packet = smoltcp::wire::Ipv4Packet::new_checked(packet)
                .map_err(|_| Error::invalid("malformed IPv4 packet"))?;
            packet.more_frags() || packet.frag_offset() != 0
        }
        IpVersion::Ipv6 => {
            let packet = smoltcp::wire::Ipv6Packet::new_checked(packet)
                .map_err(|_| Error::invalid("malformed IPv6 packet"))?;
            ipv6_has_fragment_header(packet.into_inner())
        }
    };
    Ok(PacketInfo {
        version: match version {
            IpVersion::Ipv4 => IpPacketVersion::V4,
            IpVersion::Ipv6 => IpPacketVersion::V6,
        },
        length: packet.len(),
        fragmented,
    })
}

/// Validate a packet against the TUN MTU.
///
/// A fragmented IP datagram is represented by multiple wire packets, and
/// each packet must fit the interface MTU independently. This helper keeps
/// that behavior explicit for both real `AsyncDevice` reads and injected
/// devices used by Android/iOS hosts. IPv4 reassembly itself is handled by
/// smoltcp's bounded reassembly buffer when the packet reaches the interface.
pub fn inspect_ip_packet_with_mtu(packet: &[u8], mtu: usize) -> Result<PacketInfo> {
    if !(576..=9216).contains(&mtu) {
        return Err(Error::invalid("TUN MTU must be between 576 and 9216"));
    }
    let info = inspect_ip_packet(packet)?;
    if info.length > mtu {
        return Err(Error::invalid("TUN packet exceeds configured MTU"));
    }
    Ok(info)
}

pub(crate) fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32;
        sum += word;
    }
    while sum > u16::MAX as u32 {
        sum = (sum & u16::MAX as u32) + (sum >> 16);
    }
    !(sum as u16)
}

/// Fragment one complete IP datagram into packets accepted by the real TUN
/// MTU.
///
/// smoltcp 0.13 has IPv4 fragmentation support but drops oversized IPv6
/// output. Keeping the stack's output as one complete datagram and applying
/// the wire-format operation here gives both families the same behavior.
/// IPv6 extension headers that belong to the unfragmentable part are copied
/// into every fragment; a destination-options header after a routing header is
/// left in the fragmentable part as required by the wire format.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ipv6FragmentLayout<'a> {
    unfragmentable_prefix: &'a [u8],
    previous_next_header_offset: usize,
    next_header: u8,
    fragmentable_part: &'a [u8],
}

pub(crate) fn ipv6_fragment_layout(
    packet: &[u8],
    total_len: usize,
) -> Result<Ipv6FragmentLayout<'_>> {
    let mut next_header = packet[6];
    let mut previous_next_header_offset = 6usize;
    let mut offset = 40usize;
    let mut saw_routing_header = false;

    // IPv6 permits a bounded extension-header chain in practice. Do not walk
    // an attacker-controlled chain indefinitely while preparing a packet for
    // the TUN device.
    for _ in 0..16 {
        match next_header {
            44 => {
                return Err(Error::invalid(
                    "cannot re-fragment an already-fragmented IPv6 packet",
                ));
            }
            0 => {
                if offset != 40 {
                    return Err(Error::invalid(
                        "IPv6 hop-by-hop header is not the first extension header",
                    ));
                }
                if offset + 2 > total_len {
                    return Err(Error::invalid("truncated IPv6 extension header"));
                }
                let header_len = (packet[offset + 1] as usize + 1) * 8;
                if header_len < 8 || offset + header_len > total_len {
                    return Err(Error::invalid("invalid IPv6 extension header length"));
                }
                previous_next_header_offset = offset;
                next_header = packet[offset];
                offset += header_len;
            }
            43 => {
                if offset + 2 > total_len {
                    return Err(Error::invalid("truncated IPv6 routing header"));
                }
                let header_len = (packet[offset + 1] as usize + 1) * 8;
                if header_len < 8 || offset + header_len > total_len {
                    return Err(Error::invalid("invalid IPv6 routing header length"));
                }
                saw_routing_header = true;
                previous_next_header_offset = offset;
                next_header = packet[offset];
                offset += header_len;
            }
            60 => {
                if saw_routing_header {
                    // Destination options after Routing are part of the
                    // fragmentable portion. They occur only in the first
                    // fragment and are reconstructed with the rest of the
                    // datagram by the receiver.
                    return Ok(Ipv6FragmentLayout {
                        unfragmentable_prefix: &packet[..offset],
                        previous_next_header_offset,
                        next_header,
                        fragmentable_part: &packet[offset..total_len],
                    });
                }
                if offset + 2 > total_len {
                    return Err(Error::invalid("truncated IPv6 destination header"));
                }
                let header_len = (packet[offset + 1] as usize + 1) * 8;
                if header_len < 8 || offset + header_len > total_len {
                    return Err(Error::invalid("invalid IPv6 destination header length"));
                }
                previous_next_header_offset = offset;
                next_header = packet[offset];
                offset += header_len;
            }
            // AH and ESP must follow the Fragment header in a fragmented
            // packet. Treat them as the beginning of the fragmentable part;
            // their bytes are never guessed or rewritten here.
            50 | 51 => {
                return Ok(Ipv6FragmentLayout {
                    unfragmentable_prefix: &packet[..offset],
                    previous_next_header_offset,
                    next_header,
                    fragmentable_part: &packet[offset..total_len],
                });
            }
            // Mobility, HIP, Shim6 and an upper-layer protocol are not
            // headers that this boundary needs to parse. Keeping them in the
            // fragmentable part preserves their bytes and avoids claiming a
            // layout we cannot validate.
            _ => {
                return Ok(Ipv6FragmentLayout {
                    unfragmentable_prefix: &packet[..offset],
                    previous_next_header_offset,
                    next_header,
                    fragmentable_part: &packet[offset..total_len],
                });
            }
        }
    }
    Err(Error::invalid("IPv6 extension header chain is too long"))
}

/// Fragment one complete IPv4 or IPv6 datagram for a wire MTU.
///
/// The returned packets are individually bounded by `mtu`. IPv4 and IPv6
/// use the same boundary API so callers such as the native TUN runtime and a
/// WireGuard virtual interface cannot accidentally implement different MTU
/// behavior.
pub fn fragment_ip_packet(packet: &[u8], mtu: usize, identification: u32) -> Result<Vec<Vec<u8>>> {
    if !(576..=9216).contains(&mtu) {
        return Err(Error::invalid("TUN MTU must be between 576 and 9216"));
    }
    if packet.is_empty() {
        return Err(Error::invalid("cannot fragment an empty IP packet"));
    }

    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return Err(Error::invalid("malformed IPv4 packet"));
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < 20 || header_len > packet.len() {
                return Err(Error::invalid("malformed IPv4 header length"));
            }
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            if total_len < header_len || total_len > packet.len() {
                return Err(Error::invalid("malformed IPv4 total length"));
            }
            if total_len <= mtu {
                return Ok(vec![packet[..total_len].to_vec()]);
            }

            let flags_and_offset = u16::from_be_bytes([packet[6], packet[7]]);
            if flags_and_offset & 0x3fff != 0 {
                return Err(Error::invalid(
                    "cannot re-fragment an already-fragmented IPv4 packet",
                ));
            }
            let max_payload = ((mtu - header_len) / 8) * 8;
            if max_payload == 0 {
                return Err(Error::invalid("TUN MTU cannot carry an IPv4 fragment"));
            }
            let payload = &packet[header_len..total_len];
            let mut fragments = Vec::new();
            let mut offset = 0usize;
            while offset < payload.len() {
                let remaining = payload.len() - offset;
                let chunk_len = remaining.min(max_payload);
                let more_fragments = offset + chunk_len < payload.len();
                if offset / 8 > 0x1fff {
                    return Err(Error::invalid("IPv4 fragment offset exceeds wire format"));
                }
                let fragment_len = header_len + chunk_len;
                let mut fragment = vec![0u8; fragment_len];
                fragment[..header_len].copy_from_slice(&packet[..header_len]);
                fragment[header_len..].copy_from_slice(&payload[offset..offset + chunk_len]);
                fragment[2..4].copy_from_slice(&(fragment_len as u16).to_be_bytes());
                fragment[4..6].copy_from_slice(&(identification as u16).to_be_bytes());
                let reserved = flags_and_offset & 0x8000;
                // smoltcp's IPv4 Repr emits DF by default.  This function is
                // only called for packets freshly produced by that stack, so
                // the TUN boundary owns the final fragmentation decision and
                // deliberately clears DF here.
                let flags =
                    reserved | if more_fragments { 0x2000 } else { 0 } | (offset as u16 / 8);
                fragment[6..8].copy_from_slice(&flags.to_be_bytes());
                fragment[10..12].fill(0);
                let checksum = ipv4_header_checksum(&fragment[..header_len]);
                fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
                fragments.push(fragment);
                offset += chunk_len;
            }
            Ok(fragments)
        }
        6 => {
            if packet.len() < 40 {
                return Err(Error::invalid("malformed IPv6 packet"));
            }
            let total_len = 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            if total_len < 40 || total_len > packet.len() {
                return Err(Error::invalid("malformed IPv6 payload length"));
            }
            if total_len <= mtu {
                return Ok(vec![packet[..total_len].to_vec()]);
            }
            let layout = ipv6_fragment_layout(&packet[..total_len], total_len)?;
            let fragment_header_offset = layout.unfragmentable_prefix.len();
            let fragment_overhead = fragment_header_offset
                .checked_add(8)
                .ok_or_else(|| Error::invalid("IPv6 fragment length overflow"))?;
            let max_payload = if fragment_overhead >= mtu {
                0
            } else {
                ((mtu - fragment_overhead) / 8) * 8
            };
            if max_payload == 0 {
                return Err(Error::invalid("TUN MTU cannot carry an IPv6 fragment"));
            }
            let payload = layout.fragmentable_part;
            let mut fragments = Vec::new();
            let mut offset = 0usize;
            while offset < payload.len() {
                let remaining = payload.len() - offset;
                let chunk_len = remaining.min(max_payload);
                let more_fragments = offset + chunk_len < payload.len();
                if offset / 8 > 0x1fff {
                    return Err(Error::invalid("IPv6 fragment offset exceeds wire format"));
                }
                let fragment_len = fragment_header_offset + 8 + chunk_len;
                let mut fragment = vec![0u8; fragment_len];
                fragment[..fragment_header_offset].copy_from_slice(layout.unfragmentable_prefix);
                fragment[layout.previous_next_header_offset] = 44; // Fragment Header
                fragment[4..6].copy_from_slice(&((fragment_len - 40) as u16).to_be_bytes());
                let fragment_header = fragment_header_offset;
                fragment[fragment_header] = layout.next_header;
                let offset_and_flags = ((offset as u16 / 8) << 3) | u16::from(more_fragments);
                fragment[fragment_header + 2..fragment_header + 4]
                    .copy_from_slice(&offset_and_flags.to_be_bytes());
                fragment[fragment_header + 4..fragment_header + 8]
                    .copy_from_slice(&identification.to_be_bytes());
                fragment[fragment_header + 8..]
                    .copy_from_slice(&payload[offset..offset + chunk_len]);
                fragments.push(fragment);
                offset += chunk_len;
            }
            Ok(fragments)
        }
        _ => Err(Error::invalid("packet is not IPv4 or IPv6")),
    }
}
