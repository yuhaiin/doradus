//! Packet parsing, fragmentation, reassembly, and the smoltcp device.

use super::*;

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

pub(crate) fn fragment_ip_packet(
    packet: &[u8],
    mtu: usize,
    identification: u32,
) -> Result<Vec<Vec<u8>>> {
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

#[derive(Debug, Clone, Copy)]
pub(crate) struct Ipv6FragmentMetadata<'a> {
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identification: u32,
    fragment_offset: usize,
    more_fragments: bool,
    next_header: u8,
    previous_next_header_offset: usize,
    unfragmentable_prefix: &'a [u8],
    payload: &'a [u8],
}

pub(crate) fn parse_ipv6_fragment_metadata(
    bytes: &[u8],
) -> Result<Option<Ipv6FragmentMetadata<'_>>> {
    if bytes.is_empty() || bytes[0] >> 4 != 6 {
        return Ok(None);
    }
    if bytes.len() < 40 {
        return Err(Error::invalid("malformed IPv6 packet"));
    }
    let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let packet_len = 40usize
        .checked_add(payload_len)
        .ok_or_else(|| Error::invalid("IPv6 packet length overflow"))?;
    if packet_len > bytes.len() {
        return Err(Error::invalid("malformed IPv6 packet length"));
    }
    let bytes = &bytes[..packet_len];
    let source = Ipv6Addr::from(
        <[u8; 16]>::try_from(&bytes[8..24])
            .map_err(|_| Error::invalid("malformed IPv6 source address"))?,
    );
    let destination = Ipv6Addr::from(
        <[u8; 16]>::try_from(&bytes[24..40])
            .map_err(|_| Error::invalid("malformed IPv6 destination address"))?,
    );
    let mut next_header = bytes[6];
    let mut previous_next_header_offset = 6usize;
    let mut offset = 40usize;

    // Hop-by-hop, routing and destination options are TLV extension headers
    // whose length is expressed in eight-octet units. AH uses four-octet
    // units. Stop at ESP/unknown headers rather than guessing offsets from
    // attacker-controlled bytes.
    for _ in 0..16 {
        match next_header {
            44 => {
                if offset + 8 > bytes.len() {
                    return Err(Error::invalid("truncated IPv6 fragment header"));
                }
                let raw_offset_and_flags =
                    u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
                let fragment_offset = ((raw_offset_and_flags >> 3) as usize) * 8;
                let more_fragments = raw_offset_and_flags & 1 != 0;
                let fragment_payload = &bytes[offset + 8..];
                if more_fragments
                    && (fragment_payload.is_empty() || !fragment_payload.len().is_multiple_of(8))
                {
                    return Err(Error::invalid("invalid IPv6 fragment payload alignment"));
                }
                // RFC 8200 permits an atomic fragment, but it is not a
                // reassembly input. Passing it through preserves the raw
                // packet contract; smoltcp will decide whether the following
                // extension chain is supported.
                if fragment_offset == 0 && !more_fragments {
                    return Ok(None);
                }
                return Ok(Some(Ipv6FragmentMetadata {
                    source,
                    destination,
                    identification: u32::from_be_bytes([
                        bytes[offset + 4],
                        bytes[offset + 5],
                        bytes[offset + 6],
                        bytes[offset + 7],
                    ]),
                    fragment_offset,
                    more_fragments,
                    next_header: bytes[offset],
                    previous_next_header_offset,
                    unfragmentable_prefix: &bytes[..offset],
                    payload: fragment_payload,
                }));
            }
            0 | 43 | 60 => {
                if offset + 2 > bytes.len() {
                    return Err(Error::invalid("truncated IPv6 extension header"));
                }
                let header_len = (bytes[offset + 1] as usize + 1) * 8;
                if header_len < 8 || offset + header_len > bytes.len() {
                    return Err(Error::invalid("invalid IPv6 extension header length"));
                }
                previous_next_header_offset = offset;
                next_header = bytes[offset];
                offset += header_len;
            }
            51 => {
                if offset + 2 > bytes.len() {
                    return Err(Error::invalid("truncated IPv6 AH header"));
                }
                let header_len = (bytes[offset + 1] as usize + 2) * 4;
                if header_len < 12 || offset + header_len > bytes.len() {
                    return Err(Error::invalid("invalid IPv6 AH header length"));
                }
                previous_next_header_offset = offset;
                next_header = bytes[offset];
                offset += header_len;
            }
            _ => return Ok(None),
        }
    }
    Err(Error::invalid("IPv6 extension header chain is too long"))
}

pub(crate) fn ipv6_has_fragment_header(bytes: &[u8]) -> bool {
    parse_ipv6_fragment_metadata(bytes).ok().flatten().is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Ipv6FragmentKey {
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identification: u32,
    next_header: u8,
}

#[derive(Debug)]
pub(crate) struct Ipv6FragmentPiece {
    start: usize,
    end: usize,
    payload: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct Ipv6FragmentAssembly {
    unfragmentable_prefix: Vec<u8>,
    previous_next_header_offset: usize,
    next_header: u8,
    pieces: Vec<Ipv6FragmentPiece>,
    received_bytes: usize,
    total_payload: Option<usize>,
    expires_at: StdInstant,
}

impl Ipv6FragmentAssembly {
    fn complete(&self) -> Option<usize> {
        let total = self.total_payload?;
        let mut pieces = self
            .pieces
            .iter()
            .map(|piece| (piece.start, piece.end))
            .collect::<Vec<_>>();
        pieces.sort_unstable_by_key(|(start, _)| *start);
        let mut covered = 0usize;
        for (start, end) in pieces {
            if start != covered {
                return None;
            }
            covered = end;
        }
        (covered == total).then_some(total)
    }

    fn finish(self, total_payload: usize) -> Option<Vec<u8>> {
        let payload_length = self
            .unfragmentable_prefix
            .len()
            .checked_sub(40)?
            .checked_add(total_payload)?;
        if payload_length > u16::MAX as usize {
            return None;
        }
        let mut packet = self.unfragmentable_prefix;
        packet[self.previous_next_header_offset] = self.next_header;
        packet[4..6].copy_from_slice(&(payload_length as u16).to_be_bytes());
        let payload_start = packet.len();
        packet.resize(payload_start + total_payload, 0);
        for piece in self.pieces {
            packet[payload_start + piece.start..payload_start + piece.end]
                .copy_from_slice(&piece.payload);
        }
        Some(packet)
    }
}

pub(crate) fn ipv6_unfragmentable_prefixes_match(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.get(..4) == right.get(..4) && left.get(6..) == right.get(6..)
}

#[derive(Debug, Default)]
pub(crate) struct Ipv6FragmentReassembler {
    pub(crate) assemblies: HashMap<Ipv6FragmentKey, Ipv6FragmentAssembly>,
}

impl Ipv6FragmentReassembler {
    pub(crate) fn expire(&mut self, now: StdInstant) {
        self.assemblies
            .retain(|_, assembly| assembly.expires_at > now);
    }

    /// Return the packet to enqueue, or `None` for an incomplete/invalid
    /// assembly. Invalid and resource-exhausted fragments are intentionally
    /// dropped without poisoning the TUN runtime.
    pub(crate) fn push(&mut self, packet: &[u8], now: StdInstant) -> Result<Option<Vec<u8>>> {
        self.expire(now);
        let Some(metadata) = parse_ipv6_fragment_metadata(packet)? else {
            return Ok(Some(packet.to_vec()));
        };
        let fragment_end = metadata
            .fragment_offset
            .checked_add(metadata.payload.len())
            .ok_or_else(|| Error::invalid("IPv6 fragment offset overflow"))?;
        if fragment_end > IPV6_FRAGMENT_MAX_PACKET
            || metadata.unfragmentable_prefix.len() > IPV6_FRAGMENT_MAX_PACKET
            || metadata
                .unfragmentable_prefix
                .len()
                .saturating_add(fragment_end)
                > IPV6_FRAGMENT_MAX_PACKET
        {
            return Ok(None);
        }
        let key = Ipv6FragmentKey {
            source: metadata.source,
            destination: metadata.destination,
            identification: metadata.identification,
            next_header: metadata.next_header,
        };
        if !self.assemblies.contains_key(&key) {
            if self.assemblies.len() >= IPV6_FRAGMENT_MAX_ENTRIES {
                return Ok(None);
            }
            self.assemblies.insert(
                key,
                Ipv6FragmentAssembly {
                    unfragmentable_prefix: metadata.unfragmentable_prefix.to_vec(),
                    previous_next_header_offset: metadata.previous_next_header_offset,
                    next_header: metadata.next_header,
                    pieces: Vec::new(),
                    received_bytes: 0,
                    total_payload: None,
                    expires_at: now + IPV6_FRAGMENT_TIMEOUT,
                },
            );
        }

        let Some(assembly) = self.assemblies.get_mut(&key) else {
            return Ok(None);
        };
        if !ipv6_unfragmentable_prefixes_match(
            &assembly.unfragmentable_prefix,
            metadata.unfragmentable_prefix,
        ) || assembly.previous_next_header_offset != metadata.previous_next_header_offset
            || assembly.next_header != metadata.next_header
            || assembly.pieces.len() >= IPV6_FRAGMENT_MAX_FRAGMENTS
            || assembly
                .received_bytes
                .saturating_add(metadata.payload.len())
                > IPV6_FRAGMENT_MAX_PACKET
        {
            self.assemblies.remove(&key);
            return Ok(None);
        }
        if assembly
            .pieces
            .iter()
            .any(|piece| metadata.fragment_offset < piece.end && fragment_end > piece.start)
        {
            // Overlap handling is deliberately fail-closed. Accepting either
            // first- or last-fragment bytes creates ambiguous security policy.
            self.assemblies.remove(&key);
            return Ok(None);
        }
        if let Some(total) = assembly.total_payload
            && fragment_end > total
        {
            self.assemblies.remove(&key);
            return Ok(None);
        }
        if !metadata.more_fragments {
            if let Some(total) = assembly.total_payload
                && total != fragment_end
            {
                self.assemblies.remove(&key);
                return Ok(None);
            }
            assembly.total_payload = Some(fragment_end);
        }
        assembly.received_bytes += metadata.payload.len();
        assembly.pieces.push(Ipv6FragmentPiece {
            start: metadata.fragment_offset,
            end: fragment_end,
            payload: metadata.payload.to_vec(),
        });
        let Some(total) = assembly.complete() else {
            return Ok(None);
        };
        let assembly = self.assemblies.remove(&key).expect("assembly exists");
        Ok(assembly.finish(total))
    }
}

#[derive(Debug, Default)]
pub(crate) struct PacketQueue {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl PacketQueue {
    fn new(capacity: usize) -> Self {
        Self {
            rx: VecDeque::with_capacity(capacity),
            tx: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push_rx(&mut self, packet: Vec<u8>) -> bool {
        if self.rx.len() >= self.capacity {
            return false;
        }
        self.rx.push_back(packet);
        true
    }

    fn push_tx(&mut self, packet: Vec<u8>) -> bool {
        if self.tx.len() >= self.capacity {
            return false;
        }
        self.tx.push_back(packet);
        true
    }

    fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }

    fn pop_rx(&mut self) -> Option<Vec<u8>> {
        self.rx.pop_front()
    }
}

pub struct QueueRxToken {
    packet: Vec<u8>,
}

impl phy::RxToken for QueueRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

pub struct QueueTxToken {
    queue: Arc<Mutex<PacketQueue>>,
    timestamp: Instant,
    max_packet_size: usize,
}

impl phy::TxToken for QueueTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        if len <= self.max_packet_size
            && let Ok(mut queue) = self.queue.lock()
        {
            let _ = queue.push_tx(packet);
        }
        let _ = self.timestamp;
        result
    }
}

/// A smoltcp `Device` backed by bounded in-memory queues.
///
/// Async TUN I/O is deliberately kept outside smoltcp's synchronous token API:
/// `recv_from_tun` fills the RX queue and `send_to_tun` drains the TX queue.
/// This keeps the runtime boundary small and makes the packet engine testable
/// with no privileged TUN device.
pub struct SmoltcpTunDevice {
    queue: Arc<Mutex<PacketQueue>>,
    mtu: usize,
}

impl SmoltcpTunDevice {
    pub fn new(mtu: usize, queue_capacity: usize) -> Result<Self> {
        if !(576..=9216).contains(&mtu) || queue_capacity == 0 {
            return Err(Error::invalid("invalid smoltcp TUN device configuration"));
        }
        Ok(Self {
            queue: Arc::new(Mutex::new(PacketQueue::new(queue_capacity))),
            mtu,
        })
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn enqueue_rx(&self, packet: Vec<u8>) -> Result<bool> {
        inspect_ip_packet_with_mtu(&packet, self.mtu)?;
        self.enqueue_rx_validated(packet)
    }

    pub(crate) fn enqueue_tx(&self, packet: Vec<u8>) -> Result<bool> {
        inspect_ip_packet_with_mtu(&packet, self.mtu)?;
        self.queue
            .lock()
            .map(|mut queue| queue.push_tx(packet))
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    /// Enqueue a packet reassembled from IPv6 wire fragments.
    ///
    /// A reassembled datagram is allowed to be larger than the interface MTU;
    /// only each individual packet crossing the TUN boundary must fit that
    /// MTU.  Keep this path separate from [`Self::enqueue_rx`] so a caller
    /// cannot accidentally bypass the wire-packet validation for ordinary
    /// TUN input.
    pub(crate) fn enqueue_rx_reassembled(&self, packet: Vec<u8>) -> Result<bool> {
        inspect_ip_packet(&packet)?;
        if packet.len() > MAX_SMOLTCP_PACKET_SIZE {
            return Err(Error::invalid("reassembled TUN packet is too large"));
        }
        self.enqueue_rx_validated(packet)
    }

    fn enqueue_rx_validated(&self, packet: Vec<u8>) -> Result<bool> {
        self.queue
            .lock()
            .map(|mut queue| queue.push_rx(packet))
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    pub fn take_tx(&self) -> Result<Option<Vec<u8>>> {
        self.queue
            .lock()
            .map(|mut queue| queue.pop_tx())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    /// Inspect the next TX packet without removing it.
    pub fn peek_tx_packet(&self) -> Result<Option<Vec<u8>>> {
        self.queue
            .lock()
            .map(|queue| queue.tx.front().cloned())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    /// Inspect the next RX packet without removing it.
    ///
    /// This is primarily useful for a dispatcher that must choose an ICMP
    /// identifier or another socket before handing the packet to smoltcp.
    pub fn peek_rx_packet(&self) -> Result<Option<Vec<u8>>> {
        self.queue
            .lock()
            .map(|queue| queue.rx.front().cloned())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    /// Remove the next RX packet without handing it to smoltcp.
    ///
    /// A dispatcher may use this for packets it deliberately handles outside
    /// the socket set, or for control traffic that is not part of the current
    /// protocol loop. Normal data-plane code should let `Interface::poll`
    /// consume the queue instead.
    pub fn take_rx_packet(&self) -> Result<Option<Vec<u8>>> {
        self.queue
            .lock()
            .map(|mut queue| queue.pop_rx())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    pub fn queued_rx(&self) -> Result<usize> {
        self.queue
            .lock()
            .map(|queue| queue.rx.len())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    pub fn queued_tx(&self) -> Result<usize> {
        self.queue
            .lock()
            .map(|queue| queue.tx.len())
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))
    }

    pub(crate) fn drop_multicast_rx_packets(&self) -> Result<usize> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| Error::new(crate::ErrorKind::Io, "TUN packet queue poisoned"))?;
        let packets: Vec<_> = queue.rx.drain(..).collect();
        let mut keep = Vec::with_capacity(packets.len());
        let mut dropped = 0;
        for packet in &packets {
            match ip_packet_has_multicast_destination(packet) {
                Ok(true) => {
                    dropped += 1;
                    keep.push(false);
                }
                Ok(false) => keep.push(true),
                Err(error) => {
                    queue.rx.extend(packets);
                    return Err(error);
                }
            }
        }
        queue.rx.extend(
            packets
                .into_iter()
                .zip(keep)
                .filter_map(|(packet, keep)| keep.then_some(packet)),
        );
        Ok(dropped)
    }
}

impl phy::Device for SmoltcpTunDevice {
    type RxToken<'a> = QueueRxToken;
    type TxToken<'a> = QueueTxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        // Do not advertise the OS wire MTU here.  smoltcp 0.13 drops an
        // oversized IPv6 packet instead of fragmenting it.  We keep the
        // complete datagram in this bounded queue and fragment both IP
        // versions at the asynchronous TUN boundary below.
        capabilities.max_transmission_unit = MAX_SMOLTCP_PACKET_SIZE;
        capabilities.medium = Medium::Ip;
        capabilities.checksum = ChecksumCapabilities::default();
        capabilities
    }

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.queue.lock().ok()?.rx.pop_front()?;
        Some((
            QueueRxToken { packet },
            QueueTxToken {
                queue: Arc::clone(&self.queue),
                timestamp,
                max_packet_size: MAX_SMOLTCP_PACKET_SIZE,
            },
        ))
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let queue = self.queue.lock().ok()?;
        if queue.tx.len() >= queue.capacity {
            return None;
        }
        drop(queue);
        Some(QueueTxToken {
            queue: Arc::clone(&self.queue),
            timestamp,
            max_packet_size: MAX_SMOLTCP_PACKET_SIZE,
        })
    }
}
