//! Yuubinsya wire formats: authenticated UDP packets and UDP-over-TCP frames.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sha2::{Digest, Sha256};

use doradus_core::{DomainName, Endpoint, Error, ErrorKind, Network, Result};

pub const MAX_SEGMENT_SIZE: usize = 64 * 1024 - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum YuubinsyaProtocol {
    Tcp = 2,
    Ping = 4,
    Udp = 5,
    UdpWithMigrateId = 6,
}
impl YuubinsyaProtocol {
    pub fn from_byte(value: u8) -> Result<Self> {
        match value & 0b111 {
            2 => Ok(Self::Tcp),
            4 => Ok(Self::Ping),
            5 => Ok(Self::Udp),
            6 => Ok(Self::UdpWithMigrateId),
            _ => Err(Error::new(
                ErrorKind::Protocol,
                "unknown Yuubinsya protocol",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YuubinsyaHeader {
    pub protocol: YuubinsyaProtocol,
    pub migrate_id: Option<u64>,
    pub destination: Option<Endpoint>,
}

pub fn derive_salt(password: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update(b"+s@1t");
    hasher.finalize().into()
}

pub fn encode_header(password_hash: &[u8], header: &YuubinsyaHeader) -> Result<Vec<u8>> {
    if password_hash.len() != 32 {
        return Err(Error::invalid("Yuubinsya password hash must be 32 bytes"));
    }
    let protocol = header.protocol;
    if matches!(protocol, YuubinsyaProtocol::UdpWithMigrateId) && header.migrate_id.is_none() {
        return Err(Error::invalid(
            "Yuubinsya migrate protocol needs migrate_id",
        ));
    }
    if matches!(protocol, YuubinsyaProtocol::Tcp | YuubinsyaProtocol::Ping)
        && header.destination.is_none()
    {
        return Err(Error::invalid("Yuubinsya TCP/Ping needs destination"));
    }
    let mut output = vec![protocol as u8];
    if let Some(migrate_id) = header.migrate_id {
        output.extend_from_slice(&migrate_id.to_be_bytes());
    }
    output.extend_from_slice(password_hash);
    if let Some(destination) = &header.destination {
        encode_endpoint(destination, &mut output)?;
    }
    Ok(output)
}

pub fn decode_header(password_hash: &[u8], packet: &[u8]) -> Result<(YuubinsyaHeader, usize)> {
    if password_hash.len() != 32 || packet.len() < 33 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Yuubinsya header is truncated",
        ));
    }
    let protocol = YuubinsyaProtocol::from_byte(packet[0])?;
    let mut cursor = 1;
    let migrate_id = if matches!(protocol, YuubinsyaProtocol::UdpWithMigrateId) {
        let bytes = take(packet, &mut cursor, 8)?;
        Some(u64::from_be_bytes(bytes.try_into().unwrap()))
    } else {
        None
    };
    let expected = take(packet, &mut cursor, 32)?;
    if !constant_time_eq(expected, password_hash) {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Yuubinsya password is incorrect",
        ));
    }
    let destination = if matches!(protocol, YuubinsyaProtocol::Tcp | YuubinsyaProtocol::Ping) {
        Some(decode_endpoint(packet, &mut cursor, Network::Tcp)?)
    } else {
        None
    };
    Ok((
        YuubinsyaHeader {
            protocol,
            migrate_id,
            destination,
        },
        cursor,
    ))
}

/// Decode a header against a bounded set of accepted password hashes and
/// return the hash that authenticated it. The selected hash is copied into
/// the session, so later framing keeps the same authentication key without
/// retaining the whole credential set.
pub fn decode_header_any(
    password_hashes: &[[u8; 32]],
    packet: &[u8],
) -> Result<(YuubinsyaHeader, usize, [u8; 32])> {
    if packet.is_empty() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Yuubinsya header is truncated",
        ));
    }
    let protocol = YuubinsyaProtocol::from_byte(packet[0])?;
    let password_offset = if matches!(protocol, YuubinsyaProtocol::UdpWithMigrateId) {
        9
    } else {
        1
    };
    let expected = packet
        .get(password_offset..password_offset + 32)
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "Yuubinsya header is truncated"))?;
    let mut selected = [0u8; 32];
    let mut found = 0u8;
    for candidate in password_hashes {
        let matched = u8::from(constant_time_eq(expected, candidate));
        let mask = 0u8.wrapping_sub(matched);
        for (selected_byte, candidate_byte) in selected.iter_mut().zip(candidate) {
            *selected_byte = (*selected_byte & !mask) | (*candidate_byte & mask);
        }
        found |= matched;
    }
    if found == 0 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Yuubinsya password is incorrect",
        ));
    }
    let (header, consumed) = decode_header(&selected, packet)?;
    Ok((header, consumed, selected))
}

pub fn encode_udp_packet(
    password_hash: &[u8],
    destination: &Endpoint,
    payload: &[u8],
    socks5_prefix: bool,
) -> Result<Vec<u8>> {
    if password_hash.len() != 32 {
        return Err(Error::invalid("Yuubinsya password hash must be 32 bytes"));
    }
    if payload.len() > MAX_SEGMENT_SIZE {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Yuubinsya UDP payload too large",
        ));
    }
    let mut output = Vec::with_capacity(password_hash.len() + 3 + 260 + payload.len());
    output.extend_from_slice(password_hash);
    if socks5_prefix {
        output.extend_from_slice(&[0, 0, 0]);
    }
    encode_endpoint(destination, &mut output)?;
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn decode_udp_packet<'a>(
    password_hash: &[u8],
    packet: &'a [u8],
    socks5_prefix: bool,
) -> Result<(Endpoint, &'a [u8])> {
    let password_hash: [u8; 32] = password_hash
        .try_into()
        .map_err(|_| Error::invalid("Yuubinsya password hash must be 32 bytes"))?;
    let (destination, payload, _) =
        decode_udp_packet_any(std::slice::from_ref(&password_hash), packet, socks5_prefix)?;
    Ok((destination, payload))
}

/// Decode a native UDP packet against multiple accepted hashes and return the
/// hash that authenticated it. The caller can use that hash for the response
/// packet, preserving per-user authentication on a shared UDP socket.
pub fn decode_udp_packet_any<'a>(
    password_hashes: &[[u8; 32]],
    packet: &'a [u8],
    socks5_prefix: bool,
) -> Result<(Endpoint, &'a [u8], [u8; 32])> {
    let expected = packet
        .get(..32)
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "Yuubinsya UDP packet is truncated"))?;
    let mut selected = [0u8; 32];
    let mut found = 0u8;
    for candidate in password_hashes {
        let matched = u8::from(constant_time_eq(expected, candidate));
        let mask = 0u8.wrapping_sub(matched);
        for (selected_byte, candidate_byte) in selected.iter_mut().zip(candidate) {
            *selected_byte = (*selected_byte & !mask) | (*candidate_byte & mask);
        }
        found |= matched;
    }
    if found == 0 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Yuubinsya password is incorrect",
        ));
    }
    let mut cursor = 32;
    if socks5_prefix && take(packet, &mut cursor, 3)? != [0, 0, 0] {
        return Err(Error::new(
            ErrorKind::Protocol,
            "invalid Yuubinsya SOCKS5 prefix",
        ));
    }
    let destination = decode_endpoint(packet, &mut cursor, Network::Udp)?;
    Ok((destination, &packet[cursor..], selected))
}

pub fn encode_uot_frame(destination: &Endpoint, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(Error::new(ErrorKind::InvalidInput, "UOT payload too large"));
    }
    let mut output = Vec::with_capacity(260 + 2 + payload.len());
    encode_endpoint(destination, &mut output)?;
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn decode_uot_frame(packet: &[u8]) -> Result<(Endpoint, &[u8], usize)> {
    let mut cursor = 0;
    let destination = decode_endpoint(packet, &mut cursor, Network::Udp)?;
    let length = u16::from_be_bytes(take(packet, &mut cursor, 2)?.try_into().unwrap()) as usize;
    let payload = take(packet, &mut cursor, length)?;
    Ok((destination, payload, cursor))
}

/// Encode the SOCKS-style address used by Yuubinsya and Trojan.
///
/// Keeping this representation in the shared core avoids subtly different
/// domain/IPv4/IPv6 handling in each protocol adapter.
pub fn encode_endpoint(endpoint: &Endpoint, output: &mut Vec<u8>) -> Result<()> {
    let (host, port) = match endpoint {
        Endpoint::Ip { addr, .. } => (Some(addr.ip()), addr.port()),
        Endpoint::Domain { port, .. } => (None, *port),
    };
    match (host, endpoint.host()) {
        (Some(IpAddr::V4(address)), _) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        (Some(IpAddr::V6(address)), _) => {
            output.push(4);
            output.extend_from_slice(&address.octets());
        }
        (None, Some(domain)) => {
            if domain.as_str().len() > 255 {
                return Err(Error::invalid("Yuubinsya domain is too long"));
            }
            output.push(3);
            output.push(domain.as_str().len() as u8);
            output.extend_from_slice(domain.as_str().as_bytes());
        }
        _ => return Err(Error::invalid("endpoint has no address")),
    }
    output.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

/// Decode a SOCKS-style address and advance `cursor` past the address.
pub fn decode_endpoint(packet: &[u8], cursor: &mut usize, network: Network) -> Result<Endpoint> {
    let address_type = take(packet, cursor, 1)?[0];
    let host = match address_type {
        1 => IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(take(packet, cursor, 4)?).unwrap(),
        )),
        4 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(take(packet, cursor, 16)?).unwrap(),
        )),
        3 => {
            let length = usize::from(take(packet, cursor, 1)?[0]);
            let domain = std::str::from_utf8(take(packet, cursor, length)?)
                .map_err(|_| Error::new(ErrorKind::Protocol, "Yuubinsya domain is not UTF-8"))?;
            let domain = DomainName::new(domain)?;
            let port = u16::from_be_bytes(take(packet, cursor, 2)?.try_into().unwrap());
            return Ok(Endpoint::domain(network, domain, port));
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "unknown Yuubinsya address type",
            ));
        }
    };
    let port = u16::from_be_bytes(take(packet, cursor, 2)?.try_into().unwrap());
    Ok(Endpoint::ip(network, (host, port).into()))
}

fn take<'a>(packet: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "Yuubinsya length overflow"))?;
    if end > packet.len() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Yuubinsya packet is truncated",
        ));
    }
    let result = &packet[*cursor..end];
    *cursor = end;
    Ok(result)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}
