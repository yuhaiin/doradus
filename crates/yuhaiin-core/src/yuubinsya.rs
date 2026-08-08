//! Yuubinsya wire formats: authenticated UDP packets and UDP-over-TCP frames.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sha2::{Digest, Sha256};

use crate::{DomainName, Endpoint, Error, ErrorKind, Network, Result};

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
    if packet.len() < password_hash.len() + usize::from(socks5_prefix) * 3 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Yuubinsya UDP packet is truncated",
        ));
    }
    let mut cursor = 0;
    let password = take(packet, &mut cursor, password_hash.len())?;
    if !constant_time_eq(password, password_hash) {
        return Err(Error::new(
            ErrorKind::Protocol,
            "Yuubinsya password is incorrect",
        ));
    }
    if socks5_prefix {
        if take(packet, &mut cursor, 3)? != [0, 0, 0] {
            return Err(Error::new(
                ErrorKind::Protocol,
                "invalid Yuubinsya SOCKS5 prefix",
            ));
        }
    }
    let destination = decode_endpoint(packet, &mut cursor, Network::Udp)?;
    Ok((destination, &packet[cursor..]))
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

/// A length-delimited Yuubinsya TCP/UOT session.
///
/// The session owns only authentication and framing. Routing, TCP stream
/// lifetime, retry policy, and cancellation stay with the caller.
pub struct YuubinsyaTcpSession<S> {
    stream: S,
    password_hash: [u8; 32],
}

impl<S: Read + Write> YuubinsyaTcpSession<S> {
    pub fn connect(mut stream: S, password_hash: [u8; 32], destination: Endpoint) -> Result<Self> {
        let header = encode_header(
            &password_hash,
            &YuubinsyaHeader {
                protocol: YuubinsyaProtocol::Tcp,
                migrate_id: None,
                destination: Some(destination),
            },
        )?;
        stream.write_all(&header).map_err(io_error)?;
        Ok(Self {
            stream,
            password_hash,
        })
    }

    pub fn accept(mut stream: S, password_hash: [u8; 32]) -> Result<(Self, YuubinsyaHeader)> {
        let header_bytes = read_header_bytes(&mut stream)?;
        let (header, _) = decode_header(&password_hash, &header_bytes)?;
        if header.protocol != YuubinsyaProtocol::Tcp {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "Yuubinsya TCP session received a non-TCP protocol",
            ));
        }
        Ok((
            Self {
                stream,
                password_hash,
            },
            header,
        ))
    }

    pub fn send_uot(&mut self, destination: &Endpoint, payload: &[u8]) -> Result<()> {
        let frame = encode_uot_frame(destination, payload)?;
        self.stream.write_all(&frame).map_err(io_error)
    }

    pub fn recv_uot(&mut self) -> Result<(Endpoint, Vec<u8>)> {
        let frame = read_uot_frame(&mut self.stream)?;
        let (destination, payload, _) = decode_uot_frame(&frame)?;
        Ok((destination, payload.to_vec()))
    }

    pub fn into_inner(self) -> S {
        self.stream
    }

    pub fn password_hash(&self) -> &[u8; 32] {
        &self.password_hash
    }
}

fn read_header_bytes<S: Read>(stream: &mut S) -> Result<Vec<u8>> {
    let mut packet = [0u8; 1].to_vec();
    stream.read_exact(&mut packet).map_err(io_error)?;
    let protocol = YuubinsyaProtocol::from_byte(packet[0])?;
    if protocol == YuubinsyaProtocol::UdpWithMigrateId {
        let mut migrate_id = [0u8; 8];
        stream.read_exact(&mut migrate_id).map_err(io_error)?;
        packet.extend_from_slice(&migrate_id);
    }
    let mut password = [0u8; 32];
    stream.read_exact(&mut password).map_err(io_error)?;
    packet.extend_from_slice(&password);
    if matches!(protocol, YuubinsyaProtocol::Tcp | YuubinsyaProtocol::Ping) {
        packet.extend_from_slice(&read_endpoint_bytes(stream)?);
    }
    Ok(packet)
}

fn read_endpoint_bytes<S: Read>(stream: &mut S) -> Result<Vec<u8>> {
    let mut bytes = [0u8; 1].to_vec();
    stream.read_exact(&mut bytes).map_err(io_error)?;
    let remaining = match bytes[0] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).map_err(io_error)?;
            bytes.push(length[0]);
            usize::from(length[0]) + 2
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "unknown Yuubinsya address type",
            ));
        }
    };
    let old_len = bytes.len();
    bytes.resize(old_len + remaining, 0);
    stream.read_exact(&mut bytes[old_len..]).map_err(io_error)?;
    Ok(bytes)
}

fn read_uot_frame<S: Read>(stream: &mut S) -> Result<Vec<u8>> {
    let mut frame = read_endpoint_bytes(stream)?;
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).map_err(io_error)?;
    frame.extend_from_slice(&length);
    let payload_len = usize::from(u16::from_be_bytes(length));
    let old_len = frame.len();
    frame.resize(old_len + payload_len, 0);
    stream.read_exact(&mut frame[old_len..]).map_err(io_error)?;
    Ok(frame)
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn password() -> [u8; 32] {
        derive_salt(b"password")
    }

    #[test]
    fn header_round_trip_supports_migration_id() {
        let header = YuubinsyaHeader {
            protocol: YuubinsyaProtocol::UdpWithMigrateId,
            migrate_id: Some(42),
            destination: None,
        };
        let encoded = encode_header(&password(), &header).unwrap();
        let (decoded, consumed) = decode_header(&password(), &encoded).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn udp_packet_round_trip_supports_domain_and_prefix() {
        let destination =
            Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);
        let packet = encode_udp_packet(&password(), &destination, b"payload", true).unwrap();
        let (decoded, payload) = decode_udp_packet(&password(), &packet, true).unwrap();
        assert_eq!(decoded, destination);
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn uot_frame_round_trip_is_length_delimited() {
        let destination = Endpoint::ip(Network::Udp, "192.0.2.1:443".parse().unwrap());
        let frame = encode_uot_frame(&destination, b"abc").unwrap();
        let (decoded, payload, consumed) = decode_uot_frame(&frame).unwrap();
        assert_eq!(decoded, destination);
        assert_eq!(payload, b"abc");
        assert_eq!(consumed, frame.len());
    }

    #[test]
    fn wrong_password_and_truncated_frames_fail() {
        let destination = Endpoint::ip(Network::Udp, "192.0.2.1:443".parse().unwrap());
        let packet = encode_udp_packet(&password(), &destination, b"abc", false).unwrap();
        assert!(decode_udp_packet(&derive_salt(b"wrong"), &packet, false).is_err());
        assert!(decode_uot_frame(&[1, 2, 3]).is_err());
    }

    #[test]
    fn uot_frame_accepts_the_u16_payload_limit_and_rejects_one_byte_more() {
        let destination = Endpoint::ip(Network::Udp, "192.0.2.1:53".parse().unwrap());
        let payload = vec![0x5a; u16::MAX as usize];
        let frame = encode_uot_frame(&destination, &payload).unwrap();
        let (decoded_destination, decoded_payload, consumed) = decode_uot_frame(&frame).unwrap();
        assert_eq!(decoded_destination, destination);
        assert_eq!(decoded_payload, payload.as_slice());
        assert_eq!(consumed, frame.len());
        assert!(encode_uot_frame(&destination, &[0; u16::MAX as usize + 1]).is_err());
    }

    #[test]
    fn random_wire_bytes_are_rejected_without_panicking() {
        let mut state = 0x9e37_79b9_u32;
        for length in 0..512 {
            let mut bytes = vec![0u8; length];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *byte = state as u8;
            }
            let _ = decode_uot_frame(&bytes);
            let _ = decode_udp_packet(&password(), &bytes, false);
            let _ = decode_udp_packet(&password(), &bytes, true);
        }
    }

    #[test]
    fn randomized_yuubinsya_sequences_preserve_framing_and_fail_closed() {
        let destinations = [
            Endpoint::ip(Network::Udp, "192.0.2.1:53".parse().unwrap()),
            Endpoint::ip(Network::Udp, "[2001:db8::53]:443".parse().unwrap()),
            Endpoint::domain(
                Network::Udp,
                DomainName::new("resolver.example").unwrap(),
                5353,
            ),
        ];
        let tcp_destination = Endpoint::ip(Network::Tcp, "192.0.2.10:443".parse().unwrap());
        let mut state = 0xa5a5_1234_u32;

        for _case in 0..512 {
            let header = encode_header(
                &password(),
                &YuubinsyaHeader {
                    protocol: YuubinsyaProtocol::Tcp,
                    migrate_id: None,
                    destination: Some(tcp_destination.clone()),
                },
            )
            .unwrap();
            let frame_count = (next_random(&mut state) as usize % 8) + 1;
            let mut wire = header;
            let mut expected = Vec::with_capacity(frame_count);
            for _ in 0..frame_count {
                let destination =
                    destinations[next_random(&mut state) as usize % destinations.len()].clone();
                let payload_len = next_random(&mut state) as usize % 1025;
                let mut payload = vec![0u8; payload_len];
                for byte in &mut payload {
                    *byte = next_random(&mut state) as u8;
                }
                wire.extend_from_slice(&encode_uot_frame(&destination, &payload).unwrap());
                expected.push((destination, payload));
            }

            let mut session = YuubinsyaTcpSession::accept(std::io::Cursor::new(wire), password())
                .unwrap()
                .0;
            for (destination, payload) in expected {
                let (decoded_destination, decoded_payload) = session.recv_uot().unwrap();
                assert_eq!(decoded_destination, destination);
                assert_eq!(decoded_payload, payload);
            }
            assert!(session.recv_uot().is_err());

            // A frame can be truncated at every prefix boundary, or claim a
            // payload larger than the bytes available.  Both must fail at
            // this frame and never read beyond the supplied slice.
            let valid = encode_uot_frame(&destinations[0], b"state-machine").unwrap();
            for cut in 0..valid.len() {
                assert!(decode_uot_frame(&valid[..cut]).is_err());
            }
            let mut oversized = encode_uot_frame(&destinations[0], &[]).unwrap();
            let length_offset = oversized.len() - 2;
            oversized[length_offset..].copy_from_slice(&u16::MAX.to_be_bytes());
            assert!(decode_uot_frame(&oversized).is_err());

            let mut wrong_password = encode_header(
                &password(),
                &YuubinsyaHeader {
                    protocol: YuubinsyaProtocol::UdpWithMigrateId,
                    migrate_id: Some(next_random(&mut state) as u64),
                    destination: None,
                },
            )
            .unwrap();
            wrong_password[9] ^= 0x80;
            assert!(decode_header(&password(), &wrong_password).is_err());
        }
    }

    fn next_random(state: &mut u32) -> u32 {
        *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *state
    }

    #[test]
    fn tcp_session_writes_authenticated_header() {
        let destination = Endpoint::ip(Network::Tcp, "192.0.2.10:443".parse().unwrap());
        let stream = std::io::Cursor::new(Vec::new());
        let session =
            YuubinsyaTcpSession::connect(stream, password(), destination.clone()).unwrap();
        let bytes = session.into_inner().into_inner();
        let (accepted, header) =
            YuubinsyaTcpSession::accept(std::io::Cursor::new(bytes), password()).unwrap();
        assert_eq!(header.protocol, YuubinsyaProtocol::Tcp);
        assert_eq!(header.destination, Some(destination));
        assert_eq!(accepted.password_hash(), &password());
    }
}
