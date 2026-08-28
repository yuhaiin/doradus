use super::{
    YuubinsyaHeader, YuubinsyaProtocol, decode_header, decode_header_any, decode_udp_packet,
    decode_udp_packet_any, decode_uot_frame, derive_salt, encode_header, encode_udp_packet,
    encode_uot_frame,
};
use doradus_core::{DomainName, Endpoint, Network};

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
fn header_accepts_any_bounded_password_hash_and_returns_the_match() {
    let header = YuubinsyaHeader {
        protocol: YuubinsyaProtocol::Tcp,
        migrate_id: None,
        destination: Some(Endpoint::domain(
            Network::Tcp,
            DomainName::new("example.com").unwrap(),
            443,
        )),
    };
    let first = derive_salt(b"first");
    let second = derive_salt(b"second");
    let encoded = encode_header(&second, &header).unwrap();
    let (decoded, consumed, selected) = decode_header_any(&[first, second], &encoded).unwrap();
    assert_eq!(decoded, header);
    assert_eq!(consumed, encoded.len());
    assert_eq!(selected, second);
    assert!(decode_header_any(&[first], &encoded).is_err());
}

#[test]
fn udp_packet_round_trip_supports_domain_and_prefix() {
    let destination = Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);
    let packet = encode_udp_packet(&password(), &destination, b"payload", true).unwrap();
    let (decoded, payload) = decode_udp_packet(&password(), &packet, true).unwrap();
    assert_eq!(decoded, destination);
    assert_eq!(payload, b"payload");
}

#[test]
fn udp_packet_accepts_any_bounded_password_hash_and_returns_the_match() {
    let destination = Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 53);
    let first = derive_salt(b"first");
    let second = derive_salt(b"second");
    let packet = encode_udp_packet(&second, &destination, b"payload", false).unwrap();
    let (decoded, payload, selected) =
        decode_udp_packet_any(&[first, second], &packet, false).unwrap();
    assert_eq!(decoded, destination);
    assert_eq!(payload, b"payload");
    assert_eq!(selected, second);
    assert!(decode_udp_packet_any(&[first], &packet, false).is_err());
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
    let mut state = 0xa5a5_1234_u32;
    for _case in 0..512 {
        let mut frame = encode_uot_frame(
            &destinations[next_random(&mut state) as usize % destinations.len()],
            b"state-machine",
        )
        .unwrap();
        for cut in 0..frame.len() {
            assert!(decode_uot_frame(&frame[..cut]).is_err());
        }
        let length_offset = frame.len() - b"state-machine".len() - 2;
        frame[length_offset..length_offset + 2].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(decode_uot_frame(&frame).is_err());

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
