//! VMess codec and proxy tests.

use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncWriteExt, split};
use tokio::sync::Mutex;
use yuhaiin_core::proxy::{AsyncDatagram, BoxAsyncStream};
use yuhaiin_core::{DomainName, Endpoint, Network};

const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";

#[test]
fn modern_request_round_trips_all_address_families() {
    let uuid = crate::vless::parse_uuid(UUID).unwrap();
    for destination in [
        Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443),
        Endpoint::ip(Network::Tcp, "192.0.2.1:443".parse().unwrap()),
        Endpoint::ip(Network::Tcp, "[2001:db8::1]:443".parse().unwrap()),
    ] {
        let (encoded, expected) =
            encode_request(&uuid, Security::Aes128Gcm, CMD_TCP, &destination).unwrap();
        let decoded = decode_request(&encoded, &uuid).unwrap();
        assert_eq!(decoded.destination, expected.destination);
        assert_eq!(decoded.body_iv, expected.body_iv);
        assert_eq!(decoded.body_key, expected.body_key);
        assert_eq!(decoded.response_v, expected.response_v);
    }
}

#[test]
fn nested_kdf_is_deterministic_and_chacha_key_matches_go_shape() {
    let uuid = crate::vless::parse_uuid(UUID).unwrap();
    assert_eq!(command_key(&uuid).len(), 16);
    assert_eq!(
        kdf(&command_key(&uuid), &[VMESS_HEADER_PAYLOAD_KEY]).len(),
        32
    );
    assert_eq!(chacha_key(&command_key(&uuid)).len(), 32);
}

#[test]
fn malformed_headers_fail_closed() {
    let uuid = crate::vless::parse_uuid(UUID).unwrap();
    let destination = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
    let (mut encoded, _) =
        encode_request(&uuid, Security::Aes128Gcm, CMD_TCP, &destination).unwrap();
    let last = encoded.len() - 1;
    encoded[last] ^= 1;
    assert!(decode_request(&encoded, &uuid).is_err());
    assert!(decode_request(&encoded[..10], &uuid).is_err());
}

#[test]
fn legacy_request_matches_go_user_and_cfb_header_shape() {
    let primary = crate::vless::parse_uuid(UUID).unwrap();
    let users = alter_id_users(primary, 2).unwrap();
    assert_eq!(users.len(), 3);
    assert_ne!(users[0], users[1]);
    assert_ne!(users[1], users[2]);

    let destination = Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443);
    let (encoded, state) = encode_legacy_request(
        &primary,
        &users[1],
        Security::Aes128Gcm,
        CMD_TCP,
        &destination,
    )
    .unwrap();
    assert!(state.legacy);
    assert!(encoded.len() > 16);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut matched_timestamp = false;
    for timestamp in now.saturating_sub(1)..=now.saturating_add(1) {
        let timestamp_bytes = timestamp.to_be_bytes();
        if encoded[..16] != legacy_auth_id(&users[1], &timestamp_bytes).unwrap() {
            continue;
        }
        let plaintext = aes_cfb_xor(
            &command_key(&primary),
            &legacy_timestamp_iv(timestamp),
            &encoded[16..],
            true,
        )
        .unwrap();
        assert_eq!(plaintext[0], VERSION);
        assert_eq!(plaintext[37], CMD_TCP);
        assert_eq!(plaintext[38..40], 443u16.to_be_bytes());
        assert_eq!(plaintext[40], 2);
        assert_eq!(plaintext[41], 11);
        assert_eq!(&plaintext[42..53], b"example.com",);
        assert_eq!(
            fnv1a(&plaintext[..plaintext.len() - 4]),
            u32::from_be_bytes(plaintext[plaintext.len() - 4..].try_into().unwrap())
        );
        matched_timestamp = true;
        break;
    }
    assert!(matched_timestamp, "legacy request timestamp was not found");
}

#[test]
fn legacy_response_header_and_body_keys_round_trip() {
    let body_key = [0x11; 16];
    let body_iv = [0x22; 16];
    let encoded = encode_legacy_response_header(0x7f, &body_key, &body_iv).unwrap();
    let decrypted = aes_cfb_xor(
        &response_key_for(&body_key, true),
        &response_key_for(&body_iv, true),
        &encoded,
        true,
    )
    .unwrap();
    assert_eq!(decrypted, [0x7f, 0, 0, 0]);
    assert!(alter_id_users(body_key, MAX_ALTER_ID + 1).is_err());
}

#[tokio::test]
async fn udp_command_round_trips_with_independent_direction_counters() {
    let uuid = crate::vless::parse_uuid(UUID).unwrap();
    let destination = Endpoint::domain(Network::Udp, DomainName::new("example.com").unwrap(), 443);
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    let (client_reader, mut client_writer) = split(Box::new(client) as BoxAsyncStream);
    let expected_destination = destination.clone();

    let server_task = tokio::spawn(async move {
        let request = read_request(&mut server, &uuid).await.unwrap();
        assert_eq!(request.command, CMD_UDP);
        assert_eq!(request.destination, expected_destination);

        let response_header = encode_response_header(
            request.response_v,
            &response_key_for(&request.body_key, false),
            &response_key_for(&request.body_iv, false),
        )
        .unwrap();
        server.write_all(&response_header).await.unwrap();
        let payload = read_body_frame(
            &mut server,
            &request.body_key,
            &request.body_iv,
            request.security,
            0,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(payload, b"ping");
        write_body_frame(
            &mut server,
            &response_key_for(&request.body_key, false),
            &response_key_for(&request.body_iv, false),
            request.security,
            0,
            b"pong",
        )
        .await
        .unwrap();
    });

    let (request, state) =
        encode_request(&uuid, Security::Aes128Gcm, CMD_UDP, &destination).unwrap();
    client_writer.write_all(&request).await.unwrap();
    let datagram = VmessDatagram {
        reader: Mutex::new(VmessDatagramReader {
            reader: client_reader,
            response_key: response_key_for(&state.body_key, false),
            response_iv: response_key_for(&state.body_iv, false),
            response_v: state.response_v,
            security: state.security,
            legacy: false,
            count: 0,
            response_read: false,
            destination: destination.clone(),
        }),
        writer: Mutex::new(VmessDatagramWriter {
            writer: client_writer,
            key: state.body_key,
            iv: state.body_iv,
            security: state.security,
            count: 0,
            destination: destination.clone(),
        }),
    };

    assert_eq!(
        datagram
            .send_to(b"ping", destination.clone())
            .await
            .unwrap(),
        4
    );
    let mut buffer = [0u8; 32];
    let (length, received_from) = datagram.recv_from(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..length], b"pong");
    assert_eq!(received_from, destination);
    server_task.await.unwrap();
}
