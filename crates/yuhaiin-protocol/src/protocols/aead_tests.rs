//! AEAD protocol tests.

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn password_salt_and_method_aliases_are_stable() {
    assert_eq!(password_salt(b"secret").len(), HASH_SIZE);
    assert_eq!(
        CryptoMethod::parse("AeadCryptoMethod_XChacha20Poly1305"),
        CryptoMethod::XChacha20Poly1305
    );
    assert_eq!(
        CryptoMethod::parse("unknown"),
        CryptoMethod::Chacha20Poly1305
    );
}

#[tokio::test]
async fn client_and_server_round_trip_both_cipher_methods() {
    for method in [
        CryptoMethod::Chacha20Poly1305,
        CryptoMethod::XChacha20Poly1305,
    ] {
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let (client, server) = tokio::join!(
            super::client(Box::new(client_io), b"secret", method),
            super::server(Box::new(server_io), b"secret", method),
        );
        let mut client = client.unwrap();
        let mut server = server.unwrap();
        client.write_all(b"client-to-server").await.unwrap();
        let mut request = vec![0u8; 16];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"client-to-server");
        server.write_all(b"server-to-client").await.unwrap();
        let mut response = vec![0u8; 16];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"server-to-client");
    }
}

#[tokio::test]
async fn server_accepts_a_central_password_from_a_bounded_set() {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let passwords = vec![b"old-password".to_vec(), b"central-password".to_vec()];
    let (client, server) = tokio::join!(
        super::client(
            Box::new(client_io),
            b"central-password",
            CryptoMethod::Chacha20Poly1305
        ),
        super::server_with_passwords(
            Box::new(server_io),
            &passwords,
            CryptoMethod::Chacha20Poly1305
        ),
    );
    let mut client = client.unwrap();
    let mut server = server.unwrap();
    client.write_all(b"central-authenticated").await.unwrap();
    let mut request = vec![0u8; 21];
    server.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"central-authenticated");
}

#[test]
fn udp_packet_round_trip_both_cipher_methods_and_rejects_wrong_password() {
    for method in [
        CryptoMethod::Chacha20Poly1305,
        CryptoMethod::XChacha20Poly1305,
    ] {
        let packet = encrypt_packet(b"udp-payload", b"secret", method).unwrap();
        assert_eq!(
            decrypt_packet(&packet, b"secret", method).unwrap(),
            b"udp-payload"
        );
        assert!(decrypt_packet(&packet, b"wrong", method).is_err());
    }
}
