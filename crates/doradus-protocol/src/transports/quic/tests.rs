use super::*;
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CERTIFICATE_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUA6T+/U88N9aMPipK+MdNsAFRUAUwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNeXVoYWlpbi1wMC1jYTAeFw0yNjA4MDYxODIwNDlaFw0zNjA4
MDMxODIwNDlaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABLPnwlYFERi1MgbJNuBHZV/eSpTGdJCQIOyxBt8LlR1ZTEG06pWy
FnJVIzUS4oPuuHc0RcDEltGb/WolyQlM75SjbTBrMBQGA1UdEQQNMAuCCWxvY2Fs
aG9zdDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUZoMmXETR998IsWt1
UTBOVMIs7jMwHwYDVR0jBBgwFoAUhaYkOXheQ1JzLpIKK4I2FEcRMyMwCgYIKoZI
zj0EAwIDSAAwRQIgGEU+sldusbLVAE/kxzZYXaMpIt6l+CZ0cC2jm7lQBqoCIQCw
M5PhuwMhCCb+dUnK6ueJUMHwyK3l2pIAJTMp9+cwqw==
-----END CERTIFICATE-----
"#;
const PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqkH6SeIb9vVEJ6WecsMk5Pn/a8sQ+vdNS/ZSkl3KwfoAoGCCqGSM49
AwEHoUQDQgAEs+fCVgURGLUyBsk24EdlX95KlMZ0kJAg7LEG3wuVHVlMQbTqlbIW
clUjNRLig+64dzRFwMSW0Zv9aiXJCUzvlA==
-----END EC PRIVATE KEY-----
"#;

fn server_tls() -> Arc<rustls::ServerConfig> {
    let cert = rustls_pemfile::certs(&mut Cursor::new(CERTIFICATE_PEM))
        .next()
        .unwrap()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY_PEM))
        .unwrap()
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    Arc::new(config)
}

#[tokio::test(flavor = "current_thread")]
async fn quic_raw_stream_and_datagram_share_one_connection() {
    let server = Arc::new(
        QuicServer::new(
            "127.0.0.1:0".parse().unwrap(),
            server_tls(),
            QuicServerConfig::default(),
        )
        .unwrap(),
    );
    let server_address = server.local_addr().unwrap();
    let config = QuicConfig {
        insecure_skip_verify: true,
        ..QuicConfig::new(server_address, "localhost", Duration::from_secs(2))
    };
    let proxy = Arc::new(QuicProxy::new(config).unwrap());
    let accepting = {
        let server = server.clone();
        tokio::spawn(async move { server.accept().await.unwrap() })
    };
    let context = FlowContext::new(Endpoint::ip(Network::Tcp, server_address));
    let mut stream = proxy.connect(&context).await.unwrap();
    let datagram = proxy
        .open_datagram(&FlowContext::new(Endpoint::ip(
            Network::Udp,
            server_address,
        )))
        .await
        .unwrap();

    let connection = accepting.await.unwrap();
    stream.write_all(b"stream").await.unwrap();
    let mut server_stream = connection.accept_stream().await.unwrap();
    let mut stream_buffer = [0; 6];
    server_stream.read_exact(&mut stream_buffer).await.unwrap();
    assert_eq!(&stream_buffer, b"stream");

    datagram
        .send_to(b"udp", Endpoint::ip(Network::Udp, server_address))
        .await
        .unwrap();
    let server_datagram = connection.accept_datagram().await.unwrap();
    let mut udp_buffer = [0; 8];
    let (length, peer) = server_datagram.recv_from(&mut udp_buffer).await.unwrap();
    assert_eq!(&udp_buffer[..length], b"udp");
    assert_eq!(peer.addr().unwrap().ip(), server_address.ip());
    assert_ne!(peer.addr().unwrap().port(), server_address.port());
    server_datagram.send_to(b"reply", peer).await.unwrap();
    let (length, _) = datagram.recv_from(&mut udp_buffer).await.unwrap();
    assert_eq!(&udp_buffer[..length], b"reply");
    proxy.close().await.unwrap();
    server.close();
}

#[tokio::test(flavor = "current_thread")]
async fn fragmented_udp_round_trips_without_retransmission_state() {
    let server = Arc::new(
        QuicServer::new(
            "127.0.0.1:0".parse().unwrap(),
            server_tls(),
            QuicServerConfig::default(),
        )
        .unwrap(),
    );
    let server_address = server.local_addr().unwrap();
    let config = QuicConfig {
        insecure_skip_verify: true,
        ..QuicConfig::new(server_address, "localhost", Duration::from_secs(2))
    };
    let proxy = QuicProxy::new(config).unwrap();
    let accepting = {
        let server = server.clone();
        tokio::spawn(async move { server.accept().await.unwrap() })
    };
    let datagram = proxy
        .open_datagram(&FlowContext::new(Endpoint::ip(
            Network::Udp,
            server_address,
        )))
        .await
        .unwrap();
    let connection = accepting.await.unwrap();
    let payload = vec![0x5a; 32 * 1024];
    datagram
        .send_to(&payload, Endpoint::ip(Network::Udp, server_address))
        .await
        .unwrap();
    let server_datagram = connection.accept_datagram().await.unwrap();
    let mut received = vec![0; payload.len()];
    let (length, _) = server_datagram.recv_from(&mut received).await.unwrap();
    assert_eq!(&received[..length], payload.as_slice());
    assert!(connection.stats().datagrams_received > 0);
    proxy.close().await.unwrap();
    server.close();
}

#[tokio::test(flavor = "current_thread")]
async fn multiple_udp_associations_share_the_same_quic_connection() {
    let server = Arc::new(
        QuicServer::new(
            "127.0.0.1:0".parse().unwrap(),
            server_tls(),
            QuicServerConfig::default(),
        )
        .unwrap(),
    );
    let server_address = server.local_addr().unwrap();
    let proxy = QuicProxy::new(QuicConfig {
        max_associations: 2,
        insecure_skip_verify: true,
        ..QuicConfig::new(server_address, "localhost", Duration::from_secs(2))
    })
    .unwrap();
    let accepting = {
        let server = server.clone();
        tokio::spawn(async move { server.accept().await.unwrap() })
    };
    let context = FlowContext::new(Endpoint::ip(Network::Udp, server_address));
    let first = proxy.open_datagram(&context).await.unwrap();
    let second = proxy.open_datagram(&context).await.unwrap();
    assert!(proxy.open_datagram(&context).await.is_err());

    let connection = accepting.await.unwrap();
    first
        .send_to(b"first", context.destination.clone())
        .await
        .unwrap();
    second
        .send_to(b"second", context.destination.clone())
        .await
        .unwrap();
    let server_first = connection.accept_datagram().await.unwrap();
    let server_second = connection.accept_datagram().await.unwrap();
    assert_ne!(
        server_first.association_id(),
        server_second.association_id()
    );
    let mut first_buffer = [0; 16];
    let mut second_buffer = [0; 16];
    let mut values = [
        server_first.recv_from(&mut first_buffer).await.unwrap().0,
        server_second.recv_from(&mut second_buffer).await.unwrap().0,
    ];
    values.sort_unstable();
    assert_eq!(values, [5, 6]);
    proxy.close().await.unwrap();
    server.close();
}

#[tokio::test(flavor = "current_thread")]
async fn full_receive_queue_drops_newest_udp_packet() {
    let server = Arc::new(
        QuicServer::new(
            "127.0.0.1:0".parse().unwrap(),
            server_tls(),
            QuicServerConfig {
                rx_queue_capacity: 1,
                ..QuicServerConfig::default()
            },
        )
        .unwrap(),
    );
    let server_address = server.local_addr().unwrap();
    let proxy = QuicProxy::new(QuicConfig {
        rx_queue_capacity: 1,
        insecure_skip_verify: true,
        ..QuicConfig::new(server_address, "localhost", Duration::from_secs(2))
    })
    .unwrap();
    let accepting = {
        let server = server.clone();
        tokio::spawn(async move { server.accept().await.unwrap() })
    };
    let context = FlowContext::new(Endpoint::ip(Network::Udp, server_address));
    let datagram = proxy.open_datagram(&context).await.unwrap();
    let connection = accepting.await.unwrap();
    datagram
        .send_to(b"first", context.destination.clone())
        .await
        .unwrap();
    let server_datagram = connection.accept_datagram().await.unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    datagram
        .send_to(b"second", context.destination.clone())
        .await
        .unwrap();

    for _ in 0..20 {
        if connection.stats().datagrams_dropped > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(connection.stats().datagrams_dropped > 0);
    let mut buffer = [0; 16];
    let (length, _) = server_datagram.recv_from(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..length], b"first");
    proxy.close().await.unwrap();
    server.close();
}

#[tokio::test(flavor = "current_thread")]
async fn yuubinsya_keeps_logical_targets_above_raw_quic() {
    let server = Arc::new(
        QuicServer::new(
            "127.0.0.1:0".parse().unwrap(),
            server_tls(),
            QuicServerConfig::default(),
        )
        .unwrap(),
    );
    let server_address = server.local_addr().unwrap();
    let config = QuicConfig {
        insecure_skip_verify: true,
        ..QuicConfig::new(server_address, "localhost", Duration::from_secs(2))
    };
    let proxy = QuicProxy::new(config).unwrap();
    let accepting = {
        let server = server.clone();
        tokio::spawn(async move { server.accept().await.unwrap() })
    };
    let raw = proxy
        .open_datagram(&FlowContext::new(Endpoint::ip(
            Network::Udp,
            server_address,
        )))
        .await
        .unwrap();
    let connection = accepting.await.unwrap();
    let target_a = Endpoint::ip(Network::Udp, "192.0.2.10:5300".parse().unwrap());
    let target_b = Endpoint::domain(
        Network::Udp,
        doradus_core::DomainName::new("target.example").unwrap(),
        5353,
    );
    let password_hash = crate::yuubinsya::derive_salt(b"quic-test-password");
    let client = crate::YuubinsyaUdpDatagram::new(
        raw,
        password_hash,
        Endpoint::ip(Network::Udp, server_address),
        false,
    )
    .unwrap();
    client.send_to(b"one", target_a.clone()).await.unwrap();
    let raw_server = connection.accept_datagram().await.unwrap();
    let server_protocol =
        crate::YuubinsyaUdpServer::new(Box::new(raw_server), password_hash, false);
    let mut buffer = [0; 128];
    let (length, decoded_target, _peer) = server_protocol.recv_from(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..length], b"one");
    assert_eq!(decoded_target, target_a);
    client.send_to(b"two", target_b.clone()).await.unwrap();
    let (length, decoded_target, peer) = server_protocol.recv_from(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..length], b"two");
    assert_eq!(decoded_target, target_b);
    server_protocol
        .send_to(b"reply", decoded_target, peer)
        .await
        .unwrap();
    let (length, decoded_target) = client.recv_from(&mut buffer).await.unwrap();
    assert_eq!(&buffer[..length], b"reply");
    assert_eq!(decoded_target, target_b);
    proxy.close().await.unwrap();
    server.close();
}
