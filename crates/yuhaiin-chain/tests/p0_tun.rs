use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::Response;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use smoltcp::iface::{Config, Interface};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl,
    TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use yuhaiin_chain::{
    ChainClient, ChainProxy, ValidatedChain, ValidatedHttp2, ValidatedTls, ValidatedYuubinsya,
    YuubinsyaH2Server, YuubinsyaServerProxy,
};
use yuhaiin_core::proxy::{AsyncProxy, DirectAsyncProxy, DropAsyncProxy, StaticProxySelector};
use yuhaiin_core::tun::{SmoltcpTunDevice, TunDispatcher, TunProxyRuntime};
use yuhaiin_core::yuubinsya::{
    YuubinsyaProtocol, decode_header, decode_uot_frame, derive_salt, encode_uot_frame,
};
use yuhaiin_core::{DomainName, Endpoint, FlowContext, Network};

const PASSWORD: &str = "p0-yuubinsya-password";
const CA_CERTIFICATE_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBlTCCATugAwIBAgIUbS/bRRel4PtBGY4lbCYyc2lxKngwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNeXVoYWlpbi1wMC1jYTAeFw0yNjA4MDYxODIwMzRaFw0zNjA4
MDMxODIwMzRaMBgxFjAUBgNVBAMMDXl1aGFpaW4tcDAtY2EwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAATBHNZR0dSTLNKfYwheVmhyGdCeMBSibhHEGBzXtZ6v0nIA
DhHIIK38v1qnoiTWN9Fof8HXKfhvl1LxSY0rSqe0o2MwYTAdBgNVHQ4EFgQUhaYk
OXheQ1JzLpIKK4I2FEcRMyMwHwYDVR0jBBgwFoAUhaYkOXheQ1JzLpIKK4I2FEcR
MyMwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwID
SAAwRQIhAOzmDAm07/ezq+5WBQhYYOi/F1onvS4skssoRtRq8w8XAiBH0LCIlJk5
QX0jqAZz0309NRht+WWJtz28CPHvuhGXNg==
-----END CERTIFICATE-----
"#;
const LEAF_CERTIFICATE_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
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

fn udp_packet(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0; 20 + 8 + payload.len()];
    let source_ip = IpAddress::Ipv4(source);
    let destination_ip = IpAddress::Ipv4(destination);
    let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
    Ipv4Repr {
        src_addr: source,
        dst_addr: destination,
        next_header: IpProtocol::Udp,
        payload_len: 8 + payload.len(),
        hop_limit: 64,
    }
    .emit(&mut ip, &ChecksumCapabilities::default());
    UdpRepr {
        src_port: source_port,
        dst_port: destination_port,
    }
    .emit(
        &mut UdpPacket::new_unchecked(ip.payload_mut()),
        &source_ip,
        &destination_ip,
        payload.len(),
        |packet| packet.copy_from_slice(payload),
        &ChecksumCapabilities::default(),
    );
    bytes
}

fn tcp_syn_packet(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
) -> Vec<u8> {
    let mut bytes = vec![0; 20 + 20];
    let source_ip = IpAddress::Ipv4(source);
    let destination_ip = IpAddress::Ipv4(destination);
    let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
    Ipv4Repr {
        src_addr: source,
        dst_addr: destination,
        next_header: IpProtocol::Tcp,
        payload_len: 20,
        hop_limit: 64,
    }
    .emit(&mut ip, &ChecksumCapabilities::default());
    TcpRepr {
        src_port: source_port,
        dst_port: destination_port,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(sequence as i32),
        ack_number: None,
        window_len: 4096,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: &[],
    }
    .emit(
        &mut TcpPacket::new_unchecked(ip.payload_mut()),
        &source_ip,
        &destination_ip,
        &ChecksumCapabilities::default(),
    );
    bytes
}

fn tcp_data_packet(
    source: Ipv4Address,
    destination: Ipv4Address,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgement: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0; 20 + 20 + payload.len()];
    let source_ip = IpAddress::Ipv4(source);
    let destination_ip = IpAddress::Ipv4(destination);
    let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
    Ipv4Repr {
        src_addr: source,
        dst_addr: destination,
        next_header: IpProtocol::Tcp,
        payload_len: 20 + payload.len(),
        hop_limit: 64,
    }
    .emit(&mut ip, &ChecksumCapabilities::default());
    TcpRepr {
        src_port: source_port,
        dst_port: destination_port,
        control: TcpControl::Psh,
        seq_number: TcpSeqNumber(sequence as i32),
        ack_number: Some(TcpSeqNumber(acknowledgement as i32)),
        window_len: 4096,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload,
    }
    .emit(
        &mut TcpPacket::new_unchecked(ip.payload_mut()),
        &source_ip,
        &destination_ip,
        &ChecksumCapabilities::default(),
    );
    bytes
}

async fn relay_yuubinsya(
    mut body: h2::RecvStream,
    mut send: h2::SendStream<Bytes>,
    password_hash: [u8; 32],
) {
    let mut buffered = Vec::new();
    let mut protocol = None;
    loop {
        let Some(result) = body.data().await else {
            return;
        };
        let data = result.unwrap();
        body.flow_control().release_capacity(data.len()).unwrap();
        buffered.extend_from_slice(&data);

        if protocol.is_none() {
            let Some(&first) = buffered.first() else {
                continue;
            };
            let current = YuubinsyaProtocol::from_byte(first).unwrap();
            let header_length = match current {
                YuubinsyaProtocol::Tcp => 40,
                YuubinsyaProtocol::UdpWithMigrateId => 41,
                _ => panic!("unexpected protocol in P0 chain fixture: {current:?}"),
            };
            if buffered.len() < header_length {
                continue;
            }
            let (header, consumed) = decode_header(&password_hash, &buffered).unwrap();
            assert_eq!(header.protocol, current);
            buffered.drain(..consumed);
            protocol = Some(current);
            if current == YuubinsyaProtocol::UdpWithMigrateId {
                send.send_data(Bytes::copy_from_slice(&99u64.to_be_bytes()), false)
                    .unwrap();
            }
        }

        match protocol.unwrap() {
            YuubinsyaProtocol::Tcp if !buffered.is_empty() => {
                send.send_data(Bytes::from(buffered.split_off(0)), false)
                    .unwrap();
                send.send_data(Bytes::new(), true).unwrap();
                return;
            }
            YuubinsyaProtocol::UdpWithMigrateId => {
                if let Ok((destination, payload, consumed)) = decode_uot_frame(&buffered) {
                    let frame = encode_uot_frame(&destination, payload).unwrap();
                    buffered.drain(..consumed);
                    send.send_data(Bytes::from(frame), false).unwrap();
                    send.send_data(Bytes::new(), true).unwrap();
                    return;
                }
            }
            _ => {}
        }
    }
}

async fn serve_chain_connection(
    stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    password_hash: [u8; 32],
) {
    let stream = acceptor.accept(stream).await.unwrap();
    let mut connection = h2::server::handshake(stream).await.unwrap();
    let request = connection.accept().await.unwrap().unwrap();
    let (request, mut respond) = request;
    assert_eq!(request.method(), http::Method::CONNECT);
    let send = respond.send_response(Response::new(()), false).unwrap();
    let relay = tokio::spawn(relay_yuubinsya(request.into_body(), send, password_hash));
    let driver = tokio::spawn(async move {
        while let Some(result) = connection.accept().await {
            if result.is_err() {
                break;
            }
        }
    });
    let _ = relay.await;
    // `send_data` queues the response on h2; give the connection driver one
    // scheduling turn to flush it before the short-lived fixture is stopped.
    tokio::task::yield_now().await;
    driver.abort();
}

async fn serve_ping_connection(stream: tokio::net::TcpStream, acceptor: TlsAcceptor) {
    let stream = acceptor.accept(stream).await.unwrap();
    let mut connection = h2::server::handshake(stream).await.unwrap();
    let (request, mut respond) = connection.accept().await.unwrap().unwrap();
    assert_eq!(request.method(), http::Method::CONNECT);
    let mut body = request.into_body();
    let mut send = respond.send_response(Response::new(()), false).unwrap();
    let driver = tokio::spawn(async move {
        while let Some(result) = connection.accept().await {
            if result.is_err() {
                break;
            }
        }
    });
    let mut buffered = Vec::new();
    let mut header_consumed = false;
    while let Some(result) = body.data().await {
        let Ok(data) = result else { break };
        body.flow_control().release_capacity(data.len()).unwrap();
        buffered.extend_from_slice(&data);
        if !header_consumed {
            if buffered.len() < 40 {
                continue;
            }
            let (header, consumed) =
                decode_header(&derive_salt(PASSWORD.as_bytes()), &buffered).unwrap();
            assert_eq!(header.protocol, YuubinsyaProtocol::Ping);
            buffered.drain(..consumed);
            send.send_data(Bytes::copy_from_slice(&1u64.to_be_bytes()), false)
                .unwrap();
            header_consumed = true;
        }
        while buffered.len() >= 8 {
            buffered.drain(..8);
            send.send_data(Bytes::copy_from_slice(&2u64.to_be_bytes()), false)
                .unwrap();
        }
    }
    driver.abort();
}

async fn spawn_ping_fixture() -> (SocketAddr, Vec<u8>, tokio::task::JoinHandle<()>) {
    let ca_certificate_der = rustls_pemfile::certs(&mut Cursor::new(CA_CERTIFICATE_PEM))
        .next()
        .unwrap()
        .unwrap();
    let leaf_certificate_der = rustls_pemfile::certs(&mut Cursor::new(LEAF_CERTIFICATE_PEM))
        .next()
        .unwrap()
        .unwrap();
    let certificate = ca_certificate_der.as_ref().to_vec();
    let key = rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY_PEM))
        .unwrap()
        .unwrap();
    let provider = Arc::new(rustls_rustcrypto::provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf_certificate_der.to_vec())],
            key,
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve_ping_connection(stream, acceptor).await;
    });
    (address, certificate, task)
}

async fn spawn_chain_fixture(
    connections: usize,
) -> (SocketAddr, Vec<u8>, tokio::task::JoinHandle<()>) {
    let ca_certificate_der = rustls_pemfile::certs(&mut Cursor::new(CA_CERTIFICATE_PEM))
        .next()
        .unwrap()
        .unwrap();
    let leaf_certificate_der = rustls_pemfile::certs(&mut Cursor::new(LEAF_CERTIFICATE_PEM))
        .next()
        .unwrap()
        .unwrap();
    let certificate = ca_certificate_der.as_ref().to_vec();
    let key = rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY_PEM))
        .unwrap()
        .unwrap();
    let provider = Arc::new(rustls_rustcrypto::provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf_certificate_der.to_vec())],
            key,
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let password_hash = derive_salt(PASSWORD.as_bytes());
    let task = tokio::spawn(async move {
        let mut handlers = Vec::with_capacity(connections);
        for _ in 0..connections {
            let (stream, _) = listener.accept().await.unwrap();
            handlers.push(tokio::spawn(serve_chain_connection(
                stream,
                acceptor.clone(),
                password_hash,
            )));
        }
        for handler in handlers {
            let _ = handler.await;
        }
    });
    (address, certificate, task)
}

async fn spawn_uot_rollover_fixture() -> (
    SocketAddr,
    Vec<u8>,
    tokio::task::JoinHandle<()>,
    Arc<tokio::sync::Notify>,
) {
    let server_config = yuubinsya_server_config();
    let acceptor = TlsAcceptor::from(server_config);
    let ca_certificate_der = rustls_pemfile::certs(&mut Cursor::new(CA_CERTIFICATE_PEM))
        .next()
        .unwrap()
        .unwrap();
    let certificate = ca_certificate_der.as_ref().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let password = derive_salt(PASSWORD.as_bytes());
    let first_closed = Arc::new(tokio::sync::Notify::new());
    let first_closed_for_task = Arc::clone(&first_closed);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let stream = acceptor.accept(stream).await.unwrap();
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        let mut body = request.into_body();
        let mut send = respond.send_response(Response::new(()), false).unwrap();
        let driver = tokio::spawn(async move {
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        let mut header = Vec::new();
        while header.len() < 41 {
            let data = body.data().await.unwrap().unwrap();
            body.flow_control().release_capacity(data.len()).unwrap();
            header.extend_from_slice(&data);
        }
        let (decoded, consumed) = decode_header(&password, &header).unwrap();
        assert_eq!(decoded.protocol, YuubinsyaProtocol::UdpWithMigrateId);
        assert_eq!(decoded.migrate_id, Some(0));
        header.drain(..consumed);
        send.send_data(Bytes::copy_from_slice(&77u64.to_be_bytes()), false)
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        drop(send);
        drop(body);
        driver.abort();
        let _ = driver.await;
        first_closed_for_task.notify_one();

        let (stream, _) = listener.accept().await.unwrap();
        let stream = acceptor.accept(stream).await.unwrap();
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        let mut body = request.into_body();
        let mut send = respond.send_response(Response::new(()), false).unwrap();
        let driver = tokio::spawn(async move {
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        let mut buffered = Vec::new();
        let mut header_consumed = false;
        loop {
            let Some(data) = body.data().await else { break };
            let data = data.unwrap();
            body.flow_control().release_capacity(data.len()).unwrap();
            buffered.extend_from_slice(&data);
            if !header_consumed && buffered.len() >= 41 {
                let (decoded, consumed) = decode_header(&password, &buffered).unwrap();
                assert_eq!(decoded.protocol, YuubinsyaProtocol::UdpWithMigrateId);
                assert_eq!(decoded.migrate_id, Some(77));
                buffered.drain(..consumed);
                header_consumed = true;
                send.send_data(Bytes::copy_from_slice(&77u64.to_be_bytes()), false)
                    .unwrap();
            }
            if header_consumed
                && let Ok((_destination, _payload, consumed)) = decode_uot_frame(&buffered)
            {
                send.send_data(Bytes::copy_from_slice(&buffered[..consumed]), true)
                    .unwrap();
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        driver.abort();
        let _ = driver.await;
    });
    (address, certificate, task, first_closed)
}

async fn spawn_uot_loss_after_send_fixture() -> (
    SocketAddr,
    Vec<u8>,
    tokio::task::JoinHandle<()>,
    Arc<tokio::sync::Notify>,
) {
    let acceptor = TlsAcceptor::from(yuubinsya_server_config());
    let ca_certificate_der = rustls_pemfile::certs(&mut Cursor::new(CA_CERTIFICATE_PEM))
        .next()
        .unwrap()
        .unwrap();
    let certificate = ca_certificate_der.as_ref().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let password = derive_salt(PASSWORD.as_bytes());
    let first_frame_seen = Arc::new(tokio::sync::Notify::new());
    let first_frame_seen_for_task = Arc::clone(&first_frame_seen);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let stream = acceptor.accept(stream).await.unwrap();
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let mut body = request.into_body();
        let mut send = respond.send_response(Response::new(()), false).unwrap();
        let driver = tokio::spawn(async move {
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        let mut buffered = Vec::new();
        let mut header_consumed = false;
        loop {
            let data = body.data().await.unwrap().unwrap();
            body.flow_control().release_capacity(data.len()).unwrap();
            buffered.extend_from_slice(&data);
            if !header_consumed && buffered.len() >= 41 {
                let (header, consumed) = decode_header(&password, &buffered).unwrap();
                assert_eq!(header.protocol, YuubinsyaProtocol::UdpWithMigrateId);
                assert_eq!(header.migrate_id, Some(0));
                buffered.drain(..consumed);
                send.send_data(Bytes::copy_from_slice(&77u64.to_be_bytes()), false)
                    .unwrap();
                header_consumed = true;
            }
            if header_consumed && decode_uot_frame(&buffered).is_ok() {
                first_frame_seen_for_task.notify_one();
                drop(send);
                drop(body);
                driver.abort();
                let _ = driver.await;
                break;
            }
        }

        let (stream, _) = listener.accept().await.unwrap();
        let stream = acceptor.accept(stream).await.unwrap();
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let mut body = request.into_body();
        let mut send = respond.send_response(Response::new(()), false).unwrap();
        let driver = tokio::spawn(async move {
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        let mut buffered = Vec::new();
        let mut header_consumed = false;
        loop {
            let Some(data) = body.data().await else { break };
            let data = data.unwrap();
            body.flow_control().release_capacity(data.len()).unwrap();
            buffered.extend_from_slice(&data);
            if !header_consumed && buffered.len() >= 41 {
                let (header, consumed) = decode_header(&password, &buffered).unwrap();
                assert_eq!(header.protocol, YuubinsyaProtocol::UdpWithMigrateId);
                assert_eq!(header.migrate_id, Some(77));
                buffered.drain(..consumed);
                send.send_data(Bytes::copy_from_slice(&77u64.to_be_bytes()), false)
                    .unwrap();
                header_consumed = true;
            }
            if header_consumed
                && let Ok((destination, payload, consumed)) = decode_uot_frame(&buffered)
            {
                let frame = encode_uot_frame(&destination, payload).unwrap();
                buffered.drain(..consumed);
                send.send_data(Bytes::from(frame), true).unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
                break;
            }
        }
        driver.abort();
        let _ = driver.await;
    });
    (address, certificate, task, first_frame_seen)
}

async fn spawn_uot_stall_fixture() -> (
    SocketAddr,
    Vec<u8>,
    tokio::task::JoinHandle<()>,
    Arc<tokio::sync::Notify>,
) {
    let acceptor = TlsAcceptor::from(yuubinsya_server_config());
    let ca_certificate_der = rustls_pemfile::certs(&mut Cursor::new(CA_CERTIFICATE_PEM))
        .next()
        .unwrap()
        .unwrap();
    let certificate = ca_certificate_der.as_ref().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let password = derive_salt(PASSWORD.as_bytes());
    let ready = Arc::new(tokio::sync::Notify::new());
    let ready_for_task = Arc::clone(&ready);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let stream = acceptor.accept(stream).await.unwrap();
        let mut connection = h2::server::handshake(stream).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let mut body = request.into_body();
        let mut send = respond.send_response(Response::new(()), false).unwrap();
        let driver = tokio::spawn(async move {
            while let Some(result) = connection.accept().await {
                if result.is_err() {
                    break;
                }
            }
        });
        let mut header = Vec::new();
        while header.len() < 41 {
            let data = body.data().await.unwrap().unwrap();
            body.flow_control().release_capacity(data.len()).unwrap();
            header.extend_from_slice(&data);
        }
        let (decoded, consumed) = decode_header(&password, &header).unwrap();
        assert_eq!(decoded.protocol, YuubinsyaProtocol::UdpWithMigrateId);
        assert_eq!(decoded.migrate_id, Some(0));
        header.drain(..consumed);
        send.send_data(Bytes::copy_from_slice(&77u64.to_be_bytes()), false)
            .unwrap();
        ready_for_task.notify_one();

        while let Some(result) = body.data().await {
            let Ok(data) = result else { break };
            body.flow_control().release_capacity(data.len()).unwrap();
        }
        driver.abort();
        let _ = driver.await;
    });
    (address, certificate, task, ready)
}

async fn spawn_uot_double_loss_fixture() -> (
    SocketAddr,
    Vec<u8>,
    tokio::task::JoinHandle<()>,
    Arc<tokio::sync::Notify>,
) {
    spawn_uot_loss_matrix_fixture(3, Some(2)).await
}

async fn spawn_uot_loss_matrix_fixture(
    attempts: usize,
    success_attempt: Option<usize>,
) -> (
    SocketAddr,
    Vec<u8>,
    tokio::task::JoinHandle<()>,
    Arc<tokio::sync::Notify>,
) {
    assert!(attempts > 0);
    let acceptor = TlsAcceptor::from(yuubinsya_server_config());
    let ca_certificate_der = rustls_pemfile::certs(&mut Cursor::new(CA_CERTIFICATE_PEM))
        .next()
        .unwrap()
        .unwrap();
    let certificate = ca_certificate_der.as_ref().to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let password = derive_salt(PASSWORD.as_bytes());
    let completed = Arc::new(tokio::sync::Notify::new());
    let completed_for_task = Arc::clone(&completed);
    let task = tokio::spawn(async move {
        for attempt in 0..attempts {
            let accepted = if attempt == 0 {
                Some(listener.accept().await.unwrap())
            } else {
                tokio::time::timeout(Duration::from_millis(250), listener.accept())
                    .await
                    .ok()
                    .and_then(Result::ok)
            };
            let Some((stream, _)) = accepted else {
                break;
            };
            let stream = acceptor.accept(stream).await.unwrap();
            let mut connection = h2::server::handshake(stream).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.method(), http::Method::CONNECT);
            let mut body = request.into_body();
            let mut send = respond.send_response(Response::new(()), false).unwrap();
            let driver = tokio::spawn(async move {
                while let Some(result) = connection.accept().await {
                    if result.is_err() {
                        break;
                    }
                }
            });

            let mut buffered = Vec::new();
            while buffered.len() < 41 {
                let data = body.data().await.unwrap().unwrap();
                body.flow_control().release_capacity(data.len()).unwrap();
                buffered.extend_from_slice(&data);
            }
            let (decoded, consumed) = decode_header(&password, &buffered).unwrap();
            assert_eq!(decoded.protocol, YuubinsyaProtocol::UdpWithMigrateId);
            assert_eq!(decoded.migrate_id, Some(if attempt == 0 { 0 } else { 77 }));
            buffered.drain(..consumed);
            send.send_data(Bytes::copy_from_slice(&77u64.to_be_bytes()), false)
                .unwrap();

            loop {
                if let Ok((destination, payload, consumed)) = decode_uot_frame(&buffered) {
                    let frame = encode_uot_frame(&destination, payload).unwrap();
                    buffered.drain(..consumed);
                    if success_attempt == Some(attempt) {
                        send.send_data(Bytes::from(frame), true).unwrap();
                        completed_for_task.notify_one();
                        // Give the H2 driver time to flush the final DATA frame
                        // before the fixture tears down the connection.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    break;
                }
                let Some(data) = body.data().await else { break };
                let data = data.unwrap();
                body.flow_control().release_capacity(data.len()).unwrap();
                buffered.extend_from_slice(&data);
            }
            drop(send);
            drop(body);
            driver.abort();
            let _ = driver.await;
        }
    });
    (address, certificate, task, completed)
}

fn yuubinsya_server_config() -> Arc<ServerConfig> {
    let leaf_certificate_der = rustls_pemfile::certs(&mut Cursor::new(LEAF_CERTIFICATE_PEM))
        .next()
        .unwrap()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY_PEM))
        .unwrap()
        .unwrap();
    let provider = Arc::new(rustls_rustcrypto::provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf_certificate_der.to_vec())],
            key,
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

fn chain_client(address: SocketAddr, certificate: Vec<u8>) -> ChainClient {
    chain_client_with_max_streams(address, certificate, 128)
}

fn chain_client_with_max_streams(
    address: SocketAddr,
    certificate: Vec<u8>,
    max_streams: usize,
) -> ChainClient {
    ChainClient::new(ValidatedChain {
        id: None,
        name: Some("P0 fixture".to_owned()),
        fixed_addresses: vec![yuhaiin_chain::ValidatedFixedAddress {
            host: address.ip().to_string(),
            port: address.port(),
        }],
        tls: ValidatedTls {
            servernames: vec!["localhost".to_owned()],
            ca_certificates: vec![certificate],
            next_protos: vec!["h2".to_owned()],
        },
        http2: ValidatedHttp2 {
            concurrency: 4,
            max_streams,
            idle_timeout: std::time::Duration::from_secs(300),
        },
        yuubinsya: ValidatedYuubinsya {
            password: PASSWORD.to_owned(),
            udp_over_stream: true,
            udp_coalesce: false,
        },
    })
    .unwrap()
}

fn proxy_runtime(proxy: Arc<dyn AsyncProxy>) -> TunProxyRuntime {
    let drop: Arc<dyn AsyncProxy> = Arc::new(DropAsyncProxy);
    let selector = Arc::new(StaticProxySelector {
        direct: Arc::clone(&drop),
        proxy,
        bypass: Arc::clone(&drop),
        drop,
    });
    TunProxyRuntime::new(selector, 8)
        .unwrap()
        .with_io_timeout(Duration::from_secs(3))
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn chain_proxy_runs_tcp_and_uot_udp_through_tun_runtime() {
    let (address, certificate, server) = spawn_chain_fixture(2).await;
    let chain = chain_client(address, certificate);
    let chain_proxy: Arc<dyn AsyncProxy> = Arc::new(ChainProxy::new(chain));

    let local = Ipv4Address::new(10, 0, 0, 1);
    let remote = Ipv4Address::new(10, 0, 0, 2);
    let tcp_destination = Ipv4Address::new(192, 0, 2, 1);
    let mut tcp_device = SmoltcpTunDevice::new(1500, 16).unwrap();
    let mut tcp_interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut tcp_device,
        Instant::from_millis(0),
    );
    tcp_interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(tcp_destination), 32))
            .unwrap();
    });
    let mut tcp_dispatcher = TunDispatcher::new(4096, 4096, 4).unwrap();
    let mut tcp_runtime = proxy_runtime(Arc::clone(&chain_proxy));
    let tcp_port = 443;
    tcp_device
        .enqueue_rx(tcp_syn_packet(
            remote,
            tcp_destination,
            41000,
            tcp_port,
            100,
        ))
        .unwrap();
    tcp_dispatcher
        .poll_with(&mut tcp_interface, &mut tcp_device, Instant::from_millis(1))
        .unwrap();
    let syn_ack = tcp_device.take_tx().unwrap().unwrap();
    let syn_ack_ip = Ipv4Packet::new_checked(&syn_ack).unwrap();
    let server_sequence = TcpPacket::new_checked(syn_ack_ip.payload())
        .unwrap()
        .seq_number()
        .0 as u32;
    tcp_device
        .enqueue_rx(tcp_data_packet(
            remote,
            tcp_destination,
            41000,
            tcp_port,
            101,
            server_sequence + 1,
            &[],
        ))
        .unwrap();
    tcp_dispatcher
        .poll_with(&mut tcp_interface, &mut tcp_device, Instant::from_millis(2))
        .unwrap();
    for event in tcp_dispatcher.events().collect::<Vec<_>>() {
        tcp_runtime.handle_event(event).unwrap();
    }
    let request = b"chain-tcp";
    tcp_device
        .enqueue_rx(tcp_data_packet(
            remote,
            tcp_destination,
            41000,
            tcp_port,
            101,
            server_sequence + 1,
            request,
        ))
        .unwrap();
    tcp_dispatcher
        .poll_with(&mut tcp_interface, &mut tcp_device, Instant::from_millis(3))
        .unwrap();
    for event in tcp_dispatcher.events().collect::<Vec<_>>() {
        tcp_runtime.handle_event(event).unwrap();
    }
    let mut tcp_response = None;
    for tick in 4..2000 {
        tokio::time::sleep(Duration::from_millis(1)).await;
        tcp_runtime.poll_outputs(&mut tcp_dispatcher).unwrap();
        tcp_dispatcher
            .poll_with(
                &mut tcp_interface,
                &mut tcp_device,
                Instant::from_millis(tick),
            )
            .unwrap();
        while let Some(packet) = tcp_device.take_tx().unwrap() {
            let ip = Ipv4Packet::new_checked(&packet).unwrap();
            let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
            if tcp.payload() == request {
                tcp_response = Some(packet);
                break;
            }
        }
        if tcp_response.is_some() {
            break;
        }
    }
    tcp_runtime.close();
    let tcp_response = tcp_response.expect("Yuubinsya TCP did not return data to TUN");
    let tcp_ip = Ipv4Packet::new_checked(&tcp_response).unwrap();
    let tcp = TcpPacket::new_checked(tcp_ip.payload()).unwrap();
    assert_eq!(tcp_ip.src_addr(), tcp_destination);
    assert_eq!(tcp.payload(), request);

    let udp_destination = Ipv4Address::new(198, 18, 0, 1);
    let mut udp_device = SmoltcpTunDevice::new(1500, 16).unwrap();
    let mut udp_interface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut udp_device,
        Instant::from_millis(0),
    );
    udp_interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(local), 24))
            .unwrap();
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(udp_destination), 32))
            .unwrap();
    });
    let mut udp_dispatcher = TunDispatcher::new(2048, 2048, 4).unwrap();
    let mut udp_runtime = proxy_runtime(Arc::clone(&chain_proxy));
    let payload = b"chain-uot";
    udp_device
        .enqueue_rx(udp_packet(remote, udp_destination, 41001, 5353, payload))
        .unwrap();
    udp_dispatcher
        .poll_with(&mut udp_interface, &mut udp_device, Instant::from_millis(1))
        .unwrap();
    for event in udp_dispatcher.events().collect::<Vec<_>>() {
        udp_runtime.handle_event(event).unwrap();
    }
    let mut udp_response = None;
    for tick in 2..2000 {
        tokio::time::sleep(Duration::from_millis(1)).await;
        udp_runtime.poll_outputs(&mut udp_dispatcher).unwrap();
        udp_dispatcher
            .poll_with(
                &mut udp_interface,
                &mut udp_device,
                Instant::from_millis(tick),
            )
            .unwrap();
        if let Some(packet) = udp_device.take_tx().unwrap() {
            udp_response = Some(packet);
            break;
        }
    }
    udp_runtime.close();
    if udp_response.is_none() {
        server.abort();
    }
    let udp_response = udp_response.expect("Yuubinsya UOT did not return data to TUN");
    let udp_ip = Ipv4Packet::new_checked(&udp_response).unwrap();
    let udp = UdpPacket::new_checked(udp_ip.payload()).unwrap();
    assert_eq!(udp_ip.src_addr(), udp_destination);
    assert_eq!(udp.payload(), payload);

    server.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn chain_client_reuses_h2_pool_for_cached_ping() {
    let (address, certificate, server) = spawn_ping_fixture().await;
    let chain = chain_client(address, certificate);
    let destination = Endpoint::domain(
        Network::Tcp,
        DomainName::new("target.example").unwrap(),
        443,
    );
    assert!(chain.ping(destination.clone()).await.unwrap() >= Duration::ZERO);
    assert!(chain.ping(destination).await.unwrap() >= Duration::ZERO);
    assert_eq!(chain.h2_connection_count().await, 1);
    assert_eq!(chain.h2_active_streams().await, 1);
    let stats = chain.runtime_stats().await;
    assert_eq!(stats.h2_connections, 1);
    assert_eq!(stats.h2_active_streams, 1);
    assert_eq!(stats.h2_pool.connection_attempts, 1);
    chain.close().await;
    let error = chain
        .ping(Endpoint::domain(
            Network::Tcp,
            DomainName::new("target.example").unwrap(),
            443,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.kind, yuhaiin_core::ErrorKind::Closed);
    chain.close().await;
    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "current_thread")]
async fn chain_client_uses_multiple_tls_h2_connections_for_concurrent_migrated_uot() {
    let response_order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let first_target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let first_target_address = first_target.local_addr().unwrap();
    let first_order = Arc::clone(&response_order);
    let first_target_task = tokio::spawn(async move {
        let mut buffer = [0u8; 1024];
        let (length, peer) = first_target.recv_from(&mut buffer).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        first_target.send_to(&buffer[..length], peer).await.unwrap();
        first_order.lock().unwrap().push(1u8);
    });
    let second_target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second_target_address = second_target.local_addr().unwrap();
    let second_order = Arc::clone(&response_order);
    let second_target_task = tokio::spawn(async move {
        let mut buffer = [0u8; 1024];
        let (length, peer) = second_target.recv_from(&mut buffer).await.unwrap();
        second_target
            .send_to(&buffer[..length], peer)
            .await
            .unwrap();
        second_order.lock().unwrap().push(2u8);
    });

    let upstream: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy {
        timeout: Duration::from_secs(3),
    });
    let proxy = Arc::new(YuubinsyaServerProxy::new(
        derive_salt(PASSWORD.as_bytes()),
        upstream,
    ));
    let server = Arc::new(YuubinsyaH2Server::new(yuubinsya_server_config(), proxy).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            server
                .serve_listener_until(listener, async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        })
    };
    let certificate = rustls_pemfile::certs(&mut Cursor::new(CA_CERTIFICATE_PEM))
        .next()
        .unwrap()
        .unwrap();
    let chain = chain_client_with_max_streams(address, certificate.as_ref().to_vec(), 1);

    let mut first = chain.connect_uot(0).await.unwrap();
    let migrate_id = first.migrate_id;
    let mut second = chain.connect_uot(migrate_id).await.unwrap();
    assert_eq!(chain.h2_connection_count().await, 2);
    assert_eq!(chain.h2_active_streams().await, 2);
    let stats = chain.runtime_stats().await;
    assert_eq!(stats.h2_connections, 2);
    assert_eq!(stats.h2_active_streams, 2);
    assert_eq!(stats.h2_pool.connection_attempts, 2);

    let first_target = Endpoint::ip(Network::Udp, first_target_address);
    let second_target = Endpoint::ip(Network::Udp, second_target_address);
    let (first_send, second_send) = tokio::join!(
        first.send_to(&first_target, b"first-connection"),
        second.send_to(&second_target, b"second-connection"),
    );
    first_send.unwrap();
    second_send.unwrap();

    let (first_response, second_response) = tokio::join!(first.recv_from(), second.recv_from());
    assert_eq!(first_response.unwrap().1, b"first-connection");
    assert_eq!(second_response.unwrap().1, b"second-connection");
    assert_eq!(&*response_order.lock().unwrap(), &[2, 1]);

    first.shutdown().await.unwrap();
    second.shutdown().await.unwrap();
    chain.close().await;
    let _ = shutdown_tx.send(());
    server_task.await.unwrap();
    first_target_task.await.unwrap();
    second_target_task.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn tls_h2_yuubinsya_server_dispatches_tcp_and_migrated_uot() {
    let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_target_address = tcp_target.local_addr().unwrap();
    let tcp_target_task = tokio::spawn(async move {
        let (mut stream, _) = tcp_target.accept().await.unwrap();
        let mut buffer = [0u8; 1024];
        loop {
            let length = stream.read(&mut buffer).await.unwrap();
            if length == 0 {
                break;
            }
            stream.write_all(&buffer[..length]).await.unwrap();
        }
    });

    let udp_target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_target_address = udp_target.local_addr().unwrap();
    let udp_target_task = tokio::spawn(async move {
        let mut buffer = [0u8; 65_535];
        loop {
            let (length, source) = udp_target.recv_from(&mut buffer).await.unwrap();
            udp_target.send_to(&buffer[..length], source).await.unwrap();
        }
    });

    let upstream: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy {
        timeout: Duration::from_secs(3),
    });
    let proxy = Arc::new(YuubinsyaServerProxy::new(
        derive_salt(PASSWORD.as_bytes()),
        upstream,
    ));
    let server = Arc::new(YuubinsyaH2Server::new(yuubinsya_server_config(), proxy).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_task = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            server
                .serve_listener_until(listener, async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        })
    };

    let chain = chain_client(address, {
        let ca = rustls_pemfile::certs(&mut Cursor::new(CA_CERTIFICATE_PEM))
            .next()
            .unwrap()
            .unwrap();
        ca.as_ref().to_vec()
    });

    let tcp_destination = Endpoint::ip(Network::Tcp, tcp_target_address);
    let mut tcp = chain.connect_tcp(tcp_destination).await.unwrap();
    tcp.write_all(b"server-side-tcp").await.unwrap();
    let mut tcp_response = vec![0u8; 15];
    tcp.read_exact(&mut tcp_response).await.unwrap();
    assert_eq!(&tcp_response, b"server-side-tcp");
    tcp.shutdown().await.unwrap();

    let udp_destination = Endpoint::ip(Network::Udp, udp_target_address);
    let mut first = chain.connect_uot(0).await.unwrap();
    assert_ne!(first.migrate_id, 0);
    first.send_to(&udp_destination, b"first-uot").await.unwrap();
    let (source, response) = first.recv_from().await.unwrap();
    assert_eq!(source, udp_destination);
    assert_eq!(response, b"first-uot");
    let migrate_id = first.migrate_id;
    first.shutdown().await.unwrap();

    let mut second = chain.connect_uot(migrate_id).await.unwrap();
    assert_eq!(second.migrate_id, migrate_id);
    second
        .send_to(&udp_destination, b"second-uot")
        .await
        .unwrap();
    let (source, response) = second.recv_from().await.unwrap();
    assert_eq!(source, udp_destination);
    assert_eq!(response, b"second-uot");
    second.shutdown().await.unwrap();

    chain.close().await;
    let _ = shutdown_tx.send(());
    server_task.await.unwrap();
    tcp_target_task.abort();
    udp_target_task.abort();
    let _ = tcp_target_task.await;
    let _ = udp_target_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn chain_datagram_reconnects_after_h2_stream_loss_with_same_migration() {
    let (address, certificate, server, first_closed) = spawn_uot_rollover_fixture().await;
    let chain = chain_client(address, certificate);
    let proxy = ChainProxy::new(chain.clone());
    let target = Endpoint::ip(Network::Udp, "198.51.100.9:5353".parse().unwrap());
    let context = FlowContext::new(target.clone());
    let datagram = proxy.open_datagram(&context).await.unwrap();
    first_closed.notified().await;
    // The server-side close is explicit, but the client H2 connection task
    // observes the transport close asynchronously before the pool can reject
    // the dead stream and create the replacement connection.
    tokio::time::sleep(Duration::from_millis(100)).await;
    tokio::time::timeout(
        Duration::from_secs(3),
        datagram.send_to(b"rollover", target.clone()),
    )
    .await
    .expect("UOT rollover send timed out")
    .unwrap();
    let mut buffer = [0u8; 64];
    let received = tokio::time::timeout(Duration::from_secs(3), datagram.recv_from(&mut buffer))
        .await
        .expect("UOT datagram rollover timed out")
        .unwrap();
    assert_eq!(received.0, b"rollover".len());
    assert_eq!(&buffer[..received.0], b"rollover");
    assert_eq!(received.1, target);
    datagram.close().await.unwrap();
    chain.close().await;
    server.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn chain_datagram_replays_unacknowledged_frame_after_response_loss() {
    let (address, certificate, server, first_frame_seen) =
        spawn_uot_loss_after_send_fixture().await;
    let chain = chain_client(address, certificate);
    let proxy = ChainProxy::new(chain.clone());
    let target = Endpoint::ip(Network::Udp, "198.51.100.10:5353".parse().unwrap());
    let datagram = proxy
        .open_datagram(&FlowContext::new(target.clone()))
        .await
        .unwrap();

    datagram
        .send_to(b"response-lost", target.clone())
        .await
        .unwrap();
    first_frame_seen.notified().await;
    let mut buffer = [0u8; 64];
    let received = tokio::time::timeout(Duration::from_secs(3), datagram.recv_from(&mut buffer))
        .await
        .expect("UOT response-loss retry timed out")
        .unwrap();
    assert_eq!(&buffer[..received.0], b"response-lost");
    assert_eq!(received.1, target);

    datagram.close().await.unwrap();
    chain.close().await;
    server.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn chain_datagram_survives_two_consecutive_uot_losses() {
    let (address, certificate, server, completed) = spawn_uot_double_loss_fixture().await;
    let chain = chain_client(address, certificate);
    let proxy = ChainProxy::new(chain.clone());
    let target = Endpoint::ip(Network::Udp, "198.51.100.12:5353".parse().unwrap());
    let datagram = proxy
        .open_datagram(&FlowContext::new(target.clone()))
        .await
        .unwrap();

    let send_result = tokio::time::timeout(
        Duration::from_secs(3),
        datagram.send_to(b"two-losses", target.clone()),
    )
    .await
    .expect("UOT send through consecutive losses timed out");
    if let Err(error) = send_result {
        assert!(matches!(
            error.kind,
            yuhaiin_core::ErrorKind::Io
                | yuhaiin_core::ErrorKind::Closed
                | yuhaiin_core::ErrorKind::Protocol
                | yuhaiin_core::ErrorKind::Timeout
        ));
    }

    let mut buffer = [0u8; 64];
    let received = tokio::time::timeout(Duration::from_secs(5), datagram.recv_from(&mut buffer))
        .await
        .expect("UOT recv did not survive two consecutive losses")
        .unwrap();
    assert_eq!(received.0, b"two-losses".len());
    assert_eq!(&buffer[..received.0], b"two-losses");
    assert_eq!(received.1, target);
    completed.notified().await;

    datagram.close().await.unwrap();
    chain.close().await;
    server.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn chain_datagram_stops_after_bounded_uot_losses() {
    // One reconnect can happen while send_to is recovering the failed write;
    // recv_from then has its own bounded reconnect budget.  Five server-side
    // stream generations cover the initial stream plus those retries.
    let (address, certificate, server, _completed) = spawn_uot_loss_matrix_fixture(5, None).await;
    let chain = chain_client(address, certificate);
    let proxy = ChainProxy::new(chain.clone());
    let target = Endpoint::ip(Network::Udp, "198.51.100.13:5353".parse().unwrap());
    let datagram = proxy
        .open_datagram(&FlowContext::new(target.clone()))
        .await
        .unwrap();

    let send_result = tokio::time::timeout(
        Duration::from_secs(3),
        datagram.send_to(b"bounded-losses", target.clone()),
    )
    .await
    .expect("bounded-loss UOT send timed out");
    if let Err(error) = send_result {
        assert!(matches!(
            error.kind,
            yuhaiin_core::ErrorKind::Io
                | yuhaiin_core::ErrorKind::Closed
                | yuhaiin_core::ErrorKind::Protocol
                | yuhaiin_core::ErrorKind::Timeout
        ));
    }

    let mut buffer = [0u8; 64];
    let error = tokio::time::timeout(Duration::from_secs(5), datagram.recv_from(&mut buffer))
        .await
        .expect("bounded UOT reconnect loop timed out")
        .unwrap_err();
    assert!(matches!(
        error.kind,
        yuhaiin_core::ErrorKind::Io
            | yuhaiin_core::ErrorKind::Closed
            | yuhaiin_core::ErrorKind::Protocol
            | yuhaiin_core::ErrorKind::Timeout
    ));

    datagram.close().await.unwrap();
    chain.close().await;
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("bounded UOT fixture did not finish")
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn chain_datagram_survives_deterministic_random_loss_state_machine() {
    // Keep the random sequence reproducible: every case describes one UOT
    // operation whose first N stream generations are dropped after the frame
    // is received, followed by an echoing generation. This exercises both
    // send-side and recv-side recovery without making the normal test suite
    // depend on stochastic kernel packet loss.
    const MAX_RECONNECTS: usize = 3;
    let mut state = 0x9e37_79b9_u32;
    for case in 0..12 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let dropped_generations = (state as usize) % (MAX_RECONNECTS + 1);
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let payload_len = 1 + ((state >> 8) as usize % 4096);
        let mut payload = vec![0u8; payload_len];
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte = state
                .wrapping_add(index as u32)
                .rotate_left((index % 31) as u32) as u8;
        }
        let target = Endpoint::ip(
            Network::Udp,
            format!("198.51.100.{}:{}", 40 + case, 5300 + case)
                .parse()
                .unwrap(),
        );
        let (address, certificate, server, completed) =
            spawn_uot_loss_matrix_fixture(dropped_generations + 1, Some(dropped_generations)).await;
        let chain = chain_client(address, certificate);
        let proxy = ChainProxy::new(chain.clone());
        let datagram = proxy
            .open_datagram(&FlowContext::new(target.clone()))
            .await
            .unwrap();

        tokio::time::timeout(
            Duration::from_secs(5),
            datagram.send_to(&payload, target.clone()),
        )
        .await
        .expect("randomized UOT send timed out")
        .unwrap();
        let mut buffer = vec![0u8; payload_len];
        let received =
            tokio::time::timeout(Duration::from_secs(5), datagram.recv_from(&mut buffer))
                .await
                .expect("randomized UOT recv timed out")
                .unwrap();
        assert_eq!(received.0, payload.len(), "case {case}");
        assert_eq!(&buffer[..received.0], payload, "case {case}");
        assert_eq!(received.1, target, "case {case}");
        completed.notified().await;

        datagram.close().await.unwrap();
        chain.close().await;
        server.await.unwrap();
    }
}

fn set_loopback_netem_loss(percent: u8) {
    let loss = format!("{percent}%");
    let status = std::process::Command::new("tc")
        .args([
            "qdisc", "replace", "dev", "lo", "root", "netem", "loss", &loss,
        ])
        .status()
        .expect("tc must be installed for the kernel netem test");
    assert!(status.success(), "tc netem setup failed with {status}");
}

fn clear_loopback_netem() {
    let status = std::process::Command::new("tc")
        .args(["qdisc", "del", "dev", "lo", "root"])
        .status()
        .expect("tc must be installed for the kernel netem test");
    assert!(status.success(), "tc netem cleanup failed with {status}");
}

struct LoopbackNetemGuard {
    active: bool,
}

impl LoopbackNetemGuard {
    fn install(loss_percent: u8) -> Self {
        set_loopback_netem_loss(loss_percent);
        Self { active: true }
    }

    fn clear(mut self) {
        clear_loopback_netem();
        self.active = false;
    }
}

impl Drop for LoopbackNetemGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = std::process::Command::new("tc")
                .args(["qdisc", "del", "dev", "lo", "root"])
                .status();
        }
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires an isolated user network namespace with tc netem"]
async fn chain_datagram_survives_kernel_loopback_loss() {
    let (address, certificate, server) = spawn_chain_fixture(2).await;
    let chain = chain_client(address, certificate);
    let proxy = ChainProxy::new(chain.clone());
    let target = Endpoint::ip(Network::Udp, "198.51.100.14:5353".parse().unwrap());
    let datagram = proxy
        .open_datagram(&FlowContext::new(target.clone()))
        .await
        .unwrap();

    datagram
        .send_to(b"before-netem", target.clone())
        .await
        .unwrap();
    let mut buffer = [0u8; 64];
    let received = tokio::time::timeout(Duration::from_secs(3), datagram.recv_from(&mut buffer))
        .await
        .expect("baseline UOT response timed out")
        .unwrap();
    assert_eq!(&buffer[..received.0], b"before-netem");

    // Drop all loopback packets only after TLS/H2/UOT setup is complete. TCP
    // must recover the data through its own retransmission after the qdisc is
    // removed; this is intentionally different from closing the H2 stream.
    set_loopback_netem_loss(100);
    let mut send = std::pin::pin!(datagram.send_to(b"kernel-loss", target.clone()));
    let send_result = tokio::select! {
        result = &mut send => {
            clear_loopback_netem();
            result
        }
        _ = tokio::time::sleep(Duration::from_millis(250)) => {
            clear_loopback_netem();
            tokio::time::timeout(Duration::from_secs(5), &mut send)
                .await
                .expect("UOT send did not recover after kernel loss")
        }
    };
    send_result.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), datagram.recv_from(&mut buffer))
        .await
        .expect("UOT response did not recover after kernel loss")
        .unwrap();
    assert_eq!(&buffer[..received.0], b"kernel-loss");
    assert_eq!(received.1, target);

    datagram.close().await.unwrap();
    chain.close().await;
    server.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires an isolated user network namespace with tc netem"]
async fn chain_datagram_survives_kernel_loopback_loss_matrix() {
    // These are intentionally deterministic profiles. The qdisc is installed
    // only after TLS/H2/UOT setup and removed before the final assertion, so
    // TCP retransmission is tested independently from the synthetic stream
    // drop fixtures above.
    for (case, (loss_percent, hold)) in [
        (0, Duration::from_millis(50)),
        (25, Duration::from_millis(200)),
        (50, Duration::from_millis(300)),
        (75, Duration::from_millis(400)),
        (100, Duration::from_millis(250)),
    ]
    .into_iter()
    .enumerate()
    {
        let (address, certificate, server) = spawn_chain_fixture(2).await;
        let chain = chain_client(address, certificate);
        let proxy = ChainProxy::new(chain.clone());
        let target = Endpoint::ip(
            Network::Udp,
            format!("198.51.100.{}:{}", 60 + case, 5400 + case)
                .parse()
                .unwrap(),
        );
        let datagram = proxy
            .open_datagram(&FlowContext::new(target.clone()))
            .await
            .unwrap();

        datagram
            .send_to(b"matrix-baseline", target.clone())
            .await
            .unwrap();
        let mut buffer = [0u8; 128];
        let received =
            tokio::time::timeout(Duration::from_secs(3), datagram.recv_from(&mut buffer))
                .await
                .expect("kernel matrix baseline timed out")
                .unwrap();
        assert_eq!(&buffer[..received.0], b"matrix-baseline");

        let payload = format!("matrix-loss-{case}");
        let netem = LoopbackNetemGuard::install(loss_percent);
        let mut send = std::pin::pin!(datagram.send_to(payload.as_bytes(), target.clone()));
        let send_result = tokio::select! {
            result = &mut send => {
                netem.clear();
                result
            }
            _ = tokio::time::sleep(hold) => {
                netem.clear();
                tokio::time::timeout(Duration::from_secs(5), &mut send)
                    .await
                    .expect("kernel loss matrix send did not recover")
            }
        };
        send_result.unwrap();

        let received =
            tokio::time::timeout(Duration::from_secs(5), datagram.recv_from(&mut buffer))
                .await
                .expect("kernel loss matrix response timed out")
                .unwrap();
        assert_eq!(&buffer[..received.0], payload.as_bytes(), "case {case}");
        assert_eq!(received.1, target);

        datagram.close().await.unwrap();
        chain.close().await;
        server.await.unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn chain_datagram_close_cancels_pending_recv() {
    let (address, certificate, server, ready) = spawn_uot_stall_fixture().await;
    let chain = chain_client(address, certificate);
    let proxy = ChainProxy::new(chain.clone());
    let target = Endpoint::ip(Network::Udp, "198.51.100.11:5353".parse().unwrap());
    let datagram: Arc<dyn yuhaiin_core::proxy::AsyncDatagram> = proxy
        .open_datagram(&FlowContext::new(target))
        .await
        .unwrap()
        .into();
    ready.notified().await;

    let pending = {
        let datagram = Arc::clone(&datagram);
        tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            datagram.recv_from(&mut buffer).await
        })
    };
    tokio::task::yield_now().await;
    datagram.close().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(1), pending)
        .await
        .expect("pending UOT recv was not cancelled")
        .unwrap();
    assert_eq!(result.unwrap_err().kind, yuhaiin_core::ErrorKind::Closed);

    chain.close().await;
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("stall fixture did not observe UOT close")
        .unwrap();
}
