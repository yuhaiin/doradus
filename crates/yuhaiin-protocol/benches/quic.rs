use std::io::Cursor;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy};
use yuhaiin_core::{Endpoint, FlowContext, Network};
use yuhaiin_protocol::quic::{
    FragmentReassembler, QuicConfig, QuicProxy, QuicServer, QuicServerConfig, decode_frame,
    encode_datagrams,
};

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
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap(),
    )
}

fn bench_codec(c: &mut Criterion) {
    let mut group = c.benchmark_group("quic_codec");
    for size in [64, 1200, 16 * 1024, 64 * 1024] {
        let payload = vec![0x5a; size];
        group.bench_with_input(BenchmarkId::new("encode", size), &payload, |b, payload| {
            b.iter(|| black_box(encode_datagrams(7, 11, black_box(payload), 1200).unwrap()));
        });
    }

    let single = encode_datagrams(7, 11, &[0x5a; 1024], 1200).unwrap();
    group.bench_function("decode_single", |b| {
        b.iter(|| black_box(decode_frame(black_box(&single[0])).unwrap()));
    });

    let fragmented = encode_datagrams(7, 11, &[0x5a; 64 * 1024], 1200).unwrap();
    group.bench_function("decode_and_reassemble", |b| {
        b.iter(|| {
            let mut reassembler = FragmentReassembler::new(Duration::from_secs(2), 1024 * 1024);
            let now = Instant::now();
            for datagram in &fragmented {
                let frame = decode_frame(black_box(datagram)).unwrap();
                let _ = reassembler.push(frame, now);
            }
            black_box(reassembler.incomplete_bytes());
        });
    });
    group.finish();
}

fn bench_loopback(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (proxy, server, client_datagram, server_datagram) = runtime.block_on(async {
        let server = Arc::new(
            QuicServer::new(
                "127.0.0.1:0".parse().unwrap(),
                server_tls(),
                QuicServerConfig::default(),
            )
            .unwrap(),
        );
        let server_address = server.local_addr().unwrap();
        let accepting = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await.unwrap() })
        };
        let proxy = Arc::new(
            QuicProxy::new(QuicConfig {
                insecure_skip_verify: true,
                ..QuicConfig::new(server_address, "localhost", Duration::from_secs(2))
            })
            .unwrap(),
        );
        let context = FlowContext::new(Endpoint::ip(Network::Udp, server_address));
        let client_datagram = proxy.open_datagram(&context).await.unwrap();
        let connection = accepting.await.unwrap();
        client_datagram
            .send_to(b"warmup", Endpoint::ip(Network::Udp, server_address))
            .await
            .unwrap();
        let server_datagram = connection.accept_datagram().await.unwrap();
        let mut warmup_buffer = [0; 16];
        server_datagram.recv_from(&mut warmup_buffer).await.unwrap();
        (proxy, server, client_datagram, server_datagram)
    });

    let server_address = server.local_addr().unwrap();
    let mut group = c.benchmark_group("quic_loopback");
    for size in [64, 1200, 16 * 1024] {
        let payload = vec![0x5a; size];
        let mut buffer = vec![0; size];
        group.bench_with_input(
            BenchmarkId::new("datagram_round_trip", size),
            &payload,
            |b, payload| {
                b.iter_custom(|iterations| {
                    let started = Instant::now();
                    runtime.block_on(async {
                        for _ in 0..iterations {
                            client_datagram
                                .send_to(payload, Endpoint::ip(Network::Udp, server_address))
                                .await
                                .unwrap();
                            let (length, _) = server_datagram.recv_from(&mut buffer).await.unwrap();
                            black_box(length);
                        }
                    });
                    started.elapsed()
                });
            },
        );
    }
    group.finish();
    runtime.block_on(async {
        client_datagram.close().await.unwrap();
        proxy.close().await.unwrap();
    });
    server.close();
}

criterion_group!(benches, bench_codec, bench_loopback);
criterion_main!(benches);
