#![cfg(feature = "quic")]

use std::io::Cursor;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use tokio::sync::oneshot;
use yuhaiin_dns::{
    DomainName, DoqResolverConfig, DoqResolverFactory, IpSet, dns::DnsResponse,
    dns::encode_response, probe_doq,
};

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

fn certificate_der(pem: &[u8]) -> Vec<u8> {
    rustls_pemfile::certs(&mut Cursor::new(pem))
        .next()
        .unwrap()
        .unwrap()
        .to_vec()
}

async fn spawn_server() -> (std::net::SocketAddr, oneshot::Receiver<()>) {
    let key = rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY_PEM))
        .unwrap()
        .unwrap();
    let mut tls =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate_der(LEAF_CERTIFICATE_PEM))],
                key,
            )
            .unwrap();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = endpoint.local_addr().unwrap();
    let (finished, done) = oneshot::channel();
    tokio::spawn(async move {
        let Some(incoming) = endpoint.accept().await else {
            return;
        };
        let Ok(connection) = incoming.await else {
            return;
        };
        let Ok((mut send, mut recv)) = connection.accept_bi().await else {
            return;
        };
        let Ok(request) = recv.read_to_end(65_537).await else {
            return;
        };
        assert_eq!(
            u16::from_be_bytes([request[0], request[1]]) as usize,
            request.len() - 2
        );
        assert_eq!(&request[2..][..2], &[0, 0]);
        let response = encode_response(
            &request[2..],
            &DnsResponse {
                addresses: IpSet {
                    v4: vec!["192.0.2.125".parse().unwrap()],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            },
        )
        .unwrap();
        send.write_all(&(response.len() as u16).to_be_bytes())
            .await
            .unwrap();
        send.write_all(&response).await.unwrap();
        send.finish().unwrap();
        let _ = finished.send(());
        let _ = connection.closed().await;
    });
    (address, done)
}

#[tokio::test(flavor = "current_thread")]
async fn doq_resolver_round_trips_through_quinn() {
    let (address, done) = spawn_server().await;
    let factory = DoqResolverFactory::new(
        &[certificate_der(CA_CERTIFICATE_PEM)],
        std::time::Duration::from_secs(2),
        8,
    )
    .unwrap();
    let elapsed = probe_doq(
        &factory,
        DoqResolverConfig {
            id: "doq-local".to_owned(),
            host: address.to_string(),
            server_name: Some("localhost".to_owned()),
            local_bind_addresses: Vec::new(),
            bind_interface: None,
        },
        &DomainName::new("example.com").unwrap(),
        std::time::Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert!(elapsed > std::time::Duration::ZERO);
    done.await.unwrap();
}
