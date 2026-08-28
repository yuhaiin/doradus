#![allow(dead_code)]

#[cfg(all(feature = "tls-ring", feature = "websocket"))]
use std::io::Cursor;

#[cfg(all(feature = "tls-ring", feature = "websocket"))]
use std::sync::Arc;

#[cfg(all(feature = "tls-ring", feature = "websocket"))]
use rustls::ServerConfig;
#[cfg(all(feature = "tls-ring", feature = "websocket"))]
use tokio::net::TcpStream;
#[cfg(all(feature = "tls-ring", feature = "websocket"))]
use tokio_rustls::{TlsAcceptor, server::TlsStream};
#[cfg(all(feature = "tls-ring", feature = "websocket"))]
use tokio_tungstenite::WebSocketStream;

#[cfg(all(feature = "tls-ring", feature = "websocket"))]
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

#[cfg(all(feature = "tls-ring", feature = "websocket"))]
const PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqkH6SeIb9vVEJ6WecsMk5Pn/a8sQ+vdNS/ZSkl3KwfoAoGCCqGSM49
AwEHoUQDQgAEs+fCVgURGLUyBsk24EdlX95KlMZ0kJAg7LEG3wuVHVlMQbTqlbIW
clUjNRLig+64dzRFwMSW0Zv9aiXJCUzvlA==
-----END EC PRIVATE KEY-----
"#;

#[cfg(all(feature = "tls-ring", feature = "websocket"))]
fn tls_server_config() -> Arc<ServerConfig> {
    let certificate = rustls_pemfile::certs(&mut Cursor::new(LEAF_CERTIFICATE_PEM))
        .next()
        .unwrap()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY_PEM))
        .unwrap()
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(
                certificate.to_vec(),
            )],
            key,
        )
        .unwrap();
    Arc::new(config)
}

#[cfg(all(feature = "tls-ring", feature = "websocket"))]
pub async fn accept_tls_websocket(stream: TcpStream) -> WebSocketStream<TlsStream<TcpStream>> {
    let tls = TlsAcceptor::from(tls_server_config())
        .accept(stream)
        .await
        .unwrap();
    tokio_tungstenite::accept_async(tls).await.unwrap()
}
