//! Linux transparent TCP inbound adapters.
//!
//! `tproxy` receives the original destination from the accepted socket's
//! local address, while `redir` obtains it through `SO_ORIGINAL_DST`.  The
//! socket setup is isolated here because it is Linux capability/namespace
//! dependent; after the destination is recovered, both protocols use the
//! ordinary runtime router and outbound relay.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::task::JoinSet;

use yuhaiin_core::proxy::BoxAsyncStream;
use yuhaiin_core::{Endpoint, Error, ErrorKind, Network, Result};

use super::common::io_error;
use crate::inbound::{
    InboundHandler, InboundSpec, InboundTlsAcceptor, InboundUdpFlowPolicy, InboundUdpSession,
    prepare_inbound_stream,
};
use crate::{ConnectionMonitor, RuntimeProxySelector};

pub(crate) async fn serve_listener(
    listen: SocketAddr,
    protocol: String,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    tls_acceptor: Option<InboundTlsAcceptor>,
) -> Result<()> {
    let listener = yuhaiin_protocol::transparent::bind_listener(
        listen,
        protocol.eq_ignore_ascii_case("tproxy"),
    )?;
    let inbound = InboundHandler::new(spec, Arc::clone(&selector), Arc::clone(&monitor));
    let mut connections = JoinSet::new();
    let result = async {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, peer) = accepted.map_err(io_error)?;
                    let protocol = protocol.clone();
                    let inbound = Arc::clone(&inbound);
                    let tls_acceptor = tls_acceptor.clone();
                    connections.spawn(async move {
                        handle_connection(
                            stream,
                            peer,
                            &protocol,
                            inbound,
                            tls_acceptor,
                        )
                        .await
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        monitor.warn(format!("transparent connection task stopped: {error}"));
                    } else if let Ok(Err(error)) = result {
                        monitor.warn(format!("transparent connection failed: {error}"));
                    }
                }
            }
        }
    }
    .await;
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    result
}

pub(crate) async fn serve_udp_listener(
    listen: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()> {
    monitor.info(format!("transparent UDP listener ready at {listen}"));
    let inbound = InboundHandler::new(spec, Arc::clone(&selector), Arc::clone(&monitor));
    let codec = yuhaiin_protocol::transparent::UdpServer::bind(
        listen,
        inbound.selector().udp_buffer_size(),
    )?;
    InboundUdpSession::new(codec, inbound).run().await
}

impl InboundUdpFlowPolicy for yuhaiin_protocol::transparent::UdpServer {}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    protocol: &str,
    inbound: Arc<InboundHandler>,
    tls_acceptor: Option<InboundTlsAcceptor>,
) -> Result<()> {
    let destination = yuhaiin_protocol::transparent::tcp_destination(
        &stream,
        protocol.eq_ignore_ascii_case("tproxy"),
    )?;
    if destination.ip().is_unspecified() || destination.port() == 0 {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("{protocol} did not provide a usable original destination"),
        ));
    }
    let stream = prepare_inbound_stream(stream, inbound.spec(), tls_acceptor, false).await?;
    handle_transparent_stream(stream, peer, protocol, inbound, destination).await
}

async fn handle_transparent_stream(
    stream: BoxAsyncStream,
    peer: SocketAddr,
    protocol: &str,
    inbound: Arc<InboundHandler>,
    destination: SocketAddr,
) -> Result<()> {
    let endpoint = Endpoint::ip(Network::Tcp, destination);
    inbound.serve_stream(stream, peer, protocol, endpoint).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use yuhaiin_core::dns_resolver::SystemAsyncIpResolver;
    use yuhaiin_store::{ConfigStore, GoNodeRecord};

    #[cfg(feature = "doh-tls")]
    use std::io::Cursor;

    #[cfg(feature = "doh-tls")]
    use rustls::pki_types::ServerName;
    #[cfg(feature = "doh-tls")]
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    #[cfg(feature = "doh-tls")]
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[cfg(feature = "doh-tls")]
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

    #[cfg(feature = "doh-tls")]
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

    #[cfg(feature = "doh-tls")]
    const PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqkH6SeIb9vVEJ6WecsMk5Pn/a8sQ+vdNS/ZSkl3KwfoAoGCCqGSM49
AwEHoUQDQgAEs+fCVgURGLUyBsk24EdlX95KlMZ0kJAg7LEG3wuVHVlMQbTqlbIW
clUjNRLig+64dzRFwMSW0Zv9aiXJCUzvlA==
-----END EC PRIVATE KEY-----
"#;

    #[cfg(feature = "doh-tls")]
    fn transparent_tls_acceptor() -> TlsAcceptor {
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
            .with_single_cert(vec![certificate], key)
            .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }

    #[cfg(feature = "doh-tls")]
    fn transparent_tls_connector() -> TlsConnector {
        let mut roots = RootCertStore::empty();
        let certificate = rustls_pemfile::certs(&mut Cursor::new(CA_CERTIFICATE_PEM))
            .next()
            .unwrap()
            .unwrap();
        roots.add(certificate).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }

    async fn direct_test_runtime() -> (Arc<RuntimeProxySelector>, Arc<ConnectionMonitor>) {
        use crate::{RuntimeBuilder, RuntimeController};

        let store = ConfigStore::open_memory().await.unwrap();
        let controller = RuntimeController::from_builder(RuntimeBuilder::new(
            store,
            Arc::new(SystemAsyncIpResolver),
        ))
        .await
        .unwrap();
        controller
            .store()
            .repository()
            .put_go_node(&GoNodeRecord {
                id: "direct".to_owned(),
                name: "Direct".to_owned(),
                group_name: "default".to_owned(),
                origin: "transparent-test".to_owned(),
                enabled: true,
                chain_types_json: br#"["direct"]"#.to_vec(),
                updated_at: 1,
                data_json: br#"{"protocol":"direct"}"#.to_vec(),
            })
            .await
            .unwrap();
        controller.reload().await.unwrap();
        let selector = controller
            .build_proxy_selector("", "direct", "", "", Duration::from_secs(2))
            .await
            .unwrap();
        (selector, controller.monitor())
    }

    #[test]
    fn transparent_transport_allowlist_preserves_original_destination() {
        for transport in ["normal", "tls", "tls_auto", "aead", "http_mock"] {
            assert!(
                crate::inbound::is_supported_transparent_transport(transport),
                "transparent transport {transport} should be accepted"
            );
        }
        for transport in ["http2", "websocket", "proxy", "mux", "reality", "quic"] {
            assert!(
                !crate::inbound::is_supported_transparent_transport(transport),
                "transparent transport {transport} must not lose the original destination"
            );
        }
    }

    #[tokio::test]
    async fn transparent_aead_transport_is_unwrapped_before_relay() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_test_runtime().await;
        let server_task = tokio::spawn(async move {
            let (stream, peer) = inbound_listener.accept().await.unwrap();
            let spec = InboundSpec {
                id: "transparent-aead".to_owned(),
                name: "transparent-aead".to_owned(),
                protocol: "redir".to_owned(),
                listen: inbound,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: crate::inbound::UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["aead".to_owned()],
                aead_password: Some("secret".to_owned()),
                aead_method: yuhaiin_protocol::aead::CryptoMethod::XChacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            };
            let stream = prepare_inbound_stream(stream, &spec, None, false)
                .await
                .unwrap();
            handle_transparent_stream(
                stream,
                peer,
                "redir",
                InboundHandler::new(spec, selector, monitor),
                target,
            )
            .await
            .unwrap();
        });

        let mut client = yuhaiin_protocol::aead::client(
            Box::new(TcpStream::connect(inbound).await.unwrap()),
            b"secret",
            yuhaiin_protocol::aead::CryptoMethod::XChacha20Poly1305,
        )
        .await
        .unwrap();
        client.write_all(b"transparent-aead-payload").await.unwrap();
        client.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"transparent-aead-payload");

        server_task.await.unwrap();
        target_task.await.unwrap();
    }

    #[cfg(feature = "doh-tls")]
    #[tokio::test]
    async fn transparent_tls_transport_is_unwrapped_before_relay() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.unwrap();
            let mut payload = Vec::new();
            stream.read_to_end(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let inbound = inbound_listener.local_addr().unwrap();
        let (selector, monitor) = direct_test_runtime().await;
        let acceptor = transparent_tls_acceptor();
        let server_task = tokio::spawn(async move {
            let (stream, peer) = inbound_listener.accept().await.unwrap();
            let spec = InboundSpec {
                id: "transparent-tls".to_owned(),
                name: "transparent-tls".to_owned(),
                protocol: "redir".to_owned(),
                listen: inbound,
                username: String::new(),
                password: String::new(),
                auth: None,
                udp_mode: crate::inbound::UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["tls".to_owned()],
                aead_password: None,
                aead_method: yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
                outbound_id: "direct".to_owned(),
                reverse_target: None,
                reverse_http: None,
            };
            let stream = prepare_inbound_stream(stream, &spec, Some(acceptor), false)
                .await
                .unwrap();
            handle_transparent_stream(
                stream,
                peer,
                "redir",
                InboundHandler::new(spec, selector, monitor),
                target,
            )
            .await
            .unwrap();
        });

        let connector = transparent_tls_connector();
        let mut client = connector
            .connect(
                ServerName::try_from("localhost".to_owned()).unwrap(),
                TcpStream::connect(inbound).await.unwrap(),
            )
            .await
            .unwrap();
        client.write_all(b"transparent-tls-payload").await.unwrap();
        client.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"transparent-tls-payload");

        server_task.await.unwrap();
        target_task.await.unwrap();
    }
}
