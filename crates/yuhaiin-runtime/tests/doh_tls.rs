#![cfg(feature = "doh-tls")]

use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::Response;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use yuhaiin_core::dns::{DnsResponse, encode_response};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, AsyncProxySelector, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, DomainName, Error, ErrorKind, FlowContext, IpSet, ResolveStrategy};
use yuhaiin_runtime::{
    ResolverProxyBridge, ResolverTransportFactory, RustCryptoDohResolverFactory,
    RustCryptoDotResolverFactory, RustCryptoResolverFactory,
};
use yuhaiin_store::{GoResolverRuntimeConfig, GoResolverTransport};

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

fn server_config(with_h2: bool) -> Arc<ServerConfig> {
    let leaf = certificate_der(LEAF_CERTIFICATE_PEM);
    let key = rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY_PEM))
        .unwrap()
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(leaf)], key)
        .unwrap();
    if with_h2 {
        config.alpn_protocols = vec![b"h2".to_vec()];
    }
    Arc::new(config)
}

async fn spawn_doh_server(
    with_h2: bool,
    response_status: http::StatusCode,
    response_content_type: &'static str,
    response_delay: Duration,
) -> (
    std::net::SocketAddr,
    oneshot::Receiver<std::net::SocketAddr>,
) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (finished, done) = oneshot::channel();
    tokio::spawn(async move {
        let Ok((stream, peer)) = listener.accept().await else {
            return;
        };
        let tls = match TlsAcceptor::from(server_config(with_h2))
            .accept(stream)
            .await
        {
            Ok(tls) => tls,
            Err(_) => return,
        };
        let Ok(mut connection) = h2::server::handshake(tls).await else {
            return;
        };
        let Some(Ok((request, mut respond))) = connection.accept().await else {
            return;
        };
        let mut body = request.into_body();
        let mut query = Vec::new();
        while let Some(result) = body.data().await {
            let Ok(chunk) = result else { return };
            body.flow_control().release_capacity(chunk.len()).unwrap();
            query.extend_from_slice(&chunk);
        }
        tokio::time::sleep(response_delay).await;
        let response = encode_response(
            &query,
            &DnsResponse {
                addresses: IpSet {
                    v4: vec!["192.0.2.123".parse().unwrap()],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            },
        )
        .unwrap();
        let head = Response::builder()
            .status(response_status)
            .header(http::header::CONTENT_TYPE, response_content_type)
            .body(())
            .unwrap();
        let mut send = respond.send_response(head, false).unwrap();
        send.send_data(Bytes::from(response), true).unwrap();
        let _ = finished.send(peer);
        // A real DoH endpoint normally keeps TLS/HTTP2 alive after one
        // response. Let the client drop the connection instead of producing
        // an artificial unexpected TLS EOF in the response path.
        let _ = connection.accept().await;
    });
    (address, done)
}

async fn spawn_dot_server() -> (
    std::net::SocketAddr,
    oneshot::Receiver<std::net::SocketAddr>,
) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let (finished, done) = oneshot::channel();
    tokio::spawn(async move {
        let Ok((stream, peer)) = listener.accept().await else {
            return;
        };
        let Ok(mut stream) = TlsAcceptor::from(server_config(false)).accept(stream).await else {
            return;
        };
        let mut length = [0u8; 2];
        if stream.read_exact(&mut length).await.is_err() {
            return;
        }
        let mut query = vec![0u8; u16::from_be_bytes(length) as usize];
        if stream.read_exact(&mut query).await.is_err() {
            return;
        }
        let response = encode_response(
            &query,
            &DnsResponse {
                addresses: IpSet {
                    v4: vec!["192.0.2.124".parse().unwrap()],
                    v6: Vec::new(),
                },
                ptr_names: Vec::new(),
                service_bindings: Vec::new(),
                minimum_ttl: Some(30),
            },
        )
        .unwrap();
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&response).await.unwrap();
        let _ = finished.send(peer);
    });
    (address, done)
}

fn resolver_config(address: std::net::SocketAddr) -> GoResolverRuntimeConfig {
    GoResolverRuntimeConfig {
        id: "doh-local".to_owned(),
        transport: GoResolverTransport::Doh,
        host: format!("https://{address}/dns-query"),
        subnet: None,
        tls_server_name: Some("localhost".to_owned()),
    }
}

fn dot_resolver_config(address: std::net::SocketAddr) -> GoResolverRuntimeConfig {
    GoResolverRuntimeConfig {
        id: "dot-local".to_owned(),
        transport: GoResolverTransport::Dot,
        host: address.to_string(),
        subnet: None,
        tls_server_name: Some("localhost".to_owned()),
    }
}

struct FixedTargetProxy {
    target: std::net::SocketAddr,
    calls: Arc<AtomicUsize>,
}

impl AsyncProxy for FixedTargetProxy {
    fn connect<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, yuhaiin_core::Result<BoxAsyncStream>> {
        let target = self.target;
        let calls = self.calls.clone();
        Box::pin(async move {
            calls.fetch_add(1, Ordering::Relaxed);
            let stream = tokio::net::TcpStream::connect(target)
                .await
                .map_err(|error| {
                    Error::new(ErrorKind::Io, format!("test proxy connect: {error}"))
                })?;
            Ok(Box::new(stream) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, yuhaiin_core::Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async { Err(Error::new(ErrorKind::Unsupported, "test proxy has no UDP")) })
    }

    fn close(&self) -> BoxFuture<'_, yuhaiin_core::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

struct FixedTargetSelector {
    proxy: Arc<dyn AsyncProxy>,
}

impl AsyncProxySelector for FixedTargetSelector {
    fn select(&self, _context: &FlowContext) -> Arc<dyn AsyncProxy> {
        self.proxy.clone()
    }
}

#[tokio::test(flavor = "current_thread")]
async fn rustcrypto_doh_factory_resolves_over_real_tls_and_http2() {
    let (address, done) = spawn_doh_server(
        true,
        http::StatusCode::OK,
        "application/dns-message",
        Duration::ZERO,
    )
    .await;
    let factory = RustCryptoDohResolverFactory::new(
        &[certificate_der(CA_CERTIFICATE_PEM)],
        Duration::from_secs(2),
        8,
    )
    .unwrap();
    let resolver = factory.build(&resolver_config(address)).unwrap();
    let answer = resolver
        .resolve(
            &DomainName::new("example.com").unwrap(),
            ResolveStrategy::OnlyIpv4,
        )
        .await
        .unwrap();
    assert_eq!(
        answer.v4,
        vec!["192.0.2.123".parse::<std::net::Ipv4Addr>().unwrap()]
    );
    done.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn rustcrypto_doh_proxy_resolver_uses_the_runtime_selector_before_tls() {
    let (address, done) = spawn_doh_server(
        true,
        http::StatusCode::OK,
        "application/dns-message",
        Duration::ZERO,
    )
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    let bridge = Arc::new(ResolverProxyBridge::new());
    bridge.set_proxy_resolver_id(Some("doh-proxy"));
    bridge.set_selector(Arc::new(FixedTargetSelector {
        proxy: Arc::new(FixedTargetProxy {
            target: address,
            calls: calls.clone(),
        }),
    }));
    let factory = RustCryptoDohResolverFactory::new(
        &[certificate_der(CA_CERTIFICATE_PEM)],
        Duration::from_secs(2),
        8,
    )
    .unwrap()
    .with_proxy_bridge(bridge);
    let mut config = resolver_config(address);
    config.id = "doh-proxy".to_owned();
    let answer = factory
        .build(&config)
        .unwrap()
        .resolve(
            &DomainName::new("example.com").unwrap(),
            ResolveStrategy::OnlyIpv4,
        )
        .await
        .unwrap();
    assert_eq!(
        answer.v4,
        vec!["192.0.2.123".parse::<std::net::Ipv4Addr>().unwrap()]
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    done.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn rustcrypto_dot_factory_resolves_over_real_tls_and_tcp_framing() {
    let (address, done) = spawn_dot_server().await;
    let factory = RustCryptoDotResolverFactory::new(
        &[certificate_der(CA_CERTIFICATE_PEM)],
        Duration::from_secs(2),
        8,
    )
    .unwrap();
    let resolver = factory.build(&dot_resolver_config(address)).unwrap();
    let answer = resolver
        .resolve(
            &DomainName::new("example.com").unwrap(),
            ResolveStrategy::OnlyIpv4,
        )
        .await
        .unwrap();
    assert_eq!(
        answer.v4,
        vec!["192.0.2.124".parse::<std::net::Ipv4Addr>().unwrap()]
    );
    done.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn rustcrypto_encrypted_resolvers_honor_local_bind_address() {
    let (doh_address, doh_done) = spawn_doh_server(
        true,
        http::StatusCode::OK,
        "application/dns-message",
        Duration::ZERO,
    )
    .await;
    let (dot_address, dot_done) = spawn_dot_server().await;
    let factory = RustCryptoResolverFactory::new(
        &[certificate_der(CA_CERTIFICATE_PEM)],
        Duration::from_secs(2),
        8,
    )
    .unwrap();
    let local_bind_addresses = ["127.0.0.2".parse().unwrap()];

    let doh = factory
        .build_with_policy(&resolver_config(doh_address), &local_bind_addresses)
        .unwrap();
    let doh_answer = doh
        .resolve(
            &DomainName::new("example.com").unwrap(),
            ResolveStrategy::OnlyIpv4,
        )
        .await
        .unwrap();
    assert_eq!(
        doh_answer.v4,
        vec!["192.0.2.123".parse::<std::net::Ipv4Addr>().unwrap()]
    );

    let dot = factory
        .build_with_policy(&dot_resolver_config(dot_address), &local_bind_addresses)
        .unwrap();
    let dot_answer = dot
        .resolve(
            &DomainName::new("example.com").unwrap(),
            ResolveStrategy::OnlyIpv4,
        )
        .await
        .unwrap();
    assert_eq!(
        dot_answer.v4,
        vec!["192.0.2.124".parse::<std::net::Ipv4Addr>().unwrap()]
    );

    assert_eq!(
        doh_done.await.unwrap().ip(),
        "127.0.0.2".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(
        dot_done.await.unwrap().ip(),
        "127.0.0.2".parse::<std::net::IpAddr>().unwrap()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rustcrypto_registry_resolves_mixed_doh_and_dot_configs() {
    let (doh_address, doh_done) = spawn_doh_server(
        true,
        http::StatusCode::OK,
        "application/dns-message",
        Duration::ZERO,
    )
    .await;
    let (dot_address, dot_done) = spawn_dot_server().await;
    let factory = RustCryptoResolverFactory::new(
        &[certificate_der(CA_CERTIFICATE_PEM)],
        Duration::from_secs(2),
        8,
    )
    .unwrap();

    let doh = factory.build(&resolver_config(doh_address)).unwrap();
    let doh_answer = doh
        .resolve(
            &DomainName::new("example.com").unwrap(),
            ResolveStrategy::OnlyIpv4,
        )
        .await
        .unwrap();
    assert_eq!(
        doh_answer.v4,
        vec!["192.0.2.123".parse::<std::net::Ipv4Addr>().unwrap()]
    );

    let dot = factory.build(&dot_resolver_config(dot_address)).unwrap();
    let dot_answer = dot
        .resolve(
            &DomainName::new("example.com").unwrap(),
            ResolveStrategy::OnlyIpv4,
        )
        .await
        .unwrap();
    assert_eq!(
        dot_answer.v4,
        vec!["192.0.2.124".parse::<std::net::Ipv4Addr>().unwrap()]
    );
    doh_done.await.unwrap();
    dot_done.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn rustcrypto_doh_rejects_bad_certificate_and_missing_h2() {
    let (address, _) = spawn_doh_server(
        true,
        http::StatusCode::OK,
        "application/dns-message",
        Duration::ZERO,
    )
    .await;
    let factory = RustCryptoDohResolverFactory::new(&[], Duration::from_secs(2), 8).unwrap();
    let error = factory
        .build(&resolver_config(address))
        .unwrap()
        .resolve(
            &DomainName::new("example.com").unwrap(),
            ResolveStrategy::OnlyIpv4,
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, yuhaiin_core::ErrorKind::Protocol);

    let (address, _) = spawn_doh_server(
        false,
        http::StatusCode::OK,
        "application/dns-message",
        Duration::ZERO,
    )
    .await;
    let factory = RustCryptoDohResolverFactory::new(
        &[certificate_der(CA_CERTIFICATE_PEM)],
        Duration::from_secs(2),
        8,
    )
    .unwrap();
    let error = factory
        .build(&resolver_config(address))
        .unwrap()
        .resolve(
            &DomainName::new("example.com").unwrap(),
            ResolveStrategy::OnlyIpv4,
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, yuhaiin_core::ErrorKind::Protocol);
}

#[tokio::test(flavor = "current_thread")]
async fn rustcrypto_doh_rejects_non_dns_http_response() {
    let (address, _) = spawn_doh_server(
        true,
        http::StatusCode::BAD_GATEWAY,
        "text/plain",
        Duration::ZERO,
    )
    .await;
    let factory = RustCryptoDohResolverFactory::new(
        &[certificate_der(CA_CERTIFICATE_PEM)],
        Duration::from_secs(2),
        8,
    )
    .unwrap();
    let error = factory
        .build(&resolver_config(address))
        .unwrap()
        .resolve(
            &DomainName::new("example.com").unwrap(),
            ResolveStrategy::OnlyIpv4,
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, yuhaiin_core::ErrorKind::Protocol);
}

#[tokio::test(flavor = "current_thread")]
async fn rustcrypto_doh_cancels_a_slow_response_at_the_resolver_timeout() {
    let (address, _) = spawn_doh_server(
        true,
        http::StatusCode::OK,
        "application/dns-message",
        Duration::from_millis(100),
    )
    .await;
    let factory = RustCryptoDohResolverFactory::new(
        &[certificate_der(CA_CERTIFICATE_PEM)],
        Duration::from_millis(20),
        8,
    )
    .unwrap();
    let error = factory
        .build(&resolver_config(address))
        .unwrap()
        .resolve(
            &DomainName::new("example.com").unwrap(),
            ResolveStrategy::OnlyIpv4,
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, yuhaiin_core::ErrorKind::Timeout);
}

#[test]
fn doh_factory_keeps_system_resolver_for_non_doh_configs() {
    let factory = RustCryptoDohResolverFactory::new(&[], Duration::from_secs(1), 4).unwrap();
    let config = GoResolverRuntimeConfig {
        id: "system".to_owned(),
        transport: GoResolverTransport::System,
        host: "system".to_owned(),
        subnet: None,
        tls_server_name: None,
    };
    let resolver = factory.build(&config).unwrap();
    let _ = resolver;
}
