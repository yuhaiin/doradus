//! Shared process-level fixtures for runtime integration tests.
//!
//! The fixtures deliberately use loopback sockets and a cache-owned state
//! directory. `YUHAIIN_INTEGRATION_DIR` can point at a persistent directory
//! when a developer or Podman job wants to inspect/reuse the SQLite state.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Cursor};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use http::Response;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex as AsyncMutex, oneshot, watch};
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream};
use yuhaiin_chain::{YuubinsyaH2Server, YuubinsyaServerProxy};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream, DirectAsyncProxy};
use yuhaiin_core::yuubinsya::derive_salt;
use yuhaiin_core::{BoxFuture, Endpoint, FlowContext, Result};
use yuhaiin_store::ConfigStore;

pub const YUUBINSYA_PASSWORD: &str = "runtime-integration-yuubinsya";
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

pub fn integration_dir(name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os("YUHAIIN_INTEGRATION_DIR") {
        return PathBuf::from(path).join(name);
    }
    let cache = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(".cache"));
    cache
        .join("yuhaiin-rust")
        .join("integration")
        .join(name)
        .join(std::process::id().to_string())
}

pub async fn reserve_loopback() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

pub async fn connect_loopback(address: SocketAddr) -> TcpStream {
    for _ in 0..120 {
        match TcpStream::connect(address).await {
            Ok(stream) => return stream,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("loopback listener {address} did not become ready");
}

/// Connect to a runtime TLS inbound using the fixture certificate. The
/// certificate is intentionally not trusted by the host; the verifier keeps
/// TLS handshake signature validation enabled while skipping only chain and
/// hostname validation, matching the outbound `insecure_skip_verify` test
/// semantics without introducing a system CA dependency.
pub async fn connect_tls_loopback(address: SocketAddr) -> TlsStream<TcpStream> {
    connect_tls_loopback_with_alpn(address, &[]).await
}

/// Connect to an inbound TLS listener while advertising the given ALPN
/// protocols. HTTP/2 inbound tests must negotiate `h2`; ordinary TLS/HTTP
/// tests intentionally keep the list empty and exercise HTTP/1.1 fallback.
pub async fn connect_tls_h2_loopback(address: SocketAddr) -> TlsStream<TcpStream> {
    connect_tls_loopback_with_alpn(address, &[b"h2"]).await
}

async fn connect_tls_loopback_with_alpn(
    address: SocketAddr,
    alpn_protocols: &[&[u8]],
) -> TlsStream<TcpStream> {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new(provider))
        .with_no_client_auth();
    config.alpn_protocols = alpn_protocols.iter().map(|value| value.to_vec()).collect();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from("localhost").unwrap().to_owned();
    connector
        .connect(server_name, connect_loopback(address).await)
        .await
        .unwrap()
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A small HTTP CONNECT proxy and target server used to prove that the Rust
/// service sends a flow through a configured outbound, rather than merely
/// connecting directly from the inbound listener.
pub struct ConnectFixture {
    pub target: SocketAddr,
    pub outbound: SocketAddr,
    pub connect_authorities: Arc<Mutex<Vec<String>>>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl ConnectFixture {
    pub async fn start() -> Self {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap();
        let outbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let outbound = outbound_listener.local_addr().unwrap();
        let connect_authorities = Arc::new(Mutex::new(Vec::new()));
        let (shutdown, _) = watch::channel(false);

        let target_shutdown = shutdown.subscribe();
        let target_task = tokio::spawn(serve_target(target_listener, target_shutdown));
        let proxy_shutdown = shutdown.subscribe();
        let proxy_authorities = connect_authorities.clone();
        let proxy_task = tokio::spawn(serve_connect_proxy(
            outbound_listener,
            target_shutdown_for(proxy_shutdown),
            proxy_authorities,
        ));

        Self {
            target,
            outbound,
            connect_authorities,
            shutdown,
            tasks: vec![target_task, proxy_task],
        }
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

/// A minimal no-auth SOCKS5 proxy fixture. It records the address form sent by
/// the runtime and maps domain destinations to the loopback echo target so
/// the integration test proves proxy-side DNS framing without host DNS.
pub struct Socks5Fixture {
    pub target: SocketAddr,
    pub outbound: SocketAddr,
    pub destinations: Arc<Mutex<Vec<String>>>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

#[derive(Clone, Copy)]
pub enum H2FinalProtocol {
    Http,
    Socks5,
}

/// A prior-knowledge HTTP/2 server with an HTTP CONNECT or SOCKS5 protocol
/// endpoint behind each CONNECT stream. It exercises the same composition
/// that a configured Rust chain uses: fixed -> HTTP/2 -> final protocol.
pub struct H2ProtocolFixture {
    pub outbound: SocketAddr,
    shutdown: watch::Sender<bool>,
    server_task: tokio::task::JoinHandle<()>,
}

impl H2ProtocolFixture {
    pub async fn start(protocol: H2FinalProtocol) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let outbound = listener.local_addr().unwrap();
        let (shutdown, receiver) = watch::channel(false);
        let server_task = tokio::spawn(serve_h2_protocol_listener(listener, receiver, protocol));
        Self {
            outbound,
            shutdown,
            server_task,
        }
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        let _ = self.server_task.await;
    }
}

impl Socks5Fixture {
    pub async fn start() -> Self {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap();
        let outbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let outbound = outbound_listener.local_addr().unwrap();
        let destinations = Arc::new(Mutex::new(Vec::new()));
        let (shutdown, _) = watch::channel(false);

        let target_task = tokio::spawn(serve_target(target_listener, shutdown.subscribe()));
        let proxy_task = tokio::spawn(serve_socks5_proxy(
            outbound_listener,
            shutdown.subscribe(),
            target,
            destinations.clone(),
        ));
        Self {
            target,
            outbound,
            destinations,
            shutdown,
            tasks: vec![target_task, proxy_task],
        }
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

struct DomainMappingProxy {
    direct: DirectAsyncProxy,
    tcp_target: SocketAddr,
    udp_target: SocketAddr,
}

impl DomainMappingProxy {
    fn mapped_context(&self, context: &FlowContext) -> FlowContext {
        let mut mapped = context.clone();
        let target = if context.network == yuhaiin_core::Network::Udp {
            self.udp_target
        } else {
            self.tcp_target
        };
        mapped.resolved_destination = Some(Endpoint::ip(context.network, target));
        mapped
    }
}

struct DomainMappingDatagram {
    inner: Box<dyn AsyncDatagram>,
    target: SocketAddr,
}

impl DomainMappingDatagram {
    fn map_target(&self, target: Endpoint) -> Endpoint {
        let port = target.port().unwrap_or(self.target.port());
        Endpoint::ip(
            yuhaiin_core::Network::Udp,
            SocketAddr::new(self.target.ip(), port),
        )
    }
}

impl AsyncDatagram for DomainMappingDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        let target = self.map_target(target);
        Box::pin(async move { self.inner.send_to(payload, target).await })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        self.inner.recv_from(buffer)
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.inner.local_addr()
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

impl AsyncProxy for DomainMappingProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let mapped = self.mapped_context(context);
        Box::pin(async move { self.direct.connect(&mapped).await })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let mapped = self.mapped_context(context);
        let target = self.udp_target;
        Box::pin(async move {
            let datagram = self.direct.open_datagram(&mapped).await?;
            Ok(Box::new(DomainMappingDatagram {
                inner: datagram,
                target,
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        let mapped = self.mapped_context(context);
        Box::pin(async move { self.direct.ping(&mapped).await })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.direct.close()
    }
}

/// A real TLS + HTTP/2 + Yuubinsya server used by the service-level chain
/// test. The target mapping is deliberately kept in the fixture so the
/// client can send a domain destination while the loopback target remains
/// deterministic and does not depend on the host resolver.
pub struct H2YuubinsyaFixture {
    pub target: SocketAddr,
    pub udp_target: SocketAddr,
    pub outbound: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    target_shutdown: watch::Sender<bool>,
    server_task: tokio::task::JoinHandle<()>,
    target_task: tokio::task::JoinHandle<()>,
    udp_target_task: tokio::task::JoinHandle<()>,
}

impl H2YuubinsyaFixture {
    pub async fn start() -> Self {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap();
        let (target_shutdown, target_receiver) = watch::channel(false);
        let target_task = tokio::spawn(serve_target(target_listener, target_receiver));
        let udp_target_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_target = udp_target_socket.local_addr().unwrap();
        let udp_target_task = tokio::spawn(serve_udp_echo(
            udp_target_socket,
            target_shutdown.subscribe(),
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let outbound = listener.local_addr().unwrap();
        let upstream: Arc<dyn AsyncProxy> = Arc::new(DomainMappingProxy {
            direct: DirectAsyncProxy {
                timeout: Duration::from_secs(3),
            },
            tcp_target: target,
            udp_target,
        });
        let proxy = Arc::new(YuubinsyaServerProxy::new(
            derive_salt(YUUBINSYA_PASSWORD.as_bytes()),
            upstream,
        ));
        let server = Arc::new(YuubinsyaH2Server::new(yuubinsya_server_config(), proxy).unwrap());
        let (shutdown, receiver) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            server
                .serve_listener_until(listener, async move {
                    let _ = receiver.await;
                })
                .await
                .unwrap();
        });

        Self {
            target,
            udp_target,
            outbound,
            shutdown: Some(shutdown),
            target_shutdown,
            server_task,
            target_task,
            udp_target_task,
        }
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.server_task.await;
        let _ = self.target_shutdown.send(true);
        let _ = self.target_task.await;
        let _ = self.udp_target_task.await;
    }
}

fn build_tls_server_config(alpn_protocols: Vec<Vec<u8>>) -> Arc<ServerConfig> {
    let certificate = rustls_pemfile::certs(&mut Cursor::new(LEAF_CERTIFICATE_PEM))
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
            vec![rustls::pki_types::CertificateDer::from(
                certificate.to_vec(),
            )],
            key,
        )
        .unwrap();
    config.alpn_protocols = alpn_protocols;
    Arc::new(config)
}

pub fn tls_server_acceptor() -> TlsAcceptor {
    TlsAcceptor::from(build_tls_server_config(Vec::new()))
}

fn yuubinsya_server_config() -> Arc<ServerConfig> {
    build_tls_server_config(vec![b"h2".to_vec()])
}

// Keep the proxy fixture's receiver independent from the target receiver. The
// helper makes the ownership at the two spawned task boundaries explicit.
fn target_shutdown_for(receiver: watch::Receiver<bool>) -> watch::Receiver<bool> {
    receiver
}

async fn serve_target(listener: TcpListener, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                tokio::spawn(handle_target(stream));
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
}

async fn serve_udp_echo(socket: tokio::net::UdpSocket, mut shutdown: watch::Receiver<bool>) {
    let mut packet = [0u8; 65_535];
    loop {
        tokio::select! {
            received = socket.recv_from(&mut packet) => {
                let Ok((length, peer)) = received else { break };
                if socket.send_to(&packet[..length], peer).await.is_err() {
                    break;
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
}

async fn handle_target(mut stream: TcpStream) {
    let mut buffer = vec![0u8; 16 * 1024];
    let Ok(mut length) = stream.read(&mut buffer).await else {
        return;
    };
    if length == 0 {
        return;
    }
    if buffer[..length].starts_with(b"GET ") || buffer[..length].starts_with(b"HEAD ") {
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    } else {
        loop {
            if stream.write_all(&buffer[..length]).await.is_err() {
                return;
            }
            let Ok(next_length) = stream.read(&mut buffer).await else {
                return;
            };
            if next_length == 0 {
                return;
            }
            length = next_length;
        }
    }
}

async fn serve_connect_proxy(
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
    authorities: Arc<Mutex<Vec<String>>>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                let authorities = authorities.clone();
                tokio::spawn(async move { handle_connect(stream, authorities).await; });
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
}

async fn handle_connect(mut client: TcpStream, authorities: Arc<Mutex<Vec<String>>>) {
    let mut request = Vec::with_capacity(1024);
    let mut buffer = [0u8; 1024];
    loop {
        let Ok(length) = client.read(&mut buffer).await else {
            return;
        };
        if length == 0 {
            return;
        }
        request.extend_from_slice(&buffer[..length]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() > 16 * 1024 {
            return;
        }
    }
    let request = String::from_utf8_lossy(&request);
    let Some(authority) = request
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("CONNECT "))
        .and_then(|line| line.split_whitespace().next())
    else {
        return;
    };
    authorities
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(authority.to_owned());
    let Ok(target) = authority.parse::<SocketAddr>() else {
        let Some(port) = authority
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok())
        else {
            return;
        };
        let Ok(target) = "127.0.0.1:0".parse::<SocketAddr>() else {
            return;
        };
        let target = SocketAddr::new(target.ip(), port);
        let Ok(mut upstream) = TcpStream::connect(target).await else {
            return;
        };
        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .is_err()
        {
            return;
        }
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        return;
    };
    let Ok(mut upstream) = TcpStream::connect(target).await else {
        return;
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

async fn serve_socks5_proxy(
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
    fallback_target: SocketAddr,
    destinations: Arc<Mutex<Vec<String>>>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                let destinations = destinations.clone();
                tokio::spawn(async move {
                    handle_socks5_proxy(stream, fallback_target, destinations).await;
                });
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
}

async fn handle_socks5_proxy(
    mut client: TcpStream,
    fallback_target: SocketAddr,
    destinations: Arc<Mutex<Vec<String>>>,
) {
    let mut greeting = [0u8; 2];
    if client.read_exact(&mut greeting).await.is_err() || greeting[0] != 5 {
        return;
    }
    let mut methods = vec![0u8; usize::from(greeting[1])];
    if client.read_exact(&mut methods).await.is_err() {
        return;
    }
    if !methods.contains(&0) {
        let _ = client.write_all(&[5, 255]).await;
        return;
    }
    if client.write_all(&[5, 0]).await.is_err() {
        return;
    }

    let mut request = [0u8; 4];
    if client.read_exact(&mut request).await.is_err()
        || request[0] != 5
        || request[1] != 1
        || request[2] != 0
    {
        return;
    }
    let (authority, target) = match request[3] {
        1 => {
            let mut ip = [0u8; 4];
            if client.read_exact(&mut ip).await.is_err() {
                return;
            }
            let mut port = [0u8; 2];
            if client.read_exact(&mut port).await.is_err() {
                return;
            }
            let address =
                SocketAddr::new(std::net::IpAddr::V4(ip.into()), u16::from_be_bytes(port));
            (address.to_string(), address)
        }
        3 => {
            let mut length = [0u8; 1];
            if client.read_exact(&mut length).await.is_err() {
                return;
            }
            let mut host = vec![0u8; usize::from(length[0])];
            if client.read_exact(&mut host).await.is_err() {
                return;
            }
            let host = String::from_utf8_lossy(&host);
            let mut port = [0u8; 2];
            if client.read_exact(&mut port).await.is_err() {
                return;
            }
            let port = u16::from_be_bytes(port);
            (
                format!("{host}:{port}"),
                SocketAddr::new(fallback_target.ip(), port),
            )
        }
        4 => {
            let mut ip = [0u8; 16];
            if client.read_exact(&mut ip).await.is_err() {
                return;
            }
            let mut port = [0u8; 2];
            if client.read_exact(&mut port).await.is_err() {
                return;
            }
            let address =
                SocketAddr::new(std::net::IpAddr::V6(ip.into()), u16::from_be_bytes(port));
            (address.to_string(), address)
        }
        _ => return,
    };
    destinations
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(authority);
    let Ok(mut upstream) = TcpStream::connect(target).await else {
        let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return;
    };
    if client
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .is_err()
    {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

async fn serve_h2_protocol_listener(
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
    protocol: H2FinalProtocol,
) {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                tasks.spawn(serve_h2_protocol_connection(stream, shutdown.clone(), protocol));
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            joined = tasks.join_next(), if !tasks.is_empty() => {
                let _ = joined;
            }
        }
    }
    while let Some(result) = tasks.join_next().await {
        let _ = result;
    }
}

async fn serve_h2_protocol_connection(
    socket: TcpStream,
    mut shutdown: watch::Receiver<bool>,
    protocol: H2FinalProtocol,
) {
    let Ok(mut connection) = h2::server::handshake(socket).await else {
        return;
    };
    let request = tokio::select! {
        request = connection.accept() => request,
        changed = shutdown.changed() => {
            if changed.is_ok() { connection.abrupt_shutdown(h2::Reason::NO_ERROR); }
            return;
        }
    };
    let Some(Ok((request, mut respond))) = request else {
        return;
    };
    if request.method() != http::Method::CONNECT || request.uri().host() != Some("localhost") {
        let _ = respond.send_response(
            Response::builder()
                .status(http::StatusCode::BAD_REQUEST)
                .body(())
                .unwrap(),
            true,
        );
        return;
    }

    let mut body = request.into_body();
    let Ok(mut send) = respond.send_response(Response::new(()), false) else {
        return;
    };
    let (application, relay) = tokio::io::duplex(64 * 1024);
    let (mut relay_read, mut relay_write) = tokio::io::split(relay);
    let body_to_application = tokio::spawn(async move {
        while let Some(data) = body.data().await {
            let Ok(data) = data else { break };
            if body.flow_control().release_capacity(data.len()).is_err() {
                break;
            }
            if relay_write.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = relay_write.shutdown().await;
    });
    let application_to_body = tokio::spawn(async move {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let length = match relay_read.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(length) => length,
            };
            if send
                .send_data(Bytes::copy_from_slice(&buffer[..length]), false)
                .is_err()
            {
                break;
            }
        }
        let _ = send.send_data(Bytes::new(), true);
    });
    let protocol_task = tokio::spawn(serve_h2_destination(application, protocol));

    while let Some(result) = tokio::select! {
        result = connection.accept() => result,
        changed = shutdown.changed() => {
            if changed.is_ok() { connection.abrupt_shutdown(h2::Reason::NO_ERROR); }
            None
        }
    } {
        if result.is_err() {
            break;
        }
    }

    protocol_task.abort();
    body_to_application.abort();
    application_to_body.abort();
    let _ = protocol_task.await;
    let _ = body_to_application.await;
    let _ = application_to_body.await;
}

async fn serve_h2_destination(mut stream: tokio::io::DuplexStream, protocol: H2FinalProtocol) {
    match protocol {
        H2FinalProtocol::Http => {
            let request = read_fixture_headers(&mut stream).await;
            if !request.starts_with("CONNECT example.test:")
                || !request.contains(" HTTP/1.1\r\n")
                || !request.contains("Host: ")
                || !request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n")
            {
                return;
            }
            if stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
        }
        H2FinalProtocol::Socks5 => {
            let mut greeting = [0u8; 4];
            if stream.read_exact(&mut greeting).await.is_err() || greeting != [5, 2, 0, 2] {
                return;
            }
            if stream.write_all(&[5, 2]).await.is_err() {
                return;
            }
            let mut auth_head = [0u8; 2];
            if stream.read_exact(&mut auth_head).await.is_err() || auth_head[0] != 1 {
                return;
            }
            let mut username = vec![0u8; usize::from(auth_head[1])];
            if stream.read_exact(&mut username).await.is_err() {
                return;
            }
            let mut password_length = [0u8; 1];
            if stream.read_exact(&mut password_length).await.is_err() {
                return;
            }
            let mut password = vec![0u8; usize::from(password_length[0])];
            if stream.read_exact(&mut password).await.is_err()
                || username != b"user"
                || password != b"pass"
            {
                return;
            }
            if stream.write_all(&[1, 0]).await.is_err() {
                return;
            }
            let mut request = [0u8; 4];
            if stream.read_exact(&mut request).await.is_err() || request != [5, 1, 0, 3] {
                return;
            }
            let mut host_length = [0u8; 1];
            if stream.read_exact(&mut host_length).await.is_err() {
                return;
            }
            let mut host = vec![0u8; usize::from(host_length[0])];
            if stream.read_exact(&mut host).await.is_err() {
                return;
            }
            let mut port = [0u8; 2];
            if stream.read_exact(&mut port).await.is_err() || host != b"example.test" {
                return;
            }
            if stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .is_err()
            {
                return;
            }
        }
    }

    let mut buffer = [0u8; 16 * 1024];
    let length = match stream.read(&mut buffer).await {
        Ok(0) | Err(_) => return,
        Ok(length) => length,
    };
    if buffer[..length].starts_with(b"GET ") {
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return;
    }
    if stream.write_all(&buffer[..length]).await.is_err() {
        return;
    }
    loop {
        let length = match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(length) => length,
        };
        if stream.write_all(&buffer[..length]).await.is_err() {
            break;
        }
    }
}

async fn read_fixture_headers(stream: &mut tokio::io::DuplexStream) -> String {
    let mut headers = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !headers.ends_with(b"\r\n\r\n") && headers.len() <= 64 * 1024 {
        if stream.read_exact(&mut byte).await.is_err() {
            return String::new();
        }
        headers.push(byte[0]);
    }
    String::from_utf8(headers).unwrap_or_default()
}

pub async fn seed_empty_database(path: &Path) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    // The reusable Podman smoke scripts deliberately keep their cache mount
    // so logs and fixture directories survive a run. Their explicit reset
    // gate makes the database itself disposable and prevents a prior test's
    // selected node/inbound from changing a later scenario.
    if std::env::var("YUHAIIN_RESET_INTEGRATION_STATE").as_deref() == Ok("1") {
        for suffix in ["", "-wal", "-shm"] {
            let candidate = if suffix.is_empty() {
                path.to_owned()
            } else {
                PathBuf::from(format!("{}{}", path.display(), suffix))
            };
            let _ = std::fs::remove_file(candidate);
        }
    }
    let store = ConfigStore::open(path).await.unwrap();
    drop(store);
}

pub async fn api_json(
    client: &reqwest::Client,
    base_url: &str,
    method: reqwest::Method,
    path: &str,
    body: Option<&Value>,
) -> Value {
    let request = client.request(method, format!("{base_url}{path}"));
    let response = match body {
        Some(body) => request.json(body).send().await.unwrap(),
        None => request.send().await.unwrap(),
    };
    let status = response.status();
    let text = response.text().await.unwrap();
    assert!(status.is_success(), "{path} returned {status}: {text}");
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{path} returned invalid JSON: {error}: {text}"))
}

/// Management mutations publish the snapshot before the inbound owner has
/// finished rebinding its listener set. Process-level flow fixtures wait for
/// that short latest-wins reload window before opening a protocol connection,
/// so a test does not connect to a socket that is about to be retired by an
/// already-acknowledged mutation.
async fn settle_runtime_reload() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

pub struct ServiceProcess {
    child: Child,
    pub client: reqwest::Client,
    pub base_url: String,
    diagnostics: Arc<Mutex<String>>,
}

// `reserve_loopback` closes its temporary listener before the child binds.
// Serialize that small hand-off so parallel integration tests cannot choose
// the same port between the probe and the runtime's real bind.
static API_START_LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();

impl ServiceProcess {
    pub async fn start(db: &Path) -> Self {
        let _api_start_guard = API_START_LOCK
            .get_or_init(|| AsyncMutex::new(()))
            .lock()
            .await;
        let api_address = reserve_loopback().await;
        let diagnostics = Arc::new(Mutex::new(String::new()));
        let runtime_binary = std::env::var_os("YUHAIIN_RUNTIME_BIN")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_yuhaiin").into());
        let mut child = Command::new(runtime_binary)
            .env("YUHAIIN_DB", db)
            .env("YUHAIIN_HTTP", api_address.to_string())
            .env("YUHAIIN_QUIET", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(mut stderr) = child.stderr.take() {
            let diagnostics_writer = diagnostics.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(&mut stderr);
                let mut output = String::new();
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) != 0 {
                    output.push_str(&line);
                    // Keep diagnostics useful while bounding the memory held
                    // by a long-running child. The tail contains the latest
                    // startup/reload failure, which is what a timed-out
                    // integration test needs.
                    if output.len() > 64 * 1024 {
                        let trim_at = output.len() - 64 * 1024;
                        let trim_at = output
                            .char_indices()
                            .find(|(index, _)| *index >= trim_at)
                            .map(|(index, _)| index)
                            .unwrap_or(0);
                        output.drain(..trim_at);
                    }
                    *diagnostics_writer
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = output.clone();
                    line.clear();
                }
            });
        }
        let _ = rustls_rustcrypto::provider().install_default();
        let client = reqwest::Client::builder().build().unwrap();
        let base_url = format!("http://{api_address}");
        let mut service = Self {
            child,
            client,
            base_url,
            diagnostics,
        };
        for _ in 0..120 {
            if let Some(status) = service.child.try_wait().unwrap() {
                panic!(
                    "yuhaiin exited before ready ({status}): {}",
                    service.diagnostics()
                );
            }
            if let Ok(response) = service
                .client
                .get(format!("{}/api/v2/info", service.base_url))
                .send()
                .await
                && response.status().is_success()
            {
                return service;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("yuhaiin did not become ready: {}", service.diagnostics());
    }

    pub fn diagnostics(&self) -> String {
        self.diagnostics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub async fn shutdown(mut self) {
        if self.child.try_wait().unwrap().is_none() {
            #[cfg(unix)]
            {
                let _ = Command::new("kill")
                    .args(["-TERM", &self.child.id().to_string()])
                    .status();
            }
            #[cfg(not(unix))]
            {
                let _ = self.child.kill();
            }
            for _ in 0..100 {
                if self.child.try_wait().unwrap().is_some() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }

    /// Terminate the runtime without giving the persistence worker a
    /// shutdown opportunity. This deliberately models SIGKILL/force-stop so
    /// callers can verify SQLite WAL recovery and the next process takeover.
    pub async fn force_stop(mut self) {
        self.force_stop_inner().await;
    }

    pub async fn force_stop_with_diagnostics(mut self) -> String {
        self.force_stop_inner().await;
        self.diagnostics()
    }

    async fn force_stop_inner(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl Drop for ServiceProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
    }
}

pub async fn wait_for_connection(client: &reqwest::Client, base_url: &str) -> Value {
    // The reusable Podman smoke runs many real service processes in parallel;
    // under load the flow can be established before the monitor checkpoint
    // is visible, so keep the observation window independent of the normal
    // listener startup retry budget.
    for _ in 0..500 {
        let value = api_json(
            client,
            base_url,
            reqwest::Method::GET,
            "/api/v2/connections",
            None,
        )
        .await;
        if value["connections"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
        {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("connection did not become visible");
}

pub async fn configure_http_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    configure_http_chain_with_transport(service, inbound, outbound, "http-chain-in", "normal")
        .await;
}

pub async fn configure_http_chain_with_transport(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
    inbound_id: &str,
    transport_type: &str,
) {
    let node = json!({
        "id":"http-out",
        "name":"HTTP test outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"http","http":{"user":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    let default_node = json!({
        "id":"http-default",
        "name":"HTTP default fallback",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":1}},
            {"type":"http","http":{"user":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&default_node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes/http-default/use",
        None,
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::PUT,
        "/api/v2/route/tags/integration",
        Some(&json!({"type":"node","hash":"http-out"})),
    )
    .await;

    let mut transport = json!({"type":transport_type});
    transport[transport_type] = json!({});
    let inbound = json!({
        "id":inbound_id,
        "name":"HTTP chain inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[transport],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":"proxy-example-test",
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    settle_runtime_reload().await;
}

/// Configure an HTTP inbound whose route is selected only when the runtime
/// can recover both the real client process and the inbound name. This keeps
/// the integration test on the persisted Go-shaped route-list/rule contract.
pub async fn configure_http_process_inbound_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
    process_path: &str,
) {
    let node = json!({
        "id":"http-process-out",
        "name":"HTTP process matcher outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"http","http":{"user":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes/http-process-out/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"http-process-in",
        "name":"HTTP process matcher inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let list = json!({
        "name":"process-current",
        "type":"process",
        "source":{"type":"local","local":{"lists":[process_path]}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/lists",
        Some(&list),
    )
    .await;

    let rule = json!({
        "name":"proxy-process-inbound",
        "mode":"proxy",
        "rules":[{"type":"all","all":[
            {"type":"process","process":{"list":"process-current"}},
            {"type":"inbound","inbound":{"names":["HTTP process matcher inbound"]}},
            {"type":"network","network":{"network":"tcp"}}
        ]}],
        "tag":"process-inbound-integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    settle_runtime_reload().await;
}

/// Configure the smallest real TLS-termination inbound: TLS transport,
/// HTTP proxy protocol, and the built-in direct outbound. Keeping this in the
/// shared process fixture makes it reusable for future TLS/SOCKS5 and
/// TLS/HTTP2 inbound matrix tests.
pub async fn configure_tls_http_inbound(service: &ServiceProcess, inbound: SocketAddr) {
    let node = json!({
        "id":"tls-inbound-direct",
        "name":"TLS inbound direct outbound",
        "group":"integration",
        "enabled":true,
        "chain":[{"type":"direct","direct":{}}]
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes/tls-inbound-direct/use",
        None,
    )
    .await;

    let certificate = base64::engine::general_purpose::STANDARD.encode(LEAF_CERTIFICATE_PEM);
    let private_key = base64::engine::general_purpose::STANDARD.encode(PRIVATE_KEY_PEM);
    let inbound = json!({
        "id":"tls-http-in",
        "name":"TLS HTTP inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[{
            "type":"tls",
            "tls":{"tls":{
                "certificates":[{"certBase64":certificate,"keyBase64":private_key}],
                "nextProtos":[]
            }}
        }],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;
    settle_runtime_reload().await;
}

/// Configure a prior-knowledge HTTP/2 inbound over the same runtime owner as
/// the other socket inbounds. The selected outbound is an HTTP CONNECT proxy
/// so the process test proves that the H2 transport, router, and outbound
/// protocol are all part of one data-plane chain.
pub async fn configure_h2_http_inbound(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    let node = json!({
        "id":"h2-inbound-http-out",
        "name":"HTTP/2 inbound HTTP outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"http","http":{"user":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes/h2-inbound-http-out/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"h2-http-in",
        "name":"HTTP/2 HTTP inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[{"type":"http2","http2":{}}],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":"proxy-example-test-over-h2-inbound",
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    settle_runtime_reload().await;
}

/// Configure an AEAD-wrapped prior-knowledge HTTP/2 inbound. The AEAD layer
/// is intentionally outside the H2 handshake, matching the Go transport
/// composition used by legacy inbound configurations.
pub async fn configure_aead_h2_http_inbound(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    let node = json!({
        "id":"aead-h2-inbound-http-out",
        "name":"AEAD HTTP/2 inbound HTTP outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"http","http":{"user":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes/aead-h2-inbound-http-out/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"aead-h2-http-in",
        "name":"AEAD HTTP/2 inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[
            {"type":"aead","aead":{"password":"runtime-aead-password","cryptoMethod":"XChacha20Poly1305"}},
            {"type":"http2","http2":{}}
        ],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":"proxy-example-test-over-aead-h2-inbound",
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    settle_runtime_reload().await;
}

/// Configure TLS termination followed by HTTP/2 prior-knowledge framing.
/// The selected outbound is fixed → HTTP CONNECT so this fixture exercises
/// TLS ALPN negotiation, H2 stream handling, router selection, and proxy-side
/// domain authority in one process-level chain.
pub async fn configure_tls_h2_http_inbound(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    configure_tls_h2_http_inbound_with_transports(
        service,
        inbound,
        outbound,
        "tls-h2-inbound-http-out",
        "TLS HTTP/2 inbound HTTP outbound",
        "tls-h2-http-in",
        "TLS HTTP/2 inbound",
        "proxy-example-test-over-tls-h2-inbound",
        json!([
            {"type":"tls","tls":{"tls":{
                "certificates":[{"certBase64":base64::engine::general_purpose::STANDARD.encode(LEAF_CERTIFICATE_PEM),"keyBase64":base64::engine::general_purpose::STANDARD.encode(PRIVATE_KEY_PEM)}],
                "nextProtos":[]
            }}},
            {"type":"http2","http2":{}}
        ]),
    )
    .await;
}

/// Configure TLS followed by AEAD and HTTP/2. The declaration order is
/// intentional: the runtime must unwrap TLS first, then AEAD, before handing
/// the stream to the prior-knowledge H2 server.
pub async fn configure_tls_aead_h2_http_inbound(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    configure_tls_h2_http_inbound_with_transports(
        service,
        inbound,
        outbound,
        "tls-aead-h2-inbound-http-out",
        "TLS AEAD HTTP/2 inbound HTTP outbound",
        "tls-aead-h2-http-in",
        "TLS AEAD HTTP/2 inbound",
        "proxy-example-test-over-tls-aead-h2-inbound",
        json!([
            {"type":"tls","tls":{"tls":{
                "certificates":[{"certBase64":base64::engine::general_purpose::STANDARD.encode(LEAF_CERTIFICATE_PEM),"keyBase64":base64::engine::general_purpose::STANDARD.encode(PRIVATE_KEY_PEM)}],
                "nextProtos":[]
            }}},
            {"type":"aead","aead":{"password":"runtime-aead-password","cryptoMethod":"XChacha20Poly1305"}},
            {"type":"http2","http2":{}}
        ]),
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn configure_tls_h2_http_inbound_with_transports(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
    node_id: &str,
    node_name: &str,
    inbound_id: &str,
    inbound_name: &str,
    rule_name: &str,
    transports: Value,
) {
    let node = json!({
        "id":node_id,
        "name":node_name,
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"http","http":{"user":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    let node_use_path = format!("/api/v2/nodes/{node_id}/use");
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        &node_use_path,
        None,
    )
    .await;

    let inbound = json!({
        "id":inbound_id,
        "name":inbound_name,
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":transports,
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":rule_name,
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    settle_runtime_reload().await;
}

pub async fn configure_socks5_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    let node = json!({
        "id":"socks5-out",
        "name":"SOCKS5 test outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"socks5","socks5":{"username":"","password":""}}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes/socks5-out/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"socks5-chain-in",
        "name":"SOCKS5 outbound chain inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":"proxy-example-test-over-socks5",
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    settle_runtime_reload().await;
}

pub async fn configure_h2_http_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    configure_h2_protocol_chain(
        service,
        inbound,
        outbound,
        "h2-http-out",
        "h2-http-chain-in",
        "proxy-example-test-over-h2-http",
        json!({"type":"http","http":{"user":"user","password":"pass"}}),
    )
    .await;
    settle_runtime_reload().await;
}

pub async fn configure_h2_socks5_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    configure_h2_protocol_chain(
        service,
        inbound,
        outbound,
        "h2-socks5-out",
        "h2-socks5-chain-in",
        "proxy-example-test-over-h2-socks5",
        json!({
            "type":"socks5",
            "socks5":{"user":"user","password":"pass","hostname":"","override_port":0}
        }),
    )
    .await;
    settle_runtime_reload().await;
}

async fn configure_h2_protocol_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
    node_id: &str,
    inbound_id: &str,
    rule_name: &str,
    final_node: Value,
) {
    let node = json!({
        "id":node_id,
        "name":"HTTP/2 protocol test outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"http2","http2":{"concurrency":1,"max_streams":8,"idle_timeout_secs":30}},
            final_node
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        &format!("/api/v2/nodes/{node_id}/use"),
        None,
    )
    .await;

    let inbound = json!({
        "id":inbound_id,
        "name":"HTTP/2 protocol chain inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":rule_name,
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    settle_runtime_reload().await;
}

pub async fn configure_tls_h2_yuubinsya_chain(
    service: &ServiceProcess,
    inbound: SocketAddr,
    outbound: SocketAddr,
) {
    let node = json!({
        "id":"tls-h2-yuubinsya-out",
        "name":"TLS H2 Yuubinsya test outbound",
        "group":"integration",
        "enabled":true,
        "chain":[
            {"type":"fixed","fixed":{"host":"127.0.0.1","port":outbound.port()}},
            {"type":"tls","tls":{
                "enable":true,
                "insecure_skip_verify":true,
                "servernames":["localhost"],
                "next_protos":["h2"],
                "ca_cert":[]
            }},
            {"type":"http2","http2":{
                "concurrency":1,
                "max_streams":16,
                "idle_timeout_secs":30
            }},
            {"type":"yuubinsya","yuubinsya":{
                "password":YUUBINSYA_PASSWORD,
                "udp_over_stream":true,
                "udp_coalesce":false
            }}
        ]
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes/tls-h2-yuubinsya-out/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"tls-h2-yuubinsya-in",
        "name":"TLS H2 Yuubinsya chain inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":inbound.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"http","http":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;

    let rule = json!({
        "name":"proxy-example-test-over-yuubinsya",
        "mode":"proxy",
        "match":{"domain":"example.test"},
        "tag":"integration"
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/route/rules",
        Some(&rule),
    )
    .await;
    settle_runtime_reload().await;
}

pub async fn add_mixed_udp_inbound(service: &ServiceProcess, id: &str, listen: SocketAddr) {
    let inbound = json!({
        "id":id,
        "name":"TLS H2 Yuubinsya UDP chain inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":listen.to_string(),"udp":"enabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"mixed","mixed":{"username":"","password":""}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;
    settle_runtime_reload().await;
}

pub async fn add_socks5_inbound(
    service: &ServiceProcess,
    id: &str,
    listen: SocketAddr,
    username: &str,
    password: &str,
) {
    let inbound = json!({
        "id":id,
        "name":"SOCKS5 integration inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":listen.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"socks5","socks5":{"username":username,"password":password}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;
    settle_runtime_reload().await;
}

pub async fn add_yuubinsya_inbound(service: &ServiceProcess, id: &str, listen: SocketAddr) {
    let inbound = json!({
        "id":id,
        "name":"Yuubinsya integration inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":listen.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"yuubinsya","yuubinsya":{"password":YUUBINSYA_PASSWORD,"udp":false}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&inbound),
    )
    .await;
    settle_runtime_reload().await;
}

/// Configure both Go-compatible reverse inbound forms against the built-in
/// direct outbound. Keeping the pair in one process fixture exercises the
/// persisted inbound contract and the shared listener supervisor together.
pub async fn add_reverse_inbounds(
    service: &ServiceProcess,
    reverse_tcp_listen: SocketAddr,
    reverse_tcp_target: SocketAddr,
    reverse_http_listen: SocketAddr,
    reverse_http_url: &str,
) {
    let node = json!({
        "id":"reverse-direct",
        "name":"Reverse integration direct outbound",
        "group":"integration",
        "enabled":true,
        "chain":[{"type":"direct","direct":{}}]
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes",
        Some(&node),
    )
    .await;
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes/reverse-direct/use",
        None,
    )
    .await;

    let reverse_tcp = json!({
        "id":"reverse-tcp-in",
        "name":"Reverse TCP integration inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":reverse_tcp_listen.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"reverse_tcp","reverse_tcp":{"host":reverse_tcp_target.to_string()}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&reverse_tcp),
    )
    .await;

    let reverse_http = json!({
        "id":"reverse-http-in",
        "name":"Reverse HTTP integration inbound",
        "enabled":true,
        "network":{"type":"tcp_udp","tcp_udp":{"host":reverse_http_listen.to_string(),"udp":"disabled"}},
        "transports":[{"type":"normal","normal":{}}],
        "protocol":{"type":"reverse_http","reverse_http":{"url":reverse_http_url}}
    });
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/inbounds",
        Some(&reverse_http),
    )
    .await;
    settle_runtime_reload().await;
}
