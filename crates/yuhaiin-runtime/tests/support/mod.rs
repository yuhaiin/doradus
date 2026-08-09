//! Shared process-level fixtures for runtime integration tests.
//!
//! The fixtures deliberately use loopback sockets and a cache-owned state
//! directory. `YUHAIIN_INTEGRATION_DIR` can point at a persistent directory
//! when a developer or Podman job wants to inspect/reuse the SQLite state.

use std::io::{Cursor, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::ServerConfig;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
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

fn yuubinsya_server_config() -> Arc<ServerConfig> {
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
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
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
    let Ok(length) = stream.read(&mut buffer).await else {
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
        let _ = stream.write_all(&buffer[..length]).await;
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

pub async fn seed_empty_database(path: &Path) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
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

pub struct ServiceProcess {
    child: Child,
    pub client: reqwest::Client,
    pub base_url: String,
    diagnostics: Arc<Mutex<String>>,
}

impl ServiceProcess {
    pub async fn start(db: &Path) -> Self {
        let api_address = reserve_loopback().await;
        let diagnostics = Arc::new(Mutex::new(String::new()));
        let mut child = Command::new(env!("CARGO_BIN_EXE_yuhaiin"))
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
                let mut output = String::new();
                let _ = stderr.read_to_string(&mut output);
                *diagnostics_writer
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = output;
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
            {
                if response.status().is_success() {
                    return service;
                }
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
}

impl Drop for ServiceProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
    }
}

pub async fn wait_for_connection(client: &reqwest::Client, base_url: &str) -> Value {
    for _ in 0..100 {
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
    api_json(
        &service.client,
        &service.base_url,
        reqwest::Method::POST,
        "/api/v2/nodes/http-out/use",
        None,
    )
    .await;

    let inbound = json!({
        "id":"http-chain-in",
        "name":"HTTP chain inbound",
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
}
