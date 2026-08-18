//! Runnable transport chain for the proxy configuration format.
//!
//! The crate keeps each protocol boundary explicit:
//!
//! ```text
//! fixed TCP -> Rustls TLS -> HTTP/2 CONNECT stream -> Yuubinsya TCP/UOT
//! ```
//!
//! TCP and UDP-over-TCP use the same HTTP/2 stream transport, but different
//! Yuubinsya sessions. This prevents the UDP framing and TCP byte stream from
//! being accidentally mixed into one "universal" connection type.

mod config;
mod go_node;

pub use config::{
    ChainConfig, ChainNode, ValidatedChain, ValidatedFixedAddress, ValidatedHttp, ValidatedHttp2,
    ValidatedSocks5, ValidatedTls, ValidatedWebSocket, ValidatedYuubinsya, parse_config,
};
pub use go_node::parse_go_node;
pub use yuhaiin_protocol::YuubinsyaH2Server;
pub use yuhaiin_protocol::{
    AsyncYuubinsyaPingServerSession, AsyncYuubinsyaPingSession, AsyncYuubinsyaTcpSession,
    AsyncYuubinsyaUotServerSession, AsyncYuubinsyaUotSession, YuubinsyaDnsHandler,
    YuubinsyaServerProxy,
};
pub use yuhaiin_protocol::{H2Connection, H2PoolStats};

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::time::Instant;

use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, Notify, watch};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use yuhaiin_core::dns_resolver_async::{AsyncIpResolver, SystemAsyncIpResolver};
use yuhaiin_core::proxy::{
    AsyncDatagram, AsyncProxy, BoxAsyncStream, connect_tokio_tcp_with_interface, stream_local_addr,
    with_stream_local_addr,
};
use yuhaiin_core::{
    BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, ResolveStrategy, Result,
};

use yuhaiin_protocol::direct_uot::{DirectUotProxy, parse_go_direct_uot};
use yuhaiin_protocol::session::{MAX_UOT_COALESCE_BYTES, MAX_UOT_COALESCE_FRAMES, read_uot_frame};
use yuhaiin_protocol::yuubinsya::derive_salt;
use yuhaiin_protocol::{H2Pool, H2PoolEndpoint};

/// A single best-effort runtime observation for the reusable chain client.
/// The pool counters are monotonic, while connection/stream counts describe
/// the instant at which this snapshot was taken.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ChainRuntimeStats {
    pub h2_connections: usize,
    pub h2_active_streams: usize,
    pub h2_pool: H2PoolStats,
}

impl ChainRuntimeStats {
    /// Render a dependency-free Prometheus text snapshot.
    ///
    /// This is intentionally a pure pull-format encoder: the embedding app
    /// owns the HTTP endpoint, logging cadence, labels and authentication.
    /// No listener, task or global registry is created by the transport crate.
    pub fn render_prometheus(&self) -> String {
        format!(
            "# HELP yuhaiin_chain_h2_connections Current live HTTP/2 connections.\n\
# TYPE yuhaiin_chain_h2_connections gauge\n\
yuhaiin_chain_h2_connections {}\n\
# HELP yuhaiin_chain_h2_active_streams Current active HTTP/2 CONNECT streams.\n\
# TYPE yuhaiin_chain_h2_active_streams gauge\n\
yuhaiin_chain_h2_active_streams {}\n\
# HELP yuhaiin_chain_h2_connection_attempts Total HTTP/2 connection attempts.\n\
# TYPE yuhaiin_chain_h2_connection_attempts counter\n\
yuhaiin_chain_h2_connection_attempts {}\n\
# HELP yuhaiin_chain_h2_connection_failures Total HTTP/2 connection failures.\n\
# TYPE yuhaiin_chain_h2_connection_failures counter\n\
yuhaiin_chain_h2_connection_failures {}\n\
# HELP yuhaiin_chain_h2_stream_capacity_rejections Total stream-capacity rejections.\n\
# TYPE yuhaiin_chain_h2_stream_capacity_rejections counter\n\
yuhaiin_chain_h2_stream_capacity_rejections {}\n\
# HELP yuhaiin_chain_h2_stream_open_failures Total CONNECT stream open failures.\n\
# TYPE yuhaiin_chain_h2_stream_open_failures counter\n\
yuhaiin_chain_h2_stream_open_failures {}\n",
            self.h2_connections,
            self.h2_active_streams,
            self.h2_pool.connection_attempts,
            self.h2_pool.connection_failures,
            self.h2_pool.stream_capacity_rejections,
            self.h2_pool.stream_open_failures,
        )
    }
}

const PING_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_UOT_RETRY_BYTES: usize = 256 * 1024;
const MAX_UOT_RETRY_FRAMES: usize = 128;
const MAX_UOT_RECONNECT_ATTEMPTS: usize = 3;

struct CachedPing {
    session: Mutex<AsyncYuubinsyaPingSession<BoxAsyncStream>>,
    last_used: StdMutex<Instant>,
}

/// A validated, reusable client for one fixed -> optional TLS/WebSocket ->
/// HTTP/2 -> Yuubinsya chain.
#[derive(Clone)]
pub struct ChainClient {
    chain: Arc<ValidatedChain>,
    resolver: Arc<dyn AsyncIpResolver>,
    tls: TlsConnector,
    pool: Arc<H2Pool>,
    ping_cache: Arc<Mutex<HashMap<String, Arc<CachedPing>>>>,
    ping_connect_lock: Arc<Mutex<()>>,
    closed: Arc<AtomicBool>,
}

impl ChainClient {
    pub fn new(chain: ValidatedChain) -> Result<Self> {
        Self::new_with_resolver(chain, Arc::new(SystemAsyncIpResolver))
    }

    pub fn new_with_resolver(
        chain: ValidatedChain,
        resolver: Arc<dyn AsyncIpResolver>,
    ) -> Result<Self> {
        let roots = if chain.tls.insecure_skip_verify {
            // The verifier below does not consult roots; matching Go also
            // means malformed optional CA material must not block an
            // explicitly insecure test node.
            RootCertStore::empty()
        } else {
            root_store(&chain.tls.ca_certificates)?
        };
        let h2_idle_timeout = chain.http2.idle_timeout;
        let provider = Arc::new(rustls_rustcrypto::provider());
        let mut config = if chain.tls.insecure_skip_verify {
            ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(tls_error)?
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new(provider))
                .with_no_client_auth()
        } else {
            ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(tls_error)?
                .with_root_certificates(roots)
                .with_no_client_auth()
        };
        config.alpn_protocols = chain
            .tls
            .next_protos
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect();
        Ok(Self {
            chain: Arc::new(chain),
            resolver,
            tls: TlsConnector::from(Arc::new(config)),
            pool: Arc::new(H2Pool::with_limits(4, h2_idle_timeout)),
            ping_cache: Arc::new(Mutex::new(HashMap::new())),
            ping_connect_lock: Arc::new(Mutex::new(())),
            closed: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn from_json(json: &str) -> Result<Self> {
        Self::new(parse_config(json)?)
    }

    /// Build a runnable chain directly from the tagged node payload stored by
    /// Go `nodes_v2`.  The adapter lives in this crate so callers do not need
    /// a second DTO or a store-to-chain dependency just to start a proxy.
    pub fn from_go_json(json: &str) -> Result<Self> {
        Self::new(parse_go_node(json)?)
    }

    pub fn from_go_json_with_resolver(
        json: &str,
        resolver: Arc<dyn AsyncIpResolver>,
    ) -> Result<Self> {
        Self::new_with_resolver(parse_go_node(json)?, resolver)
    }

    pub fn chain(&self) -> &ValidatedChain {
        &self.chain
    }

    pub async fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        // Close the H2 pool first.  A cached Yuubinsya ping may be holding its
        // session mutex while waiting for a peer response; draining the H2
        // relay wakes that read before we try to acquire the same mutex.
        self.pool.close().await;
        let sessions = self
            .ping_cache
            .lock()
            .await
            .drain()
            .map(|(_, session)| session)
            .collect::<Vec<_>>();
        for session in sessions {
            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                let mut session = session.session.lock().await;
                session.shutdown().await
            })
            .await;
        }
    }

    pub async fn h2_connection_count(&self) -> usize {
        self.pool.len().await
    }

    pub async fn h2_active_streams(&self) -> usize {
        self.pool.active_streams().await
    }

    /// Sample H2 capacity and pool counters together for runtime observation.
    pub async fn runtime_stats(&self) -> ChainRuntimeStats {
        ChainRuntimeStats {
            h2_connections: self.pool.len().await,
            h2_active_streams: self.pool.active_streams().await,
            h2_pool: self.pool.stats(),
        }
    }

    /// Render a point-in-time Prometheus snapshot for an embedding exporter.
    pub async fn prometheus_metrics(&self) -> String {
        self.runtime_stats().await.render_prometheus()
    }

    /// Return monotonic HTTP/2 pool counters for operational backpressure and
    /// connection-rebuild diagnostics.
    pub fn h2_pool_stats(&self) -> H2PoolStats {
        self.pool.stats()
    }

    /// Ping through a hostname-keyed persistent session. The session lock
    /// guarantees one in-flight probe per destination, while the cache lock
    /// only protects lookup and idle eviction.
    pub async fn ping(&self, destination: Endpoint) -> Result<Duration> {
        self.ping_with_bind(destination, &[]).await
    }

    pub async fn ping_with_bind(
        &self,
        destination: Endpoint,
        local_bind_addresses: &[std::net::IpAddr],
    ) -> Result<Duration> {
        self.ping_with_bind_and_interface(destination, local_bind_addresses, None)
            .await
    }

    pub async fn ping_with_bind_and_interface(
        &self,
        destination: Endpoint,
        local_bind_addresses: &[std::net::IpAddr],
        bind_interface: Option<&str>,
    ) -> Result<Duration> {
        self.ensure_open()?;
        if destination.network() != Network::Tcp {
            return Err(Error::invalid("Yuubinsya ping target must use tcp network"));
        }
        let key = destination
            .host()
            .map(|host| host.as_str().to_owned())
            .or_else(|| destination.addr().map(|address| address.to_string()))
            .ok_or_else(|| Error::invalid("Yuubinsya ping target has no host"))?;
        let cached = {
            let mut cache = self.ping_cache.lock().await;
            cache.retain(|_, session| {
                session
                    .last_used
                    .lock()
                    .map(|last| last.elapsed() <= PING_IDLE_TIMEOUT)
                    .unwrap_or(false)
            });
            cache.get(&key).cloned()
        };
        if let Some(session) = cached {
            let result =
                tokio::time::timeout(Duration::from_secs(10), session.session.lock().await.ping())
                    .await
                    .map_err(|_| Error::new(ErrorKind::Timeout, "Yuubinsya ping timed out"))?;
            match result {
                Ok(elapsed) => {
                    if let Ok(mut last_used) = session.last_used.lock() {
                        *last_used = Instant::now();
                    }
                    return Ok(elapsed);
                }
                Err(_) => {
                    self.ping_cache
                        .lock()
                        .await
                        .retain(|_, current| !Arc::ptr_eq(current, &session));
                }
            }
        }

        let _guard = self.ping_connect_lock.lock().await;
        if let Some(session) = self.ping_cache.lock().await.get(&key).cloned() {
            let elapsed =
                tokio::time::timeout(Duration::from_secs(10), session.session.lock().await.ping())
                    .await
                    .map_err(|_| Error::new(ErrorKind::Timeout, "Yuubinsya ping timed out"))??;
            if let Ok(mut last_used) = session.last_used.lock() {
                *last_used = Instant::now();
            }
            return Ok(elapsed);
        }

        let Some(yuubinsya) = self.chain.yuubinsya.as_ref() else {
            let started = Instant::now();
            let mut stream = self
                .open_h2_stream(local_bind_addresses, bind_interface)
                .await?;
            stream
                .shutdown()
                .await
                .map_err(|error| Error::new(ErrorKind::Closed, error.to_string()))?;
            return Ok(started.elapsed());
        };
        let stream = self
            .open_h2_stream(local_bind_addresses, bind_interface)
            .await?;
        let (session, elapsed) = tokio::time::timeout(
            Duration::from_secs(10),
            AsyncYuubinsyaPingSession::connect(
                stream,
                derive_salt(yuubinsya.password.as_bytes()),
                destination,
            ),
        )
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "Yuubinsya ping timed out"))??;
        self.ping_cache.lock().await.insert(
            key,
            Arc::new(CachedPing {
                session: Mutex::new(session),
                last_used: StdMutex::new(Instant::now()),
            }),
        );
        Ok(elapsed)
    }

    /// Open a transparent Yuubinsya TCP stream for `destination`.
    pub async fn connect_tcp(
        &self,
        destination: Endpoint,
    ) -> Result<AsyncYuubinsyaTcpSession<BoxAsyncStream>> {
        self.connect_tcp_with_bind(destination, &[]).await
    }

    pub async fn connect_tcp_with_bind(
        &self,
        destination: Endpoint,
        local_bind_addresses: &[std::net::IpAddr],
    ) -> Result<AsyncYuubinsyaTcpSession<BoxAsyncStream>> {
        self.connect_tcp_with_bind_and_interface(destination, local_bind_addresses, None)
            .await
    }

    pub async fn connect_tcp_with_bind_and_interface(
        &self,
        destination: Endpoint,
        local_bind_addresses: &[std::net::IpAddr],
        bind_interface: Option<&str>,
    ) -> Result<AsyncYuubinsyaTcpSession<BoxAsyncStream>> {
        self.ensure_open()?;
        if destination.network() != Network::Tcp {
            return Err(Error::invalid(
                "Yuubinsya TCP destination must use tcp network",
            ));
        }
        let yuubinsya = self.chain.yuubinsya.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                "standalone HTTP/2 transport has no destination protocol",
            )
        })?;
        let stream = self
            .open_h2_stream(local_bind_addresses, bind_interface)
            .await?;
        AsyncYuubinsyaTcpSession::connect(
            stream,
            derive_salt(yuubinsya.password.as_bytes()),
            destination,
        )
        .await
    }

    /// Open a raw Go-compatible HTTP/2 CONNECT stream. This is the transport
    /// half used by standalone HTTP/2 inbound/outbound compositions; it does
    /// not encode a destination because Go's HTTP/2 transport deliberately
    /// leaves that to the protocol layer above it.
    pub async fn connect_raw_with_bind(
        &self,
        local_bind_addresses: &[std::net::IpAddr],
    ) -> Result<BoxAsyncStream> {
        self.connect_raw_with_bind_and_interface(local_bind_addresses, None)
            .await
    }

    pub async fn connect_raw_with_bind_and_interface(
        &self,
        local_bind_addresses: &[std::net::IpAddr],
        bind_interface: Option<&str>,
    ) -> Result<BoxAsyncStream> {
        if self.chain.yuubinsya.is_some() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "raw HTTP/2 transport requested from a Yuubinsya chain",
            ));
        }
        self.open_h2_stream(local_bind_addresses, bind_interface)
            .await
    }

    /// Open a Yuubinsya UDP-over-TCP session. The first frame is the migrate
    /// handshake; subsequent calls can send and receive length-delimited UDP
    /// datagrams on the same HTTP/2 CONNECT stream.
    pub async fn connect_uot(
        &self,
        migrate_id: u64,
    ) -> Result<AsyncYuubinsyaUotSession<BoxAsyncStream>> {
        self.connect_uot_with_bind(migrate_id, &[]).await
    }

    pub async fn connect_uot_with_bind(
        &self,
        migrate_id: u64,
        local_bind_addresses: &[std::net::IpAddr],
    ) -> Result<AsyncYuubinsyaUotSession<BoxAsyncStream>> {
        self.connect_uot_with_bind_and_interface(migrate_id, local_bind_addresses, None)
            .await
    }

    pub async fn connect_uot_with_bind_and_interface(
        &self,
        migrate_id: u64,
        local_bind_addresses: &[std::net::IpAddr],
        bind_interface: Option<&str>,
    ) -> Result<AsyncYuubinsyaUotSession<BoxAsyncStream>> {
        self.ensure_open()?;
        let yuubinsya = self.chain.yuubinsya.as_ref().ok_or_else(|| {
            Error::new(
                ErrorKind::Unsupported,
                "standalone HTTP/2 transport has no UDP protocol",
            )
        })?;
        if !yuubinsya.udp_over_stream {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "chain does not enable yuubinsya udp_over_stream",
            ));
        }
        let stream = self
            .open_h2_stream(local_bind_addresses, bind_interface)
            .await?;
        let local_addr = stream_local_addr(&*stream);
        AsyncYuubinsyaUotSession::connect_with_local_addr(
            stream,
            derive_salt(yuubinsya.password.as_bytes()),
            migrate_id,
            yuubinsya.udp_coalesce,
            local_addr,
        )
        .await
    }

    async fn open_h2_stream(
        &self,
        local_bind_addresses: &[std::net::IpAddr],
        bind_interface: Option<&str>,
    ) -> Result<BoxAsyncStream> {
        self.ensure_open()?;
        let tls_identity = self.transport_identity();
        let endpoints = self
            .resolve_fixed_addresses()
            .await?
            .iter()
            .map(|(address, bind_interface)| H2PoolEndpoint {
                address: *address,
                bind_interface: bind_interface.clone(),
            })
            .collect::<Vec<_>>();
        let stream = self
            .pool
            .open_with_endpoints_and_local_addr(
                &endpoints,
                &tls_identity,
                self.chain.http2.concurrency,
                |endpoint| {
                    let endpoint_interface = endpoint
                        .bind_interface
                        .or_else(|| bind_interface.map(str::to_owned));
                    self.open_h2_connection(
                        endpoint.address,
                        local_bind_addresses,
                        endpoint_interface,
                    )
                },
            )
            .await?;
        let (stream, local_addr) = stream;
        if self.closed.load(Ordering::Acquire) {
            let mut stream = stream;
            let _ = stream.shutdown().await;
            return Err(closed_error());
        }
        Ok(with_stream_local_addr(
            Box::new(stream) as BoxAsyncStream,
            local_addr,
        ))
    }

    fn transport_identity(&self) -> String {
        let websocket = self
            .chain
            .websocket
            .as_ref()
            .map(|websocket| format!("{}{}", websocket.host, websocket.path))
            .unwrap_or_default();
        format!("{}\0websocket:{websocket}", self.chain.tls.pool_identity())
    }

    async fn resolve_fixed_addresses(&self) -> Result<Vec<(SocketAddr, Option<String>)>> {
        let mut addresses = Vec::new();
        for endpoint in &self.chain.fixed_addresses {
            if let Some(address) = endpoint.socket_addr() {
                addresses.push((address, endpoint.network_interface.clone()));
                continue;
            }
            let domain = endpoint
                .domain()
                .ok_or_else(|| Error::invalid("fixedv2 endpoint has an invalid domain"))?;
            let resolved = self
                .resolver
                .resolve(&domain, ResolveStrategy::Default)
                .await?;
            addresses.extend(resolved.iter().map(|address| {
                (
                    SocketAddr::new(address, endpoint.port),
                    endpoint.network_interface.clone(),
                )
            }));
        }
        if addresses.is_empty() {
            return Err(Error::invalid("fixedv2 has no resolved upstream address"));
        }
        Ok(addresses)
    }

    fn ensure_open(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        Ok(())
    }

    async fn open_h2_connection(
        &self,
        address: SocketAddr,
        local_bind_addresses: &[std::net::IpAddr],
        bind_interface: Option<String>,
    ) -> Result<Arc<H2Connection>> {
        let local_bind = local_bind_addresses
            .iter()
            .copied()
            .find(|ip| ip.is_ipv4() == address.ip().is_ipv4())
            .map(|ip| SocketAddr::new(ip, 0));
        let stream = connect_tokio_tcp_with_interface(
            address,
            local_bind,
            bind_interface.as_deref(),
            Duration::from_secs(15),
        )
        .await?;
        let local_addr = stream.local_addr().ok();
        let mut stream: BoxAsyncStream = if self.chain.tls.servernames.is_empty() {
            Box::new(stream)
        } else {
            let server_name = self.chain.tls.server_name();
            let server_name = rustls::pki_types::ServerName::try_from(server_name)
                .map_err(|_| Error::invalid("TLS server name is invalid"))?;
            Box::new(
                self.tls
                    .connect(server_name, stream)
                    .await
                    .map_err(tls_error)?,
            )
        };
        if let Some(websocket) = &self.chain.websocket {
            let request = websocket
                .request_uri()
                .into_client_request()
                .map_err(|error| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("WebSocket request: {error}"),
                    )
                })?;
            let (websocket, _) = tokio_tungstenite::client_async(request, stream)
                .await
                .map_err(|error| {
                    Error::new(ErrorKind::Protocol, format!("WebSocket handshake: {error}"))
                })?;
            stream = Box::new(yuhaiin_protocol::websocket::WebSocketIo::new(websocket));
        }
        H2Connection::handshake_with_limits_and_local_addr(
            stream,
            self.chain.http2.max_streams,
            local_addr,
        )
        .await
    }
}

/// Adapter from the runnable fixed -> TLS -> HTTP/2 -> destination protocol
/// chain to the common async proxy contract used by the TUN flow runtime.
#[derive(Clone)]
pub struct ChainProxy {
    backend: ChainProxyBackend,
}

#[derive(Clone)]
enum ChainProxyBackend {
    H2(ChainClient),
    Protocol(Arc<dyn AsyncProxy>),
    DirectUot(DirectUotProxy),
}

impl ChainProxy {
    pub fn new(client: ChainClient) -> Self {
        Self {
            backend: ChainProxyBackend::H2(client),
        }
    }

    fn final_proxy(client: ChainClient) -> Result<Self> {
        if client.chain.yuubinsya.is_some() {
            return Ok(Self::new(client));
        }
        let parent: Arc<dyn AsyncProxy> = Arc::new(Self::new(client.clone()));
        if let Some(http) = client.chain.http.as_ref() {
            return Ok(Self {
                backend: ChainProxyBackend::Protocol(Arc::new(
                    yuhaiin_protocol::http::HttpProxy::new(
                        parent,
                        http.user.clone(),
                        http.password.clone(),
                    ),
                )),
            });
        }
        if let Some(socks5) = client.chain.socks5.as_ref() {
            return Ok(Self {
                backend: ChainProxyBackend::Protocol(Arc::new(
                    yuhaiin_protocol::socks5::Socks5Proxy::new(
                        parent,
                        socks5.user.clone(),
                        socks5.password.clone(),
                        socks5.hostname.clone(),
                        socks5.override_port,
                    )?,
                )),
            });
        }
        Err(Error::new(
            ErrorKind::Unsupported,
            "standalone HTTP/2 transport requires a destination protocol layer",
        ))
    }

    /// Construct the common async proxy contract from a Go node payload.
    pub fn from_go_json(json: &str) -> Result<Self> {
        Self::final_proxy(ChainClient::from_go_json(json)?)
    }

    pub fn from_go_json_with_resolver(
        json: &str,
        resolver: Arc<dyn AsyncIpResolver>,
    ) -> Result<Self> {
        if let Some(proxy) = parse_go_direct_uot(json, Arc::clone(&resolver))? {
            return Ok(Self {
                backend: ChainProxyBackend::DirectUot(proxy),
            });
        }
        Self::final_proxy(ChainClient::from_go_json_with_resolver(json, resolver)?)
    }

    /// Construct only the raw Go-compatible HTTP/2 transport from a node
    /// payload whose final protocol layer is supplied by the caller.
    ///
    /// Go builds protocol nodes by folding every chain item over the previous
    /// proxy. This entry point preserves that boundary for VLESS/VMess/Trojan:
    /// the chain crate owns fixed/TLS/WebSocket/HTTP2, while the protocol
    /// crate remains the outer framing layer.
    pub fn from_go_json_transport_with_resolver(
        json: &str,
        resolver: Arc<dyn AsyncIpResolver>,
    ) -> Result<Self> {
        let client = ChainClient::from_go_json_with_resolver(json, resolver)?;
        if client.chain.yuubinsya.is_some()
            || client.chain.http.is_some()
            || client.chain.socks5.is_some()
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "raw HTTP/2 transport cannot contain a destination protocol",
            ));
        }
        Ok(Self::new(client))
    }

    pub fn client(&self) -> Option<&ChainClient> {
        match &self.backend {
            ChainProxyBackend::H2(client) => Some(client),
            ChainProxyBackend::Protocol(_) => None,
            ChainProxyBackend::DirectUot(_) => None,
        }
    }
}

impl AsyncProxy for ChainProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        match &self.backend {
            ChainProxyBackend::H2(client) => {
                let client = client.clone();
                Box::pin(async move {
                    if client.chain.yuubinsya.is_some() {
                        let session = client
                            .connect_tcp_with_bind_and_interface(
                                context.effective_destination(),
                                &context.local_bind_addresses,
                                context.bind_interface.as_deref(),
                            )
                            .await?;
                        let local_addr = stream_local_addr(session.transport());
                        Ok(with_stream_local_addr(
                            Box::new(session) as BoxAsyncStream,
                            local_addr,
                        ))
                    } else {
                        let stream = client
                            .connect_raw_with_bind_and_interface(
                                &context.local_bind_addresses,
                                context.bind_interface.as_deref(),
                            )
                            .await?;
                        Ok(stream)
                    }
                })
            }
            ChainProxyBackend::Protocol(proxy) => proxy.connect(context),
            ChainProxyBackend::DirectUot(proxy) => proxy.connect(context),
        }
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        match &self.backend {
            ChainProxyBackend::H2(client) => {
                let client = client.clone();
                let migrate_id = Arc::clone(&context.udp_migrate_id);
                let local_bind_addresses = Arc::new(context.local_bind_addresses.clone());
                let bind_interface = context.bind_interface.clone();
                Box::pin(async move {
                    let session = client
                        .connect_uot_with_bind_and_interface(
                            migrate_id.load(Ordering::Acquire),
                            local_bind_addresses.as_slice(),
                            bind_interface.as_deref(),
                        )
                        .await?;
                    let migrate = session.migrate_id;
                    let udp_coalesce = session.udp_coalesce;
                    let local_addr = session.local_addr();
                    let (reader, writer) = session.into_split().await;
                    migrate_id.store(migrate, Ordering::Release);
                    Ok(Box::new(ChainDatagram {
                        client,
                        migrate_id,
                        session: Mutex::new(Some(ChainUotSession::new(
                            reader,
                            writer,
                            udp_coalesce,
                        ))),
                        reconnect_lock: Mutex::new(()),
                        generation: std::sync::atomic::AtomicU64::new(1),
                        closed: std::sync::atomic::AtomicBool::new(false),
                        shutdown: watch::channel(false).0,
                        next_retry_id: std::sync::atomic::AtomicU64::new(1),
                        retry: Mutex::new(RetryQueue::new()),
                        local_bind_addresses,
                        bind_interface,
                        local_addr: StdMutex::new(local_addr),
                    }) as Box<dyn AsyncDatagram>)
                })
            }
            ChainProxyBackend::Protocol(proxy) => proxy.open_datagram(context),
            ChainProxyBackend::DirectUot(proxy) => proxy.open_datagram(context),
        }
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        match &self.backend {
            ChainProxyBackend::H2(client) => {
                let client = client.clone();
                Box::pin(async move {
                    client.close().await;
                    Ok(())
                })
            }
            ChainProxyBackend::Protocol(proxy) => proxy.close(),
            ChainProxyBackend::DirectUot(proxy) => proxy.close(),
        }
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        match &self.backend {
            ChainProxyBackend::H2(client) => {
                let client = client.clone();
                let destination = context.effective_destination();
                let local_bind_addresses = context.local_bind_addresses.clone();
                let bind_interface = context.bind_interface.clone();
                Box::pin(async move {
                    client
                        .ping_with_bind_and_interface(
                            destination,
                            &local_bind_addresses,
                            bind_interface.as_deref(),
                        )
                        .await
                })
            }
            ChainProxyBackend::Protocol(proxy) => proxy.ping(context),
            ChainProxyBackend::DirectUot(proxy) => proxy.ping(context),
        }
    }
}

struct ChainDatagram {
    client: ChainClient,
    migrate_id: Arc<std::sync::atomic::AtomicU64>,
    session: Mutex<Option<Arc<ChainUotSession>>>,
    reconnect_lock: Mutex<()>,
    generation: std::sync::atomic::AtomicU64,
    closed: std::sync::atomic::AtomicBool,
    shutdown: watch::Sender<bool>,
    next_retry_id: std::sync::atomic::AtomicU64,
    retry: Mutex<RetryQueue>,
    local_bind_addresses: Arc<Vec<std::net::IpAddr>>,
    bind_interface: Option<String>,
    local_addr: StdMutex<Option<SocketAddr>>,
}

struct PendingUotDatagram {
    id: u64,
    target: Endpoint,
    payload: Vec<u8>,
}

struct RetryQueue {
    frames: VecDeque<PendingUotDatagram>,
    bytes: usize,
}

impl RetryQueue {
    fn new() -> Self {
        Self {
            frames: VecDeque::new(),
            bytes: 0,
        }
    }

    fn push(&mut self, frame: PendingUotDatagram) -> Result<()> {
        if frame.payload.len() > MAX_UOT_RETRY_BYTES
            || self.frames.len() >= MAX_UOT_RETRY_FRAMES
            || self.bytes.saturating_add(frame.payload.len()) > MAX_UOT_RETRY_BYTES
        {
            return Err(Error::new(
                ErrorKind::Timeout,
                "Yuubinsya UOT retry queue is full",
            ));
        }
        self.bytes += frame.payload.len();
        self.frames.push_back(frame);
        Ok(())
    }

    fn remove_id(&mut self, id: u64) {
        if let Some(index) = self.frames.iter().position(|frame| frame.id == id)
            && let Some(frame) = self.frames.remove(index)
        {
            self.bytes = self.bytes.saturating_sub(frame.payload.len());
        }
    }

    fn acknowledge(&mut self, source: &Endpoint, payload: &[u8]) {
        let exact = self
            .frames
            .iter()
            .position(|frame| &frame.target == source && frame.payload == payload);
        let index = exact.or_else(|| {
            self.frames
                .iter()
                .position(|frame| frame.payload == payload)
        });
        if let Some(index) = index
            && let Some(frame) = self.frames.remove(index)
        {
            self.bytes = self.bytes.saturating_sub(frame.payload.len());
        }
    }

    fn snapshot(&self) -> Vec<(Endpoint, Vec<u8>)> {
        self.frames
            .iter()
            .map(|frame| (frame.target.clone(), frame.payload.clone()))
            .collect()
    }

    fn clear(&mut self) {
        self.frames.clear();
        self.bytes = 0;
    }
}

struct ChainUotWriter {
    stream: WriteHalf<BoxAsyncStream>,
    udp_coalesce: bool,
    pending: Vec<u8>,
    pending_frames: usize,
}

struct ChainUotSession {
    reader: Mutex<ReadHalf<BoxAsyncStream>>,
    writer: Mutex<ChainUotWriter>,
    coalescer: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    coalesce_notify: Arc<Notify>,
}

impl ChainUotSession {
    fn new(
        reader: ReadHalf<BoxAsyncStream>,
        writer: WriteHalf<BoxAsyncStream>,
        udp_coalesce: bool,
    ) -> Arc<Self> {
        let session = Arc::new(Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(ChainUotWriter {
                stream: writer,
                udp_coalesce,
                pending: Vec::new(),
                pending_frames: 0,
            }),
            coalescer: StdMutex::new(None),
            coalesce_notify: Arc::new(Notify::new()),
        });
        if udp_coalesce {
            let weak = Arc::downgrade(&session);
            let notify = Arc::clone(&session.coalesce_notify);
            let task = tokio::spawn(async move {
                loop {
                    notify.notified().await;
                    tokio::task::yield_now().await;
                    let Some(session) = weak.upgrade() else {
                        return;
                    };
                    if session.flush().await.is_err() {
                        return;
                    }
                }
            });
            if let Ok(mut coalescer) = session.coalescer.lock() {
                *coalescer = Some(task);
            } else {
                task.abort();
            }
        }
        session
    }

    async fn send_to(&self, target: &Endpoint, payload: &[u8]) -> Result<()> {
        let frame = yuhaiin_protocol::yuubinsya::encode_uot_frame(target, payload)?;
        let mut writer = self.writer.lock().await;
        if !writer.udp_coalesce {
            writer.stream.write_all(&frame).await.map_err(io_error)?;
            return writer.stream.flush().await.map_err(io_error);
        }
        if frame.len() > MAX_UOT_COALESCE_BYTES
            || writer.pending.len() + frame.len() > MAX_UOT_COALESCE_BYTES
            || writer.pending_frames >= MAX_UOT_COALESCE_FRAMES
        {
            flush_uot_writer(&mut writer).await?;
        }
        writer.pending.extend_from_slice(&frame);
        writer.pending_frames += 1;
        if writer.pending_frames >= MAX_UOT_COALESCE_FRAMES {
            flush_uot_writer(&mut writer).await?;
        }
        drop(writer);
        // Match the Go packet-conn policy: one producer enqueue wakes an
        // owner flush loop, which gets one scheduler turn to batch concurrent
        // producers before writing.  Threshold and explicit recv/close
        // flushes remain the hard upper bounds for the batch size.
        self.coalesce_notify.notify_one();
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Endpoint, Vec<u8>)> {
        self.flush().await?;
        let mut reader = self.reader.lock().await;
        let frame = read_uot_frame(&mut *reader).await?;
        let (destination, payload, _) = yuhaiin_protocol::yuubinsya::decode_uot_frame(&frame)?;
        Ok((destination, payload.to_vec()))
    }

    async fn flush(&self) -> Result<()> {
        let mut writer = self.writer.lock().await;
        flush_uot_writer(&mut writer).await
    }

    async fn shutdown(&self) -> Result<()> {
        self.flush().await?;
        let task = self
            .coalescer
            .lock()
            .ok()
            .and_then(|mut coalescer| coalescer.take());
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        let mut writer = self.writer.lock().await;
        writer.stream.shutdown().await.map_err(io_error)
    }
}

impl Drop for ChainUotSession {
    fn drop(&mut self) {
        if let Ok(mut coalescer) = self.coalescer.lock()
            && let Some(task) = coalescer.take()
        {
            task.abort();
        }
    }
}

async fn flush_uot_writer(writer: &mut ChainUotWriter) -> Result<()> {
    if writer.pending.is_empty() {
        return Ok(());
    }
    writer
        .stream
        .write_all(&writer.pending)
        .await
        .map_err(io_error)?;
    writer.stream.flush().await.map_err(io_error)?;
    writer.pending.clear();
    writer.pending_frames = 0;
    Ok(())
}

impl AsyncDatagram for ChainDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let retry_id = self.queue_retry(target.clone(), payload).await?;
            let generation = self.generation.load(Ordering::Acquire);
            let mut shutdown = self.shutdown.subscribe();
            let send_result = tokio::select! {
                result = self.send_once(&target, payload) => result,
                changed = shutdown.changed() => match changed {
                    Ok(()) | Err(_) => Err(closed_error()),
                },
            };
            if let Err(mut error) = send_result {
                if !is_recoverable_uot_error(&error) {
                    self.drop_retry(retry_id).await;
                    return Err(error);
                }

                // A write can fail before the peer has observed the frame, or
                // after it has already reached the peer. `reconnect()`
                // replays every still-unacknowledged frame from the bounded
                // retry queue, so retrying the connection is safe with the
                // duplicate-tolerant semantics required by UDP callers. Keep
                // the original frame queued when the reconnect budget is
                // exhausted; a concurrent/follow-up recv can still recover it.
                let mut reconnect_attempts = 0;
                loop {
                    if reconnect_attempts >= MAX_UOT_RECONNECT_ATTEMPTS {
                        return Err(error);
                    }
                    reconnect_attempts += 1;
                    let reconnect = tokio::select! {
                        result = self.reconnect(generation) => result,
                        changed = shutdown.changed() => match changed {
                            Ok(()) | Err(_) => Err(closed_error()),
                        },
                    };
                    match reconnect {
                        Ok(()) => break,
                        Err(reconnect_error) if reconnect_error.kind == ErrorKind::Closed => {
                            self.drop_retry(retry_id).await;
                            return Err(reconnect_error);
                        }
                        Err(reconnect_error) => error = reconnect_error,
                    }
                }
            }
            if self.closed.load(Ordering::Acquire) {
                self.drop_retry(retry_id).await;
                return Err(closed_error());
            }
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let generation = self.generation.load(Ordering::Acquire);
            let mut shutdown = self.shutdown.subscribe();
            let mut generation = generation;
            let mut reconnect_attempts = 0;
            let (source, payload) = loop {
                let result = tokio::select! {
                    result = self.recv_once() => result,
                    changed = shutdown.changed() => match changed {
                        Ok(()) | Err(_) => Err(closed_error()),
                    },
                };
                match result {
                    Ok(value) => break value,
                    Err(error)
                        if is_recoverable_uot_error(&error)
                            && reconnect_attempts < MAX_UOT_RECONNECT_ATTEMPTS =>
                    {
                        let reconnect = tokio::select! {
                            result = self.reconnect(generation) => result,
                            changed = shutdown.changed() => match changed {
                                Ok(()) | Err(_) => Err(closed_error()),
                            },
                        };
                        reconnect?;
                        generation = self.generation.load(Ordering::Acquire);
                        reconnect_attempts += 1;
                    }
                    Err(error) => return Err(error),
                }
            };
            if self.closed.load(Ordering::Acquire) {
                return Err(closed_error());
            }
            if buffer.len() < payload.len() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Yuubinsya UDP payload exceeds receive buffer",
                ));
            }
            self.acknowledge_retry(&source, &payload).await;
            buffer[..payload.len()].copy_from_slice(&payload);
            Ok((payload.len(), source))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        let local_addr = self
            .local_addr
            .lock()
            .ok()
            .and_then(|address| *address)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unsupported,
                    "Yuubinsya UOT has no observable local endpoint",
                )
            })?;
        Ok(Endpoint::ip(Network::Tcp, local_addr))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.closed.store(true, Ordering::Release);
            let _ = self.shutdown.send(true);
            let session = self.session.lock().await.take();
            let result = if let Some(session) = session {
                session.shutdown().await
            } else {
                Ok(())
            };
            self.retry.lock().await.clear();
            result
        })
    }
}

fn closed_error() -> Error {
    Error::new(ErrorKind::Closed, "Yuubinsya UOT session is closed")
}

impl ChainDatagram {
    async fn send_once(&self, target: &Endpoint, payload: &[u8]) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UOT session is closed",
            ));
        }
        let session = self.session.lock().await.clone();
        let session = session
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Closed, "Yuubinsya UOT session is closed"))?;
        session.send_to(target, payload).await
    }

    async fn recv_once(&self) -> Result<(Endpoint, Vec<u8>)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UOT session is closed",
            ));
        }
        let session = self.session.lock().await.clone();
        let session = session
            .as_ref()
            .ok_or_else(|| Error::new(ErrorKind::Closed, "Yuubinsya UOT session is closed"))?;
        session.recv_from().await
    }

    async fn reconnect(&self, failed_generation: u64) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UOT session is closed",
            ));
        }
        let _guard = self.reconnect_lock.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UOT session is closed",
            ));
        }
        if self.generation.load(Ordering::Acquire) != failed_generation {
            return Ok(());
        }
        let migrate_id = self.migrate_id.load(Ordering::Acquire);
        // A failed write may have reached the peer before reporting an error;
        // retrying one UDP datagram can therefore duplicate it. UDP callers
        // already need duplicate-tolerant semantics, while a bounded retry
        // prevents a dead H2 stream from permanently wedging the flow.
        let replacement = self
            .client
            .connect_uot_with_bind_and_interface(
                migrate_id,
                self.local_bind_addresses.as_slice(),
                self.bind_interface.as_deref(),
            )
            .await?;
        let replacement_id = replacement.migrate_id;
        let udp_coalesce = replacement.udp_coalesce;
        let local_addr = replacement.local_addr();
        let (reader, writer) = replacement.into_split().await;
        let replacement = ChainUotSession::new(reader, writer, udp_coalesce);
        let retry = self.retry.lock().await.snapshot();
        for (target, payload) in &retry {
            replacement.send_to(target, payload).await?;
        }
        replacement.flush().await?;
        if self.closed.load(Ordering::Acquire) {
            replacement.shutdown().await?;
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UOT session is closed",
            ));
        }
        self.migrate_id.store(replacement_id, Ordering::Release);
        if let Ok(mut current) = self.local_addr.lock() {
            *current = local_addr;
        }
        let mut session = self.session.lock().await;
        if self.closed.load(Ordering::Acquire) {
            replacement.shutdown().await?;
            return Err(Error::new(
                ErrorKind::Closed,
                "Yuubinsya UOT session is closed",
            ));
        }
        let _ = session.take();
        *session = Some(replacement);
        self.generation.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    async fn queue_retry(&self, target: Endpoint, payload: &[u8]) -> Result<u64> {
        let id = self.next_retry_id.fetch_add(1, Ordering::AcqRel);
        self.retry.lock().await.push(PendingUotDatagram {
            id,
            target,
            payload: payload.to_vec(),
        })?;
        Ok(id)
    }

    async fn drop_retry(&self, id: u64) {
        self.retry.lock().await.remove_id(id);
    }

    async fn acknowledge_retry(&self, source: &Endpoint, payload: &[u8]) {
        self.retry.lock().await.acknowledge(source, payload);
    }
}

fn is_recoverable_uot_error(error: &Error) -> bool {
    matches!(
        error.kind,
        ErrorKind::Io | ErrorKind::Closed | ErrorKind::Protocol | ErrorKind::Timeout
    )
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

fn root_store(certificates: &[Vec<u8>]) -> Result<RootCertStore> {
    // Go starts from the platform system pool and appends node-specific
    // certificates.  The pure-Rust equivalent uses the Mozilla WebPKI set;
    // private or enterprise roots can still be appended through ca_cert.
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for certificate in certificates {
        let mut cursor = std::io::Cursor::new(certificate);
        let mut parsed = false;
        for certificate in rustls_pemfile::certs(&mut cursor) {
            let certificate = certificate.map_err(tls_error)?;
            roots.add(certificate).map_err(tls_error)?;
            parsed = true;
        }
        if !parsed {
            roots
                .add(rustls::pki_types::CertificateDer::from(certificate.clone()))
                .map_err(tls_error)?;
        }
    }
    Ok(roots)
}

/// Go's `InsecureSkipVerify` skips certificate-chain and hostname validation,
/// but the TLS handshake still needs to verify the server's ephemeral
/// signature.  Keep that signature check enabled so this option does not
/// disable the cryptographic part of TLS itself.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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

fn tls_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Protocol, format!("TLS: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(port: u16) -> Endpoint {
        Endpoint::ip(Network::Udp, SocketAddr::from(([192, 0, 2, 1], port)))
    }

    #[test]
    fn root_store_has_public_roots_without_custom_certificates() {
        let roots = root_store(&[]).unwrap();
        assert!(!roots.is_empty());
    }

    #[test]
    fn retry_queue_has_bounded_frame_and_byte_capacity() {
        let mut queue = RetryQueue::new();
        for id in 0..MAX_UOT_RETRY_FRAMES as u64 {
            queue
                .push(PendingUotDatagram {
                    id,
                    target: endpoint(5353),
                    payload: vec![id as u8],
                })
                .unwrap();
        }
        let error = queue
            .push(PendingUotDatagram {
                id: MAX_UOT_RETRY_FRAMES as u64,
                target: endpoint(5353),
                payload: vec![0],
            })
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout);

        queue.remove_id(0);
        queue
            .push(PendingUotDatagram {
                id: MAX_UOT_RETRY_FRAMES as u64,
                target: endpoint(5353),
                payload: vec![0],
            })
            .unwrap();
        assert_eq!(queue.snapshot().len(), MAX_UOT_RETRY_FRAMES);

        let mut bytes = RetryQueue::new();
        bytes
            .push(PendingUotDatagram {
                id: 1,
                target: endpoint(5353),
                payload: vec![0; MAX_UOT_RETRY_BYTES],
            })
            .unwrap();
        let error = bytes
            .push(PendingUotDatagram {
                id: 2,
                target: endpoint(5353),
                payload: vec![0],
            })
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout);
    }

    #[test]
    fn retry_queue_acknowledges_exact_target_before_payload_fallback() {
        let first_target = endpoint(5353);
        let second_target = endpoint(5354);
        let mut queue = RetryQueue::new();
        queue
            .push(PendingUotDatagram {
                id: 1,
                target: first_target.clone(),
                payload: b"same".to_vec(),
            })
            .unwrap();
        queue
            .push(PendingUotDatagram {
                id: 2,
                target: second_target.clone(),
                payload: b"same".to_vec(),
            })
            .unwrap();

        queue.acknowledge(&second_target, b"same");
        assert_eq!(queue.snapshot(), vec![(first_target, b"same".to_vec())]);
        queue.acknowledge(&endpoint(5355), b"same");
        assert!(queue.snapshot().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn coalesced_uot_flushes_a_low_traffic_datagram_without_recv() {
        let (client, mut peer) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(Box::new(client) as BoxAsyncStream);
        let session = ChainUotSession::new(reader, writer, true);
        let target = endpoint(5353);

        session.send_to(&target, b"low-traffic").await.unwrap();
        let frame = tokio::time::timeout(Duration::from_secs(1), read_uot_frame(&mut peer))
            .await
            .expect("coalesced UOT frame was not flushed")
            .unwrap();
        let (decoded_target, payload, _) =
            yuhaiin_protocol::yuubinsya::decode_uot_frame(&frame).unwrap();
        assert_eq!(decoded_target, target);
        assert_eq!(payload, b"low-traffic");
        session.shutdown().await.unwrap();
    }

    #[test]
    fn runtime_stats_render_a_stable_prometheus_snapshot() {
        let stats = ChainRuntimeStats {
            h2_connections: 2,
            h2_active_streams: 5,
            h2_pool: H2PoolStats {
                connection_attempts: 7,
                connection_failures: 1,
                stream_capacity_rejections: 3,
                stream_open_failures: 2,
            },
        };
        let rendered = stats.render_prometheus();
        assert!(rendered.contains("# TYPE yuhaiin_chain_h2_connections gauge"));
        assert!(rendered.contains("yuhaiin_chain_h2_connections 2\n"));
        assert!(rendered.contains("yuhaiin_chain_h2_active_streams 5\n"));
        assert!(rendered.contains("yuhaiin_chain_h2_connection_attempts 7\n"));
        assert!(rendered.contains("yuhaiin_chain_h2_stream_capacity_rejections 3\n"));
        assert!(rendered.ends_with('\n'));
    }
}
