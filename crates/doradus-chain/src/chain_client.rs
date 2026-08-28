//! Public ordered chain client and protocol operations.

use super::chain_transports::{FixedChainProxy, H2ChainProxy, TlsChainProxy};
use super::chain_uot::closed_error;
use super::*;

struct CachedPing {
    session: Mutex<AsyncYuubinsyaPingSession<BoxAsyncStream>>,
    last_used: StdMutex<Instant>,
}

#[derive(Clone)]
pub struct ChainClient {
    chain: Arc<ValidatedChain>,
    pub(super) proxy: Arc<dyn AsyncProxy>,
    h2_layers: Vec<Arc<H2ChainProxy>>,
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
        Self::new_with_resolver_and_metrics(
            chain,
            resolver,
            Arc::new(doradus_metrics::RuntimeMetrics::new()),
        )
    }

    pub fn new_with_resolver_and_metrics(
        chain: ValidatedChain,
        resolver: Arc<dyn AsyncIpResolver>,
        metrics: Arc<doradus_metrics::RuntimeMetrics>,
    ) -> Result<Self> {
        Self::new_with_resolver_and_metrics_and_dialer(
            chain,
            resolver,
            metrics,
            Arc::new(HappyEyeballsV2Dialer::new(None)),
        )
    }

    pub fn new_with_resolver_and_metrics_and_dialer(
        chain: ValidatedChain,
        resolver: Arc<dyn AsyncIpResolver>,
        metrics: Arc<doradus_metrics::RuntimeMetrics>,
        dialer: Arc<HappyEyeballsV2Dialer>,
    ) -> Result<Self> {
        // Go's ContractDialer starts with zeroproxy.  For transport purposes
        // that sentinel behaves like direct dialing until a node replaces it.
        let direct: Arc<dyn AsyncProxy> = Arc::new(HappyEyeballsTcpProxy::new(
            Arc::new(DirectAsyncProxy {
                timeout: Duration::from_secs(15),
            }),
            Arc::clone(&dialer),
            Duration::from_secs(15),
        ));
        let mut proxy = Some(direct);
        let mut h2_layers = Vec::new();
        for (index, node) in chain.nodes.iter().enumerate() {
            match node {
                ValidatedNode::Direct(config) => {
                    let direct: Arc<dyn AsyncProxy> = Arc::new(HappyEyeballsTcpProxy::new(
                        Arc::new(DirectAsyncProxy {
                            timeout: Duration::from_secs(15),
                        }),
                        Arc::clone(&dialer),
                        Duration::from_secs(15),
                    ));
                    proxy = Some(match &config.network_interface {
                        Some(interface) => {
                            Arc::new(BindInterfaceProxy::new(direct, Some(interface.clone())))
                        }
                        None => direct,
                    });
                    // An explicit direct node resets the Go fold.  Any
                    // transport layers before it are no longer reachable.
                    h2_layers.clear();
                }
                ValidatedNode::Fixed(config) => {
                    let upstream = proxy.take();
                    proxy = Some(Arc::new(FixedChainProxy::new(
                        config.clone(),
                        Arc::clone(&resolver),
                        upstream,
                        Arc::clone(&dialer),
                    )));
                }
                ValidatedNode::Tls(config) => {
                    let upstream = proxy
                        .take()
                        .ok_or_else(|| Error::invalid("TLS node has no parent transport"))?;
                    proxy = Some(Arc::new(TlsChainProxy::new(upstream, config.clone())?));
                }
                ValidatedNode::WebSocket(config) => {
                    let upstream = proxy
                        .take()
                        .ok_or_else(|| Error::invalid("WebSocket node has no parent transport"))?;
                    proxy = Some(Arc::new(doradus_protocol::websocket::WebSocketProxy::new(
                        upstream,
                        config.host.clone(),
                        config.path.clone(),
                    )?));
                }
                ValidatedNode::Http2(config) => {
                    let upstream = proxy
                        .take()
                        .ok_or_else(|| Error::invalid("HTTP/2 node has no parent transport"))?;
                    let layer =
                        H2ChainProxy::new(upstream, config.clone(), index, Arc::clone(&metrics));
                    proxy = Some(layer.clone());
                    h2_layers.push(layer);
                }
                ValidatedNode::Http(config) | ValidatedNode::HttpProxy(config) => {
                    let upstream = proxy
                        .take()
                        .ok_or_else(|| Error::invalid("HTTP node has no parent transport"))?;
                    proxy = Some(Arc::new(doradus_protocol::http::HttpProxy::new(
                        upstream,
                        config.user.clone(),
                        config.password.clone(),
                    )));
                }
                ValidatedNode::Socks5(config) => {
                    let upstream = proxy
                        .take()
                        .ok_or_else(|| Error::invalid("SOCKS5 node has no parent transport"))?;
                    proxy = Some(Arc::new(doradus_protocol::socks5::Socks5Proxy::new(
                        upstream,
                        config.user.clone(),
                        config.password.clone(),
                        config.hostname.clone(),
                        config.override_port,
                    )?));
                }
                ValidatedNode::Yuubinsya(_)
                | ValidatedNode::None
                | ValidatedNode::Proxy
                | ValidatedNode::BootstrapDnsWarp => {}
            }
        }
        let proxy = proxy.ok_or_else(|| Error::invalid("chain has no runnable transport"))?;
        Ok(Self {
            chain: Arc::new(chain),
            proxy,
            h2_layers,
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

    pub fn from_go_json_with_resolver_and_metrics(
        json: &str,
        resolver: Arc<dyn AsyncIpResolver>,
        metrics: Arc<doradus_metrics::RuntimeMetrics>,
    ) -> Result<Self> {
        Self::new_with_resolver_and_metrics(parse_go_node(json)?, resolver, metrics)
    }

    pub fn from_go_json_with_resolver_and_metrics_and_dialer(
        json: &str,
        resolver: Arc<dyn AsyncIpResolver>,
        metrics: Arc<doradus_metrics::RuntimeMetrics>,
        dialer: Arc<HappyEyeballsV2Dialer>,
    ) -> Result<Self> {
        Self::new_with_resolver_and_metrics_and_dialer(
            parse_go_node(json)?,
            resolver,
            metrics,
            dialer,
        )
    }

    pub fn chain(&self) -> &ValidatedChain {
        &self.chain
    }

    pub async fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        // Close every ordered transport layer first. A cached Yuubinsya ping
        // may be waiting on one of the H2 layers; closing the chain wakes it.
        let _ = self.proxy.close().await;
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
        let mut count = 0;
        for layer in &self.h2_layers {
            count += layer.pool.len().await;
        }
        count
    }

    pub async fn h2_active_streams(&self) -> usize {
        let mut count = 0;
        for layer in &self.h2_layers {
            count += layer.pool.active_streams().await;
        }
        count
    }

    /// Sample H2 capacity and pool counters together for runtime observation.
    pub async fn runtime_stats(&self) -> ChainRuntimeStats {
        let mut stats = H2PoolStats::default();
        let mut connections = 0;
        let mut active_streams = 0;
        for layer in &self.h2_layers {
            connections += layer.pool.len().await;
            active_streams += layer.pool.active_streams().await;
            let current = layer.stats();
            stats.connection_attempts += current.connection_attempts;
            stats.connection_failures += current.connection_failures;
            stats.stream_capacity_rejections += current.stream_capacity_rejections;
            stats.stream_open_failures += current.stream_open_failures;
        }
        ChainRuntimeStats {
            h2_connections: connections,
            h2_active_streams: active_streams,
            h2_pool: stats,
        }
    }

    /// Return monotonic HTTP/2 pool counters for operational backpressure and
    /// connection-rebuild diagnostics.
    pub fn h2_pool_stats(&self) -> H2PoolStats {
        self.h2_layers
            .iter()
            .fold(H2PoolStats::default(), |mut total, layer| {
                let current = layer.stats();
                total.connection_attempts += current.connection_attempts;
                total.connection_failures += current.connection_failures;
                total.stream_capacity_rejections += current.stream_capacity_rejections;
                total.stream_open_failures += current.stream_open_failures;
                total
            })
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

        let Some(yuubinsya) = self.yuubinsya() else {
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
        let yuubinsya = self.yuubinsya().ok_or_else(|| {
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
        if self.has_destination_protocol() {
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
        let yuubinsya = self.yuubinsya().ok_or_else(|| {
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

    pub(super) fn yuubinsya(&self) -> Option<&ValidatedYuubinsya> {
        match self.chain.nodes.iter().rev().find(|node| {
            !matches!(
                node,
                ValidatedNode::None | ValidatedNode::Proxy | ValidatedNode::BootstrapDnsWarp
            )
        }) {
            Some(ValidatedNode::Yuubinsya(config)) => Some(config),
            _ => None,
        }
    }

    pub(super) fn has_destination_protocol(&self) -> bool {
        matches!(
            self.chain.nodes.iter().rev().find(|node| {
                !matches!(
                    node,
                    ValidatedNode::None | ValidatedNode::Proxy | ValidatedNode::BootstrapDnsWarp
                )
            }),
            Some(
                ValidatedNode::Yuubinsya(_)
                    | ValidatedNode::Http(_)
                    | ValidatedNode::HttpProxy(_)
                    | ValidatedNode::Socks5(_)
            )
        )
    }

    async fn open_h2_stream(
        &self,
        local_bind_addresses: &[std::net::IpAddr],
        bind_interface: Option<&str>,
    ) -> Result<BoxAsyncStream> {
        self.ensure_open()?;
        let mut context = FlowContext::new(Endpoint::ip(Network::Tcp, TRANSPORT_ENDPOINT));
        context.local_bind_addresses = local_bind_addresses.to_vec();
        context.bind_interface = bind_interface.map(str::to_owned);
        let stream = self.proxy.connect(&context).await?;
        if self.closed.load(Ordering::Acquire) {
            let mut stream = stream;
            let _ = stream.shutdown().await;
            return Err(closed_error());
        }
        Ok(stream)
    }

    fn ensure_open(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        Ok(())
    }
}
