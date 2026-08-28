use super::*;

pub struct NetworkSplitProxy {
    pub(super) tcp: Arc<dyn AsyncProxy>,
    pub(super) udp: Arc<dyn AsyncProxy>,
    pub(super) parent: Arc<dyn AsyncProxy>,
}

#[cfg(feature = "doh-tls")]
pub struct TlsTerminationProxy {
    pub(super) upstream: Arc<dyn AsyncProxy>,
    pub(super) acceptor: tokio_rustls::TlsAcceptor,
}

#[cfg(feature = "doh-tls")]
const TLS_TERMINATION_PIPE_BUFFER_SIZE: usize = 128 * 1024;

#[cfg(feature = "doh-tls")]
impl AsyncProxy for TlsTerminationProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let upstream = self.upstream.connect(context).await?;
            let local_addr = stream_local_addr(&*upstream);
            // Go's unWrapConn returns the client-facing side of a pipe
            // immediately. The TLS server handshake runs after the caller
            // starts relaying bytes; awaiting `accept` here deadlocks reverse
            // HTTP's non-HTTP path because its input cannot be copied until
            // `connect` returns.
            let (client, server) = tokio::io::duplex(TLS_TERMINATION_PIPE_BUFFER_SIZE);
            let acceptor = self.acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(server).await else {
                    return;
                };
                let mut upstream = upstream;
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
            });
            Ok(with_stream_local_addr(Box::new(client), local_addr))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        self.upstream.open_datagram(context)
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        self.upstream.ping(context)
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

impl AsyncProxy for NetworkSplitProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        self.tcp.connect(context)
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        self.udp.open_datagram(context)
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        // Go embeds the parent proxy, so Ping is intentionally not selected
        // by network here.
        self.parent.ping(context)
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        let proxies = [
            Arc::clone(&self.tcp),
            Arc::clone(&self.udp),
            Arc::clone(&self.parent),
        ];
        Box::pin(async move {
            let mut last_error = None;
            for proxy in proxies {
                if let Err(error) = proxy.close().await {
                    last_error = Some(error);
                }
            }
            last_error.map_or(Ok(()), Err)
        })
    }
}

/// A single nested Yuubinsya point used by `network_split`.  Full HTTP/2
/// chains use `doradus-chain::ChainProxy`; this adapter is for the Go point
/// contract where the branch wraps an already-built parent stream.
pub struct NetworkSplitYuubinsyaProxy {
    pub(super) upstream: Arc<dyn AsyncProxy>,
    pub(super) password_hash: [u8; 32],
    pub(super) udp_over_stream: bool,
    pub(super) udp_coalesce: bool,
    pub(super) udp_server: Option<Endpoint>,
}

/// Go's HTTP/2 contract wraps the already-built parent proxy and uses that
/// proxy only as the dialer for plaintext prior-knowledge HTTP/2.  Its UDP
/// method is inherited from the parent, so this adapter deliberately applies
/// HTTP/2 only to TCP streams as well.
pub struct NetworkSplitHttp2Proxy {
    pub(super) upstream: Arc<dyn AsyncProxy>,
    pub(super) connections: tokio::sync::Mutex<Vec<Arc<doradus_chain::H2Connection>>>,
    pub(super) connect_lock: tokio::sync::Mutex<()>,
    pub(super) concurrency: usize,
    pub(super) max_streams: usize,
}

impl NetworkSplitHttp2Proxy {
    async fn connect_stream(
        &self,
        context: &FlowContext,
    ) -> Result<(tokio::io::DuplexStream, Option<SocketAddr>)> {
        let _connect_guard = self.connect_lock.lock().await;
        let connections = {
            let mut connections = self.connections.lock().await;
            connections.retain(|connection| !connection.is_closed());
            connections.clone()
        };

        for connection in connections {
            if connection.at_capacity() {
                continue;
            }
            match connection
                .open_connect_stream_with_local_addr(self.concurrency)
                .await
            {
                Ok(stream) => return Ok(stream),
                Err(_) if connection.is_closed() => {
                    let mut connections = self.connections.lock().await;
                    connections.retain(|current| !Arc::ptr_eq(current, &connection));
                }
                Err(error) => {
                    let mut connections = self.connections.lock().await;
                    connections.retain(|current| !Arc::ptr_eq(current, &connection));
                    drop(connections);
                    connection.close().await;
                    // A live HTTP/2 connection can reject a CONNECT stream
                    // without closing the session. Do not let that stale
                    // session block every later flow.
                    let _ = error;
                }
            }
        }

        let upstream = self.upstream.connect(context).await?;
        let local_addr = stream_local_addr(&*upstream);
        let connection = doradus_chain::H2Connection::handshake_with_limits_and_local_addr(
            upstream,
            self.max_streams,
            local_addr,
        )
        .await?;
        let stream = match connection
            .open_connect_stream_with_local_addr(self.concurrency)
            .await
        {
            Ok(stream) => stream,
            Err(error) => {
                connection.close().await;
                return Err(error);
            }
        };
        self.connections.lock().await.push(connection);
        Ok(stream)
    }
}

impl AsyncProxy for NetworkSplitHttp2Proxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let (stream, local_addr) = self.connect_stream(context).await?;
            Ok(with_stream_local_addr(Box::new(stream), local_addr))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        self.upstream.open_datagram(context)
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        self.upstream.ping(context)
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        let upstream = Arc::clone(&self.upstream);
        let connect_lock = &self.connect_lock;
        let connections = &self.connections;
        Box::pin(async move {
            let _connect_guard = connect_lock.lock().await;
            let connections = connections.lock().await.drain(..).collect::<Vec<_>>();
            for connection in connections {
                connection.close().await;
            }
            upstream.close().await
        })
    }
}

impl AsyncProxy for NetworkSplitYuubinsyaProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let stream = self.upstream.connect(context).await?;
            let session = doradus_chain::AsyncYuubinsyaTcpSession::connect(
                stream,
                self.password_hash,
                context.effective_destination(),
            )
            .await?;
            let local_addr = stream_local_addr(session.transport());
            Ok(with_stream_local_addr(
                Box::new(session) as BoxAsyncStream,
                local_addr,
            ))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            if self.udp_over_stream {
                let stream = self.upstream.connect(context).await?;
                let local_addr = stream_local_addr(&stream);
                let session = doradus_chain::AsyncYuubinsyaUotSession::connect(
                    stream,
                    self.password_hash,
                    context.udp_migrate_id.load(Ordering::Acquire),
                    self.udp_coalesce,
                )
                .await?;
                context
                    .udp_migrate_id
                    .store(session.migrate_id, Ordering::Release);
                return Ok(Box::new(NetworkSplitYuubinsyaUotDatagram {
                    session: Arc::new(session),
                    local_addr,
                }) as Box<dyn AsyncDatagram>);
            }

            let server = self.udp_server.clone().ok_or_else(|| {
                Error::new(
                    ErrorKind::Unsupported,
                    "network_split Yuubinsya native UDP requires a fixed parent endpoint",
                )
            })?;
            let transport = self.upstream.open_datagram(context).await?;
            Ok(Box::new(YuubinsyaUdpDatagram::new(
                transport,
                self.password_hash,
                server,
                false,
            )?) as Box<dyn AsyncDatagram>)
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        self.upstream.ping(context)
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

pub struct NetworkSplitYuubinsyaUotDatagram {
    session: Arc<doradus_chain::AsyncYuubinsyaUotSession<BoxAsyncStream>>,
    local_addr: Option<SocketAddr>,
}

impl AsyncDatagram for NetworkSplitYuubinsyaUotDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            self.session.send_to(&target, payload).await?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let (target, payload) = self.session.recv_from().await?;
            if buffer.len() < payload.len() {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Yuubinsya UDP payload exceeds receive buffer",
                ));
            }
            buffer[..payload.len()].copy_from_slice(&payload);
            Ok((payload.len(), target))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Ok(Endpoint::ip(
            doradus_core::Network::Udp,
            self.local_addr
                .unwrap_or_else(|| "0.0.0.0:0".parse().expect("valid wildcard endpoint")),
        ))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move { self.session.shutdown().await })
    }
}

/// Keep a selected outbound proxy's socket in the loopback registry for the
/// exact lifetime of the returned stream. Protocol layers may replace the
/// concrete stream type, so the core transport carries the local endpoint as
/// optional metadata and this adapter owns the runtime-only guard.
pub struct LoopbackTrackingProxy {
    inner: Arc<dyn AsyncProxy>,
    detector: LoopbackDetector,
}

pub struct LoopbackTrackedStream {
    inner: BoxAsyncStream,
    _connection: crate::loopback::TrackedConnection,
}

impl AsyncRead for LoopbackTrackedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for LoopbackTrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub fn track_stream(detector: &LoopbackDetector, stream: BoxAsyncStream) -> BoxAsyncStream {
    let Some(local_addr) = stream_local_addr(&*stream) else {
        return stream;
    };
    let remote_addr = stream_remote_addr(&*stream);
    with_stream_socket_addrs(
        Box::new(LoopbackTrackedStream {
            inner: stream,
            _connection: detector.track_connection(local_addr),
        }),
        Some(local_addr),
        remote_addr,
    )
}

pub struct LoopbackTrackedDatagram {
    inner: Box<dyn AsyncDatagram>,
    connection: Mutex<Option<crate::loopback::TrackedConnection>>,
}

impl AsyncDatagram for LoopbackTrackedDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        self.inner.send_to(payload, target)
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        self.inner.recv_from(buffer)
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.inner.local_addr()
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let result = self.inner.close().await;
            self.connection
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            result
        })
    }
}

pub fn track_datagram(
    detector: &LoopbackDetector,
    datagram: Box<dyn AsyncDatagram>,
) -> Box<dyn AsyncDatagram> {
    let connection = datagram
        .local_addr()
        .ok()
        .and_then(|endpoint| endpoint.addr())
        .map(|local_addr| detector.track_connection(local_addr));
    Box::new(LoopbackTrackedDatagram {
        inner: datagram,
        connection: Mutex::new(connection),
    })
}

/// Go route tags resolve to a node set. Keep the set at the common async
/// proxy boundary so TCP, UDP and stateful protocol chains share the same
/// retry behavior. A failed member is tried before the set reports the
/// connection failure to the inbound.
pub struct NodeSetProxy {
    members: Vec<Arc<dyn AsyncProxy>>,
    cursor: AtomicUsize,
    round_robin: bool,
}

impl NodeSetProxy {
    pub(super) fn new(members: Vec<Arc<dyn AsyncProxy>>, round_robin: bool) -> Result<Self> {
        if members.is_empty() {
            return Err(Error::invalid("node tag has no usable members"));
        }
        Ok(Self {
            members,
            cursor: AtomicUsize::new(0),
            round_robin,
        })
    }

    fn ordered_members(&self) -> Vec<Arc<dyn AsyncProxy>> {
        let length = self.members.len();
        let ticket = self.cursor.fetch_add(1, Ordering::Relaxed);
        // Go defaults to a random set strategy. A cheap deterministic
        // permutation spreads new flows without adding a runtime RNG to this
        // hot path; explicit round_robin keeps strict order.
        let start = if self.round_robin {
            ticket % length
        } else {
            ticket
                .wrapping_mul(0x9e37_79b9_7f4a_7c15u64 as usize)
                .wrapping_add(0x243f_6a88_85a3_08d3u64 as usize)
                % length
        };
        (0..length)
            .map(|offset| Arc::clone(&self.members[(start + offset) % length]))
            .collect()
    }
}

impl AsyncProxy for NodeSetProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let members = self.ordered_members();
        let context = context.clone();
        Box::pin(async move {
            let mut last_error = None;
            for member in members {
                match member.connect(&context).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| Error::invalid("node tag proxy failed")))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let members = self.ordered_members();
        let context = context.clone();
        Box::pin(async move {
            let mut last_error = None;
            for member in members {
                match member.open_datagram(&context).await {
                    Ok(datagram) => return Ok(datagram),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| Error::invalid("node tag datagram failed")))
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        let members = self.ordered_members();
        let context = context.clone();
        Box::pin(async move {
            let mut last_error = None;
            for member in members {
                match member.ping(&context).await {
                    Ok(duration) => return Ok(duration),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| Error::invalid("node tag ping failed")))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let mut last_error = None;
            for member in &self.members {
                if let Err(error) = member.close().await {
                    last_error = Some(error);
                }
            }
            last_error.map_or(Ok(()), Err)
        })
    }
}

pub fn track_tagged_proxies(
    proxies: BTreeMap<String, Arc<dyn AsyncProxy>>,
    detector: &LoopbackDetector,
) -> BTreeMap<String, Arc<dyn AsyncProxy>> {
    proxies
        .into_iter()
        .map(|(tag, proxy)| {
            (
                tag,
                Arc::new(LoopbackTrackingProxy {
                    inner: proxy,
                    detector: detector.clone(),
                }) as Arc<dyn AsyncProxy>,
            )
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct NodeTagDefinition {
    pub(super) kind: String,
    pub(super) targets: Vec<String>,
    pub(super) round_robin: bool,
}

pub fn parse_node_tag(record: &doradus_store::GoNodeTagRecord) -> Result<NodeTagDefinition> {
    let value: serde_json::Value =
        serde_json::from_slice(&record.members_json).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("invalid node tag {:?} JSON: {error}", record.name),
            )
        })?;
    let object = value.as_object().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("node tag {:?} must be a JSON object", record.name),
        )
    })?;
    let kind = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .filter(|kind| !kind.trim().is_empty())
        .unwrap_or("node")
        .to_ascii_lowercase();
    if kind != "node" && kind != "mirror" {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("unknown node tag {:?} type {kind:?}", record.name),
        ));
    }
    let targets = match object.get("hash") {
        Some(serde_json::Value::Array(values)) => values
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|target| !target.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(serde_json::Value::String(value)) if !value.trim().is_empty() => {
            vec![value.trim().to_owned()]
        }
        Some(_) => {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("node tag {:?} hash must be a string or array", record.name),
            ));
        }
        None => Vec::new(),
    };
    let strategy = object
        .get("strategy")
        .or_else(|| object.get("mode"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    Ok(NodeTagDefinition {
        kind,
        targets,
        round_robin: strategy.eq_ignore_ascii_case("round_robin")
            || strategy.eq_ignore_ascii_case("round-robin")
            || strategy.eq_ignore_ascii_case("roundrobin"),
    })
}

pub fn resolve_node_tag_targets(
    tag: &str,
    definitions: &BTreeMap<String, NodeTagDefinition>,
    visiting: &mut BTreeSet<String>,
) -> Vec<String> {
    let Some(definition) = definitions.get(tag) else {
        return Vec::new();
    };
    if !visiting.insert(tag.to_owned()) {
        return Vec::new();
    }
    let targets = if definition.kind == "mirror" {
        definition
            .targets
            .first()
            .map(|target| resolve_node_tag_targets(target, definitions, visiting))
            .unwrap_or_default()
    } else {
        definition.targets.clone()
    };
    visiting.remove(tag);
    targets
}

pub fn track_selector(
    selector: RuntimeRoutedProxySelector,
    detector: &LoopbackDetector,
) -> RuntimeRoutedProxySelector {
    let wrap = |inner: Arc<dyn AsyncProxy>| {
        Arc::new(LoopbackTrackingProxy {
            inner,
            detector: detector.clone(),
        }) as Arc<dyn AsyncProxy>
    };
    RuntimeRoutedProxySelector {
        router: selector.router,
        direct: wrap(selector.direct),
        proxy: wrap(selector.proxy),
        bypass: wrap(selector.bypass),
        drop: wrap(selector.drop),
    }
}

impl AsyncProxy for LoopbackTrackingProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let stream = self.inner.connect(context).await?;
            Ok(track_stream(&self.detector, stream))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            let datagram = self.inner.open_datagram(context).await?;
            Ok(track_datagram(&self.detector, datagram))
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        self.inner.ping(context)
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

#[cfg(feature = "http-termination")]
#[path = "outbound_layers/http_termination.rs"]
pub(crate) mod http_termination;

/// The selected runtime proxy plus its persisted public configuration.
/// Keeping both together makes future HTTP handlers able to expose stable
/// metadata without reconstructing or serializing protocol internals.
pub struct ProxyBuild {
    pub config: GoProxyRuntimeConfig,
    pub proxy: Arc<dyn AsyncProxy>,
}

/// Resolve final domain destinations once per accepted flow before a direct
/// socket is opened. The context still carries the domain, so protocol layers
/// such as TLS, HTTP/2 and Yuubinsya preserve their domain/SNI semantics; only
/// the direct transport reads `FlowContext::proxy_destination`.
pub struct ResolvingProxy {
    inner: Arc<dyn AsyncProxy>,
    direct_resolver: Arc<dyn AsyncIpResolver>,
    proxy_resolver: Arc<dyn AsyncIpResolver>,
}

impl ResolvingProxy {
    pub(super) fn new(inner: Arc<dyn AsyncProxy>, resolver: Arc<dyn AsyncIpResolver>) -> Self {
        Self {
            inner,
            direct_resolver: Arc::clone(&resolver),
            proxy_resolver: resolver,
        }
    }

    pub(super) fn with_route_resolvers(
        inner: Arc<dyn AsyncProxy>,
        direct_resolver: Arc<dyn AsyncIpResolver>,
        proxy_resolver: Arc<dyn AsyncIpResolver>,
    ) -> Self {
        Self {
            inner,
            direct_resolver,
            proxy_resolver,
        }
    }

    fn resolve_context<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<FlowContext>> {
        let mut resolved = context.clone();
        if resolved.skip_resolve {
            return Box::pin(async move { Ok(resolved) });
        }
        let destination = resolved.effective_destination();
        let Endpoint::Domain {
            network,
            host,
            port,
        } = destination
        else {
            return Box::pin(async move { Ok(resolved) });
        };
        let resolver = match context.route_mode {
            RouteMode::Proxy => Arc::clone(&self.proxy_resolver),
            RouteMode::Direct | RouteMode::Bypass | RouteMode::Block => {
                Arc::clone(&self.direct_resolver)
            }
        };
        let strategy = resolved.resolver_policy.strategy;
        Box::pin(async move {
            let addresses = resolver.resolve(&host, strategy).await?;
            let address = select_resolved_address(&addresses, strategy).ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("resolver returned no usable address for {host}"),
                )
            })?;
            resolved.resolved_destination =
                Some(Endpoint::ip(network, SocketAddr::new(address, port)));
            Ok(resolved)
        })
    }
}

impl AsyncProxy for ResolvingProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let context = self.resolve_context(context).await?;
            inner.connect(&context).await
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let context = self.resolve_context(context).await?;
            inner.open_datagram(&context).await
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let context = self.resolve_context(context).await?;
            inner.ping(&context).await
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

pub fn select_resolved_address(
    addresses: &IpSet,
    strategy: ResolveStrategy,
) -> Option<std::net::IpAddr> {
    match strategy {
        ResolveStrategy::OnlyIpv6 | ResolveStrategy::PreferIpv6 => addresses
            .v6
            .first()
            .copied()
            .map(std::net::IpAddr::V6)
            .or_else(|| addresses.v4.first().copied().map(std::net::IpAddr::V4)),
        ResolveStrategy::OnlyIpv4 | ResolveStrategy::PreferIpv4 | ResolveStrategy::Default => {
            addresses
                .v4
                .first()
                .copied()
                .map(std::net::IpAddr::V4)
                .or_else(|| addresses.v6.first().copied().map(std::net::IpAddr::V6))
        }
    }
}
