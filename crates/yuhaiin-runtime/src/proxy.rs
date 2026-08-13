//! Proxy construction from the shared runtime snapshot.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use yuhaiin_chain::ChainProxy;
use yuhaiin_core::dns_resolver_async::AsyncIpResolver;
use yuhaiin_core::proxy::{
    AsyncDatagram, AsyncProxy, AsyncProxySelector, BoxAsyncStream, DelayedDropAsyncProxy,
    DirectAsyncProxy, DropAsyncProxy, YuubinsyaUdpDatagram, stream_local_addr,
    with_stream_local_addr,
};
use yuhaiin_core::proxy_factory::{BaseProxyConfig, BaseProxyKind};
use yuhaiin_core::{
    BoxFuture, Endpoint, Error, ErrorKind, FlowContext, GeoLookup, IpSet, ResolveStrategy, Result,
};
use yuhaiin_store::{GoProxyLayer, GoProxyRuntimeConfig, GoProxyTransport};
use yuhaiin_trie::router::RuntimeRoutedProxySelector;

use crate::RuntimeSnapshot;
use crate::loopback::LoopbackDetector;
use crate::route::RouteListSnapshot;

/// Go's `network_split` point keeps one already-built parent proxy and
/// selects an independent wrapper for TCP and UDP.  The selection happens at
/// the common async boundary so every inbound (including TUN) gets the same
/// semantics.
struct NetworkSplitProxy {
    tcp: Arc<dyn AsyncProxy>,
    udp: Arc<dyn AsyncProxy>,
    parent: Arc<dyn AsyncProxy>,
}

#[cfg(feature = "doh-tls")]
struct TlsTerminationProxy {
    upstream: Arc<dyn AsyncProxy>,
    acceptor: tokio_rustls::TlsAcceptor,
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
/// chains use `yuhaiin-chain::ChainProxy`; this adapter is for the Go point
/// contract where the branch wraps an already-built parent stream.
struct NetworkSplitYuubinsyaProxy {
    upstream: Arc<dyn AsyncProxy>,
    password_hash: [u8; 32],
    udp_over_stream: bool,
    udp_coalesce: bool,
    udp_server: Option<Endpoint>,
}

/// Go's HTTP/2 contract wraps the already-built parent proxy and uses that
/// proxy only as the dialer for plaintext prior-knowledge HTTP/2.  Its UDP
/// method is inherited from the parent, so this adapter deliberately applies
/// HTTP/2 only to TCP streams as well.
struct NetworkSplitHttp2Proxy {
    upstream: Arc<dyn AsyncProxy>,
    connections: tokio::sync::Mutex<Vec<Arc<yuhaiin_chain::H2Connection>>>,
    concurrency: usize,
    max_streams: usize,
}

impl NetworkSplitHttp2Proxy {
    async fn connect_stream(
        &self,
        context: &FlowContext,
    ) -> Result<(tokio::io::DuplexStream, Option<SocketAddr>)> {
        let mut connections = self.connections.lock().await;
        connections.retain(|connection| !connection.is_closed());

        for connection in connections.iter() {
            if connection.at_capacity() {
                continue;
            }
            match connection
                .open_connect_stream_with_local_addr(self.concurrency)
                .await
            {
                Ok(stream) => return Ok(stream),
                Err(_) if connection.is_closed() => continue,
                Err(error) => return Err(error),
            }
        }

        let upstream = self.upstream.connect(context).await?;
        let local_addr = stream_local_addr(&*upstream);
        let connection = yuhaiin_chain::H2Connection::handshake_with_limits_and_local_addr(
            upstream,
            self.max_streams,
            local_addr,
        )
        .await?;
        let stream = connection
            .open_connect_stream_with_local_addr(self.concurrency)
            .await?;
        connections.push(connection);
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
        let connections = &self.connections;
        Box::pin(async move {
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
            let session = yuhaiin_chain::AsyncYuubinsyaTcpSession::connect(
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
                let session = yuhaiin_chain::AsyncYuubinsyaUotSession::connect(
                    stream,
                    self.password_hash,
                    context.udp_migrate_id.load(Ordering::Acquire),
                    self.udp_coalesce,
                )
                .await?;
                context
                    .udp_migrate_id
                    .store(session.migrate_id, Ordering::Release);
                let local_addr = stream_local_addr(session.transport());
                return Ok(Box::new(NetworkSplitYuubinsyaUotDatagram {
                    session: tokio::sync::Mutex::new(Some(session)),
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

struct NetworkSplitYuubinsyaUotDatagram {
    session: tokio::sync::Mutex<Option<yuhaiin_chain::AsyncYuubinsyaUotSession<BoxAsyncStream>>>,
    local_addr: Option<SocketAddr>,
}

impl AsyncDatagram for NetworkSplitYuubinsyaUotDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let mut session = self.session.lock().await;
            let session = session
                .as_mut()
                .ok_or_else(|| Error::new(ErrorKind::Closed, "Yuubinsya UDP session is closed"))?;
            session.send_to(&target, payload).await?;
            Ok(payload.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            let mut session = self.session.lock().await;
            let session = session
                .as_mut()
                .ok_or_else(|| Error::new(ErrorKind::Closed, "Yuubinsya UDP session is closed"))?;
            let (target, payload) = session.recv_from().await?;
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
            yuhaiin_core::Network::Udp,
            self.local_addr
                .unwrap_or_else(|| "0.0.0.0:0".parse().expect("valid wildcard endpoint")),
        ))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let session = self.session.lock().await.take();
            if let Some(mut session) = session {
                session.shutdown().await?;
            }
            Ok(())
        })
    }
}

/// Keep a selected outbound proxy's socket in the loopback registry for the
/// exact lifetime of the returned stream. Protocol layers may replace the
/// concrete stream type, so the core transport carries the local endpoint as
/// optional metadata and this adapter owns the runtime-only guard.
struct LoopbackTrackingProxy {
    inner: Arc<dyn AsyncProxy>,
    detector: LoopbackDetector,
}

struct LoopbackTrackedStream {
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

fn track_stream(detector: &LoopbackDetector, stream: BoxAsyncStream) -> BoxAsyncStream {
    let Some(local_addr) = stream_local_addr(&*stream) else {
        return stream;
    };
    with_stream_local_addr(
        Box::new(LoopbackTrackedStream {
            inner: stream,
            _connection: detector.track_connection(local_addr),
        }),
        Some(local_addr),
    )
}

struct LoopbackTrackedDatagram {
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

fn track_datagram(
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
struct NodeSetProxy {
    members: Vec<Arc<dyn AsyncProxy>>,
    cursor: AtomicUsize,
    round_robin: bool,
}

impl NodeSetProxy {
    fn new(members: Vec<Arc<dyn AsyncProxy>>, round_robin: bool) -> Result<Self> {
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

fn track_tagged_proxies(
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
struct NodeTagDefinition {
    kind: String,
    targets: Vec<String>,
    round_robin: bool,
}

fn parse_node_tag(record: &yuhaiin_store::GoNodeTagRecord) -> Result<NodeTagDefinition> {
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

fn resolve_node_tag_targets(
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

fn track_selector(
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

#[path = "proxy/common.rs"]
pub(crate) mod common;
#[path = "proxy/http.rs"]
pub(crate) mod http;
#[cfg(feature = "http-termination")]
#[path = "proxy/http_termination.rs"]
pub(crate) mod http_termination;
#[path = "proxy/reverse.rs"]
pub(crate) mod reverse;
#[path = "proxy/socks4a.rs"]
pub(crate) mod socks4a;
#[cfg(target_os = "linux")]
#[path = "proxy/transparent.rs"]
pub(crate) mod transparent;
#[path = "proxy/trojan.rs"]
pub(crate) mod trojan;
#[path = "proxy/vless.rs"]
pub(crate) mod vless;
#[cfg(feature = "websocket")]
#[path = "proxy/websocket.rs"]
pub(crate) mod websocket;
#[path = "proxy/yuubinsya.rs"]
pub(crate) mod yuubinsya;

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
struct ResolvingProxy {
    inner: Arc<dyn AsyncProxy>,
    resolver: Arc<dyn AsyncIpResolver>,
}

impl ResolvingProxy {
    fn new(inner: Arc<dyn AsyncProxy>, resolver: Arc<dyn AsyncIpResolver>) -> Self {
        Self { inner, resolver }
    }

    fn resolve_context<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<FlowContext>> {
        let mut resolved = context.clone();
        let destination = resolved.effective_destination();
        let Endpoint::Domain {
            network,
            host,
            port,
        } = destination
        else {
            return Box::pin(async move { Ok(resolved) });
        };
        let resolver = Arc::clone(&self.resolver);
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

fn select_resolved_address(
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

impl RuntimeSnapshot {
    async fn build_network_split_proxy(
        &self,
        config: &GoProxyRuntimeConfig,
        timeout: Duration,
    ) -> Result<Arc<dyn AsyncProxy>> {
        let (split_index, split) = config
            .layers
            .iter()
            .enumerate()
            .find(|(_, layer)| layer.kind.eq_ignore_ascii_case("network_split"))
            .ok_or_else(|| Error::invalid("network_split protocol layer is missing"))?;
        let object = split
            .config
            .as_object()
            .ok_or_else(|| Error::invalid("network_split configuration must be an object"))?;
        let tcp = network_split_branch(object.get("tcp"))?;
        let udp = network_split_branch(object.get("udp"))?;
        if tcp.is_none() && udp.is_none() {
            return Err(Error::invalid("network_split protocols are empty"));
        }

        let parent_config = config.chain_prefix(split_index)?;
        let parent = if split_index == 0 {
            let proxy: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy { timeout });
            self.resolve_proxy(proxy)
        } else {
            let mut parent_snapshot = self.clone();
            parent_snapshot.proxies = vec![parent_config.clone()];
            Box::pin(parent_snapshot.build_proxy(&parent_config.id, timeout))
                .await?
                .proxy
        };
        let udp_server = parent_config
            .resolved_fixed_endpoint(self.resolver.as_ref())
            .await?
            .map(|address| Endpoint::ip(yuhaiin_core::Network::Udp, address));
        let tcp = match tcp {
            Some(layer) => {
                self.build_network_split_branch(
                    &layer,
                    Arc::clone(&parent),
                    timeout,
                    udp_server.clone(),
                )
                .await?
            }
            None => Arc::clone(&parent),
        };
        let udp = match udp {
            Some(layer) => {
                self.build_network_split_branch(&layer, Arc::clone(&parent), timeout, udp_server)
                    .await?
            }
            None => Arc::clone(&parent),
        };
        Ok(Arc::new(NetworkSplitProxy { tcp, udp, parent }))
    }

    async fn build_network_split_branch(
        &self,
        layer: &GoProxyLayer,
        parent: Arc<dyn AsyncProxy>,
        timeout: Duration,
        udp_server: Option<Endpoint>,
    ) -> Result<Arc<dyn AsyncProxy>> {
        let kind = layer.kind.to_ascii_lowercase();
        match kind.as_str() {
            // Go registers `none` and `proxy` as parent-preserving no-op
            // wrappers. Neither may replace the already-built prefix with a
            // fresh direct socket.
            "none" | "proxy" => Ok(parent),
            "direct" => {
                let child = GoProxyRuntimeConfig::single_layer(layer, GoProxyTransport::Direct);
                let proxy: Arc<dyn AsyncProxy> = Arc::new(DirectAsyncProxy { timeout });
                let proxy = Arc::new(SocketPolicyProxy {
                    inner: proxy,
                    bind_addresses: self.socket_bind_addresses.clone(),
                    bind_interface: child.network_interface(),
                }) as Arc<dyn AsyncProxy>;
                Ok(self.resolve_proxy(proxy))
            }
            "reject" | "block" => Ok(Arc::new(DropAsyncProxy)),
            "drop" => Ok(Arc::new(DelayedDropAsyncProxy::new())),
            "fixed" | "simple" | "fixedv2" => {
                let child = GoProxyRuntimeConfig::single_layer(layer, GoProxyTransport::Fixed);
                Ok(child
                    .to_base_proxy_config_with_resolver(timeout, self.resolver.clone())
                    .await?
                    .build()?)
            }
            "http" | "http_proxy" => {
                let user = layer_string(layer, "user").unwrap_or_default();
                let password = layer_string(layer, "password").unwrap_or_default();
                Ok(Arc::new(yuhaiin_protocol::http::HttpProxy::new(
                    parent, user, password,
                )))
            }
            "socks5" => {
                let user = layer_string(layer, "user").unwrap_or_default();
                let password = layer_string(layer, "password").unwrap_or_default();
                let hostname = layer_string(layer, "hostname").unwrap_or_default();
                let override_port = layer
                    .config
                    .get("override_port")
                    .or_else(|| layer.config.get("overridePort"))
                    .and_then(serde_json::Value::as_i64)
                    .unwrap_or(0);
                let override_port = i32::try_from(override_port)
                    .map_err(|_| Error::invalid("SOCKS5 override_port is out of range"))?;
                Ok(Arc::new(yuhaiin_protocol::socks5::Socks5Proxy::new(
                    parent,
                    user,
                    password,
                    hostname,
                    override_port,
                )?))
            }
            "http_mock" => Ok(Arc::new(yuhaiin_protocol::http_mock::HttpMockProxy::new(
                parent,
            ))),
            "tls" => {
                let child = GoProxyRuntimeConfig::single_layer(layer, GoProxyTransport::Tls);
                #[cfg(feature = "doh-tls")]
                {
                    build_protocol_tls_proxy(&child, parent)
                }
                #[cfg(not(feature = "doh-tls"))]
                {
                    let _ = child;
                    Err(Error::new(
                        ErrorKind::Unsupported,
                        "network_split TLS branch requires the doh-tls feature",
                    ))
                }
            }
            "websocket" => {
                let child = GoProxyRuntimeConfig::single_layer(
                    layer,
                    GoProxyTransport::Unknown {
                        name: "websocket".to_owned(),
                    },
                );
                build_protocol_websocket_proxy(&child, parent)
            }
            "shadowsocks" | "shadowsocksr" | "trojan" | "vless" | "vmess" => {
                let transport = match kind.as_str() {
                    "shadowsocks" => GoProxyTransport::Shadowsocks,
                    "shadowsocksr" => GoProxyTransport::Shadowsocksr,
                    "trojan" => GoProxyTransport::Trojan,
                    "vless" => GoProxyTransport::Vless,
                    "vmess" => GoProxyTransport::Vmess,
                    _ => unreachable!(),
                };
                let child = GoProxyRuntimeConfig::single_layer(layer, transport);
                build_protocol_proxy(&child, parent)
            }
            "aead" => {
                let password = layer_string(layer, "password")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| Error::invalid("AEAD password is empty"))?;
                let method = layer
                    .config
                    .get("cryptoMethod")
                    .or_else(|| layer.config.get("crypto_method"))
                    .and_then(serde_json::Value::as_str)
                    .map(yuhaiin_protocol::aead::CryptoMethod::parse)
                    .unwrap_or(yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305);
                Ok(Arc::new(yuhaiin_protocol::aead::AeadProxy::new(
                    parent, password, method, None,
                )))
            }
            "yuubinsya" => {
                let password = layer_string(layer, "password")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| Error::invalid("Yuubinsya password is empty"))?;
                Ok(Arc::new(NetworkSplitYuubinsyaProxy {
                    upstream: parent,
                    password_hash: yuhaiin_core::yuubinsya::derive_salt(password.as_bytes()),
                    udp_over_stream: layer_bool(layer, "udp_over_stream", "udpOverStream"),
                    udp_coalesce: layer_bool(layer, "udp_coalesce", "udpCoalesce"),
                    udp_server,
                }))
            }
            // Go's bootstrap_dns_warp point currently only embeds and returns
            // its parent proxy. Keep that no-op behavior instead of treating
            // it as an unknown protocol or accidentally replacing the parent
            // with a direct socket.
            "bootstrap_dns_warp" | "bootstrapdnswarp" => Ok(parent),
            "http2" => {
                let concurrency = layer
                    .config
                    .get("concurrency")
                    .or_else(|| layer.config.get("max_concurrency"))
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .filter(|value| *value >= 7)
                    .unwrap_or(10);
                let max_streams = layer
                    .config
                    .get("max_streams")
                    .or_else(|| layer.config.get("maxStreams"))
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or(128)
                    .max(1);
                Ok(Arc::new(NetworkSplitHttp2Proxy {
                    upstream: parent,
                    connections: tokio::sync::Mutex::new(Vec::new()),
                    concurrency,
                    max_streams,
                }))
            }
            "wireguard" | "wire_guard" | "wg" => {
                let child = GoProxyRuntimeConfig::single_layer(layer, GoProxyTransport::Wireguard);
                build_wireguard_proxy(
                    layer,
                    timeout,
                    self.resolver.clone(),
                    child.network_interface(),
                )
                .await
            }
            "network_split" | "networksplit" => {
                Err(Error::invalid("nested network_split is not supported"))
            }
            other => Err(Error::new(
                ErrorKind::Unsupported,
                format!("network_split branch protocol {other:?} is not supported"),
            )),
        }
    }

    pub async fn build_proxy(&self, id: &str, timeout: Duration) -> Result<ProxyBuild> {
        let config = self.require_proxy_config(id)?.clone();
        self.build_proxy_config(config, timeout).await
    }

    async fn build_proxy_config(
        &self,
        config: GoProxyRuntimeConfig,
        timeout: Duration,
    ) -> Result<ProxyBuild> {
        self.build_proxy_config_with_tls_marker(config, timeout, false)
            .await
    }

    async fn build_proxy_config_with_tls_marker(
        &self,
        config: GoProxyRuntimeConfig,
        timeout: Duration,
        tls_terminated: bool,
    ) -> Result<ProxyBuild> {
        if !config.enabled {
            return Err(Error::new(
                ErrorKind::Closed,
                format!("proxy runtime config {:?} is disabled", config.id),
            ));
        }

        let proxy = if config.transport == yuhaiin_store::GoProxyTransport::NetworkSplit {
            self.build_network_split_proxy(&config, timeout).await?
        } else if is_protocol_h2_config(&config) {
            build_protocol_h2_proxy(&config, timeout, self.resolver.clone()).await?
        } else if is_vless_websocket_config(&config) {
            build_vless_transport_proxy(&config, timeout, self.resolver.clone()).await?
        } else if is_vmess_transport_config(&config) {
            build_vmess_transport_proxy(&config, timeout, self.resolver.clone()).await?
        } else if is_trojan_websocket_config(&config) {
            build_trojan_transport_proxy(&config, timeout, self.resolver.clone()).await?
        } else if config.transport == yuhaiin_store::GoProxyTransport::Wireguard {
            let layer = config
                .layers
                .iter()
                .find(|layer| layer.kind.eq_ignore_ascii_case("wireguard"))
                .ok_or_else(|| Error::invalid("WireGuard protocol layer is missing"))?;
            build_wireguard_proxy(
                layer,
                timeout,
                self.resolver.clone(),
                config.network_interface(),
            )
            .await?
        } else if config.transport == yuhaiin_store::GoProxyTransport::HttpMock {
            let base = config
                .to_base_proxy_config_with_resolver(timeout, self.resolver.clone())
                .await?;
            Arc::new(yuhaiin_protocol::http_mock::HttpMockProxy::new(
                base.build()?,
            )) as Arc<dyn AsyncProxy>
        } else if config.transport == yuhaiin_store::GoProxyTransport::HttpTermination {
            let index = config
                .layers
                .iter()
                .rposition(|layer| layer.kind.eq_ignore_ascii_case("http_termination"))
                .ok_or_else(|| Error::invalid("HTTP termination layer is missing"))?;
            let parent = if index == 0 {
                self.resolve_proxy(Arc::new(DirectAsyncProxy { timeout }))
            } else {
                Box::pin(self.build_proxy_config(config.chain_prefix(index)?, timeout))
                    .await?
                    .proxy
            };
            #[cfg(feature = "http-termination")]
            {
                crate::proxy::http_termination::build(&config, parent, tls_terminated)?
            }
            #[cfg(not(feature = "http-termination"))]
            {
                let _ = parent;
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "HTTP termination requires the http-termination feature",
                ));
            }
        } else if config.transport == yuhaiin_store::GoProxyTransport::TlsTermination {
            let index = config
                .layers
                .iter()
                .rposition(|layer| layer.kind.eq_ignore_ascii_case("tls_termination"))
                .ok_or_else(|| Error::invalid("TLS termination layer is missing"))?;
            // The Go TLS unwrap point marks its parent HTTP-termination
            // connection before putting the TLS server on top. Propagate that
            // per-chain fact into the recursive prefix build so the reverse
            // proxy can choose the same upstream wire mode.
            let parent = if index == 0 {
                self.resolve_proxy(Arc::new(DirectAsyncProxy { timeout }))
            } else {
                Box::pin(self.build_proxy_config_with_tls_marker(
                    config.chain_prefix(index)?,
                    timeout,
                    true,
                ))
                .await?
                .proxy
            };
            #[cfg(feature = "doh-tls")]
            {
                build_tls_termination_proxy(&config, parent)?
            }
            #[cfg(not(feature = "doh-tls"))]
            {
                let _ = parent;
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "TLS termination requires the doh-tls feature",
                ));
            }
        } else if is_chain_config(&config) {
            let json = std::str::from_utf8(&config.data_json).map_err(|error| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("proxy {:?} data_json is not UTF-8: {error}", config.id),
                )
            })?;
            Arc::new(ChainProxy::from_go_json_with_resolver(
                json,
                self.resolver.clone(),
            )?) as Arc<dyn AsyncProxy>
        } else if config.transport == yuhaiin_store::GoProxyTransport::Aead {
            build_aead_proxy(&config, timeout, self.resolver.clone()).await?
        } else if matches!(
            config.transport,
            yuhaiin_store::GoProxyTransport::Shadowsocks
                | yuhaiin_store::GoProxyTransport::Shadowsocksr
                | yuhaiin_store::GoProxyTransport::Trojan
                | yuhaiin_store::GoProxyTransport::Vless
                | yuhaiin_store::GoProxyTransport::Vmess
        ) {
            let base = config
                .to_base_proxy_config_with_resolver(timeout, self.resolver.clone())
                .await?;
            let mut upstream = base.build()?;
            if config
                .chain_types
                .iter()
                .any(|kind| kind.eq_ignore_ascii_case("tls"))
            {
                #[cfg(feature = "doh-tls")]
                {
                    upstream = build_protocol_tls_proxy(&config, upstream)?;
                }
                #[cfg(not(feature = "doh-tls"))]
                {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "protocol TLS requires the doh-tls feature",
                    ));
                }
            }
            let layer = config
                .layers
                .iter()
                .find(|layer| {
                    layer.kind.eq_ignore_ascii_case(match config.transport {
                        yuhaiin_store::GoProxyTransport::Shadowsocks => "shadowsocks",
                        yuhaiin_store::GoProxyTransport::Shadowsocksr => "shadowsocksr",
                        yuhaiin_store::GoProxyTransport::Trojan => "trojan",
                        yuhaiin_store::GoProxyTransport::Vless => "vless",
                        yuhaiin_store::GoProxyTransport::Vmess => "vmess",
                        _ => unreachable!(),
                    })
                })
                .ok_or_else(|| Error::invalid("proxy protocol layer is missing"))?;
            if config
                .layers
                .iter()
                .any(|layer| layer.kind.eq_ignore_ascii_case("obfs_http"))
            {
                if config.transport != yuhaiin_store::GoProxyTransport::Shadowsocks {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "obfs_http is only supported around the Go Shadowsocks protocol",
                    ));
                }
                let obfs = config
                    .layers
                    .iter()
                    .find(|layer| layer.kind.eq_ignore_ascii_case("obfs_http"))
                    .expect("obfs_http layer was checked above");
                let host = obfs
                    .config
                    .get("host")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| Error::invalid("obfs_http host is missing"))?;
                let port = obfs
                    .config
                    .get("port")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| Error::invalid("obfs_http port is missing"))?;
                upstream = Arc::new(yuhaiin_protocol::http_obfs::HttpObfsProxy::new(
                    upstream, host, port,
                )?);
            }
            match config.transport {
                yuhaiin_store::GoProxyTransport::Shadowsocks => {
                    let password = layer
                        .config
                        .get("password")
                        .and_then(serde_json::Value::as_str)
                        .filter(|password| !password.is_empty())
                        .ok_or_else(|| Error::invalid("proxy protocol password is empty"))?;
                    let method = layer
                        .config
                        .get("method")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| Error::invalid("Shadowsocks method is missing"))?;
                    Arc::new(yuhaiin_protocol::shadowsocks::ShadowsocksProxy::new(
                        upstream, method, password,
                    )?) as Arc<dyn AsyncProxy>
                }
                yuhaiin_store::GoProxyTransport::Shadowsocksr => {
                    let password = layer
                        .config
                        .get("password")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    let method = layer
                        .config
                        .get("method")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("chacha20-ietf");
                    let protocol = layer
                        .config
                        .get("protocol")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("origin");
                    let protocol_param = layer
                        .config
                        .get("protoparam")
                        .or_else(|| layer.config.get("protocol_param"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    let obfs = layer
                        .config
                        .get("obfs")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("plain");
                    let obfs_param = layer
                        .config
                        .get("obfsparam")
                        .or_else(|| layer.config.get("obfs_param"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    Arc::new(yuhaiin_protocol::shadowsocksr::ShadowsocksrProxy::new(
                        upstream,
                        method,
                        password,
                        protocol,
                        protocol_param,
                        obfs,
                        obfs_param,
                    )?) as Arc<dyn AsyncProxy>
                }
                yuhaiin_store::GoProxyTransport::Trojan => {
                    let password = layer
                        .config
                        .get("password")
                        .and_then(serde_json::Value::as_str)
                        .filter(|password| !password.is_empty())
                        .ok_or_else(|| Error::invalid("proxy protocol password is empty"))?;
                    Arc::new(yuhaiin_protocol::trojan::TrojanProxy::new(
                        upstream, password,
                    )) as Arc<dyn AsyncProxy>
                }
                yuhaiin_store::GoProxyTransport::Vless => {
                    let uuid = layer
                        .config
                        .get("uuid")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| Error::invalid("VLESS UUID is missing"))?;
                    Arc::new(yuhaiin_protocol::vless::VlessProxy::new(upstream, uuid)?)
                        as Arc<dyn AsyncProxy>
                }
                yuhaiin_store::GoProxyTransport::Vmess => {
                    let uuid = layer
                        .config
                        .get("id")
                        .or_else(|| layer.config.get("uuid"))
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| Error::invalid("VMess UUID is missing"))?;
                    let security = layer
                        .config
                        .get("security")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("auto");
                    let alter_id = vmess_alter_id(&layer.config)?;
                    Arc::new(yuhaiin_protocol::vmess::VmessProxy::new(
                        upstream, uuid, security, alter_id,
                    )?) as Arc<dyn AsyncProxy>
                }
                _ => unreachable!("protocol branch validated above"),
            }
        } else {
            let base = config
                .to_base_proxy_config_with_resolver(timeout, self.resolver.clone())
                .await?;
            base.build()?
        };

        let proxy = Arc::new(ConnectBudgetProxy {
            inner: Arc::new(SocketPolicyProxy {
                inner: proxy,
                bind_addresses: self.socket_bind_addresses.clone(),
                bind_interface: config.network_interface(),
            }),
            semaphore: self.connect_semaphore.clone(),
        }) as Arc<dyn AsyncProxy>;
        let proxy = if matches!(
            config.transport,
            yuhaiin_store::GoProxyTransport::Direct | yuhaiin_store::GoProxyTransport::Wireguard
        ) {
            // Direct and the userspace WireGuard stack both require an IP
            // endpoint before opening their final socket. Keep their lookup
            // on the runtime resolver boundary so route resolver policy,
            // hosts and FakeIP are not silently replaced by getaddrinfo.
            self.resolve_proxy(proxy)
        } else {
            proxy
        };
        Ok(ProxyBuild {
            config,
            // `build_proxy` is also used by management operations such as
            // node latency and route-list refresh, which do not pass through
            // the routed selector. Direct is the one final transport that
            // requires an IP; HTTP/SOCKS5/protocol chains must retain the
            // original domain for their wire framing and proxy-side DNS.
            proxy,
        })
    }

    pub async fn build_proxy_for_management(
        &self,
        id: &str,
        timeout: Duration,
    ) -> Result<Arc<dyn AsyncProxy>> {
        self.build_proxy_slot(id, timeout, BaseProxyKind::Direct)
            .await
    }

    /// Build the four proxy slots consumed by the TUN dispatcher.
    ///
    /// The persisted records are reused directly; the method only assembles
    /// the already existing proxy implementations into the routing adapter.
    /// Empty IDs use safe built-ins. The internal `direct` sentinel is also
    /// accepted for the selected-node fallback, but unknown non-empty proxy
    /// IDs remain errors so a missing configured node cannot leak traffic.
    pub async fn build_proxy_selector(
        &self,
        direct_id: &str,
        proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: Duration,
    ) -> Result<RuntimeProxySelector> {
        self.build_proxy_selector_with_udp(
            direct_id, proxy_id, proxy_id, bypass_id, drop_id, timeout,
        )
        .await
    }

    /// Build a selector with Go-compatible independent TCP and UDP selected
    /// nodes. Existing callers that only provide one node intentionally use
    /// [`Self::build_proxy_selector`] and retain the same node for both
    /// networks.
    pub async fn build_proxy_selector_with_udp(
        &self,
        direct_id: &str,
        tcp_proxy_id: &str,
        udp_proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: Duration,
    ) -> Result<RuntimeProxySelector> {
        RuntimeProxySelector::from_snapshot(
            self,
            direct_id,
            tcp_proxy_id,
            udp_proxy_id,
            bypass_id,
            drop_id,
            timeout,
        )
        .await
    }

    async fn build_routed_proxy_selector(
        &self,
        direct_id: &str,
        proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: Duration,
    ) -> Result<RuntimeRoutedProxySelector> {
        let direct = self
            .build_proxy_slot(direct_id, timeout, BaseProxyKind::Direct)
            .await?;
        // Go's empty selected-node state means the built-in direct transport;
        // it does not create a synthetic `direct` node row. Keep the proxy
        // slot fail-closed for non-empty unknown IDs while treating only an
        // empty ID as this explicit direct fallback.
        let proxy = self
            .build_proxy_slot(proxy_id, timeout, BaseProxyKind::Direct)
            .await?;
        let bypass = self
            .build_proxy_slot(bypass_id, timeout, BaseProxyKind::Direct)
            .await?;
        let drop = self
            .build_proxy_slot(drop_id, timeout, BaseProxyKind::Reject)
            .await?;

        Ok(RuntimeRoutedProxySelector {
            router: self.router.clone(),
            direct,
            proxy,
            bypass,
            drop,
        })
    }

    pub(crate) fn resolve_proxy(&self, proxy: Arc<dyn AsyncProxy>) -> Arc<dyn AsyncProxy> {
        Arc::new(ResolvingProxy::new(proxy, self.resolver.clone()))
    }

    async fn build_proxy_slot(
        &self,
        id: &str,
        timeout: Duration,
        fallback: BaseProxyKind,
    ) -> Result<Arc<dyn AsyncProxy>> {
        if id.trim().is_empty() || (id == "direct" && matches!(fallback, BaseProxyKind::Direct)) {
            let is_direct = matches!(fallback, BaseProxyKind::Direct);
            let proxy = BaseProxyConfig {
                kind: fallback,
                timeout,
            }
            .build()?;
            let proxy = Arc::new(ConnectBudgetProxy {
                inner: Arc::new(SocketPolicyProxy {
                    inner: proxy,
                    bind_addresses: self.socket_bind_addresses.clone(),
                    bind_interface: None,
                }),
                semaphore: self.connect_semaphore.clone(),
            }) as Arc<dyn AsyncProxy>;
            return Ok(if is_direct {
                self.resolve_proxy(proxy)
            } else {
                proxy
            });
        }
        Ok(self.build_proxy(id, timeout).await?.proxy)
    }
}

/// Apply the immutable interface policy at the last common proxy boundary.
/// This keeps protocol implementations independent from runtime settings and
/// also covers chain transports whose first socket is opened outside core.
struct SocketPolicyProxy {
    inner: Arc<dyn AsyncProxy>,
    bind_addresses: Arc<[std::net::IpAddr]>,
    bind_interface: Option<String>,
}

impl AsyncProxy for SocketPolicyProxy {
    fn connect<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> yuhaiin_core::BoxFuture<'a, Result<yuhaiin_core::proxy::BoxAsyncStream>> {
        let mut context = context.clone();
        context.local_bind_addresses = self.bind_addresses.to_vec();
        if self.bind_interface.is_some() {
            context.bind_interface = self.bind_interface.clone();
        }
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.connect(&context).await })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> yuhaiin_core::BoxFuture<'a, Result<Box<dyn yuhaiin_core::proxy::AsyncDatagram>>> {
        let mut context = context.clone();
        context.local_bind_addresses = self.bind_addresses.to_vec();
        if self.bind_interface.is_some() {
            context.bind_interface = self.bind_interface.clone();
        }
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.open_datagram(&context).await })
    }

    fn ping<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> yuhaiin_core::BoxFuture<'a, Result<Duration>> {
        let mut context = context.clone();
        context.local_bind_addresses = self.bind_addresses.to_vec();
        if self.bind_interface.is_some() {
            context.bind_interface = self.bind_interface.clone();
        }
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.ping(&context).await })
    }

    fn close(&self) -> yuhaiin_core::BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

/// Apply the Go happy-eyeballs dial budget at the runtime boundary. The
/// permit covers only connection establishment; once a flow is connected it
/// must not consume a slot for the lifetime of the relay.
struct ConnectBudgetProxy {
    inner: Arc<dyn AsyncProxy>,
    semaphore: Arc<tokio::sync::Semaphore>,
}

impl AsyncProxy for ConnectBudgetProxy {
    fn connect<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> yuhaiin_core::BoxFuture<'a, Result<yuhaiin_core::proxy::BoxAsyncStream>> {
        Box::pin(async move {
            let _permit =
                self.semaphore.clone().acquire_owned().await.map_err(|_| {
                    Error::new(ErrorKind::Closed, "runtime connect budget is closed")
                })?;
            self.inner.connect(context).await
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> yuhaiin_core::BoxFuture<'a, Result<Box<dyn yuhaiin_core::proxy::AsyncDatagram>>> {
        self.inner.open_datagram(context)
    }

    fn ping<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> yuhaiin_core::BoxFuture<'a, Result<Duration>> {
        self.inner.ping(context)
    }

    fn close(&self) -> yuhaiin_core::BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

async fn build_aead_proxy(
    config: &GoProxyRuntimeConfig,
    timeout: Duration,
    resolver: Arc<dyn yuhaiin_core::dns_resolver_async::AsyncIpResolver>,
) -> Result<Arc<dyn AsyncProxy>> {
    let base = config
        .to_base_proxy_config_with_resolver(timeout, resolver)
        .await?;
    let udp_server = match &base.kind {
        BaseProxyKind::Fixed { address } => Some(*address),
        _ => None,
    };
    #[cfg(feature = "doh-tls")]
    let mut upstream: Arc<dyn AsyncProxy> = base.build()?;
    #[cfg(not(feature = "doh-tls"))]
    let upstream: Arc<dyn AsyncProxy> = base.build()?;
    if config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("tls"))
    {
        #[cfg(feature = "doh-tls")]
        {
            upstream = build_protocol_tls_proxy(config, upstream)?;
        }
        #[cfg(not(feature = "doh-tls"))]
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "AEAD TLS transport requires the doh-tls feature",
            ));
        }
    }
    let layer = config
        .layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case("aead"))
        .ok_or_else(|| Error::invalid("AEAD transport layer is missing"))?;
    let password = layer
        .config
        .get("password")
        .and_then(serde_json::Value::as_str)
        .filter(|password| !password.is_empty())
        .ok_or_else(|| Error::invalid("AEAD password is empty"))?;
    let method = layer
        .config
        .get("cryptoMethod")
        .or_else(|| layer.config.get("crypto_method"))
        .and_then(serde_json::Value::as_str)
        .map(yuhaiin_protocol::aead::CryptoMethod::parse)
        .unwrap_or(yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305);
    Ok(Arc::new(yuhaiin_protocol::aead::AeadProxy::new(
        upstream, password, method, udp_server,
    )))
}

/// A TUN-facing selector whose proxy slots can be replaced as one unit after
/// a successful configuration reload. Existing flows keep the `Arc` returned
/// by the old slot; new flows observe the new snapshot after `replace`.
pub struct RuntimeProxySelector {
    current: RwLock<RuntimeRoutedProxySelector>,
    udp_current: RwLock<RuntimeRoutedProxySelector>,
    tagged: RwLock<BTreeMap<String, Arc<dyn AsyncProxy>>>,
    udp_tagged: RwLock<BTreeMap<String, Arc<dyn AsyncProxy>>>,
    direct_id: String,
    proxy_id: String,
    udp_proxy_id: String,
    bypass_id: String,
    drop_id: String,
    timeout: Duration,
    closed_nodes: RwLock<BTreeSet<String>>,
    retargeted_nodes: RwLock<BTreeSet<String>>,
    metadata: RwLock<ProxyContextMetadata>,
    settings: RwLock<crate::RuntimeSettings>,
    loopback: LoopbackDetector,
}

#[derive(Clone, Default)]
struct ProxyContextMetadata {
    hosts: yuhaiin_core::dns_hosts::HostsTable,
    route_lists: RouteListSnapshot,
    geo: Option<Arc<dyn GeoLookup>>,
    endpoints: BTreeMap<String, SocketAddr>,
    tag_endpoints: BTreeMap<String, SocketAddr>,
    tag_node_ids: BTreeMap<String, String>,
    node_names: BTreeMap<String, String>,
    direct_resolver: Option<String>,
    proxy_resolver: Option<String>,
}

impl RuntimeProxySelector {
    pub(crate) fn active_node_ids(&self) -> Vec<String> {
        let closed_nodes = self
            .closed_nodes
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let retargeted_nodes = self
            .retargeted_nodes
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        [
            self.direct_id.as_str(),
            self.proxy_id.as_str(),
            self.udp_proxy_id.as_str(),
            self.bypass_id.as_str(),
            self.drop_id.as_str(),
        ]
        .into_iter()
        .filter(|id| {
            !id.is_empty() && !closed_nodes.contains(*id) && !retargeted_nodes.contains(*id)
        })
        .map(str::to_owned)
        .collect()
    }

    async fn from_snapshot(
        snapshot: &RuntimeSnapshot,
        direct_id: &str,
        tcp_proxy_id: &str,
        udp_proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: Duration,
    ) -> Result<Self> {
        let loopback = LoopbackDetector::new();
        let current = snapshot
            .build_routed_proxy_selector(direct_id, tcp_proxy_id, bypass_id, drop_id, timeout)
            .await?;
        let udp_current = snapshot
            .build_routed_proxy_selector(direct_id, udp_proxy_id, bypass_id, drop_id, timeout)
            .await?;
        let tagged = snapshot.build_tagged_proxies(timeout).await?;
        let udp_tagged = snapshot.build_tagged_proxies(timeout).await?;
        Ok(Self {
            current: RwLock::new(track_selector(current, &loopback)),
            udp_current: RwLock::new(track_selector(udp_current, &loopback)),
            tagged: RwLock::new(track_tagged_proxies(tagged, &loopback)),
            udp_tagged: RwLock::new(track_tagged_proxies(udp_tagged, &loopback)),
            direct_id: direct_id.to_owned(),
            proxy_id: tcp_proxy_id.to_owned(),
            udp_proxy_id: udp_proxy_id.to_owned(),
            bypass_id: bypass_id.to_owned(),
            drop_id: drop_id.to_owned(),
            timeout,
            closed_nodes: RwLock::new(BTreeSet::new()),
            retargeted_nodes: RwLock::new(BTreeSet::new()),
            metadata: RwLock::new(
                snapshot
                    .proxy_context_metadata(
                        direct_id,
                        tcp_proxy_id,
                        udp_proxy_id,
                        bypass_id,
                        drop_id,
                    )
                    .await?,
            ),
            settings: RwLock::new(snapshot.settings.clone()),
            loopback,
        })
    }

    pub(crate) async fn prepare(
        &self,
        snapshot: &RuntimeSnapshot,
    ) -> Result<PreparedProxySelector> {
        let direct_id = self.effective_node_id(&self.direct_id);
        let proxy_id = self.effective_node_id(&self.proxy_id);
        let udp_proxy_id = self.effective_node_id(&self.udp_proxy_id);
        let bypass_id = self.effective_node_id(&self.bypass_id);
        let drop_id = self.effective_node_id(&self.drop_id);
        let tagged = snapshot.build_tagged_proxies(self.timeout).await?;
        let udp_tagged = snapshot.build_tagged_proxies(self.timeout).await?;
        Ok(PreparedProxySelector {
            selector: track_selector(
                snapshot
                    .build_routed_proxy_selector(
                        &direct_id,
                        &proxy_id,
                        &bypass_id,
                        &drop_id,
                        self.timeout,
                    )
                    .await?,
                &self.loopback,
            ),
            udp_selector: track_selector(
                snapshot
                    .build_routed_proxy_selector(
                        &direct_id,
                        &udp_proxy_id,
                        &bypass_id,
                        &drop_id,
                        self.timeout,
                    )
                    .await?,
                &self.loopback,
            ),
            tagged: track_tagged_proxies(tagged, &self.loopback),
            udp_tagged: track_tagged_proxies(udp_tagged, &self.loopback),
            metadata: snapshot
                .proxy_context_metadata(&direct_id, &proxy_id, &udp_proxy_id, &bypass_id, &drop_id)
                .await?,
            settings: snapshot.settings.clone(),
        })
    }

    pub(crate) fn replace(&self, next: PreparedProxySelector) {
        let mut current = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = next.selector;
        *self
            .udp_current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next.udp_selector;
        *self
            .tagged
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next.tagged;
        *self
            .udp_tagged
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next.udp_tagged;
        self.closed_nodes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.retargeted_nodes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        *self
            .metadata
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next.metadata;
        *self
            .settings
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = next.settings;
    }

    /// Close every slot that currently points at `id`, then make new flows
    /// fail closed until the next successful runtime reload. Existing flows
    /// keep their selected `Arc`, so closing the old instances also mirrors
    /// Go's `ProxyStore.Delete` behavior for those flows.
    pub(crate) async fn close_node(&self, id: &str) {
        let mut old_proxies = Vec::new();
        {
            let mut current = self
                .current
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut closed_nodes = self
                .closed_nodes
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());

            macro_rules! close_slot {
                ($slot_id:expr, $slot:expr) => {
                    if $slot_id == id {
                        old_proxies.push(Arc::clone($slot));
                        *$slot = Arc::new(DropAsyncProxy);
                    }
                };
            }
            close_slot!(&self.direct_id, &mut current.direct);
            close_slot!(&self.proxy_id, &mut current.proxy);
            close_slot!(&self.bypass_id, &mut current.bypass);
            close_slot!(&self.drop_id, &mut current.drop);
            let mut udp_current = self
                .udp_current
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            close_slot!(&self.direct_id, &mut udp_current.direct);
            close_slot!(&self.udp_proxy_id, &mut udp_current.proxy);
            close_slot!(&self.bypass_id, &mut udp_current.bypass);
            close_slot!(&self.drop_id, &mut udp_current.drop);
            let mut tagged = self
                .tagged
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            old_proxies.extend(std::mem::take(&mut *tagged).into_values());
            let mut udp_tagged = self
                .udp_tagged
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            old_proxies.extend(std::mem::take(&mut *udp_tagged).into_values());
            if !old_proxies.is_empty() {
                closed_nodes.insert(id.to_owned());
            }
        }

        for proxy in old_proxies {
            let _ = proxy.close().await;
        }
    }

    /// Retarget a node that is about to be deleted to the built-in direct
    /// slot. Go removes a selected node and reloads the inbound runtime in one
    /// management operation; keeping the old ID in a live selector would
    /// make that reload fail while preparing the selector. Existing flows are
    /// already closed by `close_node`; the next successful replacement then
    /// installs the direct fallback for new flows.
    pub(crate) async fn retarget_node_to_direct(&self, id: &str) {
        self.close_node(id).await;
        self.retargeted_nodes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id.to_owned());
    }

    fn effective_node_id(&self, id: &str) -> String {
        if self
            .retargeted_nodes
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(id)
        {
            String::new()
        } else {
            id.to_owned()
        }
    }

    pub(crate) fn relay_buffer_size(&self) -> usize {
        self.settings
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .relay_buffer_size
    }

    pub(crate) fn udp_buffer_size(&self) -> usize {
        self.settings
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .udp_buffer_size
    }

    pub(crate) fn udp_ringbuffer_size(&self) -> usize {
        self.settings
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .udp_ringbuffer_size
    }
}

pub(crate) struct PreparedProxySelector {
    pub(crate) selector: RuntimeRoutedProxySelector,
    pub(crate) udp_selector: RuntimeRoutedProxySelector,
    tagged: BTreeMap<String, Arc<dyn AsyncProxy>>,
    udp_tagged: BTreeMap<String, Arc<dyn AsyncProxy>>,
    metadata: ProxyContextMetadata,
    settings: crate::RuntimeSettings,
}

impl AsyncProxySelector for RuntimeProxySelector {
    fn route_context(&self, context: &mut FlowContext) {
        let direct_id = self.effective_node_id(&self.direct_id);
        let proxy_id = self.effective_node_id(&self.proxy_id);
        let udp_proxy_id = self.effective_node_id(&self.udp_proxy_id);
        let bypass_id = self.effective_node_id(&self.bypass_id);
        let metadata = self
            .metadata
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let matched_lists = metadata.route_lists.matching_names(context);
        context.lists = matched_lists.clone();
        if let Some(reason) = self.loopback.reason(context) {
            context.route_mode = yuhaiin_core::RouteMode::Block;
            context.skip_route = true;
            context.tag = Some(reason.to_owned());
            context.match_history.clear();
        } else {
            let current = self
                .current
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            current.route_context(context);
        }
        // The trie evaluates List matchers against the membership populated
        // above. Restore the complete snapshot-derived membership afterward
        // so connection metadata is independent of which rule was selected.
        context.lists = matched_lists;
        context.resolver = match context.route_mode {
            yuhaiin_core::RouteMode::Proxy => metadata.proxy_resolver.clone(),
            yuhaiin_core::RouteMode::Direct | yuhaiin_core::RouteMode::Bypass => {
                metadata.direct_resolver.clone()
            }
            yuhaiin_core::RouteMode::Block => None,
        };
        annotate_connection_metadata(
            context,
            &metadata,
            &direct_id,
            &proxy_id,
            &udp_proxy_id,
            &bypass_id,
        );
    }

    fn select(&self, context: &FlowContext) -> Arc<dyn AsyncProxy> {
        if context.route_mode != yuhaiin_core::RouteMode::Block {
            let tagged = if context.network == yuhaiin_core::Network::Udp {
                self.udp_tagged
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
            } else {
                self.tagged
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
            };
            if let Some(tag) = context.tag.as_deref().filter(|tag| !tag.trim().is_empty())
                && let Some(proxy) = tagged.get(tag)
            {
                return Arc::clone(proxy);
            }
        }
        let current = if context.network == yuhaiin_core::Network::Udp {
            self.udp_current
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        } else {
            self.current
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        };
        current.select(context)
    }
}

impl RuntimeSnapshot {
    fn node_tag_definitions(&self) -> Result<BTreeMap<String, NodeTagDefinition>> {
        let mut definitions = BTreeMap::new();
        for record in &self.node_tags {
            let name = if record.name.trim().is_empty() {
                record.id.trim()
            } else {
                record.name.trim()
            };
            if name.is_empty() {
                return Err(Error::invalid("node tag name is empty"));
            }
            definitions.insert(name.to_owned(), parse_node_tag(record)?);
        }
        Ok(definitions)
    }

    async fn build_tagged_proxies(
        &self,
        timeout: Duration,
    ) -> Result<BTreeMap<String, Arc<dyn AsyncProxy>>> {
        let definitions = self.node_tag_definitions()?;

        let mut tagged = BTreeMap::new();
        for (tag, definition) in &definitions {
            let ids = resolve_node_tag_targets(tag, &definitions, &mut BTreeSet::new());
            let mut members = Vec::new();
            let mut seen = BTreeSet::new();
            for id in ids {
                if !seen.insert(id.clone()) {
                    continue;
                }
                // Go's node set skips members that cannot be opened and lets
                // the ordinary route-mode slot handle an empty set. This is
                // important during a partial node migration or after a node
                // was disabled without deleting its tag membership.
                if let Ok(build) = self.build_proxy(&id, timeout).await {
                    members.push(build.proxy);
                }
            }
            if members.is_empty() {
                continue;
            }
            let proxy = if members.len() == 1 {
                members.pop().expect("one node tag member was checked")
            } else {
                Arc::new(NodeSetProxy::new(members, definition.round_robin)?)
            };
            tagged.insert(tag.clone(), proxy);
        }
        Ok(tagged)
    }

    async fn proxy_context_metadata(
        &self,
        direct_id: &str,
        proxy_id: &str,
        udp_proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
    ) -> Result<ProxyContextMetadata> {
        let mut endpoints = BTreeMap::new();
        for id in [direct_id, proxy_id, udp_proxy_id, bypass_id, drop_id]
            .into_iter()
            .filter(|id| !id.trim().is_empty())
        {
            let Some(config) = self.proxy_config(id) else {
                continue;
            };
            if let Ok(Some(endpoint)) = config.resolved_fixed_endpoint(self.resolver.as_ref()).await
            {
                endpoints.insert(id.to_owned(), endpoint);
            }
        }
        let (tag_endpoints, tag_node_ids) = self.tag_metadata().await?;
        let node_names = self
            .proxies
            .iter()
            .filter(|config| !config.name.trim().is_empty())
            .map(|config| (config.id.clone(), config.name.clone()))
            .collect();
        let (direct_resolver, proxy_resolver) = self
            .route
            .as_ref()
            .map(|route| {
                (
                    (!route.direct_resolver.trim().is_empty())
                        .then(|| route.direct_resolver.trim().to_owned()),
                    (!route.proxy_resolver.trim().is_empty())
                        .then(|| route.proxy_resolver.trim().to_owned()),
                )
            })
            .unwrap_or_default();
        Ok(ProxyContextMetadata {
            hosts: self.hosts.clone(),
            route_lists: self.route_lists.clone(),
            geo: self.geo.clone(),
            endpoints,
            tag_endpoints,
            tag_node_ids,
            node_names,
            direct_resolver,
            proxy_resolver,
        })
    }

    async fn tag_metadata(
        &self,
    ) -> Result<(BTreeMap<String, SocketAddr>, BTreeMap<String, String>)> {
        let definitions = self.node_tag_definitions()?;

        let mut endpoints = BTreeMap::new();
        let mut node_ids = BTreeMap::new();
        for tag in definitions.keys() {
            let ids = resolve_node_tag_targets(tag, &definitions, &mut BTreeSet::new());
            for id in ids {
                let Some(config) = self.proxy_config(&id) else {
                    continue;
                };
                if !config.enabled {
                    continue;
                }
                node_ids.entry(tag.clone()).or_insert_with(|| id.clone());
                if let Ok(Some(endpoint)) =
                    config.resolved_fixed_endpoint(self.resolver.as_ref()).await
                {
                    endpoints.insert(tag.clone(), endpoint);
                    break;
                }
            }
        }
        Ok((endpoints, node_ids))
    }
}

fn annotate_connection_metadata(
    context: &mut FlowContext,
    metadata: &ProxyContextMetadata,
    direct_id: &str,
    proxy_id: &str,
    udp_proxy_id: &str,
    bypass_id: &str,
) {
    if context.hosts.is_none() {
        let domain = context
            .original_domain
            .as_ref()
            .or_else(|| context.destination.host());
        if let Some(domain) = domain
            && metadata.hosts.resolve(domain).ok().flatten().is_some()
        {
            context.hosts = Some(
                context
                    .destination
                    .port()
                    .map(|port| format!("{domain}:{port}"))
                    .unwrap_or_else(|| domain.to_string()),
            );
        }
    }

    let selected_proxy_id = if context.network == yuhaiin_core::Network::Udp {
        udp_proxy_id
    } else {
        proxy_id
    };
    let selected_id = match context.route_mode {
        yuhaiin_core::RouteMode::Direct => direct_id,
        yuhaiin_core::RouteMode::Proxy => selected_proxy_id,
        yuhaiin_core::RouteMode::Bypass => bypass_id,
        yuhaiin_core::RouteMode::Block => return,
    };
    if context.route_mode == yuhaiin_core::RouteMode::Proxy && !selected_id.is_empty() {
        context.outbound = context
            .tag
            .as_deref()
            .and_then(|tag| metadata.tag_node_ids.get(tag))
            .cloned()
            .or_else(|| Some(selected_id.to_owned()));
    }
    if let Some(node_id) = context.outbound.as_deref() {
        context.outbound_name = metadata.node_names.get(node_id).cloned();
    }
    let endpoint = context
        .tag
        .as_deref()
        .and_then(|tag| metadata.tag_endpoints.get(tag).copied())
        .or_else(|| metadata.endpoints.get(selected_id).copied())
        .or_else(|| context.destination.addr())
        .or_else(|| context.effective_destination().addr());
    let Some(endpoint) = endpoint else {
        return;
    };
    if context.outbound_addr.is_none() {
        context.outbound_addr = Some(Endpoint::ip(context.network, endpoint));
    }
    #[cfg(feature = "http-api")]
    if context.interface.is_none() {
        context.interface = crate::interfaces::interface_for_ip(endpoint.ip());
    }
    if context.outbound_geo.is_none() {
        context.outbound_geo = metadata
            .geo
            .as_ref()
            .and_then(|geo| geo.country_code(endpoint.ip()).ok().flatten());
    }
}

fn network_split_branch(value: Option<&serde_json::Value>) -> Result<Option<GoProxyLayer>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let object = value
        .as_object()
        .ok_or_else(|| Error::invalid("network_split branch must be an object"))?;
    let kind = object
        .get("type")
        .or_else(|| object.get("protocol"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::invalid("network_split branch requires a protocol type"))?;
    let config = object
        .get(kind)
        .cloned()
        .unwrap_or_else(|| serde_json::Value::Object(object.clone()));
    Ok(Some(GoProxyLayer {
        kind: kind.to_owned(),
        config,
    }))
}

fn layer_string(layer: &GoProxyLayer, key: &str) -> Option<String> {
    layer
        .config
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

fn layer_bool(layer: &GoProxyLayer, snake: &str, camel: &str) -> bool {
    layer
        .config
        .get(snake)
        .or_else(|| layer.config.get(camel))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn is_chain_config(config: &GoProxyRuntimeConfig) -> bool {
    if config
        .chain_types
        .iter()
        .any(|kind| matches!(kind.to_ascii_lowercase().as_str(), "http2" | "websocket"))
    {
        return true;
    }
    if config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("tls"))
        && !matches!(
            config.transport,
            yuhaiin_store::GoProxyTransport::Trojan
                | yuhaiin_store::GoProxyTransport::Shadowsocks
                | yuhaiin_store::GoProxyTransport::Shadowsocksr
                | yuhaiin_store::GoProxyTransport::Vless
                | yuhaiin_store::GoProxyTransport::Vmess
        )
    {
        return true;
    }
    config.chain_types.iter().any(|kind| {
        kind.eq_ignore_ascii_case("yuubinsya")
            && config
                .layers
                .iter()
                .find(|layer| layer.kind.eq_ignore_ascii_case("yuubinsya"))
                .and_then(|layer| layer.config.get("udp_over_stream"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
    })
}

fn is_protocol_h2_config(config: &GoProxyRuntimeConfig) -> bool {
    let has_http2 = config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("http2"));
    let protocol = match config.transport {
        yuhaiin_store::GoProxyTransport::Vless => "vless",
        yuhaiin_store::GoProxyTransport::Vmess => "vmess",
        yuhaiin_store::GoProxyTransport::Trojan => "trojan",
        _ => return false,
    };
    has_http2
        && config
            .chain_types
            .iter()
            .any(|kind| kind.eq_ignore_ascii_case(protocol))
}

fn is_vless_websocket_config(config: &GoProxyRuntimeConfig) -> bool {
    let has_websocket = config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("websocket"));
    let has_vless = config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("vless"));
    config.transport == yuhaiin_store::GoProxyTransport::Vless
        && has_websocket
        && has_vless
        && config.chain_types.iter().all(|kind| {
            matches!(
                kind.to_ascii_lowercase().as_str(),
                "fixed" | "fixedv2" | "tls" | "websocket" | "vless"
            )
        })
}

fn is_vmess_transport_config(config: &GoProxyRuntimeConfig) -> bool {
    let has_vmess = config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("vmess"));
    let has_transport = config
        .chain_types
        .iter()
        .any(|kind| matches!(kind.to_ascii_lowercase().as_str(), "tls" | "websocket"));
    config.transport == yuhaiin_store::GoProxyTransport::Vmess
        && has_vmess
        && has_transport
        && config.chain_types.iter().all(|kind| {
            matches!(
                kind.to_ascii_lowercase().as_str(),
                "fixed" | "fixedv2" | "tls" | "websocket" | "vmess"
            )
        })
}

fn is_trojan_websocket_config(config: &GoProxyRuntimeConfig) -> bool {
    let has_websocket = config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("websocket"));
    let has_trojan = config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("trojan"));
    config.transport == yuhaiin_store::GoProxyTransport::Trojan
        && has_websocket
        && has_trojan
        && config.chain_types.iter().all(|kind| {
            matches!(
                kind.to_ascii_lowercase().as_str(),
                "fixed" | "fixedv2" | "tls" | "websocket" | "trojan"
            )
        })
}

async fn build_stream_transport_upstream(
    config: &GoProxyRuntimeConfig,
    timeout: Duration,
    resolver: Arc<dyn yuhaiin_core::dns_resolver_async::AsyncIpResolver>,
    protocol_name: &str,
) -> Result<Arc<dyn AsyncProxy>> {
    #[cfg(feature = "doh-tls")]
    let _ = protocol_name;

    let base = config
        .to_base_proxy_config_with_resolver(timeout, resolver)
        .await?;
    let mut upstream: Arc<dyn AsyncProxy> = base.build()?;
    if config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("tls"))
    {
        #[cfg(feature = "doh-tls")]
        {
            upstream = build_protocol_tls_proxy(config, upstream)?;
        }
        #[cfg(not(feature = "doh-tls"))]
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("{protocol_name} TLS transport requires the doh-tls feature"),
            ));
        }
    }
    if config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("websocket"))
    {
        upstream = build_protocol_websocket_proxy(config, upstream)?;
    }
    Ok(upstream)
}

async fn build_wireguard_proxy(
    layer: &GoProxyLayer,
    timeout: Duration,
    resolver: Arc<dyn AsyncIpResolver>,
    bind_interface: Option<String>,
) -> Result<Arc<dyn AsyncProxy>> {
    let wireguard: yuhaiin_wireguard::WireGuardConfig =
        serde_json::from_value(layer.config.clone()).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("invalid WireGuard node configuration: {error}"),
            )
        })?;
    Ok(Arc::new(
        yuhaiin_wireguard::build_proxy_with_interface_and_resolver(
            wireguard,
            timeout,
            bind_interface.as_deref(),
            Some(resolver),
        )
        .await?,
    ))
}

async fn build_protocol_h2_proxy(
    config: &GoProxyRuntimeConfig,
    _timeout: Duration,
    resolver: Arc<dyn yuhaiin_core::dns_resolver_async::AsyncIpResolver>,
) -> Result<Arc<dyn AsyncProxy>> {
    let protocol = match config.transport {
        yuhaiin_store::GoProxyTransport::Vless => "vless",
        yuhaiin_store::GoProxyTransport::Vmess => "vmess",
        yuhaiin_store::GoProxyTransport::Trojan => "trojan",
        _ => {
            return Err(Error::invalid(
                "HTTP/2 protocol transport requires VLESS, VMess, or Trojan",
            ));
        }
    };
    let mut node: serde_json::Value =
        serde_json::from_slice(&config.data_json).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("proxy node chain JSON is invalid: {error}"),
            )
        })?;
    let chain = node
        .get_mut("chain")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| Error::invalid("HTTP/2 protocol node requires a chain array"))?;
    let original_len = chain.len();
    chain.retain(|layer| {
        !layer
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| kind.eq_ignore_ascii_case(protocol))
    });
    if chain.len() == original_len {
        return Err(Error::invalid(format!(
            "HTTP/2 protocol node is missing its {protocol} chain layer"
        )));
    }

    let upstream = Arc::new(ChainProxy::from_go_json_transport_with_resolver(
        &node.to_string(),
        resolver,
    )?) as Arc<dyn AsyncProxy>;
    build_protocol_proxy(config, upstream)
}

fn build_protocol_proxy(
    config: &GoProxyRuntimeConfig,
    upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    let protocol = match config.transport {
        yuhaiin_store::GoProxyTransport::Vless => "vless",
        yuhaiin_store::GoProxyTransport::Vmess => "vmess",
        yuhaiin_store::GoProxyTransport::Trojan => "trojan",
        _ => {
            return Err(Error::invalid(
                "protocol framing requires VLESS, VMess, or Trojan",
            ));
        }
    };
    let layer = config
        .layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case(protocol))
        .ok_or_else(|| Error::invalid(format!("{protocol} protocol layer is missing")))?;
    match config.transport {
        yuhaiin_store::GoProxyTransport::Vless => {
            let uuid = layer
                .config
                .get("uuid")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::invalid("VLESS UUID is missing"))?;
            Ok(Arc::new(yuhaiin_protocol::vless::VlessProxy::new(
                upstream, uuid,
            )?))
        }
        yuhaiin_store::GoProxyTransport::Vmess => {
            let uuid = layer
                .config
                .get("id")
                .or_else(|| layer.config.get("uuid"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| Error::invalid("VMess UUID is missing"))?;
            let security = layer
                .config
                .get("security")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("auto");
            let alter_id = vmess_alter_id(&layer.config)?;
            Ok(Arc::new(yuhaiin_protocol::vmess::VmessProxy::new(
                upstream, uuid, security, alter_id,
            )?))
        }
        yuhaiin_store::GoProxyTransport::Trojan => {
            let password = layer
                .config
                .get("password")
                .and_then(serde_json::Value::as_str)
                .filter(|password| !password.is_empty())
                .ok_or_else(|| Error::invalid("Trojan password is empty"))?;
            Ok(Arc::new(yuhaiin_protocol::trojan::TrojanProxy::new(
                upstream, password,
            )))
        }
        _ => unreachable!("protocol kind was validated above"),
    }
}

async fn build_vless_transport_proxy(
    config: &GoProxyRuntimeConfig,
    timeout: Duration,
    resolver: Arc<dyn yuhaiin_core::dns_resolver_async::AsyncIpResolver>,
) -> Result<Arc<dyn AsyncProxy>> {
    let upstream = build_stream_transport_upstream(config, timeout, resolver, "VLESS").await?;
    build_protocol_proxy(config, upstream)
}

async fn build_vmess_transport_proxy(
    config: &GoProxyRuntimeConfig,
    timeout: Duration,
    resolver: Arc<dyn yuhaiin_core::dns_resolver_async::AsyncIpResolver>,
) -> Result<Arc<dyn AsyncProxy>> {
    let upstream = build_stream_transport_upstream(config, timeout, resolver, "VMess").await?;
    build_protocol_proxy(config, upstream)
}

async fn build_trojan_transport_proxy(
    config: &GoProxyRuntimeConfig,
    timeout: Duration,
    resolver: Arc<dyn yuhaiin_core::dns_resolver_async::AsyncIpResolver>,
) -> Result<Arc<dyn AsyncProxy>> {
    let upstream = build_stream_transport_upstream(config, timeout, resolver, "Trojan").await?;
    build_protocol_proxy(config, upstream)
}

fn vmess_alter_id(config: &serde_json::Value) -> Result<u32> {
    let Some(value) = config.get("aid").or_else(|| config.get("alter_id")) else {
        return Ok(0);
    };
    if let Some(number) = value.as_u64() {
        return u32::try_from(number).map_err(|_| Error::invalid("VMess alter_id is out of range"));
    }
    value
        .as_str()
        .ok_or_else(|| Error::invalid("VMess alter_id must be a string or integer"))?
        .parse::<u32>()
        .map_err(|error| Error::invalid(format!("VMess alter_id is invalid: {error}")))
}

#[cfg(feature = "websocket")]
fn build_protocol_websocket_proxy(
    config: &GoProxyRuntimeConfig,
    upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    let layer = config
        .layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case("websocket"))
        .ok_or_else(|| Error::invalid("WebSocket transport layer is missing"))?;
    let host = layer
        .config
        .get("host")
        .or_else(|| layer.config.get("hostname"))
        .and_then(serde_json::Value::as_str)
        .filter(|host| !host.is_empty())
        .ok_or_else(|| Error::invalid("WebSocket transport host is missing"))?;
    let path = layer
        .config
        .get("path")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("/");
    Ok(Arc::new(yuhaiin_protocol::websocket::WebSocketProxy::new(
        upstream, host, path,
    )?))
}

#[cfg(not(feature = "websocket"))]
fn build_protocol_websocket_proxy(
    _config: &GoProxyRuntimeConfig,
    _upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "VLESS WebSocket transport requires the websocket feature",
    ))
}

#[cfg(feature = "doh-tls")]
fn build_protocol_tls_proxy(
    config: &GoProxyRuntimeConfig,
    upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    use base64::Engine;
    use rustls::RootCertStore;
    use rustls::pki_types::CertificateDer;

    let layer = config
        .layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case("tls"))
        .ok_or_else(|| Error::invalid("protocol TLS layer is missing"))?;
    let server_name = layer
        .config
        .get("servernames")
        .or_else(|| layer.config.get("serverNames"))
        .and_then(serde_json::Value::as_array)
        .and_then(|values| values.iter().find_map(serde_json::Value::as_str))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::invalid("protocol TLS layer requires servernames"))?;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(certificates) = layer
        .config
        .get("ca_cert")
        .or_else(|| layer.config.get("caCert"))
        .and_then(serde_json::Value::as_array)
    {
        for certificate in certificates {
            let encoded = certificate
                .as_str()
                .ok_or_else(|| Error::invalid("Trojan TLS ca_cert must contain strings"))?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|error| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("protocol TLS ca_cert: {error}"),
                    )
                })?;
            roots.add(CertificateDer::from(bytes)).map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("protocol TLS CA: {error}"))
            })?;
        }
    }
    let insecure_skip_verify = layer
        .config
        .get("insecure_skip_verify")
        .or_else(|| layer.config.get("insecureSkipVerify"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let next_protocols = layer
        .config
        .get("next_protos")
        .or_else(|| layer.config.get("nextProtos"))
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(Arc::new(
        yuhaiin_protocol::tls::RustCryptoTlsProxy::new_with_options(
            upstream,
            roots,
            server_name,
            &next_protocols,
            insecure_skip_verify,
        )?,
    ))
}

#[cfg(feature = "doh-tls")]
fn build_tls_termination_proxy(
    config: &GoProxyRuntimeConfig,
    upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::sign::CertifiedKey;
    use tokio_rustls::TlsAcceptor;

    let layer = config
        .layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case("tls_termination"))
        .ok_or_else(|| Error::invalid("TLS termination layer is missing"))?;
    let tls = layer.config.get("tls").unwrap_or(&layer.config);
    let certificates = tls
        .get("certificates")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::invalid("TLS termination certificates are missing"))?;

    let mut entries = Vec::new();
    for certificate in certificates {
        let certificate = certificate
            .as_object()
            .ok_or_else(|| Error::invalid("TLS termination certificate must be an object"))?;
        entries.push((certificate, None));
    }
    if let Some(named_certificates) = tls
        .get("serverNameCertificate")
        .or_else(|| tls.get("server_name_certificate"))
        .and_then(serde_json::Value::as_object)
    {
        for (name, certificate) in named_certificates {
            let certificate = certificate.as_object().ok_or_else(|| {
                Error::invalid("TLS termination named certificate must be an object")
            })?;
            entries.push((certificate, Some(name.as_str())));
        }
    }

    let mut default = Vec::new();
    let mut named = BTreeMap::new();
    for (certificate, name) in entries {
        let cert_bytes = tls_termination_bytes(
            certificate,
            &["cert", "certBase64"],
            &["certFilePath", "cert_file_path"],
            "TLS termination certificate",
        )?;
        let key_bytes = tls_termination_bytes(
            certificate,
            &["key", "keyBase64"],
            &["keyFilePath", "key_file_path"],
            "TLS termination private key",
        )?;
        let cert_chain = if cert_bytes.starts_with(b"-----BEGIN") {
            rustls_pemfile::certs(&mut std::io::Cursor::new(cert_bytes))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|error| {
                    Error::new(
                        ErrorKind::Protocol,
                        format!("TLS termination certificate PEM: {error}"),
                    )
                })?
        } else {
            vec![CertificateDer::from(cert_bytes)]
        };
        if cert_chain.is_empty() {
            return Err(Error::invalid("TLS termination certificate chain is empty"));
        }
        let key = if key_bytes.starts_with(b"-----BEGIN") {
            rustls_pemfile::private_key(&mut std::io::Cursor::new(key_bytes))
                .map_err(|error| {
                    Error::new(
                        ErrorKind::Protocol,
                        format!("TLS termination private key PEM: {error}"),
                    )
                })?
                .ok_or_else(|| Error::invalid("TLS termination private key is empty"))?
        } else {
            PrivateKeyDer::try_from(key_bytes).map_err(|error| {
                Error::new(
                    ErrorKind::Protocol,
                    format!("TLS termination private key DER: {error}"),
                )
            })?
        };
        let signer = rustls_rustcrypto::sign::any_supported_type(&key).map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("TLS termination signing key: {error:?}"),
            )
        })?;
        let certified = Arc::new(CertifiedKey::new(cert_chain, signer));
        if let Some(name) = name {
            let name = tls_termination_name(name);
            if !name.is_empty() {
                named.insert(name, Arc::clone(&certified));
            }
        } else {
            default.push(Arc::clone(&certified));
        }
    }
    if default.is_empty() && named.is_empty() {
        return Err(Error::invalid("TLS termination has no usable certificates"));
    }
    let resolver = StaticTlsTerminationResolver { default, named };
    let mut server =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|error| {
                Error::new(
                    ErrorKind::Protocol,
                    format!("TLS termination provider: {error}"),
                )
            })?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
    server.alpn_protocols = tls
        .get("nextProtos")
        .or_else(|| tls.get("next_protos"))
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::as_bytes)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();

    Ok(Arc::new(TlsTerminationProxy {
        upstream,
        acceptor: TlsAcceptor::from(Arc::new(server)),
    }))
}

#[cfg(feature = "doh-tls")]
fn tls_termination_name(name: &str) -> String {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.starts_with("*.") || name.parse::<std::net::IpAddr>().is_ok() {
        name
    } else {
        format!("*.{name}")
    }
}

#[cfg(feature = "doh-tls")]
fn tls_termination_bytes(
    value: &serde_json::Map<String, serde_json::Value>,
    encoded_keys: &[&str],
    file_keys: &[&str],
    label: &str,
) -> Result<Vec<u8>> {
    use base64::Engine as _;

    for key in encoded_keys {
        if let Some(bytes) = value.get(*key).and_then(serde_json::Value::as_array) {
            return bytes
                .iter()
                .map(|byte| {
                    byte.as_u64()
                        .and_then(|byte| u8::try_from(byte).ok())
                        .ok_or_else(|| Error::invalid(format!("{label} byte is invalid")))
                })
                .collect();
        }
        if let Some(encoded) = value.get(*key).and_then(serde_json::Value::as_str) {
            if encoded.starts_with("-----BEGIN") {
                return Ok(encoded.as_bytes().to_vec());
            }
            return base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|error| Error::invalid(format!("{label} base64: {error}")));
        }
    }
    for key in file_keys {
        if let Some(path) = value
            .get(*key)
            .and_then(serde_json::Value::as_str)
            .filter(|path| !path.trim().is_empty())
        {
            return std::fs::read(path)
                .map_err(|error| Error::invalid(format!("read {label} {path:?}: {error}")));
        }
    }
    Err(Error::invalid(format!("{label} is missing")))
}

#[cfg(feature = "doh-tls")]
#[derive(Debug)]
struct StaticTlsTerminationResolver {
    default: Vec<Arc<rustls::sign::CertifiedKey>>,
    named: BTreeMap<String, Arc<rustls::sign::CertifiedKey>>,
}

#[cfg(feature = "doh-tls")]
impl rustls::server::ResolvesServerCert for StaticTlsTerminationResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = client_hello
            .server_name()?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if let Some(certificate) = self.named.get(&name) {
            return Some(Arc::clone(certificate));
        }
        let mut labels = name.split('.');
        labels.next()?;
        let wildcard = format!("*.{}", labels.collect::<Vec<_>>().join("."));
        self.named
            .get(&wildcard)
            .cloned()
            .or_else(|| self.default.first().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeSnapshot;
    use base64::Engine;
    use std::sync::Arc;
    use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
    use yuhaiin_core::proxy::FixedAsyncProxy;
    use yuhaiin_core::proxy::{AsyncProxySelector, YuubinsyaUdpServer};
    use yuhaiin_core::proxy_factory::{BaseProxyConfig, BaseProxyKind};
    use yuhaiin_core::{FlowContext, GeoLookup, RouteMode};
    use yuhaiin_protocol::trojan::{self, Command};
    use yuhaiin_store::GoProxyLayer;
    use yuhaiin_store::GoProxyTransport;
    use yuhaiin_trie::router::{RouteDecision, Router, RouterRuntime};

    fn snapshot(config: GoProxyRuntimeConfig) -> RuntimeSnapshot {
        snapshot_with_resolver(config, Arc::new(SystemAsyncIpResolver))
    }

    fn snapshot_with_resolver(
        config: GoProxyRuntimeConfig,
        resolver: Arc<dyn AsyncIpResolver>,
    ) -> RuntimeSnapshot {
        RuntimeSnapshot {
            settings: crate::RuntimeSettings::default(),
            connect_semaphore: Arc::new(tokio::sync::Semaphore::new(250)),
            socket_bind_addresses: Arc::from(Vec::<std::net::IpAddr>::new().into_boxed_slice()),
            resolver: Arc::clone(&resolver),
            dns_resolver: resolver,
            hosts: yuhaiin_core::dns_hosts::HostsTable::new(),
            fakeip: None,
            inbound_settings: yuhaiin_store::InboundSettings::default(),
            resolvers: Vec::new(),
            route: None,
            route_rules: Vec::new(),
            node_tags: Vec::new(),
            route_lists: crate::RouteListSnapshot::default(),
            router: RouterRuntime::new(
                Router::compile(
                    Vec::new(),
                    RouteDecision {
                        mode: yuhaiin_core::RouteMode::Direct,
                        resolver_policy: yuhaiin_core::ResolverPolicy::default(),
                        priority: 0,
                    },
                )
                .unwrap(),
            ),
            resolver_by_id: std::collections::BTreeMap::new(),
            resolver_errors: std::collections::BTreeMap::new(),
            resolver_registry_enabled: false,
            geo_metadata: Vec::new(),
            geo: None,
            proxies: vec![config],
            nat: yuhaiin_store::NatConfigRecord::default(),
        }
    }

    #[tokio::test]
    async fn loopback_stream_wrapper_preserves_outbound_local_address() {
        let detector = LoopbackDetector::new();
        let (stream, _peer) = tokio::io::duplex(64);
        let local = "127.0.0.1:41000".parse().unwrap();
        let stream = with_stream_local_addr(Box::new(stream), Some(local));

        let tracked = track_stream(&detector, stream);

        assert_eq!(stream_local_addr(&*tracked), Some(local));
    }

    #[test]
    fn node_tag_parser_accepts_legacy_and_extended_member_shapes() {
        let legacy = yuhaiin_store::GoNodeTagRecord {
            id: "edge".to_owned(),
            name: "edge".to_owned(),
            members_json: br#"{"type":"node","hash":"node-a"}"#.to_vec(),
            updated_at: 1,
        };
        let parsed = parse_node_tag(&legacy).unwrap();
        assert_eq!(parsed.kind, "node");
        assert_eq!(parsed.targets, ["node-a"]);

        let extended = yuhaiin_store::GoNodeTagRecord {
            id: "mirror".to_owned(),
            name: "mirror".to_owned(),
            members_json: br#"{"type":"mirror","hash":["edge"],"strategy":"round_robin"}"#.to_vec(),
            updated_at: 1,
        };
        let parsed = parse_node_tag(&extended).unwrap();
        assert_eq!(parsed.kind, "mirror");
        assert_eq!(parsed.targets, ["edge"]);
        assert!(parsed.round_robin);
    }

    #[test]
    fn node_tag_mirror_resolution_stops_on_cycles() {
        let definitions = BTreeMap::from([
            (
                "a".to_owned(),
                NodeTagDefinition {
                    kind: "mirror".to_owned(),
                    targets: vec!["b".to_owned()],
                    round_robin: false,
                },
            ),
            (
                "b".to_owned(),
                NodeTagDefinition {
                    kind: "mirror".to_owned(),
                    targets: vec!["a".to_owned()],
                    round_robin: false,
                },
            ),
            (
                "edge".to_owned(),
                NodeTagDefinition {
                    kind: "node".to_owned(),
                    targets: vec!["node-a".to_owned(), "node-b".to_owned()],
                    round_robin: false,
                },
            ),
        ]);
        assert!(resolve_node_tag_targets("a", &definitions, &mut BTreeSet::new()).is_empty());
        assert_eq!(
            resolve_node_tag_targets("edge", &definitions, &mut BTreeSet::new()),
            ["node-a", "node-b"]
        );
    }

    #[cfg(feature = "doh-tls")]
    #[test]
    fn tls_termination_preserves_go_certificate_name_and_byte_shapes() {
        assert_eq!(tls_termination_name("example.com"), "*.example.com");
        assert_eq!(tls_termination_name("*.Example.COM."), "*.example.com");
        assert_eq!(tls_termination_name("127.0.0.1"), "127.0.0.1");

        let value = serde_json::json!({
            "cert": [1, 2, 255],
            "keyBase64": base64::engine::general_purpose::STANDARD.encode([3u8, 4, 5]),
        });
        let object = value.as_object().unwrap();
        assert_eq!(
            tls_termination_bytes(object, &["cert"], &[], "cert").unwrap(),
            [1, 2, 255]
        );
        assert_eq!(
            tls_termination_bytes(object, &["keyBase64"], &[], "key").unwrap(),
            [3, 4, 5]
        );
    }

    #[cfg(feature = "doh-tls")]
    #[test]
    fn tls_termination_rejects_empty_certificate_set_before_runtime_use() {
        let config = GoProxyRuntimeConfig {
            id: "tls-termination-empty".to_owned(),
            name: "tls-termination-empty".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["tls_termination".to_owned()],
            layers: vec![GoProxyLayer {
                kind: "tls_termination".to_owned(),
                config: serde_json::json!({"tls": {"certificates": []}}),
            }],
            transport: GoProxyTransport::TlsTermination,
            data_json: br#"{"chain":[]}"#.to_vec(),
        };
        let parent = Arc::new(DirectAsyncProxy {
            timeout: Duration::from_secs(1),
        });
        let error = match build_tls_termination_proxy(&config, parent) {
            Ok(_) => panic!("empty TLS termination certificate set must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("TLS termination"));
    }

    #[tokio::test]
    async fn node_set_proxy_retries_a_failed_member() {
        let failed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let failed_address = failed_listener.local_addr().unwrap();
        drop(failed_listener);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });
        let proxy = NodeSetProxy::new(
            vec![
                Arc::new(FixedAsyncProxy {
                    address: failed_address,
                    timeout: Duration::from_secs(1),
                }),
                Arc::new(FixedAsyncProxy {
                    address,
                    timeout: Duration::from_secs(1),
                }),
            ],
            true,
        )
        .unwrap();
        let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        assert!(proxy.connect(&context).await.is_ok());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn runtime_selector_uses_node_tag_for_tcp_and_udp() {
        let config = GoProxyRuntimeConfig {
            id: "tagged-node".to_owned(),
            name: "tagged-node".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let mut snapshot = snapshot(config);
        snapshot.node_tags.push(yuhaiin_store::GoNodeTagRecord {
            id: "edge".to_owned(),
            name: "edge".to_owned(),
            members_json: br#"{"type":"node","hash":["tagged-node"]}"#.to_vec(),
            updated_at: 1,
        });
        let selector = snapshot
            .build_proxy_selector("", "", "", "", Duration::from_secs(1))
            .await
            .unwrap();
        for network in [yuhaiin_core::Network::Tcp, yuhaiin_core::Network::Udp] {
            let mut context = FlowContext::new(yuhaiin_core::Endpoint::ip(
                network,
                "192.0.2.1:443".parse().unwrap(),
            ));
            context.route_mode = RouteMode::Proxy;
            context.tag = Some("edge".to_owned());
            let selected = selector.select(&context);
            let tagged = if network == yuhaiin_core::Network::Udp {
                selector
                    .udp_tagged
                    .read()
                    .unwrap()
                    .get("edge")
                    .cloned()
                    .unwrap()
            } else {
                selector
                    .tagged
                    .read()
                    .unwrap()
                    .get("edge")
                    .cloned()
                    .unwrap()
            };
            assert!(Arc::ptr_eq(&selected, &tagged));
        }
    }

    #[test]
    fn base_proxy_build_uses_shared_snapshot_config_without_a_dto() {
        let config = GoProxyRuntimeConfig {
            id: "direct".to_owned(),
            name: "Direct".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let built =
            block_on(snapshot(config).build_proxy("direct", Duration::from_secs(1))).unwrap();
        assert_eq!(built.config.id, "direct");
        let _ = BaseProxyConfig {
            kind: BaseProxyKind::Direct,
            timeout: Duration::from_secs(1),
        };
    }

    #[tokio::test]
    async fn runtime_builds_go_http_mock_around_a_fixed_parent() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let expected =
                b"GET / HTTP/1.1\r\nHost: www.speedtest.cn\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n";
            let mut request = vec![0u8; expected.len()];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected);
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let config = GoProxyRuntimeConfig {
            id: "http-mock".to_owned(),
            name: "HTTP mock".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "http_mock".to_owned()],
            layers: vec![
                GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{
                            "host": address.ip().to_string(),
                            "port": address.port()
                        }]
                    }),
                },
                GoProxyLayer {
                    kind: "http_mock".to_owned(),
                    config: serde_json::json!({"data": []}),
                },
            ],
            transport: GoProxyTransport::HttpMock,
            data_json: Vec::new(),
        };
        let proxy = snapshot(config)
            .build_proxy("http-mock", Duration::from_secs(1))
            .await
            .unwrap()
            .proxy;
        let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        let mut stream = proxy.connect(&context).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[cfg(feature = "http-termination")]
    #[tokio::test]
    async fn runtime_builds_go_http_termination_around_a_fixed_parent() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(
                request.starts_with("get /runtime http/1.1\r\n"),
                "request={request:?}"
            );
            assert!(
                request.contains("host: runtime.example:80\r\n"),
                "request={request:?}"
            );
            assert!(
                request.contains("x-runtime: http-termination\r\n"),
                "request={request:?}"
            );
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nruntime",
                )
                .await
                .unwrap();
        });
        let config = GoProxyRuntimeConfig {
            id: "http-termination".to_owned(),
            name: "HTTP termination".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "http_termination".to_owned()],
            layers: vec![
                GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{
                            "host": address.ip().to_string(),
                            "port": address.port()
                        }]
                    }),
                },
                GoProxyLayer {
                    kind: "http_termination".to_owned(),
                    config: serde_json::json!({
                        "headers": {
                            "runtime.example": {
                                "headers": [{"key": "X-Runtime", "value": "http-termination"}]
                            }
                        }
                    }),
                },
            ],
            transport: GoProxyTransport::HttpTermination,
            data_json: Vec::new(),
        };
        let proxy = snapshot(config)
            .build_proxy("http-termination", Duration::from_secs(1))
            .await
            .unwrap()
            .proxy;
        let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        let mut stream = proxy.connect(&context).await.unwrap();
        stream
            .write_all(
                b"GET /runtime HTTP/1.1\r\nHost: runtime.example:80\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"runtime"));
        proxy.close().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn runtime_network_split_dispatches_tcp_and_udp_branches() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let config = GoProxyRuntimeConfig {
            id: "network-split".to_owned(),
            name: "network split".to_owned(),
            group_name: "default".to_owned(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "network_split".to_owned()],
            layers: vec![
                GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{
                            "host": target.ip().to_string(),
                            "port": target.port()
                        }]
                    }),
                },
                GoProxyLayer {
                    kind: "network_split".to_owned(),
                    config: serde_json::json!({
                        "tcp": {
                            "type": "proxy",
                            "proxy": {}
                        },
                        "udp": {"type": "drop", "drop": {}}
                    }),
                },
            ],
            transport: GoProxyTransport::NetworkSplit,
            data_json: Vec::new(),
        };
        let proxy = snapshot(config)
            .build_proxy("network-split", Duration::from_secs(1))
            .await
            .unwrap()
            .proxy;

        let tcp_context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            target,
        ));
        let mut stream = proxy.connect(&tcp_context).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");

        let udp_context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Udp,
            "127.0.0.1:53".parse().unwrap(),
        ));
        let datagram = proxy.open_datagram(&udp_context).await.unwrap();
        assert_eq!(
            datagram
                .send_to(b"drop", udp_context.destination.clone())
                .await
                .unwrap(),
            4
        );
        let mut dropped = [0u8; 8];
        let error = match datagram.recv_from(&mut dropped).await {
            Ok(_) => panic!("UDP must be dispatched to the drop branch"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Closed);

        datagram.close().await.unwrap();
        proxy.close().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn runtime_network_split_wraps_http2_tcp_branch_over_parent() {
        use bytes::Bytes;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = h2::server::handshake(socket).await.unwrap();
            while let Some(result) = connection.accept().await {
                let (request, mut respond) = result.unwrap();
                assert_eq!(request.method(), ::http::Method::CONNECT);
                assert_eq!(request.uri().host(), Some("localhost"));
                tokio::spawn(async move {
                    let mut body = request.into_body();
                    let mut send = respond
                        .send_response(::http::Response::new(()), false)
                        .unwrap();
                    while let Some(data) = body.data().await {
                        let Ok(data) = data else { break };
                        if body.flow_control().release_capacity(data.len()).is_err()
                            || send.send_data(data, false).is_err()
                        {
                            break;
                        }
                    }
                    let _ = send.send_data(Bytes::new(), true);
                });
            }
        });
        let config = GoProxyRuntimeConfig {
            id: "network-split-http2".to_owned(),
            name: "network split HTTP/2".to_owned(),
            group_name: "default".to_owned(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "network_split".to_owned()],
            layers: vec![
                GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{
                            "host": target.ip().to_string(),
                            "port": target.port()
                        }]
                    }),
                },
                GoProxyLayer {
                    kind: "network_split".to_owned(),
                    config: serde_json::json!({
                        "tcp": {
                            "type": "http2",
                            "http2": {"concurrency": 1, "max_streams": 1}
                        },
                        "udp": {"type": "direct", "direct": {}}
                    }),
                },
            ],
            transport: GoProxyTransport::NetworkSplit,
            data_json: Vec::new(),
        };
        let proxy = snapshot(config)
            .build_proxy("network-split-http2", Duration::from_secs(1))
            .await
            .unwrap()
            .proxy;
        let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        let mut stream = proxy.connect(&context).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");

        proxy.close().await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_builds_wireguard_from_go_layer() {
        let key = |value| base64::engine::general_purpose::STANDARD.encode([value; 32]);
        let config = GoProxyRuntimeConfig {
            id: "wireguard".to_owned(),
            name: "WireGuard".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["wireguard".to_owned()],
            layers: vec![GoProxyLayer {
                kind: "wireguard".to_owned(),
                config: serde_json::json!({
                    "secretKey": key(1),
                    "endpoint": ["10.0.0.2/32"],
                    "reserved": "AAAA",
                    "peers": [{
                        "publicKey": key(2),
                        "endpoint": "127.0.0.1:51820",
                        "allowedIps": ["0.0.0.0/0"]
                    }]
                }),
            }],
            transport: GoProxyTransport::Wireguard,
            data_json: Vec::new(),
        };
        let built = snapshot(config)
            .build_proxy("wireguard", Duration::from_secs(1))
            .await
            .unwrap();
        built.proxy.close().await.unwrap();
    }

    struct MappingResolver {
        address: std::net::Ipv4Addr,
        queries: Arc<Mutex<Vec<String>>>,
    }

    impl AsyncIpResolver for MappingResolver {
        fn resolve<'a>(
            &'a self,
            domain: &'a yuhaiin_core::DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            self.queries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(domain.to_string());
            let address = self.address;
            Box::pin(async move {
                Ok(IpSet {
                    v4: vec![address],
                    v6: Vec::new(),
                })
            })
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_wireguard_resolves_peer_and_domain_targets_with_configured_resolver() {
        let key = |value| base64::engine::general_purpose::STANDARD.encode([value; 32]);
        let config = GoProxyRuntimeConfig {
            id: "wireguard-domain".to_owned(),
            name: "WireGuard domain".to_owned(),
            group_name: "default".to_owned(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["wireguard".to_owned()],
            layers: vec![GoProxyLayer {
                kind: "wireguard".to_owned(),
                config: serde_json::json!({
                    "secretKey": key(3),
                    "endpoint": ["10.0.0.2/32"],
                    "peers": [{
                        "publicKey": key(4),
                        "endpoint": "peer-resolver-only.invalid:51820",
                        "allowedIps": ["0.0.0.0/0"]
                    }]
                }),
            }],
            transport: GoProxyTransport::Wireguard,
            data_json: Vec::new(),
        };
        let queries = Arc::new(Mutex::new(Vec::new()));
        let resolver = Arc::new(MappingResolver {
            address: std::net::Ipv4Addr::LOCALHOST,
            queries: Arc::clone(&queries),
        });
        let built = snapshot_with_resolver(config, resolver)
            .build_proxy("wireguard-domain", Duration::from_secs(1))
            .await
            .unwrap();
        let context = FlowContext::new(Endpoint::domain(
            yuhaiin_core::Network::Tcp,
            yuhaiin_core::DomainName::new("resolver-only.invalid").unwrap(),
            80,
        ));
        let _stream = built.proxy.connect(&context).await.unwrap();
        built.proxy.close().await.unwrap();

        assert_eq!(
            queries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_slice(),
            ["peer-resolver-only.invalid", "resolver-only.invalid"]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn standalone_build_proxy_resolves_domain_destinations() {
        let config = GoProxyRuntimeConfig {
            id: "direct".to_owned(),
            name: "Direct".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let built = snapshot(config)
            .build_proxy("direct", Duration::from_secs(1))
            .await
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut payload = [0u8; 18];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
                .await
                .unwrap();
            payload
        });
        let context = FlowContext::new(yuhaiin_core::Endpoint::domain(
            yuhaiin_core::Network::Tcp,
            yuhaiin_core::DomainName::new("localhost").unwrap(),
            address.port(),
        ));
        let mut stream = built.proxy.connect(&context).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"standalone-resolve")
            .await
            .unwrap();
        assert_eq!(server.await.unwrap(), *b"standalone-resolve");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn runtime_proxy_carries_node_network_interface_into_direct_socket() {
        let config = GoProxyRuntimeConfig {
            id: "direct-interface".to_owned(),
            name: "Direct interface".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: vec![GoProxyLayer {
                kind: "direct".to_owned(),
                config: serde_json::json!({ "network_interface": "lo" }),
            }],
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let built = snapshot(config)
            .build_proxy("direct-interface", Duration::from_secs(1))
            .await
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            address,
        ));
        let mut stream = built.proxy.connect(&context).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"interface")
            .await
            .unwrap();
        let mut accepted = server.await.unwrap();
        let mut payload = [0u8; 9];
        tokio::io::AsyncReadExt::read_exact(&mut accepted, &mut payload)
            .await
            .unwrap();
        assert_eq!(&payload, b"interface");
    }

    #[test]
    fn proxy_selector_assembles_snapshot_proxies_and_safe_builtin_slots() {
        let config = GoProxyRuntimeConfig {
            id: "proxy".to_owned(),
            name: "Proxy".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let selector = block_on(snapshot(config).build_proxy_selector(
            "",
            "proxy",
            "",
            "",
            Duration::from_secs(1),
        ))
        .unwrap();

        let mut context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        context.route_mode = RouteMode::Proxy;
        context.skip_route = true;
        let selected = selector.select(&context);
        context.route_mode = RouteMode::Direct;
        let direct = selector.select(&context);
        assert!(!Arc::ptr_eq(&selected, &direct));
    }

    #[test]
    fn proxy_selector_uses_independent_tcp_and_udp_selected_nodes() {
        let make_direct = |id: &str| GoProxyRuntimeConfig {
            id: id.to_owned(),
            name: id.to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let mut snapshot = snapshot(make_direct("tcp-node"));
        snapshot.proxies.push(make_direct("udp-node"));
        let selector = block_on(snapshot.build_proxy_selector_with_udp(
            "",
            "tcp-node",
            "udp-node",
            "",
            "",
            Duration::from_secs(1),
        ))
        .unwrap();

        let mut tcp = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        tcp.route_mode = RouteMode::Proxy;
        let mut udp = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Udp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        udp.route_mode = RouteMode::Proxy;
        udp.skip_route = true;

        let tcp_proxy = selector.select(&tcp);
        let udp_proxy = selector.select(&udp);
        assert!(!Arc::ptr_eq(&tcp_proxy, &udp_proxy));
        assert!(selector.active_node_ids().contains(&"udp-node".to_owned()));
        selector.route_context(&mut udp);
        assert_eq!(udp.outbound.as_deref(), Some("udp-node"));
    }

    #[test]
    fn runtime_selector_blocks_inbound_listener_cycle_before_route_rules() {
        let config = GoProxyRuntimeConfig {
            id: "proxy".to_owned(),
            name: "Proxy".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let selector = block_on(snapshot(config).build_proxy_selector(
            "",
            "proxy",
            "",
            "",
            Duration::from_secs(1),
        ))
        .unwrap();
        let address = "127.0.0.1:18080".parse().unwrap();
        let mut context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            address,
        ));
        context.local_addr = Some(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            address,
        ));

        selector.route_context(&mut context);

        assert_eq!(context.route_mode, RouteMode::Block);
        assert!(context.skip_route);
        assert_eq!(context.tag.as_deref(), Some("loopback cycle"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn selector_resolves_domain_for_direct_socket_without_losing_protocol_domain() {
        let config = GoProxyRuntimeConfig {
            id: "proxy".to_owned(),
            name: "Proxy".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let selector = snapshot(config)
            .build_proxy_selector("", "proxy", "", "", Duration::from_secs(1))
            .await
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut payload = [0u8; 15];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
                .await
                .unwrap();
            payload
        });

        let mut context = FlowContext::new(yuhaiin_core::Endpoint::domain(
            yuhaiin_core::Network::Tcp,
            yuhaiin_core::DomainName::new("localhost").unwrap(),
            address.port(),
        ));
        context.route_mode = RouteMode::Proxy;
        let selected = selector.select(&context);
        let mut stream = selected.connect(&context).await.unwrap();
        assert_eq!(
            context.effective_destination().host().unwrap().as_str(),
            "localhost"
        );
        assert!(context.resolved_destination.is_none());
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"resolved-domain")
            .await
            .unwrap();
        assert_eq!(server.await.unwrap(), *b"resolved-domain");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn selector_resolves_domain_for_direct_udp_even_when_proxy_dns_is_skipped() {
        let config = GoProxyRuntimeConfig {
            id: "proxy".to_owned(),
            name: "Proxy".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let selector = snapshot(config)
            .build_proxy_selector("", "proxy", "", "", Duration::from_secs(1))
            .await
            .unwrap();
        let destination = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = destination.local_addr().unwrap().port();
        let mut context = FlowContext::new(yuhaiin_core::Endpoint::domain(
            yuhaiin_core::Network::Udp,
            yuhaiin_core::DomainName::new("localhost").unwrap(),
            port,
        ));
        context.route_mode = RouteMode::Proxy;
        context.resolver_policy.udp_skip_resolve_target = true;

        selector
            .select(&context)
            .open_datagram(&context)
            .await
            .expect("direct transport must resolve its own UDP target");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn live_selector_reload_replaces_data_plane_settings() {
        let config = GoProxyRuntimeConfig {
            id: "proxy".to_owned(),
            name: "Proxy".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let mut first = snapshot(config.clone());
        first.settings.udp_buffer_size = 4096;
        first.settings.relay_buffer_size = 8192;
        first.settings.udp_ringbuffer_size = 512;
        first.socket_bind_addresses =
            Arc::from(vec!["127.0.0.2".parse::<std::net::IpAddr>().unwrap()].into_boxed_slice());
        let selector = first
            .build_proxy_selector("", "proxy", "", "", Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(selector.udp_buffer_size(), 4096);
        assert_eq!(selector.relay_buffer_size(), 8192);
        assert_eq!(selector.udp_ringbuffer_size(), 512);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let peer = std::thread::spawn(move || listener.accept().unwrap().0.peer_addr().unwrap());
        let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            address,
        ));
        let _stream = selector.select(&context).connect(&context).await.unwrap();
        assert_eq!(
            peer.join().unwrap().ip(),
            "127.0.0.2".parse::<std::net::IpAddr>().unwrap()
        );

        let mut next = snapshot(config);
        next.settings.udp_buffer_size = 2048;
        next.settings.relay_buffer_size = 2049;
        next.settings.udp_ringbuffer_size = 100;
        next.socket_bind_addresses =
            Arc::from(vec!["127.0.0.2".parse::<std::net::IpAddr>().unwrap()].into_boxed_slice());
        let prepared = selector.prepare(&next).await.unwrap();
        selector.replace(prepared);
        assert_eq!(selector.udp_buffer_size(), 2048);
        assert_eq!(selector.relay_buffer_size(), 2049);
        assert_eq!(selector.udp_ringbuffer_size(), 100);
    }

    struct TestGeo;

    impl GeoLookup for TestGeo {
        fn country_code(&self, _address: std::net::IpAddr) -> yuhaiin_core::Result<Option<String>> {
            Ok(Some("ZZ".to_owned()))
        }
    }

    #[test]
    fn selector_populates_hosts_and_outbound_geo_before_proxy_connect() {
        let config = GoProxyRuntimeConfig {
            id: "proxy".to_owned(),
            name: "Proxy".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let mut snapshot = snapshot(config);
        let domain = yuhaiin_core::DomainName::new("hosts.example").unwrap();
        snapshot
            .hosts
            .insert_ip(domain.clone(), "192.0.2.44".parse().unwrap())
            .unwrap();
        snapshot.geo = Some(Arc::new(TestGeo));
        let selector =
            block_on(snapshot.build_proxy_selector("", "proxy", "", "", Duration::from_secs(1)))
                .unwrap();

        let mut context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.44:443".parse().unwrap(),
        ));
        context.original_domain = Some(domain);
        context.route_mode = RouteMode::Direct;
        selector.route_context(&mut context);

        assert_eq!(context.hosts.as_deref(), Some("hosts.example:443"));
        assert_eq!(context.outbound_geo.as_deref(), Some("ZZ"));
        assert_eq!(
            context.outbound_addr,
            Some(Endpoint::ip(
                yuhaiin_core::Network::Tcp,
                "192.0.2.44:443".parse().unwrap(),
            ))
        );
    }

    #[tokio::test]
    async fn trojan_outbound_wraps_fixed_parent_and_preserves_connect_payload() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let hash = trojan::password_hash(b"secret");
            let request = trojan::read_request(&mut stream, &hash).await.unwrap();
            assert_eq!(request.command, Command::Connect);
            let mut payload = [0u8; 5];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &payload)
                .await
                .unwrap();
        });
        let parent: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
            address,
            timeout: Duration::from_secs(2),
        });
        let proxy = yuhaiin_protocol::trojan::TrojanProxy::new(parent, "secret");
        let destination = yuhaiin_core::Endpoint::domain(
            yuhaiin_core::Network::Tcp,
            yuhaiin_core::DomainName::new("example.com").unwrap(),
            443,
        );
        let context = yuhaiin_core::FlowContext::new(destination);
        let mut stream = proxy.connect(&context).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"hello")
            .await
            .unwrap();
        let mut echoed = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut echoed)
            .await
            .unwrap();
        assert_eq!(&echoed, b"hello");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn go_aead_layer_builds_stream_transport_over_fixed_parent() {
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_address = tcp_listener.local_addr().unwrap();
        let tcp_server = tokio::spawn(async move {
            let (stream, _) = tcp_listener.accept().await.unwrap();
            let mut stream = yuhaiin_protocol::aead::server(
                Box::new(stream),
                b"secret",
                yuhaiin_protocol::aead::CryptoMethod::XChacha20Poly1305,
            )
            .await
            .unwrap();
            let mut payload = [0u8; 5];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &payload)
                .await
                .unwrap();
        });
        let config = GoProxyRuntimeConfig {
            id: "aead".to_owned(),
            name: "aead".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "aead".to_owned()],
            layers: vec![
                GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{"host": "127.0.0.1", "port": tcp_address.port()}]
                    }),
                },
                GoProxyLayer {
                    kind: "aead".to_owned(),
                    config: serde_json::json!({
                        "password": "secret",
                        "cryptoMethod": "AeadCryptoMethod_XChacha20Poly1305"
                    }),
                },
            ],
            transport: GoProxyTransport::Aead,
            data_json: serde_json::json!({"chain": []}).to_string().into_bytes(),
        };
        let built = snapshot(config)
            .build_proxy("aead", Duration::from_secs(2))
            .await
            .unwrap();
        let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        let mut stream = built.proxy.connect(&context).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"hello")
            .await
            .unwrap();
        let mut echoed = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut echoed)
            .await
            .unwrap();
        assert_eq!(&echoed, b"hello");
        tcp_server.await.unwrap();
    }

    #[tokio::test]
    async fn go_aead_layer_builds_authenticated_udp_over_fixed_parent() {
        let udp_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp_socket.local_addr().unwrap();
        let udp_server = tokio::spawn(async move {
            let mut packet = [0u8; 2048];
            let (length, peer) = udp_socket.recv_from(&mut packet).await.unwrap();
            let payload = yuhaiin_protocol::aead::decrypt_packet(
                &packet[..length],
                b"secret",
                yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
            )
            .unwrap();
            assert_eq!(payload, b"udp-hello");
            let reply = yuhaiin_protocol::aead::encrypt_packet(
                b"udp-world",
                b"secret",
                yuhaiin_protocol::aead::CryptoMethod::Chacha20Poly1305,
            )
            .unwrap();
            udp_socket.send_to(&reply, peer).await.unwrap();
        });
        let config = GoProxyRuntimeConfig {
            id: "aead-udp".to_owned(),
            name: "aead-udp".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "aead".to_owned()],
            layers: vec![
                GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{"host": "127.0.0.1", "port": udp_address.port()}]
                    }),
                },
                GoProxyLayer {
                    kind: "aead".to_owned(),
                    config: serde_json::json!({"password": "secret"}),
                },
            ],
            transport: GoProxyTransport::Aead,
            data_json: serde_json::json!({"chain": []}).to_string().into_bytes(),
        };
        let built = snapshot(config)
            .build_proxy("aead-udp", Duration::from_secs(2))
            .await
            .unwrap();
        let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Udp,
            "192.0.2.1:5353".parse().unwrap(),
        ));
        let datagram = built.proxy.open_datagram(&context).await.unwrap();
        let target = context.effective_destination();
        datagram.send_to(b"udp-hello", target).await.unwrap();
        let mut response = [0u8; 64];
        let (length, _) = datagram.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..length], b"udp-world");
        udp_server.await.unwrap();
    }

    #[tokio::test]
    async fn go_trojan_layer_builds_a_runtime_proxy_without_dropping_unknown_fields() {
        let address: std::net::SocketAddr = "127.0.0.1:24443".parse().unwrap();
        let config = GoProxyRuntimeConfig {
            id: "trojan".to_owned(),
            name: "trojan".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "trojan".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":address.port()}]}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "trojan".to_owned(),
                    config: serde_json::json!({"password":"secret","futureField":true}),
                },
            ],
            transport: GoProxyTransport::Trojan,
            data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
        };
        let built = snapshot(config)
            .build_proxy("trojan", Duration::from_secs(2))
            .await
            .unwrap();
        let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        assert!(built.proxy.connect(&context).await.is_err());
    }

    #[tokio::test]
    async fn go_shadowsocks_layer_builds_a_runtime_proxy_without_dropping_unknown_fields() {
        let config = GoProxyRuntimeConfig {
            id: "shadowsocks".to_owned(),
            name: "shadowsocks".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "shadowsocks".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24444}]}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "shadowsocks".to_owned(),
                    config: serde_json::json!({
                        "method":"AEAD_AES_256_GCM",
                        "password":"secret",
                        "futureField":true
                    }),
                },
            ],
            transport: GoProxyTransport::Shadowsocks,
            data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
        };
        let built = snapshot(config)
            .build_proxy("shadowsocks", Duration::from_secs(2))
            .await
            .unwrap();
        let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        assert!(built.proxy.connect(&context).await.is_err());
    }

    #[tokio::test]
    async fn go_shadowsocks_obfs_http_layer_builds_before_protocol_framing() {
        let config = GoProxyRuntimeConfig {
            id: "shadowsocks-obfs-http".to_owned(),
            name: "shadowsocks-obfs-http".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec![
                "fixedv2".to_owned(),
                "obfs_http".to_owned(),
                "shadowsocks".to_owned(),
            ],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24445}]}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "obfs_http".to_owned(),
                    config: serde_json::json!({"host":"obfs.example","port":"80"}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "shadowsocks".to_owned(),
                    config: serde_json::json!({"method":"AEAD_AES_256_GCM","password":"secret"}),
                },
            ],
            transport: GoProxyTransport::Shadowsocks,
            data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
        };
        let built = snapshot(config)
            .build_proxy("shadowsocks-obfs-http", Duration::from_secs(2))
            .await
            .unwrap();
        let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        assert!(built.proxy.connect(&context).await.is_err());
    }

    #[tokio::test]
    async fn go_shadowsocksr_layer_builds_a_runtime_proxy() {
        let config = GoProxyRuntimeConfig {
            id: "shadowsocksr".to_owned(),
            name: "shadowsocksr".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "shadowsocksr".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24447}]}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "shadowsocksr".to_owned(),
                    config: serde_json::json!({
                        "method":"aes-256-ctr",
                        "password":"secret",
                        "protocol":"auth_aes128_md5",
                        "obfs":"plain",
                        "futureField":true
                    }),
                },
            ],
            transport: GoProxyTransport::Shadowsocksr,
            data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
        };
        let built = snapshot(config)
            .build_proxy("shadowsocksr", Duration::from_secs(2))
            .await
            .unwrap();
        let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        assert!(built.proxy.connect(&context).await.is_err());
    }

    #[tokio::test]
    async fn go_vless_layer_builds_a_runtime_proxy_without_password_assumption() {
        let config = GoProxyRuntimeConfig {
            id: "vless".to_owned(),
            name: "vless".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "vless".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24445}]}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "vless".to_owned(),
                    config: serde_json::json!({
                        "uuid":"00112233-4455-6677-8899-aabbccddeeff",
                        "futureField":true
                    }),
                },
            ],
            transport: GoProxyTransport::Vless,
            data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
        };
        let built = snapshot(config)
            .build_proxy("vless", Duration::from_secs(2))
            .await
            .unwrap();
        let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        assert!(built.proxy.connect(&context).await.is_err());
    }

    #[tokio::test]
    async fn go_stream_protocols_build_over_http2_transport_chain() {
        for (name, transport, protocol_layer) in [
            (
                "vless-http2",
                GoProxyTransport::Vless,
                serde_json::json!({
                    "type": "vless",
                    "vless": {"uuid": "00112233-4455-6677-8899-aabbccddeeff"}
                }),
            ),
            (
                "vmess-http2",
                GoProxyTransport::Vmess,
                serde_json::json!({
                    "type": "vmess",
                    "vmess": {
                        "id": "00112233-4455-6677-8899-aabbccddeeff",
                        "aid": "0",
                        "security": "aes-128-gcm"
                    }
                }),
            ),
            (
                "trojan-http2",
                GoProxyTransport::Trojan,
                serde_json::json!({
                    "type": "trojan",
                    "trojan": {"password": "runtime-password"}
                }),
            ),
        ] {
            let protocol = protocol_layer["type"].as_str().unwrap();
            let config = GoProxyRuntimeConfig {
                id: name.to_owned(),
                name: name.to_owned(),
                group_name: "default".to_owned(),
                origin: "go".to_owned(),
                enabled: true,
                chain_types: vec![
                    "fixedv2".to_owned(),
                    "http2".to_owned(),
                    protocol.to_owned(),
                ],
                layers: vec![yuhaiin_store::GoProxyLayer {
                    kind: protocol.to_owned(),
                    config: protocol_layer[protocol].clone(),
                }],
                transport,
                data_json: serde_json::to_vec(&serde_json::json!({
                    "id": name,
                    "chain": [
                        {"type": "fixedv2", "fixedv2": {
                            "addresses": [{"host": "127.0.0.1", "port": 24448}]
                        }},
                        {"type": "http2", "http2": {"concurrency": 1}},
                        protocol_layer
                    ]
                }))
                .unwrap(),
            };
            let built = snapshot(config)
                .build_proxy(name, Duration::from_secs(2))
                .await;
            if let Err(error) = built {
                panic!("{name} HTTP/2 transport failed: {error}");
            }
        }
    }

    #[tokio::test]
    async fn go_stream_protocol_http2_rejects_missing_transport_chain() {
        let config = GoProxyRuntimeConfig {
            id: "vless-http2-invalid".to_owned(),
            name: "vless-http2-invalid".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "http2".to_owned(), "vless".to_owned()],
            layers: vec![yuhaiin_store::GoProxyLayer {
                kind: "vless".to_owned(),
                config: serde_json::json!({
                    "uuid": "00112233-4455-6677-8899-aabbccddeeff"
                }),
            }],
            transport: GoProxyTransport::Vless,
            data_json: serde_json::to_vec(&serde_json::json!({"chain": []})).unwrap(),
        };
        let error = match snapshot(config)
            .build_proxy("vless-http2-invalid", Duration::from_secs(2))
            .await
        {
            Ok(_) => panic!("invalid HTTP/2 protocol chain unexpectedly built"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::InvalidInput);
        assert!(error.message.contains("chain"));
    }

    #[tokio::test]
    async fn go_vmess_layer_builds_a_modern_runtime_proxy() {
        let config = GoProxyRuntimeConfig {
            id: "vmess".to_owned(),
            name: "vmess".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "vmess".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24446}]}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "vmess".to_owned(),
                    config: serde_json::json!({
                        "id":"00112233-4455-6677-8899-aabbccddeeff",
                        "aid":"0",
                        "security":"aes-128-gcm",
                        "futureField":true
                    }),
                },
            ],
            transport: GoProxyTransport::Vmess,
            data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
        };
        let built = snapshot(config)
            .build_proxy("vmess", Duration::from_secs(2))
            .await
            .unwrap();
        let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        assert!(built.proxy.connect(&context).await.is_err());
    }

    #[tokio::test]
    async fn go_vmess_legacy_alter_id_builds_runtime_proxy() {
        let config = GoProxyRuntimeConfig {
            id: "vmess-legacy".to_owned(),
            name: "vmess-legacy".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "vmess".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24447}]}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "vmess".to_owned(),
                    config: serde_json::json!({
                        "id":"00112233-4455-6677-8899-aabbccddeeff",
                        "aid":"2",
                        "security":"aes-128-gcm"
                    }),
                },
            ],
            transport: GoProxyTransport::Vmess,
            data_json: Vec::new(),
        };
        let built = snapshot(config)
            .build_proxy("vmess-legacy", Duration::from_secs(2))
            .await
            .unwrap();
        let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        assert!(built.proxy.connect(&context).await.is_err());
    }

    #[cfg(feature = "doh-tls")]
    #[tokio::test]
    async fn go_trojan_layer_builds_tls_transport_before_protocol_wrapper() {
        let config = GoProxyRuntimeConfig {
            id: "trojan-tls".to_owned(),
            name: "trojan-tls".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "tls".to_owned(), "trojan".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24443}]}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "tls".to_owned(),
                    config: serde_json::json!({"servernames":["example.com"], "insecure_skip_verify": true}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "trojan".to_owned(),
                    config: serde_json::json!({"password":"secret"}),
                },
            ],
            transport: GoProxyTransport::Trojan,
            data_json: Vec::new(),
        };
        let built = snapshot(config)
            .build_proxy("trojan-tls", Duration::from_secs(2))
            .await
            .unwrap();
        assert!(
            built
                .proxy
                .ping(&FlowContext::new(yuhaiin_core::Endpoint::ip(
                    yuhaiin_core::Network::Tcp,
                    "192.0.2.1:443".parse().unwrap(),
                )))
                .await
                .is_err()
        );
    }

    #[test]
    fn runtime_builds_native_yuubinsya_udp_from_go_layers() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let password_hash = yuhaiin_core::yuubinsya::derive_salt(b"password");
            let server =
                YuubinsyaUdpServer::bind("127.0.0.1:0".parse().unwrap(), password_hash, false)
                    .await
                    .unwrap();
            let server_address = server.local_addr().unwrap().addr().unwrap();
            let config = GoProxyRuntimeConfig {
                id: "yuubinsya-udp".to_owned(),
                name: "yuubinsya-udp".to_owned(),
                group_name: "default".to_owned(),
                origin: "go".to_owned(),
                enabled: true,
                chain_types: vec!["fixedv2".to_owned(), "yuubinsya".to_owned()],
                layers: vec![
                    yuhaiin_store::GoProxyLayer {
                        kind: "fixedv2".to_owned(),
                        config: serde_json::json!({
                            "addresses": [{
                                "host": server_address.ip().to_string(),
                                "port": server_address.port()
                            }]
                        }),
                    },
                    yuhaiin_store::GoProxyLayer {
                        kind: "yuubinsya".to_owned(),
                        config: serde_json::json!({ "password": "password" }),
                    },
                ],
                transport: GoProxyTransport::Yuubinsya,
                data_json: Vec::new(),
            };
            let proxy = snapshot(config)
                .build_proxy("yuubinsya-udp", Duration::from_secs(3))
                .await
                .unwrap()
                .proxy;
            let target = yuhaiin_core::Endpoint::domain(
                yuhaiin_core::Network::Udp,
                yuhaiin_core::DomainName::new("example.com").unwrap(),
                53,
            );
            let context = FlowContext::new(target.clone());
            let datagram = proxy.open_datagram(&context).await.unwrap();
            datagram.send_to(b"query", target.clone()).await.unwrap();
            let mut buffer = [0; 64];
            let (length, decoded_target, peer) = server.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"query");
            assert_eq!(decoded_target, target);
            server
                .send_to(b"answer", decoded_target.clone(), peer)
                .await
                .unwrap();
            let (length, response_target) = datagram.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"answer");
            assert_eq!(response_target, decoded_target);
        });
    }

    #[test]
    fn runtime_builds_simple_go_yuubinsya_uot_chain_without_four_layer_assumption() {
        let config = GoProxyRuntimeConfig {
            id: "yuubinsya-uot".to_owned(),
            name: "yuubinsya-uot".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "yuubinsya".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{ "host": "127.0.0.1", "port": 40501 }]
                    }),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "yuubinsya".to_owned(),
                    config: serde_json::json!({
                        "password": "password",
                        "udp_over_stream": true,
                        "udp_coalesce": true
                    }),
                },
            ],
            transport: GoProxyTransport::Yuubinsya,
            data_json: serde_json::json!({
                "chain": [
                    { "type": "fixedv2", "fixedv2": {
                        "addresses": [{ "host": "127.0.0.1", "port": 40501 }]
                    }},
                    { "type": "yuubinsya", "yuubinsya": {
                        "password": "password",
                        "udp_over_stream": true,
                        "udp_coalesce": true
                    }}
                ]
            })
            .to_string()
            .into_bytes(),
        };
        let built = block_on(snapshot(config).build_proxy("yuubinsya-uot", Duration::from_secs(1)))
            .unwrap();
        let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        let error = match block_on(built.proxy.connect(&context)) {
            Ok(_) => panic!("simple Yuubinsya UOT must reject TCP stream connect"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Unsupported);
    }

    #[test]
    fn runtime_routes_go_websocket_http2_chain_to_chain_builder() {
        let config = GoProxyRuntimeConfig {
            id: "websocket-chain".to_owned(),
            name: "websocket-chain".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec![
                "fixedv2".to_owned(),
                "websocket".to_owned(),
                "http2".to_owned(),
                "yuubinsya".to_owned(),
            ],
            layers: Vec::new(),
            transport: GoProxyTransport::Yuubinsya,
            data_json: serde_json::json!({
                "chain": [
                    {"type": "fixedv2", "fixedv2": {
                        "addresses": [{"host": "127.0.0.1:40501"}]
                    }},
                    {"type": "websocket", "websocket": {
                        "host": "localhost", "path": "/proxy/ws"
                    }},
                    {"type": "http2", "http2": {"concurrency": 2}},
                    {"type": "yuubinsya", "yuubinsya": {
                        "password": "password"
                    }}
                ]
            })
            .to_string()
            .into_bytes(),
        };
        let built =
            block_on(snapshot(config).build_proxy("websocket-chain", Duration::from_secs(1)))
                .unwrap();
        assert_eq!(built.config.id, "websocket-chain");
    }

    #[cfg(feature = "websocket")]
    #[test]
    fn runtime_builds_vless_over_websocket_transport_chain() {
        let config = GoProxyRuntimeConfig {
            id: "vless-websocket".to_owned(),
            name: "vless-websocket".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec![
                "fixedv2".to_owned(),
                "websocket".to_owned(),
                "vless".to_owned(),
            ],
            layers: vec![
                GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{"host": "127.0.0.1", "port": 40501}]
                    }),
                },
                GoProxyLayer {
                    kind: "websocket".to_owned(),
                    config: serde_json::json!({"host": "localhost", "path": "/vless"}),
                },
                GoProxyLayer {
                    kind: "vless".to_owned(),
                    config: serde_json::json!({
                        "uuid": "00000000-0000-0000-0000-000000000001"
                    }),
                },
            ],
            transport: GoProxyTransport::Vless,
            data_json: serde_json::json!({}).to_string().into_bytes(),
        };
        let built =
            block_on(snapshot(config).build_proxy("vless-websocket", Duration::from_secs(1)))
                .unwrap();
        assert_eq!(built.config.id, "vless-websocket");
    }

    #[cfg(feature = "websocket")]
    #[test]
    fn runtime_builds_vmess_over_websocket_transport_chain() {
        let config = GoProxyRuntimeConfig {
            id: "vmess-websocket".to_owned(),
            name: "vmess-websocket".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec![
                "fixedv2".to_owned(),
                "websocket".to_owned(),
                "vmess".to_owned(),
            ],
            layers: vec![
                GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{"host": "127.0.0.1", "port": 40502}]
                    }),
                },
                GoProxyLayer {
                    kind: "websocket".to_owned(),
                    config: serde_json::json!({"host": "localhost", "path": "/vmess"}),
                },
                GoProxyLayer {
                    kind: "vmess".to_owned(),
                    config: serde_json::json!({
                        "id": "00000000-0000-0000-0000-000000000001",
                        "aid": 0,
                        "security": "auto"
                    }),
                },
            ],
            transport: GoProxyTransport::Vmess,
            data_json: serde_json::json!({}).to_string().into_bytes(),
        };
        let built =
            block_on(snapshot(config).build_proxy("vmess-websocket", Duration::from_secs(1)))
                .unwrap();
        assert_eq!(built.config.id, "vmess-websocket");
    }

    #[cfg(feature = "websocket")]
    #[test]
    fn runtime_builds_trojan_over_websocket_transport_chain() {
        let config = GoProxyRuntimeConfig {
            id: "trojan-websocket".to_owned(),
            name: "trojan-websocket".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec![
                "fixedv2".to_owned(),
                "websocket".to_owned(),
                "trojan".to_owned(),
            ],
            layers: vec![
                GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{"host": "127.0.0.1", "port": 40503}]
                    }),
                },
                GoProxyLayer {
                    kind: "websocket".to_owned(),
                    config: serde_json::json!({"host": "localhost", "path": "/trojan"}),
                },
                GoProxyLayer {
                    kind: "trojan".to_owned(),
                    config: serde_json::json!({"password": "secret"}),
                },
            ],
            transport: GoProxyTransport::Trojan,
            data_json: serde_json::json!({}).to_string().into_bytes(),
        };
        let built =
            block_on(snapshot(config).build_proxy("trojan-websocket", Duration::from_secs(1)))
                .unwrap();
        assert_eq!(built.config.id, "trojan-websocket");
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(value) => return value,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
