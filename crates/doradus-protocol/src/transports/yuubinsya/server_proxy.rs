//! Yuubinsya server proxy dispatch and observed-flow integration.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use super::super::{YuubinsyaHeader, YuubinsyaProtocol, decode_header_any};
use super::common::{io_error, read_header_bytes};
use super::observed_flow::{
    DnsTcpDecision, ObservedFlow, ObservedInbound, answer_dns_packet, copy_bidirectional_observed,
    endpoint_socket_addr, intercept_dns_tcp,
};
use super::server_udp_session::{ServerUdpMessage, ServerUdpSession};
use super::tcp_impl::{AsyncYuubinsyaPingServerSession, AsyncYuubinsyaTcpSession};
use super::uot_impl::AsyncYuubinsyaUotServerSession;

use doradus_core::flow::{Flow, FlowDirection, FlowKey, FlowObserver, FlowObserverGuard};
use doradus_core::proxy::AsyncProxy;
use doradus_core::{Endpoint, Error, ErrorKind, FlowContext, Result};
use doradus_types::{InboundDnsHandler, InboundStreamHandler};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

/// Server-side Yuubinsya protocol dispatcher.
///
/// The transport listener and HTTP/2 server remain outside this type. The
/// caller hands each authenticated stream to [`serve`], while the injected
/// `AsyncProxy` owns the actual outbound TCP/UDP routing policy. UOT sessions
/// are keyed by migrate id, so a new HTTP/2 stream can continue an existing
/// UDP flow instead of creating a second upstream datagram.
pub struct YuubinsyaServerProxy {
    password_hashes: Arc<[[u8; 32]]>,
    upstream: Arc<dyn AsyncProxy>,
    udp_buffer_size: usize,
    next_migrate_id: AtomicU64,
    udp_sessions: Mutex<HashMap<u64, Arc<ServerUdpSession>>>,
    udp_open_lock: Mutex<()>,
}

impl YuubinsyaServerProxy {
    pub fn new(password_hash: [u8; 32], upstream: Arc<dyn AsyncProxy>) -> Self {
        Self::new_with_password_hashes(vec![password_hash], upstream)
    }

    pub fn new_with_password_hashes(
        password_hashes: Vec<[u8; 32]>,
        upstream: Arc<dyn AsyncProxy>,
    ) -> Self {
        Self::new_with_password_hashes_and_udp_buffer_size(
            password_hashes,
            upstream,
            u16::MAX as usize,
        )
    }

    /// Construct a server with the payload buffer retained by each migrated
    /// UDP session. The legacy constructor keeps the maximum-sized default;
    /// runtime callers pass their configured `udpBufferSize` here.
    pub fn new_with_password_hashes_and_udp_buffer_size(
        password_hashes: Vec<[u8; 32]>,
        upstream: Arc<dyn AsyncProxy>,
        udp_buffer_size: usize,
    ) -> Self {
        let password_hashes = if password_hashes.is_empty() {
            vec![[0u8; 32]]
        } else {
            password_hashes
        };
        Self {
            password_hashes: password_hashes.into(),
            upstream,
            udp_buffer_size: udp_buffer_size.min(u16::MAX as usize).max(512),
            next_migrate_id: AtomicU64::new(1),
            udp_sessions: Mutex::new(HashMap::new()),
            udp_open_lock: Mutex::new(()),
        }
    }

    /// Serve one Yuubinsya stream. A closed stream returns its underlying I/O
    /// error; the listener may treat that as normal per-stream cleanup.
    pub async fn serve<S>(&self, stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.serve_inner(stream, None, None).await
    }

    /// Serve an inbound stream while publishing the same lifecycle and byte
    /// callbacks used by the TUN monitor. The chain crate owns protocol
    /// framing; the application only supplies the source endpoint and a
    /// context annotator for inbound/outbound metadata.
    pub async fn serve_observed<S, F>(
        &self,
        stream: S,
        source: SocketAddr,
        observer: Arc<dyn FlowObserver>,
        annotate: F,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: Fn(&mut FlowContext) + Send + Sync + 'static,
    {
        self.serve_observed_with_dns(stream, source, observer, annotate, None)
            .await
    }

    pub async fn serve_observed_with_dns<S, F>(
        &self,
        stream: S,
        source: SocketAddr,
        observer: Arc<dyn FlowObserver>,
        annotate: F,
        dns_handler: Option<Arc<dyn InboundDnsHandler>>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        F: Fn(&mut FlowContext) + Send + Sync + 'static,
    {
        self.serve_inner(
            stream,
            Some(ObservedInbound {
                source,
                observer,
                annotate: Arc::new(annotate),
            }),
            dns_handler,
        )
        .await
    }

    /// Serve the TCP part of one Yuubinsya stream through the shared inbound
    /// handler. Ping and UOT still use the server's protocol-local upstream;
    /// only the authenticated TCP payload is handed to the application seam.
    pub async fn serve_with_handler<S, H, F>(
        &self,
        mut stream: S,
        source: SocketAddr,
        handler: &H,
        observer: Arc<dyn FlowObserver>,
        annotate: F,
        dns_handler: Option<Arc<dyn InboundDnsHandler>>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        H: InboundStreamHandler<S> + ?Sized,
        F: Fn(&mut FlowContext) + Send + Sync + 'static,
    {
        let header_bytes = read_header_bytes(&mut stream).await?;
        let (header, _, password_hash) = decode_header_any(&self.password_hashes, &header_bytes)?;
        if header.protocol == YuubinsyaProtocol::Tcp {
            let destination = header.destination.ok_or_else(|| {
                Error::new(
                    ErrorKind::Protocol,
                    "Yuubinsya TCP header has no destination",
                )
            })?;
            return handler
                .handle_stream(stream, source, destination, "yuubinsya")
                .await;
        }

        self.serve_decoded(
            stream,
            header,
            password_hash,
            Some(ObservedInbound {
                source,
                observer,
                annotate: Arc::new(annotate),
            }),
            dns_handler,
        )
        .await
    }

    async fn serve_inner<S>(
        &self,
        mut stream: S,
        observed: Option<ObservedInbound>,
        dns_handler: Option<Arc<dyn InboundDnsHandler>>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let header_bytes = read_header_bytes(&mut stream).await?;
        let (header, _, password_hash) = decode_header_any(&self.password_hashes, &header_bytes)?;
        self.serve_decoded(stream, header, password_hash, observed, dns_handler)
            .await
    }

    async fn serve_decoded<S>(
        &self,
        stream: S,
        header: YuubinsyaHeader,
        password_hash: [u8; 32],
        observed: Option<ObservedInbound>,
        dns_handler: Option<Arc<dyn InboundDnsHandler>>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        match header.protocol {
            YuubinsyaProtocol::Tcp => {
                let destination = header.destination.ok_or_else(|| {
                    Error::new(
                        ErrorKind::Protocol,
                        "Yuubinsya TCP header has no destination",
                    )
                })?;
                let mut inbound = AsyncYuubinsyaTcpSession {
                    stream,
                    password_hash,
                    write_shutdown: false,
                };
                let mut context = FlowContext::new(destination.clone());
                let flow = observed.as_ref().map(|observed| {
                    context.source =
                        Some(Endpoint::ip(doradus_core::Network::Tcp, observed.source));
                    (observed.annotate)(&mut context);
                    FlowKey {
                        network: doradus_core::Network::Tcp,
                        source: observed.source,
                        destination: endpoint_socket_addr(&destination, observed.source),
                    }
                });
                let mut prefix = Vec::new();
                if let Some(handler) = dns_handler.as_deref() {
                    match intercept_dns_tcp(&mut inbound, handler, destination.port()).await? {
                        DnsTcpDecision::Answered { upload, download } => {
                            if let (Some(observed), Some(flow)) = (observed.as_ref(), flow) {
                                let _observation = FlowObserverGuard::open(
                                    Arc::clone(&observed.observer),
                                    Flow { key: flow },
                                    context,
                                );
                                observed.observer.bytes(flow, FlowDirection::Upload, upload);
                                observed
                                    .observer
                                    .bytes(flow, FlowDirection::Download, download);
                            }
                            return Ok(());
                        }
                        DnsTcpDecision::Forward(bytes) => prefix = bytes,
                    }
                }
                let mut outbound = self.upstream.connect(&context).await?;
                if !prefix.is_empty() {
                    outbound.write_all(&prefix).await.map_err(io_error)?;
                    if let (Some(observed), Some(flow)) = (observed.as_ref(), flow) {
                        observed
                            .observer
                            .bytes(flow, FlowDirection::Upload, prefix.len());
                    }
                }
                if let (Some(observed), Some(flow)) = (observed.as_ref(), flow) {
                    let _observation = FlowObserverGuard::open(
                        Arc::clone(&observed.observer),
                        Flow { key: flow },
                        context,
                    );
                    let result = copy_bidirectional_observed(
                        &mut inbound,
                        &mut outbound,
                        Arc::clone(&observed.observer),
                        flow,
                    )
                    .await
                    .map_err(io_error);
                    result?;
                } else {
                    tokio::io::copy_bidirectional(&mut inbound, &mut outbound)
                        .await
                        .map_err(io_error)?;
                }
                Ok(())
            }
            YuubinsyaProtocol::Ping => {
                let destination = header.destination.ok_or_else(|| {
                    Error::new(
                        ErrorKind::Protocol,
                        "Yuubinsya Ping header has no destination",
                    )
                })?;
                let mut session = AsyncYuubinsyaPingServerSession { stream };
                let context = FlowContext::new(destination);
                let initial = self.upstream.ping(&context).await;
                let follow_up = self.upstream.ping(&context).await;
                session.serve_one_probe(initial, follow_up).await
            }
            YuubinsyaProtocol::UdpWithMigrateId => {
                let requested = header.migrate_id.unwrap_or(0);
                let migrate_id = if requested == 0 {
                    self.allocate_migrate_id()
                } else {
                    requested
                };
                let mut session = AsyncYuubinsyaUotServerSession {
                    stream,
                    password_hash,
                    migrate_id,
                };
                session
                    .stream
                    .write_all(&migrate_id.to_be_bytes())
                    .await
                    .map_err(io_error)?;
                session.stream.flush().await.map_err(io_error)?;
                self.serve_uot(&mut session, observed.as_ref(), dns_handler.as_deref())
                    .await
            }
            YuubinsyaProtocol::Udp => Err(Error::new(
                ErrorKind::Unsupported,
                "native Yuubinsya UDP must use its datagram socket boundary",
            )),
        }
    }

    fn allocate_migrate_id(&self) -> u64 {
        loop {
            let id = self.next_migrate_id.fetch_add(1, Ordering::AcqRel);
            if id != 0 {
                return id;
            }
        }
    }

    async fn serve_uot<S>(
        &self,
        session: &mut AsyncYuubinsyaUotServerSession<S>,
        observed: Option<&ObservedInbound>,
        dns_handler: Option<&dyn InboundDnsHandler>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut destination, mut payload) = session.recv_from().await?;
        while let Some(handler) = dns_handler
            && handler.should_hijack(destination.port(), &payload)
        {
            let Some(response) = answer_dns_packet(handler, destination.port(), &payload).await?
            else {
                break;
            };
            session.send_to(&destination, &response).await?;
            (destination, payload) = session.recv_from().await?;
        }
        let mut context = FlowContext::new(destination.clone());
        context
            .udp_migrate_id
            .store(session.migrate_id, Ordering::Release);
        if let Some(observed) = observed {
            context.source = Some(Endpoint::ip(doradus_core::Network::Udp, observed.source));
            (observed.annotate)(&mut context);
        }
        let shared = self.udp_session(session.migrate_id, &context).await?;
        if context.outbound_local_addr.is_none()
            && let Ok(local_addr) = shared.local_addr()
            && local_addr.addr().is_some()
        {
            context.outbound_local_addr = Some(local_addr);
        }
        let (sender, mut responses) = shared.register(destination.clone()).await;
        let mut observed_flows = HashMap::<Endpoint, ObservedFlow>::new();
        let result: Result<()> = async {
            if let Some(observed) = observed {
                let flow = FlowKey {
                    network: doradus_core::Network::Udp,
                    source: observed.source,
                    destination: endpoint_socket_addr(&destination, observed.source),
                };
                let observation = FlowObserverGuard::open(
                    Arc::clone(&observed.observer),
                    Flow { key: flow },
                    context,
                );
                observed_flows.insert(
                    destination.clone(),
                    ObservedFlow {
                        flow,
                        _observation: observation,
                    },
                );
                observed.observer.bytes(flow, FlowDirection::Upload, payload.len());
            }
            shared.send_to(&payload, destination).await?;
            loop {
                tokio::select! {
                    incoming = session.recv_from() => {
                        let (destination, payload) = incoming?;
                        if let Some(handler) = dns_handler
                            && handler.should_hijack(destination.port(), &payload)
                            && let Some(response) =
                                answer_dns_packet(handler, destination.port(), &payload).await?
                        {
                            session.send_to(&destination, &response).await?;
                            continue;
                        }
                        if let Some(observed) = observed {
                            let flow = if let Some(flow) = observed_flows.get(&destination) {
                                flow.flow
                            } else {
                                let mut context = FlowContext::new(destination.clone());
                                context.source = Some(Endpoint::ip(doradus_core::Network::Udp, observed.source));
                                context.udp_migrate_id.store(session.migrate_id, Ordering::Release);
                                (observed.annotate)(&mut context);
                                if let Ok(local_addr) = shared.local_addr()
                                    && local_addr.addr().is_some()
                                {
                                    context.outbound_local_addr = Some(local_addr);
                                }
                                let flow = FlowKey {
                                    network: doradus_core::Network::Udp,
                                    source: observed.source,
                                    destination: endpoint_socket_addr(&destination, observed.source),
                                };
                                let observation = FlowObserverGuard::open(
                                    Arc::clone(&observed.observer),
                                    Flow { key: flow },
                                    context,
                                );
                                observed_flows.insert(
                                    destination.clone(),
                                    ObservedFlow {
                                        flow,
                                        _observation: observation,
                                    },
                                );
                                flow
                            };
                            observed.observer.bytes(flow, FlowDirection::Upload, payload.len());
                        }
                        shared.route(destination.clone(), &sender).await;
                        shared.send_to(&payload, destination).await?;
                    }
                    response = responses.recv() => {
                        match response {
                            Some(ServerUdpMessage::Data { source, payload }) => {
                                shared.touch();
                                session.send_to(&source, &payload).await?;
                                if let Some(observed) = observed
                                    && let Some(flow) = observed_flows.get(&source)
                                {
                                    observed.observer.bytes(
                                        flow.flow,
                                        FlowDirection::Download,
                                        payload.len(),
                                    );
                                }
                            }
                            Some(ServerUdpMessage::Closed) | None => {
                                return Err(Error::new(
                                    ErrorKind::Closed,
                                    "Yuubinsya upstream UDP session closed",
                                ));
                            }
                        }
                    }
                }
            }
        }
        .await;
        drop(observed_flows);
        shared.unregister_sender(&sender).await;
        result
    }

    async fn udp_session(
        &self,
        migrate_id: u64,
        context: &FlowContext,
    ) -> Result<Arc<ServerUdpSession>> {
        let _open_guard = self.udp_open_lock.lock().await;
        let now = Instant::now();
        let stale = {
            let mut sessions = self.udp_sessions.lock().await;
            let mut stale = Vec::new();
            sessions.retain(|_, session| {
                if session.is_idle(now) {
                    stale.push(Arc::clone(session));
                    false
                } else {
                    true
                }
            });
            stale
        };
        for session in stale {
            let _ = session.close().await;
        }
        if let Some(session) = self.udp_sessions.lock().await.get(&migrate_id) {
            session.touch();
            return Ok(Arc::clone(session));
        }
        let datagram = self.upstream.open_datagram(context).await?;
        let session = ServerUdpSession::spawn(datagram, self.udp_buffer_size).await;
        self.udp_sessions
            .lock()
            .await
            .insert(migrate_id, Arc::clone(&session));
        Ok(session)
    }

    /// Close all retained migrated UDP sessions when the owning listener
    /// stops.
    pub async fn close(&self) {
        let sessions = self
            .udp_sessions
            .lock()
            .await
            .drain()
            .map(|(_, session)| session)
            .collect::<Vec<_>>();
        for session in sessions {
            let _ = session.close().await;
        }
    }
}
