use super::*;

pub struct NetworkSplitProxy {
    pub(in crate::plane::outbound) tcp: Arc<dyn AsyncProxy>,
    pub(in crate::plane::outbound) udp: Arc<dyn AsyncProxy>,
    pub(in crate::plane::outbound) parent: Arc<dyn AsyncProxy>,
}

#[cfg(feature = "doh-tls")]
pub struct TlsTerminationProxy {
    pub(in crate::plane::outbound) upstream: Arc<dyn AsyncProxy>,
    pub(in crate::plane::outbound) acceptor: tokio_rustls::TlsAcceptor,
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
    pub(in crate::plane::outbound) upstream: Arc<dyn AsyncProxy>,
    pub(in crate::plane::outbound) password_hash: [u8; 32],
    pub(in crate::plane::outbound) udp_over_stream: bool,
    pub(in crate::plane::outbound) udp_coalesce: bool,
    pub(in crate::plane::outbound) udp_server: Option<Endpoint>,
}

/// Go's HTTP/2 contract wraps the already-built parent proxy and uses that
/// proxy only as the dialer for plaintext prior-knowledge HTTP/2.  Its UDP
/// method is inherited from the parent, so this adapter deliberately applies
/// HTTP/2 only to TCP streams as well.
pub struct NetworkSplitHttp2Proxy {
    pub(in crate::plane::outbound) upstream: Arc<dyn AsyncProxy>,
    pub(in crate::plane::outbound) connections:
        tokio::sync::Mutex<Vec<Arc<doradus_chain::H2Connection>>>,
    pub(in crate::plane::outbound) connect_lock: tokio::sync::Mutex<()>,
    pub(in crate::plane::outbound) concurrency: usize,
    pub(in crate::plane::outbound) max_streams: usize,
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
