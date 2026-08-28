use super::*;

#[cfg(feature = "http2")]
pub(crate) async fn serve_h2_listener(
    listener: TcpListener,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    tls_acceptor: Option<InboundTlsAcceptor>,
) -> Result<()> {
    use tokio::task::JoinSet;

    let yuubinsya_server = (spec.protocol == "yuubinsya")
        .then(|| crate::inbound::adapters::yuubinsya::new_server(&spec, selector.clone()))
        .flatten();
    let handler = protocol_handler(
        spec.protocol.clone(),
        spec.clone(),
        selector,
        monitor.clone(),
        yuubinsya_server.clone(),
    );
    let mut connections = JoinSet::new();
    let result = async {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, peer) = accepted.map_err(crate::inbound::adapters::common::io_error)?;
                    let spec = spec.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let handler = handler.clone();
                    let logs = monitor.logs();
                    connections.spawn(async move {
                        let result: Result<()> = async {
                            let stream =
                                prepare_inbound_stream(stream, &spec, tls_acceptor, true).await?;
                            serve_h2_connection(stream, peer, handler).await
                        }
                        .await;
                        if let Err(error) = result {
                            logs.error(format!("HTTP/2 inbound connection error: {error}"));
                        }
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        monitor.warn(format!("HTTP/2 connection task stopped: {error}"));
                    }
                }
            }
        }
    }
    .await;
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    if let Some(server) = yuubinsya_server {
        server.close().await;
    }
    result
}

#[cfg(feature = "http2")]
pub(crate) async fn serve_h2_connection<S>(
    stream: S,
    peer: SocketAddr,
    handler: Arc<ProtocolHandler>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::task::JoinSet;

    let mut connection = h2::server::handshake(stream)
        .await
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("HTTP/2 handshake: {error}")))?;
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            request = connection.accept() => {
                let Some(request) = request else { break };
                let (request, respond) = match request {
                    Ok(request) => request,
                    Err(error) => {
                        return Err(Error::new(
                            ErrorKind::Protocol,
                            format!("HTTP/2 request: {error}"),
                        ));
                    }
                };
                let handler = handler.clone();
                streams.spawn(async move {
                    serve_h2_stream(request, respond, peer, handler).await
                });
            }
            Some(result) = streams.join_next(), if !streams.is_empty() => {
                match result {
                    Ok(Err(error)) => handler.inbound.monitor().error(format!("HTTP/2 inbound stream error: {error}")),
                    Err(error) => handler.inbound.monitor().error(format!("HTTP/2 inbound stream task panicked: {error}")),
                    Ok(Ok(())) => {}
                }
            }
        }
    }
    streams.abort_all();
    while streams.join_next().await.is_some() {}
    Ok(())
}

#[cfg(feature = "http2")]
pub(crate) async fn serve_h2_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    peer: SocketAddr,
    handler: Arc<ProtocolHandler>,
) -> Result<()> {
    use http::{Response, StatusCode};
    use tokio::io::duplex;

    if request.method() != http::Method::CONNECT {
        let response = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(())
            .map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("HTTP/2 response: {error}"))
            })?;
        respond.send_response(response, true).map_err(|error| {
            Error::new(ErrorKind::Protocol, format!("HTTP/2 response: {error}"))
        })?;
        return Ok(());
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(())
        .map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("HTTP/2 CONNECT response: {error}"),
            )
        })?;
    let send = respond.send_response(response, false).map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("HTTP/2 CONNECT response: {error}"),
        )
    })?;
    let (protocol_io, bridge_io) = duplex(16 * 1024);
    let bridge = tokio::spawn(bridge_h2_stream(request.into_body(), send, bridge_io));
    let result = serve_connection(protocol_io, peer, handler).await;
    bridge.abort();
    let _ = bridge.await;
    result
}

#[cfg(feature = "http2")]
pub(crate) async fn bridge_h2_stream(
    mut body: h2::RecvStream,
    mut send: h2::SendStream<bytes::Bytes>,
    relay_side: tokio::io::DuplexStream,
) -> Result<()> {
    use bytes::Bytes;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, split};

    let (mut reader, mut writer) = split(relay_side);
    let mut buffer = vec![0u8; 16 * 1024];
    let mut request_done = false;
    loop {
        tokio::select! {
            result = reader.read(&mut buffer) => {
                let length = result.map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
                if length == 0 {
                    send.send_data(Bytes::new(), true).map_err(|error| {
                        Error::new(ErrorKind::Protocol, format!("HTTP/2 response end: {error}"))
                    })?;
                    return Ok(());
                }
                send.send_data(Bytes::copy_from_slice(&buffer[..length]), false).map_err(|error| {
                    Error::new(ErrorKind::Protocol, format!("HTTP/2 response data: {error}"))
                })?;
            }
            result = body.data(), if !request_done => {
                let Some(result) = result else {
                    // Tokio's in-memory duplex does not expose a separate
                    // half-close boundary to the protocol task.  Closing the
                    // writer here would also tear down the response side;
                    // protocol framing already defines request completion,
                    // and the bridge owner closes both sides after it exits.
                    request_done = true;
                    continue;
                };
                let data = result.map_err(|error| Error::new(ErrorKind::Protocol, format!("HTTP/2 request data: {error}")))?;
                body.flow_control().release_capacity(data.len()).map_err(|error| {
                    Error::new(ErrorKind::Protocol, format!("HTTP/2 request capacity: {error}"))
                })?;
                writer.write_all(&data).await.map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
            }
        }
    }
}

pub(crate) async fn serve_listener(
    listener: TcpListener,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    tls_acceptor: Option<InboundTlsAcceptor>,
) -> Result<()> {
    use tokio::task::JoinSet;

    let protocol = spec.protocol.clone();
    let yuubinsya_server = (protocol == "yuubinsya")
        .then(|| crate::inbound::adapters::yuubinsya::new_server(&spec, selector.clone()))
        .flatten();
    let handler = protocol_handler(
        protocol.clone(),
        spec.clone(),
        selector,
        monitor.clone(),
        yuubinsya_server.clone(),
    );
    let mut connections = JoinSet::new();
    let result = async {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, peer) = accepted.map_err(crate::inbound::adapters::common::io_error)?;
                    let spec = spec.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let handler = handler.clone();
                    let logs = monitor.logs();
                    connections.spawn(async move {
                        let result = async {
                            let stream =
                                prepare_inbound_stream(stream, &spec, tls_acceptor, false).await?;
                            serve_connection(stream, peer, handler).await
                        }
                        .await;
                        if let Err(error) = result {
                            logs.error(format!("inbound connection error: {error}"));
                        }
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        monitor.warn(format!("inbound connection task stopped: {error}"));
                    }
                }
            }
        }
    }
    .await;
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    if let Some(server) = yuubinsya_server {
        server.close().await;
    }
    result
}

#[cfg(feature = "websocket")]
pub(crate) async fn serve_websocket_listener(
    listener: TcpListener,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    tls_acceptor: Option<InboundTlsAcceptor>,
) -> Result<()> {
    use tokio::task::JoinSet;

    let protocol = spec.protocol.clone();
    let yuubinsya_server = (protocol == "yuubinsya")
        .then(|| crate::inbound::adapters::yuubinsya::new_server(&spec, selector.clone()))
        .flatten();
    let handler = protocol_handler(
        protocol.clone(),
        spec.clone(),
        selector,
        monitor.clone(),
        yuubinsya_server.clone(),
    );
    let mut connections = JoinSet::new();
    let result = async {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, peer) = accepted.map_err(crate::inbound::adapters::common::io_error)?;
                    let spec = spec.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let handler = handler.clone();
                    let logs = monitor.logs();
                    connections.spawn(async move {
                        let result: Result<()> = async {
                            let stream =
                                prepare_inbound_stream(stream, &spec, tls_acceptor, false).await?;
                            serve_websocket_stream(stream, peer, handler).await
                        }
                        .await;
                        if let Err(error) = result {
                            logs.error(format!("WebSocket inbound connection error: {error}"));
                        }
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        monitor.warn(format!("WebSocket connection task stopped: {error}"));
                    }
                }
            }
        }
    }
    .await;
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    if let Some(server) = yuubinsya_server {
        server.close().await;
    }
    result
}
#[cfg(feature = "websocket")]
#[allow(clippy::result_large_err)]
pub(crate) async fn accept_websocket_stream<S>(
    stream: S,
) -> Result<(doradus_protocol::websocket::WebSocketIo<S>, Vec<u8>)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    doradus_protocol::websocket_server::accept_stream(stream).await
}

#[cfg(all(feature = "websocket", feature = "http2"))]
pub(crate) async fn serve_websocket_h2_listener(
    listener: TcpListener,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    tls_acceptor: Option<InboundTlsAcceptor>,
) -> Result<()> {
    use tokio::task::JoinSet;

    let yuubinsya_server = (spec.protocol == "yuubinsya")
        .then(|| crate::inbound::adapters::yuubinsya::new_server(&spec, selector.clone()))
        .flatten();
    let handler = protocol_handler(
        spec.protocol.clone(),
        spec.clone(),
        selector,
        monitor.clone(),
        yuubinsya_server.clone(),
    );
    let mut connections = JoinSet::new();
    let result = async {
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, peer) = accepted.map_err(crate::inbound::adapters::common::io_error)?;
                    let spec = spec.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let handler = handler.clone();
                    let logs = monitor.logs();
                    connections.spawn(async move {
                        let result = async {
                            let stream =
                                prepare_inbound_stream(stream, &spec, tls_acceptor, false).await?;
                            let (stream, early_data) = accept_websocket_stream(stream).await?;
                            let stream = PrefixedIo::new(early_data, stream);
                            serve_h2_connection(stream, peer, handler).await
                        }
                        .await;
                        if let Err(error) = result {
                            logs.error(format!(
                                "WebSocket+HTTP/2 inbound connection error: {error}"
                            ));
                        }
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        monitor.warn(format!("WebSocket+HTTP/2 connection task stopped: {error}"));
                    }
                }
            }
        }
    }
    .await;
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    if let Some(server) = yuubinsya_server {
        server.close().await;
    }
    result
}

#[cfg(feature = "websocket")]
pub(crate) async fn serve_websocket_stream<S>(
    stream: S,
    peer: SocketAddr,
    handler: Arc<ProtocolHandler>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (stream, early_data) = accept_websocket_stream(stream).await?;
    let stream = PrefixedIo::new(early_data, stream);
    serve_connection(stream, peer, handler).await
}

trait InboundProtocol: Send + Sync {
    fn handle<'a>(&'a self, stream: BoxAsyncStream, peer: SocketAddr) -> BoxFuture<'a, Result<()>>;
}

pub(crate) struct ProtocolHandler {
    protocol: String,
    inbound: Arc<InboundHandler>,
    yuubinsya_server: Option<Arc<doradus_chain::YuubinsyaServerProxy>>,
}

impl InboundProtocol for ProtocolHandler {
    fn handle<'a>(&'a self, stream: BoxAsyncStream, peer: SocketAddr) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            match self.protocol.as_str() {
                "socks4a" => {
                    let username = self.inbound.spec().username.clone();
                    doradus_protocol::socks4a_server::handle(
                        stream,
                        peer,
                        username.as_bytes(),
                        self.inbound.as_ref(),
                    )
                    .await
                }
                "socks5" => {
                    crate::inbound::socks5::handle(stream, peer, Arc::clone(&self.inbound)).await
                }
                "http" => {
                    let stream = crate::inbound::adapters::http::HttpInboundStream(stream);
                    serve_http(stream, peer, Arc::clone(&self.inbound)).await
                }
                "reverse_tcp" => {
                    crate::inbound::adapters::reverse::handle_tcp(
                        stream,
                        peer,
                        Arc::clone(&self.inbound),
                    )
                    .await
                }
                "reverse_http" => {
                    crate::inbound::adapters::reverse::handle_http(
                        stream,
                        peer,
                        Arc::clone(&self.inbound),
                    )
                    .await
                }
                "mixed" => serve_mixed(stream, peer, Arc::clone(&self.inbound)).await,
                "trojan" => {
                    let hashes =
                        crate::inbound::adapters::trojan::password_hashes(self.inbound.spec());
                    let udp_inbound = Arc::clone(&self.inbound);
                    doradus_protocol::trojan::handle(
                        stream,
                        peer,
                        &hashes,
                        self.inbound.selector().udp_buffer_size(),
                        self.inbound.as_ref(),
                        move |codec| async move {
                            InboundUdpSession::new(codec, udp_inbound).run().await
                        },
                    )
                    .await
                }
                "vless" => {
                    let uuid = doradus_protocol::vless::parse_uuid(&self.inbound.spec().password)?;
                    let udp_inbound = Arc::clone(&self.inbound);
                    doradus_protocol::vless::handle(
                        stream,
                        peer,
                        &uuid,
                        self.inbound.selector().udp_buffer_size(),
                        self.inbound.as_ref(),
                        move |server| async move {
                            let codec = crate::inbound::adapters::vless::VlessUdpCodec {
                                server,
                                flow_key: None,
                            };
                            InboundUdpSession::new(codec, udp_inbound).run().await
                        },
                    )
                    .await
                }
                "yuubinsya" => {
                    let server = self
                        .yuubinsya_server
                        .clone()
                        .or_else(|| {
                            crate::inbound::adapters::yuubinsya::new_server(
                                self.inbound.spec(),
                                Arc::clone(self.inbound.selector()),
                            )
                        })
                        .ok_or_else(|| {
                            Error::new(
                                ErrorKind::Unsupported,
                                "Yuubinsya inbound has no concrete password hash",
                            )
                        })?;
                    let annotate = self.inbound.spec().clone();
                    let route = Arc::clone(self.inbound.selector());
                    let monitor = Arc::clone(self.inbound.monitor());
                    let dns_handler = monitor.dns_hijack_enabled().then(|| {
                        Arc::new(self.inbound.dns_policy())
                            as Arc<dyn doradus_types::InboundDnsHandler>
                    });
                    server
                        .serve_with_handler(
                            stream,
                            peer,
                            self.inbound.as_ref(),
                            monitor,
                            move |context| {
                                annotate.annotate_context(context);
                                route.route_context(context);
                            },
                            dns_handler,
                        )
                        .await
                }
                "none" => Ok(()),
                other => Err(Error::new(
                    ErrorKind::Unsupported,
                    format!("inbound protocol {other:?} is not implemented"),
                )),
            }
        })
    }
}

pub(crate) async fn serve_http(
    stream: crate::inbound::adapters::http::HttpInboundStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let spec = inbound.spec().clone();
    let handler = crate::inbound::adapters::http::HttpInboundHandler { inbound };
    let central_auth: Option<&dyn InboundBasicAuth> = spec
        .auth
        .as_deref()
        .map(|auth| auth as &dyn InboundBasicAuth);
    doradus_protocol::http_server::handle::<crate::inbound::adapters::http::HttpInboundStream, _>(
        stream,
        peer,
        &spec.username,
        &spec.password,
        central_auth,
        &handler,
    )
    .await
}

pub(crate) fn protocol_handler(
    protocol: String,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    yuubinsya_server: Option<Arc<doradus_chain::YuubinsyaServerProxy>>,
) -> Arc<ProtocolHandler> {
    Arc::new(ProtocolHandler {
        protocol,
        inbound: InboundHandler::new(spec, selector, monitor),
        yuubinsya_server,
    })
}

pub(crate) async fn serve_connection(
    stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    peer: SocketAddr,
    handler: Arc<ProtocolHandler>,
) -> Result<()> {
    handler.handle(Box::new(stream), peer).await
}

pub(crate) fn normalize_inbound_protocol(protocol: &str) -> String {
    match protocol.trim().to_ascii_lowercase().as_str() {
        "mix" => "mixed".to_owned(),
        "reversehttp" => "reverse_http".to_owned(),
        "reversetcp" => "reverse_tcp".to_owned(),
        normalized => normalized.to_owned(),
    }
}

pub(crate) async fn serve_mixed(
    mut stream: BoxAsyncStream,
    peer: SocketAddr,
    inbound: Arc<InboundHandler>,
) -> Result<()> {
    let mut first = [0u8; 1];
    stream
        .read_exact(&mut first)
        .await
        .map_err(crate::inbound::adapters::common::io_error)?;
    let stream = PrefixedIo::new(vec![first[0]], stream);
    if first[0] == 4 {
        let username = inbound.spec().username.clone();
        let stream: BoxAsyncStream = Box::new(stream);
        doradus_protocol::socks4a_server::handle(
            stream,
            peer,
            username.as_bytes(),
            inbound.as_ref(),
        )
        .await
    } else if first[0] == 5 {
        crate::inbound::socks5::handle(Box::new(stream), peer, inbound).await
    } else {
        let stream: BoxAsyncStream = Box::new(stream);
        let spec = inbound.spec().clone();
        let handler = crate::inbound::adapters::http::HttpInboundHandler { inbound };
        let central_auth: Option<&dyn InboundBasicAuth> = spec
            .auth
            .as_deref()
            .map(|auth| auth as &dyn InboundBasicAuth);
        doradus_protocol::http_server::handle::<crate::inbound::adapters::http::HttpInboundStream, _>(
            crate::inbound::adapters::http::HttpInboundStream(stream),
            peer,
            &spec.username,
            &spec.password,
            central_auth,
            &handler,
        )
        .await
    }
}
