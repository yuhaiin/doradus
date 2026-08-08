//! Inbound proxy listeners and their connection into the shared outbound
//! selector.
//!
//! TUN is one inbound among several. This module owns the normal TCP variants
//! of the Go inbound contract: SOCKS5, HTTP CONNECT and Yuubinsya. Each accepted
//! request is converted into the same [`FlowContext`] used by TUN, then routed
//! through the live `RuntimeProxySelector`; listeners therefore observe
//! direct/proxy/bypass/drop changes after a reload without duplicating proxy
//! construction logic.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;

use yuhaiin_core::process::{ProcessResolver, default_process_resolver};
#[cfg(all(feature = "websocket", feature = "http2"))]
use yuhaiin_core::proxy::BoxAsyncStream;
use yuhaiin_core::{Endpoint, Error, ErrorKind, FlowContext, Result};
use yuhaiin_store::GoInboundRecord;

use crate::{ConnectionMonitor, RuntimeController, RuntimeProxySelector};

#[cfg(feature = "doh-tls")]
type InboundTlsAcceptor = tokio_rustls::TlsAcceptor;
#[cfg(not(feature = "doh-tls"))]
type InboundTlsAcceptor = ();

fn has_transport(transports: &[String], kind: &str) -> bool {
    transports
        .iter()
        .any(|transport| transport.eq_ignore_ascii_case(kind))
}

fn inbound_process_resolver() -> Option<&'static dyn ProcessResolver> {
    static RESOLVER: OnceLock<Option<Arc<dyn ProcessResolver>>> = OnceLock::new();
    RESOLVER.get_or_init(default_process_resolver).as_deref()
}

#[derive(Debug, Clone)]
pub(crate) struct InboundSpec {
    pub(crate) id: String,
    pub(crate) protocol: String,
    pub(crate) listen: SocketAddr,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) udp_mode: UdpMode,
    pub(crate) protocol_udp: bool,
    pub(crate) transports: Vec<String>,
    pub(crate) outbound_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpMode {
    Enabled,
    Disabled,
    TcpOnly,
    UdpOnly,
}

impl UdpMode {
    fn from_value(value: Option<&serde_json::Value>) -> Self {
        match value {
            Some(value) if value.is_boolean() => {
                if value.as_bool().unwrap_or(false) {
                    Self::Enabled
                } else {
                    Self::Disabled
                }
            }
            Some(value) => match value
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str()
            {
                "enabled" => Self::Enabled,
                "udp_only" => Self::UdpOnly,
                "tcp_only" => Self::TcpOnly,
                _ => Self::Disabled,
            },
            None => Self::Disabled,
        }
    }

    fn tcp_enabled(self) -> bool {
        !matches!(self, Self::UdpOnly)
    }

    fn udp_enabled(self) -> bool {
        matches!(self, Self::Enabled | Self::UdpOnly)
    }
}

/// Run all enabled normal TCP inbounds and restart their listener set after a
/// successful configuration reload. The supervisor is intentionally outside
/// `RuntimeController`: the controller publishes immutable snapshots, while
/// this owner controls sockets and listener task lifetimes.
pub async fn run_until(
    controller: RuntimeController,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut reload = controller.subscribe_reload();
    let mut listeners = Vec::new();
    loop {
        abort_listeners(&mut listeners).await;
        listeners = start_listeners(&controller).await?;
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            changed = reload.recv() => {
                if changed.is_err() {
                    break;
                }
            }
        }
    }
    abort_listeners(&mut listeners).await;
    Ok(())
}

async fn start_listeners(
    controller: &RuntimeController,
) -> Result<Vec<tokio::task::JoinHandle<()>>> {
    let records = controller.store().repository().list_go_inbounds().await?;
    let proxy_id = selected_proxy_id(controller).await?;
    let selector = controller
        .build_proxy_selector("", &proxy_id, "", "", Duration::from_secs(30))
        .await?;
    let monitor = controller.monitor();
    let mut listeners = Vec::new();
    for record in records.into_iter().filter(|record| record.enabled) {
        let mut spec = match InboundSpec::from_record(record.clone()) {
            Ok(spec) => spec,
            Err(error) => {
                monitor.error(format!("skip inbound: {error}"));
                continue;
            }
        };
        spec.outbound_id = proxy_id.clone();
        if !spec.transports.is_empty()
            && spec.transports.iter().any(|transport| {
                !transport.eq_ignore_ascii_case("normal")
                    && !transport.eq_ignore_ascii_case("tls")
                    && !transport.eq_ignore_ascii_case("http2")
                    && !transport.eq_ignore_ascii_case("websocket")
            })
        {
            monitor.warn(format!(
                "skip inbound {}: configured transport is not implemented",
                spec.id
            ));
            continue;
        }
        let tls_acceptor = match build_inbound_tls_acceptor(&record.data_json, &spec.transports) {
            Ok(acceptor) => acceptor,
            Err(error) => {
                monitor.error(format!("skip inbound {}: {error}", spec.id));
                continue;
            }
        };
        if has_transport(&spec.transports, "websocket") {
            if spec.udp_mode.udp_enabled() {
                monitor.warn(format!(
                    "skip UDP inbound {}: WebSocket transport only wraps TCP listeners",
                    spec.id
                ));
            }
            if spec.udp_mode.tcp_enabled() {
                let listener = TcpListener::bind(spec.listen).await.map_err(|error| {
                    Error::new(ErrorKind::Io, format!("bind inbound {}: {error}", spec.id))
                })?;
                let selector = selector.clone();
                let monitor = monitor.clone();
                let spec = spec.clone();
                let tls_acceptor = tls_acceptor.clone();
                let logs = monitor.logs();
                #[cfg(all(feature = "websocket", feature = "http2"))]
                {
                    if has_transport(&spec.transports, "http2") {
                        listeners.push(tokio::spawn(async move {
                            if let Err(error) = serve_websocket_h2_listener(
                                listener,
                                spec,
                                selector,
                                monitor,
                                tls_acceptor,
                            )
                            .await
                            {
                                logs.error(format!(
                                    "WebSocket+HTTP/2 inbound listener stopped: {error}"
                                ));
                            }
                        }));
                    } else {
                        listeners.push(tokio::spawn(async move {
                            if let Err(error) = serve_websocket_listener(
                                listener,
                                spec,
                                selector,
                                monitor,
                                tls_acceptor,
                            )
                            .await
                            {
                                logs.error(format!("WebSocket inbound listener stopped: {error}"));
                            }
                        }));
                    }
                }
                #[cfg(all(feature = "websocket", not(feature = "http2")))]
                {
                    if has_transport(&spec.transports, "http2") {
                        let _ = (listener, spec, selector, monitor, tls_acceptor);
                        logs.warn(
                            "skip inbound: WebSocket+HTTP/2 requires both websocket and http2 features",
                        );
                    } else {
                        listeners.push(tokio::spawn(async move {
                            if let Err(error) = serve_websocket_listener(
                                listener,
                                spec,
                                selector,
                                monitor,
                                tls_acceptor,
                            )
                            .await
                            {
                                logs.error(format!("WebSocket inbound listener stopped: {error}"));
                            }
                        }));
                    }
                }
                #[cfg(not(feature = "websocket"))]
                {
                    let _ = (listener, spec, selector, monitor, tls_acceptor);
                    logs.warn("skip inbound: WebSocket transport requires the websocket feature");
                }
            }
            continue;
        }
        if has_transport(&spec.transports, "http2") {
            if spec.udp_mode.udp_enabled() {
                monitor.warn(format!(
                    "skip UDP inbound {}: HTTP/2 transport only wraps TCP listeners",
                    spec.id
                ));
            }
            if spec.udp_mode.tcp_enabled() {
                let listener = TcpListener::bind(spec.listen).await.map_err(|error| {
                    Error::new(ErrorKind::Io, format!("bind inbound {}: {error}", spec.id))
                })?;
                let selector = selector.clone();
                let monitor = monitor.clone();
                let spec = spec.clone();
                let tls_acceptor = tls_acceptor.clone();
                let logs = monitor.logs();
                #[cfg(feature = "http2")]
                listeners.push(tokio::spawn(async move {
                    if let Err(error) =
                        serve_h2_listener(listener, spec, selector, monitor, tls_acceptor).await
                    {
                        logs.error(format!("HTTP/2 inbound listener stopped: {error}"));
                    }
                }));
                #[cfg(not(feature = "http2"))]
                {
                    let _ = (listener, spec, selector, monitor, tls_acceptor);
                    logs.warn("skip inbound: HTTP/2 transport requires the http2 feature");
                }
            }
            continue;
        }
        if spec.udp_mode.tcp_enabled() {
            let listener = TcpListener::bind(spec.listen).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("bind inbound {}: {error}", spec.id))
            })?;
            let selector = selector.clone();
            let monitor = monitor.clone();
            let spec = spec.clone();
            let tls_acceptor = tls_acceptor.clone();
            let logs = monitor.logs();
            listeners.push(tokio::spawn(async move {
                if let Err(error) =
                    serve_listener(listener, spec, selector, monitor, tls_acceptor).await
                {
                    logs.error(format!("inbound listener stopped: {error}"));
                }
            }));
        }
        if spec.udp_mode.udp_enabled() {
            let selector = selector.clone();
            let monitor = monitor.clone();
            let spec = spec.clone();
            match spec.protocol.as_str() {
                "yuubinsya" => {
                    if tls_acceptor.is_some() {
                        monitor.warn(format!(
                            "skip UDP inbound {}: TLS transport only wraps TCP listeners",
                            spec.id
                        ));
                        continue;
                    }
                    let socket = yuhaiin_core::proxy::YuubinsyaUdpServer::bind(
                        spec.listen,
                        yuhaiin_core::yuubinsya::derive_salt(spec.password.as_bytes()),
                        // Go's Yuubinsya inbound uses the native packet
                        // format without the SOCKS5 three-byte prefix.  The
                        // prefix is only used when Yuubinsya wraps a SOCKS5
                        // UDP association.
                        false,
                    )
                    .await?;
                    let logs = monitor.logs();
                    listeners.push(tokio::spawn(async move {
                        if let Err(error) =
                            crate::proxy::yuubinsya::serve_udp(socket, spec, selector, monitor)
                                .await
                        {
                            logs.error(format!("Yuubinsya UDP listener stopped: {error}"));
                        }
                    }));
                }
                "socks5" if spec.protocol_udp => {
                    if tls_acceptor.is_some() {
                        monitor.warn(format!(
                            "skip UDP inbound {}: TLS transport only wraps TCP listeners",
                            spec.id
                        ));
                        continue;
                    }
                    let socket = UdpSocket::bind(spec.listen).await.map_err(|error| {
                        Error::new(
                            ErrorKind::Io,
                            format!("bind SOCKS5 UDP inbound {}: {error}", spec.id),
                        )
                    })?;
                    let logs = monitor.logs();
                    listeners.push(tokio::spawn(async move {
                        if let Err(error) =
                            crate::proxy::socks5::serve_udp_socket(socket, spec, selector, monitor)
                                .await
                        {
                            logs.error(format!("SOCKS5 UDP listener stopped: {error}"));
                        }
                    }));
                }
                _ => monitor.warn(format!(
                    "skip UDP inbound {}: protocol {:?} has no UDP mode",
                    spec.id, spec.protocol
                )),
            }
        }
    }
    Ok(listeners)
}

pub async fn selected_proxy_id(controller: &RuntimeController) -> Result<String> {
    let nodes = controller.store().repository().list_go_nodes().await?;
    let selected = controller
        .store()
        .get_config("selected.node")
        .await?
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| {
            value
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    Ok(selected
        .filter(|id| nodes.iter().any(|node| node.enabled && node.id == *id))
        .or_else(|| {
            nodes
                .into_iter()
                .find(|node| node.enabled)
                .map(|node| node.id)
        })
        .unwrap_or_else(|| "direct".to_owned()))
}

async fn abort_listeners(listeners: &mut Vec<tokio::task::JoinHandle<()>>) {
    for listener in listeners.drain(..) {
        listener.abort();
        let _ = listener.await;
    }
}

impl InboundSpec {
    fn from_record(record: GoInboundRecord) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_slice(&record.data_json)
            .map_err(|error| Error::new(ErrorKind::Protocol, format!("inbound JSON: {error}")))?;
        let protocol = value
            .pointer("/protocol/type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(record.protocol_type.as_str())
            .to_ascii_lowercase();
        let network_type = value
            .pointer("/network/type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(record.network_type.as_str());
        if !network_type.eq_ignore_ascii_case("tcp_udp") {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("inbound network {network_type:?} is not a TCP listener"),
            ));
        }
        let listen_text = value
            .pointer("/network/tcp_udp/host")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let listen = parse_listen_addr(listen_text)?;
        let protocol_value = value.pointer("/protocol").cloned().unwrap_or_default();
        let section = protocol_value.get(&protocol).cloned().unwrap_or_default();
        let udp_mode = UdpMode::from_value(value.pointer("/network/tcp_udp/udp"));
        let username = section
            .get("username")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let password = section
            .get("password")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let protocol_udp = section
            .get("udp")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let transports =
            serde_json::from_slice::<Vec<serde_json::Value>>(&record.transport_types_json)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|transport| {
                    transport
                        .get("type")
                        .and_then(serde_json::Value::as_str)
                        .or_else(|| transport.as_str())
                        .map(ToOwned::to_owned)
                })
                .collect();
        Ok(Self {
            id: record.id,
            protocol,
            listen,
            username,
            password,
            udp_mode,
            protocol_udp,
            transports,
            outbound_id: String::new(),
        })
    }

    pub(crate) fn annotate_context(&self, context: &mut FlowContext) {
        self.annotate_context_with_process_resolver(context, inbound_process_resolver());
    }

    fn annotate_context_with_process_resolver(
        &self,
        context: &mut FlowContext,
        resolver: Option<&dyn ProcessResolver>,
    ) {
        context.inbound = Some(self.protocol.clone());
        context.inbound_name = Some(self.id.clone());
        if !self.outbound_id.is_empty() {
            context.outbound = Some(self.outbound_id.clone());
        }
        let Some(resolver) = resolver else {
            return;
        };
        let Some(source) = context.source.as_ref().and_then(Endpoint::addr) else {
            return;
        };
        if context.process.is_some() && context.process_id.is_some() && context.user_id.is_some() {
            return;
        }
        if let Ok(Some(process)) = resolver.resolve(context.network, source, self.listen) {
            if context.process.is_none() {
                context.process = Some(process.path);
            }
            if context.process_id.is_none() {
                context.process_id = Some(process.pid);
            }
            if context.user_id.is_none() {
                context.user_id = Some(process.uid);
            }
        }
    }
}

fn parse_listen_addr(value: &str) -> Result<SocketAddr> {
    let value = value.trim();
    let value = if value.starts_with(':') {
        format!("0.0.0.0{value}")
    } else {
        value.to_owned()
    };
    value.parse().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("inbound listen address: {error}"),
        )
    })
}

fn build_inbound_tls_acceptor(
    data_json: &[u8],
    transports: &[String],
) -> Result<Option<InboundTlsAcceptor>> {
    let enabled = transports
        .iter()
        .any(|transport| transport.eq_ignore_ascii_case("tls"));
    if !enabled {
        return Ok(None);
    }

    #[cfg(not(feature = "doh-tls"))]
    {
        let _ = data_json;
        return Err(Error::new(
            ErrorKind::Unsupported,
            "inbound TLS transport requires the doh-tls feature",
        ));
    }

    #[cfg(feature = "doh-tls")]
    {
        use std::io::Cursor;

        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use tokio_rustls::TlsAcceptor;

        let value: serde_json::Value = serde_json::from_slice(data_json).map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("inbound TLS configuration JSON: {error}"),
            )
        })?;
        let transport = value
            .get("transport")
            .or_else(|| value.get("transports"))
            .and_then(serde_json::Value::as_array)
            .and_then(|items| {
                items.iter().find(|item| {
                    item.get("type")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|kind| kind.eq_ignore_ascii_case("tls"))
                })
            })
            .ok_or_else(|| Error::invalid("inbound TLS transport configuration is missing"))?;
        let config = transport
            .get("tls")
            .and_then(serde_json::Value::as_object)
            .and_then(|value| value.get("tls"))
            .and_then(serde_json::Value::as_object)
            .or_else(|| transport.get("tls").and_then(serde_json::Value::as_object))
            .ok_or_else(|| Error::invalid("inbound TLS server config is missing"))?;
        let certificate = config
            .get("certificates")
            .and_then(serde_json::Value::as_array)
            .and_then(|certificates| certificates.first())
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| Error::invalid("inbound TLS certificate is missing"))?;
        let cert_bytes = tls_file_or_base64(certificate, "certBase64", "certFile")?;
        let key_bytes = tls_file_or_base64(certificate, "keyBase64", "keyFile")?;
        let certificates = if cert_bytes.starts_with(b"-----BEGIN") {
            rustls_pemfile::certs(&mut Cursor::new(cert_bytes))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|error| {
                    Error::new(ErrorKind::Protocol, format!("inbound TLS cert: {error}"))
                })?
        } else {
            vec![CertificateDer::from(cert_bytes)]
        };
        if certificates.is_empty() {
            return Err(Error::invalid("inbound TLS certificate chain is empty"));
        }
        let key = if key_bytes.starts_with(b"-----BEGIN") {
            rustls_pemfile::private_key(&mut Cursor::new(key_bytes))
                .map_err(|error| {
                    Error::new(ErrorKind::Protocol, format!("inbound TLS key: {error}"))
                })?
                .ok_or_else(|| Error::invalid("inbound TLS private key is missing"))?
        } else {
            PrivateKeyDer::try_from(key_bytes).map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("inbound TLS DER key: {error}"))
            })?
        };
        let provider = Arc::new(rustls_rustcrypto::provider());
        let mut server = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|error| {
                Error::new(
                    ErrorKind::Protocol,
                    format!("inbound TLS provider: {error}"),
                )
            })?
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .map_err(|error| {
                Error::new(
                    ErrorKind::Protocol,
                    format!("inbound TLS cert/key: {error}"),
                )
            })?;
        if let Some(protocols) = config
            .get("nextProtos")
            .and_then(serde_json::Value::as_array)
        {
            server.alpn_protocols = protocols
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::as_bytes)
                .map(ToOwned::to_owned)
                .collect();
        }
        if has_transport(transports, "http2")
            && !has_transport(transports, "websocket")
            && server.alpn_protocols.is_empty()
        {
            server.alpn_protocols.push(b"h2".to_vec());
        }
        Ok(Some(TlsAcceptor::from(Arc::new(server))))
    }
}

#[cfg(feature = "doh-tls")]
fn tls_file_or_base64(
    value: &serde_json::Map<String, serde_json::Value>,
    encoded_key: &str,
    file_key: &str,
) -> Result<Vec<u8>> {
    use base64::Engine;

    if let Some(encoded) = value.get(encoded_key).and_then(serde_json::Value::as_str) {
        return base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| {
                Error::new(ErrorKind::InvalidInput, format!("{encoded_key}: {error}"))
            });
    }
    if let Some(bytes) = value.get(encoded_key).and_then(serde_json::Value::as_array) {
        return bytes
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|value| u8::try_from(value).ok())
                    .ok_or_else(|| Error::invalid(format!("{encoded_key} contains a non-byte")))
            })
            .collect();
    }
    let path = value
        .get(file_key)
        .and_then(serde_json::Value::as_str)
        .filter(|path| !path.trim().is_empty())
        .ok_or_else(|| {
            Error::invalid(format!(
                "TLS certificate requires {encoded_key} or {file_key}"
            ))
        })?;
    std::fs::read(path)
        .map_err(|error| Error::new(ErrorKind::Io, format!("read TLS file {path:?}: {error}")))
}

#[cfg(feature = "http2")]
async fn serve_h2_listener(
    listener: TcpListener,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    tls_acceptor: Option<InboundTlsAcceptor>,
) -> Result<()> {
    use tokio::task::JoinSet;

    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted.map_err(crate::proxy::common::io_error)?;
                let spec = spec.clone();
                let selector = selector.clone();
                let monitor = monitor.clone();
                let tls_acceptor = tls_acceptor.clone();
                let logs = monitor.logs();
                connections.spawn(async move {
                    let result: Result<()> = if let Some(acceptor) = tls_acceptor {
                        #[cfg(feature = "doh-tls")]
                        {
                            match acceptor.accept(stream).await {
                                Ok(stream) if stream.get_ref().1.alpn_protocol() == Some(b"h2") => {
                                    serve_h2_connection(stream, peer, spec, selector, monitor).await
                                }
                                Ok(_) => Err(Error::new(
                                    ErrorKind::Protocol,
                                    "inbound HTTP/2 TLS did not negotiate ALPN h2",
                                )),
                                Err(error) => Err(Error::new(
                                    ErrorKind::Protocol,
                                    format!("inbound HTTP/2 TLS handshake: {error}"),
                                )),
                            }
                        }
                        #[cfg(not(feature = "doh-tls"))]
                        {
                            let _ = (acceptor, stream, peer, spec, selector, monitor);
                            Err(Error::new(
                                ErrorKind::Unsupported,
                                "inbound HTTP/2 TLS requires the doh-tls feature",
                            ))
                        }
                    } else {
                        serve_h2_connection(stream, peer, spec, selector, monitor).await
                    };
                    if let Err(error) = result {
                        logs.error(format!("HTTP/2 inbound connection error: {error}"));
                    }
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                let _ = result;
            }
        }
    }
}

#[cfg(feature = "http2")]
async fn serve_h2_connection<S>(
    stream: S,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
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
                let spec = spec.clone();
                let selector = selector.clone();
                let monitor = monitor.clone();
                streams.spawn(async move {
                    serve_h2_stream(request, respond, peer, spec, selector, monitor).await
                });
            }
            Some(result) = streams.join_next(), if !streams.is_empty() => {
                match result {
                    Ok(Err(error)) => monitor.error(format!("HTTP/2 inbound stream error: {error}")),
                    Err(error) => monitor.error(format!("HTTP/2 inbound stream task panicked: {error}")),
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
async fn serve_h2_stream(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
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
    let result = serve_connection(
        protocol_io,
        peer,
        spec.protocol.clone(),
        spec,
        selector,
        monitor,
    )
    .await;
    bridge.abort();
    let _ = bridge.await;
    result
}

#[cfg(feature = "http2")]
async fn bridge_h2_stream(
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

async fn serve_listener(
    listener: TcpListener,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    tls_acceptor: Option<InboundTlsAcceptor>,
) -> Result<()> {
    let protocol = spec.protocol.clone();
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(crate::proxy::common::io_error)?;
        let selector = selector.clone();
        let monitor = monitor.clone();
        let spec = spec.clone();
        let protocol = protocol.clone();
        let tls_acceptor = tls_acceptor.clone();
        let logs = monitor.logs();
        tokio::spawn(async move {
            #[cfg(feature = "doh-tls")]
            let result = if let Some(acceptor) = tls_acceptor {
                match acceptor.accept(stream).await {
                    Ok(stream) => {
                        serve_connection(stream, peer, protocol, spec, selector, monitor).await
                    }
                    Err(error) => Err(Error::new(
                        ErrorKind::Protocol,
                        format!("inbound TLS handshake: {error}"),
                    )),
                }
            } else {
                serve_connection(stream, peer, protocol, spec, selector, monitor).await
            };
            #[cfg(not(feature = "doh-tls"))]
            let result = {
                let _ = tls_acceptor;
                serve_connection(stream, peer, protocol, spec, selector, monitor).await
            };
            if let Err(error) = result {
                logs.error(format!("inbound connection error: {error}"));
            }
        });
    }
}

#[cfg(feature = "websocket")]
async fn accept_websocket_stream<S>(stream: S) -> Result<crate::proxy::websocket::WebSocketIo<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let websocket = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|error| {
            Error::new(ErrorKind::Protocol, format!("WebSocket handshake: {error}"))
        })?;
    Ok(crate::proxy::websocket::WebSocketIo::new(websocket))
}

#[cfg(all(feature = "websocket", feature = "http2"))]
async fn serve_websocket_h2_listener(
    listener: TcpListener,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    tls_acceptor: Option<InboundTlsAcceptor>,
) -> Result<()> {
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(crate::proxy::common::io_error)?;
        let selector = selector.clone();
        let monitor = monitor.clone();
        let spec = spec.clone();
        let tls_acceptor = tls_acceptor.clone();
        let logs = monitor.logs();
        tokio::spawn(async move {
            let result = async {
                #[cfg(feature = "doh-tls")]
                let stream: BoxAsyncStream = if let Some(acceptor) = tls_acceptor {
                    Box::new(acceptor.accept(stream).await.map_err(|error| {
                        Error::new(
                            ErrorKind::Protocol,
                            format!("inbound WebSocket TLS handshake: {error}"),
                        )
                    })?)
                } else {
                    Box::new(stream)
                };
                #[cfg(not(feature = "doh-tls"))]
                let stream = {
                    let _ = tls_acceptor;
                    stream
                };
                let stream = accept_websocket_stream(stream).await?;
                serve_h2_connection(stream, peer, spec, selector, monitor).await
            }
            .await;
            if let Err(error) = result {
                logs.error(format!(
                    "WebSocket+HTTP/2 inbound connection error: {error}"
                ));
            }
        });
    }
}

#[cfg(feature = "websocket")]
async fn serve_websocket_listener(
    listener: TcpListener,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    tls_acceptor: Option<InboundTlsAcceptor>,
) -> Result<()> {
    let protocol = spec.protocol.clone();
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(crate::proxy::common::io_error)?;
        let selector = selector.clone();
        let monitor = monitor.clone();
        let spec = spec.clone();
        let protocol = protocol.clone();
        let tls_acceptor = tls_acceptor.clone();
        let logs = monitor.logs();
        tokio::spawn(async move {
            #[cfg(feature = "doh-tls")]
            let result = if let Some(acceptor) = tls_acceptor {
                match acceptor.accept(stream).await {
                    Ok(stream) => {
                        serve_websocket_stream(stream, peer, protocol, spec, selector, monitor)
                            .await
                    }
                    Err(error) => Err(Error::new(
                        ErrorKind::Protocol,
                        format!("inbound TLS handshake: {error}"),
                    )),
                }
            } else {
                serve_websocket_stream(stream, peer, protocol, spec, selector, monitor).await
            };
            #[cfg(not(feature = "doh-tls"))]
            let result = {
                let _ = tls_acceptor;
                serve_websocket_stream(stream, peer, protocol, spec, selector, monitor).await
            };
            if let Err(error) = result {
                logs.error(format!("WebSocket inbound connection error: {error}"));
            }
        });
    }
}

#[cfg(feature = "websocket")]
async fn serve_websocket_stream<S>(
    stream: S,
    peer: SocketAddr,
    protocol: String,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let stream = accept_websocket_stream(stream).await?;
    serve_connection(stream, peer, protocol, spec, selector, monitor).await
}

async fn serve_connection<S>(
    stream: S,
    peer: SocketAddr,
    protocol: String,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    match protocol.as_str() {
        "socks4a" => crate::proxy::socks4a::serve(stream, peer, spec, selector, monitor).await,
        "socks5" => crate::proxy::socks5::serve(stream, peer, spec, selector, monitor).await,
        "http" => crate::proxy::http::serve(stream, peer, spec, selector, monitor).await,
        "mixed" => serve_mixed(stream, peer, spec, selector, monitor).await,
        "yuubinsya" => crate::proxy::yuubinsya::serve(stream, peer, spec, selector, monitor).await,
        other => Err(Error::new(
            ErrorKind::Unsupported,
            format!("inbound protocol {other:?} is not implemented"),
        )),
    }
}

async fn serve_mixed<S>(
    mut stream: S,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut first = [0u8; 1];
    stream
        .read_exact(&mut first)
        .await
        .map_err(crate::proxy::common::io_error)?;
    let stream = PrefixedIo {
        prefix: Some(first[0]),
        inner: stream,
    };
    if first[0] == 4 {
        crate::proxy::socks4a::serve(stream, peer, spec, selector, monitor).await
    } else if first[0] == 5 {
        crate::proxy::socks5::serve(stream, peer, spec, selector, monitor).await
    } else {
        crate::proxy::http::serve(stream, peer, spec, selector, monitor).await
    }
}

/// Re-inject the protocol discriminator consumed by a mixed inbound before
/// handing the connection to the normal protocol server. The wrapper keeps
/// protocol detection separate from SOCKS5/HTTP framing and preserves writes
/// on the original stream.
struct PrefixedIo<S> {
    prefix: Option<u8>,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(prefix) = self.prefix.take() {
            if buffer.remaining() > 0 {
                buffer.put_slice(&[prefix]);
                return Poll::Ready(Ok(()));
            }
            self.prefix = Some(prefix);
        }
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[cfg(feature = "websocket")]
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, UdpSocket};

    use super::*;
    use crate::{RuntimeBuilder, RuntimeController};
    use serde_json::json;
    use yuhaiin_chain::AsyncYuubinsyaTcpSession;
    use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
    use yuhaiin_core::process::ProcessInfo;
    use yuhaiin_core::{Endpoint, Network};
    use yuhaiin_store::{ConfigStore, GoNodeRecord};

    #[cfg(feature = "doh-tls")]
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

    #[cfg(feature = "doh-tls")]
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

    #[cfg(feature = "doh-tls")]
    const PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqkH6SeIb9vVEJ6WecsMk5Pn/a8sQ+vdNS/ZSkl3KwfoAoGCCqGSM49
AwEHoUQDQgAEs+fCVgURGLUyBsk24EdlX95KlMZ0kJAg7LEG3wuVHVlMQbTqlbIW
clUjNRLig+64dzRFwMSW0Zv9aiXJCUzvlA==
-----END EC PRIVATE KEY-----
"#;

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(future)
    }

    async fn direct_runtime() -> (Arc<RuntimeProxySelector>, Arc<ConnectionMonitor>) {
        let store = ConfigStore::open_memory().await.unwrap();
        let controller = RuntimeController::from_builder(RuntimeBuilder::new(
            store,
            Arc::new(SystemAsyncIpResolver),
        ))
        .await
        .unwrap();
        controller
            .store()
            .repository()
            .put_go_node(&GoNodeRecord {
                id: "direct".to_owned(),
                name: "Direct".to_owned(),
                group_name: "default".to_owned(),
                origin: "test".to_owned(),
                enabled: true,
                chain_types_json: br#"["direct"]"#.to_vec(),
                updated_at: 1,
                data_json: br#"{"protocol":"direct"}"#.to_vec(),
            })
            .await
            .unwrap();
        controller.reload().await.unwrap();
        let selector = controller
            .build_proxy_selector("", "direct", "", "", Duration::from_secs(2))
            .await
            .unwrap();
        (selector, controller.monitor())
    }

    async fn echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    loop {
                        let Ok(size) = stream.read(&mut buffer).await else {
                            break;
                        };
                        if size == 0 || stream.write_all(&buffer[..size]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (address, task)
    }

    async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
        let mut headers = Vec::new();
        let mut byte = [0u8; 1];
        while !headers.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            headers.push(byte[0]);
        }
        headers
    }

    #[test]
    fn inbound_udp_mode_accepts_frontend_strings_and_legacy_booleans() {
        assert_eq!(
            UdpMode::from_value(Some(&json!("enabled"))),
            UdpMode::Enabled
        );
        assert_eq!(
            UdpMode::from_value(Some(&json!("udp_only"))),
            UdpMode::UdpOnly
        );
        assert_eq!(UdpMode::from_value(Some(&json!(true))), UdpMode::Enabled);
        assert!(UdpMode::UdpOnly.udp_enabled());
        assert!(!UdpMode::UdpOnly.tcp_enabled());
    }

    struct FixedProcessResolver;

    impl ProcessResolver for FixedProcessResolver {
        fn resolve(
            &self,
            _network: Network,
            _source: SocketAddr,
            _destination: SocketAddr,
        ) -> std::io::Result<Option<ProcessInfo>> {
            Ok(Some(ProcessInfo {
                path: "/usr/bin/inbound-client".to_owned(),
                pid: 4242,
                uid: 1000,
            }))
        }
    }

    #[test]
    fn inbound_context_enriches_process_metadata_before_shared_router_selection() {
        let spec = InboundSpec {
            id: "process-inbound".to_owned(),
            protocol: "http".to_owned(),
            listen: "127.0.0.1:18080".parse().unwrap(),
            username: String::new(),
            password: String::new(),
            udp_mode: UdpMode::Disabled,
            protocol_udp: false,
            transports: vec!["normal".to_owned()],
            outbound_id: "direct".to_owned(),
        };
        let mut context = FlowContext::new(Endpoint::ip(
            Network::Tcp,
            "198.51.100.10:443".parse().unwrap(),
        ));
        context.source = Some(Endpoint::ip(
            Network::Tcp,
            "127.0.0.1:41000".parse().unwrap(),
        ));
        spec.annotate_context_with_process_resolver(&mut context, Some(&FixedProcessResolver));
        assert_eq!(context.inbound.as_deref(), Some("http"));
        assert_eq!(context.inbound_name.as_deref(), Some("process-inbound"));
        assert_eq!(context.outbound.as_deref(), Some("direct"));
        assert_eq!(context.process.as_deref(), Some("/usr/bin/inbound-client"));
        assert_eq!(context.process_id, Some(4242));
        assert_eq!(context.user_id, Some(1000));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn inbound_context_resolves_the_real_local_client_process_from_proc() {
        block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listen = listener.local_addr().unwrap();
            let client = TcpStream::connect(listen).await.unwrap();
            let (_server, peer) = listener.accept().await.unwrap();
            let spec = InboundSpec {
                id: "real-process-inbound".to_owned(),
                protocol: "socks5".to_owned(),
                listen,
                username: String::new(),
                password: String::new(),
                udp_mode: UdpMode::Disabled,
                protocol_udp: false,
                transports: vec!["normal".to_owned()],
                outbound_id: "direct".to_owned(),
            };
            let mut context = FlowContext::new(Endpoint::ip(
                Network::Tcp,
                "198.51.100.11:443".parse().unwrap(),
            ));
            context.source = Some(Endpoint::ip(Network::Tcp, peer));
            spec.annotate_context(&mut context);
            assert_eq!(context.process_id, Some(std::process::id()));
            assert!(
                context
                    .process
                    .as_deref()
                    .is_some_and(|path| !path.is_empty())
            );
            drop(client);
        });
    }

    #[test]
    fn socks5_inbound_routes_a_real_tcp_flow_through_the_shared_outbound() {
        block_on(async {
            let (echo_address, echo_task) = echo_server().await;
            let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let inbound_address = inbound_listener.local_addr().unwrap();
            let (selector, monitor) = direct_runtime().await;
            let listener_task = tokio::spawn(serve_listener(
                inbound_listener,
                InboundSpec {
                    id: "socks-inbound".to_owned(),
                    protocol: "socks5".to_owned(),
                    listen: inbound_address,
                    username: String::new(),
                    password: String::new(),
                    udp_mode: UdpMode::Disabled,
                    protocol_udp: false,
                    transports: vec!["normal".to_owned()],
                    outbound_id: "direct".to_owned(),
                },
                selector,
                monitor,
                None,
            ));

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let mut client = TcpStream::connect(inbound_address).await.unwrap();
                client.write_all(&[5, 1, 0]).await.unwrap();
                let mut method = [0u8; 2];
                client.read_exact(&mut method).await.unwrap();
                assert_eq!(method, [5, 0]);

                let ip = match echo_address.ip() {
                    std::net::IpAddr::V4(ip) => ip.octets(),
                    std::net::IpAddr::V6(_) => panic!("test echo server must be IPv4"),
                };
                let mut request = vec![5, 1, 0, 1];
                request.extend_from_slice(&ip);
                request.extend_from_slice(&echo_address.port().to_be_bytes());
                client.write_all(&request).await.unwrap();
                let mut reply = [0u8; 10];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[0..2], [5, 0]);

                client.write_all(b"socks5-through-direct").await.unwrap();
                let mut echoed = vec![0u8; 21];
                client.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"socks5-through-direct");
            })
            .await;

            listener_task.abort();
            let _ = listener_task.await;
            echo_task.abort();
            let _ = echo_task.await;
            result.unwrap();
        });
    }

    #[test]
    fn socks4a_inbound_routes_a_real_tcp_flow_through_the_shared_outbound() {
        block_on(async {
            let (echo_address, echo_task) = echo_server().await;
            let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let inbound_address = inbound_listener.local_addr().unwrap();
            let (selector, monitor) = direct_runtime().await;
            let listener_task = tokio::spawn(serve_listener(
                inbound_listener,
                InboundSpec {
                    id: "socks4a-inbound".to_owned(),
                    protocol: "socks4a".to_owned(),
                    listen: inbound_address,
                    username: String::new(),
                    password: String::new(),
                    udp_mode: UdpMode::Disabled,
                    protocol_udp: false,
                    transports: vec!["normal".to_owned()],
                    outbound_id: "direct".to_owned(),
                },
                selector,
                monitor,
                None,
            ));

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let mut client = TcpStream::connect(inbound_address).await.unwrap();
                let ip = match echo_address.ip() {
                    std::net::IpAddr::V4(ip) => ip.octets(),
                    std::net::IpAddr::V6(_) => panic!("test echo server must be IPv4"),
                };
                let mut request = vec![4, 1];
                request.extend_from_slice(&echo_address.port().to_be_bytes());
                request.extend_from_slice(&ip);
                request.extend_from_slice(b"rust-test");
                request.push(0);
                client.write_all(&request).await.unwrap();
                let mut reply = [0u8; 8];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[0..2], [0, 90]);

                client.write_all(b"socks4a-through-direct").await.unwrap();
                let mut echoed = vec![0u8; 22];
                client.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"socks4a-through-direct");
            })
            .await;

            listener_task.abort();
            let _ = listener_task.await;
            echo_task.abort();
            let _ = echo_task.await;
            result.unwrap();
        });
    }

    #[test]
    fn mixed_inbound_dispatches_socks4a_socks5_and_http_to_the_shared_outbound() {
        block_on(async {
            let (echo_address, echo_task) = echo_server().await;
            let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let inbound_address = inbound_listener.local_addr().unwrap();
            let (selector, monitor) = direct_runtime().await;
            let listener_task = tokio::spawn(serve_listener(
                inbound_listener,
                InboundSpec {
                    id: "mixed-inbound".to_owned(),
                    protocol: "mixed".to_owned(),
                    listen: inbound_address,
                    username: String::new(),
                    password: String::new(),
                    udp_mode: UdpMode::Disabled,
                    protocol_udp: false,
                    transports: vec!["normal".to_owned()],
                    outbound_id: "direct".to_owned(),
                },
                selector,
                monitor,
                None,
            ));

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let mut socks = TcpStream::connect(inbound_address).await.unwrap();
                socks.write_all(&[5, 1, 0]).await.unwrap();
                let mut method = [0u8; 2];
                socks.read_exact(&mut method).await.unwrap();
                assert_eq!(method, [5, 0]);
                let ip = match echo_address.ip() {
                    std::net::IpAddr::V4(ip) => ip.octets(),
                    std::net::IpAddr::V6(_) => panic!("test echo server must be IPv4"),
                };
                let mut request = vec![5, 1, 0, 1];
                request.extend_from_slice(&ip);
                request.extend_from_slice(&echo_address.port().to_be_bytes());
                socks.write_all(&request).await.unwrap();
                let mut reply = [0u8; 10];
                socks.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[0..2], [5, 0]);
                socks.write_all(b"mixed-socks").await.unwrap();
                let mut echoed = [0u8; 11];
                socks.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"mixed-socks");

                let mut socks4a = TcpStream::connect(inbound_address).await.unwrap();
                let ip = match echo_address.ip() {
                    std::net::IpAddr::V4(ip) => ip.octets(),
                    std::net::IpAddr::V6(_) => panic!("test echo server must be IPv4"),
                };
                let mut request = vec![4, 1];
                request.extend_from_slice(&echo_address.port().to_be_bytes());
                request.extend_from_slice(&ip);
                request.extend_from_slice(b"mixed-test");
                request.push(0);
                socks4a.write_all(&request).await.unwrap();
                let mut reply = [0u8; 8];
                socks4a.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[0..2], [0, 90]);
                socks4a.write_all(b"mixed-socks4a").await.unwrap();
                let mut echoed = [0u8; 13];
                socks4a.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"mixed-socks4a");

                let mut http = TcpStream::connect(inbound_address).await.unwrap();
                http.write_all(
                    format!(
                        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                        echo_address, echo_address
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
                let response = read_headers(&mut http).await;
                assert!(response.starts_with(b"HTTP/1.1 200"));
                http.write_all(b"mixed-http").await.unwrap();
                let mut echoed = [0u8; 10];
                http.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"mixed-http");
            })
            .await;

            listener_task.abort();
            let _ = listener_task.await;
            echo_task.abort();
            let _ = echo_task.await;
            result.unwrap();
        });
    }

    #[test]
    fn connections_close_aborts_a_live_socks5_relay() {
        block_on(async {
            let (echo_address, echo_task) = echo_server().await;
            let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let inbound_address = inbound_listener.local_addr().unwrap();
            let (selector, monitor) = direct_runtime().await;
            let listener_task = tokio::spawn(serve_listener(
                inbound_listener,
                InboundSpec {
                    id: "socks-close-inbound".to_owned(),
                    protocol: "socks5".to_owned(),
                    listen: inbound_address,
                    username: String::new(),
                    password: String::new(),
                    udp_mode: UdpMode::Disabled,
                    protocol_udp: false,
                    transports: vec!["normal".to_owned()],
                    outbound_id: "direct".to_owned(),
                },
                selector,
                monitor.clone(),
                None,
            ));

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let mut client = TcpStream::connect(inbound_address).await.unwrap();
                client.write_all(&[5, 1, 0]).await.unwrap();
                let mut method = [0u8; 2];
                client.read_exact(&mut method).await.unwrap();
                let ip = match echo_address.ip() {
                    std::net::IpAddr::V4(ip) => ip.octets(),
                    std::net::IpAddr::V6(_) => panic!("test echo server must be IPv4"),
                };
                let mut request = vec![5, 1, 0, 1];
                request.extend_from_slice(&ip);
                request.extend_from_slice(&echo_address.port().to_be_bytes());
                client.write_all(&request).await.unwrap();
                let mut reply = [0u8; 10];
                client.read_exact(&mut reply).await.unwrap();
                client.write_all(b"close-me").await.unwrap();
                let mut echoed = [0u8; 8];
                client.read_exact(&mut echoed).await.unwrap();

                let connection_id = monitor.connections_value()["connections"][0]["id"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                assert_eq!(monitor.request_close(&[connection_id]), 1);
                tokio::time::timeout(Duration::from_secs(1), async {
                    loop {
                        if monitor.connections_value()["connections"]
                            .as_array()
                            .is_some_and(Vec::is_empty)
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("close request should remove the live relay");
            })
            .await;

            listener_task.abort();
            let _ = listener_task.await;
            echo_task.abort();
            let _ = echo_task.await;
            result.unwrap();
        });
    }

    #[test]
    fn connections_close_removes_a_live_socks5_udp_flow() {
        block_on(async {
            let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target_address = target.local_addr().unwrap();
            let target_task = tokio::spawn(async move {
                let mut buffer = [0u8; 2048];
                if let Ok((length, peer)) = target.recv_from(&mut buffer).await {
                    let _ = target.send_to(&buffer[..length], peer).await;
                }
            });
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_address = server.local_addr().unwrap();
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let (selector, monitor) = direct_runtime().await;
            let listener_task = tokio::spawn(crate::proxy::socks5::serve_socks5_udp_loop(
                server,
                InboundSpec {
                    id: "socks-udp-close-inbound".to_owned(),
                    protocol: "socks5".to_owned(),
                    listen: server_address,
                    username: String::new(),
                    password: String::new(),
                    udp_mode: UdpMode::Enabled,
                    protocol_udp: true,
                    transports: vec!["normal".to_owned()],
                    outbound_id: "direct".to_owned(),
                },
                selector,
                monitor.clone(),
                None,
            ));

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let target = Endpoint::ip(Network::Udp, target_address);
                let packet =
                    crate::proxy::socks5::encode_socks_udp_packet(&target, b"udp-close").unwrap();
                client.send_to(&packet, server_address).await.unwrap();
                let mut reply = [0u8; 2048];
                let (length, _) = client.recv_from(&mut reply).await.unwrap();
                let (_, payload) = crate::proxy::socks5::parse_socks_udp_packet(&reply[..length])
                    .unwrap()
                    .unwrap();
                assert_eq!(payload, b"udp-close");

                let connection_id = tokio::time::timeout(Duration::from_secs(1), async {
                    loop {
                        if let Some(id) = monitor.connections_value()["connections"]
                            .as_array()
                            .and_then(|connections| connections.first())
                            .and_then(|connection| connection["id"].as_str())
                        {
                            break id.to_owned();
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("UDP flow should be visible to the monitor");
                assert_eq!(monitor.request_close(&[connection_id]), 1);
                tokio::time::timeout(Duration::from_secs(1), async {
                    loop {
                        if monitor.connections_value()["connections"]
                            .as_array()
                            .is_some_and(Vec::is_empty)
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("close request should remove the UDP flow");
            })
            .await;

            listener_task.abort();
            let _ = listener_task.await;
            target_task.abort();
            let _ = target_task.await;
            result.unwrap();
        });
    }

    #[test]
    fn http_connect_inbound_routes_a_real_tcp_flow_through_the_shared_outbound() {
        block_on(async {
            let (echo_address, echo_task) = echo_server().await;
            let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let inbound_address = inbound_listener.local_addr().unwrap();
            let (selector, monitor) = direct_runtime().await;
            let listener_task = tokio::spawn(serve_listener(
                inbound_listener,
                InboundSpec {
                    id: "http-inbound".to_owned(),
                    protocol: "http".to_owned(),
                    listen: inbound_address,
                    username: String::new(),
                    password: String::new(),
                    udp_mode: UdpMode::Disabled,
                    protocol_udp: false,
                    transports: vec!["normal".to_owned()],
                    outbound_id: "direct".to_owned(),
                },
                selector,
                monitor,
                None,
            ));

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let mut client = TcpStream::connect(inbound_address).await.unwrap();
                client
                    .write_all(
                        format!(
                            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                            echo_address, echo_address
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                let headers = read_headers(&mut client).await;
                assert!(headers.starts_with(b"HTTP/1.1 200 Connection Established"));

                client.write_all(b"http-through-direct").await.unwrap();
                let mut echoed = vec![0u8; 19];
                client.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"http-through-direct");
            })
            .await;

            listener_task.abort();
            let _ = listener_task.await;
            echo_task.abort();
            let _ = echo_task.await;
            result.unwrap();
        });
    }

    #[cfg(feature = "websocket")]
    #[test]
    fn websocket_transport_wraps_http_inbound_and_routes_a_real_tcp_flow() {
        block_on(async {
            let (echo_address, echo_task) = echo_server().await;
            let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let inbound_address = inbound_listener.local_addr().unwrap();
            let (selector, monitor) = direct_runtime().await;
            let listener_task = tokio::spawn(serve_websocket_listener(
                inbound_listener,
                InboundSpec {
                    id: "websocket-http-inbound".to_owned(),
                    protocol: "http".to_owned(),
                    listen: inbound_address,
                    username: String::new(),
                    password: String::new(),
                    udp_mode: UdpMode::Disabled,
                    protocol_udp: false,
                    transports: vec!["websocket".to_owned()],
                    outbound_id: "direct".to_owned(),
                },
                selector,
                monitor,
                None,
            ));

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let stream = TcpStream::connect(inbound_address).await.unwrap();
                let (mut websocket, _) =
                    tokio_tungstenite::client_async("ws://localhost/ws", stream)
                        .await
                        .unwrap();
                use tokio_tungstenite::tungstenite::Message;

                websocket
                    .send(Message::binary(
                        format!(
                            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                            echo_address, echo_address
                        )
                        .into_bytes(),
                    ))
                    .await
                    .unwrap();
                let response = websocket.next().await.unwrap().unwrap();
                let response = match response {
                    Message::Binary(data) => data.to_vec(),
                    Message::Text(data) => data.as_bytes().to_vec(),
                    other => panic!("unexpected WebSocket response: {other:?}"),
                };
                assert!(response.starts_with(b"HTTP/1.1 200"));

                websocket
                    .send(Message::binary(b"websocket-http".to_vec()))
                    .await
                    .unwrap();
                let echoed = websocket.next().await.unwrap().unwrap();
                let echoed = match echoed {
                    Message::Binary(data) => data.to_vec(),
                    Message::Text(data) => data.as_bytes().to_vec(),
                    other => panic!("unexpected WebSocket echo: {other:?}"),
                };
                assert_eq!(echoed, b"websocket-http");
                websocket.close(None).await.unwrap();
            })
            .await;

            listener_task.abort();
            let _ = listener_task.await;
            echo_task.abort();
            let _ = echo_task.await;
            result.unwrap();
        });
    }

    #[test]
    fn yuubinsya_inbound_routes_a_real_tcp_flow_through_the_shared_outbound() {
        block_on(async {
            let (echo_address, echo_task) = echo_server().await;
            let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let inbound_address = inbound_listener.local_addr().unwrap();
            let (selector, monitor) = direct_runtime().await;
            let listener_task = tokio::spawn(serve_listener(
                inbound_listener,
                InboundSpec {
                    id: "yuubinsya-inbound".to_owned(),
                    protocol: "yuubinsya".to_owned(),
                    listen: inbound_address,
                    username: String::new(),
                    password: "test-password".to_owned(),
                    udp_mode: UdpMode::Disabled,
                    protocol_udp: false,
                    transports: vec!["normal".to_owned()],
                    outbound_id: "direct".to_owned(),
                },
                selector,
                monitor,
                None,
            ));

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let transport = TcpStream::connect(inbound_address).await.unwrap();
                let password = yuhaiin_core::yuubinsya::derive_salt(b"test-password");
                let destination = Endpoint::ip(Network::Tcp, echo_address);
                let mut client =
                    AsyncYuubinsyaTcpSession::connect(transport, password, destination)
                        .await
                        .unwrap();
                client.write_all(b"yuubinsya-through-direct").await.unwrap();
                let mut echoed = vec![0u8; 24];
                client.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"yuubinsya-through-direct");
            })
            .await;

            listener_task.abort();
            let _ = listener_task.await;
            echo_task.abort();
            let _ = echo_task.await;
            result.unwrap();
        });
    }

    #[cfg(feature = "doh-tls")]
    #[test]
    fn tls_transport_wraps_http_inbound_and_routes_a_real_tcp_flow() {
        block_on(async {
            use std::io::Cursor;

            use base64::Engine;
            use rustls::pki_types::{CertificateDer, ServerName};
            use tokio_rustls::TlsConnector;

            let (echo_address, echo_task) = echo_server().await;
            let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let inbound_address = inbound_listener.local_addr().unwrap();
            let config = json!({
                "transport": [{
                    "type": "tls",
                    "tls": {
                        "tls": {
                            "certificates": [{
                                "certBase64": base64::engine::general_purpose::STANDARD.encode(
                                    [LEAF_CERTIFICATE_PEM, CA_CERTIFICATE_PEM].concat()
                                ),
                                "keyBase64": base64::engine::general_purpose::STANDARD.encode(PRIVATE_KEY_PEM)
                            }],
                            "nextProtos": []
                        }
                    }
                }]
            });
            let acceptor = build_inbound_tls_acceptor(
                &serde_json::to_vec(&config).unwrap(),
                &["tls".to_owned()],
            )
            .unwrap()
            .unwrap();
            let (selector, monitor) = direct_runtime().await;
            let listener_task = tokio::spawn(serve_listener(
                inbound_listener,
                InboundSpec {
                    id: "tls-http-inbound".to_owned(),
                    protocol: "http".to_owned(),
                    listen: inbound_address,
                    username: String::new(),
                    password: String::new(),
                    udp_mode: UdpMode::Disabled,
                    protocol_udp: false,
                    transports: vec!["tls".to_owned()],
                    outbound_id: "direct".to_owned(),
                },
                selector,
                monitor,
                Some(acceptor),
            ));

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let mut roots = rustls::RootCertStore::empty();
                let certificate = rustls_pemfile::certs(&mut Cursor::new(CA_CERTIFICATE_PEM))
                    .next()
                    .unwrap()
                    .unwrap();
                roots.add(CertificateDer::from(certificate)).unwrap();
                let client = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls_rustcrypto::provider(),
                ))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
                let connector = TlsConnector::from(Arc::new(client));
                let transport = TcpStream::connect(inbound_address).await.unwrap();
                let mut client = connector
                    .connect(
                        ServerName::try_from("localhost".to_owned()).unwrap(),
                        transport,
                    )
                    .await
                    .unwrap();
                client
                    .write_all(
                        format!(
                            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                            echo_address, echo_address
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                let headers = {
                    let mut headers = Vec::new();
                    let mut byte = [0u8; 1];
                    while !headers.ends_with(b"\r\n\r\n") {
                        client.read_exact(&mut byte).await.unwrap();
                        headers.push(byte[0]);
                    }
                    headers
                };
                assert!(headers.starts_with(b"HTTP/1.1 200 Connection Established"));
                client.write_all(b"tls-through-direct").await.unwrap();
                let mut echoed = vec![0u8; 18];
                client.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"tls-through-direct");
            })
            .await;

            listener_task.abort();
            let _ = listener_task.await;
            echo_task.abort();
            let _ = echo_task.await;
            result.unwrap();
        });
    }

    #[cfg(all(feature = "websocket", feature = "http2"))]
    #[test]
    fn websocket_http2_transport_bridges_http_inbound_and_routes_a_real_tcp_flow() {
        block_on(async {
            use bytes::Bytes;
            use http::Request;

            let (echo_address, echo_task) = echo_server().await;
            let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let inbound_address = inbound_listener.local_addr().unwrap();
            let (selector, monitor) = direct_runtime().await;
            let listener_task = tokio::spawn(serve_websocket_h2_listener(
                inbound_listener,
                InboundSpec {
                    id: "websocket-http2-inbound".to_owned(),
                    protocol: "http".to_owned(),
                    listen: inbound_address,
                    username: String::new(),
                    password: String::new(),
                    udp_mode: UdpMode::Disabled,
                    protocol_udp: false,
                    transports: vec!["websocket".to_owned(), "http2".to_owned()],
                    outbound_id: "direct".to_owned(),
                },
                selector,
                monitor,
                None,
            ));

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let transport = TcpStream::connect(inbound_address).await.unwrap();
                let (websocket, _) =
                    tokio_tungstenite::client_async("ws://localhost/proxy/ws", transport)
                        .await
                        .unwrap();
                let (mut client, connection) =
                    h2::client::handshake(crate::proxy::websocket::WebSocketIo::new(websocket))
                        .await
                        .unwrap();
                let connection_task = tokio::spawn(async move {
                    let _ = connection.await;
                });
                let request = Request::builder()
                    .method(http::Method::CONNECT)
                    .uri("http://localhost")
                    .body(())
                    .unwrap();
                let (response, mut request_body) = client.send_request(request, false).unwrap();
                let response = response.await.unwrap();
                assert_eq!(response.status(), http::StatusCode::OK);
                let request_headers = format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo_address, echo_address
                );
                request_body
                    .send_data(Bytes::from(request_headers), false)
                    .unwrap();
                request_body
                    .send_data(Bytes::from_static(b"websocket-http2"), true)
                    .unwrap();
                let mut body = response.into_body();
                let mut received = Vec::new();
                while let Some(data) = body.data().await {
                    let data = data.unwrap();
                    body.flow_control().release_capacity(data.len()).unwrap();
                    received.extend_from_slice(&data);
                    if received.ends_with(b"websocket-http2") {
                        break;
                    }
                }
                assert!(received.starts_with(b"HTTP/1.1 200 Connection Established\r\n\r\n"));
                assert!(received.ends_with(b"websocket-http2"));
                connection_task.abort();
                let _ = connection_task.await;
            })
            .await;

            listener_task.abort();
            let _ = listener_task.await;
            echo_task.abort();
            let _ = echo_task.await;
            result.unwrap();
        });
    }

    #[cfg(feature = "http2")]
    #[test]
    fn http2_transport_bridges_each_connect_stream_to_the_protocol_server() {
        block_on(async {
            use bytes::Bytes;
            use http::Request;

            let (echo_address, echo_task) = echo_server().await;
            let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let inbound_address = inbound_listener.local_addr().unwrap();
            let (selector, monitor) = direct_runtime().await;
            let listener_task = tokio::spawn(serve_h2_listener(
                inbound_listener,
                InboundSpec {
                    id: "http2-http-inbound".to_owned(),
                    protocol: "http".to_owned(),
                    listen: inbound_address,
                    username: String::new(),
                    password: String::new(),
                    udp_mode: UdpMode::Disabled,
                    protocol_udp: false,
                    transports: vec!["http2".to_owned()],
                    outbound_id: "direct".to_owned(),
                },
                selector,
                monitor,
                None,
            ));

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let transport = TcpStream::connect(inbound_address).await.unwrap();
                let (mut client, connection) = h2::client::handshake(transport).await.unwrap();
                let connection_task = tokio::spawn(async move {
                    let _ = connection.await;
                });
                let request = Request::builder()
                    .method(http::Method::CONNECT)
                    .uri("http://localhost")
                    .body(())
                    .unwrap();
                let (response, mut request_body) = client.send_request(request, false).unwrap();
                let response = response.await.unwrap();
                assert_eq!(response.status(), http::StatusCode::OK);
                let request_headers = format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                    echo_address, echo_address
                );
                request_body
                    .send_data(Bytes::from(request_headers), false)
                    .unwrap();
                request_body
                    .send_data(Bytes::from_static(b"http2-through-direct"), true)
                    .unwrap();
                let mut body = response.into_body();
                let mut received = Vec::new();
                while let Some(data) = body.data().await {
                    let data = data.unwrap();
                    body.flow_control().release_capacity(data.len()).unwrap();
                    received.extend_from_slice(&data);
                    if received.len() >= 58 {
                        break;
                    }
                }
                assert!(received.starts_with(b"HTTP/1.1 200 Connection Established\r\n\r\n"));
                assert!(received.ends_with(b"http2-through-direct"));
                connection_task.abort();
                let _ = connection_task.await;
            })
            .await;

            listener_task.abort();
            let _ = listener_task.await;
            echo_task.abort();
            let _ = echo_task.await;
            result.unwrap();
        });
    }
}
