//! Inbound proxy listeners and their connection into the shared outbound
//! selector.
//!
//! TUN is only one inbound. This module owns the normal TCP variants of the
//! Go inbound contract: SOCKS5, HTTP CONNECT and Yuubinsya. Each accepted
//! request is converted into the same [`FlowContext`] used by TUN, then routed
//! through the live `RuntimeProxySelector`; listeners therefore observe
//! direct/proxy/bypass/drop changes after a reload without duplicating proxy
//! construction logic.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use yuhaiin_chain::YuubinsyaServerProxy;
use yuhaiin_core::proxy::{AsyncProxy, AsyncProxySelector, BoxAsyncStream};
use yuhaiin_core::tun::{TunFlow, TunFlowDirection, TunFlowKey, TunFlowObserver};
use yuhaiin_core::yuubinsya::derive_salt;
use yuhaiin_core::{
    BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, Network, Result,
};
use yuhaiin_store::GoInboundRecord;

use crate::{ConnectionMonitor, RuntimeController, RuntimeProxySelector};

const MAX_HEADERS: usize = 64 * 1024;
const RELAY_BUFFER: usize = 16 * 1024;

#[derive(Debug, Clone)]
struct InboundSpec {
    id: String,
    name: String,
    protocol: String,
    listen: SocketAddr,
    username: String,
    password: String,
    udp: bool,
    transports: Vec<String>,
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
    let proxy_id = controller
        .store()
        .repository()
        .list_go_nodes()
        .await?
        .into_iter()
        .find(|node| node.enabled)
        .map(|node| node.id)
        .unwrap_or_else(|| "direct".to_owned());
    let selector = controller
        .build_proxy_selector("", &proxy_id, "", "", Duration::from_secs(30))
        .await?;
    let monitor = controller.monitor();
    let mut listeners = Vec::new();
    for record in records.into_iter().filter(|record| record.enabled) {
        let spec = match InboundSpec::from_record(record) {
            Ok(spec) => spec,
            Err(error) => {
                eprintln!("skip inbound: {error}");
                continue;
            }
        };
        if !spec.transports.is_empty()
            && spec
                .transports
                .iter()
                .any(|transport| !transport.eq_ignore_ascii_case("normal"))
        {
            eprintln!(
                "skip inbound {}: only normal transport is currently implemented",
                spec.id
            );
            continue;
        }
        let listener = TcpListener::bind(spec.listen).await.map_err(|error| {
            Error::new(ErrorKind::Io, format!("bind inbound {}: {error}", spec.id))
        })?;
        let selector = selector.clone();
        let monitor = monitor.clone();
        listeners.push(tokio::spawn(async move {
            if let Err(error) = serve_listener(listener, spec, selector, monitor).await {
                eprintln!("inbound listener stopped: {error}");
            }
        }));
    }
    Ok(listeners)
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
        let udp = section
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
            name: record.name,
            protocol,
            listen,
            username,
            password,
            udp,
            transports,
        })
    }
}

async fn serve_listener(
    listener: TcpListener,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()> {
    let protocol = spec.protocol.clone();
    loop {
        let (stream, peer) = listener.accept().await.map_err(io_error)?;
        let selector = selector.clone();
        let monitor = monitor.clone();
        let spec = spec.clone();
        let protocol = protocol.clone();
        tokio::spawn(async move {
            let result = match protocol.as_str() {
                "socks5" => serve_socks5(stream, peer, spec, selector, monitor).await,
                "http" | "mixed" => serve_http(stream, peer, spec, selector, monitor).await,
                "yuubinsya" => serve_yuubinsya(stream, spec, selector).await,
                other => Err(Error::new(
                    ErrorKind::Unsupported,
                    format!("inbound protocol {other:?} is not implemented"),
                )),
            };
            if let Err(error) = result {
                eprintln!("inbound connection error: {error}");
            }
        });
    }
}

async fn serve_socks5(
    mut stream: TcpStream,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()> {
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.map_err(io_error)?;
    if greeting[0] != 5 {
        return Err(Error::new(ErrorKind::Protocol, "SOCKS5 version is not 5"));
    }
    let mut methods = vec![0u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await.map_err(io_error)?;
    let requires_auth = !spec.username.is_empty() || !spec.password.is_empty();
    let selected = if requires_auth && methods.contains(&2) {
        2
    } else if !requires_auth && methods.contains(&0) {
        0
    } else {
        255
    };
    stream.write_all(&[5, selected]).await.map_err(io_error)?;
    if selected == 255 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "SOCKS5 no acceptable method",
        ));
    }
    if selected == 2 {
        let mut auth_head = [0u8; 2];
        stream.read_exact(&mut auth_head).await.map_err(io_error)?;
        if auth_head[0] != 1 {
            return Err(Error::new(
                ErrorKind::Protocol,
                "SOCKS5 auth version is not 1",
            ));
        }
        let mut username = vec![0u8; usize::from(auth_head[1])];
        stream.read_exact(&mut username).await.map_err(io_error)?;
        let mut password_len = [0u8; 1];
        stream
            .read_exact(&mut password_len)
            .await
            .map_err(io_error)?;
        let mut password = vec![0u8; usize::from(password_len[0])];
        stream.read_exact(&mut password).await.map_err(io_error)?;
        let ok = username == spec.username.as_bytes() && password == spec.password.as_bytes();
        stream
            .write_all(&[1, if ok { 0 } else { 1 }])
            .await
            .map_err(io_error)?;
        if !ok {
            return Err(Error::new(
                ErrorKind::Protocol,
                "SOCKS5 authentication failed",
            ));
        }
    }
    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await.map_err(io_error)?;
    if request[0] != 5 || request[2] != 0 {
        return Err(Error::new(ErrorKind::Protocol, "invalid SOCKS5 request"));
    }
    if request[1] != 1 {
        write_socks_reply(&mut stream, 7).await?;
        return Err(Error::new(
            ErrorKind::Unsupported,
            "SOCKS5 command is not CONNECT",
        ));
    }
    let destination = read_socks_endpoint(&mut stream, Network::Tcp).await?;
    let source = Endpoint::ip(Network::Tcp, peer);
    let mut context = FlowContext::new(destination.clone());
    context.source = Some(source);
    context.original_domain = destination.host().cloned();
    let proxy = selector.select(&context);
    let outbound = match proxy.connect(&context).await {
        Ok(outbound) => outbound,
        Err(error) => {
            write_socks_reply(&mut stream, 5).await?;
            return Err(error);
        }
    };
    write_socks_reply(&mut stream, 0).await?;
    relay_counted(
        stream,
        outbound,
        TunFlowKey {
            network: Network::Tcp,
            source: peer,
            destination: destination
                .addr()
                .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
        },
        context,
        monitor,
    )
    .await
    .map_err(io_error)
}

async fn serve_http(
    mut stream: TcpStream,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()> {
    let headers = read_headers(&mut stream).await?;
    let mut lines = headers.split("\r\n");
    let request = lines
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "HTTP proxy request is empty"))?;
    let mut fields = request.split_whitespace();
    let method = fields.next().unwrap_or_default();
    let target = fields.next().unwrap_or_default();
    if method.eq_ignore_ascii_case("CONNECT") {
        if !authorized_http(&headers, &spec.username, &spec.password) {
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .map_err(io_error)?;
            return Err(Error::new(
                ErrorKind::Protocol,
                "HTTP proxy authentication failed",
            ));
        }
        let destination = parse_authority(target, Network::Tcp)?;
        let source = Endpoint::ip(Network::Tcp, peer);
        let mut context = FlowContext::new(destination.clone());
        context.source = Some(source);
        context.original_domain = destination.host().cloned();
        let proxy = selector.select(&context);
        let outbound = proxy.connect(&context).await?;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(io_error)?;
        return relay_counted(
            stream,
            outbound,
            TunFlowKey {
                network: Network::Tcp,
                source: peer,
                destination: destination
                    .addr()
                    .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
            },
            context,
            monitor,
        )
        .await
        .map_err(io_error);
    }
    stream
        .write_all(b"HTTP/1.1 501 Not Implemented\r\nConnection: close\r\n\r\n")
        .await
        .map_err(io_error)?;
    Err(Error::new(
        ErrorKind::Unsupported,
        format!("HTTP proxy method {method:?} is not CONNECT"),
    ))
}

async fn serve_yuubinsya(
    stream: TcpStream,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
) -> Result<()> {
    let upstream: Arc<dyn AsyncProxy> = Arc::new(RoutedProxy { selector });
    let server = YuubinsyaServerProxy::new(derive_salt(spec.password.as_bytes()), upstream);
    server.serve(stream).await
}

#[derive(Clone)]
struct RoutedProxy {
    selector: Arc<RuntimeProxySelector>,
}

impl AsyncProxy for RoutedProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move { self.selector.select(context).connect(context).await })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn yuhaiin_core::proxy::AsyncDatagram>>> {
        Box::pin(async move { self.selector.select(context).open_datagram(context).await })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        Box::pin(async move { self.selector.select(context).ping(context).await })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

async fn relay_counted<A, B>(
    left: A,
    right: B,
    flow: TunFlowKey,
    context: FlowContext,
    monitor: Arc<ConnectionMonitor>,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    monitor.opened(TunFlow { key: flow }, context);
    let (mut left_read, mut left_write) = split(left);
    let (mut right_read, mut right_write) = split(right);
    let upload = copy_counted(
        &mut left_read,
        &mut right_write,
        monitor.clone(),
        flow,
        TunFlowDirection::Upload,
    );
    let download = copy_counted(
        &mut right_read,
        &mut left_write,
        monitor.clone(),
        flow,
        TunFlowDirection::Download,
    );
    let result = tokio::try_join!(upload, download).map(|_| ());
    monitor.closed(flow);
    result
}

async fn copy_counted<R, W>(
    reader: &mut ReadHalf<R>,
    writer: &mut WriteHalf<W>,
    monitor: Arc<ConnectionMonitor>,
    flow: TunFlowKey,
    direction: TunFlowDirection,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; RELAY_BUFFER];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        writer.write_all(&buffer[..read]).await?;
        monitor.bytes(flow, direction, read);
    }
}

async fn read_headers(stream: &mut TcpStream) -> Result<String> {
    let mut bytes = Vec::with_capacity(1024);
    let mut one = [0u8; 1];
    while bytes.len() < MAX_HEADERS {
        stream.read_exact(&mut one).await.map_err(io_error)?;
        bytes.push(one[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes).map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("HTTP headers: {error}"))
            });
        }
    }
    Err(Error::new(ErrorKind::Protocol, "HTTP headers exceed limit"))
}

async fn read_socks_endpoint(stream: &mut TcpStream, network: Network) -> Result<Endpoint> {
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await.map_err(io_error)?;
    match atyp[0] {
        1 => {
            let mut address = [0u8; 4 + 2];
            stream.read_exact(&mut address).await.map_err(io_error)?;
            let ip = IpAddr::from([address[0], address[1], address[2], address[3]]);
            Ok(Endpoint::ip(
                network,
                SocketAddr::new(ip, u16::from_be_bytes([address[4], address[5]])),
            ))
        }
        4 => {
            let mut address = [0u8; 16 + 2];
            stream.read_exact(&mut address).await.map_err(io_error)?;
            let ip = IpAddr::from(<[u8; 16]>::try_from(&address[..16]).unwrap());
            Ok(Endpoint::ip(
                network,
                SocketAddr::new(ip, u16::from_be_bytes([address[16], address[17]])),
            ))
        }
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await.map_err(io_error)?;
            if length[0] == 0 || usize::from(length[0]) > 253 {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "invalid SOCKS5 domain length",
                ));
            }
            let mut host = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut host).await.map_err(io_error)?;
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await.map_err(io_error)?;
            let host = String::from_utf8(host).map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("SOCKS5 domain: {error}"))
            })?;
            Ok(Endpoint::domain(
                network,
                DomainName::new(&host)?,
                u16::from_be_bytes(port),
            ))
        }
        _ => Err(Error::new(
            ErrorKind::Protocol,
            "unsupported SOCKS5 address type",
        )),
    }
}

async fn write_socks_reply(stream: &mut TcpStream, code: u8) -> Result<()> {
    stream
        .write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(io_error)
}

fn parse_authority(value: &str, network: Network) -> Result<Endpoint> {
    let value = value.trim();
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest
            .split_once(']')
            .and_then(|(host, rest)| rest.strip_prefix(':').map(|port| (host, port)))
            .ok_or_else(|| Error::new(ErrorKind::Protocol, "invalid bracketed authority"))?;
        (host, port)
    } else {
        value
            .rsplit_once(':')
            .ok_or_else(|| Error::new(ErrorKind::Protocol, "authority has no port"))?
    };
    let port = port
        .parse::<u16>()
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("authority port: {error}")))?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(Endpoint::ip(network, SocketAddr::new(ip, port)))
    } else {
        Ok(Endpoint::domain(network, DomainName::new(host)?, port))
    }
}

fn authorized_http(headers: &str, username: &str, password: &str) -> bool {
    if username.is_empty() && password.is_empty() {
        return true;
    }
    let expected =
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
    headers.lines().any(|line| {
        let Some(value) = line.strip_prefix("Proxy-Authorization:") else {
            return false;
        };
        value
            .trim()
            .strip_prefix("Basic ")
            .is_some_and(|token| token == expected)
    })
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

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}
