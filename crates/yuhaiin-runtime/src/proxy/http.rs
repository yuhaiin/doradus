use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use yuhaiin_core::proxy::AsyncProxySelector;
use yuhaiin_core::tun::TunFlowKey;
use yuhaiin_core::{DomainName, Endpoint, Error, ErrorKind, FlowContext, Network, Result};

use super::common::{io_error, relay_counted};
use crate::inbound::InboundSpec;
use crate::{ConnectionMonitor, RuntimeProxySelector};

const MAX_HEADERS: usize = 64 * 1024;

pub(crate) async fn serve(
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
