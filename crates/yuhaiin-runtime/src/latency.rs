//! Proxy-aware node latency probes.
//!
//! The management API must measure the configured node, not the management
//! process itself.  This module therefore owns only the probe protocol and
//! consumes the shared `AsyncProxy` boundary; it does not know how an inbound
//! or an outbound proxy was built.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use yuhaiin_core::proxy::{AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{DomainName, Endpoint, Error, ErrorKind, FlowContext, Network, Result};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LatencyRequest {
    #[serde(rename = "type")]
    pub probe_type: String,
    pub url: String,
    pub user_agent: String,
    pub host: String,
    pub target_domain: String,
    pub ipv6: bool,
    pub tcp: bool,
}

impl Default for LatencyRequest {
    fn default() -> Self {
        Self {
            probe_type: String::new(),
            url: String::new(),
            user_agent: String::new(),
            host: String::new(),
            target_domain: String::new(),
            ipv6: true,
            tcp: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LatencyResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "is_zero")]
    pub latency_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpLatency>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stun: Option<StunLatency>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpLatency {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ipv4: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ipv6: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StunLatency {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub xor_mapped_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mapped_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub other_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub response_origin_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub software: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mapping: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub filtering: String,
}

#[derive(Debug, Clone)]
struct HttpTarget {
    https: bool,
    host: String,
    port: u16,
    authority: String,
    path: String,
}

#[derive(Debug)]
struct HttpReply {
    elapsed: Duration,
    body: Vec<u8>,
}

static TRANSACTION_COUNTER: AtomicU64 = AtomicU64::new(1);

pub async fn probe(
    proxy: Arc<dyn AsyncProxy>,
    mut request: LatencyRequest,
    timeout: Duration,
) -> Result<LatencyResponse> {
    let probe_type = if request.probe_type.trim().is_empty() {
        "http".to_owned()
    } else {
        request.probe_type.trim().to_owned()
    };
    request.probe_type = probe_type.clone();

    match probe_type.as_str() {
        "" | "http" | "tcp" => {
            let target = request.url_or_default(false);
            let reply =
                tokio::time::timeout(timeout, http_probe(&proxy, &target, &request, timeout))
                    .await
                    .map_err(|_| {
                        Error::new(ErrorKind::Timeout, "HTTP latency probe timed out")
                    })??;
            Ok(success(reply.elapsed))
        }
        "ip" => probe_ip(proxy, request, timeout).await,
        "stun" | "stun_tcp" => probe_stun(proxy, request, timeout).await,
        "doq" | "dns" | "udp" => Err(Error::new(
            ErrorKind::Unsupported,
            format!("latency probe type {probe_type:?} is not implemented; DoQ remains deferred"),
        )),
        other => Err(Error::new(
            ErrorKind::Unsupported,
            format!("latency probe type {other:?} is not supported"),
        )),
    }
}

impl LatencyRequest {
    fn url_or_default(&self, ip: bool) -> String {
        if !self.url.trim().is_empty() {
            return self.url.trim().to_owned();
        }
        if ip {
            "https://api.ipify.org".to_owned()
        } else {
            "https://clients3.google.com/generate_204".to_owned()
        }
    }

    fn host_or_default(&self, tcp: bool) -> String {
        if !self.host.trim().is_empty() {
            return self.host.trim().to_owned();
        }
        if tcp {
            "stun.l.google.com:19302".to_owned()
        } else {
            "stun.l.google.com:19302".to_owned()
        }
    }
}

fn success(elapsed: Duration) -> LatencyResponse {
    LatencyResponse {
        ok: true,
        latency_ms: elapsed.as_millis().min(i64::MAX as u128) as i64,
        ip: None,
        stun: None,
        error: String::new(),
    }
}

async fn probe_ip(
    proxy: Arc<dyn AsyncProxy>,
    request: LatencyRequest,
    timeout: Duration,
) -> Result<LatencyResponse> {
    let target = request.url_or_default(true);
    let (v4, v6) = tokio::join!(
        http_probe(&proxy, &target, &request, timeout),
        http_probe(&proxy, &target, &request, timeout),
    );
    let mut ip = IpLatency::default();
    if let Ok(reply) = v4 {
        let value = String::from_utf8_lossy(&reply.body).trim().to_owned();
        if value.parse::<Ipv4Addr>().is_ok() {
            ip.ipv4 = value;
        } else if value.parse::<Ipv6Addr>().is_ok() {
            ip.ipv6 = value;
        }
    }
    if let Ok(reply) = v6 {
        let value = String::from_utf8_lossy(&reply.body).trim().to_owned();
        if value.parse::<Ipv6Addr>().is_ok() {
            ip.ipv6 = value;
        } else if value.parse::<Ipv4Addr>().is_ok() {
            ip.ipv4 = value;
        }
    }
    if ip.ipv4.is_empty() && ip.ipv6.is_empty() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "IP latency endpoint returned no IPv4 or IPv6 address",
        ));
    }
    Ok(LatencyResponse {
        ok: true,
        latency_ms: 0,
        ip: Some(ip),
        stun: None,
        error: String::new(),
    })
}

async fn http_probe(
    proxy: &Arc<dyn AsyncProxy>,
    url: &str,
    request: &LatencyRequest,
    timeout: Duration,
) -> Result<HttpReply> {
    let target = parse_http_target(url)?;
    let endpoint = endpoint(Network::Tcp, &target.host, target.port)?;
    let context = FlowContext::new(endpoint);
    let started = std::time::Instant::now();
    let stream = tokio::time::timeout(timeout, proxy.connect(&context))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "proxy connect timed out"))??;
    let mut stream = wrap_tls_if_needed(stream, &target, timeout).await?;
    let user_agent = if request.user_agent.trim().is_empty() {
        "curl/7.54.1"
    } else {
        request.user_agent.trim()
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        target.path, target.authority, user_agent
    );
    tokio::time::timeout(
        timeout,
        tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()),
    )
    .await
    .map_err(|_| Error::new(ErrorKind::Timeout, "HTTP request write timed out"))?
    .map_err(io_error)?;
    let body = read_http_response(&mut stream, timeout).await?;
    Ok(HttpReply {
        elapsed: started.elapsed(),
        body,
    })
}

async fn read_http_response(stream: &mut BoxAsyncStream, timeout: Duration) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;

    let mut headers = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        let count = tokio::time::timeout(timeout, stream.read(&mut chunk))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "HTTP response headers timed out"))?
            .map_err(io_error)?;
        if count == 0 {
            return Err(Error::new(
                ErrorKind::Protocol,
                "HTTP response ended before headers",
            ));
        }
        headers.extend_from_slice(&chunk[..count]);
        if headers.len() > 64 * 1024 {
            return Err(Error::new(
                ErrorKind::Protocol,
                "HTTP response headers are too large",
            ));
        }
        if let Some(index) = headers.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let header_text = String::from_utf8_lossy(&headers[..header_end]);
    let content_length = header_text.lines().find_map(|line| {
        line.strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
    });
    let mut body = headers[header_end..].to_vec();
    if let Some(length) = content_length {
        if length > 4 * 1024 * 1024 {
            return Err(Error::new(
                ErrorKind::Protocol,
                "HTTP response body is too large",
            ));
        }
        body.resize(length.min(4 * 1024 * 1024), 0);
        let already = headers.len().saturating_sub(header_end);
        if already < body.len() {
            tokio::time::timeout(timeout, stream.read_exact(&mut body[already..]))
                .await
                .map_err(|_| Error::new(ErrorKind::Timeout, "HTTP response body timed out"))?
                .map_err(io_error)?;
        }
        body.truncate(length.min(4 * 1024 * 1024));
    } else {
        while body.len() < 4 * 1024 * 1024 {
            let remaining = 4 * 1024 * 1024 - body.len();
            let read_size = remaining.min(chunk.len());
            let count = tokio::time::timeout(timeout, stream.read(&mut chunk[..read_size]))
                .await
                .map_err(|_| Error::new(ErrorKind::Timeout, "HTTP response body timed out"))?
                .map_err(io_error)?;
            if count == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..count]);
        }
    }
    Ok(body)
}

async fn probe_stun(
    proxy: Arc<dyn AsyncProxy>,
    request: LatencyRequest,
    timeout: Duration,
) -> Result<LatencyResponse> {
    let tcp = request.probe_type == "stun_tcp" || request.tcp;
    let target = parse_host_port(&request.host_or_default(tcp), 3478)?;
    let transaction = transaction_id();
    let packet = stun_binding_request(transaction);
    let started = std::time::Instant::now();
    let values = if tcp {
        let endpoint = endpoint(Network::Tcp, &target.0, target.1)?;
        let context = FlowContext::new(endpoint);
        let mut stream = tokio::time::timeout(timeout, proxy.connect(&context))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "STUN TCP connect timed out"))??;
        use tokio::io::AsyncWriteExt;
        let mut framed = Vec::with_capacity(packet.len() + 2);
        framed.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        framed.extend_from_slice(&packet);
        tokio::time::timeout(timeout, stream.write_all(&framed))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "STUN TCP write timed out"))?
            .map_err(io_error)?;
        let response = read_stun_tcp(&mut stream, timeout).await?;
        parse_stun_response(&response, transaction)?
    } else {
        let endpoint = endpoint(Network::Udp, &target.0, target.1)?;
        let context = FlowContext::new(endpoint.clone());
        let datagram = tokio::time::timeout(timeout, proxy.open_datagram(&context))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "STUN UDP open timed out"))??;
        tokio::time::timeout(timeout, datagram.send_to(&packet, endpoint))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "STUN UDP write timed out"))??;
        let mut buffer = vec![0u8; 2048];
        let (length, _) = tokio::time::timeout(timeout, datagram.recv_from(&mut buffer))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "STUN UDP response timed out"))??;
        datagram.close().await?;
        parse_stun_response(&buffer[..length], transaction)?
    };
    Ok(LatencyResponse {
        ok: true,
        latency_ms: started.elapsed().as_millis().min(i64::MAX as u128) as i64,
        ip: None,
        stun: Some(values),
        error: String::new(),
    })
}

async fn read_stun_tcp(stream: &mut BoxAsyncStream, timeout: Duration) -> Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut length = [0u8; 2];
    tokio::time::timeout(timeout, stream.read_exact(&mut length))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "STUN TCP length timed out"))?
        .map_err(io_error)?;
    let length = usize::from(u16::from_be_bytes(length));
    if length > 2048 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "STUN TCP response is too large",
        ));
    }
    let mut response = vec![0u8; length];
    tokio::time::timeout(timeout, stream.read_exact(&mut response))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "STUN TCP response timed out"))?
        .map_err(io_error)?;
    Ok(response)
}

fn parse_http_target(url: &str) -> Result<HttpTarget> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| Error::invalid("latency URL must include http:// or https://"))?;
    let https = match scheme.to_ascii_lowercase().as_str() {
        "http" => false,
        "https" => true,
        _ => return Err(Error::invalid("latency URL scheme is not HTTP(S)")),
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = parse_host_port(authority, if https { 443 } else { 80 })?;
    let path = if path.is_empty() {
        "/".to_owned()
    } else {
        format!("/{path}")
    };
    Ok(HttpTarget {
        https,
        host,
        port,
        authority: authority.to_owned(),
        path,
    })
}

fn parse_host_port(value: &str, default_port: u16) -> Result<(String, u16)> {
    let value = value
        .strip_prefix("stun://")
        .or_else(|| value.strip_prefix("udp://"))
        .or_else(|| value.strip_prefix("tcp://"))
        .unwrap_or(value);
    if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| Error::invalid("latency host has an invalid IPv6 authority"))?;
        let port = rest
            .strip_prefix(':')
            .map(|port| port.parse::<u16>())
            .transpose()
            .map_err(|error| Error::invalid(format!("latency host port: {error}")))?
            .unwrap_or(default_port);
        return Ok((host.to_owned(), port));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if host.contains(':') {
            return Ok((value.to_owned(), default_port));
        }
        return Ok((
            host.to_owned(),
            port.parse::<u16>()
                .map_err(|error| Error::invalid(format!("latency host port: {error}")))?,
        ));
    }
    if value.is_empty() {
        return Err(Error::invalid("latency host is empty"));
    }
    Ok((value.to_owned(), default_port))
}

fn endpoint(network: Network, host: &str, port: u16) -> Result<Endpoint> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(Endpoint::ip(network, SocketAddr::new(address, port)));
    }
    Ok(Endpoint::domain(network, DomainName::new(host)?, port))
}

async fn wrap_tls_if_needed(
    stream: BoxAsyncStream,
    target: &HttpTarget,
    timeout: Duration,
) -> Result<BoxAsyncStream> {
    if !target.https {
        return Ok(stream);
    }
    #[cfg(feature = "doh-tls")]
    {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = crate::doh_tls::client_config(roots)?;
        let connector = tokio_rustls::TlsConnector::from(config);
        let name = crate::doh_tls::tls_server_name(&target.host)?;
        let tls = tokio::time::timeout(timeout, connector.connect(name, stream))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "TLS handshake timed out"))?
            .map_err(|error| Error::new(ErrorKind::Protocol, format!("TLS: {error}")))?;
        return Ok(Box::new(tls));
    }
    #[cfg(not(feature = "doh-tls"))]
    {
        let _ = (stream, timeout);
        Err(Error::new(
            ErrorKind::Unsupported,
            "HTTPS latency requires the doh-tls feature",
        ))
    }
}

fn transaction_id() -> [u8; 12] {
    let counter = TRANSACTION_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut id = [0u8; 12];
    id[..8].copy_from_slice(&(now as u64 ^ counter).to_be_bytes());
    id[8..].copy_from_slice(&(counter as u32).to_be_bytes());
    id
}

fn stun_binding_request(transaction: [u8; 12]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20);
    packet.extend_from_slice(&0x0001u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0x2112_A442u32.to_be_bytes());
    packet.extend_from_slice(&transaction);
    packet
}

fn parse_stun_response(packet: &[u8], transaction: [u8; 12]) -> Result<StunLatency> {
    if packet.len() < 20 || packet[0] & 0xc0 != 0 {
        return Err(Error::new(ErrorKind::Protocol, "invalid STUN response"));
    }
    let message_type = u16::from_be_bytes([packet[0], packet[1]]);
    if message_type != 0x0101 && message_type != 0x0111 {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("unexpected STUN response type 0x{message_type:04x}"),
        ));
    }
    let length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if length > packet.len().saturating_sub(20) {
        return Err(Error::new(ErrorKind::Protocol, "truncated STUN response"));
    }
    if packet[8..20] != transaction {
        return Err(Error::new(ErrorKind::Protocol, "STUN transaction mismatch"));
    }
    let mut result = StunLatency::default();
    let end = 20 + length;
    let mut offset = 20;
    while offset + 4 <= end {
        let kind = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let size = usize::from(u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]));
        offset += 4;
        if offset + size > end {
            return Err(Error::new(ErrorKind::Protocol, "truncated STUN attribute"));
        }
        let value = &packet[offset..offset + size];
        match kind {
            0x0001 => result.mapped_address = decode_address(value, false, transaction)?,
            0x0020 => result.xor_mapped_address = decode_address(value, true, transaction)?,
            0x8022 => result.software = String::from_utf8_lossy(value).to_string(),
            0x802b => result.response_origin_address = decode_address(value, true, transaction)?,
            0x802c => result.other_address = decode_address(value, true, transaction)?,
            _ => {}
        }
        offset += (size + 3) & !3;
    }
    if result.mapped_address.is_empty() && result.xor_mapped_address.is_empty() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "STUN response has no mapped address",
        ));
    }
    Ok(result)
}

fn decode_address(value: &[u8], xor: bool, transaction: [u8; 12]) -> Result<String> {
    if value.len() < 4 {
        return Err(Error::new(
            ErrorKind::Protocol,
            "short STUN address attribute",
        ));
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= 0x2112;
    }
    let address = match family {
        1 if value.len() >= 8 => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&value[4..8]);
            if xor {
                for (byte, cookie) in bytes.iter_mut().zip(0x2112_A442u32.to_be_bytes()) {
                    *byte ^= cookie;
                }
            }
            IpAddr::V4(Ipv4Addr::from(bytes))
        }
        2 if value.len() >= 20 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&value[4..20]);
            if xor {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&0x2112_A442u32.to_be_bytes());
                mask[4..].copy_from_slice(&transaction);
                for (byte, mask) in bytes.iter_mut().zip(mask) {
                    *byte ^= mask;
                }
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Protocol,
                "unknown STUN address family",
            ));
        }
    };
    Ok(SocketAddr::new(address, port).to_string())
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;
    use yuhaiin_core::proxy::AsyncDatagram;
    use yuhaiin_core::{BoxFuture, FlowContext};

    struct EchoProxy;

    impl AsyncProxy for EchoProxy {
        fn connect<'a>(
            &'a self,
            context: &'a FlowContext,
        ) -> BoxFuture<'a, Result<BoxAsyncStream>> {
            let destination = context.effective_destination();
            Box::pin(async move {
                let (client, mut server) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 512];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        let Ok(count) = server.read(&mut chunk).await else {
                            return;
                        };
                        if count == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..count]);
                        if request.len() > 8192 {
                            return;
                        }
                    }
                    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\n203.0.113.7\n";
                    let _ = server.write_all(response).await;
                });
                let _ = destination;
                Ok(Box::new(client) as BoxAsyncStream)
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a FlowContext,
        ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            Box::pin(async {
                let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
                let datagram = TestDatagram {
                    tx,
                    rx: tokio::sync::Mutex::new(rx),
                };
                Ok(Box::new(datagram) as Box<dyn AsyncDatagram>)
            })
        }

        fn close(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct TcpStunProxy;

    impl AsyncProxy for TcpStunProxy {
        fn connect<'a>(
            &'a self,
            _context: &'a FlowContext,
        ) -> BoxFuture<'a, Result<BoxAsyncStream>> {
            Box::pin(async {
                let (client, mut server) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    let mut length = [0u8; 2];
                    if server.read_exact(&mut length).await.is_err() {
                        return;
                    }
                    let mut request = vec![0u8; usize::from(u16::from_be_bytes(length))];
                    if server.read_exact(&mut request).await.is_err() {
                        return;
                    }
                    let response = stun_response(&request);
                    let mut framed = Vec::with_capacity(response.len() + 2);
                    framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
                    framed.extend_from_slice(&response);
                    let _ = server.write_all(&framed).await;
                });
                Ok(Box::new(client) as BoxAsyncStream)
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a FlowContext,
        ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
            Box::pin(async {
                Err(Error::new(
                    ErrorKind::Unsupported,
                    "TCP STUN fixture has no datagram transport",
                ))
            })
        }

        fn close(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct TestDatagram {
        tx: mpsc::Sender<Vec<u8>>,
        rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    }

    impl AsyncDatagram for TestDatagram {
        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            _target: Endpoint,
        ) -> BoxFuture<'a, Result<usize>> {
            let tx = self.tx.clone();
            Box::pin(async move {
                tx.send(stun_response(payload))
                    .await
                    .map_err(|_| Error::new(ErrorKind::Closed, "test datagram closed"))?;
                Ok(payload.len())
            })
        }

        fn recv_from<'a>(
            &'a self,
            buffer: &'a mut [u8],
        ) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
            let rx = &self.rx;
            Box::pin(async move {
                let packet = rx
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| Error::new(ErrorKind::Closed, "test datagram closed"))?;
                buffer[..packet.len()].copy_from_slice(&packet);
                Ok((
                    packet.len(),
                    Endpoint::ip(Network::Udp, "127.0.0.1:3478".parse().unwrap()),
                ))
            })
        }

        fn local_addr(&self) -> Result<Endpoint> {
            Ok(Endpoint::ip(Network::Udp, "127.0.0.1:0".parse().unwrap()))
        }

        fn close(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn stun_response(request: &[u8]) -> Vec<u8> {
        let mut response = Vec::from([0x01, 0x01, 0, 12, 0x21, 0x12, 0xa4, 0x42]);
        response.extend_from_slice(&request[8..20]);
        let port = 3478u16 ^ 0x2112;
        let address = [127u8, 0, 0, 1];
        let cookie = 0x2112_A442u32.to_be_bytes();
        response.extend_from_slice(&[0, 0x20, 0, 8, 0, 1]);
        response.extend_from_slice(&port.to_be_bytes());
        response.extend(
            address
                .into_iter()
                .zip(cookie)
                .map(|(a, b)| a ^ b)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        response
    }

    #[test]
    fn parses_http_and_stun_authorities() {
        let http = parse_http_target("https://[::1]:8443/path?q=1").unwrap();
        assert!(http.https);
        assert_eq!(http.host, "::1");
        assert_eq!(http.port, 8443);
        assert_eq!(http.path, "/path?q=1");
        assert_eq!(parse_host_port("stun.example:3479", 3478).unwrap().1, 3479);
    }

    #[test]
    fn stun_xor_address_decodes() {
        let transaction = [1u8; 12];
        let mut packet = stun_binding_request(transaction);
        packet[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
        packet[2..4].copy_from_slice(&12u16.to_be_bytes());
        let port = 3478u16 ^ 0x2112;
        let address = [127u8, 0, 0, 1];
        let cookie = 0x2112_A442u32.to_be_bytes();
        packet.extend_from_slice(&[0, 0x20, 0, 8, 0, 1]);
        packet.extend_from_slice(&port.to_be_bytes());
        packet.extend(
            address
                .into_iter()
                .zip(cookie)
                .map(|(a, b)| a ^ b)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let reply = parse_stun_response(&packet, transaction).unwrap();
        assert_eq!(reply.xor_mapped_address, "127.0.0.1:3478");
    }

    #[tokio::test]
    async fn udp_stun_probe_uses_proxy_datagram_and_contract_shape() {
        let response = probe_stun(
            Arc::new(EchoProxy),
            LatencyRequest {
                probe_type: "stun".to_owned(),
                host: "127.0.0.1:3478".to_owned(),
                ..LatencyRequest::default()
            },
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(response.ok);
        assert_eq!(response.stun.unwrap().xor_mapped_address, "127.0.0.1:3478");
    }

    #[tokio::test]
    async fn http_and_ip_probes_use_the_same_async_proxy_boundary() {
        let proxy: Arc<dyn AsyncProxy> = Arc::new(EchoProxy);
        let http = probe(
            Arc::clone(&proxy),
            LatencyRequest {
                probe_type: "tcp".to_owned(),
                url: "http://example.test/health".to_owned(),
                ..LatencyRequest::default()
            },
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(http.ok);
        assert!(http.latency_ms >= 0);

        let ip = probe(
            proxy,
            LatencyRequest {
                probe_type: "ip".to_owned(),
                url: "http://example.test/ip".to_owned(),
                ..LatencyRequest::default()
            },
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(ip.ip.unwrap().ipv4, "203.0.113.7");
    }

    #[tokio::test]
    async fn tcp_stun_probe_uses_length_prefixed_framing() {
        let response = probe_stun(
            Arc::new(TcpStunProxy),
            LatencyRequest {
                probe_type: "stun_tcp".to_owned(),
                host: "stun.example:3478".to_owned(),
                tcp: true,
                ..LatencyRequest::default()
            },
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(response.stun.unwrap().xor_mapped_address, "127.0.0.1:3478");
    }
}
