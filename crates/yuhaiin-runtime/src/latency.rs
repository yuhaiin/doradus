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
use tokio::io::AsyncReadExt;
use yuhaiin_core::dns_resolver::{AsyncIpResolver, SystemAsyncIpResolver};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{
    DomainName, Endpoint, Error, ErrorKind, FlowContext, IpSet, Network, ResolveStrategy, Result,
};
use yuhaiin_dns::{AsyncDnsDatagram, DnsDatagramConnector, probe_dns_udp};
#[cfg(feature = "doh-tls")]
use yuhaiin_dns::{DoqResolverConfig, DoqResolverFactory, probe_doq};

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
    request: LatencyRequest,
    timeout: Duration,
) -> Result<LatencyResponse> {
    probe_with_resolver(proxy, Arc::new(SystemAsyncIpResolver), request, timeout).await
}

/// Probe a node through the runtime's configured resolver.
///
/// Go's IP latency endpoint resolves the URL host twice, once with a
/// PreferIPv4 policy and once with PreferIPv6, before handing an IP endpoint
/// to the selected proxy.  Keeping the resolver as an explicit dependency
/// makes that behavior testable and avoids silently falling back to the
/// management process resolver.
pub async fn probe_with_resolver(
    proxy: Arc<dyn AsyncProxy>,
    resolver: Arc<dyn AsyncIpResolver>,
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
        "ip" => probe_ip(proxy, resolver, request, timeout).await,
        "stun" | "stun_tcp" => probe_stun(proxy, request, timeout).await,
        "dns" | "udp" => probe_dns(proxy, request, timeout).await,
        #[cfg(feature = "doh-tls")]
        "doq" => probe_doq_latency(proxy, resolver, request, timeout).await,
        #[cfg(not(feature = "doh-tls"))]
        "doq" => Err(Error::new(
            ErrorKind::Unsupported,
            "DoQ latency requires the doh-tls feature",
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

    fn host_or_default(&self, _tcp: bool) -> String {
        if !self.host.trim().is_empty() {
            return self.host.trim().to_owned();
        }
        "stun.l.google.com:19302".to_owned()
    }

    fn dns_host_or_default(&self) -> String {
        if !self.host.trim().is_empty() {
            return self.host.trim().to_owned();
        }
        "223.5.5.5:53".to_owned()
    }

    fn doq_host_or_default(&self) -> String {
        if !self.host.trim().is_empty() {
            return self.host.trim().to_owned();
        }
        "dns.nextdns.io:853".to_owned()
    }

    fn dns_target_or_default(&self) -> String {
        if !self.target_domain.trim().is_empty() {
            return self.target_domain.trim().to_owned();
        }
        "www.google.com".to_owned()
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
    resolver: Arc<dyn AsyncIpResolver>,
    request: LatencyRequest,
    timeout: Duration,
) -> Result<LatencyResponse> {
    let target = request.url_or_default(true);
    let (v4, v6) = tokio::join!(
        probe_ip_family(
            Arc::clone(&proxy),
            Arc::clone(&resolver),
            &target,
            &request,
            timeout,
            false,
        ),
        probe_ip_family(proxy, resolver, &target, &request, timeout, true),
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

async fn probe_ip_family(
    proxy: Arc<dyn AsyncProxy>,
    resolver: Arc<dyn AsyncIpResolver>,
    target: &str,
    request: &LatencyRequest,
    timeout: Duration,
    ipv6: bool,
) -> Result<HttpReply> {
    let parsed = parse_http_target(target)?;
    let address = if let Ok(ip) = parsed.host.parse::<IpAddr>() {
        if ip.is_ipv6() != ipv6 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "IP latency URL literal has the wrong address family",
            ));
        }
        SocketAddr::new(ip, parsed.port)
    } else {
        let domain = DomainName::new(&parsed.host)?;
        let strategy = if ipv6 {
            ResolveStrategy::OnlyIpv6
        } else {
            ResolveStrategy::OnlyIpv4
        };
        let addresses = tokio::time::timeout(timeout, resolver.resolve(&domain, strategy))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "IP latency DNS resolution timed out"))??;
        SocketAddr::new(
            select_ip(&addresses, ipv6).ok_or_else(|| {
                Error::new(
                    ErrorKind::NotFound,
                    format!(
                        "IP latency host has no IPv{} address",
                        if ipv6 { 6 } else { 4 }
                    ),
                )
            })?,
            parsed.port,
        )
    };
    http_probe_at(&proxy, target, request, timeout, Some(address)).await
}

fn select_ip(addresses: &IpSet, ipv6: bool) -> Option<IpAddr> {
    if ipv6 {
        addresses.v6.first().copied().map(IpAddr::V6)
    } else {
        addresses.v4.first().copied().map(IpAddr::V4)
    }
}

async fn http_probe(
    proxy: &Arc<dyn AsyncProxy>,
    url: &str,
    request: &LatencyRequest,
    timeout: Duration,
) -> Result<HttpReply> {
    http_probe_at(proxy, url, request, timeout, None).await
}

async fn http_probe_at(
    proxy: &Arc<dyn AsyncProxy>,
    url: &str,
    request: &LatencyRequest,
    timeout: Duration,
    address: Option<SocketAddr>,
) -> Result<HttpReply> {
    let target = parse_http_target(url)?;
    let endpoint = address
        .map(|address| Endpoint::ip(Network::Tcp, address))
        .unwrap_or(endpoint(Network::Tcp, &target.host, target.port)?);
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

#[derive(Debug, Eq, PartialEq)]
enum HttpBodyFraming {
    Empty,
    ContentLength(usize),
    Chunked,
    CloseDelimited,
}

#[derive(Debug, Eq, PartialEq)]
enum ResponseRead {
    Count(usize),
    UnexpectedEof,
}

struct BufferedResponseReader<'a> {
    stream: &'a mut BoxAsyncStream,
    buffered: Vec<u8>,
    offset: usize,
    timeout: Duration,
}

impl<'a> BufferedResponseReader<'a> {
    fn new(stream: &'a mut BoxAsyncStream, buffered: Vec<u8>, timeout: Duration) -> Self {
        Self {
            stream,
            buffered,
            offset: 0,
            timeout,
        }
    }

    async fn read(&mut self, buffer: &mut [u8]) -> Result<ResponseRead> {
        if self.offset < self.buffered.len() {
            let count = (self.buffered.len() - self.offset).min(buffer.len());
            buffer[..count].copy_from_slice(&self.buffered[self.offset..self.offset + count]);
            self.offset += count;
            return Ok(ResponseRead::Count(count));
        }

        tokio::time::timeout(self.timeout, self.stream.read(buffer))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "HTTP response body timed out"))?
            .map(ResponseRead::Count)
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    Ok(ResponseRead::UnexpectedEof)
                } else {
                    Err(io_error(error))
                }
            })
    }

    async fn read_line(&mut self) -> Result<Vec<u8>> {
        let mut line = Vec::with_capacity(32);
        let mut byte = [0u8; 1];
        loop {
            match self.read(&mut byte).await? {
                ResponseRead::Count(0) | ResponseRead::UnexpectedEof => {
                    return Err(Error::new(
                        ErrorKind::Protocol,
                        "HTTP response ended inside a line",
                    ));
                }
                ResponseRead::Count(_) => {}
            }
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                return Ok(line);
            }
            if line.len() > 64 * 1024 {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "HTTP response line is too large",
                ));
            }
        }
    }

    async fn read_exact_discard(
        &mut self,
        mut remaining: usize,
        captured: &mut Vec<u8>,
    ) -> Result<()> {
        let mut buffer = [0u8; 8192];
        while remaining > 0 {
            let size = remaining.min(buffer.len());
            match self.read(&mut buffer[..size]).await? {
                ResponseRead::Count(0) | ResponseRead::UnexpectedEof => {
                    return Err(Error::new(
                        ErrorKind::Protocol,
                        "HTTP response ended before the declared body length",
                    ));
                }
                ResponseRead::Count(count) => {
                    remaining -= count;
                    capture_body(captured, &buffer[..count]);
                }
            }
        }
        Ok(())
    }

    async fn read_exact_bytes(&mut self, buffer: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        while offset < buffer.len() {
            match self.read(&mut buffer[offset..]).await? {
                ResponseRead::Count(0) | ResponseRead::UnexpectedEof => {
                    return Err(Error::new(
                        ErrorKind::Protocol,
                        "HTTP response ended before a framing delimiter",
                    ));
                }
                ResponseRead::Count(count) => offset += count,
            }
        }
        Ok(())
    }
}

fn capture_body(captured: &mut Vec<u8>, bytes: &[u8]) {
    const MAX_CAPTURED_BODY_BYTES: usize = 4 * 1024 * 1024;
    let remaining = MAX_CAPTURED_BODY_BYTES.saturating_sub(captured.len());
    captured.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
}

fn parse_http_body_framing(headers: &[u8]) -> Result<HttpBodyFraming> {
    let header_text = String::from_utf8_lossy(headers);
    let mut status = None;
    let mut content_length = None;
    let mut transfer_chunked = false;

    for (index, line) in header_text.split("\r\n").enumerate() {
        if index == 0 {
            status = line
                .split_whitespace()
                .nth(1)
                .and_then(|value| value.parse::<u16>().ok());
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_chunked = value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"));
        } else if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| Error::new(ErrorKind::Protocol, "invalid HTTP Content-Length"))?,
            );
        }
    }

    let status =
        status.ok_or_else(|| Error::new(ErrorKind::Protocol, "invalid HTTP status line"))?;
    if (100..200).contains(&status) || status == 204 || status == 304 {
        return Ok(HttpBodyFraming::Empty);
    }
    if transfer_chunked {
        return Ok(HttpBodyFraming::Chunked);
    }
    if let Some(length) = content_length {
        return Ok(HttpBodyFraming::ContentLength(length));
    }
    Ok(HttpBodyFraming::CloseDelimited)
}

async fn read_chunked_body(
    reader: &mut BufferedResponseReader<'_>,
    captured: &mut Vec<u8>,
) -> Result<()> {
    loop {
        let line = reader.read_line().await?;
        let line = std::str::from_utf8(&line)
            .map_err(|_| Error::new(ErrorKind::Protocol, "invalid HTTP chunk size"))?;
        let size = line
            .trim_end_matches("\r\n")
            .split(';')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(|value| usize::from_str_radix(value, 16).ok())
            .ok_or_else(|| Error::new(ErrorKind::Protocol, "invalid HTTP chunk size"))?;
        if size == 0 {
            loop {
                if reader.read_line().await? == b"\r\n" {
                    return Ok(());
                }
            }
        }

        reader.read_exact_discard(size, captured).await?;
        let mut delimiter = [0u8; 2];
        reader.read_exact_bytes(&mut delimiter).await?;
        if delimiter != *b"\r\n" {
            return Err(Error::new(
                ErrorKind::Protocol,
                "invalid HTTP chunk delimiter",
            ));
        }
    }
}

async fn read_http_response(stream: &mut BoxAsyncStream, timeout: Duration) -> Result<Vec<u8>> {
    let mut headers = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
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
        if let Some(index) = headers.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = index + 4;
            let framing = parse_http_body_framing(&headers[..header_end])?;
            let mut reader =
                BufferedResponseReader::new(stream, headers[header_end..].to_vec(), timeout);
            let mut body = Vec::new();
            match framing {
                HttpBodyFraming::Empty => {}
                HttpBodyFraming::ContentLength(length) => {
                    reader.read_exact_discard(length, &mut body).await?;
                }
                HttpBodyFraming::Chunked => read_chunked_body(&mut reader, &mut body).await?,
                HttpBodyFraming::CloseDelimited => {
                    let mut scratch = [0u8; 8192];
                    loop {
                        match reader.read(&mut scratch).await? {
                            ResponseRead::Count(0) | ResponseRead::UnexpectedEof => break,
                            ResponseRead::Count(count) => {
                                capture_body(&mut body, &scratch[..count])
                            }
                        }
                    }
                }
            }
            return Ok(body);
        }
        if headers.len() > 64 * 1024 {
            return Err(Error::new(
                ErrorKind::Protocol,
                "HTTP response headers are too large",
            ));
        }
    }
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

async fn probe_dns(
    proxy: Arc<dyn AsyncProxy>,
    request: LatencyRequest,
    timeout: Duration,
) -> Result<LatencyResponse> {
    let (host, port) = parse_host_port(&request.dns_host_or_default(), 53)?;
    let domain = DomainName::new(&request.dns_target_or_default())?;
    let elapsed = probe_dns_udp(
        &LatencyDatagramConnector { proxy },
        "latency-dns",
        &host,
        port,
        &domain,
        timeout,
    )
    .await?;
    Ok(success(elapsed))
}

#[cfg(feature = "doh-tls")]
async fn probe_doq_latency(
    proxy: Arc<dyn AsyncProxy>,
    resolver: Arc<dyn AsyncIpResolver>,
    request: LatencyRequest,
    timeout: Duration,
) -> Result<LatencyResponse> {
    let (host, _) = parse_host_port(&request.doq_host_or_default(), 853)?;
    let domain = DomainName::new(&request.dns_target_or_default())?;
    let factory = DoqResolverFactory::from_webpki_roots(timeout, 1)?
        .with_server_resolver(resolver)
        .with_datagram_connector(Arc::new(LatencyDatagramConnector { proxy }));
    let elapsed = probe_doq(
        &factory,
        DoqResolverConfig {
            id: "latency-doq".to_owned(),
            host: request.doq_host_or_default(),
            server_name: Some(host),
            local_bind_addresses: Vec::new(),
            bind_interface: None,
        },
        &domain,
        timeout,
    )
    .await?;
    Ok(success(elapsed))
}

struct LatencyDatagramConnector {
    proxy: Arc<dyn AsyncProxy>,
}

impl DnsDatagramConnector for LatencyDatagramConnector {
    fn open<'a>(
        &'a self,
        _resolver_id: &'a str,
        host: &'a str,
        target: SocketAddr,
        _local_bind_addresses: &'a [IpAddr],
        _bind_interface: Option<&'a str>,
    ) -> yuhaiin_core::BoxFuture<'a, Result<Option<Box<dyn AsyncDnsDatagram>>>> {
        Box::pin(async move {
            let destination = endpoint(Network::Udp, host, target.port())?;
            let context = FlowContext::new(destination.clone());
            let datagram = self.proxy.open_datagram(&context).await?;
            Ok(Some(Box::new(LatencyDatagram {
                inner: datagram,
                destination,
                server: target,
            }) as Box<dyn AsyncDnsDatagram>))
        })
    }
}

struct LatencyDatagram {
    inner: Box<dyn AsyncDatagram>,
    destination: Endpoint,
    server: SocketAddr,
}

impl AsyncDnsDatagram for LatencyDatagram {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        _target: SocketAddr,
    ) -> yuhaiin_core::BoxFuture<'a, Result<usize>> {
        self.inner.send_to(payload, self.destination.clone())
    }

    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> yuhaiin_core::BoxFuture<'a, Result<(usize, SocketAddr)>> {
        Box::pin(async move {
            let (length, endpoint) = self.inner.recv_from(buffer).await?;
            Ok((length, endpoint.addr().unwrap_or(self.server)))
        })
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.inner
            .local_addr()?
            .addr()
            .ok_or_else(|| Error::invalid("latency DNS datagram has no local address"))
    }

    fn close(&self) -> yuhaiin_core::BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
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
        let config = crate::tls::client_config(roots)?;
        let connector = tokio_rustls::TlsConnector::from(config);
        let name = crate::tls::tls_server_name(&target.host)?;
        let tls = tokio::time::timeout(timeout, connector.connect(name, stream))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "TLS handshake timed out"))?
            .map_err(|error| Error::new(ErrorKind::Protocol, format!("TLS: {error}")))?;
        Ok(Box::new(tls))
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
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use super::*;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::sync::mpsc;
    use yuhaiin_core::proxy::AsyncDatagram;
    use yuhaiin_core::{BoxFuture, FlowContext};

    struct EchoProxy;

    struct AbruptEofStream {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl AsyncRead for AbruptEofStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.offset < self.bytes.len() {
                let length = (self.bytes.len() - self.offset).min(buffer.remaining());
                buffer.put_slice(&self.bytes[self.offset..self.offset + length]);
                self.offset += length;
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed without TLS close_notify",
                )))
            }
        }
    }

    impl AsyncWrite for AbruptEofStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Clone)]
    struct StaticResolver {
        addresses: IpSet,
    }

    impl AsyncIpResolver for StaticResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            let mut addresses = self.addresses.clone();
            match strategy {
                ResolveStrategy::OnlyIpv4 => addresses.v6.clear(),
                ResolveStrategy::OnlyIpv6 => addresses.v4.clear(),
                ResolveStrategy::Default
                | ResolveStrategy::PreferIpv4
                | ResolveStrategy::PreferIpv6 => {}
            }
            Box::pin(async move { Ok(addresses) })
        }
    }

    struct RecordingEchoProxy {
        destinations: Arc<std::sync::Mutex<Vec<Endpoint>>>,
    }

    impl AsyncProxy for RecordingEchoProxy {
        fn connect<'a>(
            &'a self,
            context: &'a FlowContext,
        ) -> BoxFuture<'a, Result<BoxAsyncStream>> {
            let destination = context.effective_destination();
            self.destinations
                .lock()
                .expect("recording proxy mutex poisoned")
                .push(destination.clone());
            Box::pin(async move {
                let (client, mut server) = tokio::io::duplex(4096);
                let value = if destination.addr().is_some_and(|address| address.is_ipv6()) {
                    "2001:db8::7"
                } else {
                    "203.0.113.7"
                };
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
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}\n",
                        value.len() + 1,
                        value
                    );
                    let _ = server.write_all(response.as_bytes()).await;
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
                    "recording proxy has no datagram transport",
                ))
            })
        }

        fn close(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

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
    async fn http_response_reads_chunked_body_and_trailers() {
        let (client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            server
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n5\r\nhello\r\n6;ext=yes\r\n world\r\n0\r\nX-Test: yes\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let body = read_http_response(
            &mut (Box::new(client) as BoxAsyncStream),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(body, b"hello world");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn http_response_accepts_close_delimited_unexpected_eof() {
        let response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody";
        let mut stream = Box::new(AbruptEofStream {
            bytes: response.to_vec(),
            offset: 0,
        }) as BoxAsyncStream;
        let body = read_http_response(&mut stream, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(body, b"body");
    }

    #[tokio::test]
    async fn http_response_rejects_truncated_content_length() {
        let (client, mut server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc")
                .await
                .unwrap();
            server.shutdown().await.unwrap();
        });
        let result = read_http_response(
            &mut (Box::new(client) as BoxAsyncStream),
            Duration::from_secs(1),
        )
        .await;
        assert!(result.is_err());
        server_task.await.unwrap();
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
    async fn dns_udp_probe_uses_proxy_datagram_and_validates_response() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut query = [0u8; 4096];
            let (length, peer) = socket.recv_from(&mut query).await.unwrap();
            assert!(length >= 12);
            // The resolver advertises an EDNS UDP size. Build the mock
            // response from the question only; copying the OPT pseudo-record
            // into the answer section would be an invalid DNS response.
            let mut question_end = 12;
            loop {
                let label_length = query[question_end] as usize;
                question_end += 1;
                if label_length == 0 {
                    break;
                }
                question_end += label_length;
            }
            question_end += 4; // QTYPE and QCLASS
            let mut response = Vec::with_capacity(length + 16);
            response.extend_from_slice(&query[..2]);
            response.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            response.extend_from_slice(&query[12..question_end]);
            response.extend_from_slice(&[
                0xc0, 0x0c, // compressed owner name
                0, 1, // A
                0, 1, // IN
                0, 0, 0, 60, // TTL
                0, 4, // IPv4 address length
                1, 2, 3, 4,
            ]);
            socket.send_to(&response, peer).await.unwrap();
        });

        let response = probe(
            Arc::new(yuhaiin_core::proxy::DirectAsyncProxy {
                timeout: Duration::from_secs(1),
            }),
            LatencyRequest {
                probe_type: "dns".to_owned(),
                host: address.to_string(),
                target_domain: "example.com".to_owned(),
                ..LatencyRequest::default()
            },
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(response.ok);
        assert!(response.latency_ms >= 0);
        server.await.unwrap();
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

        let ip = probe_with_resolver(
            proxy,
            Arc::new(StaticResolver {
                addresses: IpSet {
                    v4: vec![Ipv4Addr::new(192, 0, 2, 7)],
                    v6: Vec::new(),
                },
            }),
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
    async fn ip_probe_resolves_and_connects_one_endpoint_per_family() {
        let destinations = Arc::new(std::sync::Mutex::new(Vec::new()));
        let proxy: Arc<dyn AsyncProxy> = Arc::new(RecordingEchoProxy {
            destinations: Arc::clone(&destinations),
        });
        let response = probe_with_resolver(
            proxy,
            Arc::new(StaticResolver {
                addresses: IpSet {
                    v4: vec![Ipv4Addr::new(192, 0, 2, 7)],
                    v6: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7)],
                },
            }),
            LatencyRequest {
                probe_type: "ip".to_owned(),
                url: "http://example.test/ip".to_owned(),
                ..LatencyRequest::default()
            },
            Duration::from_secs(1),
        )
        .await
        .unwrap();

        let ip = response.ip.unwrap();
        assert_eq!(ip.ipv4, "203.0.113.7");
        assert_eq!(ip.ipv6, "2001:db8::7");
        let destinations = destinations
            .lock()
            .expect("recording proxy mutex poisoned")
            .clone();
        assert_eq!(destinations.len(), 2);
        assert!(
            destinations
                .iter()
                .any(|destination| { destination.addr() == Some("192.0.2.7:80".parse().unwrap()) })
        );
        assert!(destinations.iter().any(|destination| {
            destination.addr() == Some("[2001:db8::7]:80".parse().unwrap())
        }));
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
