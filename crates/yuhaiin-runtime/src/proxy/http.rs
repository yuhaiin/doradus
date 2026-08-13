use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use yuhaiin_core::flow::FlowObserver;
use yuhaiin_core::flow::{
    Flow as TunFlow, FlowDirection as TunFlowDirection, FlowKey as TunFlowKey, FlowObserverGuard,
};
use yuhaiin_core::proxy::AsyncProxySelector;
use yuhaiin_core::{DomainName, Endpoint, Error, ErrorKind, FlowContext, Network, Result};

use super::common::{io_error, record_outbound_stream, relay_counted_with_buffer};
use crate::inbound::{InboundAuth, InboundSpec};
use crate::{ConnectionMonitor, RuntimeProxySelector};

const MAX_HEADERS: usize = 64 * 1024;
const HOP_BY_HOP_HEADERS: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub(crate) async fn serve<S>(
    mut stream: S,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let Some(headers) = read_headers(&mut stream).await? else {
            return Ok(());
        };
        let request_line = headers
            .split_once("\r\n")
            .map(|(line, _)| line)
            .ok_or_else(|| Error::new(ErrorKind::Protocol, "HTTP proxy request is empty"))?;
        let mut fields = request_line.split_whitespace();
        let method = fields.next().unwrap_or_default();
        let target = fields.next().unwrap_or_default();
        let version = fields.next().unwrap_or("HTTP/1.1");
        if method.is_empty() || target.is_empty() {
            return Err(Error::new(
                ErrorKind::Protocol,
                "HTTP proxy request line is malformed",
            ));
        }
        match http_authorization(
            &headers,
            &spec.username,
            &spec.password,
            spec.auth.as_deref(),
        ) {
            HttpAuthorization::Allowed => {}
            HttpAuthorization::Missing => {
                stream
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .map_err(io_error)?;
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "HTTP proxy authentication is required",
                ));
            }
            HttpAuthorization::Invalid => {
                stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                    .await
                    .map_err(io_error)?;
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "HTTP proxy authentication failed",
                ));
            }
        }
        if method.eq_ignore_ascii_case("CONNECT") {
            let destination = parse_authority(target, Network::Tcp)?;
            return serve_connect(stream, peer, spec, selector, monitor, destination).await;
        }

        let request_body = body_framing(&headers)?;
        let client_wants_close = request_wants_close(version, &headers);
        let (destination, origin_target, https) = parse_forward_target(target, &headers)?;
        let source = Endpoint::ip(Network::Tcp, peer);
        let mut context = FlowContext::new(destination.clone());
        context.source = Some(source);
        context.original_domain = destination.host().cloned();
        context.http_host = yuhaiin_core::sniff::http_host(headers.as_bytes());
        spec.annotate_context(&mut context);
        selector.route_context(&mut context);
        let process = context.process.clone();
        let outbound = match selector.select(&context).connect(&context).await {
            Ok(outbound) => outbound,
            Err(error) => {
                monitor.record_failure_with_process(
                    "http",
                    &destination.to_string(),
                    &error.to_string(),
                    process.as_deref(),
                );
                return Err(error);
            }
        };
        let outbound = if https {
            #[cfg(feature = "doh-tls")]
            {
                let server_name = destination
                    .host()
                    .map(|host| host.as_str().to_owned())
                    .or_else(|| destination.addr().map(|addr| addr.ip().to_string()))
                    .ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "HTTPS target has no host")
                    })?;
                match crate::doh_tls::wrap_system_tls_stream(&server_name, outbound).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        monitor.record_failure_with_process(
                            "http",
                            &destination.to_string(),
                            &format!("HTTPS handshake: {error}"),
                            process.as_deref(),
                        );
                        return Err(error);
                    }
                }
            }
            #[cfg(not(feature = "doh-tls"))]
            {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "HTTP proxy HTTPS requests require the doh-tls feature",
                ));
            }
        } else {
            outbound
        };
        record_outbound_stream(&mut context, &outbound);
        let flow = flow_key(peer, &destination);
        let _observation = FlowObserverGuard::open(monitor.clone(), TunFlow { key: flow }, context);
        let mut outbound = outbound;
        let request = rewrite_forward_request_with_options(
            method,
            &origin_target,
            &headers,
            matches!(request_body, BodyFraming::Chunked),
        )?;
        outbound
            .write_all(request.as_bytes())
            .await
            .map_err(io_error)?;
        monitor.bytes(flow, TunFlowDirection::Upload, request.len());
        let uploaded = relay_http_body(&mut stream, &mut outbound, request_body)
            .await
            .map_err(io_error)?;
        monitor.bytes(flow, TunFlowDirection::Upload, uploaded);

        let Some(response_headers) = read_headers(&mut outbound).await? else {
            return Err(Error::new(
                ErrorKind::Protocol,
                "HTTP proxy upstream closed before response headers",
            ));
        };
        let response_body = response_body_framing(method, &response_headers)?;
        let response_close = response_wants_close(&response_headers)
            || matches!(response_body, BodyFraming::CloseDelimited);
        let response = rewrite_forward_response(&response_headers, response_body)?;
        stream
            .write_all(response.as_bytes())
            .await
            .map_err(io_error)?;
        monitor.bytes(flow, TunFlowDirection::Download, response.len());
        let downloaded = relay_http_body(&mut outbound, &mut stream, response_body)
            .await
            .map_err(io_error)?;
        monitor.bytes(flow, TunFlowDirection::Download, downloaded);
        if client_wants_close || response_close {
            return Ok(());
        }
    }
}

async fn serve_connect<S>(
    mut stream: S,
    peer: SocketAddr,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    destination: Endpoint,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let source = Endpoint::ip(Network::Tcp, peer);
    let mut context = FlowContext::new(destination.clone());
    context.source = Some(source);
    context.original_domain = destination.host().cloned();
    spec.annotate_context(&mut context);
    selector.route_context(&mut context);
    let process = context.process.clone();
    let proxy = selector.select(&context);
    let outbound = match proxy.connect(&context).await {
        Ok(outbound) => outbound,
        Err(error) => {
            monitor.record_failure_with_process(
                "http",
                &destination.to_string(),
                &error.to_string(),
                process.as_deref(),
            );
            return Err(error);
        }
    };
    record_outbound_stream(&mut context, &outbound);
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(io_error)?;
    relay_counted_with_buffer(
        stream,
        outbound,
        flow_key(peer, &destination),
        context,
        monitor,
        selector.relay_buffer_size(),
    )
    .await
    .map_err(io_error)
}

async fn read_headers<S>(stream: &mut S) -> Result<Option<String>>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(1024);
    let mut one = [0u8; 1];
    while bytes.len() < MAX_HEADERS {
        let read = stream.read(&mut one).await.map_err(io_error)?;
        if read == 0 {
            if bytes.is_empty() {
                return Ok(None);
            }
            return Err(Error::new(
                ErrorKind::Protocol,
                "HTTP headers ended before the terminator",
            ));
        }
        bytes.push(one[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes).map(Some).map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("HTTP headers: {error}"))
            });
        }
    }
    Err(Error::new(ErrorKind::Protocol, "HTTP headers exceed limit"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    None,
    ContentLength(usize),
    Chunked,
    CloseDelimited,
}

fn body_framing(headers: &str) -> Result<BodyFraming> {
    let transfer_encoding = header_value(headers, "transfer-encoding");
    if let Some(value) = transfer_encoding {
        if header_value_contains_token(value, "chunked") {
            return Ok(BodyFraming::Chunked);
        }
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!("unsupported HTTP transfer encoding: {value}"),
        ));
    }
    let Some(value) = header_value(headers, "content-length") else {
        return Ok(BodyFraming::None);
    };
    let length = value.parse::<usize>().map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("invalid HTTP Content-Length {value:?}: {error}"),
        )
    })?;
    Ok(BodyFraming::ContentLength(length))
}

fn response_body_framing(method: &str, headers: &str) -> Result<BodyFraming> {
    let status = headers
        .split_once("\r\n")
        .and_then(|(line, _)| line.split_whitespace().nth(1))
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Protocol,
                "HTTP upstream status line is malformed",
            )
        })?
        .parse::<u16>()
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("HTTP status: {error}")))?;
    if method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || matches!(status, 204 | 304)
    {
        return Ok(BodyFraming::None);
    }
    let framing = body_framing(headers)?;
    if framing == BodyFraming::None {
        Ok(BodyFraming::CloseDelimited)
    } else {
        Ok(framing)
    }
}

fn request_wants_close(version: &str, headers: &str) -> bool {
    if header_value_contains_token_list(headers, "connection", "close") {
        return true;
    }
    version.eq_ignore_ascii_case("HTTP/1.0")
        && !header_value_contains_token_list(headers, "connection", "keep-alive")
}

fn response_wants_close(headers: &str) -> bool {
    header_value_contains_token_list(headers, "connection", "close")
        || headers
            .split_once("\r\n")
            .is_some_and(|(line, _)| line.split_whitespace().next() == Some("HTTP/1.0"))
}

fn header_value_contains_token_list(headers: &str, name: &str, wanted: &str) -> bool {
    headers
        .split("\r\n")
        .skip(1)
        .filter_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name
                .trim()
                .eq_ignore_ascii_case(name)
                .then_some(value)
        })
        .any(|value| header_value_contains_token(value, wanted))
}

async fn relay_http_body<A, B>(
    source: &mut A,
    destination: &mut B,
    framing: BodyFraming,
) -> std::io::Result<usize>
where
    A: AsyncRead + Unpin,
    B: AsyncWrite + Unpin,
{
    match framing {
        BodyFraming::None => Ok(0),
        BodyFraming::ContentLength(length) => copy_exact(source, destination, length).await,
        BodyFraming::Chunked => relay_chunked(source, destination).await,
        BodyFraming::CloseDelimited => copy_until_eof(source, destination).await,
    }
}

async fn copy_exact<A, B>(
    source: &mut A,
    destination: &mut B,
    mut remaining: usize,
) -> std::io::Result<usize>
where
    A: AsyncRead + Unpin,
    B: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 16 * 1024];
    let mut copied = 0;
    while remaining > 0 {
        let size = remaining.min(buffer.len());
        source.read_exact(&mut buffer[..size]).await?;
        destination.write_all(&buffer[..size]).await?;
        remaining -= size;
        copied += size;
    }
    Ok(copied)
}

async fn copy_until_eof<A, B>(source: &mut A, destination: &mut B) -> std::io::Result<usize>
where
    A: AsyncRead + Unpin,
    B: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 16 * 1024];
    let mut copied = 0;
    loop {
        let size = source.read(&mut buffer).await?;
        if size == 0 {
            return Ok(copied);
        }
        destination.write_all(&buffer[..size]).await?;
        copied += size;
    }
}

async fn relay_chunked<A, B>(source: &mut A, destination: &mut B) -> std::io::Result<usize>
where
    A: AsyncRead + Unpin,
    B: AsyncWrite + Unpin,
{
    let mut copied = 0;
    loop {
        let line = read_crlf_line(source).await?;
        let size_text = line
            .strip_suffix(b"\r\n")
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk line"))?
            .split(|byte| *byte == b';')
            .next()
            .map(|value| value.iter().copied().map(char::from).collect::<String>())
            .unwrap_or_default();
        let size = usize::from_str_radix(size_text.trim(), 16).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid chunk size: {error}"),
            )
        })?;
        destination.write_all(&line).await?;
        copied += line.len();
        if size == 0 {
            loop {
                let trailer = read_crlf_line(source).await?;
                destination.write_all(&trailer).await?;
                copied += trailer.len();
                if trailer == b"\r\n" {
                    return Ok(copied);
                }
            }
        }
        copied += copy_exact(source, destination, size).await?;
        let mut crlf = [0u8; 2];
        source.read_exact(&mut crlf).await?;
        if crlf != *b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "chunk does not end with CRLF",
            ));
        }
        destination.write_all(&crlf).await?;
        copied += 2;
    }
}

async fn read_crlf_line<S>(source: &mut S) -> std::io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    while line.len() <= MAX_HEADERS {
        source.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "HTTP chunk line exceeds limit",
    ))
}

fn flow_key(peer: SocketAddr, target: &Endpoint) -> TunFlowKey {
    TunFlowKey {
        network: Network::Tcp,
        source: peer,
        destination: target
            .addr()
            .unwrap_or_else(|| "0.0.0.0:0".parse().expect("valid fallback address")),
    }
}

pub(crate) fn parse_authority(value: &str, network: Network) -> Result<Endpoint> {
    parse_authority_with_default(value, network, None)
}

pub(crate) fn parse_authority_with_default(
    value: &str,
    network: Network,
    default_port: Option<u16>,
) -> Result<Endpoint> {
    let value = value.trim();
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| Error::new(ErrorKind::Protocol, "invalid bracketed authority"))?;
        let port = match rest {
            "" => default_port
                .ok_or_else(|| Error::new(ErrorKind::Protocol, "authority has no port"))?,
            rest => rest
                .strip_prefix(':')
                .ok_or_else(|| Error::new(ErrorKind::Protocol, "invalid bracketed authority"))?
                .parse::<u16>()
                .map_err(|error| {
                    Error::new(ErrorKind::Protocol, format!("authority port: {error}"))
                })?,
        };
        (host, port)
    } else {
        match value.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (
                host,
                port.parse::<u16>().map_err(|error| {
                    Error::new(ErrorKind::Protocol, format!("authority port: {error}"))
                })?,
            ),
            _ => (
                value,
                default_port
                    .ok_or_else(|| Error::new(ErrorKind::Protocol, "authority has no port"))?,
            ),
        }
    };
    if host.is_empty() {
        return Err(Error::new(ErrorKind::Protocol, "authority host is empty"));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(Endpoint::ip(network, SocketAddr::new(ip, port)))
    } else {
        Ok(Endpoint::domain(network, DomainName::new(host)?, port))
    }
}

fn parse_forward_target(target: &str, headers: &str) -> Result<(Endpoint, String, bool)> {
    if let Some((scheme, rest)) = target.split_once("://") {
        let https = if scheme.eq_ignore_ascii_case("https") {
            true
        } else if scheme.eq_ignore_ascii_case("http") {
            false
        } else {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("HTTP proxy URI scheme is unsupported: {scheme}"),
            ));
        };
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        return Ok((
            parse_authority_with_default(
                authority,
                Network::Tcp,
                Some(if https { 443 } else { 80 }),
            )?,
            if path.is_empty() {
                "/".to_owned()
            } else {
                format!("/{path}")
            },
            https,
        ));
    }
    let host = header_value(headers, "host")
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "HTTP request has no Host header"))?;
    let destination = parse_authority_with_default(host, Network::Tcp, Some(80))?;
    let path = if target.starts_with('/') {
        target.to_owned()
    } else {
        format!("/{target}")
    };
    Ok((destination, path, false))
}

#[cfg(test)]
fn rewrite_forward_request(method: &str, target: &str, headers: &str) -> Result<String> {
    rewrite_forward_request_with_options(method, target, headers, false)
}

fn rewrite_forward_request_with_options(
    method: &str,
    target: &str,
    headers: &str,
    preserve_chunked: bool,
) -> Result<String> {
    let version = headers
        .split_once("\r\n")
        .and_then(|(line, _)| line.split_whitespace().nth(2))
        .unwrap_or("HTTP/1.1");
    let connection_names = connection_header_names(headers);
    let mut te_trailers = false;
    let mut request = format!("{method} {target} {version}\r\n");
    for line in headers.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(Error::new(ErrorKind::Protocol, "malformed HTTP header"));
        };
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::new(ErrorKind::Protocol, "HTTP header name is empty"));
        }
        let lower_name = name.to_ascii_lowercase();
        if lower_name == "te" {
            te_trailers |= header_value_contains_token(value, "trailers");
        }
        if HOP_BY_HOP_HEADERS.contains(&lower_name.as_str())
            || connection_names.iter().any(|value| value == &lower_name)
        {
            continue;
        }
        request.push_str(line);
        request.push_str("\r\n");
    }
    // net/http/httputil.ReverseProxy removes TE with the other hop-by-hop
    // headers, then preserves the one legal HTTP/1.1 value: `trailers`.
    if te_trailers {
        request.push_str("TE: trailers\r\n");
    }
    if preserve_chunked {
        request.push_str("Transfer-Encoding: chunked\r\n");
    }
    request.push_str("\r\n");
    Ok(request)
}

fn rewrite_forward_response(headers: &str, body: BodyFraming) -> Result<String> {
    let status = headers
        .split_once("\r\n")
        .map(|(line, _)| line)
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "HTTP upstream response is empty"))?;
    let connection_names = connection_header_names(headers);
    let mut response = format!("{status}\r\n");
    for line in headers.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, _)) = line.split_once(':') else {
            return Err(Error::new(
                ErrorKind::Protocol,
                "malformed HTTP response header",
            ));
        };
        let lower_name = name.trim().to_ascii_lowercase();
        if HOP_BY_HOP_HEADERS.contains(&lower_name.as_str())
            || connection_names.iter().any(|value| value == &lower_name)
        {
            continue;
        }
        response.push_str(line);
        response.push_str("\r\n");
    }
    match body {
        BodyFraming::Chunked => response.push_str("Transfer-Encoding: chunked\r\n"),
        BodyFraming::CloseDelimited => response.push_str("Connection: close\r\n"),
        BodyFraming::None | BodyFraming::ContentLength(_) => {}
    }
    response.push_str("\r\n");
    Ok(response)
}

fn connection_header_names(headers: &str) -> Vec<String> {
    headers
        .split("\r\n")
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("connection")
                .then_some(value)
        })
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn header_value_contains_token(value: &str, wanted: &str) -> bool {
    value
        .split(',')
        .any(|token| token.trim().eq_ignore_ascii_case(wanted))
}

fn header_value<'a>(headers: &'a str, wanted: &str) -> Option<&'a str> {
    headers.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case(wanted)
            .then_some(value.trim())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpAuthorization {
    Allowed,
    Missing,
    Invalid,
}

fn http_authorization(
    headers: &str,
    username: &str,
    password: &str,
    auth: Option<&InboundAuth>,
) -> HttpAuthorization {
    let central = auth.filter(|auth| auth.has_basic_users());
    if central.is_none() && username.is_empty() && password.is_empty() {
        return HttpAuthorization::Allowed;
    }
    let Some(token) = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("Proxy-Authorization") {
            return None;
        }
        value.trim().strip_prefix("Basic ")
    }) else {
        return HttpAuthorization::Missing;
    };

    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token) else {
        return HttpAuthorization::Invalid;
    };
    let Some(separator) = decoded.iter().position(|byte| *byte == b':') else {
        return HttpAuthorization::Invalid;
    };
    let (actual_username, actual_password) = decoded.split_at(separator);
    let actual_password = &actual_password[1..];
    if let Some(auth) = central {
        if auth.authenticate_basic(actual_username, actual_password) {
            return HttpAuthorization::Allowed;
        }
        return HttpAuthorization::Invalid;
    }
    if decoded == format!("{username}:{password}").as_bytes() {
        HttpAuthorization::Allowed
    } else {
        HttpAuthorization::Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn forward_target_accepts_absolute_and_origin_form() {
        let (absolute, absolute_path, absolute_https) = parse_forward_target(
            "http://example.com:8080/a?b=1",
            "GET http://example.com:8080/a?b=1 HTTP/1.1\r\nHost: ignored\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            absolute,
            Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 8080)
        );
        assert_eq!(absolute_path, "/a?b=1");
        assert!(!absolute_https);

        let (secure, secure_path, secure_https) = parse_forward_target(
            "HTTPS://example.com/secure",
            "GET HTTPS://example.com/secure HTTP/1.1\r\nHost: ignored\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            secure,
            Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 443)
        );
        assert_eq!(secure_path, "/secure");
        assert!(secure_https);

        let (origin, origin_path, origin_https) = parse_forward_target(
            "/health",
            "GET /health HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            origin,
            Endpoint::domain(Network::Tcp, DomainName::new("example.com").unwrap(), 80)
        );
        assert_eq!(origin_path, "/health");
        assert!(!origin_https);
    }

    #[test]
    fn forward_target_rejects_non_http_absolute_schemes() {
        let error = parse_forward_target(
            "ftp://example.com/file",
            "GET ftp://example.com/file HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unsupported);
    }

    #[test]
    fn forward_request_rewrites_proxy_form_and_removes_proxy_credentials() {
        let rewritten = rewrite_forward_request(
            "GET",
            "/path",
            "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive, X-Remove\r\nKeep-Alive: timeout=5\r\nProxy-Authenticate: Basic\r\nProxy-Authorization: Basic secret\r\nTE: gzip, trailers\r\nTrailer: X-Checksum\r\nTransfer-Encoding: chunked\r\nUpgrade: websocket\r\nX-Remove: must-not-forward\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
        assert!(rewritten.starts_with("GET /path HTTP/1.1\r\n"));
        assert!(rewritten.contains("Host: example.com\r\n"));
        assert!(rewritten.contains("Content-Length: 0\r\n"));
        assert!(rewritten.contains("TE: trailers\r\n"));
        for removed in [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "x-remove",
        ] {
            assert!(
                !rewritten.lines().any(|line| line
                    .split_once(':')
                    .is_some_and(|(name, _)| { name.eq_ignore_ascii_case(removed) })),
                "hop-by-hop header {removed:?} leaked: {rewritten:?}"
            );
        }
    }

    #[test]
    fn forward_request_removes_all_connection_tokens_case_insensitively() {
        let rewritten = rewrite_forward_request(
            "GET",
            "/",
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nconnection: X-One, x-two\r\nX-One: 1\r\nX-Two: 2\r\nX-Keep: 3\r\n\r\n",
        )
        .unwrap();
        assert!(!rewritten.contains("X-One:"));
        assert!(!rewritten.contains("X-Two:"));
        assert!(rewritten.contains("X-Keep: 3\r\n"));
    }

    #[test]
    fn forward_request_drops_non_trailer_te_values() {
        let rewritten = rewrite_forward_request(
            "GET",
            "/",
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTE: gzip\r\n\r\n",
        )
        .unwrap();
        assert!(!rewritten.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("te"))
        }));
    }

    #[test]
    fn request_and_response_framing_follow_http_one_point_one_rules() {
        assert_eq!(
            body_framing("POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n"),
            Ok(BodyFraming::ContentLength(4))
        );
        assert_eq!(
            body_framing("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Ok(BodyFraming::Chunked)
        );
        assert_eq!(
            response_body_framing(
                "GET",
                "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
            ),
            Ok(BodyFraming::None)
        );
        assert_eq!(
            response_body_framing("GET", "HTTP/1.1 200 OK\r\n\r\n"),
            Ok(BodyFraming::CloseDelimited)
        );
    }

    #[test]
    fn response_rewrite_preserves_wire_chunking_and_removes_hop_headers() {
        let rewritten = rewrite_forward_response(
            "HTTP/1.1 200 OK\r\nConnection: keep-alive, X-Remove\r\nKeep-Alive: timeout=5\r\nTransfer-Encoding: chunked\r\nX-Remove: yes\r\nX-Keep: yes\r\n\r\n",
            BodyFraming::Chunked,
        )
        .unwrap();
        assert!(rewritten.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(rewritten.contains("Transfer-Encoding: chunked\r\n"));
        assert!(rewritten.contains("X-Keep: yes\r\n"));
        assert!(!rewritten.contains("Connection:"));
        assert!(!rewritten.contains("Keep-Alive:"));
        assert!(!rewritten.contains("X-Remove:"));
    }

    #[tokio::test]
    async fn chunked_body_relay_copies_extensions_and_trailers() {
        let (mut source_writer, mut source_reader) = tokio::io::duplex(1024);
        let (mut destination_writer, mut destination_reader) = tokio::io::duplex(1024);
        source_writer
            .write_all(b"4;test=yes\r\ndata\r\n0\r\nX-Checksum: ok\r\n\r\n")
            .await
            .unwrap();
        drop(source_writer);
        let copied = relay_http_body(
            &mut source_reader,
            &mut destination_writer,
            BodyFraming::Chunked,
        )
        .await
        .unwrap();
        assert_eq!(
            copied,
            b"4;test=yes\r\ndata\r\n0\r\nX-Checksum: ok\r\n\r\n".len()
        );
        drop(destination_writer);
        let mut output = Vec::new();
        destination_reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"4;test=yes\r\ndata\r\n0\r\nX-Checksum: ok\r\n\r\n");
    }

    #[test]
    fn header_value_preserves_host_for_connection_observability() {
        let headers = "GET / HTTP/1.1\r\n hOsT: example.com:8080 \r\n\r\n";
        assert_eq!(header_value(headers, "Host"), Some("example.com:8080"));
    }

    #[test]
    fn proxy_authorization_header_name_is_case_insensitive() {
        let token = base64::engine::general_purpose::STANDARD.encode("u:p");
        let headers = format!("GET / HTTP/1.1\r\nproxy-authorization: Basic {token}\r\n\r\n");
        assert_eq!(
            http_authorization(&headers, "u", "p", None),
            HttpAuthorization::Allowed
        );
        assert_eq!(
            http_authorization(&headers, "u", "wrong", None),
            HttpAuthorization::Invalid
        );
    }

    #[test]
    fn central_inbound_users_replace_inline_http_credentials() {
        let auth = InboundAuth::from_users(vec![yuhaiin_store::GoUserRecord {
            id: "central-http".to_owned(),
            name: "central-http".to_owned(),
            enabled: true,
            origin: "manual".to_owned(),
            usage: "inbound".to_owned(),
            credential: yuhaiin_store::GoCredential {
                kind: "basic".to_owned(),
                basic: Some(yuhaiin_store::GoBasicCredential {
                    username: Some("central-user".to_owned()),
                    password: Some("central-password".to_owned()),
                    allow_any_username: false,
                    allow_any_password: false,
                }),
                uuid: None,
                token: None,
            },
            updated_at: 0,
        }]);
        let token =
            base64::engine::general_purpose::STANDARD.encode("central-user:central-password");
        let headers = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
        );
        assert_eq!(
            http_authorization(&headers, "legacy", "legacy", Some(&auth)),
            HttpAuthorization::Allowed
        );
        let wrong_token =
            base64::engine::general_purpose::STANDARD.encode("central-user:wrong-password");
        let wrong = headers.replace(&token, &wrong_token);
        assert_eq!(
            http_authorization(&wrong, "legacy", "legacy", Some(&auth)),
            HttpAuthorization::Invalid
        );
    }

    #[test]
    fn proxy_authorization_distinguishes_missing_from_invalid() {
        assert_eq!(
            http_authorization("GET / HTTP/1.1\r\n\r\n", "u", "p", None),
            HttpAuthorization::Missing
        );
    }
}
