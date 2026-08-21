//! HTTP/1.x server-side wire helpers.
//!
//! These helpers handle framing, authority parsing and hop-by-hop header
//! rewriting. Runtime code remains responsible for authentication policy,
//! routing, connection accounting and listener lifetime.

use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use yuhaiin_core::{BoxFuture, DomainName, Endpoint, Error, ErrorKind, Network, Result};
use yuhaiin_types::{InboundBasicAuth, InboundHttpRequest, InboundStreamHandler};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpTrafficDirection {
    Upload,
    Download,
}

/// Runtime port used by the protocol-owned HTTP forward loop.
pub trait HttpForwardHandler<S>: InboundStreamHandler<S> + Send + Sync
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Outbound: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn open_forward<'a>(
        &'a self,
        peer: SocketAddr,
        destination: Endpoint,
        http_host: Option<String>,
        https: bool,
    ) -> BoxFuture<'a, Result<Self::Outbound>>;

    fn record_bytes(
        &self,
        connection: &Self::Outbound,
        direction: HttpTrafficDirection,
        bytes: usize,
    );
}

pub async fn read_headers<S>(stream: &mut S) -> Result<Option<String>>
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
pub enum HttpAuthorization {
    Allowed,
    Missing,
    Invalid,
}

/// Parse the request line while keeping the complete header block available
/// for routing metadata, body framing and hop-by-hop rewriting.
pub fn parse_request(headers: &str) -> Result<InboundHttpRequest> {
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
    Ok(InboundHttpRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        version: version.to_owned(),
        headers: headers.to_owned(),
    })
}

/// Validate the optional Basic proxy credentials without knowing how central
/// inbound users are stored. The runtime supplies that policy through the
/// small `InboundBasicAuth` port.
pub fn authorize_basic(
    headers: &str,
    username: &str,
    password: &str,
    central_auth: Option<&dyn InboundBasicAuth>,
) -> HttpAuthorization {
    let central = central_auth.filter(|auth| auth.has_basic_users());
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
        return if auth.authenticate_basic(actual_username, actual_password) {
            HttpAuthorization::Allowed
        } else {
            HttpAuthorization::Invalid
        };
    }
    if constant_time_eq(actual_username, username.as_bytes())
        && constant_time_eq(actual_password, password.as_bytes())
    {
        HttpAuthorization::Allowed
    } else {
        HttpAuthorization::Invalid
    }
}

/// Serve one HTTP proxy request stream.
///
/// This owns HTTP request parsing, authentication, CONNECT handling, forward
/// request rewriting, body framing and keep-alive. Route selection and the
/// outbound connection remain behind [`HttpForwardHandler`].
pub async fn handle<S, H>(
    mut stream: S,
    peer: SocketAddr,
    username: &str,
    password: &str,
    central_auth: Option<&dyn InboundBasicAuth>,
    handler: &H,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: HttpForwardHandler<S> + ?Sized,
{
    let Some(headers) = read_headers(&mut stream).await? else {
        return Ok(());
    };
    let request = parse_request(&headers)?;
    authenticate(
        &mut stream,
        &request.headers,
        username,
        password,
        central_auth,
    )
    .await?;

    if request.method.eq_ignore_ascii_case("CONNECT") {
        let destination = parse_authority(&request.target, Network::Tcp)?;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(io_error)?;
        handler
            .handle_stream(stream, peer, destination, "http")
            .await
    } else {
        serve_forward(
            stream,
            peer,
            username,
            password,
            central_auth,
            request,
            handler,
        )
        .await
    }
}

async fn serve_forward<S, H>(
    mut stream: S,
    peer: SocketAddr,
    username: &str,
    password: &str,
    central_auth: Option<&dyn InboundBasicAuth>,
    first_request: InboundHttpRequest,
    handler: &H,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    H: HttpForwardHandler<S> + ?Sized,
{
    let mut request = Some(first_request);
    loop {
        let request = if let Some(request) = request.take() {
            request
        } else {
            let Some(headers) = read_headers(&mut stream).await? else {
                return Ok(());
            };
            let request = parse_request(&headers)?;
            authenticate(
                &mut stream,
                &request.headers,
                username,
                password,
                central_auth,
            )
            .await?;
            request
        };
        if request.method.eq_ignore_ascii_case("CONNECT") {
            let destination = parse_authority(&request.target, Network::Tcp)?;
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .map_err(io_error)?;
            return handler
                .handle_stream(stream, peer, destination, "http")
                .await;
        }

        let request_body = body_framing(&request.headers)?;
        let client_wants_close = request_wants_close(&request.version, &request.headers);
        let (destination, origin_target, https) =
            parse_forward_target(&request.target, &request.headers)?;
        let http_host = yuhaiin_core::sniff::http_host(request.headers.as_bytes());
        let mut outbound = handler
            .open_forward(peer, destination, http_host, https)
            .await?;
        let outbound_request = rewrite_forward_request_with_options(
            &request.method,
            &origin_target,
            &request.headers,
            matches!(request_body, BodyFraming::Chunked),
            request_expects_continue(&request.headers)
                && !matches!(request_body, BodyFraming::None),
        )?;
        outbound
            .write_all(outbound_request.as_bytes())
            .await
            .map_err(io_error)?;
        handler.record_bytes(
            &outbound,
            HttpTrafficDirection::Upload,
            outbound_request.len(),
        );
        if request_expects_continue(&request.headers) && !matches!(request_body, BodyFraming::None)
        {
            stream
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .await
                .map_err(io_error)?;
            handler.record_bytes(&outbound, HttpTrafficDirection::Download, 25);
        }
        let uploaded = relay_http_body(&mut stream, &mut outbound, request_body)
            .await
            .map_err(io_error)?;
        handler.record_bytes(&outbound, HttpTrafficDirection::Upload, uploaded);

        let (response_headers, response_body) = loop {
            let Some(response_headers) = read_headers(&mut outbound).await? else {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "HTTP proxy upstream closed before response headers",
                ));
            };
            let status = response_status(&response_headers)?;
            if status == 101 {
                return Err(Error::new(
                    ErrorKind::Unsupported,
                    "HTTP proxy upstream upgrade responses are unsupported",
                ));
            }
            let response_body = response_body_framing(&request.method, &response_headers)?;
            if (100..200).contains(&status) {
                let response = rewrite_forward_response(&response_headers, BodyFraming::None)?;
                stream
                    .write_all(response.as_bytes())
                    .await
                    .map_err(io_error)?;
                handler.record_bytes(&outbound, HttpTrafficDirection::Download, response.len());
                continue;
            }
            break (response_headers, response_body);
        };
        let response_close = response_wants_close(&response_headers)
            || matches!(response_body, BodyFraming::CloseDelimited);
        let response = rewrite_forward_response(&response_headers, response_body)?;
        stream
            .write_all(response.as_bytes())
            .await
            .map_err(io_error)?;
        handler.record_bytes(&outbound, HttpTrafficDirection::Download, response.len());
        let downloaded = relay_http_body(&mut outbound, &mut stream, response_body)
            .await
            .map_err(io_error)?;
        handler.record_bytes(&outbound, HttpTrafficDirection::Download, downloaded);
        if client_wants_close || response_close {
            return Ok(());
        }
    }
}

async fn authenticate<S>(
    stream: &mut S,
    headers: &str,
    username: &str,
    password: &str,
    central_auth: Option<&dyn InboundBasicAuth>,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    match authorize_basic(headers, username, password, central_auth) {
        HttpAuthorization::Allowed => Ok(()),
        authorization => {
            write_auth_failure(stream, authorization).await?;
            Err(auth_error(authorization))
        }
    }
}

async fn write_auth_failure<S>(stream: &mut S, authorization: HttpAuthorization) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let response = match authorization {
        HttpAuthorization::Missing => {
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nConnection: close\r\n\r\n".as_slice()
        }
        HttpAuthorization::Invalid => b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n",
        HttpAuthorization::Allowed => return Ok(()),
    };
    stream.write_all(response).await.map_err(io_error)
}

fn auth_error(authorization: HttpAuthorization) -> Error {
    match authorization {
        HttpAuthorization::Missing => {
            Error::new(ErrorKind::Protocol, "HTTP proxy authentication is required")
        }
        HttpAuthorization::Invalid => {
            Error::new(ErrorKind::Protocol, "HTTP proxy authentication failed")
        }
        HttpAuthorization::Allowed => Error::new(ErrorKind::Protocol, "HTTP authorization failed"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    None,
    ContentLength(usize),
    Chunked,
    CloseDelimited,
}

pub fn body_framing(headers: &str) -> Result<BodyFraming> {
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

pub fn response_status(headers: &str) -> Result<u16> {
    headers
        .split_once("\r\n")
        .and_then(|(line, _)| line.split_whitespace().nth(1))
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Protocol,
                "HTTP upstream status line is malformed",
            )
        })?
        .parse::<u16>()
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("HTTP status: {error}")))
}

pub fn response_body_framing(method: &str, headers: &str) -> Result<BodyFraming> {
    let status = response_status(headers)?;
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

pub fn request_wants_close(version: &str, headers: &str) -> bool {
    if header_value_contains_token_list(headers, "connection", "close") {
        return true;
    }
    version.eq_ignore_ascii_case("HTTP/1.0")
        && !header_value_contains_token_list(headers, "connection", "keep-alive")
}

pub fn response_wants_close(headers: &str) -> bool {
    header_value_contains_token_list(headers, "connection", "close")
        || headers
            .split_once("\r\n")
            .is_some_and(|(line, _)| line.split_whitespace().next() == Some("HTTP/1.0"))
}

pub fn request_expects_continue(headers: &str) -> bool {
    header_value_contains_token_list(headers, "expect", "100-continue")
}

pub async fn relay_http_body<A, B>(
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

pub fn parse_authority(value: &str, network: Network) -> Result<Endpoint> {
    parse_authority_with_default(value, network, None)
}

pub fn parse_authority_with_default(
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

pub fn parse_forward_target(target: &str, headers: &str) -> Result<(Endpoint, String, bool)> {
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

pub fn rewrite_forward_request_with_options(
    method: &str,
    target: &str,
    headers: &str,
    preserve_chunked: bool,
    strip_expect: bool,
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
        if strip_expect && lower_name == "expect" {
            continue;
        }
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
    if te_trailers {
        request.push_str("TE: trailers\r\n");
    }
    if preserve_chunked {
        request.push_str("Transfer-Encoding: chunked\r\n");
    }
    request.push_str("\r\n");
    Ok(request)
}

pub fn rewrite_forward_response(headers: &str, body: BodyFraming) -> Result<String> {
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

pub fn header_value<'a>(headers: &'a str, wanted: &str) -> Option<&'a str> {
    headers.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case(wanted)
            .then_some(value.trim())
    })
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(left.get(index).copied().unwrap_or_default())
            ^ usize::from(right.get(index).copied().unwrap_or_default());
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
    use yuhaiin_core::{DomainName, Network};

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
        let rewritten = rewrite_forward_request_with_options(
            "GET",
            "/path",
            "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive, X-Remove\r\nKeep-Alive: timeout=5\r\nProxy-Authenticate: Basic\r\nProxy-Authorization: Basic secret\r\nTE: gzip, trailers\r\nTrailer: X-Checksum\r\nTransfer-Encoding: chunked\r\nUpgrade: websocket\r\nX-Remove: must-not-forward\r\nContent-Length: 0\r\n\r\n",
            false,
            false,
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
                !rewritten.lines().any(|line| {
                    line.split_once(':')
                        .is_some_and(|(name, _)| name.eq_ignore_ascii_case(removed))
                }),
                "hop-by-hop header {removed:?} leaked: {rewritten:?}"
            );
        }
    }

    #[test]
    fn forward_request_removes_connection_tokens_case_insensitively() {
        let rewritten = rewrite_forward_request_with_options(
            "GET",
            "/",
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nconnection: X-One, x-two\r\nX-One: 1\r\nX-Two: 2\r\nX-Keep: 3\r\n\r\n",
            false,
            false,
        )
        .unwrap();
        assert!(!rewritten.contains("X-One:"));
        assert!(!rewritten.contains("X-Two:"));
        assert!(rewritten.contains("X-Keep: 3\r\n"));
    }

    #[test]
    fn forward_request_drops_non_trailer_te_values() {
        let rewritten = rewrite_forward_request_with_options(
            "GET",
            "/",
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nTE: gzip\r\n\r\n",
            false,
            false,
        )
        .unwrap();
        assert!(!rewritten.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("te"))
        }));
    }

    #[test]
    fn expect_continue_is_detected_and_not_forwarded_upstream() {
        let headers = "POST http://example.com/upload HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\nContent-Length: 4\r\n\r\n";
        assert!(request_expects_continue(headers));
        let rewritten =
            rewrite_forward_request_with_options("POST", "/upload", headers, false, true).unwrap();
        assert!(!rewritten.contains("Expect:"));
        assert!(rewritten.contains("Content-Length: 4\r\n"));
    }

    #[test]
    fn response_status_and_body_framing_follow_http_rules() {
        assert_eq!(
            response_status("HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n"),
            Ok(103)
        );
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
    fn response_rewrite_preserves_chunking_and_removes_hop_headers() {
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
        let (mut source_writer, mut source_reader) = duplex(1024);
        let (mut destination_writer, mut destination_reader) = duplex(1024);
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
    fn basic_auth_is_case_insensitive_and_distinguishes_missing() {
        let token = base64::engine::general_purpose::STANDARD.encode("u:p");
        let headers = format!("GET / HTTP/1.1\r\nproxy-authorization: Basic {token}\r\n\r\n");
        assert_eq!(
            authorize_basic(&headers, "u", "p", None),
            HttpAuthorization::Allowed
        );
        assert_eq!(
            authorize_basic(&headers, "u", "wrong", None),
            HttpAuthorization::Invalid
        );
        assert_eq!(
            authorize_basic("GET / HTTP/1.1\r\n\r\n", "u", "p", None),
            HttpAuthorization::Missing
        );
    }

    #[tokio::test]
    async fn connect_writes_success_before_shared_stream_handoff() {
        let (mut client, server) = duplex(4096);
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(TestHandler {
            received: Arc::clone(&received),
        });
        let task = tokio::spawn(async move {
            handle(
                server,
                "127.0.0.1:12345".parse().unwrap(),
                "",
                "",
                None,
                handler.as_ref(),
            )
            .await
        });
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\npayload")
            .await
            .unwrap();
        let mut response = vec![0; b"HTTP/1.1 200 Connection Established\r\n\r\n".len()];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(&*received.lock().unwrap(), b"payload");
    }

    struct TestHandler {
        received: Arc<Mutex<Vec<u8>>>,
    }

    impl InboundStreamHandler<DuplexStream> for TestHandler {
        fn handle_stream<'a>(
            &'a self,
            mut stream: DuplexStream,
            _peer: SocketAddr,
            _destination: Endpoint,
            _protocol: &'static str,
        ) -> BoxFuture<'a, Result<()>> {
            let received = Arc::clone(&self.received);
            Box::pin(async move {
                let mut payload = Vec::new();
                stream.read_to_end(&mut payload).await.map_err(io_error)?;
                *received.lock().unwrap() = payload;
                Ok(())
            })
        }
    }

    impl HttpForwardHandler<DuplexStream> for TestHandler {
        type Outbound = DuplexStream;

        fn open_forward<'a>(
            &'a self,
            _peer: SocketAddr,
            _destination: Endpoint,
            _http_host: Option<String>,
            _https: bool,
        ) -> BoxFuture<'a, Result<Self::Outbound>> {
            Box::pin(async { Err(Error::new(ErrorKind::Unsupported, "not a forward test")) })
        }

        fn record_bytes(
            &self,
            _connection: &Self::Outbound,
            _direction: HttpTrafficDirection,
            _bytes: usize,
        ) {
        }
    }
}
