//! HTTP/1.x server-side wire helpers.
//!
//! These helpers handle framing, authority parsing and hop-by-hop header
//! rewriting. Runtime code remains responsible for authentication policy,
//! routing, connection accounting and listener lifetime.

use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use yuhaiin_core::{DomainName, Endpoint, Error, ErrorKind, Network, Result};

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
