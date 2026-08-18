//! HTTP wire helpers used by reverse HTTP listeners.
//!
//! The runtime still owns reverse routing, target selection, TLS wrapping and
//! flow accounting. This module only recognizes and rewrites HTTP bytes.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

use yuhaiin_core::{Error, ErrorKind, Result};

const MAX_HTTP_HEADERS: usize = 64 * 1024;

/// Read enough bytes to distinguish an HTTP request from raw reverse TCP.
pub async fn read_http_prefix<S>(stream: &mut S, sniff_timeout: Duration) -> Result<(Vec<u8>, bool)>
where
    S: AsyncRead + Unpin,
{
    let mut prefix = Vec::new();
    let result = tokio::time::timeout(sniff_timeout, async {
        loop {
            if prefix.len() >= MAX_HTTP_HEADERS {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    "reverse HTTP headers exceed limit",
                ));
            }
            let mut byte = [0u8; 1];
            let length = stream
                .read(&mut byte)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
            if length == 0 {
                break;
            }
            prefix.push(byte[0]);
            if prefix.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        Ok(())
    })
    .await;
    match result {
        Ok(Ok(())) => Ok((prefix.clone(), looks_like_http_request(&prefix))),
        Ok(Err(error)) => Err(error),
        // A slow client can hit the Go-compatible sniff deadline after the
        // complete request line (or even all headers) is already buffered.
        // Preserve that evidence instead of routing a valid HTTP request as
        // raw reverse TCP, which would skip path/Host rewriting.
        Err(_) => Ok((prefix.clone(), looks_like_http_request(&prefix))),
    }
}

/// Check whether a prefix starts with an HTTP request line.
pub fn looks_like_http_request(headers: &[u8]) -> bool {
    let Ok(headers) = std::str::from_utf8(headers) else {
        return false;
    };
    let Some(line) = headers.split_once("\r\n").map(|(line, _)| line) else {
        return false;
    };
    let fields = line.split_whitespace().collect::<Vec<_>>();
    fields.len() == 3
        && fields[0].bytes().all(|byte| byte.is_ascii_alphabetic())
        && fields[2].starts_with("HTTP/")
}

/// Rewrite a reverse HTTP request to the configured upstream path and host.
pub fn rewrite_request(headers: &str, base_path: &str, authority: &str) -> Result<String> {
    let (first, rest) = headers
        .split_once("\r\n")
        .ok_or_else(|| Error::new(ErrorKind::Protocol, "reverse HTTP request line is missing"))?;
    let mut fields = first.split_whitespace();
    let method = fields.next().unwrap_or_default();
    let requested = fields.next().unwrap_or_default();
    let version = fields.next().unwrap_or("HTTP/1.1");
    if method.is_empty() || requested.is_empty() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "reverse HTTP request line is invalid",
        ));
    }
    let request_path = origin_path(requested);
    let target_path = join_path(base_path, &request_path);
    let mut output = format!("{method} {target_path} {version}\r\n");
    let mut has_host = false;
    for line in rest.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if line
            .split_once(':')
            .is_some_and(|(name, _)| name.eq_ignore_ascii_case("host"))
        {
            output.push_str("Host: ");
            output.push_str(authority);
            output.push_str("\r\n");
            has_host = true;
        } else {
            output.push_str(line);
            output.push_str("\r\n");
        }
    }
    if !has_host {
        output.push_str("Host: ");
        output.push_str(authority);
        output.push_str("\r\n");
    }
    output.push_str("\r\n");
    Ok(output)
}

fn origin_path(value: &str) -> String {
    for scheme in ["http://", "https://"] {
        if let Some(rest) = value.strip_prefix(scheme) {
            return rest
                .find('/')
                .map(|offset| rest[offset..].to_owned())
                .unwrap_or_else(|| "/".to_owned());
        }
    }
    if value.starts_with('/') {
        value.to_owned()
    } else {
        format!("/{value}")
    }
}

fn join_path(base: &str, requested: &str) -> String {
    if base == "/" {
        return requested.to_owned();
    }
    if requested == "/" {
        return base.to_owned();
    }
    format!("{}{}", base.trim_end_matches('/'), requested)
}

/// Extract the host used for routing from a reverse request.
pub fn request_host(headers: &str) -> Option<String> {
    headers
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host")
                .then(|| value.trim().split(':').next().unwrap_or_default())
        })
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
}
