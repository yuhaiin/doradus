//! HTTP wire helpers used by reverse HTTP listeners.
//!
//! The runtime still owns reverse routing, target selection, TLS wrapping and
//! flow accounting. This module only recognizes and rewrites HTTP bytes.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, Result};
use yuhaiin_types::InboundStreamHandler;

pub use crate::stream::PrefixedIo;

const MAX_HTTP_HEADERS: usize = 64 * 1024;
const HTTP_SNIFF_TIMEOUT: Duration = Duration::from_millis(55);

/// Runtime capability used after reverse HTTP has selected and rewritten an
/// HTTP request. The protocol crate does not know how to route or dial the
/// configured reverse target.
pub trait ReverseHttpForwardHandler<S>: Send + Sync
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn handle_forward<'a>(
        &'a self,
        stream: S,
        peer: SocketAddr,
        destination: Endpoint,
        http_host: Option<String>,
        https: bool,
        rewritten_request: Vec<u8>,
    ) -> BoxFuture<'a, Result<()>>;
}

/// Configuration carried by one reverse HTTP connection. Keeping the
/// protocol inputs together prevents the stream loop from growing a long
/// positional argument list as reverse HTTP gains another option.
pub struct ReverseHttpOptions<'a> {
    pub target: Endpoint,
    pub path: &'a str,
    pub authority: &'a str,
    pub https: bool,
}

/// Run the complete reverse HTTP protocol loop.
///
/// Sniffing, prefix restoration, HTTP parsing and request rewriting stay in
/// this crate. The runtime only receives either a raw stream hand-off or an
/// already rewritten HTTP request through the two capability ports.
pub async fn handle<S, R, F>(
    mut stream: S,
    peer: SocketAddr,
    options: ReverseHttpOptions<'_>,
    raw_handler: &R,
    forward_handler: &F,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: InboundStreamHandler<PrefixedIo<S>> + ?Sized,
    F: ReverseHttpForwardHandler<S> + ?Sized,
{
    let (prefix, is_http) = read_http_prefix(&mut stream, HTTP_SNIFF_TIMEOUT).await?;
    if !is_http {
        return raw_handler
            .handle_stream(
                PrefixedIo::new(prefix, stream),
                peer,
                options.target,
                "reverse_http",
            )
            .await;
    }

    let headers = std::str::from_utf8(&prefix).map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("reverse HTTP headers: {error}"),
        )
    })?;
    let http_host = request_host(headers);
    let rewritten_request = rewrite_request(headers, options.path, options.authority)?.into_bytes();
    forward_handler
        .handle_forward(
            stream,
            peer,
            options.target,
            http_host,
            options.https,
            rewritten_request,
        )
        .await
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
    use yuhaiin_core::Network;

    fn target() -> Endpoint {
        Endpoint::domain(
            Network::Tcp,
            yuhaiin_core::DomainName::new("upstream.example").unwrap(),
            8080,
        )
    }

    #[test]
    fn rewrite_extracts_host_and_joins_base_path() {
        let headers = "GET /health HTTP/1.1\r\nHost: client.example:8443\r\nX-Test: yes\r\n\r\n";
        assert_eq!(request_host(headers).as_deref(), Some("client.example"));
        let rewritten = rewrite_request(headers, "/base", "upstream.example").unwrap();
        assert!(rewritten.starts_with("GET /base/health HTTP/1.1\r\n"));
        assert!(rewritten.contains("Host: upstream.example\r\n"));
        assert!(rewritten.contains("X-Test: yes\r\n"));
    }

    #[tokio::test]
    async fn raw_fallback_restores_sniffed_prefix() {
        let (mut client, server) = duplex(1024);
        client.write_all(b"raw reverse bytes").await.unwrap();
        client.shutdown().await.unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let raw = Arc::new(RawHandler {
            received: Arc::clone(&received),
        });
        let forward = Arc::new(ForwardHandler::default());
        let task = tokio::spawn(async move {
            handle(
                server,
                "127.0.0.1:23456".parse().unwrap(),
                ReverseHttpOptions {
                    target: target(),
                    path: "/base",
                    authority: "upstream.example",
                    https: false,
                },
                raw.as_ref(),
                forward.as_ref(),
            )
            .await
        });
        task.await.unwrap().unwrap();
        assert_eq!(&*received.lock().unwrap(), b"raw reverse bytes");
    }

    #[tokio::test]
    async fn http_path_routes_to_forward_handler_after_protocol_rewrite() {
        let (mut client, server) = duplex(2048);
        client
            .write_all(
                b"GET /health HTTP/1.1\r\nHost: client.example:8443\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let forward = Arc::new(ForwardHandler::default());
        let raw = Arc::new(RawHandler {
            received: Arc::new(Mutex::new(Vec::new())),
        });
        let task_forward = Arc::clone(&forward);
        let task = tokio::spawn(async move {
            handle(
                server,
                "127.0.0.1:23456".parse().unwrap(),
                ReverseHttpOptions {
                    target: target(),
                    path: "/base",
                    authority: "upstream.example",
                    https: true,
                },
                raw.as_ref(),
                task_forward.as_ref(),
            )
            .await
        });
        task.await.unwrap().unwrap();
        assert!(
            String::from_utf8(forward.request.lock().unwrap().clone())
                .unwrap()
                .starts_with("GET /base/health HTTP/1.1\r\n")
        );
        assert_eq!(
            forward.host.lock().unwrap().as_deref(),
            Some("client.example")
        );
        assert!(*forward.https.lock().unwrap());
    }

    struct RawHandler {
        received: Arc<Mutex<Vec<u8>>>,
    }

    impl InboundStreamHandler<PrefixedIo<DuplexStream>> for RawHandler {
        fn handle_stream<'a>(
            &'a self,
            mut stream: PrefixedIo<DuplexStream>,
            _peer: SocketAddr,
            _destination: Endpoint,
            _protocol: &'static str,
        ) -> BoxFuture<'a, Result<()>> {
            let received = Arc::clone(&self.received);
            Box::pin(async move {
                let mut bytes = Vec::new();
                stream
                    .read_to_end(&mut bytes)
                    .await
                    .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
                *received.lock().unwrap() = bytes;
                Ok(())
            })
        }
    }

    #[derive(Default)]
    struct ForwardHandler {
        request: Arc<Mutex<Vec<u8>>>,
        host: Arc<Mutex<Option<String>>>,
        https: Arc<Mutex<bool>>,
    }

    impl ReverseHttpForwardHandler<DuplexStream> for ForwardHandler {
        fn handle_forward<'a>(
            &'a self,
            _stream: DuplexStream,
            _peer: SocketAddr,
            _destination: Endpoint,
            http_host: Option<String>,
            https: bool,
            rewritten_request: Vec<u8>,
        ) -> BoxFuture<'a, Result<()>> {
            *self.request.lock().unwrap() = rewritten_request;
            *self.host.lock().unwrap() = http_host;
            *self.https.lock().unwrap() = https;
            Box::pin(async { Ok(()) })
        }
    }
}
