//! S3 HTTP transport that uses the runtime's selected outbound proxy.
//!
//! `yuhaiin-backup` owns SigV4 and deliberately knows nothing about the proxy
//! graph. This module is the application boundary: it turns the signed
//! request into one HTTP/1.1 exchange over an `AsyncProxy` stream. The proxy
//! may therefore be direct, HTTP, SOCKS5, TLS/HTTP2, Yuubinsya, or WireGuard,
//! exactly like the rest of the runtime's management traffic.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yuhaiin_backup::{BoxFuture, Error, S3Request, S3Response, S3Transport};
use yuhaiin_core::proxy::{AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{DomainName, Endpoint, FlowContext, Network};

#[derive(Clone)]
pub(crate) struct ProxyS3Transport {
    proxy: Arc<dyn AsyncProxy>,
    timeout: Duration,
}

impl ProxyS3Transport {
    pub(crate) fn new(proxy: Arc<dyn AsyncProxy>, timeout: Duration) -> Self {
        Self { proxy, timeout }
    }

    async fn execute_inner(&self, request: S3Request) -> Result<S3Response, Error> {
        let endpoint = proxy_endpoint(&request.host, request.port)?;
        let mut context = FlowContext::new(endpoint);
        context.component = Some("backup.s3".to_owned());
        let stream = self
            .proxy
            .connect(&context)
            .await
            .map_err(|error| Error::Transport(format!("connect S3 endpoint: {error}")))?;
        let mut stream = if request.scheme.eq_ignore_ascii_case("https") {
            tls_stream(&request.host, stream).await?
        } else if request.scheme.eq_ignore_ascii_case("http") {
            stream
        } else {
            return Err(Error::Invalid(format!(
                "unsupported S3 endpoint scheme {:?}",
                request.scheme
            )));
        };

        write_request(&mut stream, &request).await?;
        read_response(&mut stream).await
    }
}

impl S3Transport for ProxyS3Transport {
    fn execute<'a>(&'a self, request: S3Request) -> BoxFuture<'a, Result<S3Response, Error>> {
        Box::pin(async move {
            tokio::time::timeout(self.timeout, self.execute_inner(request))
                .await
                .map_err(|_| Error::Transport("S3 request timed out".to_owned()))?
        })
    }
}

fn proxy_endpoint(host: &str, port: u16) -> Result<Endpoint, Error> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(Endpoint::ip(Network::Tcp, SocketAddr::new(address, port)));
    }
    let host = DomainName::new(host)
        .map_err(|error| Error::Invalid(format!("invalid S3 endpoint host: {error}")))?;
    Ok(Endpoint::domain(Network::Tcp, host, port))
}

async fn write_request(stream: &mut BoxAsyncStream, request: &S3Request) -> Result<(), Error> {
    let mut head = format!("{} {} HTTP/1.1\r\n", request.method, request.path_and_query);
    for (name, value) in &request.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("connection: close\r\n");
    head.push_str(&format!("content-length: {}\r\n\r\n", request.body.len()));
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(|error| Error::Transport(format!("write S3 request headers: {error}")))?;
    stream
        .write_all(&request.body)
        .await
        .map_err(|error| Error::Transport(format!("write S3 request body: {error}")))?;
    stream
        .flush()
        .await
        .map_err(|error| Error::Transport(format!("flush S3 request: {error}")))
}

async fn read_response(stream: &mut BoxAsyncStream) -> Result<S3Response, Error> {
    const MAX_HEADER_BYTES: usize = 128 * 1024;
    const MAX_BODY_BYTES: usize = 512 * 1024 * 1024;
    let mut bytes = Vec::with_capacity(4096);
    let header_end = loop {
        let mut chunk = [0_u8; 8192];
        let count = stream
            .read(&mut chunk)
            .await
            .map_err(|error| Error::Transport(format!("read S3 response headers: {error}")))?;
        if count == 0 {
            return Err(Error::Transport(
                "S3 response ended before headers".to_owned(),
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(Error::Transport(
                "S3 response headers are too large".to_owned(),
            ));
        }
    };

    let headers = String::from_utf8_lossy(&bytes[..header_end]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| Error::Transport("S3 response has an invalid status".to_owned()))?;
    let parsed_headers = headers
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect::<BTreeMap<_, _>>();
    let mut body = bytes[header_end..].to_vec();
    let chunked = parsed_headers
        .get("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    if let Some(content_length) = parsed_headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
    {
        if content_length > MAX_BODY_BYTES {
            return Err(Error::Transport("S3 response body is too large".to_owned()));
        }
        while body.len() < content_length {
            let remaining = content_length - body.len();
            let mut chunk = vec![0_u8; remaining.min(8192)];
            let count = stream
                .read(&mut chunk)
                .await
                .map_err(|error| Error::Transport(format!("read S3 response body: {error}")))?;
            if count == 0 {
                return Err(Error::Transport(
                    "S3 response ended before Content-Length".to_owned(),
                ));
            }
            body.extend_from_slice(&chunk[..count]);
        }
        body.truncate(content_length);
    } else {
        loop {
            let mut chunk = [0_u8; 8192];
            let count = stream
                .read(&mut chunk)
                .await
                .map_err(|error| Error::Transport(format!("read S3 response body: {error}")))?;
            if count == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..count]);
            if body.len() > MAX_BODY_BYTES {
                return Err(Error::Transport("S3 response body is too large".to_owned()));
            }
        }
    }
    if chunked {
        body = decode_chunked_body(&body)?;
    }
    Ok(S3Response { status, body })
}

fn decode_chunked_body(mut input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| Error::Transport("malformed S3 chunk size".to_owned()))?;
        let size = usize::from_str_radix(
            input[..line_end]
                .split(|byte| *byte == b';')
                .next()
                .and_then(|value| std::str::from_utf8(value).ok())
                .map(str::trim)
                .ok_or_else(|| Error::Transport("invalid S3 chunk size".to_owned()))?,
            16,
        )
        .map_err(|_| Error::Transport("invalid S3 chunk size".to_owned()))?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(output);
        }
        let end = size
            .checked_add(2)
            .ok_or_else(|| Error::Transport("S3 chunk size overflow".to_owned()))?;
        if input.len() < end || &input[size..end] != b"\r\n" {
            return Err(Error::Transport("truncated S3 chunk".to_owned()));
        }
        output.extend_from_slice(&input[..size]);
        input = &input[end..];
    }
}

async fn tls_stream(host: &str, stream: BoxAsyncStream) -> Result<BoxAsyncStream, Error> {
    #[cfg(feature = "doh-tls")]
    {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = crate::doh_tls::client_config(roots)
            .map_err(|error| Error::Transport(format!("build S3 TLS config: {error}")))?;
        let server_name = crate::doh_tls::tls_server_name(host)
            .map_err(|error| Error::Transport(format!("S3 TLS server name: {error}")))?;
        let stream = tokio_rustls::TlsConnector::from(config)
            .connect(server_name, stream)
            .await
            .map_err(|error| Error::Transport(format!("S3 TLS handshake: {error}")))?;
        Ok(Box::new(stream))
    }
    #[cfg(not(feature = "doh-tls"))]
    {
        let _ = (host, stream);
        Err(Error::Transport(
            "HTTPS S3 transport requires the doh-tls feature".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::AsyncReadExt;
    use yuhaiin_backup::S3Transport;
    use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy};
    use yuhaiin_core::{BoxFuture as CoreBoxFuture, ErrorKind as CoreErrorKind};

    struct DuplexProxy {
        stream: Mutex<Option<BoxAsyncStream>>,
    }

    impl DuplexProxy {
        fn new(stream: BoxAsyncStream) -> Self {
            Self {
                stream: Mutex::new(Some(stream)),
            }
        }
    }

    impl AsyncProxy for DuplexProxy {
        fn connect<'a>(
            &'a self,
            _context: &'a FlowContext,
        ) -> CoreBoxFuture<'a, yuhaiin_core::Result<BoxAsyncStream>> {
            let stream = self.stream.lock().unwrap().take();
            Box::pin(async move {
                stream.ok_or_else(|| {
                    yuhaiin_core::Error::new(CoreErrorKind::Closed, "duplex stream was reused")
                })
            })
        }

        fn open_datagram<'a>(
            &'a self,
            _context: &'a FlowContext,
        ) -> CoreBoxFuture<'a, yuhaiin_core::Result<Box<dyn AsyncDatagram>>> {
            Box::pin(async {
                Err(yuhaiin_core::Error::new(
                    CoreErrorKind::Unsupported,
                    "test proxy has no datagram",
                ))
            })
        }

        fn close(&self) -> CoreBoxFuture<'_, yuhaiin_core::Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    async fn read_request(stream: &mut tokio::io::DuplexStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0_u8; 1024];
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&chunk[..count]);
            let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&bytes[..header_end + 4]);
            let length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if bytes.len() >= header_end + 4 + length {
                return bytes;
            }
        }
    }

    #[tokio::test]
    async fn selected_proxy_transport_writes_signed_http_and_reads_chunked_body() {
        let (client, mut server) = tokio::io::duplex(16 * 1024);
        let proxy = Arc::new(DuplexProxy::new(Box::new(client)));
        let transport = ProxyS3Transport::new(proxy, Duration::from_secs(2));
        let server_task = tokio::spawn(async move {
            let request = read_request(&mut server).await;
            let request_text = String::from_utf8_lossy(&request);
            assert!(request_text.starts_with("GET /bucket/object HTTP/1.1\r\n"));
            assert!(request_text.contains("authorization: AWS4-HMAC-SHA256"));
            server
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let response = transport
            .execute(S3Request {
                method: "GET".to_owned(),
                scheme: "http".to_owned(),
                host: "s3.example".to_owned(),
                port: 80,
                path_and_query: "/bucket/object".to_owned(),
                headers: vec![
                    ("host".to_owned(), "s3.example".to_owned()),
                    (
                        "authorization".to_owned(),
                        "AWS4-HMAC-SHA256 test".to_owned(),
                    ),
                ],
                body: Vec::new(),
            })
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        server_task.await.unwrap();
    }

    #[test]
    fn chunked_decoder_rejects_truncated_data() {
        assert!(decode_chunked_body(b"5\r\nhello\r\n").is_err());
        assert_eq!(
            decode_chunked_body(b"5;foo=bar\r\nhello\r\n0\r\n\r\n").unwrap(),
            b"hello"
        );
    }
}
