//! HTTP latency probe and response framing.

use super::*;

#[derive(Debug, Clone)]
pub(super) struct HttpTarget {
    pub(super) https: bool,
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) authority: String,
    pub(super) path: String,
}

#[derive(Debug)]
pub(super) struct HttpReply {
    pub(super) elapsed: Duration,
    pub(super) body: Vec<u8>,
}

pub(super) async fn http_probe(
    proxy: &Arc<dyn AsyncProxy>,
    url: &str,
    request: &LatencyRequest,
    timeout: Duration,
) -> Result<HttpReply> {
    http_probe_at(proxy, url, request, timeout, None).await
}

pub(super) async fn http_probe_at(
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

pub(super) async fn read_http_response(
    stream: &mut BoxAsyncStream,
    timeout: Duration,
) -> Result<Vec<u8>> {
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

pub(super) fn parse_http_target(url: &str) -> Result<HttpTarget> {
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
