//! Outbound HTTP CONNECT protocol wrapper.
//!
//! The parent proxy owns the connection to the next transport (for example a
//! raw HTTP/2 CONNECT stream).  This module only writes the Go-compatible
//! HTTP CONNECT request and leaves the resulting byte stream available to the
//! caller.

use std::sync::Arc;

use base64::Engine as _;
use doradus_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use doradus_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_HEADER_BYTES: usize = 64 * 1024;

pub struct HttpProxy {
    upstream: Arc<dyn AsyncProxy>,
    username: String,
    password: String,
}

impl HttpProxy {
    pub fn new(
        upstream: Arc<dyn AsyncProxy>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            upstream,
            username: username.into(),
            password: password.into(),
        }
    }

    async fn connect_stream(&self, context: &FlowContext) -> Result<BoxAsyncStream> {
        if context.network != Network::Tcp {
            return Err(Error::invalid("HTTP CONNECT requires a TCP flow"));
        }
        let destination = context.effective_destination();
        let authority = authority(&destination)?;
        let mut stream = self.upstream.connect(context).await?;

        let mut request = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Go-http-client/1.1\r\n"
        );
        if !self.username.is_empty() || !self.password.is_empty() {
            let credentials = format!("{}:{}", self.username, self.password);
            request.push_str("Proxy-Authorization: Basic ");
            request.push_str(&base64::engine::general_purpose::STANDARD.encode(credentials));
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(io_error)?;

        let response = read_headers(&mut stream).await?;
        let status = response
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| Error::new(ErrorKind::Protocol, "invalid HTTP proxy response"))?;
        if status != 200 {
            return Err(Error::new(
                ErrorKind::Protocol,
                format!("HTTP proxy CONNECT failed with status {status}"),
            ));
        }
        Ok(stream)
    }
}

impl AsyncProxy for HttpProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move { self.connect_stream(context).await })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "HTTP CONNECT has no UDP mode",
            ))
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<std::time::Duration>> {
        Box::pin(async move {
            let started = std::time::Instant::now();
            let mut stream = self.connect_stream(context).await?;
            stream.shutdown().await.map_err(io_error)?;
            Ok(started.elapsed())
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

fn authority(endpoint: &Endpoint) -> Result<String> {
    match endpoint {
        Endpoint::Ip { network, addr } if *network == Network::Tcp => Ok(addr.to_string()),
        Endpoint::Domain {
            network,
            host,
            port,
        } if *network == Network::Tcp => Ok(format!("{host}:{port}")),
        _ => Err(Error::invalid("HTTP CONNECT target must be a TCP endpoint")),
    }
}

async fn read_headers<S>(stream: &mut S) -> Result<String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut headers = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.map_err(io_error)?;
        headers.push(byte[0]);
        if headers.len() > MAX_HEADER_BYTES {
            return Err(Error::new(
                ErrorKind::Protocol,
                "HTTP proxy response headers are too large",
            ));
        }
        if headers.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(headers)
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("HTTP proxy response: {error}")))
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::FixedAsyncProxy;
    use doradus_core::{DomainName, Network};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn connect_writes_go_compatible_request_and_preserves_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            assert!(request.contains("Host: example.com:443\r\n"));
            assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let mut payload = [0u8; 7];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let parent: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
            address,
            timeout: std::time::Duration::from_secs(1),
        });
        let proxy = HttpProxy::new(parent, "user", "pass");
        let context = FlowContext::new(Endpoint::domain(
            Network::Tcp,
            DomainName::new("example.com").unwrap(),
            443,
        ));
        let mut stream = proxy.connect(&context).await.unwrap();
        stream.write_all(b"payload").await.unwrap();
        let mut response = [0u8; 7];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"payload");
        server.await.unwrap();
    }

    #[test]
    fn formats_ipv6_authority() {
        let endpoint = Endpoint::ip(
            Network::Tcp,
            "[2001:db8::1]:443".parse::<SocketAddr>().unwrap(),
        );
        assert_eq!(authority(&endpoint).unwrap(), "[2001:db8::1]:443");
    }
}
