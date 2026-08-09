//! Go-compatible Shadowsocks `obfs_http` outbound transport.
//!
//! This is the simple-obfs HTTP wrapper used by Go's `shadowsocks` contract
//! point. It is deliberately separate from SSR `http_simple`/`http_post`:
//! those protocols have different framing and must not share this wrapper.
//! The Go implementation only exposes this as an outbound layer, so this
//! module does the same and reports datagram use as unsupported.

use std::io;
use std::sync::Arc;

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, split};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Error, ErrorKind, FlowContext, Result};

const DUPLEX_CAPACITY: usize = 64 * 1024;
const BUFFER_SIZE: usize = 16 * 1024;
const MAX_RESPONSE_HEADER: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpObfsConfig {
    pub host: String,
    pub port: String,
}

impl HttpObfsConfig {
    pub fn new(host: impl Into<String>, port: impl Into<String>) -> Result<Self> {
        let host = host.into();
        let port = port.into();
        validate_header_value("host", &host)?;
        validate_header_value("port", &port)?;
        if host.trim().is_empty() {
            return Err(Error::invalid("HTTP obfs host is empty"));
        }
        if port.trim().is_empty() {
            return Err(Error::invalid("HTTP obfs port is empty"));
        }
        Ok(Self { host, port })
    }

    fn request_host(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn request_url(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("http://[{}]/", self.host)
        } else {
            format!("http://{}/", self.host)
        }
    }
}

/// HTTP obfuscation around an already configured parent proxy.
pub struct HttpObfsProxy {
    upstream: Arc<dyn AsyncProxy>,
    config: HttpObfsConfig,
}

impl HttpObfsProxy {
    pub fn new(
        upstream: Arc<dyn AsyncProxy>,
        host: impl Into<String>,
        port: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            upstream,
            config: HttpObfsConfig::new(host, port)?,
        })
    }

    pub fn config(&self) -> &HttpObfsConfig {
        &self.config
    }
}

impl AsyncProxy for HttpObfsProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let upstream = self.upstream.connect(context).await?;
            let (client, relay) = tokio::io::duplex(DUPLEX_CAPACITY);
            let (local_reader, local_writer) = split(relay);
            let (remote_reader, remote_writer) = split(upstream);
            tokio::spawn(upload_loop(
                local_reader,
                remote_writer,
                self.config.clone(),
            ));
            tokio::spawn(download_loop(remote_reader, local_writer));
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
                "HTTP obfs does not expose a datagram transport",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

async fn upload_loop<R, W>(mut local: R, mut remote: W, config: HttpObfsConfig)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut input = vec![0u8; BUFFER_SIZE];
    let mut first_request = true;
    loop {
        let count = match local.read(&mut input).await {
            Ok(0) => {
                let _ = remote.shutdown().await;
                return;
            }
            Ok(count) => count,
            Err(_) => return,
        };

        if first_request {
            first_request = false;
            let mut request = match build_request(&config, count) {
                Ok(request) => request,
                Err(_) => return,
            };
            request.extend_from_slice(&input[..count]);
            if remote.write_all(&request).await.is_err() {
                return;
            }
        } else if remote.write_all(&input[..count]).await.is_err() {
            return;
        }
    }
}

async fn download_loop<R, W>(mut remote: R, mut local: W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut input = vec![0u8; BUFFER_SIZE];
    let mut response_header = Vec::new();
    let mut response_started = false;
    loop {
        let count = match remote.read(&mut input).await {
            Ok(0) | Err(_) => {
                let _ = local.shutdown().await;
                return;
            }
            Ok(count) => count,
        };

        if response_started {
            if local.write_all(&input[..count]).await.is_err() {
                return;
            }
            continue;
        }

        response_header.extend_from_slice(&input[..count]);
        let Some(marker) = find_header_end(&response_header) else {
            if response_header.len() > MAX_RESPONSE_HEADER {
                let _ = local.shutdown().await;
                return;
            }
            continue;
        };
        response_started = true;
        if local.write_all(&response_header[marker..]).await.is_err() {
            return;
        }
        response_header.clear();
    }
}

fn build_request(config: &HttpObfsConfig, content_length: usize) -> io::Result<Vec<u8>> {
    let mut rng = rand::rng();
    let user_agent_major = rand::RngExt::random_range(&mut rng, 0..54);
    let user_agent_minor = rand::RngExt::random_range(&mut rng, 0..2);
    let mut key = [0u8; 16];
    rand::RngExt::fill(&mut rng, &mut key);
    let sec_key = base64::engine::general_purpose::URL_SAFE.encode(key);
    let request = format!(
        "GET {} HTTP/1.1\r\nUser-Agent: curl/7.{user_agent_major}.{user_agent_minor}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nHost: {}\r\nSec-WebSocket-Key: {sec_key}\r\nContent-Length: {content_length}\r\n\r\n",
        config.request_url(),
        config.request_host(),
    );
    Ok(request.into_bytes())
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn validate_header_value(name: &str, value: &str) -> Result<()> {
    if value
        .bytes()
        .any(|byte| byte == b'\r' || byte == b'\n' || byte < 0x20)
    {
        return Err(Error::invalid(format!(
            "HTTP obfs {name} contains a control byte"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use yuhaiin_core::proxy::FixedAsyncProxy;
    use yuhaiin_core::{Endpoint, Network};

    #[test]
    fn validates_http_header_configuration() {
        assert!(HttpObfsConfig::new("example.com", "80").is_ok());
        assert!(HttpObfsConfig::new("example.com\r\nX-Leak: 1", "80").is_err());
        assert!(HttpObfsConfig::new("example.com", "").is_err());
    }

    #[test]
    fn builds_go_compatible_upgrade_request() {
        let request = build_request(&HttpObfsConfig::new("example.com", "80").unwrap(), 7).unwrap();
        let request = String::from_utf8(request).unwrap();
        assert!(request.starts_with("GET http://example.com/ HTTP/1.1\r\n"));
        assert!(request.contains("Upgrade: websocket\r\n"));
        assert!(request.contains("Connection: Upgrade\r\n"));
        assert!(request.contains("Host: example.com:80\r\n"));
        assert!(request.contains("Content-Length: 7\r\n\r\n"));
    }

    #[tokio::test]
    async fn wraps_parent_and_strips_fragmented_http_response_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                assert!(request.len() < MAX_RESPONSE_HEADER);
            }
            let request_text = String::from_utf8(request).unwrap();
            assert!(request_text.starts_with("GET http://obfs.example/ HTTP/1.1"));
            assert!(request_text.contains("Content-Length: 7\r\n"));
            let mut body = [0u8; 7];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"request");
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n")
                .await
                .unwrap();
            stream.write_all(b"\r\nres").await.unwrap();
            stream.write_all(b"ponse").await.unwrap();
        });
        let parent: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
            address,
            timeout: std::time::Duration::from_secs(1),
        });
        let proxy = HttpObfsProxy::new(parent, "obfs.example", "80").unwrap();
        let context = FlowContext::new(Endpoint::ip(
            Network::Tcp,
            "198.51.100.10:443".parse::<SocketAddr>().unwrap(),
        ));
        let mut client = proxy.connect(&context).await.unwrap();
        client.write_all(b"request").await.unwrap();
        let mut response = [0u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        server.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires the sibling Go checkout and Go toolchain"]
    async fn rust_http_obfs_interoperates_with_go_client_wrapper() {
        use std::process::Command;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.unwrap();
                request.push(byte[0]);
                assert!(request.len() < MAX_RESPONSE_HEADER);
            }
            let header = String::from_utf8(request).unwrap();
            assert!(header.contains("Upgrade: websocket\r\n"));
            assert!(header.contains("Content-Length: 14\r\n"));
            let mut body = [0u8; 14];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"hello-from-go!");
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\n\r\nreply-from-rust")
                .await
                .unwrap();
        });
        let helper = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/interop/http_obfs_go_client.go");
        let cache_root = std::env::var_os("XDG_CACHE_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("/home/asutorufa/.cache"))
            .join("yuhaiin-rust/go-tmp");
        std::fs::create_dir_all(&cache_root).unwrap();
        let output = tokio::task::spawn_blocking(move || {
            Command::new("go")
                .arg("run")
                .arg(helper)
                .current_dir("/home/asutorufa/Documents/Programming/yuhaiin")
                .env("GOEXPERIMENT", "jsonv2,greenteagc")
                .env("GOTMPDIR", &cache_root)
                .env("OBFS_LISTEN", address.to_string())
                .output()
                .unwrap()
        })
        .await
        .unwrap();
        assert!(
            output.status.success(),
            "Go obfs_http client failed: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        server.await.unwrap();
    }
}
