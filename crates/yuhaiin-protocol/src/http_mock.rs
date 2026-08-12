//! Go-compatible `http_mock` outbound wrapper.
//!
//! Go registers this protocol as a transparent wrapper around another
//! `netapi.Proxy`: every TCP connection writes one fixed HTTP request before
//! returning the connection, while datagrams are delegated unchanged.  Keep
//! that distinction here instead of treating `http_mock` as an HTTP proxy or
//! as an HTTP obfuscation layer.

use std::sync::Arc;

use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Error, ErrorKind, FlowContext, Result};

const MOCK_REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: www.speedtest.cn\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n";

/// A Go-compatible HTTP mock wrapper around an already constructed proxy.
pub struct HttpMockProxy {
    upstream: Arc<dyn AsyncProxy>,
}

impl HttpMockProxy {
    pub fn new(upstream: Arc<dyn AsyncProxy>) -> Self {
        Self { upstream }
    }
}

impl AsyncProxy for HttpMockProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let mut stream = self.upstream.connect(context).await?;
            if let Err(error) = tokio::io::AsyncWriteExt::write_all(&mut stream, MOCK_REQUEST).await
            {
                return Err(Error::new(
                    ErrorKind::Io,
                    format!("http_mock request: {error}"),
                ));
            }
            Ok(stream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        self.upstream.open_datagram(context)
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use yuhaiin_core::proxy::FixedAsyncProxy;
    use yuhaiin_core::{Endpoint, Network};

    #[test]
    fn request_matches_go_contract() {
        assert_eq!(
            MOCK_REQUEST,
            b"GET / HTTP/1.1\r\nHost: www.speedtest.cn\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn writes_mock_request_before_returning_tcp_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; MOCK_REQUEST.len()];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, MOCK_REQUEST);
            stream.read_exact(&mut [0u8; 4]).await.unwrap();
            stream.write_all(b"pong").await.unwrap();
        });

        let parent: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
            address,
            timeout: Duration::from_secs(1),
        });
        let proxy = HttpMockProxy::new(parent);
        let context = FlowContext::new(Endpoint::ip(
            Network::Tcp,
            "198.51.100.10:443".parse::<SocketAddr>().unwrap(),
        ));
        let mut stream = proxy.connect(&context).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }
}
