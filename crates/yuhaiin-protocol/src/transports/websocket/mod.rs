//! Client-side WebSocket transport for composable proxy protocols.
//!
//! The parent proxy is responsible for reaching the WebSocket endpoint.  The
//! wrapper only performs the HTTP upgrade and exposes the resulting message
//! stream as the byte stream expected by VLESS/Trojan and other protocols.

use std::sync::Arc;

use tokio_tungstenite::{client_async, tungstenite::client::IntoClientRequest};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Error, ErrorKind, FlowContext, Result};

mod io;
pub use io::WebSocketIo;
pub mod server;

pub struct WebSocketProxy {
    upstream: Arc<dyn AsyncProxy>,
    host: String,
    path: String,
}

impl WebSocketProxy {
    pub fn new(
        upstream: Arc<dyn AsyncProxy>,
        host: impl Into<String>,
        path: impl Into<String>,
    ) -> Result<Self> {
        let host = host.into();
        if host.trim().is_empty() {
            return Err(Error::invalid("WebSocket host cannot be empty"));
        }
        let path = path.into();
        let path = if path.is_empty() {
            "/".to_owned()
        } else if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        };
        Ok(Self {
            upstream,
            host,
            path,
        })
    }
}

impl AsyncProxy for WebSocketProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let stream = self.upstream.connect(context).await?;
            let uri = format!("ws://{}{}", self.host, self.path);
            let request = uri.into_client_request().map_err(|error| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("WebSocket request: {error}"),
                )
            })?;
            let (websocket, response) = client_async(request, stream).await.map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("WebSocket handshake: {error}"))
            })?;
            if response.status().as_u16() != 101 {
                return Err(Error::new(
                    ErrorKind::Protocol,
                    format!("WebSocket handshake returned {}", response.status()),
                ));
            }
            Ok(Box::new(WebSocketIo::new(websocket)) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "WebSocket transport does not expose a datagram socket",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::FixedAsyncProxy;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use yuhaiin_core::{Endpoint, Network};

    #[tokio::test]
    async fn client_wrapper_upgrades_parent_and_preserves_binary_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
            use futures_util::{SinkExt, StreamExt};
            let Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(data))) =
                websocket.next().await
            else {
                panic!("server did not receive a binary frame");
            };
            assert_eq!(&data[..], b"request");
            websocket
                .send(tokio_tungstenite::tungstenite::Message::binary(
                    &b"response"[..],
                ))
                .await
                .unwrap();
        });
        let parent: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
            address,
            timeout: std::time::Duration::from_secs(1),
        });
        let proxy = WebSocketProxy::new(parent, address.to_string(), "/proxy").unwrap();
        let context = FlowContext::new(Endpoint::ip(
            Network::Tcp,
            "198.51.100.10:443".parse::<SocketAddr>().unwrap(),
        ));
        let mut stream = proxy.connect(&context).await.unwrap();
        stream.write_all(b"request").await.unwrap();
        let mut response = vec![0u8; 8];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        server.await.unwrap();
    }
}
