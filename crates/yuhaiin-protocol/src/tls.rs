//! Async RustCrypto TLS transport wrapper for protocol layers.

use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Error, ErrorKind, FlowContext, Result};

/// Wrap an already-connected stream proxy with client-side TLS.
///
/// It intentionally leaves endpoint selection to `upstream`: a fixed parent
/// dials the configured peer while the flow context still carries the final
/// destination for the next protocol (Trojan, HTTP/2, etc.).
pub struct RustCryptoTlsProxy {
    upstream: Arc<dyn AsyncProxy>,
    connector: TlsConnector,
    server_name: String,
}

impl RustCryptoTlsProxy {
    pub fn new(
        upstream: Arc<dyn AsyncProxy>,
        root_store: RootCertStore,
        server_name: impl Into<String>,
        next_protocols: &[String],
    ) -> Result<Self> {
        let provider = Arc::new(rustls_rustcrypto::provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(tls_error)?
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = next_protocols
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect();
        Ok(Self {
            upstream,
            connector: TlsConnector::from(Arc::new(config)),
            server_name: server_name.into(),
        })
    }
}

impl AsyncProxy for RustCryptoTlsProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let stream = self.upstream.connect(context).await?;
            let name = ServerName::try_from(self.server_name.clone())
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid TLS server name"))?;
            let stream = self
                .connector
                .connect(name, stream)
                .await
                .map_err(tls_error)?;
            Ok(Box::new(stream) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "TLS transport does not expose a datagram socket; wrap its stream protocol instead",
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

fn tls_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Protocol, format!("TLS: {error}"))
}
