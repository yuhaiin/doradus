//! Async RustCrypto TLS transport wrapper for protocol layers.

use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use yuhaiin_core::proxy::{
    AsyncDatagram, AsyncProxy, BoxAsyncStream, stream_local_addr, with_stream_local_addr,
};
use yuhaiin_core::{BoxFuture, Error, ErrorKind, FlowContext, Result};

pub use super::tls_sync::RustCryptoTlsClient;

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
        Self::new_with_options(upstream, root_store, server_name, next_protocols, false)
    }

    pub fn new_with_options(
        upstream: Arc<dyn AsyncProxy>,
        root_store: RootCertStore,
        server_name: impl Into<String>,
        next_protocols: &[String],
        insecure_skip_verify: bool,
    ) -> Result<Self> {
        let provider = Arc::new(rustls_rustcrypto::provider());
        let mut config = if insecure_skip_verify {
            ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(tls_error)?
                .dangerous()
                .with_custom_certificate_verifier(SkipServerVerification::new(provider))
                .with_no_client_auth()
        } else {
            ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(tls_error)?
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };
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

/// Skip certificate-chain and hostname checks for Go's explicit
/// `insecure_skip_verify` option while retaining TLS handshake signature
/// verification.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

impl AsyncProxy for RustCryptoTlsProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let stream = self.upstream.connect(context).await?;
            let local_addr = stream_local_addr(&*stream);
            let name = ServerName::try_from(self.server_name.clone())
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid TLS server name"))?;
            let stream = self
                .connector
                .connect(name, stream)
                .await
                .map_err(tls_error)?;
            Ok(with_stream_local_addr(
                Box::new(stream) as BoxAsyncStream,
                local_addr,
            ))
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
