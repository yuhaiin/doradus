//! Pure Rust TLS client adapter for proxy and HTTP/2 transports.
//!
//! This module is feature-gated because `rustls-rustcrypto` is currently an
//! alpha provider. It is nevertheless a real `rustls` client implementation,
//! not a placeholder: callers supply a `RootCertStore`, and the resulting
//! `RustCryptoTlsClient` implements the synchronous `proxy::TlsClient` seam.

use std::net::TcpStream;
use std::sync::Arc;

use crate::proxy::TlsClient;
use crate::{Error, ErrorKind, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

#[derive(Clone)]
pub struct RustCryptoTlsClient {
    config: Arc<ClientConfig>,
}

impl RustCryptoTlsClient {
    /// Build a TLS client using the pure RustCrypto provider and caller-owned
    /// trust roots. Empty roots are allowed for test construction but will
    /// reject normal server certificates during the handshake.
    pub fn new(root_store: RootCertStore) -> Result<Self> {
        let provider = Arc::new(rustls_rustcrypto::provider());
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(tls_error)?
            .with_root_certificates(root_store)
            .with_no_client_auth();
        Ok(Self {
            config: Arc::new(config),
        })
    }

    pub fn from_config(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &Arc<ClientConfig> {
        &self.config
    }
}

impl TlsClient for RustCryptoTlsClient {
    type Stream = StreamOwned<ClientConnection, TcpStream>;

    fn connect(&self, stream: TcpStream, server_name: &str) -> Result<Self::Stream> {
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "invalid TLS server name"))?;
        let connection =
            ClientConnection::new(self.config.clone(), server_name).map_err(tls_error)?;
        Ok(StreamOwned::new(connection, stream))
    }
}

fn tls_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Protocol, format!("TLS: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_builds_a_client_config_without_c_backend() {
        let client = RustCryptoTlsClient::new(RootCertStore::empty()).unwrap();
        assert!(client.config().alpn_protocols.is_empty());
    }
}
