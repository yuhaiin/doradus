use std::sync::Arc;
use std::time::Duration;

use doradus_core::{Error, ErrorKind, Result};

use super::{ALPN, QuicConfig, QuicServerConfig};

const MAX_STREAMS: u32 = 4096;

pub(super) fn build_client_tls_config(config: &QuicConfig) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for certificate in &config.ca_certificates {
        roots
            .add(rustls::pki_types::CertificateDer::from(certificate.clone()))
            .map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("QUIC CA certificate: {error}"))
            })?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = if config.insecure_skip_verify {
        rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| Error::new(ErrorKind::Protocol, format!("QUIC TLS: {error}")))?
            .dangerous()
            .with_custom_certificate_verifier(SkipServerVerification::new(provider))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| Error::new(ErrorKind::Protocol, format!("QUIC TLS: {error}")))?
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    tls.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(tls))
}

pub(super) fn build_quinn_client_config(
    tls: Arc<rustls::ClientConfig>,
    config: &QuicConfig,
) -> Result<quinn::ClientConfig> {
    let tls = force_alpn(tls);
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("configure QUIC TLS: {error}")))?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    client.transport_config(Arc::new(transport_config(
        config.idle_timeout,
        config.rx_memory_budget,
    )?));
    Ok(client)
}

pub(super) fn force_alpn(mut tls: Arc<rustls::ClientConfig>) -> Arc<rustls::ClientConfig> {
    let config = Arc::make_mut(&mut tls);
    config.alpn_protocols = vec![ALPN.to_vec()];
    tls
}

pub(super) fn build_quinn_server_config(
    tls: Arc<rustls::ServerConfig>,
    config: &QuicServerConfig,
) -> Result<quinn::ServerConfig> {
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("configure QUIC server TLS: {error}"),
            )
        })?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(Arc::new(transport_config(
        config.idle_timeout,
        config.rx_memory_budget,
    )?));
    Ok(server)
}

fn transport_config(
    idle_timeout: Duration,
    memory_budget: usize,
) -> Result<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    let idle_timeout = idle_timeout
        .try_into()
        .map_err(|_| Error::invalid("QUIC idle timeout is too large"))?;
    transport
        .max_idle_timeout(Some(idle_timeout))
        .keep_alive_interval(None)
        .datagram_receive_buffer_size(Some(memory_budget))
        .datagram_send_buffer_size(memory_budget)
        .max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_STREAMS));
    Ok(transport)
}

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
