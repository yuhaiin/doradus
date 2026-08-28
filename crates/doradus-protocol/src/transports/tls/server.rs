//! Server-side TLS transports used by inbound listeners.
//!
//! The runtime still decides when a listener needs TLS and owns the listener
//! lifecycle.  This module owns the TLS wire configuration: certificate/key
//! decoding, rustls server configuration, ALPN defaults, and TLS-auto's
//! SNI-based certificate resolver.

use std::io::Cursor;
use std::sync::Arc;

use doradus_core::{Error, ErrorKind, Result};

pub type TlsAcceptor = tokio_rustls::TlsAcceptor;

/// Build the server acceptor for the TLS transport declared in an inbound
/// contract.  A missing TLS transport returns `None` so callers can share
/// this function with ordinary TCP listeners.
pub fn build(data_json: &[u8], transports: &[String]) -> Result<Option<TlsAcceptor>> {
    if has_transport(transports, "tls_auto") {
        return crate::tls_auto::build(data_json, transports);
    }

    if !has_transport(transports, "tls") {
        return Ok(None);
    }

    let value: serde_json::Value = serde_json::from_slice(data_json).map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("inbound TLS configuration JSON: {error}"),
        )
    })?;
    let transport = value
        .get("transport")
        .or_else(|| value.get("transports"))
        .and_then(serde_json::Value::as_array)
        .and_then(|items| {
            items.iter().find(|item| {
                item.get("type")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("tls"))
            })
        })
        .ok_or_else(|| Error::invalid("inbound TLS transport configuration is missing"))?;
    let config = transport
        .get("tls")
        .and_then(serde_json::Value::as_object)
        .and_then(|value| value.get("tls"))
        .and_then(serde_json::Value::as_object)
        .or_else(|| transport.get("tls").and_then(serde_json::Value::as_object))
        .ok_or_else(|| Error::invalid("inbound TLS server config is missing"))?;
    let certificate = config
        .get("certificates")
        .and_then(serde_json::Value::as_array)
        .and_then(|certificates| certificates.first())
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| Error::invalid("inbound TLS certificate is missing"))?;
    let cert_bytes = file_or_base64(certificate, "certBase64", "certFile")?;
    let key_bytes = file_or_base64(certificate, "keyBase64", "keyFile")?;
    let certificates = if cert_bytes.starts_with(b"-----BEGIN") {
        rustls_pemfile::certs(&mut Cursor::new(cert_bytes))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("inbound TLS cert: {error}"))
            })?
    } else {
        vec![rustls::pki_types::CertificateDer::from(cert_bytes)]
    };
    if certificates.is_empty() {
        return Err(Error::invalid("inbound TLS certificate chain is empty"));
    }
    let key = if key_bytes.starts_with(b"-----BEGIN") {
        rustls_pemfile::private_key(&mut Cursor::new(key_bytes))
            .map_err(|error| Error::new(ErrorKind::Protocol, format!("inbound TLS key: {error}")))?
            .ok_or_else(|| Error::invalid("inbound TLS private key is missing"))?
    } else {
        rustls::pki_types::PrivateKeyDer::try_from(key_bytes).map_err(|error| {
            Error::new(ErrorKind::Protocol, format!("inbound TLS DER key: {error}"))
        })?
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("inbound TLS provider: {error}"),
            )
        })?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("inbound TLS cert/key: {error}"),
            )
        })?;
    if let Some(protocols) = config
        .get("nextProtos")
        .and_then(serde_json::Value::as_array)
    {
        server.alpn_protocols = protocols
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::as_bytes)
            .map(ToOwned::to_owned)
            .collect();
    }
    if has_transport(transports, "http2")
        && !has_transport(transports, "websocket")
        && server.alpn_protocols.is_empty()
    {
        server.alpn_protocols.push(b"h2".to_vec());
    }
    Ok(Some(TlsAcceptor::from(Arc::new(server))))
}

/// Fill generated TLS-auto fields before an inbound contract is persisted.
pub fn fill_generated_fields(value: &mut serde_json::Value) -> Result<()> {
    crate::tls_auto::fill_generated_fields(value)
}

fn has_transport(transports: &[String], kind: &str) -> bool {
    transports
        .iter()
        .any(|transport| transport.eq_ignore_ascii_case(kind))
}

fn file_or_base64(
    value: &serde_json::Map<String, serde_json::Value>,
    encoded_key: &str,
    file_key: &str,
) -> Result<Vec<u8>> {
    use base64::Engine;

    if let Some(encoded) = value.get(encoded_key).and_then(serde_json::Value::as_str) {
        return base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| {
                Error::new(ErrorKind::InvalidInput, format!("{encoded_key}: {error}"))
            });
    }
    if let Some(bytes) = value.get(encoded_key).and_then(serde_json::Value::as_array) {
        return bytes
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|value| u8::try_from(value).ok())
                    .ok_or_else(|| Error::invalid(format!("{encoded_key} contains a non-byte")))
            })
            .collect();
    }
    let path = value
        .get(file_key)
        .and_then(serde_json::Value::as_str)
        .filter(|path| !path.trim().is_empty())
        .ok_or_else(|| {
            Error::invalid(format!(
                "TLS certificate requires {encoded_key} or {file_key}"
            ))
        })?;
    std::fs::read(path)
        .map_err(|error| Error::new(ErrorKind::Io, format!("read TLS file {path:?}: {error}")))
}
