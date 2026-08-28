use super::*;

#[cfg(feature = "doh-tls")]
pub(in crate::proxy) fn build_protocol_tls_proxy(
    config: &GoProxyRuntimeConfig,
    upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    use base64::Engine;
    use rustls::RootCertStore;
    use rustls::pki_types::CertificateDer;

    let layer = config
        .layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case("tls"))
        .ok_or_else(|| Error::invalid("protocol TLS layer is missing"))?;
    let server_name = layer
        .config
        .get("servernames")
        .or_else(|| layer.config.get("serverNames"))
        .and_then(serde_json::Value::as_array)
        .and_then(|values| values.iter().find_map(serde_json::Value::as_str))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::invalid("protocol TLS layer requires servernames"))?;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(certificates) = layer
        .config
        .get("ca_cert")
        .or_else(|| layer.config.get("caCert"))
        .and_then(serde_json::Value::as_array)
    {
        for certificate in certificates {
            let encoded = certificate
                .as_str()
                .ok_or_else(|| Error::invalid("Trojan TLS ca_cert must contain strings"))?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|error| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("protocol TLS ca_cert: {error}"),
                    )
                })?;
            roots.add(CertificateDer::from(bytes)).map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("protocol TLS CA: {error}"))
            })?;
        }
    }
    let insecure_skip_verify = layer
        .config
        .get("insecure_skip_verify")
        .or_else(|| layer.config.get("insecureSkipVerify"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let next_protocols = layer
        .config
        .get("next_protos")
        .or_else(|| layer.config.get("nextProtos"))
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(Arc::new(
        doradus_protocol::tls::RustCryptoTlsProxy::new_with_options(
            upstream,
            roots,
            server_name,
            &next_protocols,
            insecure_skip_verify,
        )?,
    ))
}

#[cfg(feature = "doh-tls")]
pub(in crate::proxy) fn build_tls_termination_proxy(
    config: &GoProxyRuntimeConfig,
    upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    use tokio_rustls::TlsAcceptor;

    let layer = config
        .layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case("tls_termination"))
        .ok_or_else(|| Error::invalid("TLS termination layer is missing"))?;
    let tls = layer.config.get("tls").unwrap_or(&layer.config);
    let certificates = tls
        .get("certificates")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::invalid("TLS termination certificates are missing"))?;

    let mut entries = Vec::new();
    for certificate in certificates {
        let certificate = certificate
            .as_object()
            .ok_or_else(|| Error::invalid("TLS termination certificate must be an object"))?;
        entries.push((certificate, None));
    }
    if let Some(named_certificates) = tls
        .get("serverNameCertificate")
        .or_else(|| tls.get("server_name_certificate"))
        .and_then(serde_json::Value::as_object)
    {
        for (name, certificate) in named_certificates {
            let certificate = certificate.as_object().ok_or_else(|| {
                Error::invalid("TLS termination named certificate must be an object")
            })?;
            entries.push((certificate, Some(name.as_str())));
        }
    }

    let mut default = Vec::new();
    let mut named = BTreeMap::new();
    for (certificate, name) in entries {
        let certified = tls_termination_certified_key(certificate)?;
        if let Some(name) = name {
            let name = tls_termination_name(name);
            if !name.is_empty() {
                named.insert(name, Arc::clone(&certified));
            }
        } else {
            default.push(Arc::clone(&certified));
        }
    }
    if default.is_empty() && named.is_empty() {
        return Err(Error::invalid("TLS termination has no usable certificates"));
    }
    let resolver = StaticTlsTerminationResolver { default, named };
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("TLS termination provider: {error}"),
        )
    })?
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(resolver));
    server.alpn_protocols = tls
        .get("nextProtos")
        .or_else(|| tls.get("next_protos"))
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::as_bytes)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default();

    Ok(Arc::new(TlsTerminationProxy {
        upstream,
        acceptor: TlsAcceptor::from(Arc::new(server)),
    }))
}

#[cfg(feature = "doh-tls")]
pub(super) fn tls_termination_certified_key(
    value: &serde_json::Map<String, serde_json::Value>,
) -> Result<Arc<rustls::sign::CertifiedKey>> {
    // Go's x509KeyPair tries a complete file-path pair first, then falls back
    // to the inline cert/key fields when either file is unavailable or the
    // file pair cannot be parsed. Keep that precedence for mixed legacy and
    // current JSON contracts instead of failing startup on a stale path.
    if let Some((cert_bytes, key_bytes)) = tls_termination_file_pair(value)
        && let Ok(certified) = tls_termination_certified_key_from_bytes(cert_bytes, key_bytes)
    {
        return Ok(certified);
    }

    let cert_bytes = tls_termination_bytes(
        value,
        &["cert", "certBase64"],
        &[],
        "TLS termination certificate",
    )?;
    let key_bytes = tls_termination_bytes(
        value,
        &["key", "keyBase64"],
        &[],
        "TLS termination private key",
    )?;
    tls_termination_certified_key_from_bytes(cert_bytes, key_bytes)
}

#[cfg(feature = "doh-tls")]
pub(super) fn tls_termination_file_pair(
    value: &serde_json::Map<String, serde_json::Value>,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let cert_path = value
        .get("certFile")
        .or_else(|| value.get("certFilePath"))
        .or_else(|| value.get("cert_file_path"))
        .and_then(serde_json::Value::as_str)
        .filter(|path| !path.trim().is_empty())?;
    let key_path = value
        .get("keyFile")
        .or_else(|| value.get("keyFilePath"))
        .or_else(|| value.get("key_file_path"))
        .and_then(serde_json::Value::as_str)
        .filter(|path| !path.trim().is_empty())?;
    Some((
        std::fs::read(cert_path).ok()?,
        std::fs::read(key_path).ok()?,
    ))
}

#[cfg(feature = "doh-tls")]
pub(super) fn tls_termination_certified_key_from_bytes(
    cert_bytes: Vec<u8>,
    key_bytes: Vec<u8>,
) -> Result<Arc<rustls::sign::CertifiedKey>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::sign::CertifiedKey;

    let cert_chain = if cert_bytes.starts_with(b"-----BEGIN") {
        rustls_pemfile::certs(&mut std::io::Cursor::new(cert_bytes))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| {
                Error::new(
                    ErrorKind::Protocol,
                    format!("TLS termination certificate PEM: {error}"),
                )
            })?
    } else {
        vec![CertificateDer::from(cert_bytes)]
    };
    if cert_chain.is_empty() {
        return Err(Error::invalid("TLS termination certificate chain is empty"));
    }
    let key = if key_bytes.starts_with(b"-----BEGIN") {
        rustls_pemfile::private_key(&mut std::io::Cursor::new(key_bytes))
            .map_err(|error| {
                Error::new(
                    ErrorKind::Protocol,
                    format!("TLS termination private key PEM: {error}"),
                )
            })?
            .ok_or_else(|| Error::invalid("TLS termination private key is empty"))?
    } else {
        PrivateKeyDer::try_from(key_bytes).map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("TLS termination private key DER: {error}"),
            )
        })?
    };
    let signer = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("TLS termination signing key: {error:?}"),
        )
    })?;
    Ok(Arc::new(CertifiedKey::new(cert_chain, signer)))
}

#[cfg(feature = "doh-tls")]
pub(in crate::proxy) fn tls_termination_name(name: &str) -> String {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.starts_with("*.") || name.parse::<std::net::IpAddr>().is_ok() {
        name
    } else {
        format!("*.{name}")
    }
}

#[cfg(feature = "doh-tls")]
pub(in crate::proxy) fn tls_termination_bytes(
    value: &serde_json::Map<String, serde_json::Value>,
    encoded_keys: &[&str],
    file_keys: &[&str],
    label: &str,
) -> Result<Vec<u8>> {
    use base64::Engine as _;

    for key in encoded_keys {
        if let Some(bytes) = value.get(*key).and_then(serde_json::Value::as_array) {
            return bytes
                .iter()
                .map(|byte| {
                    byte.as_u64()
                        .and_then(|byte| u8::try_from(byte).ok())
                        .ok_or_else(|| Error::invalid(format!("{label} byte is invalid")))
                })
                .collect();
        }
        if let Some(encoded) = value.get(*key).and_then(serde_json::Value::as_str) {
            if encoded.starts_with("-----BEGIN") {
                return Ok(encoded.as_bytes().to_vec());
            }
            return base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|error| Error::invalid(format!("{label} base64: {error}")));
        }
    }
    for key in file_keys {
        if let Some(path) = value
            .get(*key)
            .and_then(serde_json::Value::as_str)
            .filter(|path| !path.trim().is_empty())
        {
            return std::fs::read(path)
                .map_err(|error| Error::invalid(format!("read {label} {path:?}: {error}")));
        }
    }
    Err(Error::invalid(format!("{label} is missing")))
}

#[cfg(feature = "doh-tls")]
#[derive(Debug)]
struct StaticTlsTerminationResolver {
    default: Vec<Arc<rustls::sign::CertifiedKey>>,
    named: BTreeMap<String, Arc<rustls::sign::CertifiedKey>>,
}

#[cfg(feature = "doh-tls")]
impl rustls::server::ResolvesServerCert for StaticTlsTerminationResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(certificate) =
            tls_termination_match_name(client_hello.server_name(), &self.named)
        {
            return Some(Arc::clone(certificate));
        }
        // Go's tls.Config.GetCertificate falls back to the first configured
        // certificate when ClientHello has no SNI or does not match a named
        // certificate. This is required for standalone termination and for
        // clients that intentionally omit server_name.
        self.default.first().cloned()
    }
}

#[cfg(feature = "doh-tls")]
pub(in crate::proxy) fn tls_termination_match_name<'a, T>(
    server_name: Option<&str>,
    named: &'a BTreeMap<String, T>,
) -> Option<&'a T> {
    let name = server_name?.trim_end_matches('.').to_ascii_lowercase();
    if let Some(certificate) = named.get(&name) {
        return Some(certificate);
    }
    let mut labels = name.split('.');
    labels.next()?;
    let wildcard = format!("*.{}", labels.collect::<Vec<_>>().join("."));
    named.get(&wildcard)
}
