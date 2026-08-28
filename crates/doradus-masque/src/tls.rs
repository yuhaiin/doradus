use std::io::Write;
use std::time::Duration;

use doradus_core::{Error, ErrorKind, Result};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rcgen::{CertificateParams, KeyPair};
use tempfile::NamedTempFile;

/// TLS material consumed by quiche's BoringSSL-backed configuration.
///
/// quiche 0.22 loads the client certificate and key from PEM files. The files
/// are kept alive for the duration of the session, matching the usque-rs
/// integration while ensuring credentials never enter the repository.
pub(crate) struct TlsMaterial {
    pub(crate) cert_pem_file: NamedTempFile,
    pub(crate) key_pem_file: NamedTempFile,
    pub(crate) endpoint_pub_key_spki_der: Vec<u8>,
}

pub(crate) fn prepare_tls_material(
    private_key_der: &[u8],
    endpoint_pub_key_spki_der: &[u8],
) -> Result<TlsMaterial> {
    if endpoint_pub_key_spki_der.is_empty() {
        return Err(Error::invalid("WARP endpoint public key is empty"));
    }
    let signing_key = SigningKey::from_pkcs8_der(private_key_der).map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("WARP client key is not a P-256 PKCS#8 key: {error}"),
        )
    })?;
    let key_pem = signing_key.to_pkcs8_pem(LineEnding::LF).map_err(|error| {
        Error::new(ErrorKind::Protocol, format!("WARP client key PEM: {error}"))
    })?;
    let key_pair = KeyPair::from_pem(key_pem.as_ref()).map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("WARP client key for certificate: {error}"),
        )
    })?;

    let now = time::OffsetDateTime::now_utc();
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("WARP client certificate: {error}"),
        )
    })?;
    params.not_before = now;
    params.not_after =
        now + time::Duration::seconds(Duration::from_secs(24 * 60 * 60).as_secs() as i64);
    let certificate = params.self_signed(&key_pair).map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("WARP client certificate: {error}"),
        )
    })?;

    let mut cert_pem_file = NamedTempFile::new().map_err(error_io)?;
    cert_pem_file
        .write_all(certificate.pem().as_bytes())
        .map_err(error_io)?;
    cert_pem_file.flush().map_err(error_io)?;
    let mut key_pem_file = NamedTempFile::new().map_err(error_io)?;
    key_pem_file
        .write_all(key_pem.as_bytes())
        .map_err(error_io)?;
    key_pem_file.flush().map_err(error_io)?;

    Ok(TlsMaterial {
        cert_pem_file,
        key_pem_file,
        endpoint_pub_key_spki_der: endpoint_pub_key_spki_der.to_vec(),
    })
}

pub(crate) fn verify_endpoint_key(peer_cert_der: &[u8], expected_spki_der: &[u8]) -> bool {
    let Ok((_, certificate)) = x509_parser::parse_x509_certificate(peer_cert_der) else {
        return false;
    };
    certificate.tbs_certificate.subject_pki.raw == expected_spki_der
}

fn error_io(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::EncodePublicKey;

    #[test]
    fn builds_short_lived_p256_client_material() {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let private_key = signing_key.to_pkcs8_der().unwrap();
        let public_key = signing_key.verifying_key().to_public_key_der().unwrap();
        let material = prepare_tls_material(private_key.as_bytes(), public_key.as_bytes()).unwrap();
        assert!(material.cert_pem_file.path().exists());
        assert!(material.key_pem_file.path().exists());
    }
}
