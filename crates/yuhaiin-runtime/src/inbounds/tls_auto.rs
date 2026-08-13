//! Dynamic certificate TLS inbound transport.
//!
//! Go's `tls_auto` transport keeps a CA key and creates a leaf certificate for
//! the SNI in each ClientHello.  This module keeps the same boundary while
//! using RustCrypto's X.509 builder and rustls' synchronous certificate
//! resolver.  Generated certificates are cached per normalized SNI so a busy
//! listener does not repeatedly perform public-key work.

use std::collections::HashMap;
use std::io::Cursor;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use base64::Engine as _;
use ed25519_tls_auto::pkcs8::DecodePrivateKey as _;
use ed25519_tls_auto::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use p256_tls_auto::ecdsa::{DerSignature, SigningKey};
use p256_tls_auto::elliptic_curve::rand_core::{OsRng, RngCore};
use p256_tls_auto::pkcs8::EncodePrivateKey as _;
use p256_tls_auto::{PublicKey, SecretKey};
use rsa_tls_auto::RsaPrivateKey;
use rsa_tls_auto::pkcs1v15::{Signature as RsaSignature, SigningKey as RsaSigningKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use signature_tls_auto::{Keypair, Signer};
use tokio_rustls::TlsAcceptor;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::{Ia5String, ObjectIdentifier};
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{ExtendedKeyUsage, SubjectAltName, name::GeneralName};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{
    DynSignatureAlgorithmIdentifier, EncodePublicKey, SignatureBitStringEncoding,
    SubjectPublicKeyInfoOwned,
};
use x509_cert::time::Validity;

use yuhaiin_core::{Error, ErrorKind, Result};

const SERVER_AUTH_OID: &str = "1.3.6.1.5.5.7.3.1";
const CLIENT_AUTH_OID: &str = "1.3.6.1.5.5.7.3.2";
const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
const ED25519_OID: &str = "1.3.101.112";
const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";

pub(crate) fn build(data_json: &[u8], transports: &[String]) -> Result<Option<TlsAcceptor>> {
    let value: serde_json::Value = serde_json::from_slice(data_json).map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("inbound TLS-auto configuration JSON: {error}"),
        )
    })?;
    let config = transport_config(&value, "tls_auto")
        .ok_or_else(|| Error::invalid("inbound TLS-auto transport configuration is missing"))?;

    let ca_cert = binary_field(
        config,
        &["ca_cert", "caCert", "caCertBase64"],
        &["ca_cert_file", "caCertFile"],
    )?;
    let ca_key = binary_field(
        config,
        &["ca_key", "caKey", "caKeyBase64"],
        &["ca_key_file", "caKeyFile"],
    )?;
    let server_names = string_list(config, &["servernames", "serverNames", "server_names"])?;
    let next_protos = string_list_optional(config, &["next_protos", "nextProtos"])?;
    let authority = Arc::new(TlsAutoAuthority::parse(&ca_cert, &ca_key)?);
    let resolver = Arc::new(TlsAutoResolver::new(authority, server_names)?);

    let provider = Arc::new(rustls_rustcrypto::provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("inbound TLS-auto provider: {error}"),
            )
        })?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    server.alpn_protocols = next_protos
        .into_iter()
        .map(|protocol| protocol.into_bytes())
        .collect();
    if super::has_transport(transports, "http2")
        && !super::has_transport(transports, "websocket")
        && server.alpn_protocols.is_empty()
    {
        server.alpn_protocols.push(b"h2".to_vec());
    }

    // rustls currently exposes ECH client-side configuration but not the
    // server-side encrypted-client-hello key API used by Go's crypto/tls.
    // Keep the listener usable as ordinary SNI TLS and leave the limitation
    // visible in the migration checklist instead of silently dropping the
    // complete tls_auto transport.
    if config
        .get("ech")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|ech| {
            ech.get("enable")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        })
    {
        eprintln!(
            "inbound TLS-auto ECH is configured but server ECH is not available in rustls; using SNI TLS"
        );
    }

    Ok(Some(TlsAcceptor::from(Arc::new(server))))
}

/// Fill the generated TLS-auto CA fields at the same boundary as Go's
/// `fillGeneratedContractFields`.  The generated values are written back to
/// the contract before it is stored, so subsequent reloads keep issuing
/// certificates from the same authority.
pub(crate) fn fill_generated_fields(value: &mut serde_json::Value) -> Result<()> {
    let Some(config) = transport_config_mut(value, "tls_auto") else {
        return Ok(());
    };

    let ca_cert = optional_binary_field(
        config,
        &["ca_cert", "caCert", "caCertBase64"],
        &["ca_cert_file", "caCertFile"],
    )?;
    let ca_key = optional_binary_field(
        config,
        &["ca_key", "caKey", "caKeyBase64"],
        &["ca_key_file", "caKeyFile"],
    )?;

    if let (Some(ca_cert), Some(ca_key)) = (&ca_cert, &ca_key)
        && !ca_cert.is_empty()
        && !ca_key.is_empty()
    {
        TlsAutoAuthority::parse(ca_cert, ca_key).map_err(|error| {
            Error::new(ErrorKind::Protocol, format!("parse ca failed: {error}"))
        })?;
        return Ok(());
    }

    let (ca_cert, ca_key) = generate_ca()?;
    config.insert(
        "caCertBase64".to_owned(),
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(ca_cert)),
    );
    config.insert(
        "caKeyBase64".to_owned(),
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(ca_key)),
    );
    Ok(())
}

#[derive(Debug)]
struct TlsAutoAuthority {
    subject: Name,
    signer: TlsAutoSigner,
}

#[derive(Debug)]
enum TlsAutoSigner {
    P256(Arc<SigningKey>),
    Ed25519(Arc<Ed25519CertificateSigner>),
    Rsa(Arc<RsaSigningKey<sha2_10::Sha256>>),
}

impl TlsAutoSigner {
    fn public_key_info(&self) -> Result<SubjectPublicKeyInfoOwned> {
        let result = match self {
            Self::P256(signer) => {
                SubjectPublicKeyInfoOwned::from_key(PublicKey::from(signer.verifying_key()))
            }
            Self::Ed25519(signer) => SubjectPublicKeyInfoOwned::from_key(signer.verifying_key()),
            Self::Rsa(signer) => SubjectPublicKeyInfoOwned::from_key(signer.verifying_key()),
        };
        result.map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("inbound TLS-auto CA public key: {error}"),
            )
        })
    }
}

#[derive(Debug)]
struct Ed25519CertificateSigner(Ed25519SigningKey);

#[derive(Clone, Debug)]
struct Ed25519CertificateSignature([u8; 64]);

impl Keypair for Ed25519CertificateSigner {
    type VerifyingKey = Ed25519VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.0.verifying_key()
    }
}

impl Signer<Ed25519CertificateSignature> for Ed25519CertificateSigner {
    fn try_sign(&self, message: &[u8]) -> signature_tls_auto::Result<Ed25519CertificateSignature> {
        Ok(Ed25519CertificateSignature(self.0.sign(message).to_bytes()))
    }
}

impl DynSignatureAlgorithmIdentifier for Ed25519CertificateSigner {
    fn signature_algorithm_identifier(
        &self,
    ) -> x509_cert::spki::Result<x509_cert::spki::AlgorithmIdentifierOwned> {
        Ok(x509_cert::spki::AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap(ED25519_OID),
            parameters: None,
        })
    }
}

impl SignatureBitStringEncoding for Ed25519CertificateSignature {
    fn to_bitstring(&self) -> x509_cert::der::Result<x509_cert::der::asn1::BitString> {
        x509_cert::der::asn1::BitString::new(0, self.0.to_vec())
    }
}

impl TlsAutoAuthority {
    fn parse(cert_bytes: &[u8], key_bytes: &[u8]) -> Result<Self> {
        let cert_der = first_certificate(cert_bytes)?;
        let certificate = x509_cert::Certificate::from_der(cert_der.as_ref()).map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("inbound TLS-auto CA certificate: {error}"),
            )
        })?;
        let key_der = pkcs8_key(key_bytes)?;
        let algorithm = certificate
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .oid;
        let signer = if algorithm == ObjectIdentifier::new_unwrap(EC_PUBLIC_KEY_OID) {
            let secret = SecretKey::from_pkcs8_der(&key_der).map_err(|error| {
                Error::new(
                    ErrorKind::Protocol,
                    format!("inbound TLS-auto ECDSA CA key must be P-256 PKCS#8: {error}"),
                )
            })?;
            TlsAutoSigner::P256(Arc::new(SigningKey::from(secret)))
        } else if algorithm == ObjectIdentifier::new_unwrap(ED25519_OID) {
            TlsAutoSigner::Ed25519(Arc::new(Ed25519CertificateSigner(
                Ed25519SigningKey::from_pkcs8_der(&key_der).map_err(|error| {
                    Error::new(
                        ErrorKind::Protocol,
                        format!("inbound TLS-auto Ed25519 CA key: {error}"),
                    )
                })?,
            )))
        } else if algorithm == ObjectIdentifier::new_unwrap(RSA_ENCRYPTION_OID) {
            TlsAutoSigner::Rsa(Arc::new(RsaSigningKey::new(
                RsaPrivateKey::from_pkcs8_der(&key_der).map_err(|error| {
                    Error::new(
                        ErrorKind::Protocol,
                        format!("inbound TLS-auto RSA CA key: {error}"),
                    )
                })?,
            )))
        } else {
            return Err(Error::invalid(format!(
                "inbound TLS-auto CA public key algorithm {algorithm} is unsupported"
            )));
        };
        let signer_spki = signer.public_key_info()?;
        if signer_spki != certificate.tbs_certificate.subject_public_key_info {
            return Err(Error::invalid(
                "inbound TLS-auto CA certificate and private key do not match",
            ));
        }
        Ok(Self {
            subject: certificate.tbs_certificate.subject,
            signer,
        })
    }
}

#[derive(Debug)]
struct TlsAutoResolver {
    authority: Arc<TlsAutoAuthority>,
    patterns: Vec<ServerNamePattern>,
    cache: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    serial: std::sync::atomic::AtomicU64,
}

impl TlsAutoResolver {
    fn new(authority: Arc<TlsAutoAuthority>, names: Vec<String>) -> Result<Self> {
        let patterns = names
            .into_iter()
            .map(ServerNamePattern::new)
            .collect::<Result<Vec<_>>>()?;
        if patterns.is_empty() {
            return Err(Error::invalid("inbound TLS-auto servernames is empty"));
        }
        Ok(Self {
            authority,
            patterns,
            cache: RwLock::new(HashMap::new()),
            serial: std::sync::atomic::AtomicU64::new(1),
        })
    }

    fn resolve_name(&self, server_name: &str) -> Option<(String, Vec<String>)> {
        let normalized = normalize_name(server_name);
        self.patterns.iter().find_map(|pattern| {
            if pattern.matches(&normalized) {
                // Cache by the configured Go server-name entry, not by the
                // arbitrary SNI value. A wildcard therefore produces one
                // certificate with both wildcard SANs, just like Go's shared
                // ServerCert pointer, instead of an unbounded certificate per
                // client hostname.
                Some((pattern.value.clone(), pattern.certificate_names()))
            } else {
                None
            }
        })
    }

    fn certificate(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        let (cache_key, certificate_names) = self.resolve_name(server_name)?;
        if let Ok(cache) = self.cache.read()
            && let Some(certificate) = cache.get(&cache_key)
        {
            return Some(Arc::clone(certificate));
        }

        let certificate = match self.generate_certificate(&certificate_names) {
            Ok(certificate) => Arc::new(certificate),
            Err(error) => {
                eprintln!("generate inbound TLS-auto certificate for {cache_key}: {error}");
                return None;
            }
        };
        if let Ok(mut cache) = self.cache.write() {
            let cached = cache
                .entry(cache_key)
                .or_insert_with(|| Arc::clone(&certificate));
            return Some(Arc::clone(cached));
        }
        Some(certificate)
    }

    fn generate_certificate(&self, names: &[String]) -> Result<CertifiedKey> {
        let serial = self
            .serial
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match &self.authority.signer {
            TlsAutoSigner::P256(ca_signer) => {
                let leaf_signer = SigningKey::random(&mut OsRng);
                let certificate = build_leaf_certificate::<_, DerSignature>(
                    &self.authority.subject,
                    ca_signer.as_ref(),
                    &leaf_signer,
                    names,
                    serial,
                )?;
                let private_key =
                    SecretKey::from(&leaf_signer)
                        .to_pkcs8_der()
                        .map_err(|error| {
                            Error::new(
                                ErrorKind::Protocol,
                                format!("TLS-auto leaf private key: {error}"),
                            )
                        })?;
                certified_key(certificate, private_key.as_bytes())
            }
            TlsAutoSigner::Ed25519(ca_signer) => {
                let mut seed = [0u8; 32];
                OsRng.fill_bytes(&mut seed);
                let leaf_signer = Ed25519CertificateSigner(Ed25519SigningKey::from_bytes(&seed));
                let certificate = build_leaf_certificate::<_, Ed25519CertificateSignature>(
                    &self.authority.subject,
                    ca_signer.as_ref(),
                    &leaf_signer,
                    names,
                    serial,
                )?;
                let private_key = leaf_signer.0.to_pkcs8_der().map_err(|error| {
                    Error::new(
                        ErrorKind::Protocol,
                        format!("TLS-auto leaf private key: {error}"),
                    )
                })?;
                certified_key(certificate, private_key.as_bytes())
            }
            TlsAutoSigner::Rsa(ca_signer) => {
                let leaf_signer = RsaSigningKey::<sha2_10::Sha256>::random(&mut OsRng, 2048)
                    .map_err(|error| {
                        Error::new(
                            ErrorKind::Protocol,
                            format!("TLS-auto RSA leaf key: {error}"),
                        )
                    })?;
                let certificate = build_leaf_certificate::<_, RsaSignature>(
                    &self.authority.subject,
                    ca_signer.as_ref(),
                    &leaf_signer,
                    names,
                    serial,
                )?;
                let private_key = RsaPrivateKey::from(leaf_signer.clone())
                    .to_pkcs8_der()
                    .map_err(|error| {
                        Error::new(
                            ErrorKind::Protocol,
                            format!("TLS-auto leaf private key: {error}"),
                        )
                    })?;
                certified_key(certificate, private_key.as_bytes())
            }
        }
    }
}

fn build_leaf_certificate<S, Sig>(
    authority_subject: &Name,
    ca_signer: &S,
    leaf_signer: &S,
    names: &[String],
    serial: u64,
) -> Result<Vec<u8>>
where
    S: Keypair + DynSignatureAlgorithmIdentifier + Signer<Sig>,
    S::VerifyingKey: EncodePublicKey,
    Sig: SignatureBitStringEncoding,
{
    let leaf_public_key = SubjectPublicKeyInfoOwned::from_key(leaf_signer.verifying_key())
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("TLS-auto leaf key: {error}")))?;
    let common_name = names.first().map(String::as_str).unwrap_or("localhost");
    let mut builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer: authority_subject.clone(),
            enable_key_agreement: true,
            enable_key_encipherment: true,
        },
        SerialNumber::from(serial),
        Validity::from_now(Duration::from_secs(10 * 365 * 24 * 60 * 60)).map_err(|error| {
            Error::new(ErrorKind::Protocol, format!("TLS-auto validity: {error}"))
        })?,
        Name::from_str(&format!("CN={common_name}")).map_err(|error| {
            Error::new(ErrorKind::Protocol, format!("TLS-auto subject: {error}"))
        })?,
        leaf_public_key,
        ca_signer,
    )
    .map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("TLS-auto certificate: {error}"),
        )
    })?;

    let subject_alt_names = names
        .iter()
        .map(|name| {
            if let Ok(ip) = name.parse::<IpAddr>() {
                Ok(GeneralName::from(ip))
            } else {
                Ia5String::new(name)
                    .map(GeneralName::DnsName)
                    .map_err(|error| {
                        Error::new(ErrorKind::InvalidInput, format!("TLS-auto SAN: {error}"))
                    })
            }
        })
        .collect::<Result<Vec<_>>>()?;
    builder
        .add_extension(&SubjectAltName(subject_alt_names))
        .map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("TLS-auto SAN extension: {error}"),
            )
        })?;
    builder
        .add_extension(&ExtendedKeyUsage(vec![
            ObjectIdentifier::new_unwrap(SERVER_AUTH_OID),
            ObjectIdentifier::new_unwrap(CLIENT_AUTH_OID),
        ]))
        .map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("TLS-auto EKU extension: {error}"),
            )
        })?;
    let leaf = builder
        .build::<Sig>()
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("TLS-auto signing: {error}")))?;
    leaf.to_der()
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("TLS-auto leaf DER: {error}")))
}

fn certified_key(certificate: Vec<u8>, private_key: &[u8]) -> Result<CertifiedKey> {
    let certificate = CertificateDer::from(certificate);
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key.to_vec()));
    let signing_key =
        rustls_rustcrypto::sign::any_supported_type(&private_key).map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("TLS-auto rustls leaf key: {error:?}"),
            )
        })?;
    Ok(CertifiedKey::new(vec![certificate], signing_key))
}

impl ResolvesServerCert for TlsAutoResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.certificate(client_hello.server_name()?)
    }
}

#[derive(Debug)]
struct ServerNamePattern {
    value: String,
    wildcard_suffix: Option<String>,
}

impl ServerNamePattern {
    fn new(value: String) -> Result<Self> {
        let value = normalize_name(&value);
        if value.is_empty() {
            return Err(Error::invalid("inbound TLS-auto servername is empty"));
        }
        let wildcard_suffix = value.strip_prefix("*.").map(|suffix| format!(".{suffix}"));
        Ok(Self {
            value,
            wildcard_suffix,
        })
    }

    fn matches(&self, name: &str) -> bool {
        if self.value == name {
            return true;
        }
        self.wildcard_suffix.as_ref().is_some_and(|suffix| {
            name.strip_suffix(suffix)
                .is_some_and(|prefix| !prefix.is_empty() && !prefix.contains('.'))
        })
    }

    fn certificate_names(&self) -> Vec<String> {
        match &self.wildcard_suffix {
            Some(suffix) => vec![
                self.value.clone(),
                suffix.trim_start_matches('.').to_owned(),
            ],
            None => vec![self.value.clone()],
        }
    }
}

fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn transport_config<'a>(
    value: &'a serde_json::Value,
    kind: &str,
) -> Option<&'a serde_json::Map<String, serde_json::Value>> {
    let items = value
        .get("transport")
        .or_else(|| value.get("transports"))
        .and_then(serde_json::Value::as_array)?;
    let item = items.iter().find(|item| {
        item.get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|configured| configured.eq_ignore_ascii_case(kind))
            || item.get(kind).is_some()
    })?;
    let mut candidate = item;
    for _ in 0..3 {
        if let Some(next) = candidate.get(kind) {
            candidate = next;
            continue;
        }
        if let Some(next) = candidate.get("config") {
            candidate = next;
            continue;
        }
        return candidate.as_object();
    }
    candidate.as_object()
}

fn transport_config_mut<'a>(
    value: &'a mut serde_json::Value,
    kind: &str,
) -> Option<&'a mut serde_json::Map<String, serde_json::Value>> {
    let items = match value {
        serde_json::Value::Object(object) => {
            if object
                .get("transport")
                .and_then(serde_json::Value::as_array)
                .is_some()
            {
                object
                    .get_mut("transport")
                    .and_then(serde_json::Value::as_array_mut)
            } else {
                object
                    .get_mut("transports")
                    .and_then(serde_json::Value::as_array_mut)
            }
        }
        _ => None,
    }?;
    let item = items.iter_mut().find(|item| {
        item.get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|configured| configured.eq_ignore_ascii_case(kind))
            || item.get(kind).is_some()
    })?;
    let mut candidate = item;
    for _ in 0..3 {
        let next_key = if candidate.get(kind).is_some() {
            Some(kind)
        } else if candidate.get("config").is_some() {
            Some("config")
        } else {
            None
        };
        let Some(next_key) = next_key else {
            return candidate.as_object_mut();
        };
        candidate = candidate.get_mut(next_key)?;
    }
    candidate.as_object_mut()
}

fn string_list(
    config: &serde_json::Map<String, serde_json::Value>,
    fields: &[&str],
) -> Result<Vec<String>> {
    let list = string_list_optional(config, fields)?;
    if list.is_empty() {
        return Err(Error::invalid("inbound TLS-auto servernames is empty"));
    }
    Ok(list)
}

fn string_list_optional(
    config: &serde_json::Map<String, serde_json::Value>,
    fields: &[&str],
) -> Result<Vec<String>> {
    let Some(value) = fields.iter().find_map(|field| config.get(*field)) else {
        return Ok(Vec::new());
    };
    let Some(values) = value.as_array() else {
        return Err(Error::invalid(
            "inbound TLS-auto string list must be an array",
        ));
    };
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    Error::invalid("inbound TLS-auto string list contains an invalid value")
                })
        })
        .collect()
}

fn binary_field(
    config: &serde_json::Map<String, serde_json::Value>,
    fields: &[&str],
    file_fields: &[&str],
) -> Result<Vec<u8>> {
    if let Some(value) = fields.iter().find_map(|field| config.get(*field)) {
        return binary_value(value);
    }
    if let Some(path) = file_fields.iter().find_map(|field| {
        config
            .get(*field)
            .and_then(serde_json::Value::as_str)
            .filter(|path| !path.trim().is_empty())
    }) {
        return std::fs::read(path).map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("read TLS-auto file {path:?}: {error}"),
            )
        });
    }
    Err(Error::invalid(format!(
        "inbound TLS-auto requires {}",
        fields.join(" or ")
    )))
}

fn optional_binary_field(
    config: &serde_json::Map<String, serde_json::Value>,
    fields: &[&str],
    file_fields: &[&str],
) -> Result<Option<Vec<u8>>> {
    if let Some(value) = fields.iter().find_map(|field| config.get(*field)) {
        if value.is_null() {
            return Ok(None);
        }
        return binary_value(value).map(Some);
    }
    if let Some(path) = file_fields.iter().find_map(|field| {
        config
            .get(*field)
            .and_then(serde_json::Value::as_str)
            .filter(|path| !path.trim().is_empty())
    }) {
        return std::fs::read(path).map(Some).map_err(|error| {
            Error::new(
                ErrorKind::Io,
                format!("read TLS-auto file {path:?}: {error}"),
            )
        });
    }
    Ok(None)
}

fn binary_value(value: &serde_json::Value) -> Result<Vec<u8>> {
    if let Some(values) = value.as_array() {
        return values
            .iter()
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|value| u8::try_from(value).ok())
                    .ok_or_else(|| {
                        Error::invalid("inbound TLS-auto byte array contains a non-byte")
                    })
            })
            .collect();
    }
    let Some(encoded) = value.as_str() else {
        return Err(Error::invalid("inbound TLS-auto binary value is invalid"));
    };
    if encoded.trim_start().starts_with("-----BEGIN") {
        return Ok(encoded.as_bytes().to_vec());
    }
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("inbound TLS-auto base64: {error}"),
            )
        })
}

fn first_certificate(bytes: &[u8]) -> Result<CertificateDer<'static>> {
    if bytes.starts_with(b"-----BEGIN") {
        rustls_pemfile::certs(&mut Cursor::new(bytes))
            .next()
            .ok_or_else(|| Error::invalid("inbound TLS-auto CA certificate is empty"))?
            .map_err(|error| {
                Error::new(
                    ErrorKind::Protocol,
                    format!("inbound TLS-auto CA certificate: {error}"),
                )
            })
    } else {
        Ok(CertificateDer::from(bytes.to_owned()))
    }
}

fn pkcs8_key(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.starts_with(b"-----BEGIN") {
        let key = rustls_pemfile::private_key(&mut Cursor::new(bytes))
            .map_err(|error| {
                Error::new(
                    ErrorKind::Protocol,
                    format!("inbound TLS-auto CA key: {error}"),
                )
            })?
            .ok_or_else(|| Error::invalid("inbound TLS-auto CA private key is empty"))?;
        match key {
            PrivateKeyDer::Pkcs8(key) => Ok(key.secret_pkcs8_der().to_vec()),
            _ => Err(Error::invalid(
                "inbound TLS-auto CA private key must be PKCS#8",
            )),
        }
    } else {
        Ok(bytes.to_owned())
    }
}

fn generate_ca() -> Result<(Vec<u8>, Vec<u8>)> {
    let signer = SigningKey::random(&mut OsRng);
    let subject = Name::from_str("CN=yuhaiin TLS-auto CA").map_err(|error| {
        Error::new(ErrorKind::Protocol, format!("TLS-auto CA subject: {error}"))
    })?;
    let builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u64),
        Validity::from_now(Duration::from_secs(100 * 365 * 24 * 60 * 60)).map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("TLS-auto CA validity: {error}"),
            )
        })?,
        subject,
        SubjectPublicKeyInfoOwned::from_key(PublicKey::from(signer.verifying_key())).map_err(
            |error| {
                Error::new(
                    ErrorKind::Protocol,
                    format!("TLS-auto CA public key: {error}"),
                )
            },
        )?,
        &signer,
    )
    .map_err(|error| Error::new(ErrorKind::Protocol, format!("TLS-auto CA: {error}")))?;
    let certificate = builder
        .build_with_rng::<DerSignature>(&mut OsRng)
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("TLS-auto CA signing: {error}")))?
        .to_der()
        .map_err(|error| Error::new(ErrorKind::Protocol, format!("TLS-auto CA DER: {error}")))?;
    let key = SecretKey::from(&signer).to_pkcs8_der().map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("TLS-auto CA private key: {error}"),
        )
    })?;
    Ok((certificate, key.as_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    fn test_ca() -> (Vec<u8>, Vec<u8>) {
        let signer = SigningKey::random(&mut OsRng);
        let subject = Name::from_str("CN=TLS-auto test CA").unwrap();
        let builder = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u64),
            Validity::from_now(Duration::from_secs(86400)).unwrap(),
            subject,
            SubjectPublicKeyInfoOwned::from_key(PublicKey::from(signer.verifying_key())).unwrap(),
            &signer,
        )
        .unwrap();
        let certificate = builder.build_with_rng::<DerSignature>(&mut OsRng).unwrap();
        let certificate = certificate.to_der().unwrap();
        let key = SecretKey::from(&signer).to_pkcs8_der().unwrap();
        (certificate, key.as_bytes().to_vec())
    }

    fn test_ed25519_ca() -> (Vec<u8>, Vec<u8>) {
        let signer = Ed25519CertificateSigner(Ed25519SigningKey::from_bytes(&[9u8; 32]));
        let subject = Name::from_str("CN=TLS-auto Ed25519 test CA").unwrap();
        let builder = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u64),
            Validity::from_now(Duration::from_secs(86400)).unwrap(),
            subject,
            SubjectPublicKeyInfoOwned::from_key(signer.verifying_key()).unwrap(),
            &signer,
        )
        .unwrap();
        let certificate = builder
            .build::<Ed25519CertificateSignature>()
            .unwrap()
            .to_der()
            .unwrap();
        let key = signer.0.to_pkcs8_der().unwrap();
        (certificate, key.as_bytes().to_vec())
    }

    fn test_rsa_ca() -> (Vec<u8>, Vec<u8>) {
        let signer =
            RsaSigningKey::<sha2_10::Sha256>::new(RsaPrivateKey::new(&mut OsRng, 2048).unwrap());
        let subject = Name::from_str("CN=TLS-auto RSA test CA").unwrap();
        let builder = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u64),
            Validity::from_now(Duration::from_secs(86400)).unwrap(),
            subject,
            SubjectPublicKeyInfoOwned::from_key(signer.verifying_key()).unwrap(),
            &signer,
        )
        .unwrap();
        let certificate = builder.build::<RsaSignature>().unwrap().to_der().unwrap();
        let key = RsaPrivateKey::from(signer).to_pkcs8_der().unwrap();
        (certificate, key.as_bytes().to_vec())
    }

    fn config(ca_cert: &[u8], ca_key: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "transport": [{
                "type": "tls_auto",
                "tls_auto": {
                    "ca_cert": base64::engine::general_purpose::STANDARD.encode(ca_cert),
                    "ca_key": base64::engine::general_purpose::STANDARD.encode(ca_key),
                    "servernames": ["*.example.com"],
                    "next_protos": ["http/1.1"]
                }
            }]
        })
    }

    #[test]
    fn wildcard_matches_one_label_and_normalizes_the_pattern() {
        let pattern = ServerNamePattern::new("*.Example.com".to_owned()).unwrap();
        assert!(pattern.matches("api.example.com"));
        assert!(!pattern.matches("deep.api.example.com"));
        assert_eq!(
            pattern.certificate_names(),
            ["*.example.com", "example.com"]
        );
    }

    #[test]
    fn wildcard_snis_share_the_configured_certificate_cache_key() {
        let (ca_cert, ca_key) = test_ca();
        let authority = Arc::new(TlsAutoAuthority::parse(&ca_cert, &ca_key).unwrap());
        let resolver = TlsAutoResolver::new(authority, vec!["*.example.com".to_owned()]).unwrap();
        assert_eq!(
            resolver.resolve_name("api.example.com").unwrap().0,
            resolver.resolve_name("cdn.example.com").unwrap().0
        );
    }

    #[test]
    fn binary_value_accepts_go_base64_and_json_bytes() {
        assert_eq!(
            binary_value(&serde_json::json!("aGVsbG8=")).unwrap(),
            b"hello"
        );
        assert_eq!(binary_value(&serde_json::json!([104, 105])).unwrap(), b"hi");
        assert_eq!(
            binary_value(&serde_json::json!("-----BEGIN CERTIFICATE-----")).unwrap(),
            b"-----BEGIN CERTIFICATE-----"
        );
    }

    #[test]
    fn parses_nested_go_contract_and_rejects_a_mismatched_ca_key() {
        let (ca_cert, ca_key) = test_ca();
        let value = config(&ca_cert, &ca_key);
        let acceptor = build(
            &serde_json::to_vec(&value).unwrap(),
            &["tls_auto".to_owned()],
        )
        .unwrap();
        assert!(acceptor.is_some());

        let (_, different_key) = test_ca();
        let error = match build(
            &serde_json::to_vec(&config(&ca_cert, &different_key)).unwrap(),
            &["tls_auto".to_owned()],
        ) {
            Ok(_) => panic!("a mismatched CA key must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("do not match"));
    }

    #[test]
    fn fills_missing_go_ca_fields_and_keeps_them_stable() {
        let mut value = serde_json::json!({
            "transports": [{
                "type": "tls_auto",
                "tls_auto": {
                    "serverNames": ["localhost"],
                    "nextProtos": []
                }
            }]
        });
        fill_generated_fields(&mut value).unwrap();

        let first = value.clone();
        let tls_auto = &value["transports"][0]["tls_auto"];
        assert!(tls_auto["caCertBase64"].as_str().is_some());
        assert!(tls_auto["caKeyBase64"].as_str().is_some());
        assert!(
            build(
                &serde_json::to_vec(&value).unwrap(),
                &["tls_auto".to_owned()]
            )
            .unwrap()
            .is_some()
        );

        fill_generated_fields(&mut value).unwrap();
        assert_eq!(value, first);
    }

    #[test]
    fn replaces_a_partial_go_ca_instead_of_persisting_a_half_pair() {
        let (ca_cert, _) = test_ca();
        let mut value = serde_json::json!({
            "transport": [{
                "type": "tls_auto",
                "tls_auto": {
                    "serverNames": ["localhost"],
                    "caCertBase64": base64::engine::general_purpose::STANDARD.encode(ca_cert)
                }
            }]
        });
        fill_generated_fields(&mut value).unwrap();
        let tls_auto = &value["transport"][0]["tls_auto"];
        assert!(tls_auto["caCertBase64"].as_str().is_some());
        assert!(tls_auto["caKeyBase64"].as_str().is_some());
        assert!(
            build(
                &serde_json::to_vec(&value).unwrap(),
                &["tls_auto".to_owned()]
            )
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn rejects_two_present_but_mismatched_go_ca_fields() {
        let (ca_cert, _) = test_ca();
        let (_, different_key) = test_ca();
        let mut value = serde_json::json!({
            "transport": [{
                "type": "tls_auto",
                "tls_auto": {
                    "serverNames": ["localhost"],
                    "caCertBase64": base64::engine::general_purpose::STANDARD.encode(ca_cert),
                    "caKeyBase64": base64::engine::general_purpose::STANDARD.encode(different_key)
                }
            }]
        });
        let error = fill_generated_fields(&mut value).unwrap_err();
        assert!(error.to_string().contains("parse ca failed"));
    }

    #[test]
    fn dynamically_issues_a_certificate_for_sni_and_routes_tls_bytes() {
        async fn roundtrip(ca_cert: Vec<u8>, ca_key: Vec<u8>) {
            let acceptor = build(
                &serde_json::to_vec(&config(&ca_cert, &ca_key)).unwrap(),
                &["tls_auto".to_owned()],
            )
            .unwrap()
            .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                stream.write_all(b"tls-auto-ok").await.unwrap();
            });

            let mut roots = rustls::RootCertStore::empty();
            roots.add(CertificateDer::from(ca_cert)).unwrap();
            let client = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls_rustcrypto::provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(client));
            let stream = TcpStream::connect(address).await.unwrap();
            let mut stream = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("api.example.com".to_owned()).unwrap(),
                    stream,
                )
                .await
                .unwrap();
            let mut response = [0u8; 11];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"tls-auto-ok");
            server.await.unwrap();
        }

        block_on(async {
            let (ca_cert, ca_key) = test_ca();
            roundtrip(ca_cert, ca_key).await;
        });
    }

    #[test]
    fn supports_ed25519_and_rsa_cas_generated_by_go() {
        async fn roundtrip(ca_cert: Vec<u8>, ca_key: Vec<u8>) {
            let acceptor = build(
                &serde_json::to_vec(&config(&ca_cert, &ca_key)).unwrap(),
                &["tls_auto".to_owned()],
            )
            .unwrap()
            .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(stream).await.unwrap();
                stream.write_all(b"tls-auto-ok").await.unwrap();
            });

            let mut roots = rustls::RootCertStore::empty();
            roots.add(CertificateDer::from(ca_cert)).unwrap();
            let client = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls_rustcrypto::provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(client));
            let stream = TcpStream::connect(address).await.unwrap();
            let mut stream = connector
                .connect(
                    rustls::pki_types::ServerName::try_from("api.example.com".to_owned()).unwrap(),
                    stream,
                )
                .await
                .unwrap();
            let mut response = [0u8; 11];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"tls-auto-ok");
            server.await.unwrap();
        }

        block_on(async {
            let (ed_cert, ed_key) = test_ed25519_ca();
            roundtrip(ed_cert, ed_key).await;
            let (rsa_cert, rsa_key) = test_rsa_ca();
            roundtrip(rsa_cert, rsa_key).await;
        });
    }
}
