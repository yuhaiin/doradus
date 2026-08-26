//! TLS auto certificate/resolver tests.

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
            rustls::crypto::ring::default_provider(),
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
            rustls::crypto::ring::default_provider(),
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
