use super::*;

pub fn integration_dir(name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os("DORADUS_INTEGRATION_DIR") {
        return PathBuf::from(path).join(name);
    }
    let cache = std::env::var_os("DORADUS_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".cache"));
    cache
        .join("doradus")
        .join("integration")
        .join(name)
        .join(std::process::id().to_string())
}

pub async fn reserve_loopback() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

pub async fn connect_loopback(address: SocketAddr) -> TcpStream {
    for _ in 0..120 {
        match TcpStream::connect(address).await {
            Ok(stream) => return stream,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("loopback listener {address} did not become ready");
}

/// Connect to a runtime TLS inbound using the fixture certificate. The
/// certificate is intentionally not trusted by the host; the verifier keeps
/// TLS handshake signature validation enabled while skipping only chain and
/// hostname validation, matching the outbound `insecure_skip_verify` test
/// semantics without introducing a system CA dependency.
pub async fn connect_tls_loopback(address: SocketAddr) -> TlsStream<TcpStream> {
    connect_tls_loopback_with_alpn(address, &[]).await
}

/// Connect to an inbound TLS listener without sending SNI. Rustls omits the
/// `server_name` extension for an IP literal, which exercises the same
/// default-certificate path as clients that do not provide SNI at all.
pub async fn connect_tls_loopback_without_sni(address: SocketAddr) -> TlsStream<TcpStream> {
    connect_tls_loopback_with_server_name(address, ServerName::try_from("127.0.0.1").unwrap(), &[])
        .await
}

/// Connect to an inbound TLS listener while advertising the given ALPN
/// protocols. HTTP/2 inbound tests must negotiate `h2`; ordinary TLS/HTTP
/// tests intentionally keep the list empty and exercise HTTP/1.1 fallback.
pub async fn connect_tls_h2_loopback(address: SocketAddr) -> TlsStream<TcpStream> {
    connect_tls_loopback_with_alpn(address, &[b"h2"]).await
}

async fn connect_tls_loopback_with_alpn(
    address: SocketAddr,
    alpn_protocols: &[&[u8]],
) -> TlsStream<TcpStream> {
    connect_tls_loopback_with_server_name(
        address,
        ServerName::try_from("localhost").unwrap(),
        alpn_protocols,
    )
    .await
}

async fn connect_tls_loopback_with_server_name(
    address: SocketAddr,
    server_name: ServerName<'static>,
    alpn_protocols: &[&[u8]],
) -> TlsStream<TcpStream> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new(provider))
        .with_no_client_auth();
    config.alpn_protocols = alpn_protocols.iter().map(|value| value.to_vec()).collect();
    let connector = TlsConnector::from(Arc::new(config));
    connector
        .connect(server_name.to_owned(), connect_loopback(address).await)
        .await
        .unwrap()
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
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
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
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
