//! Ordered chain transport wrappers and TLS verification helpers.

use super::*;
#[derive(Clone)]
pub(super) struct FixedChainProxy {
    config: ValidatedFixedConfig,
    resolver: Arc<dyn AsyncIpResolver>,
    upstream: Option<Arc<dyn AsyncProxy>>,
    dialer: Arc<HappyEyeballsV2Dialer>,
}

impl FixedChainProxy {
    pub(super) fn new(
        config: ValidatedFixedConfig,
        resolver: Arc<dyn AsyncIpResolver>,
        upstream: Option<Arc<dyn AsyncProxy>>,
        dialer: Arc<HappyEyeballsV2Dialer>,
    ) -> Self {
        Self {
            config,
            resolver,
            upstream,
            dialer,
        }
    }

    async fn resolve_addresses(&self) -> Result<Vec<(SocketAddr, Option<String>)>> {
        let mut addresses = Vec::new();
        for endpoint in &self.config.addresses {
            if let Some(address) = endpoint.socket_addr() {
                addresses.push((address, endpoint.network_interface.clone()));
                continue;
            }
            let domain = endpoint
                .domain()
                .ok_or_else(|| Error::invalid("fixedv2 endpoint has an invalid domain"))?;
            let resolved = self
                .resolver
                .resolve(&domain, ResolveStrategy::Default)
                .await?;
            addresses.extend(resolved.iter().map(|address| {
                (
                    SocketAddr::new(address, endpoint.port),
                    endpoint.network_interface.clone(),
                )
            }));
        }
        if addresses.is_empty() {
            return Err(Error::invalid("fixedv2 has no resolved upstream address"));
        }
        Ok(addresses)
    }
}

impl AsyncProxy for FixedChainProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let addresses = self.resolve_addresses().await?;
            let candidates = addresses
                .iter()
                .map(|(address, endpoint_interface)| {
                    TcpDialCandidate::new(
                        *address,
                        endpoint_interface
                            .clone()
                            .or_else(|| context.bind_interface.clone()),
                    )
                })
                .collect::<Vec<_>>();
            let (address, endpoint_interface) = addresses
                .first()
                .cloned()
                .ok_or_else(|| Error::invalid("fixedv2 connection has no endpoints"))?;
            let mut candidate_context = context.clone();
            candidate_context.network = Network::Tcp;
            candidate_context.destination = Endpoint::ip(Network::Tcp, address);
            candidate_context.resolved_destination = Some(
                candidates
                    .iter()
                    .map(|candidate| candidate.address)
                    .collect(),
            );
            candidate_context.original_domain = None;
            candidate_context.bind_interface =
                endpoint_interface.or_else(|| context.bind_interface.clone());
            if let Some(upstream) = &self.upstream {
                upstream.connect(&candidate_context).await
            } else {
                let stream = self
                    .dialer
                    .dial_candidates(
                        candidates,
                        &context.local_bind_addresses,
                        Duration::from_secs(15),
                    )
                    .await?;
                let local_addr = stream.local_addr().ok();
                let remote_addr = stream.peer_addr().ok();
                Ok(doradus_core::stream_metadata::with_stream_socket_addrs(
                    Box::new(stream) as BoxAsyncStream,
                    local_addr,
                    remote_addr,
                ))
            }
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            let addresses = self.resolve_addresses().await?;
            let (address, endpoint_interface) = addresses
                .into_iter()
                .next()
                .ok_or_else(|| Error::invalid("fixedv2 has no resolved upstream address"))?;
            let mut candidate_context = context.clone();
            candidate_context.destination = Endpoint::ip(Network::Udp, address);
            candidate_context.resolved_destination = None;
            candidate_context.original_domain = None;
            candidate_context.bind_interface =
                endpoint_interface.or_else(|| context.bind_interface.clone());
            if let Some(upstream) = &self.upstream {
                upstream.open_datagram(&candidate_context).await
            } else {
                FixedAsyncProxy {
                    address,
                    timeout: Duration::from_secs(15),
                }
                .open_datagram(&candidate_context)
                .await
            }
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        Box::pin(async move {
            let started = Instant::now();
            let mut stream = self.connect(context).await?;
            stream.shutdown().await.map_err(io_error)?;
            Ok(started.elapsed())
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        if let Some(upstream) = &self.upstream {
            upstream.close()
        } else {
            Box::pin(async { Ok(()) })
        }
    }
}

#[derive(Clone)]
pub(super) struct TlsChainProxy {
    upstream: Arc<dyn AsyncProxy>,
    connector: TlsConnector,
    config: ValidatedTls,
}

impl TlsChainProxy {
    pub(super) fn new(upstream: Arc<dyn AsyncProxy>, config: ValidatedTls) -> Result<Self> {
        let roots = if config.insecure_skip_verify {
            RootCertStore::empty()
        } else {
            root_store(&config.ca_certificates)?
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client = if config.insecure_skip_verify {
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
                .with_root_certificates(roots)
                .with_no_client_auth()
        };
        client.alpn_protocols = config
            .next_protos
            .iter()
            .map(|protocol| protocol.as_bytes().to_vec())
            .collect();
        Ok(Self {
            upstream,
            connector: TlsConnector::from(Arc::new(client)),
            config,
        })
    }
}

impl AsyncProxy for TlsChainProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            let stream = self.upstream.connect(context).await?;
            let local_addr = stream_local_addr(&*stream);
            let server_name = rustls::pki_types::ServerName::try_from(self.config.server_name())
                .map_err(|_| Error::invalid("TLS server name is invalid"))?;
            let stream = self
                .connector
                .connect(server_name, stream)
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
                "TLS transport does not expose a datagram socket",
            ))
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        Box::pin(async move {
            let started = Instant::now();
            let mut stream = self.connect(context).await?;
            stream.shutdown().await.map_err(io_error)?;
            Ok(started.elapsed())
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.upstream.close()
    }
}

#[derive(Clone)]
pub(super) struct H2ChainProxy {
    upstream: Arc<dyn AsyncProxy>,
    pub(super) pool: Arc<H2Pool>,
    concurrency: usize,
    max_streams: usize,
    identity: String,
}

impl H2ChainProxy {
    pub(super) fn new(
        upstream: Arc<dyn AsyncProxy>,
        config: ValidatedHttp2,
        index: usize,
        metrics: Arc<doradus_metrics::RuntimeMetrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            upstream,
            pool: Arc::new(H2Pool::with_limits_and_metrics(
                4,
                config.idle_timeout,
                metrics,
            )),
            concurrency: config.concurrency,
            max_streams: config.max_streams,
            identity: format!("chain-http2-layer-{index}"),
        })
    }

    pub(super) fn stats(&self) -> H2PoolStats {
        self.pool.stats()
    }

    async fn open_stream(&self, context: &FlowContext) -> Result<BoxAsyncStream> {
        let mut parent_context = context.clone();
        parent_context.network = Network::Tcp;
        parent_context.destination = Endpoint::ip(Network::Tcp, TRANSPORT_ENDPOINT);
        parent_context.resolved_destination = None;
        parent_context.original_domain = None;
        let upstream = Arc::clone(&self.upstream);
        let max_streams = self.max_streams;
        let endpoints = [H2PoolEndpoint {
            address: TRANSPORT_ENDPOINT,
            bind_interface: None,
        }];
        let (stream, local_addr) = self
            .pool
            .open_with_endpoints_and_local_addr(
                &endpoints,
                &self.identity,
                self.concurrency,
                move |_| {
                    let upstream = Arc::clone(&upstream);
                    let context = parent_context.clone();
                    async move {
                        let stream = upstream.connect(&context).await?;
                        let local_addr = stream_local_addr(&*stream);
                        H2Connection::handshake_with_limits_and_local_addr(
                            stream,
                            max_streams,
                            local_addr,
                        )
                        .await
                    }
                },
            )
            .await?;
        Ok(with_stream_local_addr(
            Box::new(stream) as BoxAsyncStream,
            local_addr,
        ))
    }
}

impl AsyncProxy for H2ChainProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move { self.open_stream(context).await })
    }

    fn open_datagram<'a>(
        &'a self,
        _context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "HTTP/2 transport does not expose a datagram socket",
            ))
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        Box::pin(async move {
            let started = Instant::now();
            let mut stream = self.connect(context).await?;
            stream.shutdown().await.map_err(io_error)?;
            Ok(started.elapsed())
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        let pool = Arc::clone(&self.pool);
        let upstream = Arc::clone(&self.upstream);
        Box::pin(async move {
            pool.close().await;
            upstream.close().await
        })
    }
}

pub(super) fn root_store(certificates: &[Vec<u8>]) -> Result<RootCertStore> {
    // Go starts from the platform system pool and appends node-specific
    // certificates.  The pure-Rust equivalent uses the Mozilla WebPKI set;
    // private or enterprise roots can still be appended through ca_cert.
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for certificate in certificates {
        let mut cursor = std::io::Cursor::new(certificate);
        let mut parsed = false;
        for certificate in rustls_pemfile::certs(&mut cursor) {
            let certificate = certificate.map_err(tls_error)?;
            roots.add(certificate).map_err(tls_error)?;
            parsed = true;
        }
        if !parsed {
            roots
                .add(rustls::pki_types::CertificateDer::from(certificate.clone()))
                .map_err(tls_error)?;
        }
    }
    Ok(roots)
}

/// Go's `InsecureSkipVerify` skips certificate-chain and hostname validation,
/// but the TLS handshake still needs to verify the server's ephemeral
/// signature.  Keep that signature check enabled so this option does not
/// disable the cryptographic part of TLS itself.
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

fn tls_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Protocol, format!("TLS: {error}"))
}
