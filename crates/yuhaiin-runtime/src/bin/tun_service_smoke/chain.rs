use super::*;

pub(super) const YUUBINSYA_PASSWORD: &str = "runtime-tun-smoke-yuubinsya";
const LEAF_CERTIFICATE_PEM: &[u8] = br#"-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUA6T+/U88N9aMPipK+MdNsAFRUAUwCgYIKoZIzj0EAwIw
GDEWMBQGA1UEAwwNeXVoYWlpbi1wMC1jYTAeFw0yNjA4MDYxODIwNDlaFw0zNjA4
MDMxODIwNDlaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABLPnwlYFERi1MgbJNuBHZV/eSpTGdJCQIOyxBt8LlR1ZTEG06pWy
FnJVIzUS4oPuuHc0RcDEltGb/WolyQlM75SjbTBrMBQGA1UdEQQNMAuCCWxvY2Fs
aG9zdDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUZoMmXETR998IsWt1
UTBOVMIs7jMwHwYDVR0jBBgwFoAUhaYkOXheQ1JzLpIKK4I2FEcRMyMwCgYIKoZI
zj0EAwIDSAAwRQIgGEU+sldusbLVAE/kxzZYXaMpIt6l+CZ0cC2jm7lQBqoCIQCw
M5PhuwMhCCb+dUnK6ueJUMHwyK3l2pIAJTMp9+cwqw==
-----END CERTIFICATE-----
"#;
const PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFqkH6SeIb9vVEJ6WecsMk5Pn/a8sQ+vdNS/ZSkl3KwfoAoGCCqGSM49
AwEHoUQDQgAEs+fCVgURGLUyBsk24EdlX95KlMZ0kJAg7LEG3wuVHVlMQbTqlbIW
clUjNRLig+64dzRFwMSW0Zv9aiXJCUzvlA==
-----END EC PRIVATE KEY-----
"#;

pub(super) struct ChainFixture {
    pub(super) target: SocketAddr,
    pub(super) outbound: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server_task: tokio::task::JoinHandle<()>,
    target_task: tokio::task::JoinHandle<Result<usize>>,
}

impl ChainFixture {
    pub(super) async fn start() -> Result<Self> {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.map_err(io_error)?;
        let target = target_listener.local_addr().map_err(io_error)?;
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target_listener.accept().await.map_err(io_error)?;
            let mut buffer = vec![0u8; 16 * 1024];
            let mut received = 0usize;
            loop {
                let length = stream.read(&mut buffer).await.map_err(io_error)?;
                if length == 0 {
                    break;
                }
                stream
                    .write_all(&buffer[..length])
                    .await
                    .map_err(io_error)?;
                received = received.saturating_add(length);
            }
            Ok(received)
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(io_error)?;
        let outbound = listener.local_addr().map_err(io_error)?;
        let upstream: Arc<dyn AsyncProxy> = Arc::new(FixedTargetProxy {
            direct: DirectAsyncProxy {
                timeout: Duration::from_secs(3),
            },
            tcp_target: target,
            udp_target: target,
        });
        let proxy = Arc::new(YuubinsyaServerProxy::new(
            yuhaiin_protocol::yuubinsya::derive_salt(YUUBINSYA_PASSWORD.as_bytes()),
            upstream,
        ));
        let tls_config = chain_server_config()?;
        let tls_acceptor = TlsAcceptor::from(Arc::clone(&tls_config));
        let server = Arc::new(YuubinsyaH2Server::new(tls_config, proxy)?);
        let (shutdown, receiver) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            tokio::select! {
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            let stream = match tls_acceptor.accept(stream).await {
                                Ok(stream) => stream,
                                Err(_) => return,
                            };
                            let _ = server.serve_h2(stream).await;
                        }
                        Err(error) => eprintln!("runtime-tun-chain-listener: {error}"),
                    }
                }
                _ = receiver => {}
            }
        });
        Ok(Self {
            target,
            outbound,
            shutdown: Some(shutdown),
            server_task,
            target_task,
        })
    }

    pub(super) async fn shutdown(mut self) -> Result<usize> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.server_task.await;
        self.target_task.await.map_err(join_error)?
    }

    pub(super) fn abort(self) {
        self.server_task.abort();
        self.target_task.abort();
    }
}

fn chain_server_config() -> Result<Arc<rustls::ServerConfig>> {
    let certificate = rustls_pemfile::certs(&mut Cursor::new(LEAF_CERTIFICATE_PEM))
        .next()
        .ok_or_else(|| Error::invalid("TUN chain fixture certificate is empty"))?
        .map_err(|error| Error::invalid(format!("TUN chain fixture certificate: {error}")))?;
    let key = rustls_pemfile::private_key(&mut Cursor::new(PRIVATE_KEY_PEM))
        .map_err(|error| Error::invalid(format!("TUN chain fixture key: {error}")))?
        .ok_or_else(|| Error::invalid("TUN chain fixture key is empty"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error.to_string()))?
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(
                certificate.to_vec(),
            )],
            key,
        )
        .map_err(|error| Error::invalid(format!("TUN chain fixture TLS config: {error}")))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}

struct FixedTargetProxy {
    direct: DirectAsyncProxy,
    tcp_target: SocketAddr,
    udp_target: SocketAddr,
}

impl FixedTargetProxy {
    fn mapped_context(&self, context: &FlowContext) -> FlowContext {
        let mut mapped = context.clone();
        let target = if context.network == Network::Udp {
            self.udp_target
        } else {
            self.tcp_target
        };
        mapped.resolved_destination = Some(Endpoint::ip(context.network, target));
        mapped
    }
}

struct FixedTargetDatagram {
    inner: Box<dyn AsyncDatagram>,
    target: SocketAddr,
}

impl AsyncDatagram for FixedTargetDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], _target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        let target = Endpoint::ip(Network::Udp, self.target);
        Box::pin(async move { self.inner.send_to(payload, target).await })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        self.inner.recv_from(buffer)
    }

    fn local_addr(&self) -> Result<Endpoint> {
        self.inner.local_addr()
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

impl AsyncProxy for FixedTargetProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let mapped = self.mapped_context(context);
        Box::pin(async move { self.direct.connect(&mapped).await })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let mapped = self.mapped_context(context);
        let target = self.udp_target;
        Box::pin(async move {
            let datagram = self.direct.open_datagram(&mapped).await?;
            Ok(Box::new(FixedTargetDatagram {
                inner: datagram,
                target,
            }) as Box<dyn AsyncDatagram>)
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        let mapped = self.mapped_context(context);
        Box::pin(async move { self.direct.ping(&mapped).await })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        self.direct.close()
    }
}
