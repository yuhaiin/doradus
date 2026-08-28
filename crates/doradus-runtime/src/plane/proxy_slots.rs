use super::*;

/// Apply the immutable interface policy at the last common proxy boundary.
/// This keeps protocol implementations independent from runtime settings and
/// also covers chain transports whose first socket is opened outside core.
pub struct SocketPolicyProxy {
    pub(super) inner: Arc<dyn AsyncProxy>,
    pub(super) bind_addresses: Arc<[std::net::IpAddr]>,
    pub(super) bind_interface: Option<String>,
    pub(super) global_bind_interface: Option<String>,
}

impl AsyncProxy for SocketPolicyProxy {
    fn connect<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> doradus_core::BoxFuture<'a, Result<doradus_core::proxy::BoxAsyncStream>> {
        let mut context = context.clone();
        context.local_bind_addresses = self.bind_addresses.to_vec();
        context.bind_interface = self
            .bind_interface
            .clone()
            .or_else(|| self.global_bind_interface.clone());
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.connect(&context).await })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> doradus_core::BoxFuture<'a, Result<Box<dyn doradus_core::proxy::AsyncDatagram>>> {
        let mut context = context.clone();
        context.local_bind_addresses = self.bind_addresses.to_vec();
        context.bind_interface = self
            .bind_interface
            .clone()
            .or_else(|| self.global_bind_interface.clone());
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.open_datagram(&context).await })
    }

    fn ping<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> doradus_core::BoxFuture<'a, Result<Duration>> {
        let mut context = context.clone();
        context.local_bind_addresses = self.bind_addresses.to_vec();
        context.bind_interface = self
            .bind_interface
            .clone()
            .or_else(|| self.global_bind_interface.clone());
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.ping(&context).await })
    }

    fn close(&self) -> doradus_core::BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

/// Apply the Go happy-eyeballs dial budget at the runtime boundary. The
/// permit covers only connection establishment; once a flow is connected it
/// must not consume a slot for the lifetime of the relay.
pub struct ConnectBudgetProxy {
    pub(super) inner: Arc<dyn AsyncProxy>,
    pub(super) semaphore: Arc<tokio::sync::Semaphore>,
}

impl AsyncProxy for ConnectBudgetProxy {
    fn connect<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> doradus_core::BoxFuture<'a, Result<doradus_core::proxy::BoxAsyncStream>> {
        Box::pin(async move {
            let _permit =
                self.semaphore.clone().acquire_owned().await.map_err(|_| {
                    Error::new(ErrorKind::Closed, "runtime connect budget is closed")
                })?;
            self.inner.connect(context).await
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> doradus_core::BoxFuture<'a, Result<Box<dyn doradus_core::proxy::AsyncDatagram>>> {
        self.inner.open_datagram(context)
    }

    fn ping<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> doradus_core::BoxFuture<'a, Result<Duration>> {
        self.inner.ping(context)
    }

    fn close(&self) -> doradus_core::BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

pub async fn build_aead_proxy(
    config: &GoProxyRuntimeConfig,
    timeout: Duration,
    resolver: Arc<dyn doradus_core::dns_resolver::AsyncIpResolver>,
    metrics: Arc<doradus_metrics::RuntimeMetrics>,
) -> Result<Arc<dyn AsyncProxy>> {
    let base = config
        .to_base_proxy_config_with_resolver(timeout, resolver)
        .await?;
    let udp_server = match &base.kind {
        BaseProxyKind::Fixed { address } => Some(*address),
        _ => None,
    };
    #[cfg(feature = "doh-tls")]
    let mut upstream: Arc<dyn AsyncProxy> = base.build_with_metrics(metrics)?;
    #[cfg(not(feature = "doh-tls"))]
    let upstream: Arc<dyn AsyncProxy> = base.build()?;
    if config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("tls"))
    {
        #[cfg(feature = "doh-tls")]
        {
            upstream = build_protocol_tls_proxy(config, upstream)?;
        }
        #[cfg(not(feature = "doh-tls"))]
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "AEAD TLS transport requires the doh-tls feature",
            ));
        }
    }
    let layer = config
        .layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case("aead"))
        .ok_or_else(|| Error::invalid("AEAD transport layer is missing"))?;
    let password = layer
        .config
        .get("password")
        .and_then(serde_json::Value::as_str)
        .filter(|password| !password.is_empty())
        .ok_or_else(|| Error::invalid("AEAD password is empty"))?;
    let method = layer
        .config
        .get("cryptoMethod")
        .or_else(|| layer.config.get("crypto_method"))
        .and_then(serde_json::Value::as_str)
        .map(doradus_protocol::aead::CryptoMethod::parse)
        .unwrap_or(doradus_protocol::aead::CryptoMethod::Chacha20Poly1305);
    Ok(Arc::new(doradus_protocol::aead::AeadProxy::new(
        upstream, password, method, udp_server,
    )))
}
