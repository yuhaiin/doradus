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

pub(super) async fn build_aead_proxy(
    config: &GoProxyRuntimeConfig,
    plan: &AeadPlan,
    protocol_tls: Option<&ProtocolTlsPlan>,
    timeout: Duration,
    resolver: Arc<dyn doradus_core::dns_resolver::AsyncIpResolver>,
    metrics: Arc<doradus_metrics::RuntimeMetrics>,
    dialer: Arc<doradus_core::network::HappyEyeballsV2Dialer>,
) -> Result<Arc<dyn AsyncProxy>> {
    let base = protocol_base_proxy_config(
        config
            .to_base_proxy_config_with_resolver(timeout, resolver)
            .await?,
    )?;
    let udp_server = match &base.kind {
        BaseProxyKind::Fixed { address } => Some(*address),
        _ => None,
    };
    let mut upstream: Arc<dyn AsyncProxy> =
        if let Some(endpoints) = super::fixed_tcp_candidates(&base.kind) {
            Arc::new(super::HappyEyeballsFixedProxy::new(
                endpoints, dialer, timeout,
            )?)
        } else {
            #[cfg(feature = "doh-tls")]
            {
                base.build_with_metrics(metrics)?
            }
            #[cfg(not(feature = "doh-tls"))]
            {
                base.build()?
            }
        };
    if let Some(tls) = protocol_tls {
        #[cfg(feature = "doh-tls")]
        {
            upstream = build_protocol_tls_proxy(tls, upstream)?;
        }
        #[cfg(not(feature = "doh-tls"))]
        {
            return Err(Error::new(
                ErrorKind::Unsupported,
                "AEAD TLS transport requires the doh-tls feature",
            ));
        }
    }
    let method = doradus_protocol::aead::CryptoMethod::parse(&plan.method);
    Ok(Arc::new(doradus_protocol::aead::AeadProxy::new(
        upstream,
        &plan.password,
        method,
        udp_server,
    )))
}
