//! AsyncProxy adapter for a constructed chain.

use super::chain_client::ChainClient;
use super::chain_uot::{ChainDatagram, ChainUotSession, RetryQueue};
use super::*;

/// Adapter from the ordered protocol chain to the common async proxy contract
/// used by the TUN flow runtime.
#[derive(Clone)]
pub struct ChainProxy {
    backend: ChainProxyBackend,
}

#[derive(Clone)]
enum ChainProxyBackend {
    H2(ChainClient),
    Protocol(Arc<dyn AsyncProxy>),
    DirectUot(DirectUotProxy),
}

impl ChainProxy {
    pub fn new(client: ChainClient) -> Self {
        Self {
            backend: ChainProxyBackend::H2(client),
        }
    }

    fn final_proxy(client: ChainClient) -> Result<Self> {
        if client.yuubinsya().is_some() {
            return Ok(Self::new(client));
        }
        if client.has_destination_protocol() {
            return Ok(Self {
                backend: ChainProxyBackend::Protocol(client.proxy.clone()),
            });
        }
        Err(Error::new(
            ErrorKind::Unsupported,
            "standalone HTTP/2 transport requires a destination protocol layer",
        ))
    }

    /// Construct the common async proxy contract from a Go node payload.
    pub fn from_go_json(json: &str) -> Result<Self> {
        Self::final_proxy(ChainClient::from_go_json(json)?)
    }

    pub fn from_go_json_with_resolver(
        json: &str,
        resolver: Arc<dyn AsyncIpResolver>,
    ) -> Result<Self> {
        if let Some(proxy) = parse_go_direct_uot(json, Arc::clone(&resolver))? {
            return Ok(Self {
                backend: ChainProxyBackend::DirectUot(proxy),
            });
        }
        Self::final_proxy(ChainClient::from_go_json_with_resolver(json, resolver)?)
    }

    pub fn from_go_json_with_resolver_and_metrics(
        json: &str,
        resolver: Arc<dyn AsyncIpResolver>,
        metrics: Arc<doradus_metrics::RuntimeMetrics>,
    ) -> Result<Self> {
        if let Some(proxy) = parse_go_direct_uot(json, Arc::clone(&resolver))? {
            return Ok(Self {
                backend: ChainProxyBackend::DirectUot(proxy),
            });
        }
        Self::final_proxy(ChainClient::from_go_json_with_resolver_and_metrics(
            json, resolver, metrics,
        )?)
    }

    pub fn from_go_json_with_resolver_and_metrics_and_dialer(
        json: &str,
        resolver: Arc<dyn AsyncIpResolver>,
        metrics: Arc<doradus_metrics::RuntimeMetrics>,
        dialer: Arc<HappyEyeballsV2Dialer>,
    ) -> Result<Self> {
        if let Some(proxy) = doradus_protocol::direct_uot::parse_go_direct_uot_with_dialer(
            json,
            Arc::clone(&resolver),
            Arc::clone(&dialer),
        )? {
            return Ok(Self {
                backend: ChainProxyBackend::DirectUot(proxy),
            });
        }
        Self::final_proxy(
            ChainClient::from_go_json_with_resolver_and_metrics_and_dialer(
                json, resolver, metrics, dialer,
            )?,
        )
    }

    /// Construct only the raw Go-compatible HTTP/2 transport from a node
    /// payload whose final protocol layer is supplied by the caller.
    ///
    /// Go builds protocol nodes by folding every chain item over the previous
    /// proxy. This entry point preserves that boundary for VLESS/VMess/Trojan:
    /// the chain crate owns fixed/TLS/WebSocket/HTTP2, while the protocol
    /// crate remains the outer framing layer.
    pub fn from_go_json_transport_with_resolver(
        json: &str,
        resolver: Arc<dyn AsyncIpResolver>,
    ) -> Result<Self> {
        Self::from_go_json_transport_with_resolver_and_metrics(
            json,
            resolver,
            Arc::new(doradus_metrics::RuntimeMetrics::new()),
        )
    }

    pub fn from_go_json_transport_with_resolver_and_metrics(
        json: &str,
        resolver: Arc<dyn AsyncIpResolver>,
        metrics: Arc<doradus_metrics::RuntimeMetrics>,
    ) -> Result<Self> {
        let client = ChainClient::from_go_json_with_resolver_and_metrics(json, resolver, metrics)?;
        if client.has_destination_protocol() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "raw HTTP/2 transport cannot contain a destination protocol",
            ));
        }
        Ok(Self::new(client))
    }

    pub fn from_go_json_transport_with_resolver_and_metrics_and_dialer(
        json: &str,
        resolver: Arc<dyn AsyncIpResolver>,
        metrics: Arc<doradus_metrics::RuntimeMetrics>,
        dialer: Arc<HappyEyeballsV2Dialer>,
    ) -> Result<Self> {
        let client = ChainClient::from_go_json_with_resolver_and_metrics_and_dialer(
            json, resolver, metrics, dialer,
        )?;
        if client.has_destination_protocol() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "raw HTTP/2 transport cannot contain a destination protocol",
            ));
        }
        Ok(Self::new(client))
    }

    pub fn client(&self) -> Option<&ChainClient> {
        match &self.backend {
            ChainProxyBackend::H2(client) => Some(client),
            ChainProxyBackend::Protocol(_) => None,
            ChainProxyBackend::DirectUot(_) => None,
        }
    }
}

impl AsyncProxy for ChainProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        match &self.backend {
            ChainProxyBackend::H2(client) => {
                let client = client.clone();
                Box::pin(async move {
                    if client.yuubinsya().is_some() {
                        let session = client
                            .connect_tcp_with_bind_and_interface(
                                context.effective_destination(),
                                &context.local_bind_addresses,
                                context.bind_interface.as_deref(),
                            )
                            .await?;
                        let local_addr = stream_local_addr(session.transport());
                        Ok(with_stream_local_addr(
                            Box::new(session) as BoxAsyncStream,
                            local_addr,
                        ))
                    } else {
                        let stream = client
                            .connect_raw_with_bind_and_interface(
                                &context.local_bind_addresses,
                                context.bind_interface.as_deref(),
                            )
                            .await?;
                        Ok(stream)
                    }
                })
            }
            ChainProxyBackend::Protocol(proxy) => proxy.connect(context),
            ChainProxyBackend::DirectUot(proxy) => proxy.connect(context),
        }
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        match &self.backend {
            ChainProxyBackend::H2(client) => {
                let client = client.clone();
                let migrate_id = Arc::clone(&context.udp_migrate_id);
                let local_bind_addresses = Arc::new(context.local_bind_addresses.clone());
                let bind_interface = context.bind_interface.clone();
                Box::pin(async move {
                    let session = client
                        .connect_uot_with_bind_and_interface(
                            migrate_id.load(Ordering::Acquire),
                            local_bind_addresses.as_slice(),
                            bind_interface.as_deref(),
                        )
                        .await?;
                    let migrate = session.migrate_id;
                    let udp_coalesce = session.udp_coalesce;
                    let local_addr = session.local_addr();
                    let (reader, writer) = session.into_split().await;
                    migrate_id.store(migrate, Ordering::Release);
                    Ok(Box::new(ChainDatagram {
                        client,
                        migrate_id,
                        session: Mutex::new(Some(ChainUotSession::new(
                            reader,
                            writer,
                            udp_coalesce,
                        ))),
                        reconnect_lock: Mutex::new(()),
                        generation: std::sync::atomic::AtomicU64::new(1),
                        closed: std::sync::atomic::AtomicBool::new(false),
                        shutdown: watch::channel(false).0,
                        next_retry_id: std::sync::atomic::AtomicU64::new(1),
                        retry: Mutex::new(RetryQueue::new()),
                        local_bind_addresses,
                        bind_interface,
                        local_addr: StdMutex::new(local_addr),
                    }) as Box<dyn AsyncDatagram>)
                })
            }
            ChainProxyBackend::Protocol(proxy) => proxy.open_datagram(context),
            ChainProxyBackend::DirectUot(proxy) => proxy.open_datagram(context),
        }
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        match &self.backend {
            ChainProxyBackend::H2(client) => {
                let client = client.clone();
                Box::pin(async move {
                    client.close().await;
                    Ok(())
                })
            }
            ChainProxyBackend::Protocol(proxy) => proxy.close(),
            ChainProxyBackend::DirectUot(proxy) => proxy.close(),
        }
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        match &self.backend {
            ChainProxyBackend::H2(client) => {
                let client = client.clone();
                let destination = context.effective_destination();
                let local_bind_addresses = context.local_bind_addresses.clone();
                let bind_interface = context.bind_interface.clone();
                Box::pin(async move {
                    client
                        .ping_with_bind_and_interface(
                            destination,
                            &local_bind_addresses,
                            bind_interface.as_deref(),
                        )
                        .await
                })
            }
            ChainProxyBackend::Protocol(proxy) => proxy.ping(context),
            ChainProxyBackend::DirectUot(proxy) => proxy.ping(context),
        }
    }
}
