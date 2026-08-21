//! Ready-to-use direct resolver registry for the encrypted transports.
//!
//! The individual DoH and DoT factories remain public for deployments that
//! need a custom registry.  This composite is the normal application path:
//! one persisted resolver list can contain System/UDP/TCP, DoH and DoT
//! entries without changing the `ResolverTransportFactory` boundary.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use yuhaiin_core::dns_resolver::AsyncIpResolver;
use yuhaiin_core::proxy::AsyncDatagram;
use yuhaiin_core::{Endpoint, Error, ErrorKind, Network, Result};
use yuhaiin_dns::{AsyncDnsDatagram, DnsDatagramConnector, DoqResolverConfig, DoqResolverFactory};
use yuhaiin_store::{GoResolverRuntimeConfig, GoResolverTransport};

use crate::{
    BuiltinResolverFactory, ResolverProxyBridge, ResolverTransportFactory,
    RustlsDohResolverFactory, RustlsDotResolverFactory,
};

struct ResolverBridgeDatagramConnector {
    bridge: Arc<ResolverProxyBridge>,
}

impl DnsDatagramConnector for ResolverBridgeDatagramConnector {
    fn open<'a>(
        &'a self,
        resolver_id: &'a str,
        host: &'a str,
        target: std::net::SocketAddr,
        _local_bind_addresses: &'a [IpAddr],
        _bind_interface: Option<&'a str>,
    ) -> yuhaiin_core::BoxFuture<'a, Result<Option<Box<dyn AsyncDnsDatagram>>>> {
        Box::pin(async move {
            let Some(route_mode) = self.bridge.route_mode_for_resolver(resolver_id) else {
                return Ok(None);
            };
            let datagram = match route_mode {
                yuhaiin_core::RouteMode::Direct => {
                    self.bridge
                        .open_datagram_direct(host, target.port())
                        .await?
                }
                yuhaiin_core::RouteMode::Proxy => self
                    .bridge
                    .open_datagram(host, target.port(), true)
                    .await?
                    .ok_or_else(|| Error::invalid("DoQ proxy UDP transport was not opened"))?,
                yuhaiin_core::RouteMode::Bypass | yuhaiin_core::RouteMode::Block => {
                    return Err(Error::invalid("unsupported DoQ resolver route mode"));
                }
            };
            Ok(Some(
                Box::new(RuntimeDnsDatagram { inner: datagram }) as Box<dyn AsyncDnsDatagram>
            ))
        })
    }
}

struct RuntimeDnsDatagram {
    inner: Box<dyn AsyncDatagram>,
}

impl AsyncDnsDatagram for RuntimeDnsDatagram {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: std::net::SocketAddr,
    ) -> yuhaiin_core::BoxFuture<'a, Result<usize>> {
        let endpoint = Endpoint::ip(Network::Udp, target);
        self.inner.send_to(payload, endpoint)
    }

    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> yuhaiin_core::BoxFuture<'a, Result<(usize, std::net::SocketAddr)>> {
        Box::pin(async move {
            let (length, endpoint) = self.inner.recv_from(buffer).await?;
            let address = endpoint
                .addr()
                .ok_or_else(|| Error::invalid("DNS datagram has no socket address"))?;
            Ok((length, address))
        })
    }

    fn local_addr(&self) -> Result<std::net::SocketAddr> {
        self.inner
            .local_addr()?
            .addr()
            .ok_or_else(|| Error::invalid("DNS datagram has no local socket address"))
    }

    fn close(&self) -> yuhaiin_core::BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

#[derive(Clone)]
pub struct RuntimeResolverRegistry {
    pub builtin: BuiltinResolverFactory,
    doh: RustlsDohResolverFactory,
    dot: RustlsDotResolverFactory,
    doq: DoqResolverFactory,
}

impl RuntimeResolverRegistry {
    pub fn new(
        root_certificates: &[Vec<u8>],
        timeout: Duration,
        cache_capacity: usize,
    ) -> Result<Self> {
        let doh = RustlsDohResolverFactory::new(root_certificates, timeout, cache_capacity)?;
        let dot = RustlsDotResolverFactory::new(root_certificates, timeout, cache_capacity)?;
        let doq = DoqResolverFactory::new(root_certificates, timeout, cache_capacity)?;
        Ok(Self {
            builtin: BuiltinResolverFactory::new(timeout, cache_capacity),
            doh,
            dot,
            doq,
        })
    }

    pub fn from_client_config(
        client_config: Arc<ClientConfig>,
        timeout: Duration,
        cache_capacity: usize,
    ) -> Self {
        Self::from_client_config_with_doq_config(
            client_config.clone(),
            client_config,
            timeout,
            cache_capacity,
        )
    }

    pub fn from_client_config_with_doq_config(
        client_config: Arc<ClientConfig>,
        doq_client_config: Arc<ClientConfig>,
        timeout: Duration,
        cache_capacity: usize,
    ) -> Self {
        Self {
            builtin: BuiltinResolverFactory::new(timeout, cache_capacity),
            doh: RustlsDohResolverFactory::from_client_config(
                client_config.clone(),
                timeout,
                cache_capacity,
            ),
            dot: RustlsDotResolverFactory::from_client_config(
                client_config.clone(),
                timeout,
                cache_capacity,
            ),
            doq: DoqResolverFactory::from_client_config(doq_client_config, timeout, cache_capacity),
        }
    }

    pub fn from_client_config_with_webpki_roots(
        client_config: Arc<ClientConfig>,
        timeout: Duration,
        cache_capacity: usize,
    ) -> Result<Self> {
        let doq = DoqResolverFactory::from_webpki_roots(timeout, cache_capacity)?;
        Ok(Self {
            builtin: BuiltinResolverFactory::new(timeout, cache_capacity),
            doh: RustlsDohResolverFactory::from_client_config(
                client_config.clone(),
                timeout,
                cache_capacity,
            ),
            dot: RustlsDotResolverFactory::from_client_config(
                client_config,
                timeout,
                cache_capacity,
            ),
            doq,
        })
    }

    pub fn with_proxy_bridge(mut self, bridge: Arc<ResolverProxyBridge>) -> Self {
        self.builtin = self.builtin.with_proxy_bridge(bridge.clone());
        self.doh = self.doh.with_proxy_bridge(bridge.clone());
        self.dot = self.dot.with_proxy_bridge(bridge.clone());
        self.doq = self
            .doq
            .with_datagram_connector(Arc::new(ResolverBridgeDatagramConnector { bridge }));
        self
    }
}

impl ResolverTransportFactory for RuntimeResolverRegistry {
    fn build(&self, config: &GoResolverRuntimeConfig) -> Result<Arc<dyn AsyncIpResolver>> {
        self.build_with_policy(config, &[])
    }

    fn build_with_policy(
        &self,
        config: &GoResolverRuntimeConfig,
        local_bind_addresses: &[IpAddr],
    ) -> Result<Arc<dyn AsyncIpResolver>> {
        self.build_with_policy_and_interface(config, local_bind_addresses, None)
    }

    fn build_with_policy_and_interface(
        &self,
        config: &GoResolverRuntimeConfig,
        local_bind_addresses: &[IpAddr],
        bind_interface: Option<&str>,
    ) -> Result<Arc<dyn AsyncIpResolver>> {
        match config.transport {
            GoResolverTransport::Doh => self.doh.build_with_policy_and_interface(
                config,
                local_bind_addresses,
                bind_interface,
            ),
            GoResolverTransport::Dot => self.dot.build_with_policy_and_interface(
                config,
                local_bind_addresses,
                bind_interface,
            ),
            GoResolverTransport::Doq => {
                let resolver = self.doq.build(DoqResolverConfig {
                    id: config.id.clone(),
                    host: config.host.clone(),
                    server_name: config.tls_server_name.clone(),
                    local_bind_addresses: local_bind_addresses.to_vec(),
                    bind_interface: bind_interface.map(str::to_owned),
                })?;
                Ok(Arc::new(crate::TimeoutResolver::new(
                    resolver,
                    self.doq.timeout(),
                )))
            }
            GoResolverTransport::Doh3 => Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "resolver {} transport {:?} is not implemented by the runtime resolver registry",
                    config.id, config.transport
                ),
            )),
            GoResolverTransport::System | GoResolverTransport::Udp | GoResolverTransport::Tcp => {
                self.builtin.build_with_policy_and_interface(
                    config,
                    local_bind_addresses,
                    bind_interface,
                )
            }
        }
    }
}
