//! Ready-to-use direct resolver registry for the encrypted transports.
//!
//! The individual DoH and DoT factories remain public for deployments that
//! need a custom registry.  This composite is the normal application path:
//! one persisted resolver list can contain System/UDP/TCP, DoH and DoT
//! entries without changing the `ResolverTransportFactory` boundary.

use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use yuhaiin_core::dns_resolver_async::AsyncIpResolver;
use yuhaiin_core::{Error, ErrorKind, Result};
use yuhaiin_store::{GoResolverRuntimeConfig, GoResolverTransport};

use crate::{
    BuiltinResolverFactory, ResolverTransportFactory, RustCryptoDohResolverFactory,
    RustCryptoDotResolverFactory,
};

#[derive(Clone)]
pub struct RustCryptoResolverFactory {
    pub builtin: BuiltinResolverFactory,
    doh: RustCryptoDohResolverFactory,
    dot: RustCryptoDotResolverFactory,
}

impl RustCryptoResolverFactory {
    pub fn new(
        root_certificates: &[Vec<u8>],
        timeout: Duration,
        cache_capacity: usize,
    ) -> Result<Self> {
        let doh = RustCryptoDohResolverFactory::new(root_certificates, timeout, cache_capacity)?;
        let dot = RustCryptoDotResolverFactory::new(root_certificates, timeout, cache_capacity)?;
        Ok(Self {
            builtin: BuiltinResolverFactory::new(timeout, cache_capacity),
            doh,
            dot,
        })
    }

    pub fn from_client_config(
        client_config: Arc<ClientConfig>,
        timeout: Duration,
        cache_capacity: usize,
    ) -> Self {
        Self {
            builtin: BuiltinResolverFactory::new(timeout, cache_capacity),
            doh: RustCryptoDohResolverFactory::from_client_config(
                client_config.clone(),
                timeout,
                cache_capacity,
            ),
            dot: RustCryptoDotResolverFactory::from_client_config(
                client_config,
                timeout,
                cache_capacity,
            ),
        }
    }
}

impl ResolverTransportFactory for RustCryptoResolverFactory {
    fn build(&self, config: &GoResolverRuntimeConfig) -> Result<Arc<dyn AsyncIpResolver>> {
        match config.transport {
            GoResolverTransport::Doh => self.doh.build(config),
            GoResolverTransport::Dot => self.dot.build(config),
            GoResolverTransport::Doq | GoResolverTransport::Doh3 => Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "resolver {} transport {:?} is not implemented by the RustCrypto registry",
                    config.id, config.transport
                ),
            )),
            GoResolverTransport::System | GoResolverTransport::Udp | GoResolverTransport::Tcp => {
                self.builtin.build(config)
            }
        }
    }
}
