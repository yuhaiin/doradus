use std::sync::Arc;
use std::time::Duration;

use yuhaiin_core::dns_resolver::{AsyncIpResolver, SystemAsyncIpResolver};
use yuhaiin_core::{Error, ErrorKind, Result};
#[cfg(not(feature = "doh-tls"))]
use yuhaiin_runtime::BuiltinResolverFactory;
use yuhaiin_runtime::{ResolverProxyBridge, RuntimeBuilder, RuntimeController};
use yuhaiin_store::ConfigStore;

pub(super) async fn build_controller(store: ConfigStore) -> Result<RuntimeController> {
    let upstream: Arc<dyn AsyncIpResolver> = Arc::new(SystemAsyncIpResolver);
    let resolver_proxy_bridge = Arc::new(ResolverProxyBridge::new());
    let mut builder = RuntimeBuilder::new(store, upstream)
        .with_resolver_proxy_bridge(resolver_proxy_bridge.clone());
    #[cfg(feature = "doh-tls")]
    {
        let config = yuhaiin_dns::webpki_client_config()
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
        builder = builder.with_resolver_factory(Arc::new(
            yuhaiin_runtime::RustCryptoResolverFactory::from_client_config_with_webpki_roots(
                config,
                Duration::from_secs(15),
                256,
            )?
            .with_proxy_bridge(resolver_proxy_bridge),
        ));
    }
    #[cfg(not(feature = "doh-tls"))]
    {
        builder = builder.with_resolver_factory(Arc::new(BuiltinResolverFactory::new(
            Duration::from_secs(5),
            256,
        )));
    }
    RuntimeController::from_builder(builder).await
}
