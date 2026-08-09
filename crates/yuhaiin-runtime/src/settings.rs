//! Runtime application of the persisted Go-compatible settings object.
//!
//! The management API stores settings as JSON for wire compatibility.  Keeping
//! the normalized form in the immutable runtime snapshot makes a reload the
//! single publication point for DNS, TUN and future socket policies.

use std::sync::Arc;

use serde_json::Value;
use yuhaiin_core::dns_resolver_async::AsyncIpResolver;
use yuhaiin_core::{BoxFuture, DomainName, IpSet, ResolveStrategy, Result};
use yuhaiin_store::ConfigStore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSettings {
    pub ipv6: bool,
    pub use_default_interface: bool,
    pub net_interface: String,
    pub pprof: bool,
    pub udp_buffer_size: usize,
    pub relay_buffer_size: usize,
    pub udp_ringbuffer_size: usize,
    pub happy_eyeballs_semaphore: usize,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            ipv6: false,
            use_default_interface: true,
            net_interface: String::new(),
            // Go historically enables pprof unless a persisted setting turns
            // it off; keep that startup default for imported installations.
            pprof: true,
            udp_buffer_size: 2048,
            relay_buffer_size: 4096,
            udp_ringbuffer_size: 250,
            happy_eyeballs_semaphore: 250,
        }
    }
}

impl RuntimeSettings {
    pub async fn load(store: &ConfigStore) -> Result<Self> {
        let Some(bytes) = store.get_config("settings").await? else {
            return Ok(Self::default());
        };
        let value = serde_json::from_slice::<Value>(&bytes).map_err(|error| {
            yuhaiin_core::Error::invalid(format!("settings is invalid JSON: {error}"))
        })?;
        Ok(Self::from_value(&value))
    }

    pub fn from_value(value: &Value) -> Self {
        let defaults = Self::default();
        let advanced = value.get("advanced").unwrap_or(&Value::Null);
        Self {
            ipv6: value
                .get("ipv6")
                .and_then(Value::as_bool)
                .unwrap_or(defaults.ipv6),
            use_default_interface: value
                .get("useDefaultInterface")
                .or_else(|| value.get("use_default_interface"))
                .and_then(Value::as_bool)
                .unwrap_or(defaults.use_default_interface),
            net_interface: value
                .get("netInterface")
                .or_else(|| value.get("net_interface"))
                .and_then(Value::as_str)
                .unwrap_or(&defaults.net_interface)
                .to_owned(),
            pprof: value
                .get("pprof")
                .and_then(Value::as_bool)
                .unwrap_or(defaults.pprof),
            udp_buffer_size: bounded_or_default(
                advanced.get("udpBufferSize"),
                defaults.udp_buffer_size,
                2049,
                65534,
            ),
            relay_buffer_size: bounded_or_default(
                advanced.get("relayBufferSize"),
                defaults.relay_buffer_size,
                2049,
                65534,
            ),
            udp_ringbuffer_size: bounded_or_default(
                advanced.get("udpRingbufferSize"),
                defaults.udp_ringbuffer_size,
                100,
                5000,
            ),
            happy_eyeballs_semaphore: bounded_or_default(
                advanced.get("happyEyeballsSemaphore"),
                defaults.happy_eyeballs_semaphore,
                1,
                usize::MAX,
            ),
        }
    }
}

fn bounded_or_default(value: Option<&Value>, default: usize, min: usize, max: usize) -> usize {
    value
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| (*value >= min) && (*value <= max))
        .unwrap_or(default)
}

/// Apply Go's global IPv6 switch after all hosts/FakeIP policy has run.
/// Keeping this wrapper at the outermost resolver boundary also covers
/// resolver IDs selected by route rules and the shared system resolver.
pub struct Ipv6PolicyResolver {
    upstream: Arc<dyn AsyncIpResolver>,
    enabled: bool,
}

impl Ipv6PolicyResolver {
    pub fn new(upstream: Arc<dyn AsyncIpResolver>, enabled: bool) -> Self {
        Self { upstream, enabled }
    }
}

impl AsyncIpResolver for Ipv6PolicyResolver {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        Box::pin(async move {
            let mut result = self.upstream.resolve(domain, strategy).await?;
            if !self.enabled {
                result.v6.clear();
            }
            Ok(result)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use yuhaiin_core::dns_resolver_async::AsyncIpResolver;

    struct StaticResolver;

    impl AsyncIpResolver for StaticResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<IpSet>> {
            Box::pin(async {
                Ok(IpSet {
                    v4: vec![Ipv4Addr::new(192, 0, 2, 1)],
                    v6: vec![Ipv6Addr::LOCALHOST],
                })
            })
        }
    }

    #[test]
    fn settings_accept_legacy_snake_case_and_keep_go_bounds() {
        let settings = RuntimeSettings::from_value(&serde_json::json!({
            "ipv6": true,
            "use_default_interface": false,
            "net_interface": "eth0",
            "advanced": {
                "udpBufferSize": 4096,
                "relayBufferSize": 2048,
                "udpRingbufferSize": 5001,
                "happyEyeballsSemaphore": 32
            }
        }));
        assert!(settings.ipv6);
        assert!(!settings.use_default_interface);
        assert_eq!(settings.net_interface, "eth0");
        assert_eq!(settings.udp_buffer_size, 4096);
        assert_eq!(settings.relay_buffer_size, 4096);
        assert_eq!(settings.udp_ringbuffer_size, 250);
        assert_eq!(settings.happy_eyeballs_semaphore, 32);
    }

    #[test]
    fn ipv6_policy_removes_v6_without_changing_v4() {
        let resolver = Ipv6PolicyResolver::new(Arc::new(StaticResolver), false);
        let result = futures_block_on(resolver.resolve(
            &DomainName::new("example.test").unwrap(),
            ResolveStrategy::Default,
        ))
        .unwrap();
        assert_eq!(result.v4, vec![Ipv4Addr::new(192, 0, 2, 1)]);
        assert!(result.v6.is_empty());
    }

    fn futures_block_on<F: std::future::Future>(future: F) -> F::Output {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(future)
    }
}
