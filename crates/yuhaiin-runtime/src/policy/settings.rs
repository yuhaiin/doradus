//! Runtime application of the persisted Go-compatible settings object.
//!
//! The management API stores settings as JSON for wire compatibility.  Keeping
//! the normalized form in the immutable runtime snapshot makes a reload the
//! single publication point for DNS, TUN and future socket policies.

use std::sync::Arc;

use serde_json::Value;
use yuhaiin_core::dns::{DnsRecordType, DnsResponse, DnsServiceParam};
use yuhaiin_core::dns_resolver::AsyncIpResolver;
use yuhaiin_core::{BoxFuture, DomainName, IpSet, ResolveStrategy, Result};
use yuhaiin_store::{ConfigStore, GoSettingsKvRecord};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSettings {
    pub ipv6: bool,
    pub use_default_interface: bool,
    pub net_interface: String,
    pub pprof: bool,
    pub system_proxy_http: bool,
    pub system_proxy_socks5: bool,
    pub logcat_level: String,
    pub logcat_save: bool,
    pub ignore_timeout_error: bool,
    pub ignore_dns_error: bool,
    pub udp_buffer_size: usize,
    pub relay_buffer_size: usize,
    pub udp_ringbuffer_size: usize,
    pub happy_eyeballs_semaphore: usize,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            // Keep the zero-configuration baseline aligned with Go's
            // DefaultSetting. Persisted values still override each field.
            ipv6: true,
            use_default_interface: true,
            net_interface: String::new(),
            // Go historically enables pprof unless a persisted setting turns
            // it off; keep that startup default for imported installations.
            pprof: true,
            system_proxy_http: true,
            system_proxy_socks5: false,
            logcat_level: "debug".to_owned(),
            logcat_save: true,
            ignore_timeout_error: false,
            ignore_dns_error: false,
            udp_buffer_size: 2048,
            relay_buffer_size: 4096,
            udp_ringbuffer_size: 250,
            happy_eyeballs_semaphore: 250,
        }
    }
}

impl RuntimeSettings {
    pub async fn load(store: &ConfigStore) -> Result<Self> {
        if let Some(bytes) = store.get_config("settings").await? {
            let value = serde_json::from_slice::<Value>(&bytes).map_err(|error| {
                yuhaiin_core::Error::invalid(format!("settings is invalid JSON: {error}"))
            })?;
            return Ok(Self::from_value(&value));
        }
        let values = store.repository().list_go_settings_kv().await?;
        Ok(Self::from_go_settings_kv(&values))
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
            system_proxy_http: value
                .pointer("/systemProxy/http")
                .and_then(Value::as_bool)
                .unwrap_or(defaults.system_proxy_http),
            system_proxy_socks5: value
                .pointer("/systemProxy/socks5")
                .and_then(Value::as_bool)
                .unwrap_or(defaults.system_proxy_socks5),
            logcat_level: value
                .pointer("/logcat/level")
                .and_then(Value::as_str)
                .unwrap_or(&defaults.logcat_level)
                .to_owned(),
            logcat_save: value
                .pointer("/logcat/save")
                .and_then(Value::as_bool)
                .unwrap_or(defaults.logcat_save),
            ignore_timeout_error: value
                .pointer("/logcat/ignoreTimeoutError")
                .and_then(Value::as_bool)
                .unwrap_or(defaults.ignore_timeout_error),
            ignore_dns_error: value
                .pointer("/logcat/ignoreDnsError")
                .and_then(Value::as_bool)
                .unwrap_or(defaults.ignore_dns_error),
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

    pub fn from_go_settings_kv(values: &[GoSettingsKvRecord]) -> Self {
        let mut settings = Self::default();
        for record in values {
            let Ok(value) = serde_json::from_str::<Value>(&record.value_json) else {
                continue;
            };
            match (record.section.as_str(), record.key.as_str()) {
                ("general", "ipv6") => {
                    if let Some(value) = scalar_bool(&value) {
                        settings.ipv6 = value;
                    }
                }
                ("general", "use_default_interface") => {
                    if let Some(value) = scalar_bool(&value) {
                        settings.use_default_interface = value;
                    }
                }
                ("general", "net_interface") => {
                    if let Some(value) = value.as_str() {
                        settings.net_interface = value.to_owned();
                    }
                }
                ("general", "pprof") => {
                    if let Some(value) = scalar_bool(&value) {
                        settings.pprof = value;
                    }
                }
                ("system_proxy", "http") => {
                    if let Some(value) = scalar_bool(&value) {
                        settings.system_proxy_http = value;
                    }
                }
                ("system_proxy", "socks5") => {
                    if let Some(value) = scalar_bool(&value) {
                        settings.system_proxy_socks5 = value;
                    }
                }
                ("logcat", "save") => {
                    if let Some(value) = scalar_bool(&value) {
                        settings.logcat_save = value;
                    }
                }
                ("logcat", "ignore_timeout_error") => {
                    if let Some(value) = scalar_bool(&value) {
                        settings.ignore_timeout_error = value;
                    }
                }
                ("logcat", "ignore_dns_error") => {
                    if let Some(value) = scalar_bool(&value) {
                        settings.ignore_dns_error = value;
                    }
                }
                ("logcat", "level") => {
                    settings.logcat_level = log_level_from_json(&value, &settings.logcat_level);
                }
                ("advanced", "udp_buffer_size") => {
                    settings.udp_buffer_size =
                        bounded_from_json(&value, settings.udp_buffer_size, 2049, 65534);
                }
                ("advanced", "relay_buffer_size") => {
                    settings.relay_buffer_size =
                        bounded_from_json(&value, settings.relay_buffer_size, 2049, 65534);
                }
                ("advanced", "udp_ringbuffer_size") => {
                    settings.udp_ringbuffer_size =
                        bounded_from_json(&value, settings.udp_ringbuffer_size, 100, 5000);
                }
                ("advanced", "happyeyeballs_semaphore") => {
                    settings.happy_eyeballs_semaphore =
                        bounded_from_json(&value, settings.happy_eyeballs_semaphore, 1, usize::MAX);
                }
                _ => {}
            }
        }
        settings
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "ipv6": self.ipv6,
            "useDefaultInterface": self.use_default_interface,
            "netInterface": self.net_interface,
            "pprof": self.pprof,
            "systemProxy": {
                "http": self.system_proxy_http,
                "socks5": self.system_proxy_socks5,
            },
            "logcat": {
                "level": self.logcat_level,
                "save": self.logcat_save,
                "ignoreTimeoutError": self.ignore_timeout_error,
                "ignoreDnsError": self.ignore_dns_error,
            },
            "advanced": {
                "udpBufferSize": self.udp_buffer_size,
                "relayBufferSize": self.relay_buffer_size,
                "udpRingbufferSize": self.udp_ringbuffer_size,
                "happyEyeballsSemaphore": self.happy_eyeballs_semaphore,
            },
        })
    }

    pub fn to_go_settings_kv(&self) -> Vec<GoSettingsKvRecord> {
        let bool_json = |value: bool| if value { "true" } else { "false" }.to_owned();
        vec![
            GoSettingsKvRecord {
                section: "general".to_owned(),
                key: "ipv6".to_owned(),
                value_json: bool_json(self.ipv6),
            },
            GoSettingsKvRecord {
                section: "general".to_owned(),
                key: "use_default_interface".to_owned(),
                value_json: bool_json(self.use_default_interface),
            },
            GoSettingsKvRecord {
                section: "general".to_owned(),
                key: "net_interface".to_owned(),
                value_json: serde_json::to_string(&self.net_interface)
                    .unwrap_or_else(|_| "\"\"".to_owned()),
            },
            GoSettingsKvRecord {
                section: "general".to_owned(),
                key: "pprof".to_owned(),
                value_json: bool_json(self.pprof),
            },
            GoSettingsKvRecord {
                section: "system_proxy".to_owned(),
                key: "http".to_owned(),
                value_json: bool_json(self.system_proxy_http),
            },
            GoSettingsKvRecord {
                section: "system_proxy".to_owned(),
                key: "socks5".to_owned(),
                value_json: bool_json(self.system_proxy_socks5),
            },
            GoSettingsKvRecord {
                section: "logcat".to_owned(),
                key: "level".to_owned(),
                value_json: log_level_code(&self.logcat_level).to_string(),
            },
            GoSettingsKvRecord {
                section: "logcat".to_owned(),
                key: "save".to_owned(),
                value_json: bool_json(self.logcat_save),
            },
            GoSettingsKvRecord {
                section: "logcat".to_owned(),
                key: "ignore_dns_error".to_owned(),
                value_json: bool_json(self.ignore_dns_error),
            },
            GoSettingsKvRecord {
                section: "logcat".to_owned(),
                key: "ignore_timeout_error".to_owned(),
                value_json: bool_json(self.ignore_timeout_error),
            },
            scalar_kv("udp_buffer_size", self.udp_buffer_size),
            scalar_kv("relay_buffer_size", self.relay_buffer_size),
            scalar_kv("udp_ringbuffer_size", self.udp_ringbuffer_size),
            scalar_kv("happyeyeballs_semaphore", self.happy_eyeballs_semaphore),
        ]
    }
}

fn scalar_kv(key: &str, value: usize) -> GoSettingsKvRecord {
    GoSettingsKvRecord {
        section: "advanced".to_owned(),
        key: key.to_owned(),
        value_json: value.to_string(),
    }
}

fn bounded_or_default(value: Option<&Value>, default: usize, min: usize, max: usize) -> usize {
    value
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| (*value >= min) && (*value <= max))
        .unwrap_or(default)
}

fn scalar_bool(value: &Value) -> Option<bool> {
    value
        .as_bool()
        .or_else(|| {
            value.as_i64().and_then(|value| match value {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            })
        })
        .or_else(
            || match value.as_str()?.trim().to_ascii_lowercase().as_str() {
                "true" | "1" => Some(true),
                "false" | "0" | "" => Some(false),
                _ => None,
            },
        )
}

fn bounded_from_json(value: &Value, default: usize, min: usize, max: usize) -> usize {
    let number = value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
        .or_else(|| value.as_str()?.trim().parse::<u64>().ok())
        .and_then(|value| usize::try_from(value).ok());
    number
        .filter(|value| (*value >= min) && (*value <= max))
        .unwrap_or(default)
}

fn log_level_from_json(value: &Value, default: &str) -> String {
    if let Some(value) = value.as_str() {
        return value.to_owned();
    }
    match value.as_i64() {
        Some(0) => "verbose".to_owned(),
        Some(1) => "debug".to_owned(),
        Some(2) => "info".to_owned(),
        Some(3) => "warn".to_owned(),
        Some(4) => "error".to_owned(),
        Some(5) => "fatal".to_owned(),
        _ => default.to_owned(),
    }
}

fn log_level_code(value: &str) -> i64 {
    match value.trim().to_ascii_lowercase().as_str() {
        "verbose" => 0,
        "debug" => 1,
        "info" => 2,
        "warning" | "warn" => 3,
        "error" => 4,
        "fatal" => 5,
        _ => 2,
    }
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

    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            let mut response = self.upstream.query(domain, record_type).await?;
            if !self.enabled {
                response.addresses.v6.clear();
                for binding in &mut response.service_bindings {
                    binding
                        .params
                        .retain(|param| !matches!(param, DnsServiceParam::Ipv6Hint(_)));
                }
            }
            Ok(response)
        })
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        // IPv6 policy can safely transform the typed address model, but raw
        // DNS records must keep their original wire representation.
        self.upstream.query_packet(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use yuhaiin_core::dns_resolver::AsyncIpResolver;

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
    fn empty_settings_match_go_default_setting_baseline() {
        let settings = RuntimeSettings::default();
        assert!(settings.ipv6);
        assert!(settings.use_default_interface);
        assert!(settings.system_proxy_http);
        assert!(!settings.system_proxy_socks5);
        assert_eq!(settings.logcat_level, "debug");
        assert!(settings.logcat_save);
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
        assert_eq!(settings.logcat_level, "debug");
        assert_eq!(settings.udp_buffer_size, 4096);
        assert_eq!(settings.relay_buffer_size, 4096);
        assert_eq!(settings.udp_ringbuffer_size, 250);
        assert_eq!(settings.happy_eyeballs_semaphore, 32);
    }

    #[test]
    fn settings_load_from_go_settings_kv_rows_when_json_overlay_is_absent() {
        let settings = RuntimeSettings::from_go_settings_kv(&[
            GoSettingsKvRecord {
                section: "general".to_owned(),
                key: "ipv6".to_owned(),
                value_json: "1".to_owned(),
            },
            GoSettingsKvRecord {
                section: "general".to_owned(),
                key: "use_default_interface".to_owned(),
                value_json: "false".to_owned(),
            },
            GoSettingsKvRecord {
                section: "advanced".to_owned(),
                key: "relay_buffer_size".to_owned(),
                value_json: "8192".to_owned(),
            },
            GoSettingsKvRecord {
                section: "logcat".to_owned(),
                key: "level".to_owned(),
                value_json: "3".to_owned(),
            },
        ]);
        assert!(settings.ipv6);
        assert!(!settings.use_default_interface);
        assert_eq!(settings.relay_buffer_size, 8192);
        assert_eq!(settings.logcat_level, "warn");
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
