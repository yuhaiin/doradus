//! Proxy construction from the shared runtime snapshot.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use yuhaiin_chain::ChainProxy;
use yuhaiin_core::proxy::{AsyncProxy, AsyncProxySelector};
use yuhaiin_core::proxy_factory::{BaseProxyConfig, BaseProxyKind};
use yuhaiin_core::{Error, ErrorKind, FlowContext, Result};
use yuhaiin_store::GoProxyRuntimeConfig;
use yuhaiin_trie::router::RuntimeRoutedProxySelector;

use crate::RuntimeSnapshot;

#[path = "proxy/common.rs"]
pub(crate) mod common;
#[path = "proxy/http.rs"]
pub(crate) mod http;
#[path = "proxy/socks4a.rs"]
pub(crate) mod socks4a;
#[path = "proxy/socks5.rs"]
pub(crate) mod socks5;
#[path = "proxy/trojan.rs"]
pub(crate) mod trojan;
#[path = "proxy/vless.rs"]
pub(crate) mod vless;
#[cfg(feature = "websocket")]
#[path = "proxy/websocket.rs"]
pub(crate) mod websocket;
#[path = "proxy/yuubinsya.rs"]
pub(crate) mod yuubinsya;

/// The selected runtime proxy plus its persisted public configuration.
/// Keeping both together makes future HTTP handlers able to expose stable
/// metadata without reconstructing or serializing protocol internals.
pub struct ProxyBuild {
    pub config: GoProxyRuntimeConfig,
    pub proxy: Arc<dyn AsyncProxy>,
}

impl RuntimeSnapshot {
    pub async fn build_proxy(&self, id: &str, timeout: Duration) -> Result<ProxyBuild> {
        let config = self.require_proxy_config(id)?.clone();
        if !config.enabled {
            return Err(Error::new(
                ErrorKind::Closed,
                format!("proxy runtime config {id:?} is disabled"),
            ));
        }

        let proxy = if is_vless_websocket_config(&config) {
            build_vless_transport_proxy(&config, timeout, self.resolver.clone()).await?
        } else if is_vmess_transport_config(&config) {
            build_vmess_transport_proxy(&config, timeout, self.resolver.clone()).await?
        } else if is_chain_config(&config) {
            let json = std::str::from_utf8(&config.data_json).map_err(|error| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("proxy {id:?} data_json is not UTF-8: {error}"),
                )
            })?;
            Arc::new(ChainProxy::from_go_json_with_resolver(
                json,
                self.resolver.clone(),
            )?) as Arc<dyn AsyncProxy>
        } else if matches!(
            config.transport,
            yuhaiin_store::GoProxyTransport::Shadowsocks
                | yuhaiin_store::GoProxyTransport::Trojan
                | yuhaiin_store::GoProxyTransport::Vless
                | yuhaiin_store::GoProxyTransport::Vmess
        ) {
            let base = config
                .to_base_proxy_config_with_resolver(timeout, self.resolver.clone())
                .await?;
            let mut upstream = base.build()?;
            if config
                .chain_types
                .iter()
                .any(|kind| kind.eq_ignore_ascii_case("tls"))
            {
                #[cfg(feature = "doh-tls")]
                {
                    upstream = build_protocol_tls_proxy(&config, upstream)?;
                }
                #[cfg(not(feature = "doh-tls"))]
                {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "protocol TLS requires the doh-tls feature",
                    ));
                }
            }
            let layer = config
                .layers
                .iter()
                .find(|layer| {
                    layer.kind.eq_ignore_ascii_case(match config.transport {
                        yuhaiin_store::GoProxyTransport::Shadowsocks => "shadowsocks",
                        yuhaiin_store::GoProxyTransport::Trojan => "trojan",
                        yuhaiin_store::GoProxyTransport::Vless => "vless",
                        yuhaiin_store::GoProxyTransport::Vmess => "vmess",
                        _ => unreachable!(),
                    })
                })
                .ok_or_else(|| Error::invalid("proxy protocol layer is missing"))?;
            match config.transport {
                yuhaiin_store::GoProxyTransport::Shadowsocks => {
                    let password = layer
                        .config
                        .get("password")
                        .and_then(serde_json::Value::as_str)
                        .filter(|password| !password.is_empty())
                        .ok_or_else(|| Error::invalid("proxy protocol password is empty"))?;
                    let method = layer
                        .config
                        .get("method")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| Error::invalid("Shadowsocks method is missing"))?;
                    Arc::new(yuhaiin_protocol::shadowsocks::ShadowsocksProxy::new(
                        upstream, method, password,
                    )?) as Arc<dyn AsyncProxy>
                }
                yuhaiin_store::GoProxyTransport::Trojan => {
                    let password = layer
                        .config
                        .get("password")
                        .and_then(serde_json::Value::as_str)
                        .filter(|password| !password.is_empty())
                        .ok_or_else(|| Error::invalid("proxy protocol password is empty"))?;
                    Arc::new(yuhaiin_protocol::trojan::TrojanProxy::new(
                        upstream, password,
                    )) as Arc<dyn AsyncProxy>
                }
                yuhaiin_store::GoProxyTransport::Vless => {
                    let uuid = layer
                        .config
                        .get("uuid")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| Error::invalid("VLESS UUID is missing"))?;
                    Arc::new(yuhaiin_protocol::vless::VlessProxy::new(upstream, uuid)?)
                        as Arc<dyn AsyncProxy>
                }
                yuhaiin_store::GoProxyTransport::Vmess => {
                    let uuid = layer
                        .config
                        .get("id")
                        .or_else(|| layer.config.get("uuid"))
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| Error::invalid("VMess UUID is missing"))?;
                    let security = layer
                        .config
                        .get("security")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("auto");
                    let alter_id = vmess_alter_id(&layer.config)?;
                    Arc::new(yuhaiin_protocol::vmess::VmessProxy::new(
                        upstream, uuid, security, alter_id,
                    )?) as Arc<dyn AsyncProxy>
                }
                _ => unreachable!("protocol branch validated above"),
            }
        } else {
            let base = config
                .to_base_proxy_config_with_resolver(timeout, self.resolver.clone())
                .await?;
            base.build()?
        };

        Ok(ProxyBuild { config, proxy })
    }

    /// Build the four proxy slots consumed by the TUN dispatcher.
    ///
    /// The persisted records are reused directly; the method only assembles
    /// the already existing proxy implementations into the routing adapter.
    /// Empty direct/bypass/drop IDs use safe built-ins. An empty proxy ID is
    /// an error because silently falling back to direct would leak traffic.
    pub async fn build_proxy_selector(
        &self,
        direct_id: &str,
        proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: Duration,
    ) -> Result<RuntimeProxySelector> {
        RuntimeProxySelector::from_snapshot(self, direct_id, proxy_id, bypass_id, drop_id, timeout)
            .await
    }

    async fn build_routed_proxy_selector(
        &self,
        direct_id: &str,
        proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: Duration,
    ) -> Result<RuntimeRoutedProxySelector> {
        let direct = self
            .build_proxy_slot(direct_id, timeout, BaseProxyKind::Direct)
            .await?;
        let proxy = self.build_proxy(proxy_id, timeout).await?.proxy;
        let bypass = self
            .build_proxy_slot(bypass_id, timeout, BaseProxyKind::Direct)
            .await?;
        let drop = self
            .build_proxy_slot(drop_id, timeout, BaseProxyKind::Drop)
            .await?;

        Ok(RuntimeRoutedProxySelector {
            router: self.router.clone(),
            direct,
            proxy,
            bypass,
            drop,
        })
    }

    async fn build_proxy_slot(
        &self,
        id: &str,
        timeout: Duration,
        fallback: BaseProxyKind,
    ) -> Result<Arc<dyn AsyncProxy>> {
        if id.trim().is_empty() {
            return BaseProxyConfig {
                kind: fallback,
                timeout,
            }
            .build();
        }
        Ok(self.build_proxy(id, timeout).await?.proxy)
    }
}

/// A TUN-facing selector whose proxy slots can be replaced as one unit after
/// a successful configuration reload. Existing flows keep the `Arc` returned
/// by the old slot; new flows observe the new snapshot after `replace`.
pub struct RuntimeProxySelector {
    current: RwLock<RuntimeRoutedProxySelector>,
    direct_id: String,
    proxy_id: String,
    bypass_id: String,
    drop_id: String,
    timeout: Duration,
}

impl RuntimeProxySelector {
    async fn from_snapshot(
        snapshot: &RuntimeSnapshot,
        direct_id: &str,
        proxy_id: &str,
        bypass_id: &str,
        drop_id: &str,
        timeout: Duration,
    ) -> Result<Self> {
        let current = snapshot
            .build_routed_proxy_selector(direct_id, proxy_id, bypass_id, drop_id, timeout)
            .await?;
        Ok(Self {
            current: RwLock::new(current),
            direct_id: direct_id.to_owned(),
            proxy_id: proxy_id.to_owned(),
            bypass_id: bypass_id.to_owned(),
            drop_id: drop_id.to_owned(),
            timeout,
        })
    }

    pub(crate) async fn prepare(
        &self,
        snapshot: &RuntimeSnapshot,
    ) -> Result<RuntimeRoutedProxySelector> {
        snapshot
            .build_routed_proxy_selector(
                &self.direct_id,
                &self.proxy_id,
                &self.bypass_id,
                &self.drop_id,
                self.timeout,
            )
            .await
    }

    pub(crate) fn replace(&self, next: RuntimeRoutedProxySelector) {
        let mut current = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = next;
    }
}

impl AsyncProxySelector for RuntimeProxySelector {
    fn select(&self, context: &FlowContext) -> Arc<dyn AsyncProxy> {
        let current = self
            .current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        current.select(context)
    }
}

fn is_chain_config(config: &GoProxyRuntimeConfig) -> bool {
    if config
        .chain_types
        .iter()
        .any(|kind| matches!(kind.to_ascii_lowercase().as_str(), "http2" | "websocket"))
    {
        return true;
    }
    if config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("tls"))
        && !matches!(
            config.transport,
            yuhaiin_store::GoProxyTransport::Trojan
                | yuhaiin_store::GoProxyTransport::Shadowsocks
                | yuhaiin_store::GoProxyTransport::Vless
                | yuhaiin_store::GoProxyTransport::Vmess
        )
    {
        return true;
    }
    config.chain_types.iter().any(|kind| {
        kind.eq_ignore_ascii_case("yuubinsya")
            && config
                .layers
                .iter()
                .find(|layer| layer.kind.eq_ignore_ascii_case("yuubinsya"))
                .and_then(|layer| layer.config.get("udp_over_stream"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
    })
}

fn is_vless_websocket_config(config: &GoProxyRuntimeConfig) -> bool {
    let has_websocket = config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("websocket"));
    let has_vless = config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("vless"));
    config.transport == yuhaiin_store::GoProxyTransport::Vless
        && has_websocket
        && has_vless
        && config.chain_types.iter().all(|kind| {
            matches!(
                kind.to_ascii_lowercase().as_str(),
                "fixed" | "fixedv2" | "tls" | "websocket" | "vless"
            )
        })
}

fn is_vmess_transport_config(config: &GoProxyRuntimeConfig) -> bool {
    let has_vmess = config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("vmess"));
    let has_transport = config
        .chain_types
        .iter()
        .any(|kind| matches!(kind.to_ascii_lowercase().as_str(), "tls" | "websocket"));
    config.transport == yuhaiin_store::GoProxyTransport::Vmess
        && has_vmess
        && has_transport
        && config.chain_types.iter().all(|kind| {
            matches!(
                kind.to_ascii_lowercase().as_str(),
                "fixed" | "fixedv2" | "tls" | "websocket" | "vmess"
            )
        })
}

async fn build_vless_transport_proxy(
    config: &GoProxyRuntimeConfig,
    timeout: Duration,
    resolver: Arc<dyn yuhaiin_core::dns_resolver_async::AsyncIpResolver>,
) -> Result<Arc<dyn AsyncProxy>> {
    let base = config
        .to_base_proxy_config_with_resolver(timeout, resolver)
        .await?;
    let mut upstream: Arc<dyn AsyncProxy> = base.build()?;
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
                "VLESS TLS transport requires the doh-tls feature",
            ));
        }
    }
    if config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("websocket"))
    {
        upstream = build_protocol_websocket_proxy(config, upstream)?;
    }
    let layer = config
        .layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case("vless"))
        .ok_or_else(|| Error::invalid("VLESS protocol layer is missing"))?;
    let uuid = layer
        .config
        .get("uuid")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::invalid("VLESS UUID is missing"))?;
    Ok(Arc::new(yuhaiin_protocol::vless::VlessProxy::new(
        upstream, uuid,
    )?))
}

async fn build_vmess_transport_proxy(
    config: &GoProxyRuntimeConfig,
    timeout: Duration,
    resolver: Arc<dyn yuhaiin_core::dns_resolver_async::AsyncIpResolver>,
) -> Result<Arc<dyn AsyncProxy>> {
    let base = config
        .to_base_proxy_config_with_resolver(timeout, resolver)
        .await?;
    let mut upstream: Arc<dyn AsyncProxy> = base.build()?;
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
                "VMess TLS transport requires the doh-tls feature",
            ));
        }
    }
    if config
        .chain_types
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("websocket"))
    {
        upstream = build_protocol_websocket_proxy(config, upstream)?;
    }
    let layer = config
        .layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case("vmess"))
        .ok_or_else(|| Error::invalid("VMess protocol layer is missing"))?;
    let uuid = layer
        .config
        .get("id")
        .or_else(|| layer.config.get("uuid"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::invalid("VMess UUID is missing"))?;
    let security = layer
        .config
        .get("security")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("auto");
    let alter_id = vmess_alter_id(&layer.config)?;
    Ok(Arc::new(yuhaiin_protocol::vmess::VmessProxy::new(
        upstream, uuid, security, alter_id,
    )?))
}

fn vmess_alter_id(config: &serde_json::Value) -> Result<u32> {
    let Some(value) = config.get("aid").or_else(|| config.get("alter_id")) else {
        return Ok(0);
    };
    if let Some(number) = value.as_u64() {
        return u32::try_from(number).map_err(|_| Error::invalid("VMess alter_id is out of range"));
    }
    value
        .as_str()
        .ok_or_else(|| Error::invalid("VMess alter_id must be a string or integer"))?
        .parse::<u32>()
        .map_err(|error| Error::invalid(format!("VMess alter_id is invalid: {error}")))
}

#[cfg(feature = "websocket")]
fn build_protocol_websocket_proxy(
    config: &GoProxyRuntimeConfig,
    upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    let layer = config
        .layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case("websocket"))
        .ok_or_else(|| Error::invalid("WebSocket transport layer is missing"))?;
    let host = layer
        .config
        .get("host")
        .or_else(|| layer.config.get("hostname"))
        .and_then(serde_json::Value::as_str)
        .filter(|host| !host.is_empty())
        .ok_or_else(|| Error::invalid("WebSocket transport host is missing"))?;
    let path = layer
        .config
        .get("path")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("/");
    Ok(Arc::new(yuhaiin_protocol::websocket::WebSocketProxy::new(
        upstream, host, path,
    )?))
}

#[cfg(not(feature = "websocket"))]
fn build_protocol_websocket_proxy(
    _config: &GoProxyRuntimeConfig,
    _upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "VLESS WebSocket transport requires the websocket feature",
    ))
}

#[cfg(feature = "doh-tls")]
fn build_protocol_tls_proxy(
    config: &GoProxyRuntimeConfig,
    upstream: Arc<dyn AsyncProxy>,
) -> Result<Arc<dyn AsyncProxy>> {
    use base64::Engine;
    use rustls::RootCertStore;
    use rustls::pki_types::CertificateDer;

    let layer = config
        .layers
        .iter()
        .find(|layer| layer.kind.eq_ignore_ascii_case("tls"))
        .ok_or_else(|| Error::invalid("protocol TLS layer is missing"))?;
    let server_name = layer
        .config
        .get("servernames")
        .or_else(|| layer.config.get("serverNames"))
        .and_then(serde_json::Value::as_array)
        .and_then(|values| values.iter().find_map(serde_json::Value::as_str))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::invalid("protocol TLS layer requires servernames"))?;
    let mut roots = RootCertStore::empty();
    if let Some(certificates) = layer
        .config
        .get("ca_cert")
        .or_else(|| layer.config.get("caCert"))
        .and_then(serde_json::Value::as_array)
    {
        for certificate in certificates {
            let encoded = certificate
                .as_str()
                .ok_or_else(|| Error::invalid("Trojan TLS ca_cert must contain strings"))?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|error| {
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("protocol TLS ca_cert: {error}"),
                    )
                })?;
            roots.add(CertificateDer::from(bytes)).map_err(|error| {
                Error::new(ErrorKind::Protocol, format!("protocol TLS CA: {error}"))
            })?;
        }
    }
    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let next_protocols = layer
        .config
        .get("next_protos")
        .or_else(|| layer.config.get("nextProtos"))
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(Arc::new(yuhaiin_protocol::tls::RustCryptoTlsProxy::new(
        upstream,
        roots,
        server_name,
        &next_protocols,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeSnapshot;
    use std::sync::Arc;
    use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
    use yuhaiin_core::proxy::FixedAsyncProxy;
    use yuhaiin_core::proxy::{AsyncProxySelector, YuubinsyaUdpServer};
    use yuhaiin_core::proxy_factory::{BaseProxyConfig, BaseProxyKind};
    use yuhaiin_core::{FlowContext, RouteMode};
    use yuhaiin_protocol::trojan::{self, Command};
    use yuhaiin_store::GoProxyLayer;
    use yuhaiin_store::GoProxyTransport;
    use yuhaiin_trie::router::{RouteDecision, Router, RouterRuntime};

    fn snapshot(config: GoProxyRuntimeConfig) -> RuntimeSnapshot {
        RuntimeSnapshot {
            resolver: Arc::new(SystemAsyncIpResolver),
            hosts: yuhaiin_core::dns_hosts::HostsTable::new(),
            fakeip: None,
            resolvers: Vec::new(),
            route: None,
            route_rules: Vec::new(),
            route_lists: crate::RouteListSnapshot::default(),
            router: RouterRuntime::new(
                Router::compile(
                    Vec::new(),
                    RouteDecision {
                        mode: yuhaiin_core::RouteMode::Direct,
                        resolver_policy: yuhaiin_core::ResolverPolicy::default(),
                        priority: 0,
                    },
                )
                .unwrap(),
            ),
            resolver_by_id: std::collections::BTreeMap::new(),
            resolver_errors: std::collections::BTreeMap::new(),
            resolver_registry_enabled: false,
            geo_metadata: Vec::new(),
            geo: None,
            proxies: vec![config],
            nat: yuhaiin_store::NatConfigRecord::default(),
        }
    }

    #[test]
    fn base_proxy_build_uses_shared_snapshot_config_without_a_dto() {
        let config = GoProxyRuntimeConfig {
            id: "direct".to_owned(),
            name: "Direct".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let built =
            block_on(snapshot(config).build_proxy("direct", Duration::from_secs(1))).unwrap();
        assert_eq!(built.config.id, "direct");
        let _ = BaseProxyConfig {
            kind: BaseProxyKind::Direct,
            timeout: Duration::from_secs(1),
        };
    }

    #[test]
    fn proxy_selector_assembles_snapshot_proxies_and_safe_builtin_slots() {
        let config = GoProxyRuntimeConfig {
            id: "proxy".to_owned(),
            name: "Proxy".to_owned(),
            group_name: String::new(),
            origin: "test".to_owned(),
            enabled: true,
            chain_types: vec!["direct".to_owned()],
            layers: Vec::new(),
            transport: GoProxyTransport::Direct,
            data_json: br#"{"protocol":"direct"}"#.to_vec(),
        };
        let selector = block_on(snapshot(config).build_proxy_selector(
            "",
            "proxy",
            "",
            "",
            Duration::from_secs(1),
        ))
        .unwrap();

        let mut context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        context.route_mode = RouteMode::Proxy;
        context.skip_route = true;
        let selected = selector.select(&context);
        context.route_mode = RouteMode::Direct;
        let direct = selector.select(&context);
        assert!(!Arc::ptr_eq(&selected, &direct));
    }

    #[tokio::test]
    async fn trojan_outbound_wraps_fixed_parent_and_preserves_connect_payload() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let hash = trojan::password_hash(b"secret");
            let request = trojan::read_request(&mut stream, &hash).await.unwrap();
            assert_eq!(request.command, Command::Connect);
            let mut payload = [0u8; 5];
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut payload)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut stream, &payload)
                .await
                .unwrap();
        });
        let parent: Arc<dyn AsyncProxy> = Arc::new(FixedAsyncProxy {
            address,
            timeout: Duration::from_secs(2),
        });
        let proxy = yuhaiin_protocol::trojan::TrojanProxy::new(parent, "secret");
        let destination = yuhaiin_core::Endpoint::domain(
            yuhaiin_core::Network::Tcp,
            yuhaiin_core::DomainName::new("example.com").unwrap(),
            443,
        );
        let context = yuhaiin_core::FlowContext::new(destination);
        let mut stream = proxy.connect(&context).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"hello")
            .await
            .unwrap();
        let mut echoed = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut echoed)
            .await
            .unwrap();
        assert_eq!(&echoed, b"hello");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn go_trojan_layer_builds_a_runtime_proxy_without_dropping_unknown_fields() {
        let address: std::net::SocketAddr = "127.0.0.1:24443".parse().unwrap();
        let config = GoProxyRuntimeConfig {
            id: "trojan".to_owned(),
            name: "trojan".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "trojan".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":address.port()}]}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "trojan".to_owned(),
                    config: serde_json::json!({"password":"secret","futureField":true}),
                },
            ],
            transport: GoProxyTransport::Trojan,
            data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
        };
        let built = snapshot(config)
            .build_proxy("trojan", Duration::from_secs(2))
            .await
            .unwrap();
        let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        assert!(built.proxy.connect(&context).await.is_err());
    }

    #[tokio::test]
    async fn go_shadowsocks_layer_builds_a_runtime_proxy_without_dropping_unknown_fields() {
        let config = GoProxyRuntimeConfig {
            id: "shadowsocks".to_owned(),
            name: "shadowsocks".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "shadowsocks".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24444}]}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "shadowsocks".to_owned(),
                    config: serde_json::json!({
                        "method":"AEAD_AES_256_GCM",
                        "password":"secret",
                        "futureField":true
                    }),
                },
            ],
            transport: GoProxyTransport::Shadowsocks,
            data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
        };
        let built = snapshot(config)
            .build_proxy("shadowsocks", Duration::from_secs(2))
            .await
            .unwrap();
        let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        assert!(built.proxy.connect(&context).await.is_err());
    }

    #[tokio::test]
    async fn go_vless_layer_builds_a_runtime_proxy_without_password_assumption() {
        let config = GoProxyRuntimeConfig {
            id: "vless".to_owned(),
            name: "vless".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "vless".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24445}]}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "vless".to_owned(),
                    config: serde_json::json!({
                        "uuid":"00112233-4455-6677-8899-aabbccddeeff",
                        "futureField":true
                    }),
                },
            ],
            transport: GoProxyTransport::Vless,
            data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
        };
        let built = snapshot(config)
            .build_proxy("vless", Duration::from_secs(2))
            .await
            .unwrap();
        let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        assert!(built.proxy.connect(&context).await.is_err());
    }

    #[tokio::test]
    async fn go_vmess_layer_builds_a_modern_runtime_proxy() {
        let config = GoProxyRuntimeConfig {
            id: "vmess".to_owned(),
            name: "vmess".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "vmess".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24446}]}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "vmess".to_owned(),
                    config: serde_json::json!({
                        "id":"00112233-4455-6677-8899-aabbccddeeff",
                        "aid":"0",
                        "security":"aes-128-gcm",
                        "futureField":true
                    }),
                },
            ],
            transport: GoProxyTransport::Vmess,
            data_json: serde_json::to_vec(&serde_json::json!({"chain":[]})).unwrap(),
        };
        let built = snapshot(config)
            .build_proxy("vmess", Duration::from_secs(2))
            .await
            .unwrap();
        let context = yuhaiin_core::FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        assert!(built.proxy.connect(&context).await.is_err());
    }

    #[cfg(feature = "doh-tls")]
    #[tokio::test]
    async fn go_trojan_layer_builds_tls_transport_before_protocol_wrapper() {
        let config = GoProxyRuntimeConfig {
            id: "trojan-tls".to_owned(),
            name: "trojan-tls".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "tls".to_owned(), "trojan".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({"addresses":[{"host":"127.0.0.1","port":24443}]}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "tls".to_owned(),
                    config: serde_json::json!({"servernames":["example.com"]}),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "trojan".to_owned(),
                    config: serde_json::json!({"password":"secret"}),
                },
            ],
            transport: GoProxyTransport::Trojan,
            data_json: Vec::new(),
        };
        let built = snapshot(config)
            .build_proxy("trojan-tls", Duration::from_secs(2))
            .await
            .unwrap();
        assert!(
            built
                .proxy
                .ping(&FlowContext::new(yuhaiin_core::Endpoint::ip(
                    yuhaiin_core::Network::Tcp,
                    "192.0.2.1:443".parse().unwrap(),
                )))
                .await
                .is_err()
        );
    }

    #[test]
    fn runtime_builds_native_yuubinsya_udp_from_go_layers() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let password_hash = yuhaiin_core::yuubinsya::derive_salt(b"password");
            let server =
                YuubinsyaUdpServer::bind("127.0.0.1:0".parse().unwrap(), password_hash, false)
                    .await
                    .unwrap();
            let server_address = server.local_addr().unwrap().addr().unwrap();
            let config = GoProxyRuntimeConfig {
                id: "yuubinsya-udp".to_owned(),
                name: "yuubinsya-udp".to_owned(),
                group_name: "default".to_owned(),
                origin: "go".to_owned(),
                enabled: true,
                chain_types: vec!["fixedv2".to_owned(), "yuubinsya".to_owned()],
                layers: vec![
                    yuhaiin_store::GoProxyLayer {
                        kind: "fixedv2".to_owned(),
                        config: serde_json::json!({
                            "addresses": [{
                                "host": server_address.ip().to_string(),
                                "port": server_address.port()
                            }]
                        }),
                    },
                    yuhaiin_store::GoProxyLayer {
                        kind: "yuubinsya".to_owned(),
                        config: serde_json::json!({ "password": "password" }),
                    },
                ],
                transport: GoProxyTransport::Yuubinsya,
                data_json: Vec::new(),
            };
            let proxy = snapshot(config)
                .build_proxy("yuubinsya-udp", Duration::from_secs(3))
                .await
                .unwrap()
                .proxy;
            let target = yuhaiin_core::Endpoint::domain(
                yuhaiin_core::Network::Udp,
                yuhaiin_core::DomainName::new("example.com").unwrap(),
                53,
            );
            let context = FlowContext::new(target.clone());
            let datagram = proxy.open_datagram(&context).await.unwrap();
            datagram.send_to(b"query", target.clone()).await.unwrap();
            let mut buffer = [0; 64];
            let (length, decoded_target, peer) = server.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"query");
            assert_eq!(decoded_target, target);
            server
                .send_to(b"answer", decoded_target.clone(), peer)
                .await
                .unwrap();
            let (length, response_target) = datagram.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..length], b"answer");
            assert_eq!(response_target, decoded_target);
        });
    }

    #[test]
    fn runtime_builds_simple_go_yuubinsya_uot_chain_without_four_layer_assumption() {
        let config = GoProxyRuntimeConfig {
            id: "yuubinsya-uot".to_owned(),
            name: "yuubinsya-uot".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec!["fixedv2".to_owned(), "yuubinsya".to_owned()],
            layers: vec![
                yuhaiin_store::GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{ "host": "127.0.0.1", "port": 40501 }]
                    }),
                },
                yuhaiin_store::GoProxyLayer {
                    kind: "yuubinsya".to_owned(),
                    config: serde_json::json!({
                        "password": "password",
                        "udp_over_stream": true,
                        "udp_coalesce": true
                    }),
                },
            ],
            transport: GoProxyTransport::Yuubinsya,
            data_json: serde_json::json!({
                "chain": [
                    { "type": "fixedv2", "fixedv2": {
                        "addresses": [{ "host": "127.0.0.1", "port": 40501 }]
                    }},
                    { "type": "yuubinsya", "yuubinsya": {
                        "password": "password",
                        "udp_over_stream": true,
                        "udp_coalesce": true
                    }}
                ]
            })
            .to_string()
            .into_bytes(),
        };
        let built = block_on(snapshot(config).build_proxy("yuubinsya-uot", Duration::from_secs(1)))
            .unwrap();
        let context = FlowContext::new(yuhaiin_core::Endpoint::ip(
            yuhaiin_core::Network::Tcp,
            "192.0.2.1:443".parse().unwrap(),
        ));
        let error = match block_on(built.proxy.connect(&context)) {
            Ok(_) => panic!("simple Yuubinsya UOT must reject TCP stream connect"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ErrorKind::Unsupported);
    }

    #[test]
    fn runtime_routes_go_websocket_http2_chain_to_chain_builder() {
        let config = GoProxyRuntimeConfig {
            id: "websocket-chain".to_owned(),
            name: "websocket-chain".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec![
                "fixedv2".to_owned(),
                "websocket".to_owned(),
                "http2".to_owned(),
                "yuubinsya".to_owned(),
            ],
            layers: Vec::new(),
            transport: GoProxyTransport::Yuubinsya,
            data_json: serde_json::json!({
                "chain": [
                    {"type": "fixedv2", "fixedv2": {
                        "addresses": [{"host": "127.0.0.1:40501"}]
                    }},
                    {"type": "websocket", "websocket": {
                        "host": "localhost", "path": "/proxy/ws"
                    }},
                    {"type": "http2", "http2": {"concurrency": 2}},
                    {"type": "yuubinsya", "yuubinsya": {
                        "password": "password"
                    }}
                ]
            })
            .to_string()
            .into_bytes(),
        };
        let built =
            block_on(snapshot(config).build_proxy("websocket-chain", Duration::from_secs(1)))
                .unwrap();
        assert_eq!(built.config.id, "websocket-chain");
    }

    #[cfg(feature = "websocket")]
    #[test]
    fn runtime_builds_vless_over_websocket_transport_chain() {
        let config = GoProxyRuntimeConfig {
            id: "vless-websocket".to_owned(),
            name: "vless-websocket".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec![
                "fixedv2".to_owned(),
                "websocket".to_owned(),
                "vless".to_owned(),
            ],
            layers: vec![
                GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{"host": "127.0.0.1", "port": 40501}]
                    }),
                },
                GoProxyLayer {
                    kind: "websocket".to_owned(),
                    config: serde_json::json!({"host": "localhost", "path": "/vless"}),
                },
                GoProxyLayer {
                    kind: "vless".to_owned(),
                    config: serde_json::json!({
                        "uuid": "00000000-0000-0000-0000-000000000001"
                    }),
                },
            ],
            transport: GoProxyTransport::Vless,
            data_json: serde_json::json!({}).to_string().into_bytes(),
        };
        let built =
            block_on(snapshot(config).build_proxy("vless-websocket", Duration::from_secs(1)))
                .unwrap();
        assert_eq!(built.config.id, "vless-websocket");
    }

    #[cfg(feature = "websocket")]
    #[test]
    fn runtime_builds_vmess_over_websocket_transport_chain() {
        let config = GoProxyRuntimeConfig {
            id: "vmess-websocket".to_owned(),
            name: "vmess-websocket".to_owned(),
            group_name: "default".to_owned(),
            origin: "go".to_owned(),
            enabled: true,
            chain_types: vec![
                "fixedv2".to_owned(),
                "websocket".to_owned(),
                "vmess".to_owned(),
            ],
            layers: vec![
                GoProxyLayer {
                    kind: "fixedv2".to_owned(),
                    config: serde_json::json!({
                        "addresses": [{"host": "127.0.0.1", "port": 40502}]
                    }),
                },
                GoProxyLayer {
                    kind: "websocket".to_owned(),
                    config: serde_json::json!({"host": "localhost", "path": "/vmess"}),
                },
                GoProxyLayer {
                    kind: "vmess".to_owned(),
                    config: serde_json::json!({
                        "id": "00000000-0000-0000-0000-000000000001",
                        "aid": 0,
                        "security": "auto"
                    }),
                },
            ],
            transport: GoProxyTransport::Vmess,
            data_json: serde_json::json!({}).to_string().into_bytes(),
        };
        let built =
            block_on(snapshot(config).build_proxy("vmess-websocket", Duration::from_secs(1)))
                .unwrap();
        assert_eq!(built.config.id, "vmess-websocket");
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(value) => return value,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
