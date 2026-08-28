//! Inbound proxy listeners and their connection into the shared outbound
//! selector.
//!
//! TUN is one inbound among several. This module owns the normal TCP variants
//! of the Go inbound contract: SOCKS5, HTTP CONNECT and Yuubinsya. Each accepted
//! request is converted into the same [`FlowContext`] used by TUN, then routed
//! through the live `RuntimeProxySelector`; listeners therefore observe
//! direct/proxy/bypass/drop changes after a reload without duplicating proxy
//! construction logic.
use std::net::SocketAddr;
#[cfg(all(feature = "tun", unix))]
use std::os::fd::OwnedFd;
use std::sync::{Arc, OnceLock};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};

use doradus_core::process::{ProcessResolver, default_process_resolver};
use doradus_core::proxy::{AsyncProxySelector, BoxAsyncStream};
use doradus_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Result};
use doradus_protocol::stream::PrefixedIo;
use doradus_store::GoInboundRecord;
use doradus_types::InboundBasicAuth;

use crate::{ConnectionMonitor, RuntimeController, RuntimeProxySelector};

#[path = "auth.rs"]
mod auth;
pub(crate) use auth::InboundAuth;
mod handler;
#[cfg(feature = "tun")]
pub(crate) use handler::InboundInputInterceptor;
pub(crate) use handler::{
    InboundDnsHandler, InboundDnsPolicy, InboundHandler, InboundStream, InboundUdpCodec,
    InboundUdpFlowPolicy, InboundUdpRequest, InboundUdpResponse, InboundUdpSession,
};

pub(crate) mod adapters;

// Outbound SOCKS5 lives in doradus-protocol; this module owns inbound policy
// and flow lifetime.
mod listeners;
mod socks5;
use listeners::{InboundOwners, InboundStartOptions, start_inbounds};

#[path = "inbound_spec.rs"]
mod inbound_spec;
pub(crate) use inbound_spec::*;

#[path = "inbound_protocols.rs"]
mod inbound_protocols;
pub(crate) use inbound_protocols::*;

#[cfg(feature = "doh-tls")]
pub(crate) type InboundTlsAcceptor = doradus_protocol::tls_server::TlsAcceptor;
#[cfg(not(feature = "doh-tls"))]
pub(crate) type InboundTlsAcceptor = ();

fn has_transport(transports: &[String], kind: &str) -> bool {
    transports
        .iter()
        .any(|transport| transport.eq_ignore_ascii_case(kind))
}

/// Normalize generated fields that Go fills before persisting an inbound
/// contract.  Keeping this at the API/storage boundary means a reload sees
/// the same bytes that the listener used, instead of generating a new CA on
/// every process start.
pub fn fill_generated_fields(value: &mut serde_json::Value) -> Result<()> {
    #[cfg(feature = "doh-tls")]
    {
        doradus_protocol::tls_server::fill_generated_fields(value)
    }
    #[cfg(not(feature = "doh-tls"))]
    {
        let _ = value;
        Ok(())
    }
}

/// Return whether the listener supervisor can apply the Go inbound transport
/// contract without adding another wire layer.
///
/// Go's `proxy` and `http_mock` server transports are transparent listener
/// wrappers: their `NewServer` functions return the supplied listener and do
/// not alter accepted connections.  They therefore deliberately share the
/// normal TCP listener path here.  Keeping the allow-list in one function
/// prevents the compatibility check in `start_inbounds` from drifting away
/// from the actual dispatch branches below.
fn is_supported_inbound_transport(transport: &str) -> bool {
    transport.eq_ignore_ascii_case("normal")
        || transport.eq_ignore_ascii_case("tls")
        || transport.eq_ignore_ascii_case("http2")
        || transport.eq_ignore_ascii_case("websocket")
        || transport.eq_ignore_ascii_case("aead")
        || transport.eq_ignore_ascii_case("proxy")
        || transport.eq_ignore_ascii_case("http_mock")
        || transport.eq_ignore_ascii_case("tls_auto")
}

/// Return whether a transport can be applied before the transparent protocol
/// without losing the original destination address.
///
/// TLS, TLS-auto and AEAD are stream wrappers handled by
/// `prepare_inbound_stream`; `http_mock` is a transparent Go listener
/// wrapper. HTTP/2, WebSocket and PROXY protocol create logical or decoded
/// streams whose local address is no longer the TPROXY/REDIRECT destination,
/// so they remain rejected for this protocol path instead of silently routing
/// to the listen address.
pub(crate) fn is_supported_transparent_transport(transport: &str) -> bool {
    transport.eq_ignore_ascii_case("normal")
        || transport.eq_ignore_ascii_case("tls")
        || transport.eq_ignore_ascii_case("tls_auto")
        || transport.eq_ignore_ascii_case("aead")
        || transport.eq_ignore_ascii_case("http_mock")
}

fn supports_socks5_udp(protocol: &str, protocol_udp: bool) -> bool {
    let protocol = protocol.trim();
    (protocol.eq_ignore_ascii_case("mixed") || protocol.eq_ignore_ascii_case("mix"))
        || (protocol.eq_ignore_ascii_case("socks5") && protocol_udp)
}

fn inbound_process_resolver() -> Option<&'static dyn ProcessResolver> {
    static RESOLVER: OnceLock<Option<Arc<dyn ProcessResolver>>> = OnceLock::new();
    RESOLVER.get_or_init(default_process_resolver).as_deref()
}

#[derive(Debug, Clone)]
pub(crate) struct InboundSpec {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) protocol: String,
    pub(crate) listen: SocketAddr,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) auth: Option<Arc<InboundAuth>>,
    pub(crate) udp_mode: UdpMode,
    pub(crate) protocol_udp: bool,
    pub(crate) transports: Vec<String>,
    pub(crate) aead_password: Option<String>,
    pub(crate) aead_method: doradus_protocol::aead::CryptoMethod,
    pub(crate) outbound_id: String,
    pub(crate) reverse_target: Option<Endpoint>,
    pub(crate) reverse_http: Option<ReverseHttpConfig>,
}

#[derive(Debug, Clone)]
pub(crate) struct ReverseHttpConfig {
    pub(crate) target: Endpoint,
    pub(crate) path: String,
    pub(crate) authority: String,
    pub(crate) https: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UdpMode {
    Enabled,
    Disabled,
    TcpOnly,
    UdpOnly,
}

impl UdpMode {
    fn from_value(value: Option<&serde_json::Value>) -> Self {
        match value {
            Some(value) if value.is_boolean() => {
                if value.as_bool().unwrap_or(false) {
                    Self::Enabled
                } else {
                    Self::Disabled
                }
            }
            Some(value) => match value
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str()
            {
                "enabled" => Self::Enabled,
                "udp_only" => Self::UdpOnly,
                "tcp_only" => Self::TcpOnly,
                _ => Self::Disabled,
            },
            None => Self::Disabled,
        }
    }

    fn tcp_enabled(self) -> bool {
        !matches!(self, Self::UdpOnly)
    }

    fn udp_enabled(self) -> bool {
        matches!(self, Self::Enabled | Self::UdpOnly)
    }
}

/// Run all enabled inbounds and restart the affected owner after a successful
/// configuration reload. TUN, TProxy, Redir and normal socket protocols all
/// use the same owner map, matching Go's `SaveContract` lifecycle.
pub async fn run_until(
    controller: RuntimeController,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    run_until_with_ready_signal(controller, shutdown, None).await
}

/// Run all inbounds and notify the caller after the first listener setup has
/// built and published the shared outbound selector. DNS must wait for this
/// boundary because resolver transports can start dialing before any inbound
/// client connects.
pub async fn run_until_with_selector_ready(
    controller: RuntimeController,
    shutdown: watch::Receiver<bool>,
    selector_ready: oneshot::Sender<()>,
) -> Result<()> {
    run_until_with_ready_signal(controller, shutdown, Some(selector_ready)).await
}

async fn run_until_with_ready_signal(
    controller: RuntimeController,
    shutdown: watch::Receiver<bool>,
    selector_ready: Option<oneshot::Sender<()>>,
) -> Result<()> {
    run_until_inner(
        controller,
        shutdown,
        selector_ready,
        InboundStartOptions::default(),
    )
    .await
}

/// Run normal inbounds together with a TUN device created by the platform
/// host.
///
/// Android's `VpnService` owns the file descriptor, so the runtime must not
/// try to open or close a second desktop device. The injected device remains
/// owned by this inbound supervisor, is included in the same final shutdown
/// boundary as TCP/UDP listeners, and is reused across reloads while its
/// proxy runtime is rebuilt from the new snapshot.
#[cfg(feature = "tun")]
pub async fn run_until_with_tun_runtime(
    controller: RuntimeController,
    shutdown: watch::Receiver<bool>,
    tun: doradus_tun::TunRuntime,
    config: crate::TunRuntimeConfig,
) -> Result<()> {
    run_until_with_tun_runtime_ready(controller, shutdown, tun, config, None).await
}

/// Variant of [`run_until_with_tun_runtime`] that notifies the caller after
/// the normal inbound listener set has published the shared selector.
#[cfg(feature = "tun")]
pub async fn run_until_with_tun_runtime_selector_ready(
    controller: RuntimeController,
    shutdown: watch::Receiver<bool>,
    tun: doradus_tun::TunRuntime,
    config: crate::TunRuntimeConfig,
    selector_ready: oneshot::Sender<()>,
) -> Result<()> {
    run_until_with_tun_runtime_ready(controller, shutdown, tun, config, Some(selector_ready)).await
}

#[cfg(feature = "tun")]
async fn run_until_with_tun_runtime_ready(
    controller: RuntimeController,
    shutdown: watch::Receiver<bool>,
    tun: doradus_tun::TunRuntime,
    config: crate::TunRuntimeConfig,
    selector_ready: Option<oneshot::Sender<()>>,
) -> Result<()> {
    run_until_inner(
        controller,
        shutdown,
        selector_ready,
        InboundStartOptions::with_injected_tun(tun, config),
    )
    .await
}

/// Run all normal inbounds together with a TUN descriptor created by the
/// platform host. The descriptor is consumed and owned by the inbound
/// supervisor for the lifetime of the call.
///
/// This keeps the TUN entry point in the inbound module, alongside SOCKS5,
/// HTTP, Yuubinsya and UDP listeners. Platform code only supplies the
/// already-established FD; routing, proxy selection, reload and shutdown
/// remain shared with the desktop path.
#[cfg(all(feature = "tun", unix))]
pub async fn run_until_with_tun_fd(
    controller: RuntimeController,
    shutdown: watch::Receiver<bool>,
    fd: OwnedFd,
    config: crate::TunRuntimeConfig,
) -> Result<()> {
    let tun = doradus_tun::TunRuntime::from_owned_fd(config.tun.clone(), fd)
        .map_err(|error| Error::new(ErrorKind::Io, format!("open injected TUN fd: {error}")))?;
    run_until_with_tun_runtime(controller, shutdown, tun, config).await
}

/// Injected-TUN variant that notifies the caller after the first inbound
/// listener setup has published the shared selector.
#[cfg(all(feature = "tun", unix))]
pub async fn run_until_with_tun_fd_selector_ready(
    controller: RuntimeController,
    shutdown: watch::Receiver<bool>,
    fd: OwnedFd,
    config: crate::TunRuntimeConfig,
    selector_ready: oneshot::Sender<()>,
) -> Result<()> {
    let tun = doradus_tun::TunRuntime::from_owned_fd(config.tun.clone(), fd)
        .map_err(|error| Error::new(ErrorKind::Io, format!("open injected TUN fd: {error}")))?;
    run_until_with_tun_runtime_selector_ready(controller, shutdown, tun, config, selector_ready)
        .await
}

async fn run_until_inner(
    controller: RuntimeController,
    mut shutdown: watch::Receiver<bool>,
    mut selector_ready: Option<oneshot::Sender<()>>,
    mut options: InboundStartOptions,
) -> Result<()> {
    let mut reload = controller.subscribe_inbound_reload();
    let mut listeners = InboundOwners::new();
    let result = async {
        abort_inbounds(&mut listeners, &controller.inbound_runtime()).await;
        listeners = start_inbounds(&controller, &shutdown, None, &mut options).await?;
        if let Some(selector_ready) = selector_ready.take() {
            let _ = selector_ready.send(());
        }
        if *shutdown.borrow() {
            return Ok::<(), Error>(());
        }
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                changed = reload.recv() => {
                    let Ok(event) = changed else { break; };
                    match event {
                        crate::controller::InboundReload::All => {
                            // A single API operation can publish several
                            // compatible reloads; the store and snapshot
                            // are latest-wins, so discard intermediates.
                            while reload.try_recv().is_ok() {}
                            let injected_id = options.injected_owner_id();
                            abort_inbounds_except(
                                &mut listeners,
                                injected_id.as_deref(),
                                &controller.inbound_runtime(),
                            )
                            .await;
                            let owners = start_inbounds(
                                &controller,
                                &shutdown,
                                None,
                                &mut options,
                            )
                            .await?;
                            listeners.extend(owners);
                        }
                        crate::controller::InboundReload::One(id) => {
                            if !options.is_injected_owner(&id) {
                                abort_inbound_owner(
                                    &mut listeners,
                                    &id,
                                    &controller.inbound_runtime(),
                                )
                                .await;
                                let owner = start_inbounds(
                                    &controller,
                                    &shutdown,
                                    Some(&id),
                                    &mut options,
                                )
                                .await?;
                                listeners.extend(owner);
                            }
                        }
                    }
                }
            }
        }
        Ok::<(), Error>(())
    }
    .await;
    abort_inbounds(&mut listeners, &controller.inbound_runtime()).await;

    result
}

pub async fn selected_proxy_ids(controller: &RuntimeController) -> Result<(String, String)> {
    let nodes = controller.store().repository().list_go_nodes().await?;
    let legacy_selected = controller
        .store()
        .get_config("selected.node")
        .await?
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| {
            value
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });

    async fn selected_id(
        controller: &RuntimeController,
        key: &str,
        nodes: &[doradus_store::GoNodeRecord],
        legacy_selected: Option<&String>,
    ) -> Result<String> {
        let selected = controller
            .store()
            .get_config(key)
            .await?
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .and_then(|value| {
                value
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .or_else(|| legacy_selected.cloned());
        Ok(selected
            .filter(|id| nodes.iter().any(|node| node.enabled && node.id == *id))
            .or_else(|| {
                nodes
                    .iter()
                    .find(|node| node.enabled)
                    .map(|node| node.id.clone())
            })
            .unwrap_or_else(|| "direct".to_owned()))
    }

    let tcp = selected_id(
        controller,
        "selected_tcp_node_v2",
        &nodes,
        legacy_selected.as_ref(),
    )
    .await?;
    let udp = selected_id(
        controller,
        "selected_udp_node_v2",
        &nodes,
        legacy_selected.as_ref(),
    )
    .await?;
    Ok((tcp, udp))
}

pub async fn selected_proxy_id(controller: &RuntimeController) -> Result<String> {
    Ok(selected_proxy_ids(controller).await?.0)
}

async fn abort_inbounds(
    listeners: &mut InboundOwners,
    runtime: &crate::inbound_runtime::InboundRuntimeState,
) {
    for (id, owner) in listeners.drain() {
        runtime.mark_stopping(&id);
        for listener in owner {
            listener.abort();
            let _ = listener.await;
        }
    }
}

async fn abort_inbound_owner(
    listeners: &mut InboundOwners,
    id: &str,
    runtime: &crate::inbound_runtime::InboundRuntimeState,
) {
    if let Some(owner) = listeners.remove(id) {
        runtime.mark_stopping(id);
        for listener in owner {
            listener.abort();
            let _ = listener.await;
        }
    }
}

async fn abort_inbounds_except(
    listeners: &mut InboundOwners,
    keep_id: Option<&str>,
    runtime: &crate::inbound_runtime::InboundRuntimeState,
) {
    let ids = listeners
        .keys()
        .filter(|id| Some(id.as_str()) != keep_id)
        .cloned()
        .collect::<Vec<_>>();
    for id in ids {
        abort_inbound_owner(listeners, &id, runtime).await;
    }
}

#[cfg(test)]
#[path = "inbounds_tests.rs"]
mod tests;
