//! Inbound proxy listeners and their connection into the shared outbound
//! selector.
//!
//! TUN is only one inbound. This module owns the normal TCP variants of the
//! Go inbound contract: SOCKS5, HTTP CONNECT and Yuubinsya. Each accepted
//! request is converted into the same [`FlowContext`] used by TUN, then routed
//! through the live `RuntimeProxySelector`; listeners therefore observe
//! direct/proxy/bypass/drop changes after a reload without duplicating proxy
//! construction logic.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;

use yuhaiin_core::{Error, ErrorKind, FlowContext, Result};
use yuhaiin_store::GoInboundRecord;

use crate::{ConnectionMonitor, RuntimeController, RuntimeProxySelector};

#[derive(Debug, Clone)]
pub(crate) struct InboundSpec {
    pub(crate) id: String,
    pub(crate) protocol: String,
    pub(crate) listen: SocketAddr,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) udp_mode: UdpMode,
    pub(crate) protocol_udp: bool,
    pub(crate) transports: Vec<String>,
    pub(crate) outbound_id: String,
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

/// Run all enabled normal TCP inbounds and restart their listener set after a
/// successful configuration reload. The supervisor is intentionally outside
/// `RuntimeController`: the controller publishes immutable snapshots, while
/// this owner controls sockets and listener task lifetimes.
pub async fn run_until(
    controller: RuntimeController,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut reload = controller.subscribe_reload();
    let mut listeners = Vec::new();
    loop {
        abort_listeners(&mut listeners).await;
        listeners = start_listeners(&controller).await?;
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            changed = reload.recv() => {
                if changed.is_err() {
                    break;
                }
            }
        }
    }
    abort_listeners(&mut listeners).await;
    Ok(())
}

async fn start_listeners(
    controller: &RuntimeController,
) -> Result<Vec<tokio::task::JoinHandle<()>>> {
    let records = controller.store().repository().list_go_inbounds().await?;
    let proxy_id = selected_proxy_id(controller).await?;
    let selector = controller
        .build_proxy_selector("", &proxy_id, "", "", Duration::from_secs(30))
        .await?;
    let monitor = controller.monitor();
    let mut listeners = Vec::new();
    for record in records.into_iter().filter(|record| record.enabled) {
        let mut spec = match InboundSpec::from_record(record) {
            Ok(spec) => spec,
            Err(error) => {
                eprintln!("skip inbound: {error}");
                continue;
            }
        };
        spec.outbound_id = proxy_id.clone();
        if !spec.transports.is_empty()
            && spec
                .transports
                .iter()
                .any(|transport| !transport.eq_ignore_ascii_case("normal"))
        {
            eprintln!(
                "skip inbound {}: only normal transport is currently implemented",
                spec.id
            );
            continue;
        }
        if spec.udp_mode.tcp_enabled() {
            let listener = TcpListener::bind(spec.listen).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("bind inbound {}: {error}", spec.id))
            })?;
            let selector = selector.clone();
            let monitor = monitor.clone();
            let spec = spec.clone();
            listeners.push(tokio::spawn(async move {
                if let Err(error) = serve_listener(listener, spec, selector, monitor).await {
                    eprintln!("inbound listener stopped: {error}");
                }
            }));
        }
        if spec.udp_mode.udp_enabled() {
            let selector = selector.clone();
            let monitor = monitor.clone();
            let spec = spec.clone();
            match spec.protocol.as_str() {
                "yuubinsya" => {
                    let socket = yuhaiin_core::proxy::YuubinsyaUdpServer::bind(
                        spec.listen,
                        yuhaiin_core::yuubinsya::derive_salt(spec.password.as_bytes()),
                        true,
                    )
                    .await?;
                    listeners.push(tokio::spawn(async move {
                        if let Err(error) =
                            crate::proxy::yuubinsya::serve_udp(socket, spec, selector, monitor)
                                .await
                        {
                            eprintln!("Yuubinsya UDP listener stopped: {error}");
                        }
                    }));
                }
                "socks5" if spec.protocol_udp => {
                    let socket = UdpSocket::bind(spec.listen).await.map_err(|error| {
                        Error::new(
                            ErrorKind::Io,
                            format!("bind SOCKS5 UDP inbound {}: {error}", spec.id),
                        )
                    })?;
                    listeners.push(tokio::spawn(async move {
                        if let Err(error) =
                            crate::proxy::socks5::serve_udp_socket(socket, spec, selector, monitor)
                                .await
                        {
                            eprintln!("SOCKS5 UDP listener stopped: {error}");
                        }
                    }));
                }
                _ => eprintln!(
                    "skip UDP inbound {}: protocol {:?} has no UDP mode",
                    spec.id, spec.protocol
                ),
            }
        }
    }
    Ok(listeners)
}

pub async fn selected_proxy_id(controller: &RuntimeController) -> Result<String> {
    let nodes = controller.store().repository().list_go_nodes().await?;
    let selected = controller
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
    Ok(selected
        .filter(|id| nodes.iter().any(|node| node.enabled && node.id == *id))
        .or_else(|| {
            nodes
                .into_iter()
                .find(|node| node.enabled)
                .map(|node| node.id)
        })
        .unwrap_or_else(|| "direct".to_owned()))
}

async fn abort_listeners(listeners: &mut Vec<tokio::task::JoinHandle<()>>) {
    for listener in listeners.drain(..) {
        listener.abort();
        let _ = listener.await;
    }
}

impl InboundSpec {
    fn from_record(record: GoInboundRecord) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_slice(&record.data_json)
            .map_err(|error| Error::new(ErrorKind::Protocol, format!("inbound JSON: {error}")))?;
        let protocol = value
            .pointer("/protocol/type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(record.protocol_type.as_str())
            .to_ascii_lowercase();
        let network_type = value
            .pointer("/network/type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(record.network_type.as_str());
        if !network_type.eq_ignore_ascii_case("tcp_udp") {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!("inbound network {network_type:?} is not a TCP listener"),
            ));
        }
        let listen_text = value
            .pointer("/network/tcp_udp/host")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let listen = parse_listen_addr(listen_text)?;
        let protocol_value = value.pointer("/protocol").cloned().unwrap_or_default();
        let section = protocol_value.get(&protocol).cloned().unwrap_or_default();
        let udp_mode = UdpMode::from_value(value.pointer("/network/tcp_udp/udp"));
        let username = section
            .get("username")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let password = section
            .get("password")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let protocol_udp = section
            .get("udp")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let transports =
            serde_json::from_slice::<Vec<serde_json::Value>>(&record.transport_types_json)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|transport| {
                    transport
                        .get("type")
                        .and_then(serde_json::Value::as_str)
                        .or_else(|| transport.as_str())
                        .map(ToOwned::to_owned)
                })
                .collect();
        Ok(Self {
            id: record.id,
            protocol,
            listen,
            username,
            password,
            udp_mode,
            protocol_udp,
            transports,
            outbound_id: String::new(),
        })
    }

    pub(crate) fn annotate_context(&self, context: &mut FlowContext) {
        context.inbound = Some(self.protocol.clone());
        context.inbound_name = Some(self.id.clone());
        if !self.outbound_id.is_empty() {
            context.outbound = Some(self.outbound_id.clone());
        }
    }
}

fn parse_listen_addr(value: &str) -> Result<SocketAddr> {
    let value = value.trim();
    let value = if value.starts_with(':') {
        format!("0.0.0.0{value}")
    } else {
        value.to_owned()
    };
    value.parse().map_err(|error| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("inbound listen address: {error}"),
        )
    })
}

async fn serve_listener(
    listener: TcpListener,
    spec: InboundSpec,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
) -> Result<()> {
    let protocol = spec.protocol.clone();
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(crate::proxy::common::io_error)?;
        let selector = selector.clone();
        let monitor = monitor.clone();
        let spec = spec.clone();
        let protocol = protocol.clone();
        tokio::spawn(async move {
            let result = match protocol.as_str() {
                "socks5" => {
                    crate::proxy::socks5::serve(stream, peer, spec, selector, monitor).await
                }
                "http" | "mixed" => {
                    crate::proxy::http::serve(stream, peer, spec, selector, monitor).await
                }
                "yuubinsya" => {
                    crate::proxy::yuubinsya::serve(stream, peer, spec, selector, monitor).await
                }
                other => Err(Error::new(
                    ErrorKind::Unsupported,
                    format!("inbound protocol {other:?} is not implemented"),
                )),
            };
            if let Err(error) = result {
                eprintln!("inbound connection error: {error}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn inbound_udp_mode_accepts_frontend_strings_and_legacy_booleans() {
        assert_eq!(
            UdpMode::from_value(Some(&json!("enabled"))),
            UdpMode::Enabled
        );
        assert_eq!(
            UdpMode::from_value(Some(&json!("udp_only"))),
            UdpMode::UdpOnly
        );
        assert_eq!(UdpMode::from_value(Some(&json!(true))), UdpMode::Enabled);
        assert!(UdpMode::UdpOnly.udp_enabled());
        assert!(!UdpMode::UdpOnly.tcp_enabled());
    }
}
