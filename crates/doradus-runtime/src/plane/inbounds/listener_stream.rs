use std::sync::Arc;

use tokio::net::TcpListener;

use super::listeners::{InboundOwners, ListenerStartContext, push_listener};
#[cfg(feature = "http2")]
use super::serve_h2_listener;
#[cfg(all(feature = "websocket", feature = "http2"))]
use super::serve_websocket_h2_listener;
#[cfg(feature = "websocket")]
use super::serve_websocket_listener;
use super::{ConnectionMonitor, InboundProtocolKind, InboundSpec, serve_listener};
use crate::inbound_runtime::InboundRuntimeState;

async fn bind_tcp_listener(
    spec: &InboundSpec,
    monitor: &ConnectionMonitor,
    runtime: &InboundRuntimeState,
) -> Option<TcpListener> {
    match TcpListener::bind(spec.listen).await {
        Ok(listener) => {
            runtime.listener_ready(
                &spec.id,
                "tcp",
                Some(listener.local_addr().unwrap_or(spec.listen).to_string()),
            );
            Some(listener)
        }
        Err(error) => {
            runtime.listener_failed(
                &spec.id,
                "tcp",
                Some(spec.listen.to_string()),
                &error.to_string(),
            );
            monitor.error(format!(
                "skip inbound {}: bind TCP {}: {error}",
                spec.id, spec.listen
            ));
            None
        }
    }
}

/// Start the TCP side of one socket inbound.
///
/// Returns true when a stream transport owns the whole inbound branch
/// (WebSocket or HTTP/2), so the caller must not start a separate UDP socket.
/// Plain TCP returns false after updating `spec.listen` to the bound address;
/// this preserves Go's port-0 behavior where the UDP side reuses that port.
pub(super) async fn start_stream_listener(
    listeners: &mut InboundOwners,
    spec: &mut InboundSpec,
    start: &ListenerStartContext<'_>,
) -> bool {
    let protocol = start.protocol;
    let transports = start.transports;
    let selector = &start.selector;
    let monitor = &start.monitor;
    let tls_acceptor = start.tls_acceptor.clone();
    let runtime = start.runtime.as_ref();
    if transports.websocket {
        if spec.udp_mode.udp_enabled() {
            monitor.warn(format!(
                "skip UDP inbound {}: WebSocket transport only wraps TCP listeners",
                spec.id
            ));
        }
        if spec.udp_mode.tcp_enabled() {
            let Some(listener) = bind_tcp_listener(spec, monitor, runtime).await else {
                return true;
            };
            spec.listen = listener.local_addr().unwrap_or(spec.listen);
            let selector = Arc::clone(selector);
            let monitor = Arc::clone(monitor);
            let listener_spec = spec.clone();
            let listener_id = listener_spec.id.clone();
            let tls_acceptor = tls_acceptor.clone();
            let logs = monitor.logs();
            #[cfg(all(feature = "websocket", feature = "http2"))]
            {
                if transports.http2 {
                    push_listener(
                        listeners,
                        &listener_id,
                        tokio::spawn(async move {
                            if let Err(error) = serve_websocket_h2_listener(
                                listener,
                                listener_spec,
                                selector,
                                monitor,
                                tls_acceptor,
                            )
                            .await
                            {
                                logs.error(format!(
                                    "WebSocket+HTTP/2 inbound listener stopped: {error}"
                                ));
                            }
                        }),
                        runtime,
                    );
                } else {
                    push_listener(
                        listeners,
                        &listener_id,
                        tokio::spawn(async move {
                            if let Err(error) = serve_websocket_listener(
                                listener,
                                listener_spec,
                                selector,
                                monitor,
                                tls_acceptor,
                            )
                            .await
                            {
                                logs.error(format!("WebSocket inbound listener stopped: {error}"));
                            }
                        }),
                        runtime,
                    );
                }
            }
            #[cfg(all(feature = "websocket", not(feature = "http2")))]
            {
                if transports.http2 {
                    let _ = (listener, listener_spec, selector, monitor, tls_acceptor);
                    logs.warn(
                        "skip inbound: WebSocket+HTTP/2 requires both websocket and http2 features",
                    );
                } else {
                    push_listener(
                        listeners,
                        &listener_spec.id,
                        tokio::spawn(async move {
                            if let Err(error) = serve_websocket_listener(
                                listener,
                                listener_spec,
                                selector,
                                monitor,
                                tls_acceptor,
                            )
                            .await
                            {
                                logs.error(format!("WebSocket inbound listener stopped: {error}"));
                            }
                        }),
                        runtime,
                    );
                }
            }
            #[cfg(not(feature = "websocket"))]
            {
                let _ = (listener, listener_spec, selector, monitor, tls_acceptor);
                logs.warn("skip inbound: WebSocket transport requires the websocket feature");
            }
        }
        return true;
    }

    if transports.http2 {
        if spec.udp_mode.udp_enabled() {
            monitor.warn(format!(
                "skip UDP inbound {}: HTTP/2 transport only wraps TCP listeners",
                spec.id
            ));
        }
        if spec.udp_mode.tcp_enabled() {
            let Some(listener) = bind_tcp_listener(spec, monitor, runtime).await else {
                return true;
            };
            spec.listen = listener.local_addr().unwrap_or(spec.listen);
            let selector = Arc::clone(selector);
            let monitor = Arc::clone(monitor);
            let listener_spec = spec.clone();
            let listener_id = listener_spec.id.clone();
            let tls_acceptor = tls_acceptor.clone();
            let logs = monitor.logs();
            #[cfg(feature = "http2")]
            push_listener(
                listeners,
                &listener_id,
                tokio::spawn(async move {
                    if let Err(error) =
                        serve_h2_listener(listener, listener_spec, selector, monitor, tls_acceptor)
                            .await
                    {
                        logs.error(format!("HTTP/2 inbound listener stopped: {error}"));
                    }
                }),
                runtime,
            );
            #[cfg(not(feature = "http2"))]
            {
                let _ = (listener, listener_spec, selector, monitor, tls_acceptor);
                logs.warn("skip inbound: HTTP/2 transport requires the http2 feature");
            }
        }
        return true;
    }

    if spec.udp_mode.tcp_enabled()
        || (matches!(protocol, InboundProtocolKind::Vless) && spec.udp_mode.udp_enabled())
    {
        let Some(listener) = bind_tcp_listener(spec, monitor, runtime).await else {
            return false;
        };
        spec.listen = listener.local_addr().unwrap_or(spec.listen);
        let selector = Arc::clone(selector);
        let monitor = Arc::clone(monitor);
        let listener_spec = spec.clone();
        let listener_id = listener_spec.id.clone();
        let tls_acceptor = tls_acceptor.clone();
        let logs = monitor.logs();
        push_listener(
            listeners,
            &listener_id,
            tokio::spawn(async move {
                if let Err(error) =
                    serve_listener(listener, listener_spec, selector, monitor, tls_acceptor).await
                {
                    logs.error(format!("inbound listener stopped: {error}"));
                }
            }),
            runtime,
        );
    }
    false
}
