use std::sync::Arc;

use super::InboundSpec;
use super::listeners::{InboundOwners, ListenerStartContext, push_listener};

pub(super) async fn start_transparent_listener(
    listeners: &mut InboundOwners,
    spec: InboundSpec,
    start: &ListenerStartContext<'_>,
) {
    let protocol = start.protocol;
    let transports = start.transports;
    let selector = &start.selector;
    let monitor = &start.monitor;
    let tls_acceptor = &start.tls_acceptor;
    let runtime = &start.runtime;
    if spec.udp_mode.udp_enabled() && protocol.is_tproxy() {
        monitor.warn(format!(
            "start UDP inbound {}: Linux transparent UDP requires TPROXY ancillary data and CAP_NET_ADMIN",
            spec.id
        ));
    } else if spec.udp_mode.udp_enabled() {
        monitor.warn(format!(
            "ignore UDP inbound {}: Go redir contract disables UDP",
            spec.id
        ));
    }

    if transports.transparent_unsupported {
        monitor.warn(format!(
            "skip inbound {}: transparent listener transport is not implemented",
            spec.id
        ));
        return;
    }

    #[cfg(target_os = "linux")]
    {
        let is_tproxy = protocol.is_tproxy();
        let udp_enabled = spec.udp_mode.udp_enabled();
        let udp_spec = spec.clone();
        let protocol_name = spec.protocol.clone();
        let listener_spec = spec;
        let listener_selector = Arc::clone(selector);
        let listener_monitor = Arc::clone(monitor);
        let listener_tls_acceptor = tls_acceptor.clone();
        let listener_runtime = runtime.clone();
        let logs = listener_monitor.logs();
        push_listener(
            listeners,
            &listener_spec.id.clone(),
            tokio::spawn(async move {
                if let Err(error) = crate::inbound::adapters::transparent::serve_listener(
                    listener_spec.listen,
                    protocol_name,
                    listener_spec,
                    listener_selector,
                    listener_monitor,
                    listener_tls_acceptor,
                    listener_runtime,
                )
                .await
                {
                    logs.error(format!("transparent inbound listener stopped: {error}"));
                }
            }),
            runtime,
        );
        if udp_enabled && is_tproxy {
            let selector = Arc::clone(selector);
            let monitor = Arc::clone(monitor);
            let spec = udp_spec;
            let listener_runtime = runtime.clone();
            let logs = monitor.logs();
            push_listener(
                listeners,
                &spec.id.clone(),
                tokio::spawn(async move {
                    if let Err(error) = crate::inbound::adapters::transparent::serve_udp_listener(
                        spec.listen,
                        spec,
                        selector,
                        monitor,
                        listener_runtime,
                    )
                    .await
                    {
                        logs.error(format!("transparent UDP listener stopped: {error}"));
                    }
                }),
                runtime,
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (listeners, selector, tls_acceptor);
        let error = "tproxy/redir require Linux socket support";
        monitor.warn(format!("skip inbound {}: {error}", spec.id));
        runtime.listener_failed(&spec.id, "listener", Some(spec.listen.to_string()), error);
    }
}
