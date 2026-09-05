use std::sync::Arc;

use tokio::net::UdpSocket;

use super::listeners::{InboundOwners, push_listener};
use super::{
    ConnectionMonitor, InboundHandler, InboundProtocolKind, InboundProtocolPlan, InboundSpec,
    InboundTransportPlan, RuntimeProxySelector,
};
use crate::inbound_runtime::InboundRuntimeState;

pub(super) async fn start_udp_listener(
    listeners: &mut InboundOwners,
    spec: InboundSpec,
    protocol: &InboundProtocolKind,
    protocol_config: &InboundProtocolPlan,
    transports: &InboundTransportPlan,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    runtime: &InboundRuntimeState,
) {
    if matches!(protocol, InboundProtocolKind::Yuubinsya) {
        start_yuubinsya_udp(
            listeners,
            spec,
            protocol_config,
            transports,
            selector,
            monitor,
            runtime,
        )
        .await;
        return;
    }

    if matches!(
        protocol,
        InboundProtocolKind::Socks5 | InboundProtocolKind::Mixed
    ) {
        start_socks5_udp(
            listeners,
            spec,
            protocol_config,
            transports,
            selector,
            monitor,
            runtime,
        )
        .await;
        return;
    }

    monitor.warn(format!(
        "skip UDP inbound {}: protocol {:?} has no UDP mode",
        spec.id, spec.protocol
    ));
}

async fn start_yuubinsya_udp(
    listeners: &mut InboundOwners,
    spec: InboundSpec,
    protocol_config: &InboundProtocolPlan,
    transports: &InboundTransportPlan,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    runtime: &InboundRuntimeState,
) {
    if transports.tls {
        monitor.warn(format!(
            "skip UDP inbound {}: TLS transport only wraps TCP listeners",
            spec.id
        ));
        return;
    }

    let password_hashes = spec
        .auth
        .as_ref()
        .map(|auth| {
            auth.inbound_passwords()
                .into_iter()
                .map(|password| doradus_protocol::yuubinsya::derive_salt(&password))
                .collect::<Vec<_>>()
        })
        .filter(|passwords| !passwords.is_empty())
        .unwrap_or_else(|| {
            vec![doradus_protocol::yuubinsya::derive_salt(
                protocol_config.password().unwrap_or_default().as_bytes(),
            )]
        });

    let socket = if let Some(aead) = transports.aead.clone() {
        let raw = match UdpSocket::bind(spec.listen).await {
            Ok(socket) => socket,
            Err(error) => {
                runtime.listener_failed(
                    &spec.id,
                    "udp",
                    Some(spec.listen.to_string()),
                    &error.to_string(),
                );
                monitor.error(format!(
                    "skip UDP inbound {}: bind AEAD Yuubinsya UDP {}: {error}",
                    spec.id, spec.listen
                ));
                return;
            }
        };
        doradus_protocol::yuubinsya_udp::YuubinsyaUdpServer::new(
            Box::new(doradus_protocol::aead::AeadUdpServer::new(
                raw,
                aead.password,
                aead.method,
            )),
            password_hashes[0],
            false,
        )
    } else {
        match doradus_protocol::yuubinsya_udp::YuubinsyaUdpServer::bind_with_password_hashes(
            spec.listen,
            password_hashes,
            false,
        )
        .await
        {
            Ok(socket) => socket,
            Err(error) => {
                runtime.listener_failed(
                    &spec.id,
                    "udp",
                    Some(spec.listen.to_string()),
                    &error.to_string(),
                );
                monitor.error(format!(
                    "skip UDP inbound {}: bind Yuubinsya UDP {}: {error}",
                    spec.id, spec.listen
                ));
                return;
            }
        }
    };

    let logs = monitor.logs();
    let inbound_handler =
        InboundHandler::new(spec.clone(), Arc::clone(&selector), Arc::clone(&monitor));
    push_listener(
        listeners,
        &spec.id,
        tokio::spawn(async move {
            if let Err(error) =
                crate::inbound::adapters::yuubinsya::handle_udp(socket, inbound_handler).await
            {
                logs.error(format!("Yuubinsya UDP listener stopped: {error}"));
            }
        }),
        runtime,
    );
}

async fn start_socks5_udp(
    listeners: &mut InboundOwners,
    spec: InboundSpec,
    protocol_config: &InboundProtocolPlan,
    transports: &InboundTransportPlan,
    selector: Arc<RuntimeProxySelector>,
    monitor: Arc<ConnectionMonitor>,
    runtime: &InboundRuntimeState,
) {
    if !protocol_config.supports_socks5_udp() {
        monitor.warn(format!(
            "skip UDP inbound {}: protocol {:?} has no UDP mode",
            spec.id, spec.protocol
        ));
        return;
    }
    if transports.tls {
        monitor.warn(format!(
            "skip UDP inbound {}: TLS transport only wraps TCP listeners",
            spec.id
        ));
        return;
    }

    let socket = match UdpSocket::bind(spec.listen).await {
        Ok(socket) => socket,
        Err(error) => {
            runtime.listener_failed(
                &spec.id,
                "udp",
                Some(spec.listen.to_string()),
                &error.to_string(),
            );
            monitor.error(format!(
                "skip UDP inbound {}: bind SOCKS5 UDP {}: {error}",
                spec.id, spec.listen
            ));
            return;
        }
    };

    let logs = monitor.logs();
    let inbound_handler =
        InboundHandler::new(spec.clone(), Arc::clone(&selector), Arc::clone(&monitor));
    if let Some(aead) = transports.aead.clone() {
        let socket = doradus_protocol::socks5_server::AeadUdpTransport::new(
            crate::inbound::socks5::RuntimeUdpTransport(Box::new(socket)),
            aead.password,
            aead.method,
        );
        push_listener(
            listeners,
            &spec.id,
            tokio::spawn(async move {
                if let Err(error) =
                    crate::inbound::socks5::serve_udp_socket(Box::new(socket), inbound_handler)
                        .await
                {
                    logs.error(format!("AEAD SOCKS5 UDP listener stopped: {error}"));
                }
            }),
            runtime,
        );
    } else {
        let socket = crate::inbound::socks5::RuntimeUdpTransport(Box::new(socket));
        push_listener(
            listeners,
            &spec.id,
            tokio::spawn(async move {
                if let Err(error) =
                    crate::inbound::socks5::serve_udp_socket(Box::new(socket), inbound_handler)
                        .await
                {
                    logs.error(format!("SOCKS5 UDP listener stopped: {error}"));
                }
            }),
            runtime,
        );
    }
}
