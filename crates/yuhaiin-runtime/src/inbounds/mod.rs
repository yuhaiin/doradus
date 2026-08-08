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
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::*;
    use crate::{RuntimeBuilder, RuntimeController};
    use serde_json::json;
    use yuhaiin_chain::AsyncYuubinsyaTcpSession;
    use yuhaiin_core::dns_resolver_async::SystemAsyncIpResolver;
    use yuhaiin_core::{Endpoint, Network};
    use yuhaiin_store::{ConfigStore, GoNodeRecord};

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(future)
    }

    async fn direct_runtime() -> (Arc<RuntimeProxySelector>, Arc<ConnectionMonitor>) {
        let store = ConfigStore::open_memory().await.unwrap();
        let controller = RuntimeController::from_builder(RuntimeBuilder::new(
            store,
            Arc::new(SystemAsyncIpResolver),
        ))
        .await
        .unwrap();
        controller
            .store()
            .repository()
            .put_go_node(&GoNodeRecord {
                id: "direct".to_owned(),
                name: "Direct".to_owned(),
                group_name: "default".to_owned(),
                origin: "test".to_owned(),
                enabled: true,
                chain_types_json: br#"["direct"]"#.to_vec(),
                updated_at: 1,
                data_json: br#"{"protocol":"direct"}"#.to_vec(),
            })
            .await
            .unwrap();
        controller.reload().await.unwrap();
        let selector = controller
            .build_proxy_selector("", "direct", "", "", Duration::from_secs(2))
            .await
            .unwrap();
        (selector, controller.monitor())
    }

    async fn echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    loop {
                        let Ok(size) = stream.read(&mut buffer).await else {
                            break;
                        };
                        if size == 0 || stream.write_all(&buffer[..size]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (address, task)
    }

    async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
        let mut headers = Vec::new();
        let mut byte = [0u8; 1];
        while !headers.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            headers.push(byte[0]);
        }
        headers
    }

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

    #[test]
    fn socks5_inbound_routes_a_real_tcp_flow_through_the_shared_outbound() {
        block_on(async {
            let (echo_address, echo_task) = echo_server().await;
            let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let inbound_address = inbound_listener.local_addr().unwrap();
            let (selector, monitor) = direct_runtime().await;
            let listener_task = tokio::spawn(serve_listener(
                inbound_listener,
                InboundSpec {
                    id: "socks-inbound".to_owned(),
                    protocol: "socks5".to_owned(),
                    listen: inbound_address,
                    username: String::new(),
                    password: String::new(),
                    udp_mode: UdpMode::Disabled,
                    protocol_udp: false,
                    transports: vec!["normal".to_owned()],
                    outbound_id: "direct".to_owned(),
                },
                selector,
                monitor,
            ));

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let mut client = TcpStream::connect(inbound_address).await.unwrap();
                client.write_all(&[5, 1, 0]).await.unwrap();
                let mut method = [0u8; 2];
                client.read_exact(&mut method).await.unwrap();
                assert_eq!(method, [5, 0]);

                let ip = match echo_address.ip() {
                    std::net::IpAddr::V4(ip) => ip.octets(),
                    std::net::IpAddr::V6(_) => panic!("test echo server must be IPv4"),
                };
                let mut request = vec![5, 1, 0, 1];
                request.extend_from_slice(&ip);
                request.extend_from_slice(&echo_address.port().to_be_bytes());
                client.write_all(&request).await.unwrap();
                let mut reply = [0u8; 10];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[0..2], [5, 0]);

                client.write_all(b"socks5-through-direct").await.unwrap();
                let mut echoed = vec![0u8; 21];
                client.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"socks5-through-direct");
            })
            .await;

            listener_task.abort();
            let _ = listener_task.await;
            echo_task.abort();
            let _ = echo_task.await;
            result.unwrap();
        });
    }

    #[test]
    fn http_connect_inbound_routes_a_real_tcp_flow_through_the_shared_outbound() {
        block_on(async {
            let (echo_address, echo_task) = echo_server().await;
            let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let inbound_address = inbound_listener.local_addr().unwrap();
            let (selector, monitor) = direct_runtime().await;
            let listener_task = tokio::spawn(serve_listener(
                inbound_listener,
                InboundSpec {
                    id: "http-inbound".to_owned(),
                    protocol: "http".to_owned(),
                    listen: inbound_address,
                    username: String::new(),
                    password: String::new(),
                    udp_mode: UdpMode::Disabled,
                    protocol_udp: false,
                    transports: vec!["normal".to_owned()],
                    outbound_id: "direct".to_owned(),
                },
                selector,
                monitor,
            ));

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let mut client = TcpStream::connect(inbound_address).await.unwrap();
                client
                    .write_all(
                        format!(
                            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
                            echo_address, echo_address
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                let headers = read_headers(&mut client).await;
                assert!(headers.starts_with(b"HTTP/1.1 200 Connection Established"));

                client.write_all(b"http-through-direct").await.unwrap();
                let mut echoed = vec![0u8; 19];
                client.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"http-through-direct");
            })
            .await;

            listener_task.abort();
            let _ = listener_task.await;
            echo_task.abort();
            let _ = echo_task.await;
            result.unwrap();
        });
    }

    #[test]
    fn yuubinsya_inbound_routes_a_real_tcp_flow_through_the_shared_outbound() {
        block_on(async {
            let (echo_address, echo_task) = echo_server().await;
            let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let inbound_address = inbound_listener.local_addr().unwrap();
            let (selector, monitor) = direct_runtime().await;
            let listener_task = tokio::spawn(serve_listener(
                inbound_listener,
                InboundSpec {
                    id: "yuubinsya-inbound".to_owned(),
                    protocol: "yuubinsya".to_owned(),
                    listen: inbound_address,
                    username: String::new(),
                    password: "test-password".to_owned(),
                    udp_mode: UdpMode::Disabled,
                    protocol_udp: false,
                    transports: vec!["normal".to_owned()],
                    outbound_id: "direct".to_owned(),
                },
                selector,
                monitor,
            ));

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                let transport = TcpStream::connect(inbound_address).await.unwrap();
                let password = yuhaiin_core::yuubinsya::derive_salt(b"test-password");
                let destination = Endpoint::ip(Network::Tcp, echo_address);
                let mut client =
                    AsyncYuubinsyaTcpSession::connect(transport, password, destination)
                        .await
                        .unwrap();
                client.write_all(b"yuubinsya-through-direct").await.unwrap();
                let mut echoed = vec![0u8; 24];
                client.read_exact(&mut echoed).await.unwrap();
                assert_eq!(&echoed, b"yuubinsya-through-direct");
            })
            .await;

            listener_task.abort();
            let _ = listener_task.await;
            echo_task.abort();
            let _ = echo_task.await;
            result.unwrap();
        });
    }
}
