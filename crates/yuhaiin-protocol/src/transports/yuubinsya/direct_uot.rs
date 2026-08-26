//! Direct fixed -> Yuubinsya UDP-over-TCP runtime.
//!
//! The full chain uses HTTP/2 as its stream carrier. Go also supports the
//! smaller fixed -> Yuubinsya form, where the authenticated UOT session is
//! carried directly by one TCP connection. Keep this adapter here so the
//! common `AsyncProxy` contract can support both forms without adding a store
//! DTO or making core depend on the chain crate.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::yuubinsya::derive_salt;
use serde_json::Value;
use tokio::sync::Mutex;
use yuhaiin_core::dns_resolver::AsyncIpResolver;
use yuhaiin_core::network::connect_tokio_tcp_with_interface;
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, Result};

use crate::direct_uot_session::{DirectUotSession, closed_error};
use crate::session::AsyncYuubinsyaUotSession;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectUotEndpoint {
    host: String,
    port: u16,
    network_interface: Option<String>,
}

#[derive(Clone)]
pub struct DirectUotProxy {
    endpoints: Arc<Vec<DirectUotEndpoint>>,
    password_hash: [u8; 32],
    udp_coalesce: bool,
    resolver: Arc<dyn AsyncIpResolver>,
    active_datagrams: Arc<Mutex<Vec<Weak<DirectUotDatagram>>>>,
    closed: Arc<AtomicBool>,
}

pub fn parse_go_direct_uot(
    json_text: &str,
    resolver: Arc<dyn AsyncIpResolver>,
) -> Result<Option<DirectUotProxy>> {
    let root: Value = serde_json::from_str(json_text)
        .map_err(|error| Error::new(ErrorKind::InvalidInput, format!("Go node JSON: {error}")))?;
    let Some(chain) = root.get("chain").and_then(Value::as_array) else {
        return Ok(None);
    };
    let kinds = chain
        .iter()
        .filter_map(|node| node.get("type").and_then(Value::as_str))
        .collect::<Vec<_>>();
    if !kinds
        .iter()
        .any(|kind| kind.eq_ignore_ascii_case("yuubinsya"))
        || kinds.iter().any(|kind| {
            matches!(
                kind.to_ascii_lowercase().as_str(),
                "tls" | "http2" | "websocket"
            )
        })
    {
        return Ok(None);
    }
    let yuubinsya = chain
        .iter()
        .find(|node| {
            node.get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.eq_ignore_ascii_case("yuubinsya"))
        })
        .and_then(|node| node.get("yuubinsya"))
        .ok_or_else(|| Error::invalid("Go Yuubinsya node has no config"))?;
    if !yuubinsya
        .get("udp_over_stream")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(None);
    }
    let password = yuubinsya
        .get("password")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::invalid("Go Yuubinsya password is empty"))?;
    let fixed = chain
        .iter()
        .find(|node| {
            node.get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| {
                    matches!(
                        kind.to_ascii_lowercase().as_str(),
                        "fixed" | "fixedv2" | "simple"
                    )
                })
        })
        .and_then(|node| {
            let kind = node.get("type")?.as_str()?;
            node.get(kind)
                .or_else(|| node.get("fixedv2"))
                .or_else(|| node.get("fixed"))
                .or_else(|| node.get("simple"))
        })
        .ok_or_else(|| Error::invalid("direct Yuubinsya UOT requires a fixed endpoint"))?;
    let endpoints = fixed_endpoints(fixed)?;
    if endpoints.is_empty() {
        return Err(Error::invalid("direct Yuubinsya UOT has no fixed endpoint"));
    }
    Ok(Some(DirectUotProxy {
        endpoints: Arc::new(endpoints),
        password_hash: derive_salt(password.as_bytes()),
        udp_coalesce: yuubinsya
            .get("udp_coalesce")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        resolver,
        active_datagrams: Arc::new(Mutex::new(Vec::new())),
        closed: Arc::new(AtomicBool::new(false)),
    }))
}

fn fixed_endpoints(config: &Value) -> Result<Vec<DirectUotEndpoint>> {
    let default_interface = network_interface(config);
    if let Some(addresses) = config.get("addresses").and_then(Value::as_array) {
        return addresses
            .iter()
            .map(|value| endpoint_value_with_default(value, default_interface))
            .collect();
    }
    if config.get("host").is_some() {
        let mut endpoints = vec![endpoint_value_with_default(config, default_interface)?];
        if let Some(alternates) = config.get("alternate_host").and_then(Value::as_array) {
            endpoints.extend(
                alternates
                    .iter()
                    .map(|value| endpoint_value_with_default(value, default_interface))
                    .collect::<Result<Vec<_>>>()?,
            );
        }
        return Ok(endpoints);
    }
    Err(Error::invalid(
        "Go fixed node requires addresses or host/port",
    ))
}

fn endpoint_value(value: &Value) -> Result<DirectUotEndpoint> {
    if let Some(text) = value.as_str() {
        let (host, port) = split_host_port(text)?;
        return validate_endpoint(host, port, None);
    }
    let host = value
        .get("host")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid("Go fixed endpoint requires host"))?;
    let port = value
        .get("port")
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::invalid("Go fixed endpoint requires port"))?;
    let port = u16::try_from(port).map_err(|_| Error::invalid("Go fixed port is out of range"))?;
    validate_endpoint(
        host.to_owned(),
        port,
        network_interface(value).map(str::to_owned),
    )
}

fn endpoint_value_with_default(
    value: &Value,
    default_interface: Option<&str>,
) -> Result<DirectUotEndpoint> {
    let mut endpoint = endpoint_value(value)?;
    if endpoint.network_interface.is_none() {
        endpoint.network_interface = default_interface.map(str::to_owned);
    }
    Ok(endpoint)
}

fn network_interface(value: &Value) -> Option<&str> {
    value
        .get("network_interface")
        .or_else(|| value.get("networkInterface"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|interface| !interface.is_empty())
}

fn split_host_port(value: &str) -> Result<(String, u16)> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }
    let (host, port) = if let Some(value) = value.strip_prefix('[') {
        value
            .split_once("]:")
            .ok_or_else(|| Error::invalid("fixed endpoint requires host:port"))?
    } else {
        value
            .rsplit_once(':')
            .ok_or_else(|| Error::invalid("fixed endpoint requires host:port"))?
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| Error::invalid("fixed endpoint port is invalid"))?;
    Ok((host.to_owned(), port))
}

fn validate_endpoint(
    host: String,
    port: u16,
    network_interface: Option<String>,
) -> Result<DirectUotEndpoint> {
    if host.is_empty() || port == 0 {
        return Err(Error::invalid("fixed endpoint host/port is invalid"));
    }
    if host.parse::<std::net::IpAddr>().is_err() {
        DomainName::new(&host)?;
    }
    Ok(DirectUotEndpoint {
        host,
        port,
        network_interface,
    })
}

impl AsyncProxy for DirectUotProxy {
    fn connect<'a>(&'a self, _context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async {
            Err(Error::new(
                ErrorKind::Unsupported,
                "direct Yuubinsya UOT proxy has no TCP stream destination path",
            ))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let proxy = self.clone();
        let migrate_id = Arc::new(AtomicU64::new(
            context.udp_migrate_id.load(Ordering::Acquire),
        ));
        let context_migrate_id = Arc::clone(&context.udp_migrate_id);
        let local_bind_addresses = Arc::new(context.local_bind_addresses.clone());
        let bind_interface = context.bind_interface.clone();
        Box::pin(async move {
            if proxy.closed.load(Ordering::Acquire) {
                return Err(closed_error());
            }
            let (session, assigned_id) = proxy
                .connect_session(
                    migrate_id.load(Ordering::Acquire),
                    local_bind_addresses.as_slice(),
                    bind_interface.as_deref(),
                )
                .await?;
            migrate_id.store(assigned_id, Ordering::Release);
            context_migrate_id.store(assigned_id, Ordering::Release);
            let datagram = Arc::new(DirectUotDatagram::new(
                proxy.clone(),
                migrate_id,
                session,
                local_bind_addresses,
                bind_interface,
            ));
            if let Err(error) = proxy.register_datagram(&datagram).await {
                let _ = datagram.close().await;
                return Err(error);
            }
            Ok(Box::new(DirectUotDatagramHandle { inner: datagram }) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        let active_datagrams = Arc::clone(&self.active_datagrams);
        let closed = Arc::clone(&self.closed);
        Box::pin(async move {
            if closed.swap(true, Ordering::AcqRel) {
                return Ok(());
            }
            let datagrams = {
                let mut active = active_datagrams.lock().await;
                active
                    .drain(..)
                    .filter_map(|datagram| datagram.upgrade())
                    .collect::<Vec<_>>()
            };
            for datagram in datagrams {
                let _ = AsyncDatagram::close(datagram.as_ref()).await;
            }
            Ok(())
        })
    }
}

impl DirectUotProxy {
    async fn register_datagram(&self, datagram: &Arc<DirectUotDatagram>) -> Result<()> {
        let mut active = self.active_datagrams.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        active.retain(|entry| entry.strong_count() != 0);
        active.push(Arc::downgrade(datagram));
        Ok(())
    }

    async fn connect_session(
        &self,
        migrate_id: u64,
        local_bind_addresses: &[std::net::IpAddr],
        bind_interface: Option<&str>,
    ) -> Result<(Arc<DirectUotSession>, u64)> {
        let addresses = resolve_endpoints(&self.endpoints, self.resolver.as_ref()).await?;
        let mut last_error = None;
        for (address, endpoint_interface) in addresses {
            let local_bind = local_bind_addresses
                .iter()
                .copied()
                .find(|ip| ip.is_ipv4() == address.ip().is_ipv4())
                .map(|ip| SocketAddr::new(ip, 0));
            let endpoint_interface = endpoint_interface.as_deref().or(bind_interface);
            let stream = match connect_tokio_tcp_with_interface(
                address,
                local_bind,
                endpoint_interface,
                CONNECT_TIMEOUT,
            )
            .await
            {
                Ok(stream) => stream,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            let (reader, writer, assigned_id) = match AsyncYuubinsyaUotSession::connect_split(
                stream,
                self.password_hash,
                migrate_id,
            )
            .await
            {
                Ok(parts) => parts,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            return Ok((
                DirectUotSession::new(reader, writer, self.udp_coalesce),
                assigned_id,
            ));
        }
        Err(last_error.unwrap_or_else(|| Error::invalid("Yuubinsya UOT has no resolved endpoint")))
    }
}

async fn resolve_endpoints(
    endpoints: &[DirectUotEndpoint],
    resolver: &dyn AsyncIpResolver,
) -> Result<Vec<(SocketAddr, Option<String>)>> {
    let mut addresses = Vec::new();
    for endpoint in endpoints {
        if let Ok(ip) = endpoint.host.parse() {
            addresses.push((
                SocketAddr::new(ip, endpoint.port),
                endpoint.network_interface.clone(),
            ));
            continue;
        }
        let domain = DomainName::new(&endpoint.host)?;
        let resolved = resolver
            .resolve(&domain, yuhaiin_core::ResolveStrategy::Default)
            .await?;
        addresses.extend(resolved.iter().map(|ip| {
            (
                SocketAddr::new(ip, endpoint.port),
                endpoint.network_interface.clone(),
            )
        }));
    }
    Ok(addresses)
}

struct DirectUotDatagram {
    proxy: DirectUotProxy,
    migrate_id: Arc<AtomicU64>,
    local_bind_addresses: Arc<Vec<std::net::IpAddr>>,
    bind_interface: Option<String>,
    session: Mutex<Option<Arc<DirectUotSession>>>,
    reconnect_lock: Mutex<()>,
    closed: AtomicBool,
}

struct DirectUotDatagramHandle {
    inner: Arc<DirectUotDatagram>,
}

impl AsyncDatagram for DirectUotDatagramHandle {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        AsyncDatagram::send_to(self.inner.as_ref(), payload, target)
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        AsyncDatagram::recv_from(self.inner.as_ref(), buffer)
    }

    fn local_addr(&self) -> Result<Endpoint> {
        AsyncDatagram::local_addr(self.inner.as_ref())
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        AsyncDatagram::close(self.inner.as_ref())
    }
}

impl DirectUotDatagram {
    fn new(
        proxy: DirectUotProxy,
        migrate_id: Arc<AtomicU64>,
        session: Arc<DirectUotSession>,
        local_bind_addresses: Arc<Vec<std::net::IpAddr>>,
        bind_interface: Option<String>,
    ) -> Self {
        Self {
            proxy,
            migrate_id,
            local_bind_addresses,
            bind_interface,
            session: Mutex::new(Some(session)),
            reconnect_lock: Mutex::new(()),
            closed: AtomicBool::new(false),
        }
    }

    async fn current_session(&self) -> Result<Arc<DirectUotSession>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        self.session.lock().await.clone().ok_or_else(closed_error)
    }

    async fn reconnect(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        let _guard = self.reconnect_lock.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(closed_error());
        }
        if let Some(old) = self.session.lock().await.take() {
            let _ = old.close().await;
        }
        let (session, assigned_id) = self
            .proxy
            .connect_session(
                self.migrate_id.load(Ordering::Acquire),
                self.local_bind_addresses.as_slice(),
                self.bind_interface.as_deref(),
            )
            .await?;
        self.migrate_id.store(assigned_id, Ordering::Release);
        *self.session.lock().await = Some(session);
        Ok(())
    }
}

impl AsyncDatagram for DirectUotDatagram {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: Endpoint) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            for attempt in 0..=2 {
                let result = self
                    .current_session()
                    .await?
                    .send_to(&target, payload)
                    .await;
                match result {
                    Ok(()) => return Ok(payload.len()),
                    Err(error) if attempt < 2 && is_recoverable(&error) => {
                        self.reconnect().await?;
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(Error::new(
                ErrorKind::Timeout,
                "Yuubinsya UOT retry budget exhausted",
            ))
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
        Box::pin(async move {
            for attempt in 0..=2 {
                match self.current_session().await?.recv_from().await {
                    Ok((target, payload)) => {
                        if buffer.len() < payload.len() {
                            return Err(Error::new(
                                ErrorKind::InvalidInput,
                                "Yuubinsya UOT payload exceeds receive buffer",
                            ));
                        }
                        buffer[..payload.len()].copy_from_slice(&payload);
                        return Ok((payload.len(), target));
                    }
                    Err(error) if attempt < 2 && is_recoverable(&error) => {
                        self.reconnect().await?;
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(Error::new(
                ErrorKind::Timeout,
                "Yuubinsya UOT retry budget exhausted",
            ))
        })
    }

    fn local_addr(&self) -> Result<Endpoint> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "Yuubinsya UOT has no local UDP socket endpoint",
        ))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            if self.closed.swap(true, Ordering::AcqRel) {
                return Ok(());
            }
            if let Some(session) = self.session.lock().await.take() {
                session.close().await?;
            }
            Ok(())
        })
    }
}

fn is_recoverable(error: &Error) -> bool {
    matches!(
        error.kind,
        ErrorKind::Io | ErrorKind::Closed | ErrorKind::Protocol | ErrorKind::Timeout
    )
}

#[cfg(test)]
mod tests {
    use crate::direct_uot::{fixed_endpoints, parse_go_direct_uot};
    use std::sync::Arc;

    #[test]
    fn direct_uot_parser_leaves_tls_chain_for_the_full_chain_builder() {
        let json = serde_json::json!({
            "chain": [
                { "type": "fixedv2", "fixedv2": {
                    "addresses": [{ "host": "127.0.0.1", "port": 443 }]
                }},
                { "type": "tls", "tls": { "enable": true } },
                { "type": "yuubinsya", "yuubinsya": {
                    "password": "password", "udp_over_stream": true
                }}
            ]
        });
        let parsed = parse_go_direct_uot(
            &json.to_string(),
            Arc::new(yuhaiin_core::dns_resolver::SystemAsyncIpResolver),
        )
        .unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn direct_uot_preserves_endpoint_network_interfaces() {
        let endpoints = fixed_endpoints(&serde_json::json!({
            "host": "127.0.0.1",
            "port": 443,
            "network_interface": "eth0",
            "alternate_host": [
                { "host": "127.0.0.2", "port": 8443 },
                { "host": "127.0.0.3", "port": 9443, "network_interface": "lo" }
            ]
        }))
        .unwrap();
        assert_eq!(endpoints[0].network_interface.as_deref(), Some("eth0"));
        assert_eq!(endpoints[1].network_interface.as_deref(), Some("eth0"));
        assert_eq!(endpoints[2].network_interface.as_deref(), Some("lo"));
    }
}
