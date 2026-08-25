//! Proxy-aware node latency probes.
//!
//! The management API must measure the configured node, not the management
//! process itself.  This module therefore owns only the probe protocol and
//! consumes the shared `AsyncProxy` boundary; it does not know how an inbound
//! or an outbound proxy was built.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use yuhaiin_core::dns_resolver::{AsyncIpResolver, SystemAsyncIpResolver};
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use yuhaiin_core::{
    DomainName, Endpoint, Error, ErrorKind, FlowContext, IpSet, Network, ResolveStrategy, Result,
};
use yuhaiin_dns::{AsyncDnsDatagram, DnsDatagramConnector, probe_dns_udp};
#[cfg(feature = "doh-tls")]
use yuhaiin_dns::{DoqResolverConfig, DoqResolverFactory, probe_doq};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LatencyRequest {
    #[serde(rename = "type")]
    pub probe_type: String,
    pub url: String,
    pub user_agent: String,
    pub host: String,
    pub target_domain: String,
    pub ipv6: bool,
    pub tcp: bool,
}

impl Default for LatencyRequest {
    fn default() -> Self {
        Self {
            probe_type: String::new(),
            url: String::new(),
            user_agent: String::new(),
            host: String::new(),
            target_domain: String::new(),
            ipv6: true,
            tcp: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LatencyResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "is_zero")]
    pub latency_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpLatency>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stun: Option<StunLatency>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpLatency {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ipv4: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ipv6: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StunLatency {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub xor_mapped_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mapped_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub other_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub response_origin_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub software: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mapping: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub filtering: String,
}

static TRANSACTION_COUNTER: AtomicU64 = AtomicU64::new(1);

#[path = "latency_http.rs"]
mod latency_http;
#[path = "latency_stun.rs"]
mod latency_stun;
#[cfg(test)]
use latency_http::read_http_response;
use latency_http::{HttpReply, http_probe, http_probe_at, parse_http_target};
use latency_stun::probe_stun;
#[cfg(test)]
use latency_stun::{parse_stun_response, probe_stun_udp, stun_binding_request};

pub async fn probe(
    proxy: Arc<dyn AsyncProxy>,
    request: LatencyRequest,
    timeout: Duration,
) -> Result<LatencyResponse> {
    probe_with_resolver(proxy, Arc::new(SystemAsyncIpResolver), request, timeout).await
}

/// Probe a node through the runtime's configured resolver.
///
/// Go's IP latency endpoint resolves the URL host twice, once with a
/// PreferIPv4 policy and once with PreferIPv6, before handing an IP endpoint
/// to the selected proxy.  Keeping the resolver as an explicit dependency
/// makes that behavior testable and avoids silently falling back to the
/// management process resolver.
pub async fn probe_with_resolver(
    proxy: Arc<dyn AsyncProxy>,
    resolver: Arc<dyn AsyncIpResolver>,
    mut request: LatencyRequest,
    timeout: Duration,
) -> Result<LatencyResponse> {
    let probe_type = if request.probe_type.trim().is_empty() {
        "http".to_owned()
    } else {
        request.probe_type.trim().to_owned()
    };
    request.probe_type = probe_type.clone();

    match probe_type.as_str() {
        "" | "http" | "tcp" => {
            let target = request.url_or_default(false);
            let reply =
                tokio::time::timeout(timeout, http_probe(&proxy, &target, &request, timeout))
                    .await
                    .map_err(|_| {
                        Error::new(ErrorKind::Timeout, "HTTP latency probe timed out")
                    })??;
            Ok(success(reply.elapsed))
        }
        "ip" => probe_ip(proxy, resolver, request, timeout).await,
        "stun" | "stun_tcp" => probe_stun(proxy, request, timeout).await,
        "dns" | "udp" => probe_dns(proxy, request, timeout).await,
        #[cfg(feature = "doh-tls")]
        "doq" => probe_doq_latency(proxy, resolver, request, timeout).await,
        #[cfg(not(feature = "doh-tls"))]
        "doq" => Err(Error::new(
            ErrorKind::Unsupported,
            "DoQ latency requires the doh-tls feature",
        )),
        other => Err(Error::new(
            ErrorKind::Unsupported,
            format!("latency probe type {other:?} is not supported"),
        )),
    }
}

impl LatencyRequest {
    fn url_or_default(&self, ip: bool) -> String {
        if !self.url.trim().is_empty() {
            return self.url.trim().to_owned();
        }
        if ip {
            "https://api.ipify.org".to_owned()
        } else {
            "https://clients3.google.com/generate_204".to_owned()
        }
    }

    fn host_or_default(&self, tcp: bool) -> String {
        if !self.host.trim().is_empty() {
            return self.host.trim().to_owned();
        }
        if tcp {
            "stun.nextcloud.com:443".to_owned()
        } else {
            "stun.nextcloud.com:3478".to_owned()
        }
    }

    fn dns_host_or_default(&self) -> String {
        if !self.host.trim().is_empty() {
            return self.host.trim().to_owned();
        }
        "223.5.5.5:53".to_owned()
    }

    fn doq_host_or_default(&self) -> String {
        if !self.host.trim().is_empty() {
            return self.host.trim().to_owned();
        }
        "dns.nextdns.io:853".to_owned()
    }

    fn dns_target_or_default(&self) -> String {
        if !self.target_domain.trim().is_empty() {
            return self.target_domain.trim().to_owned();
        }
        "www.google.com".to_owned()
    }
}

fn success(elapsed: Duration) -> LatencyResponse {
    LatencyResponse {
        ok: true,
        latency_ms: elapsed.as_millis().min(i64::MAX as u128) as i64,
        ip: None,
        stun: None,
        error: String::new(),
    }
}

async fn probe_ip(
    proxy: Arc<dyn AsyncProxy>,
    resolver: Arc<dyn AsyncIpResolver>,
    request: LatencyRequest,
    timeout: Duration,
) -> Result<LatencyResponse> {
    let target = request.url_or_default(true);
    let (v4, v6) = tokio::join!(
        probe_ip_family(
            Arc::clone(&proxy),
            Arc::clone(&resolver),
            &target,
            &request,
            timeout,
            false,
        ),
        probe_ip_family(proxy, resolver, &target, &request, timeout, true),
    );
    let mut ip = IpLatency::default();
    if let Ok(reply) = v4 {
        let value = String::from_utf8_lossy(&reply.body).trim().to_owned();
        if value.parse::<Ipv4Addr>().is_ok() {
            ip.ipv4 = value;
        } else if value.parse::<Ipv6Addr>().is_ok() {
            ip.ipv6 = value;
        }
    }
    if let Ok(reply) = v6 {
        let value = String::from_utf8_lossy(&reply.body).trim().to_owned();
        if value.parse::<Ipv6Addr>().is_ok() {
            ip.ipv6 = value;
        } else if value.parse::<Ipv4Addr>().is_ok() {
            ip.ipv4 = value;
        }
    }
    if ip.ipv4.is_empty() && ip.ipv6.is_empty() {
        return Err(Error::new(
            ErrorKind::Protocol,
            "IP latency endpoint returned no IPv4 or IPv6 address",
        ));
    }
    Ok(LatencyResponse {
        ok: true,
        latency_ms: 0,
        ip: Some(ip),
        stun: None,
        error: String::new(),
    })
}

async fn probe_ip_family(
    proxy: Arc<dyn AsyncProxy>,
    resolver: Arc<dyn AsyncIpResolver>,
    target: &str,
    request: &LatencyRequest,
    timeout: Duration,
    ipv6: bool,
) -> Result<HttpReply> {
    let parsed = parse_http_target(target)?;
    let address = if let Ok(ip) = parsed.host.parse::<IpAddr>() {
        if ip.is_ipv6() != ipv6 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "IP latency URL literal has the wrong address family",
            ));
        }
        SocketAddr::new(ip, parsed.port)
    } else {
        let domain = DomainName::new(&parsed.host)?;
        let strategy = if ipv6 {
            ResolveStrategy::OnlyIpv6
        } else {
            ResolveStrategy::OnlyIpv4
        };
        let addresses = tokio::time::timeout(timeout, resolver.resolve(&domain, strategy))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "IP latency DNS resolution timed out"))??;
        SocketAddr::new(
            select_ip(&addresses, ipv6).ok_or_else(|| {
                Error::new(
                    ErrorKind::NotFound,
                    format!(
                        "IP latency host has no IPv{} address",
                        if ipv6 { 6 } else { 4 }
                    ),
                )
            })?,
            parsed.port,
        )
    };
    http_probe_at(&proxy, target, request, timeout, Some(address)).await
}

fn select_ip(addresses: &IpSet, ipv6: bool) -> Option<IpAddr> {
    if ipv6 {
        addresses.v6.first().copied().map(IpAddr::V6)
    } else {
        addresses.v4.first().copied().map(IpAddr::V4)
    }
}

async fn probe_dns(
    proxy: Arc<dyn AsyncProxy>,
    request: LatencyRequest,
    timeout: Duration,
) -> Result<LatencyResponse> {
    let (host, port) = parse_host_port(&request.dns_host_or_default(), 53)?;
    let domain = DomainName::new(&request.dns_target_or_default())?;
    let elapsed = probe_dns_udp(
        &LatencyDatagramConnector { proxy },
        "latency-dns",
        &host,
        port,
        &domain,
        timeout,
    )
    .await?;
    Ok(success(elapsed))
}

#[cfg(feature = "doh-tls")]
async fn probe_doq_latency(
    proxy: Arc<dyn AsyncProxy>,
    resolver: Arc<dyn AsyncIpResolver>,
    request: LatencyRequest,
    timeout: Duration,
) -> Result<LatencyResponse> {
    let (host, _) = parse_host_port(&request.doq_host_or_default(), 853)?;
    let domain = DomainName::new(&request.dns_target_or_default())?;
    let factory = DoqResolverFactory::from_webpki_roots(timeout, 1)?
        .with_server_resolver(resolver)
        .with_datagram_connector(Arc::new(LatencyDatagramConnector { proxy }));
    let elapsed = probe_doq(
        &factory,
        DoqResolverConfig {
            id: "latency-doq".to_owned(),
            host: request.doq_host_or_default(),
            server_name: Some(host),
            local_bind_addresses: Vec::new(),
            bind_interface: None,
        },
        &domain,
        timeout,
    )
    .await?;
    Ok(success(elapsed))
}

struct LatencyDatagramConnector {
    proxy: Arc<dyn AsyncProxy>,
}

impl DnsDatagramConnector for LatencyDatagramConnector {
    fn open<'a>(
        &'a self,
        _resolver_id: &'a str,
        host: &'a str,
        target: SocketAddr,
        _local_bind_addresses: &'a [IpAddr],
        _bind_interface: Option<&'a str>,
    ) -> yuhaiin_core::BoxFuture<'a, Result<Option<Box<dyn AsyncDnsDatagram>>>> {
        Box::pin(async move {
            let destination = endpoint(Network::Udp, host, target.port())?;
            let context = FlowContext::new(destination.clone());
            let datagram = self.proxy.open_datagram(&context).await?;
            Ok(Some(Box::new(LatencyDatagram {
                inner: datagram,
                destination,
                server: target,
            }) as Box<dyn AsyncDnsDatagram>))
        })
    }
}

struct LatencyDatagram {
    inner: Box<dyn AsyncDatagram>,
    destination: Endpoint,
    server: SocketAddr,
}

impl AsyncDnsDatagram for LatencyDatagram {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        _target: SocketAddr,
    ) -> yuhaiin_core::BoxFuture<'a, Result<usize>> {
        self.inner.send_to(payload, self.destination.clone())
    }

    fn recv_from<'a>(
        &'a self,
        buffer: &'a mut [u8],
    ) -> yuhaiin_core::BoxFuture<'a, Result<(usize, SocketAddr)>> {
        Box::pin(async move {
            let (length, endpoint) = self.inner.recv_from(buffer).await?;
            Ok((length, endpoint.addr().unwrap_or(self.server)))
        })
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.inner
            .local_addr()?
            .addr()
            .ok_or_else(|| Error::invalid("latency DNS datagram has no local address"))
    }

    fn close(&self) -> yuhaiin_core::BoxFuture<'_, Result<()>> {
        self.inner.close()
    }
}

fn parse_host_port(value: &str, default_port: u16) -> Result<(String, u16)> {
    let value = value
        .strip_prefix("stun://")
        .or_else(|| value.strip_prefix("udp://"))
        .or_else(|| value.strip_prefix("tcp://"))
        .unwrap_or(value);
    if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| Error::invalid("latency host has an invalid IPv6 authority"))?;
        let port = rest
            .strip_prefix(':')
            .map(|port| port.parse::<u16>())
            .transpose()
            .map_err(|error| Error::invalid(format!("latency host port: {error}")))?
            .unwrap_or(default_port);
        return Ok((host.to_owned(), port));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if host.contains(':') {
            return Ok((value.to_owned(), default_port));
        }
        return Ok((
            host.to_owned(),
            port.parse::<u16>()
                .map_err(|error| Error::invalid(format!("latency host port: {error}")))?,
        ));
    }
    if value.is_empty() {
        return Err(Error::invalid("latency host is empty"));
    }
    Ok((value.to_owned(), default_port))
}

fn endpoint(network: Network, host: &str, port: u16) -> Result<Endpoint> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(Endpoint::ip(network, SocketAddr::new(address, port)));
    }
    Ok(Endpoint::domain(network, DomainName::new(host)?, port))
}

fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

fn is_stun_timeout(error: &Error) -> bool {
    error.kind == ErrorKind::Timeout
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

#[cfg(test)]
#[path = "latency_tests.rs"]
mod tests;
