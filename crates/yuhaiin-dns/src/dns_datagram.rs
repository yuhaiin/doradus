use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::dns::{DnsRecordType, decode_response, encode_query};
use crate::{BoxFuture, DomainName, Error, ErrorKind, Result};

pub trait AsyncDnsDatagram: Send + Sync {
    fn send_to<'a>(&'a self, payload: &'a [u8], target: SocketAddr)
    -> BoxFuture<'a, Result<usize>>;
    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> BoxFuture<'a, Result<(usize, SocketAddr)>>;
    fn local_addr(&self) -> Result<SocketAddr>;
    fn close(&self) -> BoxFuture<'_, Result<()>>;
}

pub trait DnsDatagramConnector: Send + Sync {
    fn open<'a>(
        &'a self,
        resolver_id: &'a str,
        host: &'a str,
        target: SocketAddr,
        local_bind_addresses: &'a [IpAddr],
        bind_interface: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Option<Box<dyn AsyncDnsDatagram>>>>;
}

pub async fn probe_dns_udp(
    connector: &dyn DnsDatagramConnector,
    resolver_id: &str,
    host: &str,
    port: u16,
    domain: &DomainName,
    timeout: Duration,
) -> Result<Duration> {
    let target = resolve_server(host, port).await?;
    let datagram = connector
        .open(resolver_id, host, target, &[], None)
        .await?
        .ok_or_else(|| Error::invalid("DNS latency datagram connector was not opened"))?;
    let packet = encode_query(0, domain, DnsRecordType::A)?;
    let started = std::time::Instant::now();
    tokio::time::timeout(timeout, datagram.send_to(&packet, target))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "DNS UDP write timed out"))??;
    let mut buffer = vec![0u8; 4096];
    let (length, _) = tokio::time::timeout(timeout, datagram.recv_from(&mut buffer))
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "DNS UDP response timed out"))??;
    decode_response(&buffer[..length], 0, DnsRecordType::A)?;
    datagram.close().await?;
    Ok(started.elapsed())
}

pub(crate) async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(address) = host.parse::<SocketAddr>() {
        return Ok(address);
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("resolve DNS endpoint: {error}")))?
        .next()
        .ok_or_else(|| Error::new(ErrorKind::Io, "DNS endpoint resolved to no address"))
}
