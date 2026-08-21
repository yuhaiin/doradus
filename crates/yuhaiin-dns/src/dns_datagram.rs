use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::dns::{DnsRecordType, decode_response, encode_query};
use crate::dns_resolver::AsyncIpResolver;
use crate::{BoxFuture, DomainName, Error, ErrorKind, ResolveStrategy, Result};

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
    resolve_server_with_resolver(host, port, None).await
}

pub(crate) async fn resolve_server_with_resolver(
    host: &str,
    port: u16,
    resolver: Option<&dyn AsyncIpResolver>,
) -> Result<SocketAddr> {
    if let Ok(address) = host.parse::<SocketAddr>() {
        return Ok(address);
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    if let Some(resolver) = resolver {
        let domain = DomainName::new(host)?;
        let addresses = resolver
            .resolve(&domain, ResolveStrategy::PreferIpv4)
            .await?;
        if let Some(address) = addresses
            .v4
            .first()
            .copied()
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), port))
        {
            return Ok(address);
        }
        if let Some(address) = addresses
            .v6
            .first()
            .copied()
            .map(|ip| SocketAddr::new(IpAddr::V6(ip), port))
        {
            return Ok(address);
        }
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("DNS endpoint {host} resolved to no address"),
        ));
    }

    crate::dns_resolver::resolve_internet_server(host, port).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    struct StaticResolver;

    impl AsyncIpResolver for StaticResolver {
        fn resolve<'a>(
            &'a self,
            _domain: &'a DomainName,
            _strategy: ResolveStrategy,
        ) -> BoxFuture<'a, Result<crate::IpSet>> {
            Box::pin(async {
                Ok(crate::IpSet {
                    v4: vec![Ipv4Addr::new(192, 0, 2, 53)],
                    v6: vec![Ipv6Addr::LOCALHOST],
                })
            })
        }
    }

    #[tokio::test]
    async fn endpoint_resolution_uses_supplied_resolver_and_prefers_ipv4() {
        let address = resolve_server_with_resolver("dns.example", 853, Some(&StaticResolver))
            .await
            .unwrap();

        assert_eq!(address, "192.0.2.53:853".parse().unwrap());
    }
}
