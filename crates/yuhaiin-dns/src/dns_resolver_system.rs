//! System DNS resolver.

use super::*;

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemAsyncIpResolver;

const DEFAULT_DNS_CLIENT_CACHE_CAPACITY: usize = 256;

#[derive(Clone)]
pub(super) struct SystemDnsClient {
    #[cfg(unix)]
    client: Arc<AsyncUdpDnsClient>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SystemDnsClientKey {
    #[cfg(unix)]
    Unix(std::net::SocketAddr),
    #[cfg(not(unix))]
    Platform,
}

struct SystemDnsClientEntry {
    key: SystemDnsClientKey,
    resolver: Arc<AsyncDnsResolver<SystemDnsClient>>,
}

#[derive(Default)]
struct SystemDnsClientManager {
    current: Mutex<Option<SystemDnsClientEntry>>,
}

fn system_dns_manager() -> &'static SystemDnsClientManager {
    static MANAGER: OnceLock<SystemDnsClientManager> = OnceLock::new();
    MANAGER.get_or_init(SystemDnsClientManager::default)
}

pub(super) async fn shared_system_dns_resolver() -> Result<Arc<AsyncDnsResolver<SystemDnsClient>>> {
    let key = system_dns_client_key().await?;
    let manager = system_dns_manager();
    if let Some(resolver) = manager
        .current
        .lock()
        .map_err(|_| crate::Error::new(crate::ErrorKind::Closed, "system DNS manager poisoned"))?
        .as_ref()
        .filter(|entry| entry.key == key)
        .map(|entry| Arc::clone(&entry.resolver))
    {
        return Ok(resolver);
    }

    let resolver = Arc::new(
        AsyncDnsResolver::new(SystemDnsClient::new(key)?).with_cache(
            DnsCache::new(DEFAULT_DNS_CLIENT_CACHE_CAPACITY).expect("valid DNS cache capacity"),
        ),
    );
    let mut current = manager
        .current
        .lock()
        .map_err(|_| crate::Error::new(crate::ErrorKind::Closed, "system DNS manager poisoned"))?;
    if let Some(existing) = current
        .as_ref()
        .filter(|entry| entry.key == key)
        .map(|entry| Arc::clone(&entry.resolver))
    {
        return Ok(existing);
    }
    *current = Some(SystemDnsClientEntry {
        key,
        resolver: Arc::clone(&resolver),
    });
    Ok(resolver)
}

impl AsyncIpResolver for SystemAsyncIpResolver {
    fn resolve<'a>(
        &'a self,
        domain: &'a DomainName,
        strategy: ResolveStrategy,
    ) -> BoxFuture<'a, Result<IpSet>> {
        if let Ok(ip) = domain.as_str().parse::<std::net::IpAddr>() {
            let mut result = IpSet::default();
            match ip {
                std::net::IpAddr::V4(ip) => result.v4.push(ip),
                std::net::IpAddr::V6(ip) => result.v6.push(ip),
            }
            match strategy {
                ResolveStrategy::OnlyIpv4 => result.v6.clear(),
                ResolveStrategy::OnlyIpv6 => result.v4.clear(),
                ResolveStrategy::PreferIpv4
                | ResolveStrategy::PreferIpv6
                | ResolveStrategy::Default => {}
            }
            return Box::pin(async move { Ok(result) });
        }
        Box::pin(async move {
            shared_system_dns_resolver()
                .await?
                .resolve_send(domain, strategy)
                .await
        })
    }

    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            shared_system_dns_resolver()
                .await?
                .query_send(domain, record_type)
                .await
        })
    }

    fn query_packet<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            shared_system_dns_resolver()
                .await?
                .query_packet_send(packet)
                .await
        })
    }
}

#[cfg(unix)]
async fn system_dns_client_key() -> Result<SystemDnsClientKey> {
    let server = tokio::task::spawn_blocking(read_system_dns_server)
        .await
        .map_err(|error| {
            crate::Error::new(
                crate::ErrorKind::Io,
                format!("read system DNS server task: {error}"),
            )
        })??;
    Ok(SystemDnsClientKey::Unix(server))
}

#[cfg(not(unix))]
async fn system_dns_client_key() -> Result<SystemDnsClientKey> {
    Ok(SystemDnsClientKey::Platform)
}

impl SystemDnsClient {
    fn new(key: SystemDnsClientKey) -> Result<Self> {
        #[cfg(unix)]
        {
            let SystemDnsClientKey::Unix(server) = key;
            Ok(Self {
                client: Arc::new(AsyncUdpDnsClient::new(
                    server,
                    std::time::Duration::from_secs(5),
                    // Keep the receive buffer aligned with the EDNS(0) payload advertised
                    // by `encode_query`; a UDP DNS client does not need the TCP maximum.
                    8192,
                    Arc::from(Vec::new().into_boxed_slice()),
                    None,
                )),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = key;
            Ok(Self {})
        }
    }
}

impl SendAsyncDnsQuery for SystemDnsClient {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            #[cfg(unix)]
            {
                return self.client.query(domain, record_type).await;
            }
            #[cfg(target_os = "windows")]
            {
                return query_windows_system_resolver(domain, record_type).await;
            }
            #[cfg(not(any(unix, target_os = "windows")))]
            {
                let addresses = tokio::net::lookup_host((domain.as_str(), 0))
                    .await
                    .map_err(|error| {
                        crate::Error::new(
                            crate::ErrorKind::Io,
                            format!("resolve system host {}: {error}", domain.as_str()),
                        )
                    })?;
                let mut response = DnsResponse {
                    addresses: IpSet::default(),
                    ptr_names: Vec::new(),
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(30),
                };
                for address in addresses {
                    match address.ip() {
                        std::net::IpAddr::V4(ip) if record_type == DnsRecordType::A => {
                            response.addresses.v4.push(ip)
                        }
                        std::net::IpAddr::V6(ip) if record_type == DnsRecordType::Aaaa => {
                            response.addresses.v6.push(ip)
                        }
                        _ => {}
                    }
                }
                if response.addresses.is_empty() {
                    return Err(crate::Error::invalid(format!(
                        "system host {} resolved to no address for {record_type:?}",
                        domain.as_str()
                    )));
                }
                Ok(response)
            }
        })
    }

    fn query_packet_send<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            #[cfg(unix)]
            {
                return self.client.query_packet(packet).await;
            }
            #[cfg(target_os = "windows")]
            {
                return query_windows_system_packet(packet).await;
            }
            #[cfg(not(any(unix, target_os = "windows")))]
            {
                let question = decode_query(packet)?;
                let answer = self
                    .query_send(&question.domain, question.record_type)
                    .await?;
                encode_response(packet, &answer)
            }
        })
    }
}

/// Go keeps a separate built-in `Internet` resolver for bootstrap hostnames.
/// It must not depend on the system resolver, otherwise a DoH/DoT/DoQ endpoint
/// whose host is a domain could deadlock on the resolver it is bootstrapping.
#[derive(Clone)]
struct InternetDnsClient {
    primary: Arc<AsyncUdpDnsClient>,
    secondary: Arc<AsyncUdpDnsClient>,
}

fn internet_dns_resolver() -> &'static AsyncDnsResolver<InternetDnsClient> {
    static RESOLVER: OnceLock<AsyncDnsResolver<InternetDnsClient>> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        let primary = Arc::new(AsyncUdpDnsClient::new(
            ([1, 1, 1, 1], 53).into(),
            std::time::Duration::from_secs(5),
            8192,
            Arc::from(Vec::new().into_boxed_slice()),
            None,
        ));
        let secondary = Arc::new(AsyncUdpDnsClient::new(
            ([223, 5, 5, 5], 53).into(),
            std::time::Duration::from_secs(5),
            8192,
            Arc::from(Vec::new().into_boxed_slice()),
            None,
        ));
        AsyncDnsResolver::new(InternetDnsClient { primary, secondary }).with_cache(
            DnsCache::new(DEFAULT_DNS_CLIENT_CACHE_CAPACITY).expect("valid DNS cache capacity"),
        )
    })
}

impl SendAsyncDnsQuery for InternetDnsClient {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move {
            match self.primary.query(domain, record_type).await {
                Ok(response) => Ok(response),
                Err(primary_error) => {
                    self.secondary
                        .query(domain, record_type)
                        .await
                        .map_err(|secondary_error| {
                            crate::Error::new(
                                crate::ErrorKind::Io,
                                format!(
                                    "Internet DNS failed: primary: {}; secondary: {}",
                                    primary_error.message, secondary_error.message
                                ),
                            )
                        })
                }
            }
        })
    }

    fn query_packet_send<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            match self.primary.query_packet(packet).await {
                Ok(response) => Ok(response),
                Err(primary_error) => {
                    self.secondary
                        .query_packet(packet)
                        .await
                        .map_err(|secondary_error| {
                            crate::Error::new(
                                crate::ErrorKind::Io,
                                format!(
                                    "Internet DNS failed: primary: {}; secondary: {}",
                                    primary_error.message, secondary_error.message
                                ),
                            )
                        })
                }
            }
        })
    }
}

pub(crate) async fn resolve_internet_addresses(
    host: &str,
    port: u16,
) -> Result<Vec<std::net::SocketAddr>> {
    if let Ok(address) = host.parse::<std::net::SocketAddr>() {
        return Ok(vec![address]);
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![std::net::SocketAddr::new(ip, port)]);
    }
    let domain = DomainName::new(host.trim_end_matches('.'))?;
    let addresses = internet_dns_resolver()
        .resolve_send(&domain, ResolveStrategy::Default)
        .await?;
    let mut result = addresses
        .v4
        .into_iter()
        .map(|ip| std::net::SocketAddr::new(ip.into(), port))
        .collect::<Vec<_>>();
    result.extend(
        addresses
            .v6
            .into_iter()
            .map(|ip| std::net::SocketAddr::new(ip.into(), port)),
    );
    if result.is_empty() {
        return Err(crate::Error::new(
            crate::ErrorKind::Io,
            format!("Internet DNS resolved {host} to no address"),
        ));
    }
    Ok(result)
}

pub(crate) async fn resolve_internet_server(host: &str, port: u16) -> Result<std::net::SocketAddr> {
    resolve_internet_addresses(host, port)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| {
            crate::Error::new(
                crate::ErrorKind::Io,
                format!("Internet DNS resolved {host} to no address"),
            )
        })
}

#[cfg(unix)]
fn read_system_dns_server() -> Result<std::net::SocketAddr> {
    let contents = std::fs::read_to_string("/etc/resolv.conf").map_err(|error| {
        crate::Error::new(
            crate::ErrorKind::Io,
            format!("read /etc/resolv.conf: {error}"),
        )
    })?;
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        if let Some(address) = fields.next().and_then(|value| value.parse().ok()) {
            return Ok(std::net::SocketAddr::new(address, 53));
        }
    }
    Err(crate::Error::new(
        crate::ErrorKind::NotFound,
        "system DNS configuration has no nameserver",
    ))
}

#[cfg(target_os = "windows")]
fn windows_system_resolver() -> Result<std::sync::Arc<hickory_resolver::TokioResolver>> {
    use std::sync::{Arc, OnceLock};

    static RESOLVER: OnceLock<Arc<hickory_resolver::TokioResolver>> = OnceLock::new();
    if let Some(resolver) = RESOLVER.get() {
        return Ok(Arc::clone(resolver));
    }

    let resolver = Arc::new(
        hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|error| {
                crate::Error::new(
                    crate::ErrorKind::Io,
                    format!("read Windows DNS configuration: {error}"),
                )
            })?
            .build()
            .map_err(|error| {
                crate::Error::new(
                    crate::ErrorKind::Io,
                    format!("build Windows system DNS resolver: {error}"),
                )
            })?,
    );
    let _ = RESOLVER.set(Arc::clone(&resolver));
    Ok(RESOLVER.get().cloned().unwrap_or(resolver))
}

#[cfg(target_os = "windows")]
fn hickory_record_type(record_type: DnsRecordType) -> hickory_proto::rr::RecordType {
    match record_type {
        DnsRecordType::A => hickory_proto::rr::RecordType::A,
        DnsRecordType::Aaaa => hickory_proto::rr::RecordType::AAAA,
        DnsRecordType::Ptr => hickory_proto::rr::RecordType::PTR,
        DnsRecordType::Https => hickory_proto::rr::RecordType::HTTPS,
        DnsRecordType::Svcb => hickory_proto::rr::RecordType::SVCB,
    }
}

#[cfg(target_os = "windows")]
async fn query_windows_system_resolver(
    domain: &DomainName,
    record_type: DnsRecordType,
) -> Result<DnsResponse> {
    let resolver = windows_system_resolver()?;
    let lookup = resolver
        .lookup(
            format!("{}.", domain.as_str()),
            hickory_record_type(record_type),
        )
        .await
        .map_err(|error| {
            crate::Error::new(
                crate::ErrorKind::Io,
                format!("query Windows system DNS for {}: {error}", domain.as_str()),
            )
        })?;
    let packet = lookup.message().to_vec().map_err(|error| {
        crate::Error::new(
            crate::ErrorKind::Protocol,
            format!("encode Windows system DNS response: {error}"),
        )
    })?;
    let id = dns_transaction_id(&packet)?;
    decode_response(&packet, id, record_type)
}

#[cfg(target_os = "windows")]
async fn query_windows_system_packet(packet: &[u8]) -> Result<Vec<u8>> {
    use hickory_proto::op::Message;

    let message = Message::from_vec(packet).map_err(|error| {
        crate::Error::new(
            crate::ErrorKind::Protocol,
            format!("decode Windows system DNS request: {error}"),
        )
    })?;
    let query = message.queries.first().ok_or_else(|| {
        crate::Error::new(crate::ErrorKind::Protocol, "DNS request has no question")
    })?;
    let resolver = windows_system_resolver()?;
    let lookup = resolver
        .lookup(query.name().clone(), query.query_type())
        .await
        .map_err(|error| {
            crate::Error::new(
                crate::ErrorKind::Io,
                format!("query Windows system DNS packet: {error}"),
            )
        })?;
    let response = lookup.message().to_vec().map_err(|error| {
        crate::Error::new(
            crate::ErrorKind::Protocol,
            format!("encode Windows system DNS packet response: {error}"),
        )
    })?;
    rewrite_dns_transaction_id(response, message.metadata.id)
}

#[cfg(any(test, target_os = "windows"))]
fn dns_transaction_id(packet: &[u8]) -> Result<u16> {
    let bytes = packet.get(..2).ok_or_else(|| {
        crate::Error::new(
            crate::ErrorKind::Protocol,
            "DNS response is shorter than its transaction id",
        )
    })?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(any(test, target_os = "windows"))]
pub(super) fn rewrite_dns_transaction_id(mut packet: Vec<u8>, id: u16) -> Result<Vec<u8>> {
    let _ = dns_transaction_id(&packet)?;
    packet[..2].copy_from_slice(&id.to_be_bytes());
    Ok(packet)
}
