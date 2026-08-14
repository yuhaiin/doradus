//! DNS-over-TLS transport using the RFC 1035 two-byte length prefix.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use yuhaiin_core::dns::{DnsRecordType, DnsResponse, decode_response, encode_query};
use yuhaiin_core::dns_resolver_async::{
    AsyncDnsQuery, AsyncDnsResolver, AsyncIpResolver, SendAsyncDnsQuery,
};
use yuhaiin_core::proxy::BoxAsyncStream;
use yuhaiin_core::{BoxFuture, DomainName, Error, ErrorKind, LocalBoxFuture, Result};
use yuhaiin_store::{GoResolverRuntimeConfig, GoResolverTransport};

use crate::doh_tls::{RustCryptoTlsDialer, client_config, tls_server_name};
use crate::resolver::{
    BuiltinResolverFactory, ResolverProxyBridge, ResolverTransportFactory, TimeoutResolver,
};

const MAX_DNS_TCP_FRAME: usize = u16::MAX as usize;

#[derive(Clone)]
struct RustCryptoDotClient {
    dialer: RustCryptoTlsDialer,
    host: String,
    port: u16,
    server_name: String,
    max_packet_size: usize,
    proxy_bridge: Option<Arc<ResolverProxyBridge>>,
    use_proxy: bool,
}

impl RustCryptoDotClient {
    async fn query(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        let request = encode_query(next_transaction_id(), domain, record_type)?;
        if request.len() > MAX_DNS_TCP_FRAME {
            return Err(Error::new(ErrorKind::Protocol, "DoT request is too large"));
        }
        let proxied = match &self.proxy_bridge {
            Some(bridge) => match bridge.connect(&self.host, self.port, self.use_proxy).await {
                Ok(stream) => stream,
                Err(error) => return Err(error),
            },
            None => None,
        };
        let result = async {
            let raw = match proxied {
                Some(stream) => stream,
                None => Box::new(self.dialer.connect_tcp(&self.host, self.port).await?)
                    as BoxAsyncStream,
            };
            self.dialer
                .connect_boxed_stream(&self.server_name, raw)
                .await
        }
        .await;
        if let Err(error) = &result
            && let Some(bridge) = &self.proxy_bridge
        {
            bridge.record_failure(&self.host, self.port, error);
        }
        let mut stream = result?;
        write_frame(&mut stream, &request).await?;
        let response = read_frame(&mut stream, self.max_packet_size).await?;
        decode_response(
            &response,
            u16::from_be_bytes([request[0], request[1]]),
            record_type,
        )
    }
}

impl SendAsyncDnsQuery for RustCryptoDotClient {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { self.query(domain, record_type).await })
    }
}

impl AsyncDnsQuery for RustCryptoDotClient {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { self.query(domain, record_type).await })
    }
}

#[derive(Clone)]
pub struct RustCryptoDotResolverFactory {
    pub builtin: BuiltinResolverFactory,
    client_config: Arc<ClientConfig>,
    proxy_bridge: Option<Arc<ResolverProxyBridge>>,
}

impl RustCryptoDotResolverFactory {
    pub fn new(
        root_certificates: &[Vec<u8>],
        timeout: Duration,
        cache_capacity: usize,
    ) -> Result<Self> {
        Ok(Self::from_client_config(
            client_config(crate::doh_tls::root_store(root_certificates)?)?,
            timeout,
            cache_capacity,
        ))
    }

    pub fn from_client_config(
        client_config: Arc<ClientConfig>,
        timeout: Duration,
        cache_capacity: usize,
    ) -> Self {
        Self {
            builtin: BuiltinResolverFactory::new(timeout, cache_capacity),
            client_config,
            proxy_bridge: None,
        }
    }

    pub fn with_proxy_bridge(mut self, bridge: Arc<ResolverProxyBridge>) -> Self {
        self.proxy_bridge = Some(bridge);
        self
    }
}

impl ResolverTransportFactory for RustCryptoDotResolverFactory {
    fn build(&self, config: &GoResolverRuntimeConfig) -> Result<Arc<dyn AsyncIpResolver>> {
        self.build_with_policy(config, &[])
    }

    fn build_with_policy(
        &self,
        config: &GoResolverRuntimeConfig,
        local_bind_addresses: &[IpAddr],
    ) -> Result<Arc<dyn AsyncIpResolver>> {
        if config.transport != GoResolverTransport::Dot {
            return self.builtin.build_with_policy(config, local_bind_addresses);
        }
        let (host, port) = split_dot_endpoint(&config.host, &config.id)?;
        let server_name = config
            .tls_server_name
            .clone()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| host.trim_matches(['[', ']']).to_owned());
        let _ = tls_server_name(&server_name)?;
        let client = RustCryptoDotClient {
            dialer: RustCryptoTlsDialer::from_config(
                self.client_config.clone(),
                self.builtin.timeout,
            )
            .with_local_bind_addresses(local_bind_addresses),
            host,
            port,
            server_name,
            max_packet_size: self.builtin.max_packet_size,
            proxy_bridge: self.proxy_bridge.clone(),
            use_proxy: self
                .proxy_bridge
                .as_ref()
                .is_some_and(|bridge| bridge.is_proxy_resolver(&config.id)),
        };
        let resolver = AsyncDnsResolver::new(client).with_cache(yuhaiin_core::dns::DnsCache::new(
            self.builtin.cache_capacity.max(1),
        )?);
        Ok(Arc::new(TimeoutResolver::new(
            Arc::new(resolver),
            self.builtin.timeout,
        )))
    }
}

fn split_dot_endpoint(value: &str, id: &str) -> Result<(String, u16)> {
    let value = value.trim();
    if value.is_empty() || value.contains("://") {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("resolver {id} has an invalid DoT endpoint"),
        ));
    }
    if let Ok(address) = value.parse::<std::net::SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return Ok((value.to_owned(), 853));
    }
    if let Some((host, port)) = value.rsplit_once(':')
        && !host.contains(':')
        && let Ok(port) = port.parse::<u16>()
        && port != 0
    {
        return Ok((host.trim_matches(['[', ']']).to_owned(), port));
    }
    Ok((value.trim_matches(['[', ']']).to_owned(), 853))
}

async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, packet: &[u8]) -> Result<()> {
    stream
        .write_all(&(packet.len() as u16).to_be_bytes())
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("write DoT frame: {error}")))?;
    stream
        .write_all(packet)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("write DoT frame: {error}")))
}

async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_packet_size: usize,
) -> Result<Vec<u8>> {
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await.map_err(read_error)?;
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 || length > max_packet_size.min(MAX_DNS_TCP_FRAME) {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("DoT response frame exceeds configured limit: {length}"),
        ));
    }
    let mut packet = vec![0u8; length];
    stream.read_exact(&mut packet).await.map_err(read_error)?;
    Ok(packet)
}

fn read_error(error: std::io::Error) -> Error {
    let kind = match error.kind() {
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe => ErrorKind::Closed,
        _ => ErrorKind::Io,
    };
    Error::new(kind, format!("read DoT frame: {error}"))
}

fn next_transaction_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
