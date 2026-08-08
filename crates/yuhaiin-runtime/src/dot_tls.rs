//! DNS-over-TLS transport using the RFC 1035 two-byte length prefix.

use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use yuhaiin_core::dns::{DnsRecordType, DnsResponse, decode_response, encode_query};
use yuhaiin_core::dns_resolver_async::{
    AsyncDnsQuery, AsyncDnsResolver, AsyncIpResolver, SendAsyncDnsQuery,
};
use yuhaiin_core::{BoxFuture, DomainName, Error, ErrorKind, LocalBoxFuture, Result};
use yuhaiin_store::{GoResolverRuntimeConfig, GoResolverTransport};

use crate::doh_tls::{RustCryptoTlsDialer, client_config, tls_server_name};
use crate::resolver::{BuiltinResolverFactory, ResolverTransportFactory, TimeoutResolver};

const MAX_DNS_TCP_FRAME: usize = u16::MAX as usize;

#[derive(Clone)]
struct RustCryptoDotClient {
    dialer: RustCryptoTlsDialer,
    host: String,
    port: u16,
    server_name: String,
    max_packet_size: usize,
}

impl RustCryptoDotClient {
    async fn query(&self, domain: &DomainName, record_type: DnsRecordType) -> Result<DnsResponse> {
        let request = encode_query(next_transaction_id(), domain, record_type)?;
        if request.len() > MAX_DNS_TCP_FRAME {
            return Err(Error::new(ErrorKind::Protocol, "DoT request is too large"));
        }
        let mut stream = self
            .dialer
            .connect(&self.host, self.port, &self.server_name)
            .await?;
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
        }
    }
}

impl ResolverTransportFactory for RustCryptoDotResolverFactory {
    fn build(&self, config: &GoResolverRuntimeConfig) -> Result<Arc<dyn AsyncIpResolver>> {
        if config.transport != GoResolverTransport::Dot {
            return self.builtin.build(config);
        }
        let (host, port) = split_dot_endpoint(&config.host, &config.id)?;
        let server_name = config
            .tls_server_name
            .clone()
            .unwrap_or_else(|| host.trim_matches(['[', ']']).to_owned());
        let _ = tls_server_name(&server_name)?;
        let client = RustCryptoDotClient {
            dialer: RustCryptoTlsDialer::from_config(
                self.client_config.clone(),
                self.builtin.timeout,
            ),
            host,
            port,
            server_name,
            max_packet_size: self.builtin.max_packet_size,
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
    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.contains(':') {
            if let Ok(port) = port.parse::<u16>() {
                if port != 0 {
                    return Ok((host.trim_matches(['[', ']']).to_owned(), port));
                }
            }
        }
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
