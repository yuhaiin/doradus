//! Tokio DNS-over-TCP transport and RFC 1035 server.
//!
//! The synchronous dns_tcp API remains available for callers that explicitly
//! run in a blocking context. Runtime/TUN code uses this module so TCP
//! fallback does not occupy a blocking pool thread per query.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::dns::{
    AsyncDnsHandler, DnsRecordType, DnsResponse, decode_query, decode_response, encode_query,
    encode_response,
};
use crate::dns_resolver_async::{AsyncDnsQuery, SendAsyncDnsQuery};
use crate::{
    BoxFuture, DomainName, Error, ErrorKind, IpSet, LocalBoxFuture, ResolveStrategy, Result,
};

const MAX_FRAME_SIZE: usize = u16::MAX as usize;

#[derive(Debug, Clone)]
pub struct AsyncTcpDnsClient {
    pub server: SocketAddr,
    pub timeout: Duration,
    pub max_packet_size: usize,
}

impl AsyncTcpDnsClient {
    pub async fn query(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
    ) -> Result<DnsResponse> {
        let mut stream = tokio::time::timeout(self.timeout, TcpStream::connect(self.server))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "connect DNS TCP timed out"))?
            .map_err(|error| Error::new(ErrorKind::Io, format!("connect DNS TCP: {error}")))?;
        stream
            .set_nodelay(true)
            .map_err(|error| Error::new(ErrorKind::Io, format!("configure DNS TCP: {error}")))?;

        let id = next_transaction_id();
        let request = encode_query(id, domain, record_type)?;
        let response = tokio::time::timeout(self.timeout, async {
            write_frame(&mut stream, &request).await?;
            read_frame(&mut stream, self.max_packet_size).await
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "DNS TCP query timed out"))??;
        decode_response(&response, id, record_type)
    }

    pub async fn resolve(&self, domain: &DomainName, strategy: ResolveStrategy) -> Result<IpSet> {
        let mut result = IpSet::default();
        match strategy {
            ResolveStrategy::OnlyIpv4 => {
                result.v4 = self.query(domain, DnsRecordType::A).await?.addresses.v4;
            }
            ResolveStrategy::OnlyIpv6 => {
                result.v6 = self.query(domain, DnsRecordType::Aaaa).await?.addresses.v6;
            }
            ResolveStrategy::PreferIpv4 | ResolveStrategy::Default => {
                result.v4 = self.query(domain, DnsRecordType::A).await?.addresses.v4;
                result.v6 = self.query(domain, DnsRecordType::Aaaa).await?.addresses.v6;
            }
            ResolveStrategy::PreferIpv6 => {
                result.v6 = self.query(domain, DnsRecordType::Aaaa).await?.addresses.v6;
                result.v4 = self.query(domain, DnsRecordType::A).await?.addresses.v4;
            }
        }
        Ok(result)
    }
}

impl AsyncDnsQuery for AsyncTcpDnsClient {
    fn query<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> LocalBoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { AsyncTcpDnsClient::query(self, domain, record_type).await })
    }
}

impl SendAsyncDnsQuery for AsyncTcpDnsClient {
    fn query_send<'a>(
        &'a self,
        domain: &'a DomainName,
        record_type: DnsRecordType,
    ) -> BoxFuture<'a, Result<DnsResponse>> {
        Box::pin(async move { AsyncTcpDnsClient::query(self, domain, record_type).await })
    }
}

pub struct AsyncTcpDnsHandler {
    pub client: AsyncTcpDnsClient,
}

impl AsyncTcpDnsHandler {
    pub fn new(client: AsyncTcpDnsClient) -> Self {
        Self { client }
    }
}

impl AsyncDnsHandler for AsyncTcpDnsHandler {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        let question = match decode_query(packet) {
            Ok(question) => question,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        Box::pin(async move {
            let answer = self
                .client
                .query(&question.domain, question.record_type)
                .await?;
            encode_response(packet, &answer)
        })
    }
}

pub struct AsyncTcpDnsServer<H> {
    pub listener: TcpListener,
    pub handler: H,
    pub max_packet_size: usize,
    pub timeout: Duration,
}

impl<H: AsyncDnsHandler> AsyncTcpDnsServer<H> {
    pub async fn bind(
        address: SocketAddr,
        handler: H,
        max_packet_size: usize,
        timeout: Duration,
    ) -> Result<Self> {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind DNS TCP server: {error}")))?;
        Ok(Self {
            listener,
            handler,
            max_packet_size: normalize_max_packet_size(max_packet_size),
            timeout,
        })
    }

    pub async fn serve_once(&self) -> Result<usize> {
        let mut stream = self.accept().await?;
        self.serve_one(&mut stream).await
    }

    /// Accept one TCP connection and serve every length-prefixed DNS query
    /// until the peer closes it. RFC 1035 permits multiple messages on one
    /// connection; keeping this path separate preserves `serve_once` as a
    /// convenient one-request fixture for callers that want it.
    pub async fn serve_connection(&self) -> Result<usize> {
        let stream = self.accept().await?;
        self.serve_stream(stream).await
    }

    async fn accept(&self) -> Result<TcpStream> {
        let (stream, _) = self
            .listener
            .accept()
            .await
            .map_err(|error| Error::new(ErrorKind::Io, format!("accept DNS TCP: {error}")))?;
        stream
            .set_nodelay(true)
            .map_err(|error| Error::new(ErrorKind::Io, format!("configure DNS TCP: {error}")))?;
        Ok(stream)
    }

    async fn serve_stream(&self, mut stream: TcpStream) -> Result<usize> {
        let mut total = 0;
        loop {
            let bytes = tokio::time::timeout(self.timeout, async {
                let request = match read_frame_or_eof(&mut stream, self.max_packet_size).await? {
                    Some(request) => request,
                    None => return Ok(None),
                };
                let response = self.handler.answer(&request).await?;
                Ok(Some(write_frame(&mut stream, &response).await?))
            })
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "DNS TCP server query timed out"))??;
            match bytes {
                Some(bytes) => total += bytes,
                None => return Ok(total),
            }
        }
    }

    async fn serve_one(&self, stream: &mut TcpStream) -> Result<usize> {
        let response = tokio::time::timeout(self.timeout, async {
            let request = read_frame(stream, self.max_packet_size).await?;
            self.handler.answer(&request).await
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "DNS TCP server query timed out"))??;
        tokio::time::timeout(self.timeout, write_frame(stream, &response))
            .await
            .map_err(|_| Error::new(ErrorKind::Timeout, "DNS TCP server write timed out"))??;
        Ok(response.len() + 2)
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
    }

    pub async fn serve_until<S>(&self, shutdown: S) -> Result<()>
    where
        S: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        let mut connections = FuturesUnordered::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted
                        .map_err(|error| Error::new(ErrorKind::Io, format!("accept DNS TCP: {error}")))?;
                    stream
                        .set_nodelay(true)
                        .map_err(|error| Error::new(ErrorKind::Io, format!("configure DNS TCP: {error}")))?;
                    connections.push(self.serve_stream(stream));
                }
                result = connections.next(), if !connections.is_empty() => {
                    result.transpose()?;
                }
            }
        }
    }
}

async fn write_frame(stream: &mut TcpStream, packet: &[u8]) -> Result<usize> {
    if packet.len() > MAX_FRAME_SIZE {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("DNS TCP frame is too large: {}", packet.len()),
        ));
    }
    let length = (packet.len() as u16).to_be_bytes();
    stream
        .write_all(&length)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("write DNS TCP frame: {error}")))?;
    stream
        .write_all(packet)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("write DNS TCP frame: {error}")))?;
    Ok(packet.len() + 2)
}

async fn read_frame(stream: &mut TcpStream, max_packet_size: usize) -> Result<Vec<u8>> {
    read_frame_or_eof(stream, max_packet_size)
        .await?
        .ok_or_else(|| Error::new(ErrorKind::Closed, "DNS TCP peer closed before a frame"))
}

async fn read_frame_or_eof(
    stream: &mut TcpStream,
    max_packet_size: usize,
) -> Result<Option<Vec<u8>>> {
    let mut length = [0u8; 2];
    let first = stream.read(&mut length[..1]).await.map_err(read_error)?;
    if first == 0 {
        return Ok(None);
    }
    stream
        .read_exact(&mut length[1..])
        .await
        .map_err(read_error)?;
    let length = u16::from_be_bytes(length) as usize;
    let max_packet_size = normalize_max_packet_size(max_packet_size);
    if length > max_packet_size {
        return Err(Error::new(
            ErrorKind::Protocol,
            format!("DNS TCP frame exceeds configured limit: {length} > {max_packet_size}"),
        ));
    }
    let mut packet = vec![0u8; length];
    stream.read_exact(&mut packet).await.map_err(read_error)?;
    Ok(Some(packet))
}

fn normalize_max_packet_size(value: usize) -> usize {
    value.clamp(512, MAX_FRAME_SIZE)
}

fn read_error(error: std::io::Error) -> Error {
    let kind = match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ErrorKind::Timeout,
        std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::BrokenPipe => ErrorKind::Closed,
        _ => ErrorKind::Io,
    };
    Error::new(kind, format!("read DNS TCP frame: {error}"))
}

fn next_transaction_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    struct StaticHandler;

    impl AsyncDnsHandler for StaticHandler {
        fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
            Box::pin(async move {
                let question = decode_query(packet)?;
                encode_response(
                    packet,
                    &DnsResponse {
                        addresses: IpSet {
                            v4: vec![Ipv4Addr::new(192, 0, 2, 53)],
                            v6: Vec::new(),
                        },
                        ptr_names: Vec::new(),
                        service_bindings: Vec::new(),
                        minimum_ttl: Some(30),
                    },
                )
                .and_then(|response| {
                    decode_response(&response, question.id, question.record_type)?;
                    Ok(response)
                })
            })
        }
    }

    #[test]
    fn async_tcp_client_and_server_round_trip_preserves_transaction() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let server = AsyncTcpDnsServer::bind(
                "127.0.0.1:0".parse().unwrap(),
                StaticHandler,
                2048,
                Duration::from_secs(1),
            )
            .await
            .unwrap();
            let client = AsyncTcpDnsClient {
                server: server.local_addr().unwrap(),
                timeout: Duration::from_secs(1),
                max_packet_size: 2048,
            };
            let domain = DomainName::new("example.com").unwrap();
            let (server_result, client_result) =
                tokio::join!(server.serve_once(), client.query(&domain, DnsRecordType::A));
            assert!(server_result.unwrap() > 2);
            assert_eq!(
                client_result.unwrap().addresses.v4,
                vec![Ipv4Addr::new(192, 0, 2, 53)]
            );
        });
    }

    #[test]
    fn async_tcp_server_reuses_one_connection_for_multiple_queries() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let server = AsyncTcpDnsServer::bind(
                "127.0.0.1:0".parse().unwrap(),
                StaticHandler,
                2048,
                Duration::from_secs(1),
            )
            .await
            .unwrap();
            let address = server.local_addr().unwrap();
            let domain = DomainName::new("example.com").unwrap();
            let client = async move {
                let mut stream = TcpStream::connect(address).await.unwrap();
                for id in [0x1001, 0x1002] {
                    let request = encode_query(id, &domain, DnsRecordType::A).unwrap();
                    write_frame(&mut stream, &request).await.unwrap();
                    let response = read_frame(&mut stream, 2048).await.unwrap();
                    let answer = decode_response(&response, id, DnsRecordType::A).unwrap();
                    assert_eq!(answer.addresses.v4, vec![Ipv4Addr::new(192, 0, 2, 53)]);
                }
            };
            let (server_result, ()) = tokio::join!(server.serve_connection(), client);
            assert!(server_result.unwrap() > 4);
        });
    }

    #[test]
    fn async_tcp_server_accepts_multiple_connections_until_shutdown() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let server = AsyncTcpDnsServer::bind(
                "127.0.0.1:0".parse().unwrap(),
                StaticHandler,
                2048,
                Duration::from_secs(1),
            )
            .await
            .unwrap();
            let address = server.local_addr().unwrap();
            let (stop, stop_signal) = tokio::sync::oneshot::channel();
            let server_future = server.serve_until(async move {
                let _ = stop_signal.await;
            });
            let clients = async move {
                let first = AsyncTcpDnsClient {
                    server: address,
                    timeout: Duration::from_secs(1),
                    max_packet_size: 2048,
                };
                let second = first.clone();
                let domain = DomainName::new("example.com").unwrap();
                let (first, second) = tokio::join!(
                    first.query(&domain, DnsRecordType::A),
                    second.query(&domain, DnsRecordType::A)
                );
                let _ = stop.send(());
                (first, second)
            };
            let (server_result, (first, second)) = tokio::join!(server_future, clients);
            server_result.unwrap();
            assert_eq!(
                first.unwrap().addresses.v4,
                vec![Ipv4Addr::new(192, 0, 2, 53)]
            );
            assert_eq!(
                second.unwrap().addresses.v4,
                vec![Ipv4Addr::new(192, 0, 2, 53)]
            );
        });
    }
}
