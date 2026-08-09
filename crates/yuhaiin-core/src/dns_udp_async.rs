//! Tokio UDP DNS transport and packet-level resolver adapter.
//!
//! The synchronous [`crate::dns::UdpDnsClient`] remains useful for blocking
//! callers. This module keeps the async/TUN path independent of blocking
//! sockets and preserves the caller's DNS transaction when it builds a reply.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::dns::{
    AsyncDnsHandler, DnsRecordType, DnsResponse, decode_query, decode_response, encode_query,
    encode_response,
};
use crate::{DomainName, Error, ErrorKind, IpSet, LocalBoxFuture, ResolveStrategy, Result};

#[derive(Debug, Clone)]
pub struct AsyncUdpDnsClient {
    pub server: SocketAddr,
    pub timeout: Duration,
    pub max_packet_size: usize,
    pub local_bind_addresses: Arc<[IpAddr]>,
}

impl AsyncUdpDnsClient {
    pub async fn query(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
    ) -> Result<DnsResponse> {
        let default_bind = if self.server.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let bind_address = self
            .local_bind_addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == self.server.is_ipv4())
            .map(|address| SocketAddr::new(address, 0))
            .unwrap_or(default_bind);
        let socket = UdpSocket::bind(bind_address)
            .await
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind DNS UDP socket: {error}")))?;
        let id = next_transaction_id();
        let request = encode_query(id, domain, record_type)?;
        let max_packet_size = self.max_packet_size.max(512);
        let server = self.server;
        tokio::time::timeout(self.timeout, async move {
            socket
                .send_to(&request, server)
                .await
                .map_err(|error| Error::new(ErrorKind::Io, format!("send DNS query: {error}")))?;
            let mut response = vec![0; max_packet_size];
            loop {
                let (size, peer) = socket.recv_from(&mut response).await.map_err(|error| {
                    Error::new(ErrorKind::Io, format!("receive DNS response: {error}"))
                })?;
                if peer != server {
                    continue;
                }
                return decode_response(&response[..size], id, record_type);
            }
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout, "DNS UDP query timed out"))?
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

pub struct AsyncUdpDnsHandler {
    pub client: AsyncUdpDnsClient,
}

impl AsyncUdpDnsHandler {
    pub fn new(client: AsyncUdpDnsClient) -> Self {
        Self { client }
    }
}

impl AsyncDnsHandler for AsyncUdpDnsHandler {
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

pub struct AsyncUdpDnsServer<H> {
    pub socket: UdpSocket,
    pub handler: H,
    pub max_packet_size: usize,
}

impl<H: AsyncDnsHandler> AsyncUdpDnsServer<H> {
    pub async fn bind(address: SocketAddr, handler: H, max_packet_size: usize) -> Result<Self> {
        let socket = UdpSocket::bind(address)
            .await
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind DNS UDP server: {error}")))?;
        Ok(Self {
            socket,
            handler,
            max_packet_size: max_packet_size.max(512),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
    }

    pub async fn serve_once(&self) -> Result<usize> {
        let mut request = vec![0; self.max_packet_size];
        let (size, peer) =
            self.socket.recv_from(&mut request).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("receive DNS request: {error}"))
            })?;
        let packet = self.handler.answer(&request[..size]).await?;
        self.socket
            .send_to(&packet, peer)
            .await
            .map_err(|error| Error::new(ErrorKind::Io, format!("send DNS response: {error}")))
    }

    /// Serve requests until the owner signals shutdown.
    ///
    /// The handler is deliberately kept in the server instead of being moved
    /// into a spawned task, so dropping the returned future also cancels an
    /// in-flight upstream DNS query and releases the socket with the TUN
    /// runtime owner.
    pub async fn serve_until<S>(&self, shutdown: S) -> Result<()>
    where
        S: Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                result = self.serve_once() => {
                    result?;
                }
            }
        }
    }
}

fn next_transaction_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::encode_query;

    #[test]
    fn async_udp_client_and_handler_round_trip_with_original_transaction() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            struct StaticHandler;

            impl AsyncDnsHandler for StaticHandler {
                fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
                    Box::pin(async move {
                        encode_response(
                            packet,
                            &DnsResponse {
                                addresses: IpSet {
                                    v4: vec!["192.0.2.55".parse().unwrap()],
                                    v6: Vec::new(),
                                },
                                ptr_names: Vec::new(),
                                service_bindings: Vec::new(),
                                minimum_ttl: Some(30),
                            },
                        )
                    })
                }
            }

            let server =
                AsyncUdpDnsServer::bind((Ipv4Addr::LOCALHOST, 0).into(), StaticHandler, 4096)
                    .await
                    .unwrap();
            let server_address = server.local_addr().unwrap();
            let server_future = async move {
                server.serve_once().await.unwrap();
                server.serve_once().await.unwrap();
            };

            let client = AsyncUdpDnsClient {
                server: server_address,
                timeout: Duration::from_secs(1),
                max_packet_size: 4096,
                local_bind_addresses: Arc::from(
                    vec!["127.0.0.2".parse::<IpAddr>().unwrap()].into_boxed_slice(),
                ),
            };
            let domain = DomainName::new("example.com").unwrap();
            let client_future = async move {
                let direct = client.query(&domain, DnsRecordType::A).await.unwrap();
                assert_eq!(
                    direct.addresses.v4,
                    vec!["192.0.2.55".parse::<Ipv4Addr>().unwrap()]
                );

                let handler = AsyncUdpDnsHandler::new(client);
                let request = encode_query(0x4a2b, &domain, DnsRecordType::A).unwrap();
                let response = handler.answer(&request).await.unwrap();
                let decoded = decode_response(&response, 0x4a2b, DnsRecordType::A).unwrap();
                assert_eq!(
                    decoded.addresses.v4,
                    vec!["192.0.2.55".parse::<Ipv4Addr>().unwrap()]
                );
            };
            tokio::join!(server_future, client_future);
        });
    }

    #[test]
    fn async_udp_server_serve_until_stops_after_owner_signal() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            struct StaticHandler;

            impl AsyncDnsHandler for StaticHandler {
                fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
                    Box::pin(async move {
                        encode_response(
                            packet,
                            &DnsResponse {
                                addresses: IpSet {
                                    v4: vec!["192.0.2.56".parse().unwrap()],
                                    v6: Vec::new(),
                                },
                                ptr_names: Vec::new(),
                                service_bindings: Vec::new(),
                                minimum_ttl: Some(30),
                            },
                        )
                    })
                }
            }

            let server =
                AsyncUdpDnsServer::bind((Ipv4Addr::LOCALHOST, 0).into(), StaticHandler, 4096)
                    .await
                    .unwrap();
            let server_address = server.local_addr().unwrap();
            let (stop, stop_signal) = tokio::sync::oneshot::channel();
            let server_future = async move {
                server
                    .serve_until(async move {
                        let _ = stop_signal.await;
                    })
                    .await
            };
            let client = AsyncUdpDnsClient {
                server: server_address,
                timeout: Duration::from_secs(1),
                max_packet_size: 4096,
                local_bind_addresses: Arc::from(Vec::<IpAddr>::new().into_boxed_slice()),
            };
            let client_future = async {
                let answer = client
                    .query(&DomainName::new("example.com").unwrap(), DnsRecordType::A)
                    .await;
                let _ = stop.send(());
                answer
            };
            let (answer, server_result) = tokio::join!(client_future, server_future);
            answer.unwrap();
            server_result.unwrap();
        });
    }
}
