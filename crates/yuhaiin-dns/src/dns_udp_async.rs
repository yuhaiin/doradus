//! Tokio UDP DNS transport and packet-level resolver adapter.
//!
//! The synchronous [`crate::dns::UdpDnsClient`] remains useful for blocking
//! callers. This module keeps the async/TUN path independent of blocking
//! sockets and preserves the caller's DNS transaction when it builds a reply.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use futures_util::future::BoxFuture;
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, oneshot};

use crate::dns::{
    AsyncDnsHandler, DnsRecordType, DnsResponse, decode_raw_query_key, decode_response,
    encode_query, truncate_dns_response, validate_query_packet, validate_response_packet,
};
use crate::transport::bind_udp_socket;
use crate::{DomainName, Error, ErrorKind, IpSet, LocalBoxFuture, ResolveStrategy, Result};

type PendingKey = (u16, DomainName, u16);

struct AsyncUdpDnsClientState {
    socket: Mutex<Option<Arc<UdpSocket>>>,
    pending: Mutex<HashMap<PendingKey, oneshot::Sender<Result<Vec<u8>>>>>,
    shutdown: Arc<Notify>,
}

struct ReceiverCleanup {
    state: Weak<AsyncUdpDnsClientState>,
    socket: Arc<UdpSocket>,
}

impl Drop for ReceiverCleanup {
    fn drop(&mut self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        if let Ok(mut stored) = state.socket.lock()
            && stored
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.socket))
        {
            *stored = None;
        }
    }
}

impl Default for AsyncUdpDnsClientState {
    fn default() -> Self {
        Self {
            socket: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            shutdown: Arc::new(Notify::new()),
        }
    }
}

#[derive(Clone)]
pub struct AsyncUdpDnsClient {
    pub server: SocketAddr,
    pub timeout: Duration,
    pub max_packet_size: usize,
    pub local_bind_addresses: Arc<[IpAddr]>,
    pub bind_interface: Option<String>,
    state: Arc<AsyncUdpDnsClientState>,
}

impl AsyncUdpDnsClient {
    pub fn new(
        server: SocketAddr,
        timeout: Duration,
        max_packet_size: usize,
        local_bind_addresses: Arc<[IpAddr]>,
        bind_interface: Option<String>,
    ) -> Self {
        Self {
            server,
            timeout,
            max_packet_size,
            local_bind_addresses,
            bind_interface,
            state: Arc::new(AsyncUdpDnsClientState::default()),
        }
    }

    async fn socket(&self) -> Result<Arc<UdpSocket>> {
        if let Some(socket) = self
            .state
            .socket
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS UDP socket lock poisoned"))?
            .clone()
        {
            return Ok(socket);
        }

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
        let socket = Arc::new(
            bind_udp_socket(
                bind_address,
                self.server,
                self.bind_interface.as_deref(),
                "DNS",
            )
            .await?,
        );

        let mut stored = self
            .state
            .socket
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS UDP socket lock poisoned"))?;
        if let Some(existing) = stored.as_ref() {
            return Ok(existing.clone());
        }
        *stored = Some(socket.clone());
        drop(stored);

        let state: Weak<AsyncUdpDnsClientState> = Arc::downgrade(&self.state);
        let shutdown = self.state.shutdown.clone();
        let server = self.server;
        let response_buffer_size = self.max_packet_size.max(512);
        let receiver_socket = socket.clone();
        tokio::spawn(async move {
            let _cleanup = ReceiverCleanup {
                state: state.clone(),
                socket: receiver_socket.clone(),
            };
            let mut response = vec![0; response_buffer_size];
            loop {
                let result = tokio::select! {
                    _ = shutdown.notified() => return,
                    result = receiver_socket.recv_from(&mut response) => result,
                };
                let (size, peer) = match result {
                    Ok(value) => value,
                    Err(error) => {
                        let Some(state) = state.upgrade() else {
                            return;
                        };
                        if let Ok(mut stored) = state.socket.lock()
                            && stored
                                .as_ref()
                                .is_some_and(|current| Arc::ptr_eq(current, &receiver_socket))
                        {
                            *stored = None;
                        }
                        if let Ok(mut pending) = state.pending.lock() {
                            for (_, sender) in pending.drain() {
                                let _ = sender.send(Err(Error::new(
                                    ErrorKind::Io,
                                    format!("receive DNS response: {error}"),
                                )));
                            }
                        }
                        return;
                    }
                };
                if peer != server || size < 2 {
                    continue;
                }
                let packet = response[..size].to_vec();
                let Ok((domain, record_type)) = decode_raw_query_key(&packet) else {
                    continue;
                };
                let key = (
                    u16::from_be_bytes([packet[0], packet[1]]),
                    domain,
                    record_type,
                );
                let Some(state) = state.upgrade() else {
                    return;
                };
                if let Ok(mut pending) = state.pending.lock()
                    && let Some(sender) = pending.remove(&key)
                {
                    let _ = sender.send(Ok(packet));
                }
            }
        });
        Ok(socket)
    }

    async fn query_packet_once(&self, packet: &[u8]) -> Result<Vec<u8>> {
        validate_query_packet(packet)?;
        let (domain, record_type) = decode_raw_query_key(packet)?;
        let request_id = u16::from_be_bytes([packet[0], packet[1]]);
        let key = (request_id, domain, record_type);
        let socket = self.socket().await?;
        let (sender, receiver) = oneshot::channel();
        self.state
            .pending
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "DNS UDP pending lock poisoned"))?
            .insert(key.clone(), sender);
        if let Err(error) = socket.send_to(packet, self.server).await {
            if let Ok(mut pending) = self.state.pending.lock() {
                pending.remove(&key);
            }
            return Err(Error::new(
                ErrorKind::Io,
                format!("send DNS query: {error}"),
            ));
        }
        match tokio::time::timeout(self.timeout, receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(Error::new(
                ErrorKind::Closed,
                "DNS UDP response waiter closed",
            )),
            Err(_) => {
                if let Ok(mut pending) = self.state.pending.lock() {
                    pending.remove(&key);
                }
                Err(Error::new(ErrorKind::Timeout, "DNS UDP query timed out"))
            }
        }
    }

    /// Send a complete DNS message without narrowing its QTYPE to the
    /// address-oriented resolver model. This is used for MX/TXT/CNAME and
    /// DNSSEC queries received by the runtime DNS server.
    pub async fn query_packet(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let response = self.query_packet_once(packet).await?;
        validate_response_packet(packet, &response)?;
        let message = hickory_proto::op::Message::from_vec(&response)
            .map_err(|error| Error::new(ErrorKind::Protocol, error.to_string()))?;
        if message.metadata.truncation {
            let client = crate::dns_tcp_async::AsyncTcpDnsClient {
                server: self.server,
                timeout: self.timeout,
                max_packet_size: self.max_packet_size,
                local_bind_addresses: self.local_bind_addresses.clone(),
                bind_interface: self.bind_interface.clone(),
            };
            return client.query_packet(packet).await;
        }
        Ok(response)
    }

    pub async fn query(
        &self,
        domain: &DomainName,
        record_type: DnsRecordType,
    ) -> Result<DnsResponse> {
        let id = next_transaction_id();
        let request = encode_query(id, domain, record_type)?;
        let response = self.query_packet(&request).await?;
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

impl Drop for AsyncUdpDnsClient {
    fn drop(&mut self) {
        // The receiver task intentionally keeps only a Weak reference to the
        // client state. Wake it when the last public client handle disappears
        // so reloads do not accumulate one task and socket per resolver.
        if Arc::strong_count(&self.state) == 1 {
            self.state.shutdown.notify_one();
        }
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
    fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move { self.client.query_packet(packet).await })
    }
}

pub struct AsyncUdpDnsServer<H> {
    pub socket: UdpSocket,
    pub handler: H,
    pub max_packet_size: usize,
    pub max_inflight: usize,
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
            max_inflight: 150,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
    }

    pub async fn serve_once(&self) -> Result<usize> {
        self.serve_once_from().await.map(|(size, _)| size)
    }

    pub async fn serve_once_from(&self) -> Result<(usize, SocketAddr)> {
        let mut request = vec![0; self.max_packet_size];
        let (size, peer) =
            self.socket.recv_from(&mut request).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("receive DNS request: {error}"))
            })?;
        let packet = self.handler.answer(&request[..size]).await?;
        let packet = truncate_dns_response(&request[..size], &packet)?;
        let sent =
            self.socket.send_to(&packet, peer).await.map_err(|error| {
                Error::new(ErrorKind::Io, format!("send DNS response: {error}"))
            })?;
        Ok((sent, peer))
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
        let mut pending = FuturesUnordered::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                result = pending.next(), if !pending.is_empty() => {
                    // Go logs and drops an individual malformed/upstream
                    // request while keeping the listener alive.
                    let _ = result;
                }
                result = async {
                    let mut request = vec![0; self.max_packet_size];
                    let (size, peer) = self.socket.recv_from(&mut request).await
                        .map_err(|error| Error::new(ErrorKind::Io, format!("receive DNS request: {error}")))?;
                    Ok::<_, Error>((request[..size].to_vec(), peer))
                } => {
                    let (request, peer) = result?;
                    if pending.len() >= self.max_inflight.max(1)
                        && let Some(result) = pending.next().await
                    {
                        let _ = result;
                    }
                    pending.push(self.serve_packet(request, peer));
                }
            }
        }
    }

    fn serve_packet<'a>(
        &'a self,
        request: Vec<u8>,
        peer: SocketAddr,
    ) -> LocalBoxFuture<'a, Result<(usize, SocketAddr)>> {
        Box::pin(async move {
            let response = self.handler.answer(&request).await?;
            let response = truncate_dns_response(&request, &response)?;
            let sent = self
                .socket
                .send_to(&response, peer)
                .await
                .map_err(|error| {
                    Error::new(ErrorKind::Io, format!("send DNS response: {error}"))
                })?;
            Ok((sent, peer))
        })
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
    use crate::dns::{decode_query, encode_query, encode_raw_query, encode_response};

    #[test]
    fn async_udp_client_and_handler_round_trip_with_original_transaction() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            struct StaticHandler;

            impl AsyncDnsHandler for StaticHandler {
                fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
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
                let (_, first_peer) = server.serve_once_from().await.unwrap();
                let (_, second_peer) = server.serve_once_from().await.unwrap();
                assert_eq!(first_peer.ip(), IpAddr::V4("127.0.0.2".parse().unwrap()));
                assert_eq!(second_peer.ip(), IpAddr::V4("127.0.0.2".parse().unwrap()));
            };

            let client = AsyncUdpDnsClient::new(
                server_address,
                Duration::from_secs(1),
                4096,
                Arc::from(vec!["127.0.0.2".parse::<IpAddr>().unwrap()].into_boxed_slice()),
                None,
            );
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
    fn async_udp_client_forwards_unmodeled_qtypes_as_raw_packets() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(async {
                let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                let address = socket.local_addr().unwrap();
                let server = tokio::spawn(async move {
                    let mut request = vec![0; 2048];
                    let (size, peer) = socket.recv_from(&mut request).await.unwrap();
                    let request = &request[..size];
                    assert_eq!(
                        decode_query(request).unwrap_err().kind,
                        ErrorKind::Unsupported
                    );
                    let mut response = request.to_vec();
                    response[2] |= 0x80;
                    socket.send_to(&response, peer).await.unwrap();
                });

                let client = AsyncUdpDnsClient::new(
                    address,
                    Duration::from_secs(1),
                    2048,
                    Arc::from(Vec::<IpAddr>::new().into_boxed_slice()),
                    None,
                );
                let query = encode_raw_query(0x5a5a, &DomainName::new("example.com").unwrap(), 16)?;
                let response = client.query_packet(&query).await?;
                assert_eq!(&response[..2], &query[..2]);
                server.await.unwrap();
                Ok::<_, Error>(())
            })
            .unwrap();
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
                fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
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
            let client = AsyncUdpDnsClient::new(
                server_address,
                Duration::from_secs(1),
                4096,
                Arc::from(Vec::<IpAddr>::new().into_boxed_slice()),
                None,
            );
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
