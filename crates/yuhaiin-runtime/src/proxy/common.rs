use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf, split,
};

use yuhaiin_core::flow::{
    Flow as TunFlow, FlowDirection as TunFlowDirection, FlowKey as TunFlowKey,
    FlowObserver as TunFlowObserver, FlowObserverGuard,
};
use yuhaiin_core::proxy::{
    AsyncDatagram, AsyncProxy, AsyncProxySelector, BoxAsyncStream, stream_local_addr,
};
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Result};

use crate::inbound::{InboundDnsHandler, InboundDnsPolicy};
use crate::{ConnectionMonitor, RuntimeProxySelector};

/// Matches Go's `configuration.UDPIdleTimeout` (90 seconds).
pub(crate) const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const TEST_UDP_IDLE_TIMEOUT_ENV: &str = "YUHAIIN_TEST_UDP_IDLE_TIMEOUT_MS";

/// Returns the production timeout unless an explicitly test-scoped override
/// is present. This is deliberately not part of the user configuration.
pub(crate) fn udp_idle_timeout() -> Duration {
    std::env::var(TEST_UDP_IDLE_TIMEOUT_ENV)
        .ok()
        .and_then(|value| parse_udp_idle_timeout(&value))
        .unwrap_or(UDP_IDLE_TIMEOUT)
}

fn parse_udp_idle_timeout(value: &str) -> Option<Duration> {
    let milliseconds = value.parse::<u64>().ok()?;
    (milliseconds > 0).then(|| Duration::from_millis(milliseconds))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct UdpFlowId {
    pub(crate) peer: SocketAddr,
    pub(crate) target: Endpoint,
    /// Optional inbound authentication identity. Native Yuubinsya UDP needs
    /// this because one socket can serve several passwords while preserving
    /// the matching password for asynchronous replies.
    pub(crate) authentication: Option<[u8; 32]>,
}

#[allow(dead_code)]
pub(crate) struct UdpFlowState {
    pub(crate) datagram: Arc<dyn AsyncDatagram>,
    pub(crate) receiver_task: tokio::task::JoinHandle<()>,
    pub(crate) key: TunFlowKey,
    pub(crate) peer: Endpoint,
    pub(crate) last_seen: std::time::Instant,
    pub(crate) _observation: FlowObserverGuard,
}

#[allow(dead_code)]
pub(crate) async fn shutdown_udp_flow(state: UdpFlowState) {
    let UdpFlowState {
        datagram,
        receiver_task,
        ..
    } = state;
    receiver_task.abort();
    let _ = receiver_task.await;
    let _ = datagram.close().await;
}

#[allow(dead_code)]
pub(crate) fn udp_flow_expired(
    last_seen: std::time::Instant,
    now: std::time::Instant,
    timeout: Duration,
) -> bool {
    now.saturating_duration_since(last_seen) >= timeout
}

#[derive(Clone)]
pub(crate) struct RoutedProxy {
    pub(crate) selector: Arc<RuntimeProxySelector>,
}

/// Record the local endpoint chosen by the outbound stream. This is kept at
/// the relay boundary because the concrete socket is only available after
/// proxy selection/connect succeeds.
pub(crate) fn record_outbound_stream(context: &mut FlowContext, stream: &BoxAsyncStream) {
    if let Some(address) = stream_local_addr(&**stream) {
        context.outbound_local_addr = Some(Endpoint::ip(context.network, address));
    }
}

pub(crate) fn record_outbound_datagram(context: &mut FlowContext, datagram: &dyn AsyncDatagram) {
    // Some protocol datagrams (notably Yuubinsya UOT) intentionally do not
    // expose a socket endpoint. Missing metadata must not tear down an
    // otherwise valid UDP flow; Go simply reports an empty localAddr there.
    if let Ok(endpoint) = datagram.local_addr()
        && endpoint.addr().is_some()
    {
        context.outbound_local_addr = Some(endpoint);
    }
}

impl AsyncProxy for RoutedProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move { self.selector.select(context).connect(context).await })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move { self.selector.select(context).open_datagram(context).await })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        Box::pin(async move { self.selector.select(context).ping(context).await })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[allow(dead_code)]
pub(crate) async fn relay_counted<A, B>(
    left: A,
    right: B,
    flow: TunFlowKey,
    context: FlowContext,
    monitor: Arc<ConnectionMonitor>,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let dns = InboundDnsPolicy::new(Arc::clone(&monitor));
    relay_counted_with_prefix_and_buffer(left, right, flow, context, monitor, &dns, &[], 16 * 1024)
        .await
}

pub(crate) async fn relay_counted_with_buffer<A, B>(
    left: A,
    right: B,
    flow: TunFlowKey,
    context: FlowContext,
    monitor: Arc<ConnectionMonitor>,
    dns: &dyn InboundDnsHandler,
    buffer_size: usize,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    relay_counted_with_prefix_and_buffer(left, right, flow, context, monitor, dns, &[], buffer_size)
        .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay_counted_with_prefix_and_buffer<A, B>(
    mut left: A,
    right: B,
    flow: TunFlowKey,
    mut context: FlowContext,
    monitor: Arc<ConnectionMonitor>,
    dns: &dyn InboundDnsHandler,
    prefix: &[u8],
    buffer_size: usize,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut sniffed = Vec::new();
    if context.destination.port() == Some(53) && dns.should_hijack(Some(53), &[]) {
        match intercept_dns_tcp(&mut left, dns).await? {
            DnsTcpDecision::Intercepted { upload, download } => {
                let _observation =
                    FlowObserverGuard::open(monitor.clone(), TunFlow { key: flow }, context);
                monitor.bytes(flow, TunFlowDirection::Upload, upload);
                monitor.bytes(flow, TunFlowDirection::Download, download);
                return Ok(());
            }
            DnsTcpDecision::Forward(prefix) => sniffed = prefix,
        }
    }
    if sniffed.is_empty() && monitor.sniff_enabled() {
        sniffed = sniff_stream(&mut left).await;
    }
    if context.destination.port() != Some(53)
        && let Some(frame) = dns_tcp_frame(&sniffed)
        && dns.should_hijack(None, frame)
        && let Some(answer) = dns.answer(frame).await
    {
        let response = answer.map_err(|error| std::io::Error::other(error.to_string()))?;
        if response.len() > usize::from(u16::MAX) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "DNS over TCP response is too large",
            ));
        }
        left.write_all(&(response.len() as u16).to_be_bytes())
            .await?;
        left.write_all(&response).await?;
        left.flush().await?;
        return Ok(());
    }
    let metadata = yuhaiin_core::sniff::inspect(&sniffed);
    if context.tls_server_name.is_none() {
        context.tls_server_name = metadata.tls_server_name;
    }
    if context.http_host.is_none() {
        context.http_host = metadata.http_host;
    }
    if context.protocol.is_none() {
        context.protocol = if context.tls_server_name.is_some() {
            Some("tls".to_owned())
        } else if context.http_host.is_some() {
            Some("http".to_owned())
        } else {
            None
        };
    }
    let left = PrefixedStream::new(sniffed, left);
    let _observation = FlowObserverGuard::open(monitor.clone(), TunFlow { key: flow }, context);
    let (mut left_read, mut left_write) = split(left);
    let (mut right_read, mut right_write) = split(right);
    if !prefix.is_empty() {
        right_write.write_all(prefix).await?;
        monitor.bytes(flow, TunFlowDirection::Upload, prefix.len());
    }
    let upload = copy_counted(
        &mut left_read,
        &mut right_write,
        monitor.clone(),
        flow,
        TunFlowDirection::Upload,
        buffer_size,
    );
    let download = copy_counted(
        &mut right_read,
        &mut left_write,
        monitor.clone(),
        flow,
        TunFlowDirection::Download,
        buffer_size,
    );
    tokio::try_join!(upload, download).map(|_| ())
}

const DNS_TCP_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_TCP_PACKET: usize = 4096;

enum DnsTcpDecision {
    Forward(Vec<u8>),
    Intercepted { upload: usize, download: usize },
}

fn dns_tcp_frame(bytes: &[u8]) -> Option<&[u8]> {
    let length = usize::from(u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?));
    let packet = bytes.get(2..2 + length)?;
    yuhaiin_core::dns::decode_query(packet).ok()?;
    Some(packet)
}

/// Return a locally-generated DNS answer when the packet is a DNS query. A
/// malformed/non-query packet is returned with its TCP length prefix so the
/// normal outbound relay can still forward it, matching Go's IsRequest gate.
async fn intercept_dns_tcp<S>(
    stream: &mut S,
    dns: &dyn InboundDnsHandler,
) -> std::io::Result<DnsTcpDecision>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut length = [0u8; 2];
    tokio::time::timeout(DNS_TCP_TIMEOUT, stream.read_exact(&mut length))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS over TCP query timed out")
        })??;
    let length = usize::from(u16::from_be_bytes(length));
    if length > MAX_DNS_TCP_PACKET {
        return Ok(DnsTcpDecision::Forward(
            (length as u16).to_be_bytes().to_vec(),
        ));
    }
    let mut packet = vec![0u8; length];
    stream.read_exact(&mut packet).await?;
    let mut framed = Vec::with_capacity(length + 2);
    framed.extend_from_slice(&(length as u16).to_be_bytes());
    framed.extend_from_slice(&packet);

    if !dns.should_hijack(Some(53), &packet) {
        return Ok(DnsTcpDecision::Forward(framed));
    }
    let Some(answer) = dns.answer(&packet).await else {
        return Ok(DnsTcpDecision::Forward(framed));
    };
    let response = answer.map_err(|error| std::io::Error::other(error.to_string()))?;
    if response.len() > usize::from(u16::MAX) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS over TCP response is too large",
        ));
    }
    stream
        .write_all(&(response.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok(DnsTcpDecision::Intercepted {
        upload: framed.len(),
        download: response.len() + 2,
    })
}

const SNIFF_TIMEOUT: Duration = Duration::from_millis(55);
const SNIFF_BUFFER_SIZE: usize = 16 * 1024;

async fn sniff_stream<S>(stream: &mut S) -> Vec<u8>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = vec![0; SNIFF_BUFFER_SIZE];
    match tokio::time::timeout(SNIFF_TIMEOUT, stream.read(&mut bytes)).await {
        Ok(Ok(length)) => {
            bytes.truncate(length);
            bytes
        }
        Ok(Err(_)) | Err(_) => Vec::new(),
    }
}

struct PrefixedStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S> AsyncRead for PrefixedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() {
            let length = (self.prefix.len() - self.offset).min(buf.remaining());
            buf.put_slice(&self.prefix[self.offset..self.offset + length]);
            self.offset += length;
            return Poll::Ready(Ok(()));
        }
        let inner = Pin::new(&mut self.inner);
        inner.poll_read(_cx, buf)
    }
}

impl<S> AsyncWrite for PrefixedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    use tokio::io::duplex;
    use yuhaiin_core::Network;

    #[test]
    fn udp_flow_expiration_matches_idle_timeout_boundary() {
        let now = Instant::now();
        assert!(!udp_flow_expired(
            now - UDP_IDLE_TIMEOUT + Duration::from_millis(1),
            now,
            UDP_IDLE_TIMEOUT,
        ));
        assert!(udp_flow_expired(
            now - UDP_IDLE_TIMEOUT,
            now,
            UDP_IDLE_TIMEOUT,
        ));
        assert!(!udp_flow_expired(
            now + Duration::from_secs(1),
            now,
            UDP_IDLE_TIMEOUT,
        ));
    }

    #[test]
    fn test_udp_idle_timeout_override_accepts_only_positive_milliseconds() {
        assert_eq!(parse_udp_idle_timeout("1000"), Some(Duration::from_secs(1)));
        assert_eq!(parse_udp_idle_timeout("0"), None);
        assert_eq!(parse_udp_idle_timeout("nope"), None);
    }

    struct CloseTrackingDatagram {
        closed: Arc<AtomicBool>,
    }

    impl AsyncDatagram for CloseTrackingDatagram {
        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            _target: Endpoint,
        ) -> BoxFuture<'a, Result<usize>> {
            Box::pin(async move { Ok(payload.len()) })
        }

        fn recv_from<'a>(
            &'a self,
            _buffer: &'a mut [u8],
        ) -> BoxFuture<'a, Result<(usize, Endpoint)>> {
            Box::pin(std::future::pending())
        }

        fn local_addr(&self) -> Result<Endpoint> {
            Ok(Endpoint::ip(Network::Udp, "127.0.0.1:0".parse().unwrap()))
        }

        fn close(&self) -> BoxFuture<'_, Result<()>> {
            let closed = Arc::clone(&self.closed);
            Box::pin(async move {
                closed.store(true, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn shutdown_udp_flow_cancels_receiver_before_closing_datagram() {
        let receiver_dropped = Arc::new(AtomicBool::new(false));
        let receiver_dropped_guard = Arc::clone(&receiver_dropped);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let receiver_task = tokio::spawn(async move {
            struct ReceiverGuard(Arc<AtomicBool>);
            impl Drop for ReceiverGuard {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }

            let _guard = ReceiverGuard(receiver_dropped_guard);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        let datagram_closed = Arc::new(AtomicBool::new(false));
        let key = TunFlowKey {
            network: Network::Udp,
            source: "127.0.0.1:41000".parse().unwrap(),
            destination: "127.0.0.1:53".parse().unwrap(),
        };
        let monitor = Arc::new(ConnectionMonitor::new());
        let observation = FlowObserverGuard::open(
            monitor,
            TunFlow { key },
            FlowContext::new(Endpoint::ip(Network::Udp, key.destination)),
        );
        shutdown_udp_flow(UdpFlowState {
            datagram: Arc::new(CloseTrackingDatagram {
                closed: Arc::clone(&datagram_closed),
            }),
            receiver_task,
            key,
            peer: Endpoint::ip(Network::Udp, key.source),
            last_seen: Instant::now(),
            _observation: observation,
        })
        .await;

        assert!(receiver_dropped.load(Ordering::SeqCst));
        assert!(datagram_closed.load(Ordering::SeqCst));
    }

    struct EchoDnsHandler;

    impl crate::monitor::SocketDnsHandler for EchoDnsHandler {
        fn answer<'a>(&'a self, packet: &'a [u8]) -> BoxFuture<'a, Result<Vec<u8>>> {
            let response = packet.to_vec();
            Box::pin(async move { Ok(response) })
        }
    }

    #[tokio::test]
    async fn relay_hijacks_valid_dns_over_tcp_before_opening_outbound() {
        let (mut client, relay_left) = duplex(4096);
        let (relay_right, _remote) = duplex(4096);
        let monitor = Arc::new(ConnectionMonitor::new());
        monitor.set_dns_handler(Some(
            Arc::new(EchoDnsHandler) as Arc<dyn crate::monitor::SocketDnsHandler>
        ));
        let flow = TunFlowKey {
            network: Network::Tcp,
            source: "127.0.0.1:41100".parse().unwrap(),
            destination: "127.0.0.1:53".parse().unwrap(),
        };
        let context = FlowContext::new(Endpoint::ip(Network::Tcp, flow.destination));
        let relay = tokio::spawn(relay_counted(
            relay_left,
            relay_right,
            flow,
            context,
            monitor,
        ));
        let query = yuhaiin_core::dns::encode_query(
            17,
            &yuhaiin_core::DomainName::new("example.com").unwrap(),
            yuhaiin_core::dns::DnsRecordType::A,
        )
        .unwrap();
        client.write_u16(query.len() as u16).await.unwrap();
        client.write_all(&query).await.unwrap();
        let response_length = client.read_u16().await.unwrap();
        let mut response = vec![0u8; usize::from(response_length)];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, query);
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn malformed_dns_over_tcp_at_dns_port_is_handled_by_inbound_policy() {
        let (mut client, relay_left) = duplex(4096);
        let (relay_right, _remote) = duplex(4096);
        let monitor = Arc::new(ConnectionMonitor::new());
        monitor.set_dns_handler(Some(
            Arc::new(EchoDnsHandler) as Arc<dyn crate::monitor::SocketDnsHandler>
        ));
        let flow = TunFlowKey {
            network: Network::Tcp,
            source: "127.0.0.1:41101".parse().unwrap(),
            destination: "127.0.0.1:53".parse().unwrap(),
        };
        let context = FlowContext::new(Endpoint::ip(Network::Tcp, flow.destination));
        let relay = tokio::spawn(relay_counted(
            relay_left,
            relay_right,
            flow,
            context,
            monitor,
        ));
        let query = b"not a DNS query";
        client.write_u16(query.len() as u16).await.unwrap();
        client.write_all(query).await.unwrap();
        let response_length = client.read_u16().await.unwrap();
        let mut response = vec![0u8; usize::from(response_length)];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, query);
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn relay_sniffs_http_host_before_open_without_dropping_prefix() {
        let (mut client, relay_left) = duplex(4096);
        let (relay_right, mut remote) = duplex(4096);
        let monitor = Arc::new(ConnectionMonitor::new());
        let flow = TunFlowKey {
            network: Network::Tcp,
            source: "127.0.0.1:41000".parse().unwrap(),
            destination: "127.0.0.1:41001".parse().unwrap(),
        };
        let context = FlowContext::new(Endpoint::ip(Network::Tcp, flow.destination));
        let relay = tokio::spawn(relay_counted(
            relay_left,
            relay_right,
            flow,
            context,
            monitor.clone(),
        ));
        let request = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        client.write_all(request).await.unwrap();
        client.shutdown().await.unwrap();

        let mut received = vec![0; request.len()];
        remote.read_exact(&mut received).await.unwrap();
        assert_eq!(received, request);
        assert_eq!(
            monitor.connections_value()["connections"][0]["httpHost"],
            "example.com"
        );
        assert_eq!(
            monitor.connections_value()["connections"][0]["protocol"],
            "http"
        );

        remote.write_all(b"ok").await.unwrap();
        remote.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"ok");
        relay.await.unwrap().unwrap();
        assert!(
            monitor.connections_value()["connections"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn relay_does_not_wait_for_silent_peer_past_sniff_deadline() {
        let (mut client, relay_left) = duplex(4096);
        let (relay_right, mut remote) = duplex(4096);
        let monitor = Arc::new(ConnectionMonitor::new());
        let flow = TunFlowKey {
            network: Network::Tcp,
            source: "127.0.0.1:41002".parse().unwrap(),
            destination: "127.0.0.1:41003".parse().unwrap(),
        };
        let context = FlowContext::new(Endpoint::ip(Network::Tcp, flow.destination));
        let relay = tokio::spawn(relay_counted(
            relay_left,
            relay_right,
            flow,
            context,
            monitor.clone(),
        ));

        tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                if monitor.connections_value()["connections"]
                    .as_array()
                    .is_some_and(|connections| !connections.is_empty())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("relay should open after the bounded sniff deadline");

        client.write_all(b"ping").await.unwrap();
        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        remote.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"ping");
        remote.shutdown().await.unwrap();
        client.read_to_end(&mut Vec::new()).await.unwrap();
        relay.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn relay_skips_sniff_wait_and_metadata_when_disabled() {
        let (mut client, relay_left) = duplex(4096);
        let (relay_right, mut remote) = duplex(4096);
        let monitor = Arc::new(ConnectionMonitor::new());
        monitor.set_sniff_enabled(false);
        let flow = TunFlowKey {
            network: Network::Tcp,
            source: "127.0.0.1:41004".parse().unwrap(),
            destination: "127.0.0.1:41005".parse().unwrap(),
        };
        let context = FlowContext::new(Endpoint::ip(Network::Tcp, flow.destination));
        let relay = tokio::spawn(relay_counted(
            relay_left,
            relay_right,
            flow,
            context,
            monitor.clone(),
        ));
        let request = b"GET / HTTP/1.1\r\nHost: no-sniff.example\r\n\r\n";
        client.write_all(request).await.unwrap();
        let mut received = vec![0; request.len()];
        tokio::time::timeout(Duration::from_millis(20), remote.read_exact(&mut received))
            .await
            .expect("disabled sniff must not wait for its deadline")
            .unwrap();
        assert_eq!(received, request);
        assert_ne!(
            monitor.connections_value()["connections"][0]["httpHost"],
            "no-sniff.example"
        );

        client.shutdown().await.unwrap();
        remote.shutdown().await.unwrap();
        relay.await.unwrap().unwrap();
    }
}

async fn copy_counted<R, W>(
    reader: &mut ReadHalf<R>,
    writer: &mut WriteHalf<W>,
    monitor: Arc<ConnectionMonitor>,
    flow: TunFlowKey,
    direction: TunFlowDirection,
    buffer_size: usize,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; buffer_size.max(1)];
    loop {
        let read = tokio::select! {
            result = reader.read(&mut buffer) => result?,
            _ = monitor.wait_for_close(flow) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "connection close requested",
                ));
            }
        };
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        writer.write_all(&buffer[..read]).await?;
        monitor.bytes(flow, direction, read);
    }
}

pub(crate) fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}
