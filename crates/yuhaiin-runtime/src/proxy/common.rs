use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
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
use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, AsyncProxySelector, BoxAsyncStream};
use yuhaiin_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};

use crate::{ConnectionMonitor, RuntimeProxySelector};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct UdpFlowId {
    pub(crate) peer: SocketAddr,
    pub(crate) target: Endpoint,
}

pub(crate) struct UdpFlowState {
    pub(crate) datagram: Arc<dyn AsyncDatagram>,
    pub(crate) key: TunFlowKey,
    pub(crate) peer: Endpoint,
    pub(crate) _observation: FlowObserverGuard,
}

pub(crate) struct UdpReply {
    pub(crate) id: UdpFlowId,
    pub(crate) target: Endpoint,
    pub(crate) payload: Vec<u8>,
}

pub(crate) async fn close_udp_flows(
    flows: &mut HashMap<UdpFlowId, UdpFlowState>,
    flow: TunFlowKey,
) {
    let ids = flows
        .iter()
        .filter(|(_, state)| state.key == flow)
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    for id in ids {
        if let Some(state) = flows.remove(&id) {
            let _ = state.datagram.close().await;
            drop(state);
        }
    }
}

#[derive(Clone)]
pub(crate) struct RoutedProxy {
    pub(crate) selector: Arc<RuntimeProxySelector>,
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
    relay_counted_with_buffer(left, right, flow, context, monitor, 16 * 1024).await
}

pub(crate) async fn relay_counted_with_buffer<A, B>(
    left: A,
    right: B,
    flow: TunFlowKey,
    context: FlowContext,
    monitor: Arc<ConnectionMonitor>,
    buffer_size: usize,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    relay_counted_with_prefix_and_buffer(left, right, flow, context, monitor, &[], buffer_size)
        .await
}

pub(crate) async fn relay_counted_with_prefix<A, B>(
    left: A,
    right: B,
    flow: TunFlowKey,
    context: FlowContext,
    monitor: Arc<ConnectionMonitor>,
    prefix: &[u8],
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    relay_counted_with_prefix_and_buffer(left, right, flow, context, monitor, prefix, 16 * 1024)
        .await
}

pub(crate) async fn relay_counted_with_prefix_and_buffer<A, B>(
    mut left: A,
    right: B,
    flow: TunFlowKey,
    mut context: FlowContext,
    monitor: Arc<ConnectionMonitor>,
    prefix: &[u8],
    buffer_size: usize,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let sniffed = if monitor.sniff_enabled() {
        sniff_stream(&mut left).await
    } else {
        Vec::new()
    };
    let metadata = yuhaiin_core::sniff::inspect(&sniffed);
    if context.tls_server_name.is_none() {
        context.tls_server_name = metadata.tls_server_name;
    }
    if context.http_host.is_none() {
        context.http_host = metadata.http_host;
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
    let result = tokio::try_join!(upload, download).map(|_| ());
    result
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
mod tests {
    use super::*;
    use tokio::io::duplex;

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

pub(crate) fn udp_flow_key(peer: SocketAddr, target: &Endpoint) -> TunFlowKey {
    let destination = target.addr().unwrap_or_else(|| {
        SocketAddr::new(
            if peer.is_ipv4() {
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            },
            target.port().unwrap_or(0),
        )
    });
    TunFlowKey {
        network: Network::Udp,
        source: peer,
        destination,
    }
}

pub(crate) fn io_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}
