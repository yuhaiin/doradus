use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};

use yuhaiin_core::flow::{
    Flow as TunFlow, FlowDirection as TunFlowDirection, FlowKey as TunFlowKey,
    FlowObserver as TunFlowObserver,
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
}

pub(crate) struct UdpReply {
    pub(crate) id: UdpFlowId,
    pub(crate) target: Endpoint,
    pub(crate) payload: Vec<u8>,
}

pub(crate) async fn close_udp_flows(
    flows: &mut HashMap<UdpFlowId, UdpFlowState>,
    flow: TunFlowKey,
    monitor: &ConnectionMonitor,
) {
    let ids = flows
        .iter()
        .filter(|(_, state)| state.key == flow)
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    for id in ids {
        if let Some(state) = flows.remove(&id) {
            let _ = state.datagram.close().await;
            monitor.closed(state.key);
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
    relay_counted_with_prefix(left, right, flow, context, monitor, &[]).await
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
    monitor.opened(TunFlow { key: flow }, context);
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
    );
    let download = copy_counted(
        &mut right_read,
        &mut left_write,
        monitor.clone(),
        flow,
        TunFlowDirection::Download,
    );
    let result = tokio::try_join!(upload, download).map(|_| ());
    monitor.closed(flow);
    result
}

async fn copy_counted<R, W>(
    reader: &mut ReadHalf<R>,
    writer: &mut WriteHalf<W>,
    monitor: Arc<ConnectionMonitor>,
    flow: TunFlowKey,
    direction: TunFlowDirection,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 16 * 1024];
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
