use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf, split};

use yuhaiin_core::proxy::{AsyncDatagram, AsyncProxy, AsyncProxySelector, BoxAsyncStream};
use yuhaiin_core::tun::{TunFlow, TunFlowDirection, TunFlowKey, TunFlowObserver};
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
    monitor.opened(TunFlow { key: flow }, context);
    let (mut left_read, mut left_write) = split(left);
    let (mut right_read, mut right_write) = split(right);
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
        let read = reader.read(&mut buffer).await?;
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
