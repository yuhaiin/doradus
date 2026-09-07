use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;

use doradus_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use doradus_core::{BoxFuture, Endpoint, Error, ErrorKind, FlowContext, Network, Result};
use doradus_types::{AsyncIpResolver, ResolveStrategy};

use crate::config::{ParsedWarpMasqueConfig, WarpMasqueConfig};
use crate::driver::{Driver, DriverCommand};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub struct WarpMasqueProxy {
    command_tx: mpsc::Sender<DriverCommand>,
    closed: Arc<AtomicBool>,
    resolver: Option<Arc<dyn AsyncIpResolver>>,
    timeout: Duration,
    driver_task: Mutex<Option<JoinHandle<()>>>,
}

pub async fn build_proxy(config: WarpMasqueConfig, timeout: Duration) -> Result<WarpMasqueProxy> {
    build_proxy_with_interface_and_resolver(config, timeout, None, None).await
}

pub async fn build_proxy_with_interface(
    config: WarpMasqueConfig,
    timeout: Duration,
    bind_interface: Option<&str>,
) -> Result<WarpMasqueProxy> {
    build_proxy_with_interface_and_resolver(config, timeout, bind_interface, None).await
}

pub async fn build_proxy_with_interface_and_resolver(
    config: WarpMasqueConfig,
    timeout: Duration,
    bind_interface: Option<&str>,
    resolver: Option<Arc<dyn AsyncIpResolver>>,
) -> Result<WarpMasqueProxy> {
    let parsed = config.parse()?;
    Ok(WarpMasqueProxy::start(
        parsed,
        timeout,
        bind_interface,
        resolver,
    ))
}

impl WarpMasqueProxy {
    fn start(
        config: ParsedWarpMasqueConfig,
        timeout: Duration,
        bind_interface: Option<&str>,
        resolver: Option<Arc<dyn AsyncIpResolver>>,
    ) -> Self {
        let (command_tx, command_rx) = mpsc::channel(64);
        let closed = Arc::new(AtomicBool::new(false));
        let task_closed = Arc::clone(&closed);
        let bind_interface = bind_interface.map(str::to_owned);
        let driver_task = tokio::spawn(async move {
            Driver::new(config, timeout, bind_interface, command_rx, task_closed)
                .run()
                .await;
        });
        Self {
            command_tx,
            closed,
            resolver,
            timeout,
            driver_task: Mutex::new(Some(driver_task)),
        }
    }

    fn ensure_open(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            Err(Error::new(ErrorKind::Closed, "WARP MASQUE proxy is closed"))
        } else {
            Ok(())
        }
    }
}

impl AsyncProxy for WarpMasqueProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            self.ensure_open()?;
            if context.network != Network::Tcp {
                return Err(error_unsupported(
                    "WARP MASQUE TCP proxy received a non-TCP flow",
                ));
            }
            let destination =
                resolve_flow_destination(context, self.resolver.as_deref(), self.timeout).await?;
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DriverCommand::OpenTcp {
                    destination,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "WARP MASQUE driver is closed"))?;
            Ok(Box::new(reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "WARP MASQUE driver dropped TCP request")
            })??) as BoxAsyncStream)
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        Box::pin(async move {
            self.ensure_open()?;
            if context.network != Network::Udp && context.network != Network::Any {
                return Err(error_unsupported(
                    "WARP MASQUE UDP proxy received a non-UDP flow",
                ));
            }
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DriverCommand::OpenUdp { reply: reply_tx })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "WARP MASQUE driver is closed"))?;
            Ok(Box::new(reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "WARP MASQUE driver dropped UDP request")
            })??) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let mut driver_task = self.driver_task.lock().await;
            self.closed.store(true, Ordering::Release);
            let _ = self.command_tx.try_send(DriverCommand::Close);
            if let Some(task) = driver_task.take() {
                finish_task(task).await;
            }
            Ok(())
        })
    }
}

impl Drop for WarpMasqueProxy {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        let _ = self.command_tx.try_send(DriverCommand::Close);
        if let Ok(mut driver_task) = self.driver_task.try_lock()
            && let Some(task) = driver_task.take()
        {
            task.abort();
        }
    }
}

async fn finish_task(mut task: JoinHandle<()>) {
    if tokio::time::timeout(SHUTDOWN_TIMEOUT, &mut task)
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
    }
}

async fn resolve_flow_destination(
    context: &FlowContext,
    resolver: Option<&dyn AsyncIpResolver>,
    timeout: Duration,
) -> Result<SocketAddr> {
    let endpoint = context
        .resolved_destination
        .as_ref()
        .and_then(|addresses| addresses.first().copied())
        .map(|address| Endpoint::ip(context.network, address))
        .unwrap_or_else(|| context.destination.clone());
    if let Some(address) = endpoint.addr() {
        return Ok(address);
    }
    let host = endpoint
        .host()
        .ok_or_else(|| Error::invalid("WARP MASQUE destination has no host"))?;
    let port = endpoint
        .port()
        .ok_or_else(|| Error::invalid("WARP MASQUE destination has no port"))?;
    if let Some(resolver) = resolver {
        let addresses =
            tokio::time::timeout(timeout, resolver.resolve(host, ResolveStrategy::Default))
                .await
                .map_err(|_| {
                    Error::new(
                        ErrorKind::Timeout,
                        "WARP MASQUE destination resolution timed out",
                    )
                })??;
        let address = addresses
            .v4
            .first()
            .copied()
            .map(IpAddr::V4)
            .or_else(|| addresses.v6.first().copied().map(IpAddr::V6))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Io,
                    "WARP MASQUE destination resolved to no address",
                )
            })?;
        return Ok(SocketAddr::new(address, port));
    }
    tokio::time::timeout(timeout, tokio::net::lookup_host((host.as_str(), port)))
        .await
        .map_err(|_| {
            Error::new(
                ErrorKind::Timeout,
                "WARP MASQUE destination resolution timed out",
            )
        })?
        .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?
        .next()
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Io,
                "WARP MASQUE destination resolved to no address",
            )
        })
}

fn error_unsupported(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::Unsupported, message)
}
