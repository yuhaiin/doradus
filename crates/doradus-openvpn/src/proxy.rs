use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use doradus_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use doradus_core::{BoxFuture, Error, ErrorKind, FlowContext, Network, Result};
use doradus_types::AsyncIpResolver;
use openvpn_connect::tokio::{Client, SessionHandle};
use openvpn_connect::{Config, Credentials, EventHandler, ExternalTransport, ExternalTun};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::driver::{Driver, DriverCommand, resolve_flow_destination};
use crate::transport::TokioUdpTransport;
use crate::tun::ExternalTunBridge;
use crate::{OpenVpnConfig, error_openvpn};

const COMMAND_QUEUE_CAPACITY: usize = 64;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn build_proxy(config: OpenVpnConfig, timeout: Duration) -> Result<OpenVpnProxy> {
    build_proxy_with_interface_and_resolver(config, timeout, None, None).await
}

pub async fn build_proxy_with_interface_and_resolver(
    config: OpenVpnConfig,
    timeout: Duration,
    bind_interface: Option<&str>,
    resolver: Option<Arc<dyn AsyncIpResolver>>,
) -> Result<OpenVpnProxy> {
    OpenVpnProxy::start(config, timeout, bind_interface.map(str::to_owned), resolver).await
}

pub struct OpenVpnProxy {
    command_tx: mpsc::Sender<DriverCommand>,
    session: SessionHandle,
    closed: Arc<AtomicBool>,
    transport: TokioUdpTransport,
    tasks: Mutex<Option<ProxyTasks>>,
}

struct ProxyTasks {
    session: JoinHandle<()>,
    driver: JoinHandle<()>,
}

impl OpenVpnProxy {
    async fn start(
        config: OpenVpnConfig,
        timeout: Duration,
        bind_interface: Option<String>,
        resolver: Option<Arc<dyn AsyncIpResolver>>,
    ) -> Result<Self> {
        if config.profile.trim().is_empty() {
            return Err(Error::invalid("OpenVPN profile is empty"));
        }

        let (tun, tun_event_rx) = ExternalTunBridge::channel();
        let transport = TokioUdpTransport::new(bind_interface, resolver);
        let handler = Handler {
            tun,
            transport: transport.clone(),
        };
        let client = Client::new(handler).map_err(error_openvpn)?;
        let evaluation = client
            .evaluate(Config::new(config.profile))
            .await
            .map_err(error_openvpn)?;
        if !evaluation.autologin {
            let username = config
                .username
                .filter(|value| !value.is_empty())
                .ok_or_else(|| Error::invalid("OpenVPN username is required by this profile"))?;
            let password = config
                .password
                .ok_or_else(|| Error::invalid("OpenVPN password is required by this profile"))?;
            client
                .provide_credentials(Credentials::new(username, password))
                .await
                .map_err(error_openvpn)?;
        }

        let session = client.connect().await.map_err(error_openvpn)?;
        let session_handle = session.handle();
        let session_for_cleanup = session_handle.clone();
        let session_task = tokio::spawn(async move {
            let _ = session.await;
        });

        let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let closed = Arc::new(AtomicBool::new(false));
        let ready = tokio::time::timeout(
            timeout,
            Driver::start(tun_event_rx, command_rx, Arc::clone(&closed)),
        )
        .await;
        let driver = match ready {
            Ok(Ok(driver)) => driver,
            Ok(Err(error)) => {
                cleanup_failed_start(session_for_cleanup, session_task, &transport).await;
                return Err(error);
            }
            Err(_) => {
                cleanup_failed_start(session_for_cleanup, session_task, &transport).await;
                return Err(Error::new(
                    ErrorKind::Io,
                    "OpenVPN tunnel did not become ready before the connection timeout",
                ));
            }
        };
        let driver_task = tokio::spawn(driver.run());

        Ok(Self {
            command_tx,
            session: session_handle,
            closed,
            transport,
            tasks: Mutex::new(Some(ProxyTasks {
                session: session_task,
                driver: driver_task,
            })),
        })
    }

    fn ensure_open(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            Err(Error::new(ErrorKind::Closed, "OpenVPN proxy is closed"))
        } else {
            Ok(())
        }
    }
}

impl AsyncProxy for OpenVpnProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move {
            self.ensure_open()?;
            if context.network != Network::Tcp {
                return Err(Error::invalid("OpenVPN TCP proxy received a non-TCP flow"));
            }
            let destination = resolve_flow_destination(context).await?;
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DriverCommand::OpenTcp {
                    destination,
                    reply: reply_tx,
                })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "OpenVPN driver is closed"))?;
            Ok(Box::new(reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "OpenVPN driver dropped TCP request")
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
                return Err(Error::invalid("OpenVPN UDP proxy received a non-UDP flow"));
            }
            let (reply_tx, reply_rx) = oneshot::channel();
            self.command_tx
                .send(DriverCommand::OpenUdp { reply: reply_tx })
                .await
                .map_err(|_| Error::new(ErrorKind::Closed, "OpenVPN driver is closed"))?;
            Ok(Box::new(reply_rx.await.map_err(|_| {
                Error::new(ErrorKind::Closed, "OpenVPN driver dropped UDP request")
            })??) as Box<dyn AsyncDatagram>)
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let mut tasks = self.tasks.lock().await;
            self.closed.store(true, Ordering::Release);
            let _ = self.command_tx.try_send(DriverCommand::Close);
            self.session.cancel();
            self.transport.shutdown().await;
            if let Some(tasks) = tasks.take() {
                finish_task(tasks.driver).await;
                finish_task(tasks.session).await;
            }
            Ok(())
        })
    }
}

impl Drop for OpenVpnProxy {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        let _ = self.command_tx.try_send(DriverCommand::Close);
        self.session.cancel();
        self.transport.abort();
        if let Ok(mut tasks) = self.tasks.try_lock()
            && let Some(tasks) = tasks.take()
        {
            tasks.driver.abort();
            tasks.session.abort();
        }
    }
}

struct Handler {
    tun: ExternalTunBridge,
    transport: TokioUdpTransport,
}

impl EventHandler for Handler {
    fn external_tun(&self) -> Option<&dyn ExternalTun> {
        Some(&self.tun)
    }

    fn external_transport(&self) -> Option<&dyn ExternalTransport> {
        Some(&self.transport)
    }
}

async fn cleanup_failed_start(
    session: SessionHandle,
    session_task: JoinHandle<()>,
    transport: &TokioUdpTransport,
) {
    session.cancel();
    transport.shutdown().await;
    finish_task(session_task).await;
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
