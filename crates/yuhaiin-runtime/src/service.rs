//! Reusable service lifecycle for native hosts.
//!
//! The command-line binary is only one host of the runtime.  Android's
//! `VpnService` (and a future JNI/AAR boundary) needs the same API, DNS,
//! ordinary inbound and TUN ownership without starting a second process.  The
//! service handle keeps that orchestration in one place; platform adapters
//! only provide paths, listeners and, when applicable, an already-created TUN
//! descriptor.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

#[cfg(not(feature = "doh-tls"))]
use crate::BuiltinResolverFactory;
use crate::api::ApiState;
use crate::{RuntimeBuilder, RuntimeController, RuntimeHandle, RuntimeLog};
use yuhaiin_core::dns_resolver_async::{AsyncIpResolver, SystemAsyncIpResolver};
use yuhaiin_core::{Error, ErrorKind, Result};
use yuhaiin_store::{ConfigStore, restore_database};

/// A TUN device supplied by a native host instead of opened by the desktop
/// device builder.
#[cfg(all(feature = "tun", unix))]
pub struct InjectedTun {
    pub fd: std::os::fd::OwnedFd,
    pub config: crate::TunRuntimeConfig,
}

/// Inputs required to start the shared runtime service.
pub struct ServiceOptions {
    pub database: PathBuf,
    pub listen: SocketAddr,
    pub username: String,
    pub password: String,
    pub external_web: Option<PathBuf>,
    #[cfg(all(feature = "tun", unix))]
    pub injected_tun: Option<InjectedTun>,
}

impl ServiceOptions {
    pub fn new(database: PathBuf, listen: SocketAddr) -> Self {
        Self {
            database,
            listen,
            username: String::new(),
            password: String::new(),
            external_web: None,
            #[cfg(all(feature = "tun", unix))]
            injected_tun: None,
        }
    }
}

/// A running runtime host.  Dropping the handle requests shutdown; callers
/// that need to observe persistence errors should call [`Self::wait`].
pub struct RuntimeService {
    controller: RuntimeController,
    address: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl RuntimeService {
    /// Start the API listener and all runtime supervisors on the current
    /// Tokio `LocalSet`.
    pub async fn start(options: ServiceOptions) -> Result<Self> {
        if let Some(parent) = options.database.parent() {
            std::fs::create_dir_all(parent).map_err(io_error)?;
        }
        let store = ConfigStore::open(&options.database).await?;
        let controller = build_controller(store.clone()).await?;
        let listener = tokio::net::TcpListener::bind(options.listen)
            .await
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind HTTP API: {error}")))?;
        let address = listener.local_addr().map_err(|error| {
            Error::new(ErrorKind::Io, format!("read HTTP API address: {error}"))
        })?;

        let (shutdown, shutdown_rx) = watch::channel(false);
        let mut state = ApiState::new(controller.clone())
            .with_shutdown(shutdown.clone())
            .with_optional_auth(&options.username, &options.password);
        if let Some(external_web) = options.external_web {
            state = state.with_external_web(external_web);
        }

        let database = options.database;
        #[cfg(all(feature = "tun", unix))]
        let injected_tun = options.injected_tun;
        let task_controller = controller.clone();
        let task_shutdown = shutdown.clone();
        let route_refresh_state = state.clone();
        let task = tokio::task::spawn_local(async move {
            let logs = task_controller.monitor().logs();
            let dns_shutdown = shutdown_rx.clone();
            let inbound_shutdown = shutdown_rx.clone();
            let api_shutdown = shutdown_rx.clone();
            let route_refresh_shutdown = shutdown_rx.clone();
            let dns_task = tokio::task::spawn_local(crate::run_dns_supervisor(
                task_controller.clone(),
                dns_shutdown,
            ));
            let route_refresh_task =
                tokio::task::spawn_local(crate::api::run_route_list_refresh_loop(
                    route_refresh_state,
                    route_refresh_shutdown,
                ));
            let inbound_controller = task_controller.clone();
            let inbound_task = tokio::task::spawn_local(async move {
                #[cfg(all(feature = "tun", unix))]
                if let Some(injected_tun) = injected_tun {
                    return crate::inbound::run_until_with_tun_fd(
                        inbound_controller.clone(),
                        inbound_shutdown.clone(),
                        injected_tun.fd,
                        injected_tun.config,
                    )
                    .await;
                }
                crate::inbound::run_until(inbound_controller, inbound_shutdown).await
            });
            let api_task = tokio::spawn(crate::api::serve_until(
                listener,
                state,
                wait_for_shutdown(api_shutdown),
            ));

            let api_result = api_task
                .await
                .map_err(|error| Error::new(ErrorKind::Io, format!("HTTP API task: {error}")))?;
            let _ = task_shutdown.send(true);
            if let Err(error) = dns_task.await.map_err(join_error)? {
                logs.error(format!("DNS task stopped: {error}"));
            }
            if let Err(error) = inbound_task.await.map_err(join_error)? {
                logs.error(format!("inbound task stopped: {error}"));
            }
            route_refresh_task.await.map_err(join_error)?;
            task_controller.persist_monitor().await?;
            if let Some(source) = task_controller.take_restore_request() {
                restore_database(source, &database).await?;
            }
            api_result.map_err(io_error)
        });

        Ok(Self {
            controller,
            address,
            shutdown,
            task: Some(task),
        })
    }

    pub fn controller(&self) -> &RuntimeController {
        &self.controller
    }

    pub fn handle(&self) -> RuntimeHandle {
        self.controller.handle().clone()
    }

    pub fn logs(&self) -> RuntimeLog {
        self.controller.monitor().logs()
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn shutdown(&self) -> Result<()> {
        self.shutdown
            .send(true)
            .map_err(|_| Error::new(ErrorKind::Closed, "runtime service is already stopped"))
    }

    pub fn shutdown_handle(&self) -> watch::Sender<bool> {
        self.shutdown.clone()
    }

    pub async fn wait(mut self) -> Result<()> {
        let task = self
            .task
            .take()
            .ok_or_else(|| Error::new(ErrorKind::Closed, "runtime service task is missing"))?;
        task.await.map_err(join_error)?
    }
}

impl Drop for RuntimeService {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn build_controller(store: ConfigStore) -> Result<RuntimeController> {
    let upstream: Arc<dyn AsyncIpResolver> = Arc::new(SystemAsyncIpResolver);
    let mut builder = RuntimeBuilder::new(store, upstream);
    #[cfg(feature = "doh-tls")]
    {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config =
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|error| Error::new(ErrorKind::Protocol, format!("TLS provider: {error}")))?
                .with_root_certificates(roots)
                .with_no_client_auth();
        builder = builder.with_resolver_factory(Arc::new(
            crate::RustCryptoResolverFactory::from_client_config(
                Arc::new(config),
                Duration::from_secs(5),
                256,
            ),
        ));
    }
    #[cfg(not(feature = "doh-tls"))]
    {
        builder = builder.with_resolver_factory(Arc::new(BuiltinResolverFactory::new(
            Duration::from_secs(5),
            256,
        )));
    }
    RuntimeController::from_builder(builder).await
}

async fn wait_for_shutdown(mut receiver: watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    while receiver.changed().await.is_ok() && !*receiver.borrow() {}
}

fn io_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

fn join_error(error: tokio::task::JoinError) -> Error {
    io_error(error)
}

#[cfg(test)]
mod tests {
    use super::{RuntimeService, ServiceOptions};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_database() -> PathBuf {
        let root = std::env::var_os("YUHAIIN_CACHE_DIR")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
            .unwrap_or_else(|| PathBuf::from("."))
            .join("yuhaiin-rust/service-tests");
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        root.join(format!("service-{}-{nonce}.sqlite", std::process::id()))
    }

    fn remove_database(path: &std::path::Path) {
        for suffix in ["", "-wal", "-shm"] {
            let mut candidate = path.as_os_str().to_os_string();
            candidate.push(suffix);
            let _ = std::fs::remove_file(candidate);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn service_start_exposes_api_and_shutdowns() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let database = test_database();
                let mut options = ServiceOptions::new(
                    database.clone(),
                    "127.0.0.1:0".parse().expect("loopback address"),
                );
                options.username = "".to_owned();
                options.password = "".to_owned();
                let service = RuntimeService::start(options).await.unwrap();
                let response = reqwest::Client::new()
                    .get(format!("http://{}/api/v2/info", service.address()))
                    .send()
                    .await
                    .unwrap();
                assert!(response.status().is_success());
                let _ = response.text().await.unwrap();
                service.shutdown().unwrap();
                service.wait().await.unwrap();
                remove_database(&database);
            })
            .await;
    }
}
