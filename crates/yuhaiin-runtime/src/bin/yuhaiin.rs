//! Runnable first-generation yuhaiin-rust service.
//!
//! The binary intentionally keeps process wiring small: SQLite is the source
//! of truth, the runtime controller owns reloads, the HTTP API owns control
//! traffic, and TUN/DNS tasks are optional data-plane owners.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use yuhaiin_core::dns_resolver_async::{AsyncIpResolver, SystemAsyncIpResolver};
use yuhaiin_core::{Error, ErrorKind, Result};
#[cfg(not(feature = "doh-tls"))]
use yuhaiin_runtime::BuiltinResolverFactory;
use yuhaiin_runtime::api::ApiState;
use yuhaiin_runtime::{RuntimeBuilder, RuntimeController, inbound, run_dns_supervisor};
use yuhaiin_store::{ConfigStore, GoNodeRecord, restore_database};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tokio::task::LocalSet::new().run_until(run()).await
}

async fn run() -> Result<()> {
    let database = env_path("YUHAIIN_DB", default_database_path());
    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let store = ConfigStore::open(&database).await?;
    ensure_direct_node(&store).await?;

    let upstream: Arc<dyn AsyncIpResolver> = Arc::new(SystemAsyncIpResolver);
    let mut builder = RuntimeBuilder::new(store.clone(), upstream);
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
            yuhaiin_runtime::RustCryptoResolverFactory::from_client_config(
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
    let controller = RuntimeController::from_builder(builder).await?;
    let listen = env_string("YUHAIIN_HTTP", "127.0.0.1:18080")
        .parse::<SocketAddr>()
        .map_err(|error| Error::invalid(format!("YUHAIIN_HTTP is invalid: {error}")))?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("bind HTTP API: {error}")))?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let username = env_string("YUHAIIN_API_USERNAME", "");
    let password = env_string("YUHAIIN_API_PASSWORD", "");
    let state = ApiState::new(controller.clone())
        .with_shutdown(shutdown_tx.clone())
        .with_optional_auth(username, password);
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        wait_for_process_shutdown().await;
        let _ = signal_tx.send(true);
    });

    let dns_task =
        tokio::task::spawn_local(run_dns_supervisor(controller.clone(), shutdown_rx.clone()));
    let inbound_task =
        tokio::task::spawn_local(inbound::run_until(controller.clone(), shutdown_rx.clone()));

    let api_task = tokio::spawn(yuhaiin_runtime::api::serve_until(
        listener,
        state,
        wait_for_shutdown(shutdown_rx),
    ));
    let api_result = api_task
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("HTTP API task: {error}")))?;
    let _ = shutdown_tx.send(true);
    let logs = controller.monitor().logs();

    if let Err(error) = dns_task.await.map_err(join_error)? {
        logs.error(format!("DNS task stopped: {error}"));
    }
    if let Err(error) = inbound_task.await.map_err(join_error)? {
        logs.error(format!("inbound task stopped: {error}"));
    }
    controller.persist_monitor().await?;
    if let Some(source) = controller.take_restore_request() {
        restore_database(source, &database).await?;
    }
    api_result.map_err(io_error)
}

async fn ensure_direct_node(store: &ConfigStore) -> Result<()> {
    if !store.repository().list_go_nodes().await?.is_empty() {
        return Ok(());
    }
    store
        .repository()
        .put_go_node(&GoNodeRecord {
            id: "direct".to_owned(),
            name: "Direct".to_owned(),
            group_name: "builtin".to_owned(),
            origin: "rust-builtin".to_owned(),
            enabled: true,
            chain_types_json: br##"["direct"]"##.to_vec(),
            updated_at: 0,
            data_json: br##"{"id":"direct","name":"Direct","group":"builtin","origin":"rust-builtin","enabled":true,"protocol":"direct","chain":[{"type":"direct","direct":{}}]}"##.to_vec(),
        })
        .await
}

fn default_database_path() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_else(|| ".".into()))
                .join(".local/share")
        })
        .join("yuhaiin-rust/state.sqlite")
}

fn env_path(key: &str, default: PathBuf) -> PathBuf {
    std::env::var_os(key).map(PathBuf::from).unwrap_or(default)
}
fn env_string(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

async fn wait_for_shutdown(mut receiver: watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    while receiver.changed().await.is_ok() && !*receiver.borrow() {}
}

async fn wait_for_process_shutdown() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = sigterm.recv() => {},
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn io_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}
fn join_error(error: tokio::task::JoinError) -> Error {
    io_error(error)
}
