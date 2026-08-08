//! Runnable first-generation yuhaiin-rust service.
//!
//! The binary intentionally keeps process wiring small: SQLite is the source
//! of truth, the runtime controller owns reloads, the HTTP API owns control
//! traffic, and TUN/DNS tasks are optional data-plane owners.

use std::net::SocketAddr;
#[cfg(feature = "tun")]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::watch;

use yuhaiin_core::dns::{
    AsyncDnsHandler, DnsRecordType, DnsResponse, decode_query, encode_response,
};
use yuhaiin_core::dns_resolver_async::{AsyncIpResolver, SystemAsyncIpResolver};
use yuhaiin_core::{Error, ErrorKind, LocalBoxFuture, ResolveStrategy, Result};
#[cfg(not(feature = "doh-tls"))]
use yuhaiin_runtime::BuiltinResolverFactory;
use yuhaiin_runtime::api::ApiState;
use yuhaiin_runtime::{RuntimeBuilder, RuntimeController, parse_dns_server};
use yuhaiin_store::{ConfigStore, GoNodeRecord};

#[cfg(feature = "tun")]
use yuhaiin_core::tun::{TunConfig, TunDispatcher, TunRuntime};

struct RuntimeDnsHandler {
    resolver: Arc<dyn AsyncIpResolver>,
}

impl AsyncDnsHandler for RuntimeDnsHandler {
    fn answer<'a>(&'a self, packet: &'a [u8]) -> LocalBoxFuture<'a, Result<Vec<u8>>> {
        let question = match decode_query(packet) {
            Ok(question) => question,
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        Box::pin(async move {
            let addresses = self
                .resolver
                .resolve(
                    &question.domain,
                    match question.record_type {
                        DnsRecordType::A => ResolveStrategy::OnlyIpv4,
                        DnsRecordType::Aaaa => ResolveStrategy::OnlyIpv6,
                        _ => ResolveStrategy::Default,
                    },
                )
                .await?;
            encode_response(
                packet,
                &DnsResponse {
                    addresses,
                    ptr_names: Vec::new(),
                    service_bindings: Vec::new(),
                    minimum_ttl: Some(30),
                },
            )
        })
    }
}

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
    let state = ApiState::new(controller.clone());

    let listen = env_string("YUHAIIN_HTTP", "127.0.0.1:18080")
        .parse::<SocketAddr>()
        .map_err(|error| Error::invalid(format!("YUHAIIN_HTTP is invalid: {error}")))?;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("bind HTTP API: {error}")))?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = signal_tx.send(true);
    });

    #[cfg(feature = "tun")]
    let tun_task = spawn_tun_task(controller.clone(), shutdown_rx.clone()).await?;

    let dns_task = spawn_dns_task(controller.clone(), shutdown_rx.clone()).await?;

    let api_task = tokio::spawn(yuhaiin_runtime::api::serve_until(
        listener,
        state,
        wait_for_shutdown(shutdown_rx),
    ));
    let api_result = api_task
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("HTTP API task: {error}")))?;
    let _ = shutdown_tx.send(true);

    #[cfg(feature = "tun")]
    if let Err(error) = tun_task.await.map_err(join_error)? {
        eprintln!("TUN task stopped: {error}");
    }
    if let Err(error) = dns_task.await.map_err(join_error)? {
        eprintln!("DNS task stopped: {error}");
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

#[cfg(feature = "tun")]
async fn spawn_tun_task(
    controller: RuntimeController,
    shutdown: watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<std::io::Result<()>>> {
    let config = load_tun_config(&controller.store()).await?;
    if !config.enabled {
        return Ok(tokio::spawn(async { Ok(()) }));
    }
    let proxy_id = config
        .proxy_id
        .clone()
        .or_else(|| futures_proxy_id(&controller))
        .unwrap_or_else(|| "direct".to_owned());
    let mut proxy_runtime = controller
        .build_tun_proxy_runtime_with_dns(
            &config.direct_id,
            &proxy_id,
            &config.bypass_id,
            &config.drop_id,
            Duration::from_secs(30),
            config.channel_capacity,
            Some(Arc::new(RuntimeDnsHandler {
                resolver: controller.handle().load().resolver.clone(),
            })),
        )
        .await?;
    let mut tun = TunRuntime::open(config.tun).map_err(io_error)?;
    let mut dispatcher = TunDispatcher::new(64 * 1024, 64 * 1024, 2048)?;
    let future = async move {
        tun.run_dispatcher_until(
            &mut dispatcher,
            &mut proxy_runtime,
            Duration::from_millis(10),
            wait_for_shutdown(shutdown),
        )
        .await
    };
    Ok(tokio::task::spawn_local(future))
}

#[cfg(feature = "tun")]
#[derive(Debug)]
struct TunRuntimeConfig {
    enabled: bool,
    tun: TunConfig,
    direct_id: String,
    proxy_id: Option<String>,
    bypass_id: String,
    drop_id: String,
    channel_capacity: usize,
}

#[cfg(feature = "tun")]
async fn load_tun_config(store: &ConfigStore) -> Result<TunRuntimeConfig> {
    let value = store
        .get_config("tun.runtime")
        .await?
        .map(|bytes| serde_json::from_slice::<Value>(&bytes))
        .transpose()
        .map_err(|error| Error::invalid(format!("tun.runtime is invalid JSON: {error}")))?
        .unwrap_or_else(|| serde_json::json!({}));
    let enabled = value
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || std::env::var("YUHAIIN_TUN").ok().as_deref() == Some("1");
    let tun = TunConfig {
        name: value.get("name").and_then(Value::as_str).map(str::to_owned),
        ipv4: value
            .get("ipv4")
            .and_then(parse_ipv4)
            .or_else(|| enabled.then_some((Ipv4Addr::new(10, 0, 0, 1), 24))),
        ipv6: value
            .get("ipv6")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(parse_ipv6).collect())
            .unwrap_or_default(),
        mtu: value.get("mtu").and_then(Value::as_u64).unwrap_or(1500) as usize,
        queue_capacity: value
            .get("queueCapacity")
            .and_then(Value::as_u64)
            .unwrap_or(256) as usize,
    };
    Ok(TunRuntimeConfig {
        enabled,
        tun,
        direct_id: value
            .get("directId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        proxy_id: value
            .get("proxyId")
            .and_then(Value::as_str)
            .map(str::to_owned),
        bypass_id: value
            .get("bypassId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        drop_id: value
            .get("dropId")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        channel_capacity: value
            .get("channelCapacity")
            .and_then(Value::as_u64)
            .unwrap_or(256) as usize,
    })
}

#[cfg(feature = "tun")]
fn parse_ipv4(value: &Value) -> Option<(Ipv4Addr, u8)> {
    if let Some(value) = value.as_str() {
        let (address, prefix) = value.split_once('/')?;
        return Some((address.parse().ok()?, prefix.parse().ok()?));
    }
    let object = value.as_object()?;
    Some((
        object.get("address")?.as_str()?.parse().ok()?,
        object.get("prefix")?.as_u64()?.try_into().ok()?,
    ))
}

#[cfg(feature = "tun")]
fn parse_ipv6(value: &Value) -> Option<(Ipv6Addr, u8)> {
    if let Some(value) = value.as_str() {
        let (address, prefix) = value.split_once('/')?;
        return Some((address.parse().ok()?, prefix.parse().ok()?));
    }
    let object = value.as_object()?;
    Some((
        object.get("address")?.as_str()?.parse().ok()?,
        object.get("prefix")?.as_u64()?.try_into().ok()?,
    ))
}

#[cfg(feature = "tun")]
fn futures_proxy_id(controller: &RuntimeController) -> Option<String> {
    // The snapshot is immutable and cheap to inspect; selecting the first
    // enabled node gives the binary a useful zero-configuration path.
    controller
        .handle()
        .load()
        .proxies
        .iter()
        .find(|proxy| proxy.enabled)
        .map(|proxy| proxy.id.clone())
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

fn io_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}
fn join_error(error: tokio::task::JoinError) -> Error {
    io_error(error)
}

async fn spawn_dns_task(
    controller: RuntimeController,
    shutdown: watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let server = controller
        .store()
        .get_config("resolver.server")
        .await?
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| {
            value
                .get("server")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .filter(|server| !server.trim().is_empty());
    let Some(server) = server else {
        return Ok(tokio::spawn(async { Ok(()) }));
    };
    let address = parse_dns_server(&server, 53, "api-dns")?;
    let handler = RuntimeDnsHandler {
        resolver: controller.handle().load().resolver.clone(),
    };
    let dns = yuhaiin_core::dns_udp_async::AsyncUdpDnsServer::bind(address, handler, 4096).await?;
    Ok(tokio::task::spawn_local(async move {
        dns.serve_until(wait_for_shutdown(shutdown)).await
    }))
}
