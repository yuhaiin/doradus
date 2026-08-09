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
use yuhaiin_store::{ConfigStore, restore_database};

#[derive(Debug, Default, PartialEq, Eq)]
struct RunOptions {
    database: Option<PathBuf>,
    listen: Option<String>,
    username: Option<String>,
    password: Option<String>,
    external_web: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = main_result().await {
        eprintln!("yuhaiin-rust: fatal: {error}");
        std::process::exit(1);
    }
}

async fn main_result() -> Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        console_notice("no command supplied; starting the service (same as `run`)");
    }
    if args
        .first()
        .map(|arg| arg == "update-helper")
        .unwrap_or(false)
    {
        let target = args
            .get(1)
            .ok_or_else(|| Error::invalid("update-helper target is missing"))?;
        let staged = args
            .get(2)
            .ok_or_else(|| Error::invalid("update-helper staged path is missing"))?;
        yuhaiin_runtime::update::run_update_helper(
            std::path::Path::new(target),
            std::path::Path::new(staged),
        )
        .map_err(|error| Error::new(ErrorKind::Io, error))?;
        return Ok(());
    }
    if args
        .first()
        .map(|arg| arg == "version" || arg == "-v" || arg == "--version")
        .unwrap_or(false)
    {
        println!("yuhaiin-rust {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if args
        .first()
        .map(|arg| arg == "help" || arg == "-h" || arg == "--help")
        .unwrap_or(false)
    {
        print_help();
        return Ok(());
    }
    let options = parse_run_options(&args)?;
    tokio::task::LocalSet::new().run_until(run(options)).await
}

async fn run(options: RunOptions) -> Result<()> {
    let database = options
        .database
        .or_else(|| std::env::var_os("YUHAIIN_DB").map(PathBuf::from))
        .unwrap_or_else(default_database_path);
    console_notice(format!("starting; database={}", database.display()));
    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let store = ConfigStore::open(&database).await?;
    console_notice("configuration database opened");

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
    let logs = controller.monitor().logs();
    if console_logs_enabled() {
        logs.enable_console();
    }
    let listen = options
        .listen
        .or_else(|| std::env::var("YUHAIIN_HTTP").ok())
        .unwrap_or_else(|| "0.0.0.0:50051".to_owned())
        .parse::<SocketAddr>()
        .map_err(|error| Error::invalid(format!("YUHAIIN_HTTP is invalid: {error}")))?;
    console_notice(format!("binding HTTP API on {listen}"));
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| Error::new(ErrorKind::Io, format!("bind HTTP API: {error}")))?;
    console_notice(format!("HTTP API listening on http://{listen}"));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let username = options
        .username
        .or_else(|| std::env::var("YUHAIIN_API_USERNAME").ok())
        .unwrap_or_default();
    let password = options
        .password
        .or_else(|| std::env::var("YUHAIIN_API_PASSWORD").ok())
        .unwrap_or_default();
    let mut state = ApiState::new(controller.clone())
        .with_shutdown(shutdown_tx.clone())
        .with_optional_auth(username, password);
    if let Some(external_web) = options.external_web {
        state = state.with_external_web(external_web);
    }
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
    console_notice("shutdown requested; stopping runtime tasks");
    let _ = shutdown_tx.send(true);

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
    let result = api_result.map_err(io_error);
    if result.is_ok() {
        console_notice("stopped");
    }
    result
}

fn default_database_path() -> PathBuf {
    let config_root = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    let go_path = config_root.join("yuhaiin/state.db");
    let rust_path = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("yuhaiin-rust/state.sqlite");
    if go_path.exists() || !rust_path.exists() {
        go_path
    } else {
        rust_path
    }
}

fn parse_run_options(args: &[std::ffi::OsString]) -> Result<RunOptions> {
    let mut options = RunOptions::default();
    let mut index = usize::from(args.first().map(|arg| arg == "run").unwrap_or(false));
    while index < args.len() {
        let flag = args[index].to_string_lossy();
        match flag.as_ref() {
            "-host" | "--host" | "-h" => {
                options.listen = Some(required_option_value(args, &mut index, &flag)?);
            }
            "-path" | "--path" => {
                options.database = Some(
                    PathBuf::from(required_option_value(args, &mut index, &flag)?).join("state.db"),
                );
            }
            "-u" | "--username" => {
                options.username = Some(required_option_value(args, &mut index, &flag)?);
            }
            "-p" | "--password" => {
                options.password = Some(required_option_value(args, &mut index, &flag)?);
            }
            "-eweb" | "--external-web" => {
                options.external_web = Some(required_option_value(args, &mut index, &flag)?);
            }
            "-nfs-mode" | "--nfs-mode" => {}
            other if other.starts_with('-') => {
                return Err(Error::invalid(format!("unknown option {other:?}")));
            }
            other => return Err(Error::invalid(format!("unexpected argument {other:?}"))),
        }
        index += 1;
    }
    Ok(options)
}

fn required_option_value(
    args: &[std::ffi::OsString],
    index: &mut usize,
    flag: &str,
) -> Result<String> {
    *index += 1;
    let value = args
        .get(*index)
        .ok_or_else(|| Error::invalid(format!("option {flag} requires a value")))?;
    Ok(value.to_string_lossy().into_owned())
}

fn print_help() {
    println!(
        "Usage: yuhaiin-rust [run] [options]\n\nNo command is equivalent to `run` and starts the service.\nConsole logs are enabled by default; set YUHAIIN_QUIET=1 to disable them.\n\nOptions:\n  -host, --host ADDR       HTTP listen address (default 0.0.0.0:50051)\n  -path, --path DIR        Go-compatible data directory (DIR/state.db)\n  -u, --username NAME      HTTP Basic Auth username\n  -p, --password PASSWORD  HTTP Basic Auth password\n  -eweb, --external-web DIR  Accepted for Go service-command compatibility\n  -nfs-mode                Accepted for Go service-command compatibility\n  version                  Print version\n  update-helper TARGET STAGED  Apply a staged update"
    );
}

fn console_logs_enabled() -> bool {
    std::env::var_os("YUHAIIN_QUIET").is_none()
}

fn console_notice(message: impl std::fmt::Display) {
    if console_logs_enabled() {
        eprintln!("yuhaiin-rust: {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::{RunOptions, parse_run_options};
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_go_service_flags_and_maps_path_to_state_db() {
        let parsed = parse_run_options(&args(&[
            "run",
            "-host",
            "127.0.0.1:50051",
            "-path",
            "/var/lib/yuhaiin",
            "-u",
            "alice",
            "-p",
            "secret",
            "-nfs-mode",
        ]))
        .unwrap();
        assert_eq!(
            parsed,
            RunOptions {
                database: Some(PathBuf::from("/var/lib/yuhaiin/state.db")),
                listen: Some("127.0.0.1:50051".to_owned()),
                username: Some("alice".to_owned()),
                password: Some("secret".to_owned()),
                external_web: None,
            }
        );
    }

    #[test]
    fn rejects_missing_and_unknown_options() {
        assert!(parse_run_options(&args(&["-host"])).is_err());
        assert!(parse_run_options(&args(&["--unknown"])).is_err());
        assert!(parse_run_options(&args(&["run", "positional"])).is_err());
    }

    #[test]
    fn empty_arguments_mean_default_run() {
        assert_eq!(parse_run_options(&[]), Ok(RunOptions::default()));
    }
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
