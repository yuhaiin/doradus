//! Runnable first-generation yuhaiin-rust service.
//!
//! The binary intentionally keeps process wiring small: SQLite is the source
//! of truth, the runtime controller owns reloads, the HTTP API owns control
//! traffic, and TUN/DNS tasks are optional data-plane owners.

use std::net::SocketAddr;
use std::path::PathBuf;

use yuhaiin_api::service::{RuntimeService, ServiceOptions};
use yuhaiin_core::{Error, ErrorKind, Result};

mod service;

// Use mimalloc on every platform. On non-Windows targets PprofAlloc wraps it
// and records sampled allocation stacks in both Debug and Release builds.
#[cfg(not(windows))]
#[global_allocator]
static ALLOC: pprof_alloc::PprofAlloc = pprof_alloc::PprofAlloc::new()
    .with_default(pprof_alloc::Allocator::Mimalloc)
    .with_pprof();

#[cfg(windows)]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

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
    #[cfg(windows)]
    if args
        .first()
        .map(|arg| arg == "--windows-service")
        .unwrap_or(false)
    {
        return service::run_windows_service(args[1..].to_vec());
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
    if let Some(action) = args.first().and_then(|arg| arg.to_str())
        && matches!(
            action,
            "install" | "uninstall" | "rollback" | "health" | "start" | "stop" | "restart"
        )
    {
        service::run(action, &args[1..])?;
        return Ok(());
    }
    let options = parse_run_options(&args)?;
    tokio::task::LocalSet::new()
        .run_until(run_with_shutdown(options, None))
        .await
}

async fn run_with_shutdown(
    options: RunOptions,
    #[cfg(windows)] service_shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
    #[cfg(not(windows))] _service_shutdown: Option<()>,
) -> Result<()> {
    let database = options
        .database
        .or_else(|| std::env::var_os("YUHAIIN_DB").map(PathBuf::from))
        .unwrap_or_else(default_database_path);
    console_notice(format!("starting; database={}", database.display()));
    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let listen = options
        .listen
        .or_else(|| std::env::var("YUHAIIN_HTTP").ok())
        .unwrap_or_else(|| "0.0.0.0:50051".to_owned())
        .parse::<SocketAddr>()
        .map_err(|error| Error::invalid(format!("YUHAIIN_HTTP is invalid: {error}")))?;
    console_notice(format!("binding HTTP API on {listen}"));
    let username = options
        .username
        .or_else(|| std::env::var("YUHAIIN_API_USERNAME").ok())
        .unwrap_or_default();
    let password = options
        .password
        .or_else(|| std::env::var("YUHAIIN_API_PASSWORD").ok())
        .unwrap_or_default();
    let mut service_options = ServiceOptions::new(database, listen);
    service_options.username = username;
    service_options.password = password;
    service_options.external_web = options.external_web.map(PathBuf::from);
    let service = RuntimeService::start(service_options).await?;
    let logs = service.logs();
    if console_logs_enabled() {
        logs.enable_console();
    }
    console_notice("configuration database opened");
    console_notice(format!(
        "HTTP API listening on http://{}",
        service.address()
    ));
    let signal_tx = service.shutdown_handle();
    tokio::spawn(async move {
        let shutdown_reason = {
            #[cfg(windows)]
            {
                if let Some(mut service_shutdown) = service_shutdown {
                    tokio::select! {
                        reason = wait_for_process_shutdown() => reason,
                        _ = &mut service_shutdown => "Windows service stop".to_owned(),
                    }
                } else {
                    wait_for_process_shutdown().await
                }
            }
            #[cfg(not(windows))]
            {
                wait_for_process_shutdown().await
            }
        };
        console_notice(format!(
            "shutdown requested; stopping runtime tasks (signal={shutdown_reason})"
        ));
        let _ = signal_tx.send(true);
    });
    console_notice("runtime ready; DNS, inbound and HTTP API supervisors started");
    let result = service.wait().await;
    if result.is_ok() {
        console_notice("stopped");
    }
    result
}

fn default_database_path() -> PathBuf {
    let config_root = default_config_root();
    let data_root = default_data_root();
    let go_path = config_root.join("yuhaiin/state.db");
    let rust_path = data_root.join("yuhaiin-rust/state.sqlite");
    choose_database_path(&go_path, &rust_path, go_path.exists(), rust_path.exists())
}

fn default_config_root() -> PathBuf {
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join("Library/Application Support");
    }

    #[cfg(windows)]
    if let Some(appdata) = std::env::var_os("APPDATA") {
        return PathBuf::from(appdata);
    }

    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn default_data_root() -> PathBuf {
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join("Library/Application Support");
    }

    #[cfg(windows)]
    if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local_appdata);
    }

    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn choose_database_path(
    go_path: &std::path::Path,
    rust_path: &std::path::Path,
    go_exists: bool,
    rust_exists: bool,
) -> PathBuf {
    if go_exists || !rust_exists {
        go_path.to_owned()
    } else {
        rust_path.to_owned()
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
        "Usage: yuhaiin-rust [action] [options]\n\nActions:\n  install     install the native systemd/launchd/Windows Service\n  uninstall   uninstall the native service\n  rollback    restore the latest automatic service backup\n  health      check native service state and /health\n  start       start the native service\n  stop        stop the native service\n  restart     restart the native service\n  run         run the service (default)\n\nNo command is equivalent to run and starts the service.\nConsole logs are enabled by default; set YUHAIIN_QUIET=1 to disable them.\n\nRun options:\n  -host, --host ADDR       HTTP listen address (default 0.0.0.0:50051)\n  -path, --path DIR        Go-compatible data directory (DIR/state.db)\n  -u, --username NAME      HTTP Basic Auth username\n  -p, --password PASSWORD  HTTP Basic Auth password\n  -eweb, --external-web DIR  Accepted for Go service-command compatibility\n  -nfs-mode                Accepted for Go service-command compatibility\n\nInstall options:\n  -host, --host ADDR       HTTP listen address (default 0.0.0.0:50051)\n  -path, --path DIR        service data directory\n  -nfs-mode                preserve Go service compatibility\n\nRollback/health options:\n  -host, --host ADDR       health endpoint address (0.0.0.0 is probed as 127.0.0.1)\n  -path, --path DIR        service data directory containing service-backups\n\nOther:\n  version                  print version\n  update-helper TARGET STAGED  apply a staged update"
    );
}

fn console_logs_enabled() -> bool {
    !quiet_env_value_enabled(std::env::var("YUHAIIN_QUIET").ok().as_deref())
}

fn quiet_env_value_enabled(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn console_notice(message: impl std::fmt::Display) {
    if console_logs_enabled() {
        eprintln!("yuhaiin-rust: {message}");
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::{RunOptions, choose_database_path, parse_run_options, quiet_env_value_enabled};
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

    #[test]
    fn prefers_existing_go_state_for_backend_replacement() {
        let go_path = PathBuf::from("config/yuhaiin/state.db");
        let rust_path = PathBuf::from("data/yuhaiin-rust/state.sqlite");
        assert_eq!(
            choose_database_path(&go_path, &rust_path, true, true),
            go_path
        );
    }

    #[test]
    fn reuses_existing_rust_state_only_when_go_state_is_absent() {
        let go_path = PathBuf::from("config/yuhaiin/state.db");
        let rust_path = PathBuf::from("data/yuhaiin-rust/state.sqlite");
        assert_eq!(
            choose_database_path(&go_path, &rust_path, false, true),
            rust_path
        );
        assert_eq!(
            choose_database_path(&go_path, &rust_path, false, false),
            go_path
        );
    }

    #[test]
    fn quiet_switch_requires_an_explicit_truthy_value() {
        assert!(!quiet_env_value_enabled(None));
        assert!(!quiet_env_value_enabled(Some("0")));
        assert!(!quiet_env_value_enabled(Some("false")));
        assert!(quiet_env_value_enabled(Some("1")));
        assert!(quiet_env_value_enabled(Some(" TRUE ")));
        assert!(quiet_env_value_enabled(Some("on")));
    }
}

async fn wait_for_process_shutdown() -> String {
    #[cfg(unix)]
    {
        let signals = (
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()),
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit()),
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()),
        );
        match signals {
            (Ok(mut sighup), Ok(mut sigquit), Ok(mut sigterm)) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => match result {
                        Ok(()) => "SIGINT (Ctrl-C)".to_owned(),
                        Err(error) => format!("SIGINT handler error: {error}"),
                    },
                    signal = sighup.recv() => if signal.is_some() {
                        "SIGHUP".to_owned()
                    } else {
                        "SIGHUP stream closed".to_owned()
                    },
                    signal = sigquit.recv() => if signal.is_some() {
                        "SIGQUIT".to_owned()
                    } else {
                        "SIGQUIT stream closed".to_owned()
                    },
                    signal = sigterm.recv() => if signal.is_some() {
                        "SIGTERM".to_owned()
                    } else {
                        "SIGTERM stream closed".to_owned()
                    },
                }
            }
            (sighup, sigquit, sigterm) => match tokio::signal::ctrl_c().await {
                Ok(()) => "SIGINT (Ctrl-C)".to_owned(),
                Err(error) => format!(
                    "signal setup error (SIGHUP={:?}, SIGQUIT={:?}, SIGTERM={:?}, SIGINT={error})",
                    sighup.err(),
                    sigquit.err(),
                    sigterm.err()
                ),
            },
        }
    }

    #[cfg(not(unix))]
    {
        match tokio::signal::ctrl_c().await {
            Ok(()) => "SIGINT (Ctrl-C)".to_owned(),
            Err(error) => format!("SIGINT handler error: {error}"),
        }
    }
}

fn io_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}
