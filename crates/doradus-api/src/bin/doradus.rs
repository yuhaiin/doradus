//! Runnable first-generation doradus service.
//!
//! The binary intentionally keeps process wiring small: SQLite is the source
//! of truth, the runtime controller owns reloads, the HTTP API owns control
//! traffic, and TUN/DNS tasks are optional data-plane owners.

use std::net::SocketAddr;
use std::path::PathBuf;

use doradus_api::service::{RuntimeService, ServiceOptions};
use doradus_core::{Error, ErrorKind, Result};

mod service;

const DEFAULT_HTTP_LISTEN: &str = "0.0.0.0:58080";

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
    quiet: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = main_result().await {
        eprintln!("doradus: fatal: {error}");
        std::process::exit(1);
    }
}

async fn main_result() -> Result<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
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
        doradus_runtime::update::run_update_helper(
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
        println!("doradus {}", env!("CARGO_PKG_VERSION"));
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
    if args.is_empty() {
        console_notice(
            options.quiet,
            "no command supplied; starting the service (same as `run`)",
        );
    }
    tokio::task::LocalSet::new()
        .run_until(run_with_shutdown(options, None))
        .await
}

async fn run_with_shutdown(
    options: RunOptions,
    #[cfg(windows)] service_shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
    #[cfg(not(windows))] _service_shutdown: Option<()>,
) -> Result<()> {
    let quiet = options.quiet;
    let database = options.database.unwrap_or_else(default_database_path);
    console_notice(quiet, format!("starting; database={}", database.display()));
    if let Some(parent) = database.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let listen = options
        .listen
        .unwrap_or_else(|| DEFAULT_HTTP_LISTEN.to_owned())
        .parse::<SocketAddr>()
        .map_err(|error| Error::invalid(format!("HTTP listen address is invalid: {error}")))?;
    console_notice(quiet, format!("binding HTTP API on {listen}"));
    let username = options.username.unwrap_or_default();
    let password = options.password.unwrap_or_default();
    let mut service_options = ServiceOptions::new(database, listen);
    service_options.username = username;
    service_options.password = password;
    service_options.external_web = options.external_web.map(PathBuf::from);
    let service = RuntimeService::start(service_options).await?;
    let logs = service.logs();
    if !quiet {
        logs.enable_console();
    }
    console_notice(quiet, "configuration database opened");
    console_notice(
        quiet,
        format!("HTTP API listening on http://{}", service.address()),
    );
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
        console_notice(
            quiet,
            format!("shutdown requested; stopping runtime tasks (signal={shutdown_reason})"),
        );
        let _ = signal_tx.send(true);
    });
    console_notice(
        quiet,
        "runtime ready; DNS, inbound and HTTP API supervisors started",
    );
    let result = service.wait().await;
    if result.is_ok() {
        console_notice(quiet, "stopped");
    }
    result
}

fn default_database_path() -> PathBuf {
    default_data_root().join("doradus/state.sqlite")
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
                    PathBuf::from(required_option_value(args, &mut index, &flag)?)
                        .join("state.sqlite"),
                );
            }
            "-u" | "--username" => {
                options.username = Some(required_option_value(args, &mut index, &flag)?);
            }
            "-p" | "--password" => {
                options.password = Some(required_option_value(args, &mut index, &flag)?);
            }
            "-q" | "--quiet" => options.quiet = true,
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
        "Usage: doradus [action] [options]\n\nActions:\n  install     install the native systemd/launchd/Windows Service\n  uninstall   uninstall the native service\n  rollback    restore the latest service backup\n  health      check native service state and /health\n  start       start the native service\n  stop        stop the native service\n  restart     restart the native service\n  run         run the service (default)\n\nNo command is equivalent to run and starts the service.\nConsole logs are enabled by default; use -q or --quiet to disable them.\n\nRun options:\n  -host, --host ADDR       HTTP listen address (default 0.0.0.0:58080)\n  -path, --path DIR        Doradus data directory (DIR/state.sqlite)\n  -u, --username NAME      HTTP Basic Auth username\n  -p, --password PASSWORD  HTTP Basic Auth password\n  -q, --quiet              disable console logs\n  -eweb, --external-web DIR  Accepted for service-command compatibility\n  -nfs-mode                Accepted for service-command compatibility\n\nInstall options:\n  -host, --host ADDR       HTTP listen address (default 0.0.0.0:58080)\n  -path, --path DIR        service data directory\n  -nfs-mode                preserve compatibility settings\n\nRollback/health options:\n  -host, --host ADDR       health endpoint address (0.0.0.0 is probed as 127.0.0.1)\n  -path, --path DIR        service data directory containing service-backups\n\nOther:\n  version                  print version\n  update-helper TARGET STAGED  apply a staged update"
    );
}

fn console_notice(quiet: bool, message: impl std::fmt::Display) {
    if !quiet {
        eprintln!("doradus: {message}");
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::{RunOptions, parse_run_options};
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_service_flags_and_maps_path_to_state_sqlite() {
        let parsed = parse_run_options(&args(&[
            "run",
            "-host",
            "127.0.0.1:58080",
            "-path",
            "/var/lib/doradus",
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
                database: Some(PathBuf::from("/var/lib/doradus/state.sqlite")),
                listen: Some("127.0.0.1:58080".to_owned()),
                username: Some("alice".to_owned()),
                password: Some("secret".to_owned()),
                external_web: None,
                quiet: false,
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
    fn quiet_switch_is_a_command_line_option() {
        assert!(parse_run_options(&args(&["--quiet"])).unwrap().quiet);
    }

    #[test]
    fn default_http_listener_uses_doradus_port() {
        assert_eq!(super::DEFAULT_HTTP_LISTEN, "0.0.0.0:58080");
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
