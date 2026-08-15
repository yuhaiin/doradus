//! Native service-manager integration for the runtime binary.
//!
//! The data plane remains in yuhaiin-runtime; this module only owns the
//! executable's install/start/stop lifecycle so replacing the Go binary does
//! not require a second wrapper command. Linux, macOS and Windows use their
//! native service managers and share the same option parser.

use std::ffi::OsString;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::fs;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::io::{Read, Write};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::net::{IpAddr, SocketAddr, TcpStream};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::UNIX_EPOCH;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::time::{Duration, SystemTime};

use yuhaiin_core::{Error, ErrorKind, Result};

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceOptions {
    host: String,
    path: PathBuf,
    nfs_mode: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl Default for ServiceOptions {
    fn default() -> Self {
        Self {
            host: "0.0.0.0:50051".to_owned(),
            path: default_service_path(),
            nfs_mode: false,
        }
    }
}

pub fn run(action: &str, _args: &[OsString]) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        return linux::run(action, _args);
    }
    #[cfg(target_os = "macos")]
    {
        return macos::run(action, _args);
    }
    #[cfg(target_os = "windows")]
    {
        return windows::run(action, _args);
    }
    #[allow(unreachable_code)]
    Err(Error::new(
        ErrorKind::Unsupported,
        format!("service action {action:?} is not implemented on this platform"),
    ))
}

#[cfg(target_os = "windows")]
pub fn run_windows_service(args: Vec<OsString>) -> Result<()> {
    windows::run_windows_service(args)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn parse_options(args: &[OsString]) -> Result<ServiceOptions> {
    let mut options = ServiceOptions::default();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].to_string_lossy();
        match flag.as_ref() {
            "-host" | "--host" | "-h" => {
                options.host = required_value(args, &mut index, &flag)?;
            }
            "-path" | "--path" | "-p" => {
                options.path = PathBuf::from(required_value(args, &mut index, &flag)?);
            }
            "-nfs-mode" | "--nfs-mode" => options.nfs_mode = true,
            other if other.starts_with('-') => {
                return Err(Error::invalid(format!("unknown service option {other:?}")));
            }
            other => {
                return Err(Error::invalid(format!(
                    "unexpected service argument {other:?}"
                )));
            }
        }
        index += 1;
    }
    if options.host.trim().is_empty() {
        return Err(Error::invalid("service HTTP host is empty"));
    }
    if options.path.as_os_str().is_empty() {
        return Err(Error::invalid("service data path is empty"));
    }
    Ok(options)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn required_value(args: &[OsString], index: &mut usize, flag: &str) -> Result<String> {
    *index += 1;
    args.get(*index)
        .map(|value| value.to_string_lossy().into_owned())
        .ok_or_else(|| Error::invalid(format!("service option {flag} requires a value")))
}

#[cfg(any(target_os = "macos", test))]
fn parse_launchd_pid(data: &[u8]) -> Option<i32> {
    for line in String::from_utf8_lossy(data).lines() {
        let line = line.trim().trim_end_matches(';');
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !key.trim().trim_matches('"').eq_ignore_ascii_case("pid") {
            continue;
        }
        let value = value.trim().trim_matches('"');
        if let Ok(pid) = value.parse::<i32>() {
            return Some(pid);
        }
    }
    None
}

#[cfg(any(target_os = "macos", test))]
fn is_missing_launchd_service(data: &[u8]) -> bool {
    let text = String::from_utf8_lossy(data).to_ascii_lowercase();
    text.contains("could not find service")
        || text.contains("service not found")
        || text.contains("no such process")
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn default_service_path() -> PathBuf {
    if cfg!(target_os = "windows") {
        PathBuf::from(r"C:\ProgramData\yuhaiin")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/yuhaiin")
    } else {
        PathBuf::from("/var/lib/yuhaiin")
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn service_error(message: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, message.to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn command_output(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(service_error)?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(service_error(format!(
            "{program} {} failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn require_root(action: &str) -> Result<()> {
    #[cfg(unix)]
    {
        let uid = Command::new("id")
            .arg("-u")
            .output()
            .map_err(service_error)?;
        if !uid.status.success() || String::from_utf8_lossy(&uid.stdout).trim() != "0" {
            return Err(Error::new(
                ErrorKind::Io,
                format!("{action} service requires root privileges; try running with sudo"),
            ));
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn current_executable() -> Result<PathBuf> {
    std::env::current_exe().map_err(service_error)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn same_file(left: &Path, right: &Path) -> bool {
    let Some(left) = fs::canonicalize(left).ok() else {
        return false;
    };
    let Some(right) = fs::canonicalize(right).ok() else {
        return false;
    };
    left == right
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn copy_binary(source: &Path, destination: &Path) -> Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(service_error)?;
    }
    let temporary = destination.with_extension(format!("new-{}", std::process::id()));
    let result = (|| {
        fs::copy(source, &temporary).map_err(service_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))
                .map_err(service_error)?;
        }
        #[cfg(windows)]
        {
            // Windows does not replace an existing file with rename(2). The
            // service is stopped before install/update, so this is safe here.
            let _ = fs::remove_file(destination);
        }
        fs::rename(&temporary, destination).map_err(service_error)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(service_error)?;
    }
    let temporary = path.with_extension(format!("new-{}", std::process::id()));
    let result = (|| {
        fs::write(&temporary, contents).map_err(service_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))
                .map_err(service_error)?;
        }
        fs::rename(&temporary, path).map_err(service_error)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn remove_entry(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(service_error(error)),
    };
    if metadata.is_dir() {
        return Err(service_error(format!(
            "refusing to replace service path {} because it is a directory",
            path.display()
        )));
    }
    fs::remove_file(path).map_err(service_error)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unix_timestamp() -> Result<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(service_error)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn health_target(host: &str) -> Result<SocketAddr> {
    let address = host
        .parse::<SocketAddr>()
        .map_err(|error| Error::invalid(format!("service health host is invalid: {error}")))?;
    let ip = match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    Ok(SocketAddr::new(ip, address.port()))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn check_http_health(host: &str) -> Result<()> {
    let target = health_target(host)?;
    let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(2))
        .map_err(|error| service_error(format!("connect health endpoint {target}: {error}")))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(service_error)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(service_error)?;
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(service_error)?;
    let mut response = [0u8; 128];
    let length = stream.read(&mut response).map_err(service_error)?;
    let response = String::from_utf8_lossy(&response[..length]);
    if response.starts_with("HTTP/1.1 2") || response.starts_with("HTTP/1.0 2") {
        Ok(())
    } else {
        Err(service_error(format!(
            "health endpoint {target} returned {:?}",
            response.lines().next().unwrap_or_default()
        )))
    }
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
mod tests {
    use super::{ServiceOptions, is_missing_launchd_service, parse_launchd_pid, parse_options};
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_go_compatible_install_options() {
        let parsed = parse_options(&args(&[
            "--host",
            "127.0.0.1:50051",
            "-p",
            "/var/lib/yuhaiin",
            "--nfs-mode",
        ]))
        .unwrap();
        assert_eq!(
            parsed,
            ServiceOptions {
                host: "127.0.0.1:50051".to_owned(),
                path: PathBuf::from("/var/lib/yuhaiin"),
                nfs_mode: true,
            }
        );
    }

    #[test]
    fn rejects_missing_values_unknown_flags_and_positional_arguments() {
        assert!(parse_options(&args(&["--host"])).is_err());
        assert!(parse_options(&args(&["--unknown", "value"])).is_err());
        assert!(parse_options(&args(&["unexpected"])).is_err());
    }

    #[test]
    fn parses_launchd_pid_without_trusting_field_order_or_case() {
        let output = br#"
            "Label" = "com.asutorufa.yuhaiin";
            "LastExitStatus" = 0;
            "pId" = "4312";
        "#;
        assert_eq!(parse_launchd_pid(output), Some(4312));
    }

    #[test]
    fn ignores_invalid_launchd_pid_entries() {
        assert_eq!(parse_launchd_pid(br#""PID" = "not-a-pid";"#), None);
        assert_eq!(parse_launchd_pid(br#""Other" = 4312;"#), None);
    }

    #[test]
    fn recognizes_launchctl_missing_service_errors() {
        assert!(is_missing_launchd_service(
            br#"Could not find service "com.asutorufa.yuhaiin" in domain for system"#
        ));
        assert!(is_missing_launchd_service(b"No such process"));
        assert!(!is_missing_launchd_service(b"launchctl: permission denied"));
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    const TARGET_BIN: &str = "/usr/local/bin/yuhaiin";
    const SERVICE_PATH: &str = "/etc/systemd/system/yuhaiin.service";
    const SERVICE_NAME: &str = "yuhaiin.service";
    const BACKUP_DIR: &str = "service-backups";

    pub fn run(action: &str, args: &[OsString]) -> Result<()> {
        match action {
            "install" => install(args),
            "uninstall" => uninstall(args),
            "rollback" => rollback(args),
            "health" => health(args),
            "start" => manage("start"),
            "stop" => manage("stop"),
            "restart" => manage("restart"),
            _ => Err(Error::invalid(format!("unknown service action {action:?}"))),
        }
    }

    fn install(args: &[OsString]) -> Result<()> {
        require_root("install")?;
        let options = parse_options(args)?;
        let executable = current_executable()?;
        let target = Path::new(TARGET_BIN);
        if is_symlink(target) && !same_file(&executable, target) {
            return Err(service_error(format!(
                "refusing to replace non-owned symlink {}",
                target.display()
            )));
        }
        let was_active = is_active();
        let backup = backup_current(&options, target, Path::new(SERVICE_PATH))?;
        let result = install_inner(&options, &executable, target);
        if let Err(error) = result {
            let rollback_error = restore_backup(&backup, target, Path::new(SERVICE_PATH));
            let _ = Command::new("systemctl").args(["daemon-reload"]).status();
            if was_active {
                let _ = Command::new("systemctl")
                    .args(["restart", SERVICE_NAME])
                    .status();
            } else {
                let _ = Command::new("systemctl")
                    .args(["stop", SERVICE_NAME])
                    .status();
            }
            return match rollback_error {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(service_error(format!(
                    "install failed: {error}; automatic rollback failed: {rollback_error}"
                ))),
            };
        }
        Ok(())
    }

    fn install_inner(options: &ServiceOptions, executable: &Path, target: &Path) -> Result<()> {
        if !same_file(executable, target) {
            copy_binary(executable, target)?;
        }
        fs::create_dir_all(&options.path).map_err(service_error)?;
        write_atomic(
            Path::new(SERVICE_PATH),
            render_unit(options).as_bytes(),
            0o644,
        )?;
        command_output("systemctl", &["daemon-reload"])?;
        command_output("systemctl", &["enable", SERVICE_NAME])?;
        if is_active() {
            command_output("systemctl", &["restart", SERVICE_NAME])?;
        } else {
            command_output("systemctl", &["start", SERVICE_NAME])?;
        }
        wait_for_health(&options.host)
    }

    fn uninstall(args: &[OsString]) -> Result<()> {
        require_root("uninstall")?;
        if !args.is_empty() {
            return Err(Error::invalid("uninstall takes no arguments"));
        }
        let _ = Command::new("systemctl")
            .args(["stop", SERVICE_NAME])
            .status();
        let _ = Command::new("systemctl")
            .args(["disable", SERVICE_NAME])
            .status();
        if Path::new(SERVICE_PATH).exists() {
            fs::remove_file(SERVICE_PATH).map_err(service_error)?;
        }
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        if !is_symlink(Path::new(TARGET_BIN)) && Path::new(TARGET_BIN).exists() {
            fs::remove_file(TARGET_BIN).map_err(service_error)?;
        }
        Ok(())
    }

    fn rollback(args: &[OsString]) -> Result<()> {
        require_root("rollback")?;
        let options = parse_options(args)?;
        let backup = latest_backup(&options)?;
        let was_active = is_active();
        restore_backup(&backup, Path::new(TARGET_BIN), Path::new(SERVICE_PATH))?;
        command_output("systemctl", &["daemon-reload"])?;
        if was_active {
            command_output("systemctl", &["restart", SERVICE_NAME])?;
            wait_for_health(&options.host)?;
        } else {
            let _ = Command::new("systemctl")
                .args(["stop", SERVICE_NAME])
                .status();
        }
        Ok(())
    }

    fn health(args: &[OsString]) -> Result<()> {
        let options = parse_options(args)?;
        if !is_active() {
            return Err(service_error(format!("{SERVICE_NAME} is not active")));
        }
        check_http_health(&options.host)
    }

    fn manage(action: &str) -> Result<()> {
        require_root(action)?;
        command_output("systemctl", &[action, SERVICE_NAME])?;
        Ok(())
    }

    fn is_active() -> bool {
        Command::new("systemctl")
            .args(["is-active", "--quiet", SERVICE_NAME])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    fn wait_for_health(host: &str) -> Result<()> {
        let deadline = SystemTime::now()
            .checked_add(Duration::from_secs(15))
            .ok_or_else(|| service_error("health-check deadline overflow"))?;
        loop {
            let error = match check_http_health(host) {
                Ok(()) => return Ok(()),
                Err(error) => error,
            };
            if SystemTime::now() >= deadline {
                return Err(error);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn backup_current(options: &ServiceOptions, target: &Path, unit: &Path) -> Result<PathBuf> {
        let root = options.path.join(BACKUP_DIR);
        fs::create_dir_all(&root).map_err(service_error)?;
        let directory = root.join(format!("{}-{}", unix_timestamp()?, std::process::id()));
        fs::create_dir_all(&directory).map_err(service_error)?;
        let result = (|| {
            let target_kind = capture_entry(target, &directory.join("target"))?;
            let unit_kind = capture_entry(unit, &directory.join("unit"))?;
            let manifest = format!("target={target_kind}\nunit={unit_kind}\n");
            fs::write(directory.join("manifest"), manifest).map_err(service_error)?;
            Ok::<_, Error>(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&directory);
        }
        result.map(|()| directory)
    }

    fn capture_entry(path: &Path, backup: &Path) -> Result<&'static str> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok("missing"),
            Err(error) => return Err(service_error(error)),
        };
        if metadata.is_dir() {
            return Err(service_error(format!(
                "refusing to back up directory {}",
                path.display()
            )));
        }
        if metadata.file_type().is_symlink() {
            let link = fs::read_link(path).map_err(service_error)?;
            std::os::unix::fs::symlink(link, backup).map_err(service_error)?;
            Ok("symlink")
        } else {
            fs::copy(path, backup).map_err(service_error)?;
            Ok("file")
        }
    }

    fn latest_backup(options: &ServiceOptions) -> Result<PathBuf> {
        let root = options.path.join(BACKUP_DIR);
        let mut directories = fs::read_dir(&root)
            .map_err(service_error)?
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                entry
                    .file_type()
                    .ok()
                    .filter(|file_type| file_type.is_dir())
                    .map(|_| entry.path())
            })
            .filter(|path| path.join("manifest").is_file())
            .collect::<Vec<_>>();
        directories.sort();
        directories.pop().ok_or_else(|| {
            service_error(format!("no service backup found under {}", root.display()))
        })
    }

    fn restore_backup(backup: &Path, target: &Path, unit: &Path) -> Result<()> {
        let manifest = fs::read_to_string(backup.join("manifest")).map_err(service_error)?;
        let target_kind = manifest_kind(&manifest, "target")?;
        let unit_kind = manifest_kind(&manifest, "unit")?;
        restore_entry(target_kind, &backup.join("target"), target, 0o755)?;
        restore_entry(unit_kind, &backup.join("unit"), unit, 0o644)
    }

    fn manifest_kind<'a>(manifest: &'a str, key: &str) -> Result<&'a str> {
        manifest
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .filter(|kind| matches!(*kind, "missing" | "file" | "symlink"))
            .ok_or_else(|| service_error(format!("service backup manifest has no valid {key}")))
    }

    fn restore_entry(kind: &str, backup: &Path, destination: &Path, mode: u32) -> Result<()> {
        remove_entry(destination)?;
        match kind {
            "missing" => Ok(()),
            "file" => {
                let contents = fs::read(backup).map_err(service_error)?;
                write_atomic(destination, &contents, mode)
            }
            "symlink" => {
                let link = fs::read_link(backup).map_err(service_error)?;
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent).map_err(service_error)?;
                }
                std::os::unix::fs::symlink(link, destination).map_err(service_error)
            }
            _ => Err(service_error(format!(
                "unknown service backup kind {kind:?}"
            ))),
        }
    }

    fn render_unit(options: &ServiceOptions) -> String {
        let nfs = if options.nfs_mode { " -nfs-mode" } else { "" };
        format!(
            "[Unit]\nDescription=yuhaiin transparent proxy\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nWorkingDirectory={}\nExecStart={} -host {} -path {}{}\nRestart=on-failure\nRestartSec=5\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=multi-user.target\n",
            systemd_escape(&options.path.to_string_lossy()),
            systemd_escape(TARGET_BIN),
            systemd_escape(&options.host),
            systemd_escape(&options.path.to_string_lossy()),
            nfs
        )
    }

    fn systemd_escape(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace(' ', "\\s")
            .replace('\t', "\\t")
            .replace('\n', "\\n")
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Write;
        use std::net::TcpListener;
        use std::thread;

        #[test]
        fn service_unit_keeps_go_arguments_and_escapes_paths() {
            let unit = render_unit(&ServiceOptions {
                host: "127.0.0.1:50051".to_owned(),
                path: PathBuf::from("/var/lib/yuhaiin data"),
                nfs_mode: true,
            });
            assert!(unit.contains(
                "ExecStart=/usr/local/bin/yuhaiin -host 127.0.0.1:50051 -path /var/lib/yuhaiin\\sdata -nfs-mode"
            ));
            assert!(unit.contains("WantedBy=multi-user.target"));
            assert!(unit.contains("After=network-online.target"));
            assert!(unit.contains("StandardOutput=journal"));
        }

        #[test]
        fn service_backup_restores_previous_files_and_missing_entries() {
            let root = std::env::var_os("XDG_CACHE_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
                .unwrap_or_else(|| PathBuf::from(".cache"))
                .join("yuhaiin-rust/service-unit-tests")
                .join(format!(
                    "{}-{}",
                    std::process::id(),
                    unix_timestamp().unwrap()
                ));
            fs::create_dir_all(&root).unwrap();
            let target = root.join("target");
            let unit = root.join("unit");
            fs::write(&target, b"old-binary").unwrap();
            fs::write(&unit, b"old-unit").unwrap();
            let options = ServiceOptions {
                host: "127.0.0.1:50051".to_owned(),
                path: root.clone(),
                nfs_mode: false,
            };
            let backup = backup_current(&options, &target, &unit).unwrap();
            fs::write(&target, b"new-binary").unwrap();
            fs::remove_file(&unit).unwrap();
            restore_backup(&backup, &target, &unit).unwrap();
            assert_eq!(fs::read(&target).unwrap(), b"old-binary");
            assert_eq!(fs::read(&unit).unwrap(), b"old-unit");
            fs::remove_file(&target).unwrap();
            fs::remove_file(&unit).unwrap();
            let missing_backup = backup_current(&options, &target, &unit).unwrap();
            fs::write(&target, b"new-binary").unwrap();
            fs::write(&unit, b"new-unit").unwrap();
            restore_backup(&missing_backup, &target, &unit).unwrap();
            assert!(!target.exists());
            assert!(!unit.exists());
            fs::remove_dir_all(&root).unwrap();
        }

        #[test]
        fn health_probe_accepts_unspecified_bind_address() {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let task = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 128];
                let _ = std::io::Read::read(&mut stream, &mut request);
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                    .unwrap();
            });
            check_http_health(&format!("0.0.0.0:{}", address.port())).unwrap();
            task.join().unwrap();
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    const TARGET_BIN: &str = "/usr/local/bin/yuhaiin";
    const PLIST_PATH: &str = "/Library/LaunchDaemons/com.asutorufa.yuhaiin.plist";
    const SERVICE: &str = "com.asutorufa.yuhaiin";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct LaunchdServiceState {
        pid: Option<i32>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum BackupKind {
        Missing,
        File,
        Symlink,
    }

    #[derive(Debug)]
    struct BackupEntry {
        original: PathBuf,
        backup: PathBuf,
        kind: BackupKind,
        mode: u32,
    }

    #[derive(Debug)]
    struct InstallBackup {
        target: Option<BackupEntry>,
        plist: BackupEntry,
    }

    pub fn run(action: &str, args: &[OsString]) -> Result<()> {
        match action {
            "install" => install(args),
            "uninstall" => uninstall(args),
            "rollback" => rollback(args),
            "health" => health(args),
            "start" => command_output(
                "launchctl",
                &["kickstart", "-kp", &format!("system/{SERVICE}")],
            )
            .map(|_| ()),
            "stop" => command_output("launchctl", &["kill", "TERM", &format!("system/{SERVICE}")])
                .map(|_| ()),
            "restart" => {
                let pid = command_output("launchctl", &["list", SERVICE])
                    .map(|output| super::parse_launchd_pid(&output))?
                    .filter(|pid| *pid > 0);
                command_output("launchctl", &["bootout", "system/", PLIST_PATH])?;
                if let Some(pid) = pid {
                    wait_for_process_exit(pid)?;
                }
                command_output("launchctl", &["bootstrap", "system", PLIST_PATH])?;
                command_output(
                    "launchctl",
                    &["kickstart", "-kp", &format!("system/{SERVICE}")],
                )
                .map(|_| ())
            }
            _ => Err(Error::invalid(format!("unknown service action {action:?}"))),
        }
    }

    fn wait_for_process_exit(pid: i32) -> Result<()> {
        let deadline = SystemTime::now()
            .checked_add(Duration::from_secs(30))
            .ok_or_else(|| service_error("service process exit deadline overflow"))?;
        loop {
            let probe = Command::new("kill")
                .args(["-0", &pid.to_string()])
                .output()
                .map_err(service_error)?;
            if !probe.status.success() {
                let stderr = String::from_utf8_lossy(&probe.stderr);
                if stderr.to_ascii_lowercase().contains("no such process") {
                    return Ok(());
                }
                return Err(service_error(format!(
                    "check stopped service process {pid} failed: {}",
                    stderr.trim()
                )));
            }
            if SystemTime::now() >= deadline {
                return Err(service_error(format!(
                    "timeout waiting for service process {pid} to stop"
                )));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn launchd_service_state() -> Result<Option<LaunchdServiceState>> {
        let output = Command::new("launchctl")
            .args(["list", SERVICE])
            .output()
            .map_err(service_error)?;
        if output.status.success() {
            return Ok(Some(LaunchdServiceState {
                pid: super::parse_launchd_pid(&output.stdout).filter(|pid| *pid > 0),
            }));
        }
        let mut details = output.stdout;
        details.extend_from_slice(&output.stderr);
        if super::is_missing_launchd_service(&details) {
            return Ok(None);
        }
        Err(service_error(format!(
            "launchctl list {SERVICE} failed: {}",
            String::from_utf8_lossy(&details).trim()
        )))
    }

    fn unload_service(state: LaunchdServiceState) -> Result<()> {
        command_output("launchctl", &["bootout", "system/", PLIST_PATH])?;
        if let Some(pid) = state.pid {
            wait_for_process_exit(pid)?;
        }
        Ok(())
    }

    fn bootout_loaded_service() -> Result<Option<LaunchdServiceState>> {
        let state = launchd_service_state()?;
        if let Some(state) = state {
            unload_service(state)?;
        }
        Ok(state)
    }

    fn restore_service(state: Option<LaunchdServiceState>) -> Result<()> {
        if state.is_none() {
            return Ok(());
        }
        command_output("launchctl", &["bootstrap", "system", PLIST_PATH])?;
        command_output(
            "launchctl",
            &["kickstart", "-kp", &format!("system/{SERVICE}")],
        )
        .map(|_| ())
    }

    fn backup_path(path: &Path, kind: &str) -> Result<PathBuf> {
        Ok(path.with_extension(format!(
            "install-{kind}-{}-{}",
            std::process::id(),
            unix_timestamp()?
        )))
    }

    fn capture_entry(path: &Path, backup: PathBuf, mode: u32) -> Result<BackupEntry> {
        if fs::symlink_metadata(&backup).is_ok() {
            return Err(service_error(format!(
                "refusing to overwrite stale install backup {}",
                backup.display()
            )));
        }
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BackupEntry {
                    original: path.to_path_buf(),
                    backup,
                    kind: BackupKind::Missing,
                    mode,
                });
            }
            Err(error) => return Err(service_error(error)),
        };
        if metadata.is_dir() {
            return Err(service_error(format!(
                "refusing to back up service directory {}",
                path.display()
            )));
        }
        let kind = if metadata.file_type().is_symlink() {
            let link = fs::read_link(path).map_err(service_error)?;
            if let Some(parent) = backup.parent() {
                fs::create_dir_all(parent).map_err(service_error)?;
            }
            std::os::unix::fs::symlink(link, &backup).map_err(service_error)?;
            BackupKind::Symlink
        } else {
            fs::copy(path, &backup).map_err(service_error)?;
            BackupKind::File
        };
        Ok(BackupEntry {
            original: path.to_path_buf(),
            backup,
            kind,
            mode,
        })
    }

    fn remove_backup(entry: &BackupEntry) -> Result<()> {
        if entry.kind == BackupKind::Missing {
            return Ok(());
        }
        match fs::remove_file(&entry.backup) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(service_error(error)),
        }
    }

    fn restore_entry(entry: &BackupEntry) -> Result<()> {
        remove_entry(&entry.original)?;
        match entry.kind {
            BackupKind::Missing => Ok(()),
            BackupKind::File => {
                let contents = fs::read(&entry.backup).map_err(service_error)?;
                write_atomic(&entry.original, &contents, entry.mode)
            }
            BackupKind::Symlink => {
                let link = fs::read_link(&entry.backup).map_err(service_error)?;
                if let Some(parent) = entry.original.parent() {
                    fs::create_dir_all(parent).map_err(service_error)?;
                }
                std::os::unix::fs::symlink(link, &entry.original).map_err(service_error)
            }
        }
    }

    impl InstallBackup {
        fn capture(target: &Path, plist: &Path, target_changed: bool) -> Result<Self> {
            let target = if target_changed {
                Some(capture_entry(
                    target,
                    backup_path(target, "target")?,
                    0o755,
                )?)
            } else {
                None
            };
            let plist = match capture_entry(plist, backup_path(plist, "plist")?, 0o700) {
                Ok(plist) => plist,
                Err(error) => {
                    if let Some(target) = &target {
                        let _ = restore_entry(target);
                        let _ = remove_backup(target);
                    }
                    return Err(error);
                }
            };
            Ok(Self { target, plist })
        }

        fn restore(&self) -> Result<()> {
            let mut errors = Vec::new();
            if let Some(target) = &self.target {
                if let Err(error) = restore_entry(target) {
                    errors.push(format!("restore binary: {error}"));
                }
            }
            if let Err(error) = restore_entry(&self.plist) {
                errors.push(format!("restore plist: {error}"));
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(service_error(errors.join("; ")))
            }
        }

        fn cleanup(&self) -> Result<()> {
            let mut errors = Vec::new();
            if let Some(target) = &self.target {
                if let Err(error) = remove_backup(target) {
                    errors.push(format!("remove binary backup: {error}"));
                }
            }
            if let Err(error) = remove_backup(&self.plist) {
                errors.push(format!("remove plist backup: {error}"));
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(service_error(errors.join("; ")))
            }
        }
    }

    fn install(args: &[OsString]) -> Result<()> {
        require_root("install")?;
        let options = parse_options(args)?;
        let executable = current_executable()?;
        let target = Path::new(TARGET_BIN);
        if is_symlink(target) && !same_file(&executable, target) {
            return Err(service_error(format!(
                "refusing to replace non-owned symlink {}",
                target.display()
            )));
        }
        let target_changed = !same_file(&executable, target);
        let previous_state = launchd_service_state()?;
        if let Some(state) = previous_state {
            if let Err(error) = unload_service(state) {
                let restore_error = restore_service(Some(state)).err();
                return Err(service_error(match restore_error {
                    Some(restore_error) => {
                        format!(
                            "stop existing launchd service failed: {error}; restore failed: {restore_error}"
                        )
                    }
                    None => format!("stop existing launchd service failed: {error}"),
                }));
            }
        }
        let backup = match InstallBackup::capture(target, Path::new(PLIST_PATH), target_changed) {
            Ok(backup) => backup,
            Err(error) => {
                let restore_error = restore_service(previous_state).err();
                return Err(service_error(match restore_error {
                    Some(restore_error) => {
                        format!(
                            "prepare launchd install failed: {error}; restore service failed: {restore_error}"
                        )
                    }
                    None => format!("prepare launchd install failed: {error}"),
                }));
            }
        };
        let result = (|| {
            if target_changed {
                copy_binary(&executable, target)?;
            }
            fs::create_dir_all(&options.path).map_err(service_error)?;
            write_atomic(
                Path::new(PLIST_PATH),
                render_plist(&options).as_bytes(),
                0o700,
            )?;
            command_output("launchctl", &["bootstrap", "system", PLIST_PATH])?;
            command_output(
                "launchctl",
                &["kickstart", "-kp", &format!("system/{SERVICE}")],
            )?;
            wait_for_health(&options.host)
        })();
        if let Err(error) = result {
            let mut details = vec![format!("launchd install failed: {error}")];
            match bootout_loaded_service() {
                Ok(_) => {
                    if let Err(restore_error) = backup.restore() {
                        details.push(format!("restore files failed: {restore_error}"));
                    }
                    if let Err(restore_error) = restore_service(previous_state) {
                        details.push(format!("restore previous service failed: {restore_error}"));
                    }
                }
                Err(teardown_error) => details.push(format!(
                    "cannot unload failed launchd service; files left untouched: {teardown_error}"
                )),
            }
            return Err(service_error(details.join("; ")));
        }
        if let Err(error) = backup.cleanup() {
            return Err(service_error(format!(
                "launchd install succeeded but cleanup of install backups failed: {error}"
            )));
        }
        Ok(())
    }

    fn uninstall(args: &[OsString]) -> Result<()> {
        require_root("uninstall")?;
        if !args.is_empty() {
            return Err(Error::invalid("uninstall takes no arguments"));
        }
        let _ = Command::new("launchctl")
            .args(["bootout", "system/", PLIST_PATH])
            .status();
        if Path::new(PLIST_PATH).exists() {
            fs::remove_file(PLIST_PATH).map_err(service_error)?;
        }
        if !is_symlink(Path::new(TARGET_BIN)) && Path::new(TARGET_BIN).exists() {
            fs::remove_file(TARGET_BIN).map_err(service_error)?;
        }
        Ok(())
    }

    fn health(args: &[OsString]) -> Result<()> {
        let options = parse_options(args)?;
        let output = command_output("launchctl", &["print", &format!("system/{SERVICE}")])?;
        if !String::from_utf8_lossy(&output).contains("state = running") {
            return Err(service_error(format!("{SERVICE} is not running")));
        }
        check_http_health(&options.host)
    }

    fn rollback(args: &[OsString]) -> Result<()> {
        require_root("rollback")?;
        let options = parse_options(args)?;
        let target = Path::new(TARGET_BIN);
        let backup = target.with_extension("update-backup");
        if !backup.is_file() {
            return Err(service_error(format!(
                "no automatic update backup found at {}",
                backup.display()
            )));
        }
        let _ = Command::new("launchctl")
            .args(["bootout", "system/", PLIST_PATH])
            .status();
        let current = target.with_extension("rollback-current");
        let _ = fs::remove_file(&current);
        fs::rename(target, &current).map_err(service_error)?;
        if let Err(error) = fs::rename(&backup, target) {
            let _ = fs::rename(&current, target);
            return Err(service_error(format!("restore launchd binary: {error}")));
        }
        if let Err(error) = command_output("launchctl", &["bootstrap", "system", PLIST_PATH])
            .and_then(|_| {
                command_output(
                    "launchctl",
                    &["kickstart", "-kp", &format!("system/{SERVICE}")],
                )
            })
            .and_then(|_| wait_for_health(&options.host))
        {
            let _ = Command::new("launchctl")
                .args(["bootout", "system/", PLIST_PATH])
                .status();
            let _ = fs::remove_file(target);
            let _ = fs::rename(&current, target);
            let _ = Command::new("launchctl")
                .args(["bootstrap", "system", PLIST_PATH])
                .status();
            let _ = Command::new("launchctl")
                .args(["kickstart", "-kp", &format!("system/{SERVICE}")])
                .status();
            return Err(service_error(format!("launchd rollback failed: {error}")));
        }
        let _ = fs::remove_file(current);
        Ok(())
    }

    fn wait_for_health(host: &str) -> Result<()> {
        let deadline = SystemTime::now()
            .checked_add(Duration::from_secs(15))
            .ok_or_else(|| service_error("health-check deadline overflow"))?;
        loop {
            let error = match check_http_health(host) {
                Ok(()) => return Ok(()),
                Err(error) => error,
            };
            if SystemTime::now() >= deadline {
                return Err(error);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn render_plist(options: &ServiceOptions) -> String {
        let mut arguments = format!(
            "        <string>{}</string>\n        <string>-host</string>\n        <string>{}</string>\n        <string>-path</string>\n        <string>{}</string>\n",
            xml_escape(TARGET_BIN),
            xml_escape(&options.host),
            xml_escape(&options.path.to_string_lossy()),
        );
        if options.nfs_mode {
            arguments.push_str("        <string>-nfs-mode</string>\n");
        }
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n    <key>Label</key>\n    <string>{SERVICE}</string>\n    <key>ProgramArguments</key>\n    <array>\n{arguments}    </array>\n    <key>RunAtLoad</key>\n    <true/>\n    <key>KeepAlive</key>\n    <true/>\n    <key>UserName</key>\n    <string>root</string>\n    <key>StandardOutPath</key>\n    <string>/var/log/yuhaiin.log</string>\n    <key>StandardErrorPath</key>\n    <string>/var/log/yuhaiin.log</string>\n</dict>\n</plist>\n"
        )
    }

    fn xml_escape(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn launchd_plist_contains_runtime_arguments_and_nfs_mode() {
            let plist = render_plist(&ServiceOptions {
                host: "127.0.0.1:50051".to_owned(),
                path: PathBuf::from("/Library/Application Support/yuhaiin"),
                nfs_mode: true,
            });
            assert!(plist.contains("com.asutorufa.yuhaiin"));
            assert!(plist.contains("<string>-nfs-mode</string>"));
            assert!(plist.contains("Application Support/yuhaiin"));
        }

        #[test]
        fn install_backup_restores_changed_and_missing_entries() {
            let root = std::env::var_os("XDG_CACHE_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
                .unwrap_or_else(|| PathBuf::from(".cache"))
                .join("yuhaiin-rust/service-unit-tests")
                .join(format!(
                    "macos-{}-{}",
                    std::process::id(),
                    unix_timestamp().unwrap()
                ));
            fs::create_dir_all(&root).unwrap();
            let target = root.join("target");
            let plist = root.join("plist");

            fs::write(&target, b"old-binary").unwrap();
            fs::write(&plist, b"old-plist").unwrap();
            let backup = InstallBackup::capture(&target, &plist, true).unwrap();
            fs::write(&target, b"new-binary").unwrap();
            fs::write(&plist, b"new-plist").unwrap();
            backup.restore().unwrap();
            assert_eq!(fs::read(&target).unwrap(), b"old-binary");
            assert_eq!(fs::read(&plist).unwrap(), b"old-plist");
            backup.cleanup().unwrap();

            fs::remove_file(&target).unwrap();
            fs::remove_file(&plist).unwrap();
            let missing = InstallBackup::capture(&target, &plist, true).unwrap();
            fs::write(&target, b"new-binary").unwrap();
            fs::write(&plist, b"new-plist").unwrap();
            missing.restore().unwrap();
            assert!(!target.exists());
            assert!(!plist.exists());
            missing.cleanup().unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use std::sync::OnceLock;

    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
        ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    const SERVICE_NAME: &str = "yuhaiin";
    const TARGET_BIN: &str = r"C:\Program Files\yuhaiin\yuhaiin.exe";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    static SERVICE_ARGUMENTS: OnceLock<Vec<OsString>> = OnceLock::new();

    pub fn run(action: &str, args: &[OsString]) -> Result<()> {
        match action {
            "install" => install(args),
            "uninstall" => uninstall(args),
            "rollback" => rollback(args),
            "health" => health(args),
            "start" | "stop" | "restart" => manage(action),
            _ => Err(Error::invalid(format!("unknown service action {action:?}"))),
        }
    }

    fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
        ServiceManager::local_computer(None::<&str>, access).map_err(service_error)
    }

    fn open_service(manager: &ServiceManager) -> Result<windows_service::service::Service> {
        manager
            .open_service(SERVICE_NAME, service_access())
            .map_err(service_error)
    }

    fn service_access() -> ServiceAccess {
        ServiceAccess::QUERY_STATUS
            | ServiceAccess::START
            | ServiceAccess::STOP
            | ServiceAccess::DELETE
            | ServiceAccess::CHANGE_CONFIG
            | ServiceAccess::QUERY_CONFIG
    }

    fn install(args: &[OsString]) -> Result<()> {
        let options = parse_options(args)?;
        let manager =
            manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
        if manager
            .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
            .is_ok()
        {
            return Err(service_error(format!(
                "Windows service {SERVICE_NAME:?} is already installed"
            )));
        }
        let executable = current_executable()?;
        let target = Path::new(TARGET_BIN);
        if is_symlink(target) && !same_file(&executable, target) {
            return Err(service_error(format!(
                "refusing to replace non-owned symlink {}",
                target.display()
            )));
        }
        let binary_backup = if same_file(&executable, target) {
            None
        } else {
            Some(prepare_binary_install(&executable, target)?)
        };
        if let Err(error) = fs::create_dir_all(&options.path).map_err(service_error) {
            if let Err(restore_error) = restore_binary_install(target, binary_backup.as_deref()) {
                return Err(service_error(format!(
                    "create service data directory failed: {error}; restore binary failed: {restore_error}"
                )));
            }
            return Err(error);
        }
        let service = match manager
            .create_service(&service_info(&options, target), service_access())
        {
            Ok(service) => service,
            Err(error) => {
                let error = service_error(error);
                if let Err(restore_error) = restore_binary_install(target, binary_backup.as_deref())
                {
                    return Err(service_error(format!(
                        "create Windows service failed: {error}; restore binary failed: {restore_error}"
                    )));
                }
                return Err(error);
            }
        };
        let result = (|| {
            service
                .set_description("yuhaiin transparent proxy")
                .map_err(service_error)?;
            service
                .update_failure_actions(ServiceFailureActions {
                    reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(60)),
                    reboot_msg: None,
                    command: None,
                    actions: Some(recovery_actions()),
                })
                .map_err(service_error)?;
            service
                .set_failure_actions_on_non_crash_failures(true)
                .map_err(service_error)?;
            start_service(&service)?;
            wait_for_health(&options.host)
        })();
        if let Err(error) = result {
            let cleanup_error = cleanup_created_service(&manager, &service).err();
            drop(service);
            let restore_error = restore_binary_install(target, binary_backup.as_deref()).err();
            let mut message = format!("install Windows service failed: {error}");
            if let Some(cleanup_error) = cleanup_error {
                message.push_str(&format!("; cleanup failed: {cleanup_error}"));
            }
            if let Some(restore_error) = restore_error {
                message.push_str(&format!("; restore binary failed: {restore_error}"));
            }
            return Err(service_error(message));
        }
        drop(service);
        if let Some(backup) = binary_backup {
            let _ = fs::remove_file(backup);
        }
        Ok(())
    }

    fn prepare_binary_install(source: &Path, target: &Path) -> Result<PathBuf> {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(service_error)?;
        }
        let backup = target.with_extension(format!("install-backup-{}", std::process::id()));
        if target.exists() {
            fs::rename(target, &backup).map_err(service_error)?;
        }
        if let Err(error) = copy_binary(source, target) {
            let _ = fs::remove_file(target);
            return match fs::rename(&backup, target) {
                Ok(()) => Err(error),
                Err(restore_error) => Err(service_error(format!(
                    "install service binary failed: {error}; restore previous binary failed: {restore_error}"
                ))),
            };
        }
        Ok(backup)
    }

    fn restore_binary_install(target: &Path, backup: Option<&Path>) -> Result<()> {
        if target.exists() || is_symlink(target) {
            fs::remove_file(target).map_err(service_error)?;
        }
        if let Some(backup) = backup {
            if backup.exists() {
                fs::rename(backup, target).map_err(service_error)?;
            }
        }
        Ok(())
    }

    fn cleanup_created_service(
        manager: &ServiceManager,
        service: &windows_service::service::Service,
    ) -> Result<()> {
        let _ = stop_service(service);
        service.delete().map_err(service_error)?;
        wait_for_deleted(manager);
        Ok(())
    }

    fn recovery_actions() -> Vec<ServiceAction> {
        [1_u64, 2, 4, 9, 16, 25, 36, 49, 64]
            .into_iter()
            .map(|seconds| ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(seconds),
            })
            .collect()
    }

    fn service_info(options: &ServiceOptions, target: &Path) -> ServiceInfo {
        let mut launch_arguments = vec![OsString::from("--windows-service")];
        launch_arguments.extend([
            OsString::from("-host"),
            OsString::from(&options.host),
            OsString::from("-path"),
            options.path.clone().into_os_string(),
        ]);
        if options.nfs_mode {
            launch_arguments.push(OsString::from("-nfs-mode"));
        }
        ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from("yuhaiin"),
            service_type: SERVICE_TYPE,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: target.to_path_buf(),
            launch_arguments,
            dependencies: Vec::new(),
            account_name: None,
            account_password: None,
        }
    }

    fn uninstall(args: &[OsString]) -> Result<()> {
        if !args.is_empty() {
            return Err(Error::invalid("uninstall takes no arguments"));
        }
        let manager = manager(ServiceManagerAccess::CONNECT)?;
        let service = open_service(&manager)?;
        stop_service(&service)?;
        service.delete().map_err(service_error)?;
        drop(service);
        wait_for_deleted(&manager);
        let target = Path::new(TARGET_BIN);
        if !is_symlink(target) && target.exists() {
            fs::remove_file(target).map_err(service_error)?;
        }
        Ok(())
    }

    fn rollback(args: &[OsString]) -> Result<()> {
        let options = parse_options(args)?;
        let target = Path::new(TARGET_BIN);
        let backup = target.with_extension("update-backup");
        if !backup.is_file() {
            return Err(service_error(format!(
                "no automatic update backup found at {}",
                backup.display()
            )));
        }
        let manager = manager(ServiceManagerAccess::CONNECT)?;
        let service = open_service(&manager)?;
        stop_service(&service)?;
        let current = target.with_extension("rollback-current");
        let _ = fs::remove_file(&current);
        fs::rename(target, &current).map_err(service_error)?;
        if let Err(error) = fs::rename(&backup, target) {
            let _ = fs::rename(&current, target);
            return Err(service_error(format!(
                "restore Windows service binary: {error}"
            )));
        }
        if let Err(error) = start_service(&service).and_then(|_| wait_for_health(&options.host)) {
            let _ = stop_service(&service);
            let _ = fs::remove_file(target);
            let _ = fs::rename(&current, target);
            let _ = start_service(&service);
            return Err(service_error(format!(
                "Windows service rollback failed: {error}"
            )));
        }
        let _ = fs::remove_file(current);
        Ok(())
    }

    fn health(args: &[OsString]) -> Result<()> {
        let options = parse_options(args)?;
        let manager = manager(ServiceManagerAccess::CONNECT)?;
        let service = open_service(&manager)?;
        let status = service.query_status().map_err(service_error)?;
        if status.current_state != ServiceState::Running {
            return Err(service_error(format!(
                "{SERVICE_NAME} is {:?}",
                status.current_state
            )));
        }
        check_http_health(&options.host)
    }

    fn manage(action: &str) -> Result<()> {
        let manager = manager(ServiceManagerAccess::CONNECT)?;
        let service = open_service(&manager)?;
        match action {
            "start" => start_service(&service),
            "stop" => stop_service(&service),
            "restart" => {
                stop_service(&service)?;
                start_service(&service)
            }
            _ => Err(Error::invalid(format!("unknown service action {action:?}"))),
        }
    }

    fn start_service(service: &windows_service::service::Service) -> Result<()> {
        let status = service.query_status().map_err(service_error)?;
        if status.current_state == ServiceState::Running {
            return Ok(());
        }
        if status.current_state != ServiceState::StartPending {
            service.start::<&OsStr>(&[]).map_err(service_error)?;
        }
        wait_for_state(service, ServiceState::Running)
    }

    fn stop_service(service: &windows_service::service::Service) -> Result<()> {
        let status = service.query_status().map_err(service_error)?;
        if status.current_state == ServiceState::Stopped {
            return Ok(());
        }
        if status.current_state != ServiceState::StopPending {
            service.stop().map_err(service_error)?;
        }
        wait_for_state(service, ServiceState::Stopped)
    }

    fn wait_for_state(
        service: &windows_service::service::Service,
        expected: ServiceState,
    ) -> Result<()> {
        let deadline = SystemTime::now()
            .checked_add(Duration::from_secs(30))
            .ok_or_else(|| service_error("service state deadline overflow"))?;
        loop {
            let status = service.query_status().map_err(service_error)?;
            if status.current_state == expected {
                return Ok(());
            }
            if SystemTime::now() >= deadline {
                return Err(service_error(format!(
                    "timed out waiting for {SERVICE_NAME} to reach {expected:?}; current={:?}",
                    status.current_state
                )));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn wait_for_deleted(manager: &ServiceManager) {
        let deadline = SystemTime::now().checked_add(Duration::from_secs(15));
        while deadline.is_some_and(|deadline| SystemTime::now() < deadline) {
            if manager
                .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
                .is_err()
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn wait_for_health(host: &str) -> Result<()> {
        let deadline = SystemTime::now()
            .checked_add(Duration::from_secs(15))
            .ok_or_else(|| service_error("health-check deadline overflow"))?;
        loop {
            let error = match check_http_health(host) {
                Ok(()) => return Ok(()),
                Err(error) => error,
            };
            if SystemTime::now() >= deadline {
                return Err(error);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    define_windows_service!(ffi_service_main, windows_service_main);

    pub fn run_windows_service(args: Vec<OsString>) -> Result<()> {
        SERVICE_ARGUMENTS
            .set(args)
            .map_err(|_| service_error("Windows service dispatcher was started twice"))?;
        service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(service_error)
    }

    fn windows_service_main(arguments: Vec<OsString>) {
        if let Err(error) = run_windows_service_inner(arguments) {
            eprintln!("yuhaiin-rust Windows service: {error}");
        }
    }

    fn run_windows_service_inner(arguments: Vec<OsString>) -> Result<()> {
        let mut arguments = if arguments.len() > 1 {
            arguments
        } else {
            SERVICE_ARGUMENTS.get().cloned().unwrap_or_default()
        };
        if arguments
            .first()
            .is_some_and(|argument| argument == SERVICE_NAME)
        {
            arguments.remove(0);
        }
        let arguments = arguments
            .into_iter()
            .filter(|argument| argument != "--windows-service")
            .collect::<Vec<_>>();
        let options = super::super::parse_run_options(&arguments)?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let shutdown_tx = std::sync::Mutex::new(Some(shutdown_tx));
        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                    if let Ok(mut sender) = shutdown_tx.lock() {
                        if let Some(sender) = sender.take() {
                            let _ = sender.send(());
                        }
                    }
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
            .map_err(service_error)?;
        status_handle
            .set_service_status(status(
                ServiceState::StartPending,
                ServiceControlAccept::empty(),
            ))
            .map_err(service_error)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(service_error)?;
        status_handle
            .set_service_status(status(
                ServiceState::Running,
                ServiceControlAccept::STOP
                    | ServiceControlAccept::SHUTDOWN
                    | ServiceControlAccept::PRESHUTDOWN,
            ))
            .map_err(service_error)?;
        let result = tokio::task::LocalSet::new().block_on(
            &runtime,
            super::super::run_with_shutdown(options, Some(shutdown_rx)),
        );
        let exit_code = if result.is_ok() {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::Win32(1)
        };
        status_handle
            .set_service_status(ServiceStatus {
                exit_code,
                ..status(ServiceState::Stopped, ServiceControlAccept::empty())
            })
            .map_err(service_error)?;
        result
    }

    fn status(state: ServiceState, accepted: ServiceControlAccept) -> ServiceStatus {
        ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: state,
            controls_accepted: accepted,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn service_info_uses_native_service_entry_and_compatible_flags() {
            let options = ServiceOptions {
                host: "127.0.0.1:50051".to_owned(),
                path: PathBuf::from(r"C:\ProgramData\yuhaiin"),
                nfs_mode: true,
            };
            let info = service_info(&options, Path::new(TARGET_BIN));
            assert_eq!(info.name, OsString::from(SERVICE_NAME));
            assert_eq!(info.start_type, ServiceStartType::AutoStart);
            assert_eq!(info.launch_arguments[0], "--windows-service");
            assert!(info.launch_arguments.contains(&OsString::from("-nfs-mode")));
        }

        #[test]
        fn recovery_actions_match_go_service_policy() {
            let delays = recovery_actions()
                .into_iter()
                .map(|action| action.delay)
                .collect::<Vec<_>>();
            assert_eq!(
                delays,
                [1_u64, 2, 4, 9, 16, 25, 36, 49, 64]
                    .into_iter()
                    .map(Duration::from_secs)
                    .collect::<Vec<_>>()
            );
        }
    }
}
