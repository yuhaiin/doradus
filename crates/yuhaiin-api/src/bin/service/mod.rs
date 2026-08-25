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
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;
