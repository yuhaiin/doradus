//! Native service-manager integration for the runtime binary.
//!
//! The data plane remains in yuhaiin-runtime; this module only owns the
//! executable's install/start/stop lifecycle so replacing the Go binary does
//! not require a second wrapper command. Linux and macOS use their native
//! command-line managers and share the same option parser.

use std::ffi::OsString;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::{Read, Write};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::net::{IpAddr, SocketAddr, TcpStream};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use yuhaiin_core::{Error, ErrorKind, Result};

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceOptions {
    host: String,
    path: PathBuf,
    nfs_mode: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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
    #[allow(unreachable_code)]
    Err(Error::new(
        ErrorKind::Unsupported,
        format!("service action {action:?} is not implemented on this platform"),
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn required_value(args: &[OsString], index: &mut usize, flag: &str) -> Result<String> {
    *index += 1;
    args.get(*index)
        .map(|value| value.to_string_lossy().into_owned())
        .ok_or_else(|| Error::invalid(format!("service option {flag} requires a value")))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn default_service_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/yuhaiin")
    } else {
        PathBuf::from("/var/lib/yuhaiin")
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn current_executable() -> Result<PathBuf> {
    std::env::current_exe().map_err(service_error)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn same_file(left: &Path, right: &Path) -> bool {
    let Some(left) = fs::canonicalize(left).ok() else {
        return false;
    };
    let Some(right) = fs::canonicalize(right).ok() else {
        return false;
    };
    left == right
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::{ServiceOptions, parse_options};
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

    pub fn run(action: &str, args: &[OsString]) -> Result<()> {
        match action {
            "install" => install(args),
            "uninstall" => uninstall(args),
            "start" => command_output(
                "launchctl",
                &["kickstart", "-kp", &format!("system/{SERVICE}")],
            )
            .map(|_| ()),
            "stop" => command_output("launchctl", &["kill", "TERM", &format!("system/{SERVICE}")])
                .map(|_| ()),
            "restart" => {
                let _ = Command::new("launchctl")
                    .args(["bootout", "system/", PLIST_PATH])
                    .status();
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

    fn install(args: &[OsString]) -> Result<()> {
        require_root("install")?;
        let options = parse_options(args)?;
        let executable = current_executable()?;
        let target = Path::new(TARGET_BIN);
        if !same_file(&executable, target) {
            copy_binary(&executable, target)?;
        }
        fs::create_dir_all(&options.path).map_err(service_error)?;
        write_atomic(
            Path::new(PLIST_PATH),
            render_plist(&options).as_bytes(),
            0o700,
        )?;
        let _ = Command::new("launchctl")
            .args(["bootout", "system/", PLIST_PATH])
            .status();
        command_output("launchctl", &["bootstrap", "system", PLIST_PATH])?;
        command_output(
            "launchctl",
            &["kickstart", "-kp", &format!("system/{SERVICE}")],
        )
        .map(|_| ())
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
    }
}
