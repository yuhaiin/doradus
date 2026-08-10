//! Native service-manager integration for the runtime binary.
//!
//! The data plane remains in yuhaiin-runtime; this module only owns the
//! executable's install/start/stop lifecycle so replacing the Go binary does
//! not require a second wrapper command. Linux and macOS use their native
//! command-line managers and share the same option parser.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use yuhaiin_core::{Error, ErrorKind, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceOptions {
    host: String,
    path: PathBuf,
    nfs_mode: bool,
}

impl Default for ServiceOptions {
    fn default() -> Self {
        Self {
            host: "0.0.0.0:50051".to_owned(),
            path: default_service_path(),
            nfs_mode: false,
        }
    }
}

pub fn run(action: &str, args: &[OsString]) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        return linux::run(action, args);
    }
    #[cfg(target_os = "macos")]
    {
        return macos::run(action, args);
    }
    #[allow(unreachable_code)]
    Err(Error::new(
        ErrorKind::Unsupported,
        format!("service action {action:?} is not implemented on this platform"),
    ))
}

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

fn required_value(args: &[OsString], index: &mut usize, flag: &str) -> Result<String> {
    *index += 1;
    args.get(*index)
        .map(|value| value.to_string_lossy().into_owned())
        .ok_or_else(|| Error::invalid(format!("service option {flag} requires a value")))
}

fn default_service_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/yuhaiin")
    } else {
        PathBuf::from("/var/lib/yuhaiin")
    }
}

fn service_error(message: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, message.to_string())
}

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

fn current_executable() -> Result<PathBuf> {
    std::env::current_exe().map_err(service_error)
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn same_file(left: &Path, right: &Path) -> bool {
    let Some(left) = fs::canonicalize(left).ok() else {
        return false;
    };
    let Some(right) = fs::canonicalize(right).ok() else {
        return false;
    };
    left == right
}

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

#[cfg(test)]
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

    pub fn run(action: &str, args: &[OsString]) -> Result<()> {
        match action {
            "install" => install(args),
            "uninstall" => uninstall(args),
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
        if !same_file(&executable, target) {
            copy_binary(&executable, target)?;
        }
        fs::create_dir_all(&options.path).map_err(service_error)?;
        write_atomic(
            Path::new(SERVICE_PATH),
            render_unit(&options).as_bytes(),
            0o644,
        )?;
        command_output("systemctl", &["daemon-reload"])?;
        command_output("systemctl", &["enable", "yuhaiin.service"])?;
        if is_active() {
            command_output("systemctl", &["restart", "yuhaiin.service"])?;
        } else {
            command_output("systemctl", &["start", "yuhaiin.service"])?;
        }
        Ok(())
    }

    fn uninstall(args: &[OsString]) -> Result<()> {
        require_root("uninstall")?;
        if !args.is_empty() {
            return Err(Error::invalid("uninstall takes no arguments"));
        }
        let _ = Command::new("systemctl")
            .args(["stop", "yuhaiin.service"])
            .status();
        let _ = Command::new("systemctl")
            .args(["disable", "yuhaiin.service"])
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

    fn manage(action: &str) -> Result<()> {
        require_root(action)?;
        command_output("systemctl", &[action, "yuhaiin.service"])?;
        Ok(())
    }

    fn is_active() -> bool {
        Command::new("systemctl")
            .args(["is-active", "--quiet", "yuhaiin.service"])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    fn render_unit(options: &ServiceOptions) -> String {
        let nfs = if options.nfs_mode { " -nfs-mode" } else { "" };
        format!(
            "[Unit]\nDescription=yuhaiin transparent proxy\nAfter=network.target\n\n[Service]\nExecStart={} -host {} -path {}{}\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n",
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
