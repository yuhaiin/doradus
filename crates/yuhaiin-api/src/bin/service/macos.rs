//! macOS launchd service integration.

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
        "stop" => {
            command_output("launchctl", &["kill", "TERM", &format!("system/{SERVICE}")]).map(|_| ())
        }
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
        let root = std::env::var_os("YUHAIIN_CACHE_DIR")
            .map(PathBuf::from)
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
