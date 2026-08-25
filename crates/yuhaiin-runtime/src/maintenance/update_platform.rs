//! Platform-specific update hand-off and service restart helpers.

use super::*;

pub(super) fn spawn_update_helper(staged: PathBuf) -> Result<(), std::io::Error> {
    #[cfg(windows)]
    {
        let target = env::current_exe()?;
        // The service executable stays open for its whole lifetime on
        // Windows. Copying it first gives the helper an image that can
        // survive stopping the service and replacing the installed binary.
        let helper = target.with_extension("update-helper.exe");
        let _ = std::fs::remove_file(&helper);
        std::fs::copy(&target, &helper)?;
        let mut command = std::process::Command::new(&helper);
        command.arg("update-helper").arg(&target).arg(staged);
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        return command.spawn().map(|_| ());
    }

    #[cfg(not(windows))]
    {
        let target = env::current_exe()?;
        let mut command = std::process::Command::new(&target);
        command.arg("update-helper").arg(&target).arg(staged);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        command.spawn().map(|_| ())
    }
}

/// Replace an installed executable after the service has handed control to a
/// detached helper.  The old binary remains as a rollback file until the
/// service manager successfully restarts the service.
pub fn run_update_helper(target: &Path, staged: &Path) -> Result<(), String> {
    run_update_helper_with_hooks(
        target,
        staged,
        stop_platform_service,
        restart_platform_service,
    )
}

pub(super) fn run_update_helper_with_hooks<FStop, FRestart>(
    target: &Path,
    staged: &Path,
    stop_service: FStop,
    restart_service: FRestart,
) -> Result<(), String>
where
    FStop: Fn() -> Result<(), String>,
    FRestart: Fn() -> Result<(), String>,
{
    let target = target
        .canonicalize()
        .map_err(|error| format!("resolve update target: {error}"))?;
    let staged = staged
        .canonicalize()
        .map_err(|error| format!("resolve staged update: {error}"))?;
    let replacement = target.with_extension("update-stage");
    let _ = std::fs::remove_file(&replacement);
    std::fs::copy(&staged, &replacement)
        .map_err(|error| format!("copy staged update beside executable: {error}"))?;
    #[cfg(unix)]
    if let Err(error) = set_executable(&replacement) {
        let _ = std::fs::remove_file(&replacement);
        return Err(format!("set staged executable permissions: {error}"));
    }
    if let Err(error) = stop_service() {
        // The replacement is only a temporary copy until the service has
        // stopped. Do not leave it beside the executable when the service
        // manager rejects the stop request; a later retry should start from
        // the original target/staged pair.
        let _ = std::fs::remove_file(&replacement);
        return Err(format!("stop updated service: {error}"));
    }
    let backup = target.with_extension("update-backup");
    let _ = std::fs::remove_file(&backup);
    std::fs::rename(&target, &backup).map_err(|error| {
        let _ = std::fs::remove_file(&replacement);
        let _ = restart_service();
        format!("backup current executable: {error}")
    })?;
    if let Err(error) = std::fs::rename(&replacement, &target) {
        let _ = std::fs::remove_file(&replacement);
        let _ = std::fs::rename(&backup, &target);
        let _ = restart_service();
        return Err(format!("install updated executable: {error}"));
    }
    #[cfg(unix)]
    if let Err(error) = set_executable(&target) {
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::rename(&backup, &target);
        let _ = restart_service();
        return Err(format!("set executable permissions: {error}"));
    }
    if let Err(error) = restart_service() {
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::rename(&backup, &target);
        let recovery = restart_service();
        return Err(match recovery {
            Ok(()) => format!("restart updated service: {error}"),
            Err(recovery) => {
                format!("restart updated service: {error}; recovery restart failed: {recovery}")
            }
        });
    }
    let _ = std::fs::remove_file(staged);
    // Keep the previous image so the native service rollback action can
    // restore the last successfully installed release. The next update
    // replaces this single backup atomically.
    #[cfg(windows)]
    {
        let helper = target.with_extension("update-helper.exe");
        let _ = std::fs::remove_file(helper);
    }
    Ok(())
}

fn stop_platform_service() -> Result<(), String> {
    if let Ok(command) = env::var("YUHAIIN_UPDATE_STOP_COMMAND") {
        return run_shell_command(&command, "stop updated service");
    }
    #[cfg(target_os = "windows")]
    {
        return windows_service_stop();
    }
    #[cfg(target_os = "macos")]
    {
        // The helper is detached from the service process. A failed bootout
        // therefore means the old image may still be running; fail closed
        // instead of replacing the executable under an active launchd job.
        let pid = macos_launchd_pid()?;
        run_command(
            "launchctl",
            &[
                "bootout",
                "system",
                "/Library/LaunchDaemons/com.asutorufa.yuhaiin.plist",
            ],
            "stop updated launchd service",
        )?;
        if let Some(pid) = pid {
            wait_for_macos_process_exit(pid)?;
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        return Ok(());
    }
    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
pub(super) fn parse_macos_launchd_pid(data: &[u8]) -> Option<i32> {
    for field in String::from_utf8_lossy(data).split(';') {
        let Some((key, value)) = field.split_once('=') else {
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

#[cfg(target_os = "macos")]
fn macos_launchd_pid() -> Result<Option<i32>, String> {
    let output = std::process::Command::new("launchctl")
        .args(["list", "com.asutorufa.yuhaiin"])
        .output()
        .map_err(|error| format!("query updated launchd service: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "query updated launchd service exited with {}; {}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(parse_macos_launchd_pid(&output.stdout))
}

#[cfg(target_os = "macos")]
fn wait_for_macos_process_exit(pid: i32) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let probe = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map_err(|error| format!("check stopped launchd process {pid}: {error}"))?;
        if !probe.status.success() {
            let details = format!(
                "{}{}",
                String::from_utf8_lossy(&probe.stdout),
                String::from_utf8_lossy(&probe.stderr)
            );
            if details.to_ascii_lowercase().contains("no such process") {
                return Ok(());
            }
            return Err(format!(
                "check stopped launchd process {pid} exited with {}: {}",
                probe.status,
                details.trim()
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!("timeout waiting for launchd process {pid} to stop"));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn restart_platform_service() -> Result<(), String> {
    if let Ok(command) = env::var("YUHAIIN_UPDATE_RESTART_COMMAND") {
        return run_shell_command(&command, "restart updated service");
    }
    #[cfg(target_os = "windows")]
    {
        return windows_service_start();
    }
    #[cfg(target_os = "macos")]
    {
        run_command(
            "launchctl",
            &[
                "bootstrap",
                "system",
                "/Library/LaunchDaemons/com.asutorufa.yuhaiin.plist",
            ],
            "bootstrap updated launchd service",
        )?;
        return run_command(
            "launchctl",
            &["kickstart", "-kp", "system/com.asutorufa.yuhaiin"],
            "start updated launchd service",
        );
    }
    #[cfg(target_os = "linux")]
    {
        return run_command(
            "systemctl",
            &["restart", "yuhaiin.service"],
            "restart updated systemd service",
        );
    }
    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_command(program: &str, args: &[&str], action: &str) -> Result<(), String> {
    let status = std::process::Command::new(program)
        .args(args)
        .status()
        .map_err(|error| format!("{action}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{action} exited with {status}"))
    }
}

fn run_shell_command(command: &str, action: &str) -> Result<(), String> {
    #[cfg(windows)]
    let mut process = {
        let mut process = std::process::Command::new("cmd.exe");
        process.args(["/D", "/C", command]);
        process
    };
    #[cfg(not(windows))]
    let mut process = {
        let mut process = std::process::Command::new("sh");
        process.args(["-c", command]);
        process
    };
    let status = process
        .status()
        .map_err(|error| format!("{action}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{action} exited with {status}"))
    }
}

#[cfg(windows)]
fn windows_service() -> Result<windows_service::service::Service, String> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|error| format!("open Windows Service Control Manager: {error}"))?;
    manager
        .open_service(
            "yuhaiin",
            ServiceAccess::QUERY_STATUS | ServiceAccess::START | ServiceAccess::STOP,
        )
        .map_err(|error| format!("open Windows service yuhaiin: {error}"))
}

#[cfg(windows)]
fn windows_service_stop() -> Result<(), String> {
    use windows_service::service::ServiceState;
    let service = windows_service()?;
    let status = service
        .query_status()
        .map_err(|error| format!("query Windows service: {error}"))?;
    if status.current_state == ServiceState::Stopped {
        return Ok(());
    }
    if status.current_state != ServiceState::StopPending {
        service
            .stop()
            .map_err(|error| format!("stop Windows service: {error}"))?;
    }
    windows_wait_service_state(&service, ServiceState::Stopped)
}

#[cfg(windows)]
fn windows_service_start() -> Result<(), String> {
    use std::ffi::OsStr;
    use windows_service::service::ServiceState;
    let service = windows_service()?;
    let status = service
        .query_status()
        .map_err(|error| format!("query Windows service: {error}"))?;
    if status.current_state == ServiceState::Running {
        return Ok(());
    }
    if status.current_state != ServiceState::StartPending {
        service
            .start::<&OsStr>(&[])
            .map_err(|error| format!("start Windows service: {error}"))?;
    }
    windows_wait_service_state(&service, ServiceState::Running)
}

#[cfg(windows)]
fn windows_wait_service_state(
    service: &windows_service::service::Service,
    expected: windows_service::service::ServiceState,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let status = service
            .query_status()
            .map_err(|error| format!("query Windows service state: {error}"))?;
        if status.current_state == expected {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for Windows service state {expected:?}; current={:?}",
                status.current_state
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions)
}
