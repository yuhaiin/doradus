//! Windows service-control-manager integration.

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
    let manager = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
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
    let service = match manager.create_service(&service_info(&options, target), service_access()) {
        Ok(service) => service,
        Err(error) => {
            let error = service_error(error);
            if let Err(restore_error) = restore_binary_install(target, binary_backup.as_deref()) {
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
    let status_handle =
        service_control_handler::register(SERVICE_NAME, event_handler).map_err(service_error)?;
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
