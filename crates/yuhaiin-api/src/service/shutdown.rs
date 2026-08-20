use yuhaiin_core::{Error, ErrorKind};
use yuhaiin_runtime::RuntimeLog;

pub(super) const SHUTDOWN_CHILD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
pub(super) const SHUTDOWN_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub(super) async fn wait_for_shutdown(mut receiver: tokio::sync::watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    while receiver.changed().await.is_ok() && !*receiver.borrow() {}
}

pub(super) fn io_error(error: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, error.to_string())
}

pub(super) fn join_error(error: tokio::task::JoinError) -> Error {
    io_error(error)
}

pub(super) async fn await_child<T>(
    mut task: tokio::task::JoinHandle<T>,
    name: &str,
    logs: &RuntimeLog,
) -> Option<T> {
    match tokio::time::timeout(SHUTDOWN_CHILD_TIMEOUT, &mut task).await {
        Ok(Ok(result)) => Some(result),
        Ok(Err(error)) => {
            logs.error(format!("{name} task join failed: {error}"));
            None
        }
        Err(_) => {
            task.abort();
            let _ = task.await;
            logs.warn(format!(
                "{name} shutdown exceeded {:?}; task aborted",
                SHUTDOWN_CHILD_TIMEOUT
            ));
            None
        }
    }
}
