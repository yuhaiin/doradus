use tokio::sync::watch;
use yuhaiin_core::{Error, ErrorKind, Result};
use yuhaiin_runtime::{RuntimeController, RuntimeHandle, RuntimeLog};

use super::RuntimeService;
use super::shutdown::{SHUTDOWN_WAIT_TIMEOUT, join_error, wait_for_shutdown};

impl RuntimeService {
    pub fn controller(&self) -> &RuntimeController {
        &self.controller
    }

    pub fn handle(&self) -> RuntimeHandle {
        self.controller.handle().clone()
    }

    pub fn logs(&self) -> RuntimeLog {
        self.controller.monitor().logs()
    }

    pub fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    pub fn shutdown(&self) -> Result<()> {
        self.shutdown
            .send(true)
            .map_err(|_| Error::new(ErrorKind::Closed, "runtime service is already stopped"))
    }

    pub fn shutdown_handle(&self) -> watch::Sender<bool> {
        self.shutdown.clone()
    }

    pub async fn wait(mut self) -> Result<()> {
        let mut task = self
            .task
            .take()
            .ok_or_else(|| Error::new(ErrorKind::Closed, "runtime service task is missing"))?;

        // The service task is expected to live for the whole process lifetime.
        // The shutdown deadline applies only after the shutdown channel has
        // been signaled; applying it around the whole task would terminate a
        // healthy service after ten seconds without any external signal.
        let shutdown = self.shutdown.subscribe();
        if !*shutdown.borrow() {
            tokio::select! {
                result = &mut task => return result.map_err(join_error)?,
                _ = wait_for_shutdown(shutdown) => {}
            }
        }

        match tokio::time::timeout(SHUTDOWN_WAIT_TIMEOUT, &mut task).await {
            Ok(result) => result.map_err(join_error)?,
            Err(_) => {
                task.abort();
                let _ = task.await;
                self.abort_children();
                self.controller
                    .monitor()
                    .logs()
                    .error(format!(
                        "runtime service shutdown exceeded {SHUTDOWN_WAIT_TIMEOUT:?} (source=shutdown-task-timeout)"
                    ));
                Err(Error::new(
                    ErrorKind::Timeout,
                    format!("runtime service shutdown exceeded {SHUTDOWN_WAIT_TIMEOUT:?}"),
                ))
            }
        }
    }

    fn abort_children(&self) {
        if let Ok(aborts) = self.child_aborts.lock() {
            for abort in aborts.iter() {
                abort.abort();
            }
        }
    }
}

impl Drop for RuntimeService {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.abort_children();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
