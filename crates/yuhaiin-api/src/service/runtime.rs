use std::sync::Arc;

use tokio::sync::{oneshot, watch};

use crate::api::ApiState;
use crate::api::{run_route_list_refresh_loop, serve_until};
use yuhaiin_core::{Error, ErrorKind, Result};
use yuhaiin_runtime::run_dns_supervisor;
use yuhaiin_store::{ConfigStore, restore_database};

use super::controller::build_controller;
use super::shutdown::{SHUTDOWN_CHILD_TIMEOUT, await_child, io_error, wait_for_shutdown};
use super::{RuntimeService, ServiceOptions};

impl RuntimeService {
    /// Start the API listener and all runtime supervisors on the current
    /// Tokio `LocalSet`.
    pub async fn start(options: ServiceOptions) -> Result<Self> {
        if let Some(parent) = options.database.parent() {
            std::fs::create_dir_all(parent).map_err(io_error)?;
        }
        let store = ConfigStore::open(&options.database).await?;
        let controller = build_controller(store.clone()).await?;
        let listener = tokio::net::TcpListener::bind(options.listen)
            .await
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind HTTP API: {error}")))?;
        let address = listener.local_addr().map_err(|error| {
            Error::new(ErrorKind::Io, format!("read HTTP API address: {error}"))
        })?;

        let (shutdown, shutdown_rx) = watch::channel(false);
        let mut state = ApiState::new(controller.clone())
            .with_shutdown(shutdown.clone())
            .with_optional_auth(&options.username, &options.password);
        if let Some(external_web) = options.external_web {
            state = state.with_external_web(external_web);
        }

        let database = options.database;
        #[cfg(all(feature = "tun", unix))]
        let injected_tun = options.injected_tun;
        let task_controller = controller.clone();
        let task_shutdown = shutdown.clone();
        let route_refresh_state = state.clone();
        let child_aborts = Arc::new(std::sync::Mutex::new(Vec::new()));
        let task_child_aborts = Arc::clone(&child_aborts);
        let task = tokio::task::spawn_local(async move {
            let logs = task_controller.monitor().logs();
            let dns_shutdown = shutdown_rx.clone();
            let inbound_shutdown = shutdown_rx.clone();
            let api_shutdown = shutdown_rx.clone();
            let route_refresh_shutdown = shutdown_rx.clone();
            let dns_logs = logs.clone();
            let dns_controller = task_controller.clone();
            let (selector_ready_tx, selector_ready_rx) = oneshot::channel();
            let route_refresh_task = tokio::task::spawn_local(run_route_list_refresh_loop(
                route_refresh_state,
                route_refresh_shutdown,
            ));
            let inbound_controller = task_controller.clone();
            let inbound_task = tokio::task::spawn_local(async move {
                #[cfg(all(feature = "tun", unix))]
                if let Some(injected_tun) = injected_tun {
                    return yuhaiin_runtime::inbound::run_until_with_tun_fd_selector_ready(
                        inbound_controller.clone(),
                        inbound_shutdown.clone(),
                        injected_tun.fd,
                        injected_tun.config,
                        selector_ready_tx,
                    )
                    .await;
                }
                yuhaiin_runtime::inbound::run_until_with_selector_ready(
                    inbound_controller,
                    inbound_shutdown,
                    selector_ready_tx,
                )
                .await
            });
            let dns_task = tokio::task::spawn_local(async move {
                if selector_ready_rx.await.is_err() {
                    return Err(Error::new(
                        ErrorKind::Closed,
                        "inbound supervisor stopped before selector was published",
                    ));
                }
                let result = run_dns_supervisor(dns_controller, dns_shutdown).await;
                if let Err(error) = &result {
                    // Report bind/configuration failures when they happen. The
                    // service intentionally keeps the API and other inbound
                    // tasks alive, so waiting until shutdown hides the real
                    // time and cause of this failure.
                    dns_logs.error(format!("DNS task stopped: {error}"));
                }
                result
            });
            let mut api_task = tokio::spawn(serve_until(
                listener,
                state,
                wait_for_shutdown(api_shutdown),
            ));

            if let Ok(mut aborts) = task_child_aborts.lock() {
                aborts.extend([
                    dns_task.abort_handle(),
                    route_refresh_task.abort_handle(),
                    inbound_task.abort_handle(),
                    api_task.abort_handle(),
                ]);
            }

            // Axum's graceful shutdown waits for every active HTTP
            // connection. A browser-held SSE stream, an unfinished pprof
            // request, or a half-open client can therefore keep the whole
            // process alive forever. Observe the service signal separately
            // and force-close the API task after a bounded grace period.
            let shutdown_signal = wait_for_shutdown(task_shutdown.subscribe());
            tokio::pin!(shutdown_signal);
            let api_result = tokio::select! {
                result = &mut api_task => {
                    let result = result
                        .map_err(|error| Error::new(ErrorKind::Io, format!("HTTP API task: {error}")))?;
                    if *task_shutdown.borrow() {
                        logs.warn(format!(
                            "HTTP API task exited during an already-requested shutdown (source=shutdown-request, result={:?})",
                            result.as_ref().err()
                        ));
                    } else {
                        logs.error(format!(
                            "HTTP API task exited before a shutdown request (source=http-api-task, result={:?})",
                            result.as_ref().err()
                        ));
                    }
                    result
                },
                _ = &mut shutdown_signal => {
                    logs.warn(
                        "runtime shutdown channel signaled (source=API request or runtime task)",
                    );
                    match tokio::time::timeout(SHUTDOWN_CHILD_TIMEOUT, &mut api_task).await {
                        Ok(result) => result
                            .map_err(|error| Error::new(ErrorKind::Io, format!("HTTP API task: {error}")))?,
                        Err(_) => {
                            api_task.abort();
                            let _ = api_task.await;
                            logs.warn(format!(
                                "HTTP API graceful shutdown exceeded {:?}; task aborted",
                                SHUTDOWN_CHILD_TIMEOUT
                            ));
                            Ok(())
                        }
                    }
                }
            };
            let _ = task_shutdown.send(true);
            if let Some(Err(error)) = await_child(dns_task, "DNS", &logs).await {
                logs.error(format!("inbound DNS task stopped: {error}"));
            }
            if let Some(Err(error)) = await_child(inbound_task, "inbound", &logs).await {
                logs.error(format!("inbound task stopped: {error}"));
            }
            let _ = await_child(route_refresh_task, "route refresh", &logs).await;
            task_controller.persist_monitor().await?;
            if let Some(source) = task_controller.take_restore_request() {
                restore_database(source, &database).await?;
            }
            api_result.map_err(io_error)
        });

        Ok(Self {
            controller,
            address,
            shutdown,
            task: Some(task),
            child_aborts,
        })
    }
}
