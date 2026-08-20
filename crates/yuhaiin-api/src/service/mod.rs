//! Reusable service lifecycle for native hosts.
//!
//! The command-line binary is only one host of the runtime. Android's
//! `VpnService` (and a future JNI/AAR boundary) needs the same API, DNS,
//! ordinary inbound and TUN ownership without starting a second process. The
//! service handle keeps that orchestration in one place; platform adapters
//! only provide paths, listeners and, when applicable, an already-created TUN
//! descriptor.

mod controller;
mod lifecycle;
mod runtime;
mod shutdown;
#[cfg(test)]
mod tests;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;
use yuhaiin_core::Result;
use yuhaiin_runtime::RuntimeController;
#[cfg(all(feature = "tun", unix))]
use yuhaiin_runtime::TunRuntimeConfig;

/// A TUN device supplied by a native host instead of opened by the desktop
/// device builder.
#[cfg(all(feature = "tun", unix))]
pub struct InjectedTun {
    pub fd: std::os::fd::OwnedFd,
    pub config: TunRuntimeConfig,
}

/// Inputs required to start the shared runtime service.
pub struct ServiceOptions {
    pub database: PathBuf,
    pub listen: SocketAddr,
    pub username: String,
    pub password: String,
    pub external_web: Option<PathBuf>,
    #[cfg(all(feature = "tun", unix))]
    pub injected_tun: Option<InjectedTun>,
}

impl ServiceOptions {
    pub fn new(database: PathBuf, listen: SocketAddr) -> Self {
        Self {
            database,
            listen,
            username: String::new(),
            password: String::new(),
            external_web: None,
            #[cfg(all(feature = "tun", unix))]
            injected_tun: None,
        }
    }
}

/// A running runtime host. Dropping the handle requests shutdown; callers
/// that need to observe persistence errors should call [`Self::wait`].
pub struct RuntimeService {
    pub(super) controller: RuntimeController,
    pub(super) address: SocketAddr,
    pub(super) shutdown: watch::Sender<bool>,
    pub(super) task: Option<tokio::task::JoinHandle<Result<()>>>,
    pub(super) child_aborts: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
}
