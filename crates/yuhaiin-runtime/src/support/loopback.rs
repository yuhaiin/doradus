//! Route-level loopback protection.
//!
//! The Go runtime keeps two related safeguards in the route matcher: an
//! inbound endpoint must not route back to the same listener, and a process
//! which is already the proxy must not be routed through itself.  Keep this
//! state outside the trie so every inbound uses the same policy and so a
//! future socket adapter can register outbound local endpoints without
//! changing route rule compilation.

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use yuhaiin_core::FlowContext;

#[derive(Clone)]
pub(crate) struct LoopbackDetector {
    process_path: Option<PathBuf>,
    process_id: u32,
    connections: Arc<Mutex<HashMap<SocketAddr, usize>>>,
}

impl Default for LoopbackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopbackDetector {
    pub(crate) fn new() -> Self {
        Self {
            // Unit/in-process integration fixtures create both sides from
            // the same test executable. Treating that executable as the
            // managed proxy would reject every fixture flow; production
            // builds still use the real executable identity.
            process_path: if cfg!(test) {
                None
            } else {
                env::current_exe().ok()
            },
            process_id: std::process::id(),
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[cfg(test)]
    fn with_process(path: PathBuf, process_id: u32) -> Self {
        Self {
            process_path: Some(path),
            process_id,
            connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Return the Go-compatible reason for forcing a flow to `Block`.
    pub(crate) fn reason(&self, context: &FlowContext) -> Option<&'static str> {
        if self.cycle(context) {
            return Some("loopback cycle");
        }
        if self.process_loopback(context) {
            return Some("loopback process");
        }
        if self.connection_loopback(context) {
            return Some("loopback connection");
        }
        None
    }

    /// Prevent an inbound connection from being routed to its own listener.
    fn cycle(&self, context: &FlowContext) -> bool {
        let Some(local) = context
            .local_addr
            .as_ref()
            .and_then(|endpoint| endpoint.addr())
        else {
            return false;
        };
        let Some(destination) = context.destination.addr() else {
            return false;
        };
        context.local_addr.as_ref().is_some_and(|endpoint| {
            endpoint.network() == context.destination.network() && local == destination
        })
    }

    /// Match the process metadata attached by TUN/socket ownership lookup to
    /// this runtime's executable and PID. A missing PID is treated as a match
    /// when the path matches, which is the same conservative behavior as Go.
    fn process_loopback(&self, context: &FlowContext) -> bool {
        let Some(expected_path) = self.process_path.as_deref() else {
            return false;
        };
        let Some(process) = context.process.as_deref() else {
            return false;
        };
        let process = process.strip_suffix(" (deleted)").unwrap_or(process);
        if Path::new(process) != expected_path {
            return false;
        }
        if context
            .process_id
            .is_some_and(|pid| pid != 0 && pid != self.process_id)
        {
            return false;
        }

        // A normal domain flow has no stable local socket identity yet. Go
        // leaves it alone unless FakeIP/hosts metadata says that the domain
        // came from an already-resolved local route.
        if context.fake_ip.is_none()
            && context.hosts.is_none()
            && context.effective_destination().host().is_some()
        {
            return false;
        }
        true
    }

    /// Check a TUN source against local endpoints registered by an outbound
    /// socket adapter. The registration API is intentionally independent from
    /// Tokio so synchronous and platform-specific transports can share it.
    fn connection_loopback(&self, context: &FlowContext) -> bool {
        let Some(source) = context.source.as_ref().and_then(|endpoint| endpoint.addr()) else {
            return false;
        };
        self.connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&source)
    }

    /// Register an outbound local endpoint until the returned guard is
    /// dropped. Counts handle the rare case where the OS reuses an endpoint
    /// while two flow owners still hold it.
    #[allow(dead_code)] // wired by platform/transport adapters as local_addr becomes observable
    pub(crate) fn track_connection(&self, local: SocketAddr) -> TrackedConnection {
        let mut connections = self
            .connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *connections.entry(local).or_default() += 1;
        TrackedConnection {
            detector: self.clone(),
            local: Some(local),
        }
    }

    #[cfg(test)]
    fn tracked_count(&self, local: SocketAddr) -> usize {
        self.connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&local)
            .copied()
            .unwrap_or_default()
    }
}

#[allow(dead_code)] // see LoopbackDetector::track_connection
pub(crate) struct TrackedConnection {
    detector: LoopbackDetector,
    local: Option<SocketAddr>,
}

impl Drop for TrackedConnection {
    fn drop(&mut self) {
        let Some(local) = self.local.take() else {
            return;
        };
        let mut connections = self
            .detector
            .connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = connections.get_mut(&local) {
            *count -= 1;
            if *count == 0 {
                connections.remove(&local);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    use yuhaiin_core::{DomainName, Endpoint, Network};

    fn context(destination: &str) -> FlowContext {
        FlowContext::new(Endpoint::ip(
            Network::Tcp,
            destination.parse::<SocketAddr>().unwrap(),
        ))
    }

    #[test]
    fn same_inbound_listener_is_blocked() {
        let detector = LoopbackDetector::new();
        let mut context = context("127.0.0.1:18080");
        context.local_addr = Some(Endpoint::ip(
            Network::Tcp,
            "127.0.0.1:18080".parse().unwrap(),
        ));
        assert_eq!(detector.reason(&context), Some("loopback cycle"));

        context.destination = Endpoint::ip(Network::Tcp, "127.0.0.1:18081".parse().unwrap());
        assert_eq!(detector.reason(&context), None);
    }

    #[test]
    fn same_process_is_blocked_for_resolved_ip_but_not_plain_domain() {
        let path = PathBuf::from("/usr/bin/yuhaiin-rust");
        let detector = LoopbackDetector::with_process(path.clone(), 42);
        let mut resolved = context("192.0.2.1:443");
        resolved.process = Some(path.to_string_lossy().into_owned());
        resolved.process_id = Some(42);
        assert_eq!(detector.reason(&resolved), Some("loopback process"));

        resolved.process = Some(format!("{} (deleted)", path.display()));
        assert_eq!(detector.reason(&resolved), Some("loopback process"));

        let mut domain = FlowContext::new(Endpoint::domain(
            Network::Tcp,
            DomainName::new("example.com").unwrap(),
            443,
        ));
        domain.process = resolved.process;
        domain.process_id = Some(42);
        assert_eq!(detector.reason(&domain), None);
    }

    #[test]
    fn real_process_identity_blocks_a_real_local_endpoint() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let path = std::env::current_exe().unwrap();
        let process_id = std::process::id();
        let detector = LoopbackDetector::with_process(path.clone(), process_id);
        let mut context = context(&endpoint.to_string());
        context.process = Some(path.to_string_lossy().into_owned());
        context.process_id = Some(process_id);

        assert_eq!(detector.reason(&context), Some("loopback process"));
    }

    #[test]
    fn tracked_outbound_endpoint_is_reference_counted() {
        let detector = LoopbackDetector::new();
        let local = "127.0.0.1:24567".parse().unwrap();
        let mut context = context("198.51.100.1:443");
        context.source = Some(Endpoint::ip(Network::Tcp, local));
        let first = detector.track_connection(local);
        let second = detector.track_connection(local);
        assert_eq!(detector.tracked_count(local), 2);
        assert_eq!(detector.reason(&context), Some("loopback connection"));
        drop(first);
        assert_eq!(detector.tracked_count(local), 1);
        drop(second);
        assert_eq!(detector.tracked_count(local), 0);
        assert_eq!(detector.reason(&context), None);
    }
}
