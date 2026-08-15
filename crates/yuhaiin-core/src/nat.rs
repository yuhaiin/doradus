//! Minimal, runtime-independent NAT/connection tracking table.

use std::collections::{HashMap, HashSet};
use std::fmt::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::{Error, ErrorKind, Network, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NatKey {
    pub network: Network,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}
#[derive(Debug, Clone)]
pub struct NatEntry {
    pub translated: SocketAddr,
    pub created_at: Instant,
    pub last_seen: Instant,
    pub idle_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NatBindingKey {
    network: Network,
    source: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NatEndpointKey {
    network: Network,
    address: SocketAddr,
}

impl NatEndpointKey {
    fn new(network: Network, address: SocketAddr) -> Self {
        Self { network, address }
    }
}

impl From<&NatKey> for NatBindingKey {
    fn from(key: &NatKey) -> Self {
        Self {
            network: key.network,
            source: key.source,
        }
    }
}

struct NatBinding {
    entry: NatEntry,
    destinations: HashSet<SocketAddr>,
}

struct NatState {
    entries: HashMap<NatBindingKey, NatBinding>,
    translated: HashMap<NatEndpointKey, NatBindingKey>,
}

/// A point-in-time view of the endpoint-independent Full Cone NAT table.
///
/// The active values are gauges; the operation values are monotonic counters
/// shared by clones of the same [`NatTable`].  Keeping this as a plain value
/// makes it suitable for a caller-owned metrics exporter without exposing the
/// table lock or requiring a runtime-specific metrics crate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NatStats {
    pub active_bindings: usize,
    pub active_destinations: usize,
    pub reverse_mappings: usize,
    pub allocations: u64,
    pub reuses: u64,
    pub touch_hits: u64,
    pub touch_misses: u64,
    pub reverse_lookups: u64,
    pub reverse_hits: u64,
    pub translated_rebinds: u64,
    pub expired_bindings: u64,
    pub explicit_closes: u64,
}

fn append_metric<T: fmt::Display>(output: &mut String, name: &str, kind: &str, value: T) {
    let _ = writeln!(output, "# TYPE {name} {kind}");
    let _ = writeln!(output, "{name} {value}");
}

impl NatStats {
    /// Render a dependency-free Prometheus text snapshot for the NAT table.
    ///
    /// Applications can concatenate this output with other subsystem
    /// snapshots or expose it through their own authenticated endpoint.
    pub fn render_prometheus(&self) -> String {
        let mut output = String::new();
        let gauges = [
            (
                "yuhaiin_nat_active_bindings",
                "Current endpoint-independent Full Cone bindings.",
                self.active_bindings,
            ),
            (
                "yuhaiin_nat_active_destinations",
                "Current logical destinations attached to Full Cone bindings.",
                self.active_destinations,
            ),
            (
                "yuhaiin_nat_reverse_mappings",
                "Current translated-endpoint reverse mappings.",
                self.reverse_mappings,
            ),
        ];
        for (name, help, value) in gauges {
            let _ = writeln!(output, "# HELP {name} {help}");
            append_metric(&mut output, name, "gauge", value);
        }
        let counters = [
            (
                "yuhaiin_nat_allocations",
                "Total new Full Cone bindings.",
                self.allocations,
            ),
            (
                "yuhaiin_nat_reuses",
                "Total endpoint-independent mapping reuses.",
                self.reuses,
            ),
            (
                "yuhaiin_nat_touch_hits",
                "Total successful NAT touch operations.",
                self.touch_hits,
            ),
            (
                "yuhaiin_nat_touch_misses",
                "Total NAT touch misses or expired bindings.",
                self.touch_misses,
            ),
            (
                "yuhaiin_nat_reverse_lookups",
                "Total translated-endpoint reverse lookups.",
                self.reverse_lookups,
            ),
            (
                "yuhaiin_nat_reverse_hits",
                "Total successful translated-endpoint reverse lookups.",
                self.reverse_hits,
            ),
            (
                "yuhaiin_nat_translated_rebinds",
                "Total translated endpoint rebinds.",
                self.translated_rebinds,
            ),
            (
                "yuhaiin_nat_expired_bindings",
                "Total bindings removed by expiry.",
                self.expired_bindings,
            ),
            (
                "yuhaiin_nat_explicit_closes",
                "Total bindings removed by explicit close.",
                self.explicit_closes,
            ),
        ];
        for (name, help, value) in counters {
            let _ = writeln!(output, "# HELP {name} {help}");
            append_metric(&mut output, name, "counter", value);
        }
        output
    }
}

#[derive(Default)]
struct NatMetrics {
    allocations: AtomicU64,
    reuses: AtomicU64,
    touch_hits: AtomicU64,
    touch_misses: AtomicU64,
    reverse_lookups: AtomicU64,
    reverse_hits: AtomicU64,
    translated_rebinds: AtomicU64,
    expired_bindings: AtomicU64,
    explicit_closes: AtomicU64,
}

impl NatEntry {
    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_seen) >= self.idle_timeout
    }
}

#[derive(Clone)]
pub struct NatTable {
    // Full-cone NAT is endpoint independent: destination is deliberately not
    // part of this index.  It remains on NatKey so the TUN layer can identify
    // and release one logical flow without losing the shared mapping.
    // Both forward and reverse indexes live under one lock.  Keeping a single
    // lock makes every operation atomic and avoids an entries/reverse-index
    // lock-order inversion during expiry and reverse lookup.
    state: Arc<Mutex<NatState>>,
    metrics: Arc<NatMetrics>,
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new()
    }
}

impl NatTable {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(NatState {
                entries: HashMap::new(),
                translated: HashMap::new(),
            })),
            metrics: Arc::new(NatMetrics::default()),
        }
    }

    pub fn insert(
        &self,
        key: NatKey,
        translated: SocketAddr,
        idle_timeout: Duration,
    ) -> Result<()> {
        if idle_timeout.is_zero() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "NAT idle timeout must be greater than zero",
            ));
        }
        let now = Instant::now();
        let binding_key = NatBindingKey::from(&key);
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "NAT table lock poisoned"))?;
        if let Some(binding) = state.entries.get_mut(&binding_key) {
            if binding.entry.translated != translated {
                return Err(Error::invalid(
                    "full-cone NAT source already uses another translated endpoint",
                ));
            }
            binding.entry.last_seen = now;
            binding.destinations.insert(key.destination);
            self.metrics.reuses.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        if state
            .translated
            .get(&NatEndpointKey::new(key.network, translated))
            .is_some_and(|owner| owner != &binding_key)
        {
            return Err(Error::invalid(
                "translated NAT endpoint is already owned by another source",
            ));
        }
        state.entries.insert(
            binding_key,
            NatBinding {
                entry: NatEntry {
                    translated,
                    created_at: now,
                    last_seen: now,
                    idle_timeout,
                },
                destinations: HashSet::from([key.destination]),
            },
        );
        state
            .translated
            .insert(NatEndpointKey::new(key.network, translated), binding_key);
        self.metrics.allocations.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn touch(&self, key: &NatKey) -> Result<Option<NatEntry>> {
        let binding_key = NatBindingKey::from(key);
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "NAT table lock poisoned"))?;
        let expired = state
            .entries
            .get(&binding_key)
            .is_some_and(|binding| binding.entry.is_expired(Instant::now()));
        if expired {
            let removed = state.entries.remove(&binding_key);
            if let Some(binding) = removed {
                state.translated.remove(&NatEndpointKey::new(
                    binding_key.network,
                    binding.entry.translated,
                ));
                self.metrics
                    .expired_bindings
                    .fetch_add(1, Ordering::Relaxed);
            }
            self.metrics.touch_misses.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        let Some(binding) = state.entries.get_mut(&binding_key) else {
            self.metrics.touch_misses.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        };
        let now = Instant::now();
        binding.entry.last_seen = now;
        binding.destinations.insert(key.destination);
        self.metrics.touch_hits.fetch_add(1, Ordering::Relaxed);
        Ok(Some(binding.entry.clone()))
    }

    /// Bind the endpoint-independent source mapping to the endpoint that the
    /// actual UDP transport acquired after it was opened.  TUN flows are
    /// tracked before an async proxy datagram exists, so `insert` initially
    /// uses the virtual source as a placeholder; direct/native UDP transports
    /// replace it here with their real local socket endpoint.
    pub fn bind_translated(
        &self,
        network: Network,
        source: SocketAddr,
        translated: SocketAddr,
    ) -> Result<NatEntry> {
        let binding_key = NatBindingKey { network, source };
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "NAT table lock poisoned"))?;
        let expired = state
            .entries
            .get(&binding_key)
            .is_some_and(|binding| binding.entry.is_expired(now));
        if expired {
            let removed = state
                .entries
                .remove(&binding_key)
                .expect("binding was present");
            state
                .translated
                .remove(&NatEndpointKey::new(network, removed.entry.translated));
            self.metrics
                .expired_bindings
                .fetch_add(1, Ordering::Relaxed);
            return Err(Error::new(
                ErrorKind::Closed,
                "NAT source binding expired before translated endpoint was ready",
            ));
        }
        let Some(current) = state.entries.get(&binding_key) else {
            return Err(Error::new(
                ErrorKind::NotFound,
                "NAT source binding does not exist",
            ));
        };
        if current.entry.translated == translated {
            let binding = state.entries.get_mut(&binding_key).expect("binding exists");
            binding.entry.last_seen = now;
            return Ok(binding.entry.clone());
        }

        if state
            .translated
            .get(&NatEndpointKey::new(network, translated))
            .is_some_and(|owner| owner != &binding_key)
        {
            return Err(Error::invalid(
                "translated NAT endpoint is already owned by another source",
            ));
        }
        let previous_translated = current.entry.translated;
        state
            .translated
            .remove(&NatEndpointKey::new(network, previous_translated));
        state
            .translated
            .insert(NatEndpointKey::new(network, translated), binding_key);
        self.metrics
            .translated_rebinds
            .fetch_add(1, Ordering::Relaxed);
        let binding = state.entries.get_mut(&binding_key).expect("binding exists");
        binding.entry.translated = translated;
        binding.entry.last_seen = now;
        Ok(binding.entry.clone())
    }

    pub fn remove(&self, key: &NatKey) -> Result<Option<NatEntry>> {
        let binding_key = NatBindingKey::from(key);
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "NAT table lock poisoned"))?;
        let Some(binding) = state.entries.get_mut(&binding_key) else {
            return Ok(None);
        };
        binding.destinations.remove(&key.destination);
        if !binding.destinations.is_empty() {
            return Ok(Some(binding.entry.clone()));
        }
        let binding = state
            .entries
            .remove(&binding_key)
            .expect("binding was present");
        state.translated.remove(&NatEndpointKey::new(
            binding_key.network,
            binding.entry.translated,
        ));
        self.metrics.explicit_closes.fetch_add(1, Ordering::Relaxed);
        Ok(Some(binding.entry))
    }

    /// Remove the complete endpoint-independent binding for one source.  A
    /// full-cone relay can have several logical destinations sharing one
    /// translated endpoint, so closing the relay must not remove only the
    /// last destination reference.
    pub fn remove_source(&self, network: Network, source: SocketAddr) -> Result<usize> {
        let binding_key = NatBindingKey { network, source };
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "NAT table lock poisoned"))?;
        let binding = state.entries.remove(&binding_key);
        let Some(binding) = binding else {
            return Ok(0);
        };
        state
            .translated
            .remove(&NatEndpointKey::new(network, binding.entry.translated));
        self.metrics.explicit_closes.fetch_add(1, Ordering::Relaxed);
        Ok(binding.destinations.len())
    }

    pub fn sweep(&self) -> Result<usize> {
        Ok(self.sweep_keys()?.len())
    }

    pub fn sweep_keys(&self) -> Result<Vec<NatKey>> {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "NAT table lock poisoned"))?;
        let expired: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, binding)| binding.entry.is_expired(now))
            .map(|(binding_key, binding)| {
                let keys = binding
                    .destinations
                    .iter()
                    .map(|destination| NatKey {
                        network: binding_key.network,
                        source: binding_key.source,
                        destination: *destination,
                    })
                    .collect::<Vec<_>>();
                (*binding_key, binding.entry.translated, keys)
            })
            .collect();
        for (binding_key, translated, _) in &expired {
            state.entries.remove(binding_key);
            state
                .translated
                .remove(&NatEndpointKey::new(binding_key.network, *translated));
        }
        self.metrics
            .expired_bindings
            .fetch_add(expired.len() as u64, Ordering::Relaxed);
        Ok(expired.into_iter().flat_map(|(_, _, keys)| keys).collect())
    }

    /// Look up a translated endpoint without checking the external source.
    /// This is the defining inbound property of full-cone NAT: once the
    /// source mapping exists, packets from any remote address are accepted.
    pub fn lookup_translated(
        &self,
        network: Network,
        translated: SocketAddr,
        _external_source: SocketAddr,
    ) -> Result<Option<NatKey>> {
        self.metrics.reverse_lookups.fetch_add(1, Ordering::Relaxed);
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "NAT reverse index lock poisoned"))?;
        let binding_key = state
            .translated
            .get(&NatEndpointKey::new(network, translated))
            .copied();
        let Some(binding_key) = binding_key else {
            return Ok(None);
        };
        let Some(current) = state.entries.get(&binding_key) else {
            return Ok(None);
        };
        if current.entry.is_expired(Instant::now()) {
            let binding = state
                .entries
                .remove(&binding_key)
                .expect("binding was present");
            state
                .translated
                .remove(&NatEndpointKey::new(network, binding.entry.translated));
            self.metrics
                .expired_bindings
                .fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        let binding = state.entries.get_mut(&binding_key).expect("binding exists");
        binding.entry.last_seen = Instant::now();
        let result = binding
            .destinations
            .iter()
            .next()
            .map(|destination| NatKey {
                network: binding_key.network,
                source: binding_key.source,
                destination: *destination,
            });
        if result.is_some() {
            self.metrics.reverse_hits.fetch_add(1, Ordering::Relaxed);
        }
        Ok(result)
    }

    /// Read the current endpoint-independent mapping for one original source.
    /// This is intentionally destination-independent and does not update the
    /// last-seen timestamp; runtime code can use it for diagnostics or to
    /// hand the real translated endpoint to an integration boundary.
    pub fn lookup_source(&self, network: Network, source: SocketAddr) -> Result<Option<NatEntry>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "NAT source lookup lock poisoned"))?;
        let binding_key = NatBindingKey { network, source };
        let Some(current) = state.entries.get(&binding_key) else {
            return Ok(None);
        };
        if current.entry.is_expired(Instant::now()) {
            let binding = state
                .entries
                .remove(&binding_key)
                .expect("binding was present");
            state
                .translated
                .remove(&NatEndpointKey::new(network, binding.entry.translated));
            self.metrics
                .expired_bindings
                .fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        Ok(Some(current.entry.clone()))
    }

    pub fn len(&self) -> Result<usize> {
        self.state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "NAT table lock poisoned"))
            .map(|state| state.entries.len())
    }

    pub fn is_empty(&self) -> Result<bool> {
        self.state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "NAT table lock poisoned"))
            .map(|state| state.entries.is_empty())
    }

    /// Return a lock-bounded snapshot of active Full Cone mappings and the
    /// monotonic lifecycle counters accumulated by this table.
    pub fn stats(&self) -> Result<NatStats> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "NAT table lock poisoned"))?;
        Ok(NatStats {
            active_bindings: state.entries.len(),
            active_destinations: state
                .entries
                .values()
                .map(|binding| binding.destinations.len())
                .sum(),
            reverse_mappings: state.translated.len(),
            allocations: self.metrics.allocations.load(Ordering::Relaxed),
            reuses: self.metrics.reuses.load(Ordering::Relaxed),
            touch_hits: self.metrics.touch_hits.load(Ordering::Relaxed),
            touch_misses: self.metrics.touch_misses.load(Ordering::Relaxed),
            reverse_lookups: self.metrics.reverse_lookups.load(Ordering::Relaxed),
            reverse_hits: self.metrics.reverse_hits.load(Ordering::Relaxed),
            translated_rebinds: self.metrics.translated_rebinds.load(Ordering::Relaxed),
            expired_bindings: self.metrics.expired_bindings.load(Ordering::Relaxed),
            explicit_closes: self.metrics.explicit_closes.load(Ordering::Relaxed),
        })
    }
}

/// UDP relay using the same tuple table as TCP/UDP flow tracking.
pub struct UdpNatRelay {
    socket: UdpSocket,
    table: NatTable,
    mapping: Mutex<Option<NatKey>>,
    idle_timeout: Duration,
}

impl Drop for UdpNatRelay {
    fn drop(&mut self) {
        let mapping = match self.mapping.get_mut() {
            Ok(mapping) => mapping.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(key) = mapping {
            let _ = self.table.remove_source(key.network, key.source);
        }
    }
}

impl UdpNatRelay {
    pub fn bind(address: SocketAddr, table: NatTable, idle_timeout: Duration) -> Result<Self> {
        if idle_timeout.is_zero() {
            return Err(Error::invalid("UDP NAT idle timeout must be non-zero"));
        }
        let socket = UdpSocket::bind(address)
            .map_err(|error| Error::new(ErrorKind::Io, format!("bind UDP NAT socket: {error}")))?;
        socket
            .set_read_timeout(Some(idle_timeout))
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))?;
        Ok(Self {
            socket,
            table,
            mapping: Mutex::new(None),
            idle_timeout,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|error| Error::new(ErrorKind::Io, error.to_string()))
    }

    pub fn send_to(&self, key: NatKey, payload: &[u8]) -> Result<usize> {
        let destination = key.destination;
        let translated = self.local_addr()?;
        let mut mapping = self
            .mapping
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "UDP NAT mapping lock poisoned"))?;
        if let Some(current) = mapping.as_ref()
            && (current.network != key.network || current.source != key.source)
        {
            return Err(Error::invalid(
                "one UDP NAT relay cannot own multiple full-cone sources",
            ));
        }
        match self.table.touch(&key)? {
            Some(entry) if entry.translated != translated => {
                return Err(Error::new(
                    ErrorKind::Closed,
                    "UDP NAT source is already bound to another translated endpoint",
                ));
            }
            Some(_) => {}
            None => {
                self.table
                    .insert(key.clone(), translated, self.idle_timeout)?;
            }
        }
        if let Some(current) = mapping.as_mut() {
            current.destination = destination;
        } else {
            *mapping = Some(key.clone());
        }
        self.socket
            .send_to(payload, destination)
            .map_err(|error| Error::new(ErrorKind::Io, format!("send UDP NAT packet: {error}")))
    }

    pub fn recv_from(&self, buffer: &mut [u8]) -> Result<(NatKey, usize, SocketAddr)> {
        let (length, peer) = self.socket.recv_from(buffer).map_err(|error| {
            Error::new(
                ErrorKind::Timeout,
                format!("receive UDP NAT packet: {error}"),
            )
        })?;
        let key = self
            .mapping
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "UDP NAT mapping lock poisoned"))?
            .clone()
            .ok_or_else(|| Error::new(ErrorKind::NotFound, "UDP packet has no NAT mapping"))?;
        if self
            .table
            .lookup_translated(Network::Udp, self.local_addr()?, peer)?
            .is_none()
        {
            return Err(Error::new(
                ErrorKind::NotFound,
                "UDP packet has no active full-cone NAT mapping",
            ));
        }
        self.table.touch(&key)?;
        Ok((key, length, peer))
    }

    pub fn sweep(&self) -> Result<usize> {
        let mut mapping = self
            .mapping
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "UDP NAT mapping lock poisoned"))?;
        let removed = self.table.sweep()?;
        if removed != 0
            && let Some(key) = mapping.as_ref()
            && self
                .table
                .lookup_translated(Network::Udp, self.local_addr()?, key.source)?
                .is_none()
        {
            *mapping = None;
        }
        Ok(removed)
    }

    /// Explicitly release the relay's complete full-cone source binding.
    pub fn close(&self) -> Result<usize> {
        let mapping = self
            .mapping
            .lock()
            .map_err(|_| Error::new(ErrorKind::Closed, "UDP NAT mapping lock poisoned"))?
            .take();
        let Some(key) = mapping else {
            return Ok(0);
        };
        self.table.remove_source(key.network, key.source)
    }

    pub fn table(&self) -> &NatTable {
        &self.table
    }
}

#[cfg(test)]
#[path = "nat_tests.rs"]
mod tests;
