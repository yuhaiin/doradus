//! Happy Eyeballs version 2 for raw TCP connections.
//!
//! DNS policy lives above this module.  This layer only schedules the ordered
//! candidates it is given, so fixed endpoints and resolver-produced addresses
//! use exactly the same TCP race and socket binding behavior.

use std::collections::VecDeque;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::sync::{Semaphore, mpsc};

use crate::{Error, ErrorKind, Result};

use super::connect_tokio_tcp_with_interface;

const INITIAL_RTT: Duration = Duration::from_millis(300);
const MIN_DELAY: Duration = Duration::from_millis(100);
const MAX_DELAY: Duration = Duration::from_secs(2);
const RTT_SAMPLES: usize = 16;
const CACHE_CAPACITY: usize = 90;

/// One raw TCP candidate.  The interface belongs to the candidate because a
/// fixedv2 endpoint may select a different interface from its siblings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpDialCandidate {
    pub address: SocketAddr,
    pub bind_interface: Option<String>,
}

impl TcpDialCandidate {
    pub fn new(address: SocketAddr, bind_interface: Option<String>) -> Self {
        Self {
            address,
            bind_interface,
        }
    }
}

/// Optional observer used by the runtime metrics adapter.  Keeping this
/// callback in the core crate avoids making the socket implementation depend
/// on the application metrics crate.
pub trait HappyEyeballsObserver: Send + Sync {
    fn addresses_attempted(&self, count: usize);
    fn tcp_attempt_started(&self);
    fn tcp_attempt_failed(&self);
}

#[derive(Debug)]
struct DialState {
    rtt_samples: VecDeque<Duration>,
    cache: VecDeque<(String, Vec<SocketAddr>)>,
}

impl Default for DialState {
    fn default() -> Self {
        Self {
            rtt_samples: VecDeque::from([INITIAL_RTT]),
            cache: VecDeque::new(),
        }
    }
}

/// Shared Happy Eyeballs state for a runtime snapshot.
///
/// The dialer is intentionally cloneable: every proxy adapter created from a
/// snapshot shares the RTT estimate, successful-address cache and attempt
/// budget.  A new snapshot can own a new dialer while existing flows retain
/// the old one.
#[derive(Clone)]
pub struct HappyEyeballsV2Dialer {
    state: Arc<Mutex<DialState>>,
    semaphore: Option<Arc<Semaphore>>,
    observer: Option<Arc<dyn HappyEyeballsObserver>>,
}

impl fmt::Debug for HappyEyeballsV2Dialer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HappyEyeballsV2Dialer")
            .field("bounded", &self.semaphore.is_some())
            .finish_non_exhaustive()
    }
}

impl HappyEyeballsV2Dialer {
    /// Construct a dialer.  `None` and `Some(0)` both mean unlimited.
    pub fn new(max_concurrent_attempts: Option<usize>) -> Self {
        Self::with_semaphore(
            max_concurrent_attempts
                .and_then(|limit| (limit != 0).then(|| Arc::new(Semaphore::new(limit)))),
        )
    }

    pub fn with_semaphore(semaphore: Option<Arc<Semaphore>>) -> Self {
        Self {
            state: Arc::new(Mutex::new(DialState::default())),
            semaphore,
            observer: None,
        }
    }

    pub fn with_observer(mut self, observer: Arc<dyn HappyEyeballsObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Create a new configuration view while retaining the address cache and
    /// RTT samples.  Runtime reloads use this to change concurrency for new
    /// flows without throwing away learned network state.
    pub fn reconfigured(&self, max_concurrent_attempts: Option<usize>) -> Self {
        let semaphore = max_concurrent_attempts
            .and_then(|limit| (limit != 0).then(|| Arc::new(Semaphore::new(limit))));
        Self {
            state: Arc::clone(&self.state),
            semaphore,
            observer: self.observer.clone(),
        }
    }

    pub fn semaphore(&self) -> Option<Arc<Semaphore>> {
        self.semaphore.clone()
    }

    /// Race the supplied TCP candidates and return the first successful
    /// connection.  `timeout` is one deadline shared by all attempts.
    pub async fn dial_candidates(
        &self,
        candidates: Vec<TcpDialCandidate>,
        local_bind_addresses: &[IpAddr],
        timeout: Duration,
    ) -> Result<tokio::net::TcpStream> {
        self.dial_candidates_for_key(None, candidates, local_bind_addresses, timeout)
            .await
    }

    /// Same as [`Self::dial_candidates`], additionally using the successful
    /// address cache for a domain key.
    pub async fn dial_candidates_for_key(
        &self,
        key: Option<&str>,
        candidates: Vec<TcpDialCandidate>,
        local_bind_addresses: &[IpAddr],
        timeout: Duration,
    ) -> Result<tokio::net::TcpStream> {
        if candidates.is_empty() {
            return Err(Error::invalid("Happy Eyeballs has no TCP candidates"));
        }
        if timeout.is_zero() {
            return Err(Error::new(
                ErrorKind::Timeout,
                "Happy Eyeballs TCP deadline is zero",
            ));
        }

        let candidates = self.reorder_candidates(key, candidates);
        if let Some(observer) = &self.observer {
            observer.addresses_attempted(candidates.len());
        }

        let started = Instant::now();
        let deadline = started + timeout;
        let mut pending = VecDeque::from(candidates);
        let mut attempts = FuturesUnordered::new();
        let mut errors = Vec::new();
        let mut next_start = started;

        if let Some(candidate) = pending.pop_front() {
            attempts.push(self.attempt(candidate, local_bind_addresses, deadline));
            next_start = Instant::now() + self.delay();
        }

        loop {
            if attempts.is_empty() && pending.is_empty() {
                break;
            }

            if pending.is_empty() {
                if let Some(result) = attempts.next().await {
                    if let Some(stream) = self.process_attempt(result, &mut errors, key) {
                        return Ok(stream);
                    }
                }
                continue;
            }

            let now = Instant::now();
            if now >= deadline {
                errors.extend(pending.drain(..).map(|candidate| {
                    format!(
                        "{} ({}) stage=schedule: Happy Eyeballs deadline elapsed",
                        candidate.address,
                        address_family(candidate.address),
                    )
                }));
                continue;
            }

            if now >= next_start {
                let candidate = pending
                    .pop_front()
                    .expect("pending candidates checked above");
                attempts.push(self.attempt(candidate, local_bind_addresses, deadline));
                next_start = Instant::now() + self.delay();
                continue;
            }

            let sleep_for = next_start
                .saturating_duration_since(now)
                .min(deadline.saturating_duration_since(now));
            let sleep = tokio::time::sleep(sleep_for);
            tokio::pin!(sleep);
            tokio::select! {
                result = attempts.next(), if !attempts.is_empty() => {
                    if let Some(stream) = self.process_attempt(result.expect("attempt set is non-empty"), &mut errors, key) {
                        return Ok(stream);
                    }
                    // Go's failBoost advances the next candidate immediately
                    // after a failed connection.
                    next_start = Instant::now();
                }
                _ = &mut sleep => {}
            }
        }

        if errors.is_empty() {
            return Err(Error::new(
                ErrorKind::Io,
                "Happy Eyeballs failed without a connection attempt",
            ));
        }
        Err(Error::new(
            ErrorKind::Io,
            format!("Happy Eyeballs TCP attempts failed: {}", errors.join("; ")),
        ))
    }

    /// Race candidates that become available while DNS is still running.
    /// Each TCP attempt uses the same scheduler as [`Self::dial_candidates`].
    pub async fn dial_candidate_stream(
        &self,
        mut candidates: mpsc::Receiver<Result<TcpDialCandidate>>,
        local_bind_addresses: &[IpAddr],
        timeout: Duration,
        key: Option<String>,
    ) -> Result<tokio::net::TcpStream> {
        if timeout.is_zero() {
            return Err(Error::new(
                ErrorKind::Timeout,
                "Happy Eyeballs TCP deadline is zero",
            ));
        }

        let started = Instant::now();
        let deadline = started + timeout;
        let mut pending: VecDeque<TcpDialCandidate> = VecDeque::new();
        let mut attempts = FuturesUnordered::new();
        let mut errors = Vec::new();
        let mut next_start = None;
        let mut source_closed = false;

        loop {
            if source_closed && attempts.is_empty() && pending.is_empty() {
                break;
            }

            if Instant::now() >= deadline {
                errors.extend(pending.drain(..).map(|candidate| {
                    format!(
                        "{} ({}) stage=schedule: Happy Eyeballs deadline elapsed",
                        candidate.address,
                        address_family(candidate.address),
                    )
                }));
                source_closed = true;
                if attempts.is_empty() {
                    break;
                }
            }

            if next_start.is_some_and(|at| Instant::now() >= at) {
                if let Some(candidate) = pending.pop_front() {
                    attempts.push(self.attempt(candidate, local_bind_addresses, deadline));
                    next_start = Some(Instant::now() + self.delay());
                    continue;
                }
                next_start = None;
            }

            if pending.is_empty() && attempts.is_empty() && source_closed {
                break;
            }

            let sleep_for = next_start
                .map(|at| at.saturating_duration_since(Instant::now()))
                .unwrap_or(Duration::from_secs(3600));
            let sleep = tokio::time::sleep(sleep_for);
            tokio::pin!(sleep);
            tokio::select! {
                event = candidates.recv(), if !source_closed => {
                    match event {
                        Some(Ok(candidate)) => {
                            if let Some(observer) = &self.observer {
                                observer.addresses_attempted(1);
                            }
                            if attempts.is_empty() && pending.is_empty() {
                                attempts.push(self.attempt(candidate, local_bind_addresses, deadline));
                                next_start = Some(Instant::now() + self.delay());
                            } else {
                                pending.push_back(candidate);
                            }
                        }
                        Some(Err(error)) => errors.push(format!("stage=dns: {error}")),
                        None => source_closed = true,
                    }
                }
                result = attempts.next(), if !attempts.is_empty() => {
                    if let Some(stream) = self.process_attempt(result.expect("attempt set is non-empty"), &mut errors, key.as_deref()) {
                        return Ok(stream);
                    }
                    next_start = (!pending.is_empty()).then_some(Instant::now());
                }
                _ = &mut sleep, if next_start.is_some() && !pending.is_empty() => {
                    if let Some(candidate) = pending.pop_front() {
                        attempts.push(self.attempt(candidate, local_bind_addresses, deadline));
                        next_start = Some(Instant::now() + self.delay());
                    }
                }
            }
        }

        if errors.is_empty() {
            return Err(Error::invalid("Happy Eyeballs received no TCP candidates"));
        }
        Err(Error::new(
            ErrorKind::Io,
            format!("Happy Eyeballs TCP attempts failed: {}", errors.join("; ")),
        ))
    }

    fn attempt<'a>(
        &'a self,
        candidate: TcpDialCandidate,
        local_bind_addresses: &'a [IpAddr],
        deadline: Instant,
    ) -> impl std::future::Future<Output = AttemptResult> + Send + 'a {
        async move {
            let address = candidate.address;
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return AttemptResult::failure(
                    candidate,
                    Error::new(ErrorKind::Timeout, "Happy Eyeballs deadline elapsed"),
                    Duration::ZERO,
                );
            }

            let permit = if let Some(semaphore) = &self.semaphore {
                match tokio::time::timeout(remaining, Arc::clone(semaphore).acquire_owned()).await {
                    Ok(Ok(permit)) => Some(permit),
                    Ok(Err(_)) => {
                        return AttemptResult::failure(
                            candidate,
                            Error::new(ErrorKind::Closed, "Happy Eyeballs semaphore is closed"),
                            Duration::ZERO,
                        );
                    }
                    Err(_) => {
                        return AttemptResult::failure(
                            candidate,
                            Error::new(
                                ErrorKind::Timeout,
                                "waiting for Happy Eyeballs permit timed out",
                            ),
                            remaining,
                        );
                    }
                }
            } else {
                None
            };

            if let Some(observer) = &self.observer {
                observer.tcp_attempt_started();
            }
            let started = Instant::now();
            let local_bind = local_bind_addresses
                .iter()
                .copied()
                .find(|local| local.is_ipv4() == address.is_ipv4())
                .map(|local| SocketAddr::new(local, 0));
            let result = connect_tokio_tcp_with_interface(
                address,
                local_bind,
                candidate.bind_interface.as_deref(),
                deadline.saturating_duration_since(started),
            )
            .await;
            let elapsed = started.elapsed();
            drop(permit);
            if result.is_err() {
                if let Some(observer) = &self.observer {
                    observer.tcp_attempt_failed();
                }
            }
            AttemptResult {
                candidate,
                result,
                elapsed,
            }
        }
    }

    fn process_attempt(
        &self,
        result: AttemptResult,
        errors: &mut Vec<String>,
        key: Option<&str>,
    ) -> Option<tokio::net::TcpStream> {
        match result.result {
            Ok(stream) => {
                if let Some(key) = key {
                    self.remember_success(key, result.candidate.address);
                }
                self.record_success(result.candidate.address, result.elapsed);
                Some(stream)
            }
            Err(error) => {
                errors.push(format!(
                    "{} ({}) stage=tcp-connect: {}",
                    result.candidate.address,
                    address_family(result.candidate.address),
                    error,
                ));
                None
            }
        }
    }

    fn delay(&self) -> Duration {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let total: Duration = state.rtt_samples.iter().copied().sum();
        let average = total / state.rtt_samples.len() as u32;
        average.clamp(MIN_DELAY, MAX_DELAY)
    }

    fn record_success(&self, address: SocketAddr, elapsed: Duration) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.rtt_samples.push_back(elapsed);
        while state.rtt_samples.len() > RTT_SAMPLES {
            state.rtt_samples.pop_front();
        }
        // The cache key is applied by `reorder_candidates`; the address is
        // still useful to update the RTT estimate even for fixed endpoints.
        let _ = address;
    }

    fn reorder_candidates(
        &self,
        key: Option<&str>,
        candidates: Vec<TcpDialCandidate>,
    ) -> Vec<TcpDialCandidate> {
        let Some(key) = key else {
            return candidates;
        };
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((_, cached)) = state.cache.iter().find(|(cached_key, _)| cached_key == key) else {
            return candidates;
        };
        let mut reordered = Vec::with_capacity(candidates.len());
        let mut remaining = candidates;
        for address in cached {
            if let Some(index) = remaining
                .iter()
                .position(|candidate| candidate.address == *address)
            {
                reordered.push(remaining.remove(index));
            }
        }
        reordered.extend(remaining);
        reordered
    }

    /// Move the cached successful address to the front of a newly resolved
    /// list.  The resolver coordinator uses this before publishing candidates
    /// to [`Self::dial_candidate_stream`].
    pub fn prioritize_candidates(
        &self,
        key: Option<&str>,
        candidates: Vec<TcpDialCandidate>,
    ) -> Vec<TcpDialCandidate> {
        self.reorder_candidates(key, candidates)
    }

    /// Record a successful address for a domain.  The resolver coordinator
    /// calls this after it has supplied the domain key to the dialer.
    pub fn remember_success(&self, key: &str, address: SocketAddr) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(index) = state
            .cache
            .iter()
            .position(|(cached_key, _)| cached_key == key)
        {
            let (_, addresses) = state.cache.remove(index).expect("cache index exists");
            let mut addresses = addresses
                .into_iter()
                .filter(|cached| *cached != address)
                .collect::<Vec<_>>();
            addresses.insert(0, address);
            state.cache.push_front((key.to_owned(), addresses));
        } else {
            state.cache.push_front((key.to_owned(), vec![address]));
        }
        while state.cache.len() > CACHE_CAPACITY {
            state.cache.pop_back();
        }
    }
}

struct AttemptResult {
    candidate: TcpDialCandidate,
    result: Result<tokio::net::TcpStream>,
    elapsed: Duration,
}

impl AttemptResult {
    fn failure(candidate: TcpDialCandidate, error: Error, elapsed: Duration) -> Self {
        Self {
            candidate,
            result: Err(error),
            elapsed,
        }
    }
}

fn address_family(address: SocketAddr) -> &'static str {
    if address.is_ipv4() { "ipv4" } else { "ipv6" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_concurrency_is_unlimited() {
        let dialer = HappyEyeballsV2Dialer::new(Some(0));
        assert!(dialer.semaphore().is_none());
    }

    #[test]
    fn cache_moves_successful_address_to_the_front() {
        let dialer = HappyEyeballsV2Dialer::new(None);
        let first: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let second: SocketAddr = "192.0.2.2:443".parse().unwrap();
        dialer.remember_success("example.com", second);
        let reordered = dialer.reorder_candidates(
            Some("example.com"),
            vec![
                TcpDialCandidate::new(first, None),
                TcpDialCandidate::new(second, None),
            ],
        );
        assert_eq!(reordered[0].address, second);
    }

    #[test]
    fn reconfiguration_keeps_learned_address_cache() {
        let dialer = HappyEyeballsV2Dialer::new(None);
        let cached: SocketAddr = "192.0.2.8:443".parse().unwrap();
        dialer.remember_success("example.com", cached);

        let reconfigured = dialer.reconfigured(Some(10));
        let reordered = reconfigured.reorder_candidates(
            Some("example.com"),
            vec![
                TcpDialCandidate::new("192.0.2.9:443".parse().unwrap(), None),
                TcpDialCandidate::new(cached, None),
            ],
        );
        assert_eq!(reordered[0].address, cached);
        assert_eq!(reconfigured.semaphore().unwrap().available_permits(), 10);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_candidate_advances_to_the_next_tcp_candidate() {
        let stale_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stale = stale_listener.local_addr().unwrap();
        drop(stale_listener);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reachable = listener.local_addr().unwrap();

        let dialer = HappyEyeballsV2Dialer::new(None);
        let stream = dialer
            .dial_candidates(
                vec![
                    TcpDialCandidate::new(stale, None),
                    TcpDialCandidate::new(reachable, None),
                ],
                &[],
                Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), reachable);
        let _accepted = listener.accept().await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn aggregate_error_keeps_candidate_address_and_stage() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let error = HappyEyeballsV2Dialer::new(None)
            .dial_candidates(
                vec![TcpDialCandidate::new(address, None)],
                &[],
                Duration::from_millis(100),
            )
            .await
            .unwrap_err();
        assert!(error.message.contains(&address.to_string()));
        assert!(error.message.contains("stage=tcp-connect"));
    }
}
