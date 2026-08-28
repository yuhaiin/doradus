//! Runtime Happy Eyeballs coordination.
//!
//! The core dialer owns the raw TCP race.  This adapter owns resolver policy,
//! the IPv6-first default ordering and the short delay that lets the preferred
//! DNS family answer before the fallback family is released.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use doradus_core::dns_resolver::AsyncIpResolver;
use doradus_core::network::{HappyEyeballsObserver, HappyEyeballsV2Dialer, TcpDialCandidate};
use doradus_core::proxy::{AsyncDatagram, AsyncProxy, BoxAsyncStream};
use doradus_core::stream_metadata::with_stream_socket_addrs;
use doradus_core::{
    BoxFuture, DomainName, Endpoint, Error, ErrorKind, FlowContext, IpSet, ResolveStrategy, Result,
};
use doradus_metrics::RuntimeMetrics;
use doradus_protocol::proxy::{DirectAsyncProxy, FixedAsyncProxy};
use tokio::sync::mpsc;

const DNS_FAMILY_DELAY: Duration = Duration::from_millis(50);

/// Build the shared dialer for one immutable runtime snapshot.
pub(crate) fn new_dialer(
    semaphore_limit: usize,
    metrics: Arc<RuntimeMetrics>,
) -> Arc<HappyEyeballsV2Dialer> {
    // Go treats values 1..9 as the minimum useful connection budget and 0 as
    // unlimited.  Avoid constructing a zero-capacity Tokio semaphore.
    let limit = match semaphore_limit {
        0 => None,
        1..=9 => Some(10),
        value => Some(value),
    };
    Arc::new(HappyEyeballsV2Dialer::new(limit).with_observer(Arc::new(MetricsObserver { metrics })))
}

pub(crate) fn reconfigure_dialer(
    previous: &HappyEyeballsV2Dialer,
    semaphore_limit: usize,
    metrics: Arc<RuntimeMetrics>,
) -> Arc<HappyEyeballsV2Dialer> {
    let limit = match semaphore_limit {
        0 => None,
        1..=9 => Some(10),
        value => Some(value),
    };
    Arc::new(
        previous
            .reconfigured(limit)
            .with_observer(Arc::new(MetricsObserver { metrics })),
    )
}

struct MetricsObserver {
    metrics: Arc<RuntimeMetrics>,
}

impl HappyEyeballsObserver for MetricsObserver {
    fn addresses_attempted(&self, count: usize) {
        self.metrics
            .happy_eyeballs_addresses_attempted(count as u64);
    }

    fn tcp_attempt_started(&self) {
        self.metrics.happy_eyeballs_tcp_attempt();
    }

    fn tcp_attempt_failed(&self) {
        self.metrics.happy_eyeballs_tcp_failure();
    }
}

/// Direct TCP adapter that starts dialing as soon as the first DNS family is
/// available.  UDP and ICMP behavior remains delegated to the existing direct
/// implementation because Happy Eyeballs v2 is a TCP connection algorithm.
pub(crate) struct HappyEyeballsDirectProxy {
    inner: DirectAsyncProxy,
    direct_resolver: Arc<dyn AsyncIpResolver>,
    proxy_resolver: Arc<dyn AsyncIpResolver>,
    dialer: Arc<HappyEyeballsV2Dialer>,
}

/// Fixed endpoint adapter used by `fixed` and `fixedv2` configurations.  It
/// keeps each endpoint's interface attached to its own raw TCP candidate.
pub(crate) struct HappyEyeballsFixedProxy {
    endpoints: Arc<[TcpDialCandidate]>,
    dialer: Arc<HappyEyeballsV2Dialer>,
    timeout: Duration,
}

impl HappyEyeballsFixedProxy {
    pub(crate) fn new(
        endpoints: Vec<TcpDialCandidate>,
        dialer: Arc<HappyEyeballsV2Dialer>,
        timeout: Duration,
    ) -> Result<Self> {
        if endpoints.is_empty() {
            return Err(Error::invalid("fixed proxy has no endpoints"));
        }
        Ok(Self {
            endpoints: Arc::from(endpoints.into_boxed_slice()),
            dialer,
            timeout,
        })
    }
}

impl AsyncProxy for HappyEyeballsFixedProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        let candidates = self
            .endpoints
            .iter()
            .cloned()
            .map(|mut candidate| {
                if candidate.bind_interface.is_none() {
                    candidate.bind_interface = context.bind_interface.clone();
                }
                candidate
            })
            .collect();
        let dialer = Arc::clone(&self.dialer);
        let local_bind_addresses = context.local_bind_addresses.clone();
        let timeout = self.timeout;
        Box::pin(async move {
            let stream = dialer
                .dial_candidates(candidates, &local_bind_addresses, timeout)
                .await?;
            let local_addr = stream.local_addr().ok();
            let remote_addr = stream.peer_addr().ok();
            Ok(with_stream_socket_addrs(
                Box::new(stream) as BoxAsyncStream,
                local_addr,
                remote_addr,
            ))
        })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let endpoint = self.endpoints[0].clone();
        let proxy = FixedAsyncProxy {
            address: endpoint.address,
            timeout: self.timeout,
        };
        let mut context = context.clone();
        context.bind_interface = endpoint
            .bind_interface
            .or_else(|| context.bind_interface.clone());
        Box::pin(async move { proxy.open_datagram(&context).await })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        Box::pin(async move {
            let started = std::time::Instant::now();
            let mut stream = self.connect(context).await?;
            tokio::io::AsyncWriteExt::shutdown(&mut stream)
                .await
                .map_err(|error| {
                    Error::new(ErrorKind::Io, format!("close fixed stream: {error}"))
                })?;
            Ok(started.elapsed())
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl HappyEyeballsDirectProxy {
    pub(crate) fn new_with_route_resolvers(
        timeout: Duration,
        direct_resolver: Arc<dyn AsyncIpResolver>,
        proxy_resolver: Arc<dyn AsyncIpResolver>,
        dialer: Arc<HappyEyeballsV2Dialer>,
    ) -> Self {
        Self {
            inner: DirectAsyncProxy { timeout },
            direct_resolver,
            proxy_resolver,
            dialer,
        }
    }

    async fn connect_tcp(&self, context: &FlowContext) -> Result<BoxAsyncStream> {
        let destination = context.effective_destination();
        let port = destination
            .port()
            .ok_or_else(|| Error::invalid("direct destination has no port"))?;
        let key = destination.host().map(|host| host.as_str().to_owned());

        let stream = if let Some(addresses) = context.proxy_destinations() {
            let candidates = addresses
                .into_iter()
                .map(|address| TcpDialCandidate::new(address, context.bind_interface.clone()))
                .collect();
            self.dialer
                .dial_candidates_for_key(
                    key.as_deref(),
                    candidates,
                    &context.local_bind_addresses,
                    self.inner.timeout,
                )
                .await?
        } else {
            let Endpoint::Domain { host, .. } = destination else {
                return Err(Error::invalid("direct destination has no address"));
            };
            if context.skip_resolve {
                let candidates = tokio::net::lookup_host((host.as_str(), port))
                    .await
                    .map_err(|error| {
                        Error::new(
                            ErrorKind::Io,
                            format!("system resolution for {host}: {error}"),
                        )
                    })?
                    .map(|address| TcpDialCandidate::new(address, context.bind_interface.clone()))
                    .collect();
                self.dialer
                    .dial_candidates(
                        candidates,
                        &context.local_bind_addresses,
                        self.inner.timeout,
                    )
                    .await?
            } else {
                let resolver = if matches!(context.route_mode, doradus_core::RouteMode::Proxy) {
                    Arc::clone(&self.proxy_resolver)
                } else {
                    Arc::clone(&self.direct_resolver)
                };
                self.connect_resolved_domain(
                    resolver,
                    &host,
                    port,
                    context.resolver_policy.strategy,
                    &context.local_bind_addresses,
                    context.bind_interface.clone(),
                    self.inner.timeout,
                )
                .await?
            }
        };
        let local_addr = stream.local_addr().ok();
        let remote_addr = stream.peer_addr().ok();
        Ok(with_stream_socket_addrs(
            Box::new(stream) as BoxAsyncStream,
            local_addr,
            remote_addr,
        ))
    }

    async fn connect_resolved_domain(
        &self,
        resolver: Arc<dyn AsyncIpResolver>,
        host: &DomainName,
        port: u16,
        strategy: ResolveStrategy,
        local_bind_addresses: &[IpAddr],
        bind_interface: Option<String>,
        timeout: Duration,
    ) -> Result<tokio::net::TcpStream> {
        let (sender, receiver) = mpsc::channel(32);
        let dialer = Arc::clone(&self.dialer);
        let host_for_task = host.clone();
        let key = host.as_str().to_owned();
        let task = tokio::spawn(async move {
            coordinate_resolution(
                resolver,
                dialer,
                host_for_task,
                port,
                strategy,
                bind_interface,
                sender,
            )
            .await;
        });
        let result = self
            .dialer
            .dial_candidate_stream(receiver, local_bind_addresses, timeout, Some(key))
            .await;
        // DNS is only an input to this connection attempt.  Once the TCP
        // deadline is reached or a winner exists, do not retain its task.
        task.abort();
        result
    }
}

impl AsyncProxy for HappyEyeballsDirectProxy {
    fn connect<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<BoxAsyncStream>> {
        Box::pin(async move { self.connect_tcp(context).await })
    }

    fn open_datagram<'a>(
        &'a self,
        context: &'a FlowContext,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncDatagram>>> {
        let inner = self.inner;
        let direct_resolver = Arc::clone(&self.direct_resolver);
        let proxy_resolver = Arc::clone(&self.proxy_resolver);
        let mut context = context.clone();
        Box::pin(async move {
            if !context.skip_resolve && context.proxy_destinations().is_none() {
                let Endpoint::Domain { host, port, .. } = context.effective_destination() else {
                    return inner.open_datagram(&context).await;
                };
                let resolver = match context.route_mode {
                    doradus_core::RouteMode::Proxy => proxy_resolver,
                    doradus_core::RouteMode::Direct
                    | doradus_core::RouteMode::Bypass
                    | doradus_core::RouteMode::Block => direct_resolver,
                };
                let addresses = resolver
                    .resolve(&host, context.resolver_policy.strategy)
                    .await?;
                // Happy Eyeballs only applies to TCP.  Keep the historical
                // single-socket UDP choice for the default strategy, while
                // still using the configured resolver instead of libc lookup.
                let selection_strategy =
                    if matches!(context.resolver_policy.strategy, ResolveStrategy::Default) {
                        ResolveStrategy::PreferIpv4
                    } else {
                        context.resolver_policy.strategy
                    };
                let address =
                    super::proxy_adapters::select_resolved_address(&addresses, selection_strategy)
                        .ok_or_else(|| {
                            Error::new(
                                ErrorKind::InvalidInput,
                                format!("resolver returned no usable address for {host}"),
                            )
                        })?;
                context.resolved_destination = Some(vec![SocketAddr::new(address, port)]);
            }
            inner.open_datagram(&context).await
        })
    }

    fn ping<'a>(&'a self, context: &'a FlowContext) -> BoxFuture<'a, Result<Duration>> {
        self.inner.ping(context)
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

async fn coordinate_resolution(
    resolver: Arc<dyn AsyncIpResolver>,
    dialer: Arc<HappyEyeballsV2Dialer>,
    host: DomainName,
    port: u16,
    strategy: ResolveStrategy,
    bind_interface: Option<String>,
    sender: mpsc::Sender<Result<TcpDialCandidate>>,
) {
    match strategy {
        ResolveStrategy::OnlyIpv4 => {
            send_single_family(
                resolver,
                dialer,
                &host,
                port,
                ResolveStrategy::OnlyIpv4,
                bind_interface,
                sender,
            )
            .await;
        }
        ResolveStrategy::OnlyIpv6 => {
            send_single_family(
                resolver,
                dialer,
                &host,
                port,
                ResolveStrategy::OnlyIpv6,
                bind_interface,
                sender,
            )
            .await;
        }
        ResolveStrategy::PreferIpv4 | ResolveStrategy::PreferIpv6 => {
            let preferred = if matches!(strategy, ResolveStrategy::PreferIpv4) {
                ResolveStrategy::OnlyIpv4
            } else {
                ResolveStrategy::OnlyIpv6
            };
            let fallback = if matches!(strategy, ResolveStrategy::PreferIpv4) {
                ResolveStrategy::OnlyIpv6
            } else {
                ResolveStrategy::OnlyIpv4
            };
            match resolver.resolve(&host, preferred).await {
                Ok(addresses) if !addresses.is_empty() => {
                    send_addresses(
                        &dialer,
                        Some(host.as_str()),
                        &addresses,
                        preferred,
                        port,
                        bind_interface.clone(),
                        &sender,
                    )
                    .await;
                }
                Ok(_) | Err(_) => {
                    send_single_family(
                        resolver,
                        dialer,
                        &host,
                        port,
                        fallback,
                        bind_interface,
                        sender,
                    )
                    .await;
                }
            }
        }
        ResolveStrategy::Default => {
            coordinate_default_resolution(resolver, dialer, host, port, bind_interface, sender)
                .await;
        }
    }
}

async fn send_single_family(
    resolver: Arc<dyn AsyncIpResolver>,
    dialer: Arc<HappyEyeballsV2Dialer>,
    host: &DomainName,
    port: u16,
    strategy: ResolveStrategy,
    bind_interface: Option<String>,
    sender: mpsc::Sender<Result<TcpDialCandidate>>,
) {
    match resolver.resolve(host, strategy).await {
        Ok(addresses) => {
            send_addresses(
                &dialer,
                Some(host.as_str()),
                &addresses,
                strategy,
                port,
                bind_interface,
                &sender,
            )
            .await;
        }
        Err(error) => {
            let _ = sender.send(Err(error)).await;
        }
    }
}

async fn coordinate_default_resolution(
    resolver: Arc<dyn AsyncIpResolver>,
    dialer: Arc<HappyEyeballsV2Dialer>,
    host: DomainName,
    port: u16,
    bind_interface: Option<String>,
    sender: mpsc::Sender<Result<TcpDialCandidate>>,
) {
    let v6 = resolver.resolve(&host, ResolveStrategy::OnlyIpv6);
    let v4 = resolver.resolve(&host, ResolveStrategy::OnlyIpv4);
    tokio::pin!(v6);
    tokio::pin!(v4);

    let mut v6_result = None;
    let mut v4_result = None;
    let mut v6_candidates = Vec::new();
    let mut v4_candidates = Vec::new();
    let mut v6_started = false;
    let mut v6_released = false;
    let mut v4_released = false;
    let mut release_at: Option<std::time::Instant> = None;

    loop {
        if v6_result.is_some() && v4_result.is_some() && v6_released && v4_released {
            break;
        }
        let delay = tokio::time::sleep(
            release_at
                .map(|at| at.saturating_duration_since(std::time::Instant::now()))
                .unwrap_or(Duration::from_secs(3600)),
        );
        tokio::pin!(delay);
        tokio::select! {
            result = &mut v6, if v6_result.is_none() => {
                if let Ok(addresses) = &result {
                    v6_candidates = candidates_for_family(
                        &dialer,
                        Some(host.as_str()),
                        addresses,
                        ResolveStrategy::OnlyIpv6,
                        port,
                        bind_interface.clone(),
                    );
                }
                v6_result = Some(result);
                if v6_candidates.is_empty() {
                    v6_released = true;
                } else if !v6_started {
                    if !v4_candidates.is_empty() {
                        let candidates = interleave(v6_candidates.drain(..), v4_candidates.drain(..));
                        send_candidates(&sender, candidates).await;
                        v6_released = true;
                        v4_released = true;
                        release_at = None;
                    } else {
                        send_candidates(&sender, vec![v6_candidates.remove(0)]).await;
                        v6_started = true;
                        release_at = Some(std::time::Instant::now() + DNS_FAMILY_DELAY);
                    }
                }
                if v6_released && !v4_released && v4_result.is_some() {
                    send_candidates(&sender, v4_candidates.drain(..).collect()).await;
                    v4_released = true;
                    release_at = None;
                }
            }
            result = &mut v4, if v4_result.is_none() => {
                if let Ok(addresses) = &result {
                    v4_candidates = candidates_for_family(
                        &dialer,
                        Some(host.as_str()),
                        addresses,
                        ResolveStrategy::OnlyIpv4,
                        port,
                        bind_interface.clone(),
                    );
                }
                v4_result = Some(result);
                if v4_candidates.is_empty() {
                    v4_released = true;
                } else if !v6_candidates.is_empty() || v6_started {
                    let candidates = interleave(v6_candidates.drain(..), v4_candidates.drain(..));
                    send_candidates(&sender, candidates).await;
                    v6_released = true;
                    v4_released = true;
                    release_at = None;
                } else if v6_result.is_some() {
                    send_candidates(&sender, v4_candidates.drain(..).collect()).await;
                    v4_released = true;
                    release_at = None;
                } else {
                    release_at = Some(std::time::Instant::now() + DNS_FAMILY_DELAY);
                }
                if v4_released && !v6_released && v6_result.is_some() {
                    send_candidates(&sender, v6_candidates.drain(..).collect()).await;
                    v6_released = true;
                    release_at = None;
                }
            }
            _ = &mut delay, if release_at.is_some() => {
                release_at = None;
                if !v6_released && !v6_candidates.is_empty() {
                    send_candidates(&sender, v6_candidates.drain(..).collect()).await;
                    v6_released = true;
                }
                if !v4_released && !v4_candidates.is_empty() {
                    send_candidates(&sender, v4_candidates.drain(..).collect()).await;
                    v4_released = true;
                }
            }
        }
    }

    if !v6_released && !v4_released {
        if let Some(Err(error)) = v6_result {
            let _ = sender.send(Err(error)).await;
        }
        if let Some(Err(error)) = v4_result {
            let _ = sender.send(Err(error)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semaphore_configuration_matches_go_bounds() {
        let metrics = Arc::new(RuntimeMetrics::new());
        assert!(new_dialer(0, Arc::clone(&metrics)).semaphore().is_none());
        assert_eq!(
            new_dialer(1, Arc::clone(&metrics))
                .semaphore()
                .unwrap()
                .available_permits(),
            10
        );
        assert_eq!(
            new_dialer(9, Arc::clone(&metrics))
                .semaphore()
                .unwrap()
                .available_permits(),
            10
        );
        assert_eq!(
            new_dialer(11, metrics)
                .semaphore()
                .unwrap()
                .available_permits(),
            11
        );
    }

    #[test]
    fn default_resolution_interleaves_address_families() {
        let v6 = [
            TcpDialCandidate::new("[2001:db8::1]:443".parse().unwrap(), None),
            TcpDialCandidate::new("[2001:db8::2]:443".parse().unwrap(), None),
        ];
        let v4 = [
            TcpDialCandidate::new("192.0.2.1:443".parse().unwrap(), None),
            TcpDialCandidate::new("192.0.2.2:443".parse().unwrap(), None),
        ];
        let candidates = interleave(v6.into_iter(), v4.into_iter());
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.address)
                .collect::<Vec<_>>(),
            vec![
                "[2001:db8::1]:443".parse().unwrap(),
                "192.0.2.1:443".parse().unwrap(),
                "[2001:db8::2]:443".parse().unwrap(),
                "192.0.2.2:443".parse().unwrap(),
            ]
        );
    }
}

fn candidates_for_family(
    dialer: &HappyEyeballsV2Dialer,
    key: Option<&str>,
    addresses: &IpSet,
    family: ResolveStrategy,
    port: u16,
    bind_interface: Option<String>,
) -> Vec<TcpDialCandidate> {
    let candidates = addresses
        .iter()
        .filter(|address| match family {
            ResolveStrategy::OnlyIpv4 => address.is_ipv4(),
            ResolveStrategy::OnlyIpv6 => address.is_ipv6(),
            _ => true,
        })
        .map(|address| {
            TcpDialCandidate::new(SocketAddr::new(address, port), bind_interface.clone())
        })
        .collect();
    dialer.prioritize_candidates(key, candidates)
}

fn interleave(
    mut primary: impl Iterator<Item = TcpDialCandidate>,
    mut fallback: impl Iterator<Item = TcpDialCandidate>,
) -> Vec<TcpDialCandidate> {
    let mut result = Vec::new();
    loop {
        let mut added = false;
        if let Some(candidate) = primary.next() {
            result.push(candidate);
            added = true;
        }
        if let Some(candidate) = fallback.next() {
            result.push(candidate);
            added = true;
        }
        if !added {
            break;
        }
    }
    result
}

async fn send_candidates(
    sender: &mpsc::Sender<Result<TcpDialCandidate>>,
    candidates: Vec<TcpDialCandidate>,
) {
    for candidate in candidates {
        if sender.send(Ok(candidate)).await.is_err() {
            return;
        }
    }
}

async fn send_addresses(
    dialer: &HappyEyeballsV2Dialer,
    key: Option<&str>,
    addresses: &IpSet,
    family: ResolveStrategy,
    port: u16,
    bind_interface: Option<String>,
    sender: &mpsc::Sender<Result<TcpDialCandidate>>,
) {
    let candidates = candidates_for_family(dialer, key, addresses, family, port, bind_interface);
    send_candidates(sender, candidates).await;
}
