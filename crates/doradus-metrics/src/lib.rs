//! Process-lifetime metrics for the Doradus runtime.
//!
//! The collector owns the Prometheus registry, while callers only interact
//! with typed, bounded label values.  It has no Tokio or HTTP dependency, so
//! data-plane crates can share one [`RuntimeMetrics`] without coupling their
//! public APIs to a particular runtime or web framework.

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(unused)]

use std::fmt;

use prometheus_client::encoding::text::encode;
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::metrics::info::Info;
use prometheus_client::registry::Registry;

const DURATION_BUCKETS: [f64; 12] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

fn duration_histogram() -> Histogram {
    Histogram::new(DURATION_BUCKETS)
}

macro_rules! label_value {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        /// A bounded Prometheus label value.
        #[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
        pub enum $name {
            $(
                #[doc = $value]
                $variant,
            )+
        }

        impl $name {
            fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value,)+
                }
            }
        }

        impl EncodeLabelValue for $name {
            fn encode(&self, encoder: &mut LabelValueEncoder) -> Result<(), fmt::Error> {
                use std::fmt::Write as _;
                encoder.write_str(self.as_str())
            }
        }
    };
}

label_value!(Direction {
    Upload => "upload",
    Download => "download",
});

label_value!(MetricNetwork {
    Tcp => "tcp",
    Udp => "udp",
});

label_value!(InboundProtocol {
    Http => "http",
    Mixed => "mixed",
    Redir => "redir",
    ReverseHttp => "reverse_http",
    ReverseTcp => "reverse_tcp",
    Socks4a => "socks4a",
    Socks5 => "socks5",
    Tproxy => "tproxy",
    Trojan => "trojan",
    Tun => "tun",
    Vless => "vless",
    Yuubinsya => "yuubinsya",
    Other => "other",
});

impl InboundProtocol {
    /// Convert an inbound protocol name into the bounded metric label.
    pub fn from_name(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "http" => Self::Http,
            "mixed" | "mix" => Self::Mixed,
            "redir" | "redirect" => Self::Redir,
            "reverse_http" | "reverse-http" => Self::ReverseHttp,
            "reverse_tcp" | "reverse-tcp" => Self::ReverseTcp,
            "socks4a" | "socks4" => Self::Socks4a,
            "socks5" => Self::Socks5,
            "tproxy" => Self::Tproxy,
            "trojan" => Self::Trojan,
            "tun" => Self::Tun,
            "vless" => Self::Vless,
            "yuubinsya" => Self::Yuubinsya,
            _ => Self::Other,
        }
    }
}

label_value!(ResultKind {
    Success => "success",
    Failure => "failure",
    Dropped => "dropped",
    Hit => "hit",
    Miss => "miss",
    Allocated => "allocated",
    Reused => "reused",
    Expired => "expired",
    Other => "other",
});

label_value!(FailureStage {
    Listener => "listener",
    Dns => "dns",
    Route => "route",
    Dial => "dial",
    Handshake => "handshake",
    Stream => "stream",
    Other => "other",
});

label_value!(RouteAction {
    Direct => "direct",
    Proxy => "proxy",
    Block => "block",
    Reject => "reject",
    Unresolved => "unresolved",
    Other => "other",
});

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DirectionLabels {
    direction: Direction,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct PacketLabels {
    direction: Direction,
    network: MetricNetwork,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct InboundLabels {
    network: MetricNetwork,
    protocol: InboundProtocol,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ResultLabels {
    result: ResultKind,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct FailureLabels {
    stage: FailureStage,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ActionLabels {
    action: RouteAction,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BuildInfoLabels {
    version: &'static str,
    os: &'static str,
    arch: &'static str,
}

type CounterFamily<L> = Family<L, Counter>;

/// A shared process-lifetime metrics collector.
///
/// The value is intended to be wrapped in [`std::sync::Arc`] and cloned into
/// runtime owners.  The registry is created exactly once with the collector,
/// and metric registration never occurs during a scrape.
pub struct RuntimeMetrics {
    registry: Registry,
    traffic_bytes: CounterFamily<DirectionLabels>,
    packets: CounterFamily<PacketLabels>,
    connections_active: Gauge,
    connections: Counter,
    connection_failures: CounterFamily<FailureLabels>,
    inbound_requests: CounterFamily<InboundLabels>,
    inbound_request_outcomes: CounterFamily<ResultLabels>,
    dns_queries: CounterFamily<ResultLabels>,
    dns_query_duration: Histogram,
    fakeip_operations: CounterFamily<ResultLabels>,
    route_matches: CounterFamily<ActionLabels>,
    tun_packets: CounterFamily<DirectionLabels>,
    nat_active_bindings: Gauge,
    nat_active_destinations: Gauge,
    nat_reverse_mappings: Gauge,
    nat_allocations: Counter,
    nat_reuses: Counter,
    nat_touch_hits: Counter,
    nat_touch_misses: Counter,
    nat_reverse_lookups: Counter,
    nat_reverse_hits: Counter,
    nat_translated_rebinds: Counter,
    nat_expired_bindings: Counter,
    nat_explicit_closes: Counter,
    chain_h2_connections: Gauge,
    chain_h2_active_streams: Gauge,
    chain_h2_connection_attempts: Counter,
    chain_h2_connection_failures: Counter,
    chain_h2_stream_capacity_rejections: Counter,
    chain_h2_stream_open_failures: Counter,
    happy_eyeballs_addresses_attempted: Counter,
    happy_eyeballs_tcp_attempts: Counter,
    happy_eyeballs_tcp_failures: Counter,
    quic_datagrams_sent: Counter,
    quic_datagrams_received: Counter,
    quic_datagrams_dropped: Counter,
    quic_fragments_expired: Counter,
    quic_queued_bytes: Gauge,
}

impl fmt::Debug for RuntimeMetrics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeMetrics")
            .finish_non_exhaustive()
    }
}

impl Default for RuntimeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeMetrics {
    /// Create an isolated collector and register all Doradus metric families.
    pub fn new() -> Self {
        let traffic_bytes = CounterFamily::default();
        let packets = CounterFamily::default();
        let connections_active = Gauge::default();
        let connections = Counter::default();
        let connection_failures = CounterFamily::default();
        let inbound_requests = CounterFamily::default();
        let inbound_request_outcomes = CounterFamily::default();
        let dns_queries = CounterFamily::default();
        let dns_query_duration = duration_histogram();
        let fakeip_operations = CounterFamily::default();
        let route_matches = CounterFamily::default();
        let tun_packets = CounterFamily::default();
        let nat_active_bindings = Gauge::default();
        let nat_active_destinations = Gauge::default();
        let nat_reverse_mappings = Gauge::default();
        let nat_allocations = Counter::default();
        let nat_reuses = Counter::default();
        let nat_touch_hits = Counter::default();
        let nat_touch_misses = Counter::default();
        let nat_reverse_lookups = Counter::default();
        let nat_reverse_hits = Counter::default();
        let nat_translated_rebinds = Counter::default();
        let nat_expired_bindings = Counter::default();
        let nat_explicit_closes = Counter::default();
        let chain_h2_connections = Gauge::default();
        let chain_h2_active_streams = Gauge::default();
        let chain_h2_connection_attempts = Counter::default();
        let chain_h2_connection_failures = Counter::default();
        let chain_h2_stream_capacity_rejections = Counter::default();
        let chain_h2_stream_open_failures = Counter::default();
        let happy_eyeballs_addresses_attempted = Counter::default();
        let happy_eyeballs_tcp_attempts = Counter::default();
        let happy_eyeballs_tcp_failures = Counter::default();
        let quic_datagrams_sent = Counter::default();
        let quic_datagrams_received = Counter::default();
        let quic_datagrams_dropped = Counter::default();
        let quic_fragments_expired = Counter::default();
        let quic_queued_bytes = Gauge::default();

        let build_info = Info::new(BuildInfoLabels {
            version: env!("CARGO_PKG_VERSION"),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
        });

        let mut registry = Registry::default();
        registry.register("doradus_build", "Doradus build information", build_info);
        registry.register(
            "doradus_traffic_bytes",
            "Total logical payload bytes",
            traffic_bytes.clone(),
        );
        registry.register(
            "doradus_packets",
            "Total data-plane packets",
            packets.clone(),
        );
        registry.register(
            "doradus_connections_active",
            "Current active logical connections",
            connections_active.clone(),
        );
        registry.register(
            "doradus_connections",
            "Total logical connections",
            connections.clone(),
        );
        registry.register(
            "doradus_connection_failures",
            "Total connection failures",
            connection_failures.clone(),
        );
        registry.register(
            "doradus_inbound_requests",
            "Total accepted inbound logical flow requests",
            inbound_requests.clone(),
        );
        registry.register(
            "doradus_inbound_request_outcomes",
            "Total inbound request outcomes",
            inbound_request_outcomes.clone(),
        );
        registry.register(
            "doradus_dns_queries",
            "Total DNS queries",
            dns_queries.clone(),
        );
        registry.register(
            "doradus_dns_query_duration_seconds",
            "DNS query duration in seconds",
            dns_query_duration.clone(),
        );
        registry.register(
            "doradus_fakeip_cache_operations",
            "Total FakeIP cache operations",
            fakeip_operations.clone(),
        );
        registry.register(
            "doradus_route_matches",
            "Total final route decisions",
            route_matches.clone(),
        );
        registry.register(
            "doradus_tun_packets",
            "Total TUN packets",
            tun_packets.clone(),
        );
        registry.register(
            "doradus_nat_active_bindings",
            "Current active Full Cone NAT bindings",
            nat_active_bindings.clone(),
        );
        registry.register(
            "doradus_nat_active_destinations",
            "Current logical NAT destinations",
            nat_active_destinations.clone(),
        );
        registry.register(
            "doradus_nat_reverse_mappings",
            "Current NAT reverse mappings",
            nat_reverse_mappings.clone(),
        );
        registry.register(
            "doradus_nat_allocations",
            "Total new NAT bindings",
            nat_allocations.clone(),
        );
        registry.register(
            "doradus_nat_reuses",
            "Total reused NAT bindings",
            nat_reuses.clone(),
        );
        registry.register(
            "doradus_nat_touch_hits",
            "Total successful NAT touch operations",
            nat_touch_hits.clone(),
        );
        registry.register(
            "doradus_nat_touch_misses",
            "Total NAT touch misses",
            nat_touch_misses.clone(),
        );
        registry.register(
            "doradus_nat_reverse_lookups",
            "Total NAT reverse lookups",
            nat_reverse_lookups.clone(),
        );
        registry.register(
            "doradus_nat_reverse_hits",
            "Total successful NAT reverse lookups",
            nat_reverse_hits.clone(),
        );
        registry.register(
            "doradus_nat_translated_rebinds",
            "Total translated endpoint rebinds",
            nat_translated_rebinds.clone(),
        );
        registry.register(
            "doradus_nat_expired_bindings",
            "Total NAT bindings removed by expiry",
            nat_expired_bindings.clone(),
        );
        registry.register(
            "doradus_nat_explicit_closes",
            "Total NAT bindings removed explicitly",
            nat_explicit_closes.clone(),
        );
        registry.register(
            "doradus_chain_h2_connections",
            "Current HTTP/2 connections",
            chain_h2_connections.clone(),
        );
        registry.register(
            "doradus_chain_h2_active_streams",
            "Current active HTTP/2 streams",
            chain_h2_active_streams.clone(),
        );
        registry.register(
            "doradus_chain_h2_connection_attempts",
            "Total HTTP/2 connection attempts",
            chain_h2_connection_attempts.clone(),
        );
        registry.register(
            "doradus_chain_h2_connection_failures",
            "Total HTTP/2 connection failures",
            chain_h2_connection_failures.clone(),
        );
        registry.register(
            "doradus_chain_h2_stream_capacity_rejections",
            "Total HTTP/2 stream capacity rejections",
            chain_h2_stream_capacity_rejections.clone(),
        );
        registry.register(
            "doradus_chain_h2_stream_open_failures",
            "Total HTTP/2 stream open failures",
            chain_h2_stream_open_failures.clone(),
        );
        registry.register(
            "doradus_happy_eyeballs_addresses_attempted",
            "Total resolved addresses considered by Happy Eyeballs",
            happy_eyeballs_addresses_attempted.clone(),
        );
        registry.register(
            "doradus_happy_eyeballs_tcp_attempts",
            "Total raw TCP attempts made by Happy Eyeballs",
            happy_eyeballs_tcp_attempts.clone(),
        );
        registry.register(
            "doradus_happy_eyeballs_tcp_failures",
            "Total failed raw TCP attempts made by Happy Eyeballs",
            happy_eyeballs_tcp_failures.clone(),
        );
        registry.register(
            "doradus_quic_datagrams_sent",
            "Total QUIC datagrams sent",
            quic_datagrams_sent.clone(),
        );
        registry.register(
            "doradus_quic_datagrams_received",
            "Total QUIC datagrams received",
            quic_datagrams_received.clone(),
        );
        registry.register(
            "doradus_quic_datagrams_dropped",
            "Total QUIC datagrams dropped",
            quic_datagrams_dropped.clone(),
        );
        registry.register(
            "doradus_quic_fragments_expired",
            "Total expired QUIC fragments",
            quic_fragments_expired.clone(),
        );
        registry.register(
            "doradus_quic_queued_bytes",
            "Current queued QUIC bytes",
            quic_queued_bytes.clone(),
        );

        Self {
            registry,
            traffic_bytes,
            packets,
            connections_active,
            connections,
            connection_failures,
            inbound_requests,
            inbound_request_outcomes,
            dns_queries,
            dns_query_duration,
            fakeip_operations,
            route_matches,
            tun_packets,
            nat_active_bindings,
            nat_active_destinations,
            nat_reverse_mappings,
            nat_allocations,
            nat_reuses,
            nat_touch_hits,
            nat_touch_misses,
            nat_reverse_lookups,
            nat_reverse_hits,
            nat_translated_rebinds,
            nat_expired_bindings,
            nat_explicit_closes,
            chain_h2_connections,
            chain_h2_active_streams,
            chain_h2_connection_attempts,
            chain_h2_connection_failures,
            chain_h2_stream_capacity_rejections,
            chain_h2_stream_open_failures,
            happy_eyeballs_addresses_attempted,
            happy_eyeballs_tcp_attempts,
            happy_eyeballs_tcp_failures,
            quic_datagrams_sent,
            quic_datagrams_received,
            quic_datagrams_dropped,
            quic_fragments_expired,
            quic_queued_bytes,
        }
    }

    /// Encode all registered metrics in Prometheus text format.
    pub fn encode(&self, output: &mut String) -> Result<(), fmt::Error> {
        encode(output, &self.registry)
    }

    /// Record logical payload bytes.
    pub fn add_traffic(&self, direction: Direction, bytes: u64) {
        self.traffic_bytes
            .get_or_create(&DirectionLabels { direction })
            .inc_by(bytes);
    }

    /// Record a data-plane packet.
    pub fn add_packet(&self, direction: Direction, network: MetricNetwork) {
        self.packets
            .get_or_create(&PacketLabels { direction, network })
            .inc();
    }

    /// Record a newly opened logical connection.
    pub fn connection_opened(&self) {
        self.connections.inc();
        self.connections_active.inc();
    }

    /// Record a closed logical connection.
    pub fn connection_closed(&self) {
        self.connections_active.dec();
    }

    /// Record a connection failure at a bounded lifecycle stage.
    pub fn connection_failed(&self, stage: FailureStage) {
        self.connection_failures
            .get_or_create(&FailureLabels { stage })
            .inc();
    }

    /// Record an accepted inbound logical flow request.
    pub fn inbound_request(&self, network: MetricNetwork, protocol: InboundProtocol) {
        self.inbound_requests
            .get_or_create(&InboundLabels { network, protocol })
            .inc();
    }

    /// Record an inbound request outcome.
    pub fn inbound_outcome(&self, result: ResultKind) {
        self.inbound_request_outcomes
            .get_or_create(&ResultLabels { result })
            .inc();
    }

    /// Record a DNS query outcome.
    pub fn dns_query(&self, result: ResultKind) {
        self.dns_queries
            .get_or_create(&ResultLabels { result })
            .inc();
    }

    /// Record a DNS query duration in seconds.
    pub fn dns_query_duration(&self, seconds: f64) {
        self.dns_query_duration.observe(seconds.max(0.0));
    }

    /// Record a FakeIP cache operation.
    pub fn fakeip_operation(&self, result: ResultKind) {
        self.fakeip_operations
            .get_or_create(&ResultLabels { result })
            .inc();
    }

    /// Record a final route action.
    pub fn route_match(&self, action: RouteAction) {
        self.route_matches
            .get_or_create(&ActionLabels { action })
            .inc();
    }

    /// Record a TUN packet.
    pub fn tun_packet(&self, direction: Direction) {
        self.tun_packets
            .get_or_create(&DirectionLabels { direction })
            .inc();
    }

    /// Set current NAT table gauges.
    pub fn set_nat_state(&self, bindings: i64, destinations: i64, reverse_mappings: i64) {
        self.nat_active_bindings.set(bindings.max(0));
        self.nat_active_destinations.set(destinations.max(0));
        self.nat_reverse_mappings.set(reverse_mappings.max(0));
    }

    /// Synchronize NAT gauges and monotonic operation counters from a table
    /// snapshot. The table remains independent from this crate; callers only
    /// pass scalar values across the metrics boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn set_nat_counters(
        &self,
        bindings: i64,
        destinations: i64,
        reverse_mappings: i64,
        allocations: u64,
        reuses: u64,
        touch_hits: u64,
        touch_misses: u64,
        reverse_lookups: u64,
        reverse_hits: u64,
        translated_rebinds: u64,
        expired_bindings: u64,
        explicit_closes: u64,
    ) {
        self.set_nat_state(bindings, destinations, reverse_mappings);
        sync_counter(&self.nat_allocations, allocations);
        sync_counter(&self.nat_reuses, reuses);
        sync_counter(&self.nat_touch_hits, touch_hits);
        sync_counter(&self.nat_touch_misses, touch_misses);
        sync_counter(&self.nat_reverse_lookups, reverse_lookups);
        sync_counter(&self.nat_reverse_hits, reverse_hits);
        sync_counter(&self.nat_translated_rebinds, translated_rebinds);
        sync_counter(&self.nat_expired_bindings, expired_bindings);
        sync_counter(&self.nat_explicit_closes, explicit_closes);
    }

    /// Record a newly allocated NAT binding.
    pub fn nat_allocated(&self) {
        self.nat_allocations.inc();
    }

    /// Record a reused NAT binding.
    pub fn nat_reused(&self) {
        self.nat_reuses.inc();
    }

    /// Record a NAT touch result.
    pub fn nat_touched(&self, hit: bool) {
        if hit {
            self.nat_touch_hits.inc();
        } else {
            self.nat_touch_misses.inc();
        }
    }

    /// Record a NAT reverse lookup.
    pub fn nat_reverse_lookup(&self, hit: bool) {
        self.nat_reverse_lookups.inc();
        if hit {
            self.nat_reverse_hits.inc();
        }
    }

    /// Record a translated endpoint rebind.
    pub fn nat_translated_rebind(&self) {
        self.nat_translated_rebinds.inc();
    }

    /// Record a NAT binding removed by expiry.
    pub fn nat_expired(&self) {
        self.nat_expired_bindings.inc();
    }

    /// Record a NAT binding removed explicitly.
    pub fn nat_explicit_close(&self) {
        self.nat_explicit_closes.inc();
    }

    /// Record an HTTP/2 connection becoming live.
    pub fn chain_h2_connection_opened(&self) {
        self.chain_h2_connections.inc();
    }

    /// Record an HTTP/2 connection becoming unavailable.
    pub fn chain_h2_connection_closed(&self) {
        self.chain_h2_connections.dec();
    }

    /// Record an HTTP/2 stream becoming live.
    pub fn chain_h2_stream_opened(&self) {
        self.chain_h2_active_streams.inc();
    }

    /// Record an HTTP/2 stream becoming unavailable.
    pub fn chain_h2_stream_closed(&self) {
        self.chain_h2_active_streams.dec();
    }

    /// Record an HTTP/2 connection attempt.
    pub fn chain_h2_connection_attempt(&self) {
        self.chain_h2_connection_attempts.inc();
    }

    /// Record an HTTP/2 connection failure.
    pub fn chain_h2_connection_failure(&self) {
        self.chain_h2_connection_failures.inc();
    }

    /// Record an HTTP/2 stream capacity rejection.
    pub fn chain_h2_stream_capacity_rejection(&self) {
        self.chain_h2_stream_capacity_rejections.inc();
    }

    /// Record an HTTP/2 stream open failure.
    pub fn chain_h2_stream_open_failure(&self) {
        self.chain_h2_stream_open_failures.inc();
    }

    /// Record resolved addresses offered to Happy Eyeballs.
    pub fn happy_eyeballs_addresses_attempted(&self, count: u64) {
        self.happy_eyeballs_addresses_attempted.inc_by(count);
    }

    /// Record a raw TCP attempt started by Happy Eyeballs.
    pub fn happy_eyeballs_tcp_attempt(&self) {
        self.happy_eyeballs_tcp_attempts.inc();
    }

    /// Record a failed raw TCP attempt made by Happy Eyeballs.
    pub fn happy_eyeballs_tcp_failure(&self) {
        self.happy_eyeballs_tcp_failures.inc();
    }

    /// Record a QUIC datagram sent.
    pub fn quic_datagram_sent(&self) {
        self.quic_datagrams_sent.inc();
    }

    /// Record a QUIC datagram received.
    pub fn quic_datagram_received(&self) {
        self.quic_datagrams_received.inc();
    }

    /// Record a dropped QUIC datagram.
    pub fn quic_datagram_dropped(&self) {
        self.quic_datagrams_dropped.inc();
    }

    /// Record expired QUIC fragments.
    pub fn quic_fragments_expired(&self, count: u64) {
        self.quic_fragments_expired.inc_by(count);
    }

    /// Add or remove bytes from the aggregate QUIC receive queue gauge.
    pub fn change_quic_queued_bytes(&self, bytes: i64) {
        if bytes >= 0 {
            self.quic_queued_bytes.inc_by(bytes);
        } else {
            self.quic_queued_bytes.dec_by(bytes.saturating_neg());
        }
    }
}

fn sync_counter(counter: &Counter, value: u64) {
    let current = counter.get();
    if value > current {
        counter.inc_by(value - current);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_bounded_labels_and_build_info() {
        let metrics = RuntimeMetrics::new();
        metrics.add_traffic(Direction::Upload, 42);
        metrics.add_packet(Direction::Download, MetricNetwork::Udp);
        metrics.inbound_request(MetricNetwork::Tcp, InboundProtocol::Socks5);
        metrics.route_match(RouteAction::Proxy);

        let mut output = String::new();
        metrics.encode(&mut output).unwrap();

        assert!(output.contains("doradus_traffic_bytes_total{direction=\"upload\"} 42"));
        assert!(output.contains("doradus_packets_total{direction=\"download\",network=\"udp\"} 1"));
        assert!(
            output
                .contains("doradus_inbound_requests_total{network=\"tcp\",protocol=\"socks5\"} 1")
        );
        assert!(output.contains("doradus_build_info"));
        assert!(output.ends_with("# EOF\n"));
    }

    #[test]
    fn connection_gauge_follows_lifecycle() {
        let metrics = RuntimeMetrics::new();
        metrics.connection_opened();
        metrics.connection_opened();
        metrics.connection_closed();

        let mut output = String::new();
        metrics.encode(&mut output).unwrap();
        assert!(output.contains("doradus_connections_active 1"));
        assert!(output.contains("doradus_connections_total 2"));
    }

    #[test]
    fn registries_are_isolated_and_aggregate_transport_gauges() {
        let first = RuntimeMetrics::new();
        let second = RuntimeMetrics::new();
        first.add_traffic(Direction::Upload, 7);
        first.chain_h2_connection_opened();
        first.chain_h2_stream_opened();
        first.change_quic_queued_bytes(11);
        second.change_quic_queued_bytes(5);

        let mut first_output = String::new();
        first.encode(&mut first_output).unwrap();
        assert!(first_output.contains("doradus_traffic_bytes_total{direction=\"upload\"} 7"));
        assert!(first_output.contains("doradus_chain_h2_connections 1"));
        assert!(first_output.contains("doradus_chain_h2_active_streams 1"));
        assert!(first_output.contains("doradus_quic_queued_bytes 11"));

        let mut second_output = String::new();
        second.encode(&mut second_output).unwrap();
        assert!(!second_output.contains("doradus_traffic_bytes_total"));
        assert!(second_output.contains("doradus_quic_queued_bytes 5"));
    }
}
