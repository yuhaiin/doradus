use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

use super::*;
use yuhaiin_core::{Endpoint, Network};
use yuhaiin_store::ConfigStore;

fn flow() -> (TunFlow, FlowContext) {
    let key = TunFlowKey {
        network: Network::Tcp,
        source: "10.0.0.2:1234".parse().unwrap(),
        destination: "203.0.113.10:443".parse().unwrap(),
    };
    let flow = TunFlow { key };
    (
        flow,
        FlowContext::new(Endpoint::ip(key.network, key.destination)),
    )
}

fn monitor_test_database_path() -> PathBuf {
    let cache = std::env::var_os("YUHAIIN_CACHE_DIR")
        .map(PathBuf::from)
        .expect("a cache directory is required for the monitor test");
    let directory = cache.join("yuhaiin-rust-monitor-tests");
    fs::create_dir_all(&directory).unwrap();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    directory.join(format!("go-projection-{}-{nonce}.db", std::process::id()))
}

fn remove_monitor_test_database(path: &Path) {
    for suffix in ["", "-journal", "-wal", "-shm", "-yuhaiin-write-lock"] {
        let target = if suffix.is_empty() {
            path.to_path_buf()
        } else {
            PathBuf::from(format!("{}{}", path.display(), suffix))
        };
        let _ = fs::remove_file(target);
    }
}

#[test]
fn monitor_tracks_live_connections_and_precise_string_counters() {
    let monitor = ConnectionMonitor::new();
    let (flow, context) = flow();
    monitor.opened(flow, context);
    monitor.bytes(flow.key, TunFlowDirection::Upload, 7);
    monitor.bytes(flow.key, TunFlowDirection::Download, 11);
    assert_eq!(monitor.connections_value()["connections"][0]["id"], "1");
    assert_eq!(monitor.total_flow_value()["upload"], "7");
    assert_eq!(monitor.total_flow_value()["download"], "11");
    assert_eq!(monitor.total_flow_value()["counters"]["1"]["upload"], "7");
    monitor.closed(flow.key);
    assert_eq!(
        monitor.connections_value()["connections"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        monitor.total_flow_value()["counters"]
            .as_object()
            .unwrap()
            .get("1"),
        None
    );
    assert_eq!(
        monitor.telemetry_value()["groups"]
            .as_array()
            .unwrap()
            .len(),
        GO_TELEMETRY_DIMENSIONS.len()
    );
    assert_eq!(
        monitor.telemetry_value()["groups"]
            .as_array()
            .unwrap()
            .iter()
            .map(|group| group["dimension"].as_str().unwrap())
            .collect::<Vec<_>>(),
        GO_TELEMETRY_DIMENSIONS.to_vec()
    );
}

#[test]
fn history_times_are_serialized_in_utc() {
    assert_eq!(format_time(1_752_883_200), "2025-07-19T00:00:00Z");
}

#[test]
fn telemetry_dimensions_match_go_fakeip_and_route_projection() {
    let connection = json!({
        "network": {"connType": "tcp"},
        "inbound": "socks5",
        "inboundName": "Desktop SOCKS",
        "source": "[2001:db8::2]:1234",
        "addr": "198.18.0.1:443",
        "fakeIp": "198.18.0.1",
        "domain": "example.com",
        "hosts": "hosts.example",
        "destination": "203.0.113.10:443",
        "outbound": "proxy",
        "nodeId": "node-1",
        "nodeName": "Tokyo",
        "process": "/usr/bin/browser",
        "tag": "streaming",
        "matchHistory": [
            {"ruleName": "first-rule"},
            {"ruleName": "last-rule"}
        ]
    });

    assert_eq!(
        telemetry_dimensions(&connection),
        vec![
            ("addr".to_owned(), "example.com".to_owned()),
            ("inbound".to_owned(), "Desktop SOCKS".to_owned()),
            ("outbound".to_owned(), "Tokyo".to_owned()),
            ("process".to_owned(), "/usr/bin/browser".to_owned()),
            ("protocol".to_owned(), "tcp".to_owned()),
            ("rule".to_owned(), "last-rule".to_owned()),
            ("source".to_owned(), "2001:db8::2".to_owned()),
            ("tag".to_owned(), "streaming".to_owned()),
        ]
    );
    assert_eq!(telemetry_destination(&connection), "");
}

#[test]
fn telemetry_source_normalization_matches_go_http2_and_socket_forms() {
    assert_eq!(
        normalize_telemetry_source(" http2.h-ignored-2[2001:db8::4]:443 "),
        "2001:db8::4"
    );
    assert_eq!(normalize_telemetry_source("192.0.2.4:1234"), "192.0.2.4");
    assert_eq!(
        normalize_telemetry_source("[2001:db8::4]:1234"),
        "2001:db8::4"
    );
    assert_eq!(normalize_telemetry_source("unix-client"), "unix-client");
    assert_eq!(
        normalize_persisted_telemetry_value("source", "192.0.2.4:1234".to_owned()),
        "192.0.2.4"
    );
    assert_eq!(
        normalize_persisted_telemetry_value("addr", "example.com:443".to_owned()),
        "example.com:443"
    );
}

#[test]
fn monitor_preserves_inbound_and_process_metadata_in_connections() {
    let monitor = ConnectionMonitor::new();
    let (flow, mut context) = flow();
    context.inbound = Some("socks5".to_owned());
    context.inbound_name = Some("desktop-socks".to_owned());
    context.process = Some("/usr/bin/example-app".to_owned());
    context.process_id = Some(42);
    context.user_id = Some(1000);
    context.fake_ip = Some("198.18.0.1".to_owned());
    monitor.opened(flow, context);
    let connection = &monitor.connections_value()["connections"][0];
    assert_eq!(connection["inbound"], "socks5");
    assert_eq!(connection["inboundName"], "desktop-socks");
    assert_eq!(connection["process"], "/usr/bin/example-app");
    assert_eq!(connection["pid"], "42");
    assert_eq!(connection["uid"], "1000");
    assert_eq!(connection["fakeIp"], "198.18.0.1");
    assert_eq!(connection["component"], "");
}

#[test]
fn monitor_reports_resolved_ip_separately_from_fakeip() {
    let monitor = ConnectionMonitor::new();
    let (flow, mut context) = flow();
    let fake_ip = "fc00::1".parse().unwrap();
    let real_ip = "142.250.72.4".parse().unwrap();
    context.destination = Endpoint::ip(Network::Tcp, std::net::SocketAddr::new(fake_ip, 443));
    context.original_domain = Some(yuhaiin_core::DomainName::new("www.google.com").unwrap());
    context.fake_ip = Some(fake_ip.to_string());

    monitor.opened(flow, context.clone());
    let pending = &monitor.connections_value()["connections"][0];
    assert_eq!(pending["ip"], "");

    context.resolved_destination = Some(Endpoint::ip(
        Network::Tcp,
        std::net::SocketAddr::new(real_ip, 443),
    ));

    monitor.opened(flow, context);

    let connection = &monitor.connections_value()["connections"][0];
    assert_eq!(connection["domain"], "www.google.com");
    assert_eq!(connection["fakeIp"], "fc00::1");
    assert_eq!(connection["ip"], "142.250.72.4");
}

#[test]
fn monitor_preserves_route_explainability_metadata_in_connections() {
    let monitor = ConnectionMonitor::new();
    let (flow, mut context) = flow();
    context.tag = Some("streaming".to_owned());
    context.resolver = Some("secure-dns".to_owned());
    context.geo = Some("CN".to_owned());
    context.lists = vec!["media-hosts".to_owned()];
    context.match_history = vec![yuhaiin_core::MatchHistoryEntry {
        rule_name: "media-rule".to_owned(),
        history: vec![yuhaiin_core::MatchResult {
            list_name: "media-hosts".to_owned(),
            matched: true,
        }],
    }];
    monitor.opened(flow, context);

    let connection = &monitor.connections_value()["connections"][0];
    assert_eq!(connection["tag"], "streaming");
    assert_eq!(connection["resolver"], "secure-dns");
    assert_eq!(connection["geo"], "CN");
    assert_eq!(connection["lists"][0], "media-hosts");
    assert_eq!(connection["matchHistory"][0]["ruleName"], "media-rule");
    assert_eq!(
        connection["matchHistory"][0]["history"][0]["listName"],
        "media-hosts"
    );
    assert_eq!(connection["matchHistory"][0]["history"][0]["matched"], true);
}

#[test]
fn monitor_preserves_protocol_and_socket_metadata_in_connections() {
    let monitor = ConnectionMonitor::new();
    let (flow, mut context) = flow();
    context.local_addr = Some(Endpoint::ip(
        Network::Tcp,
        "127.0.0.1:1080".parse().unwrap(),
    ));
    context.outbound_local_addr = Some(Endpoint::ip(
        Network::Tcp,
        "192.0.2.20:52000".parse().unwrap(),
    ));
    context.outbound = Some("node-id".to_owned());
    context.outbound_addr = Some(Endpoint::ip(
        Network::Tcp,
        "192.0.2.10:8443".parse().unwrap(),
    ));
    context.hosts = Some("hosts".to_owned());
    context.protocol = Some("http".to_owned());
    context.tls_server_name = Some("example.com".to_owned());
    context.http_host = Some("example.com:443".to_owned());
    context.interface = Some("eth0".to_owned());
    context.outbound_geo = Some("US".to_owned());
    monitor.opened(flow, context);
    let connection = &monitor.connections_value()["connections"][0];
    assert_eq!(connection["hosts"], "hosts");
    assert_eq!(connection["tlsServerName"], "example.com");
    assert_eq!(connection["httpHost"], "example.com:443");
    assert_eq!(connection["interface"], "eth0");
    assert_eq!(connection["outboundGeo"], "US");
    assert_eq!(connection["localAddr"], "192.0.2.20:52000");
    assert_eq!(connection["network"]["underlyingType"], "tcp");
    assert_eq!(connection["protocol"], "http");
    assert_eq!(connection["outbound"], "192.0.2.10:8443");
    assert_eq!(connection["nodeId"], "node-id");
}

#[test]
fn monitor_keeps_socket_local_metadata_empty_without_outbound_socket() {
    let monitor = ConnectionMonitor::new();
    let (flow, mut context) = flow();
    context.local_addr = Some(Endpoint::ip(
        Network::Tcp,
        "127.0.0.1:1080".parse().unwrap(),
    ));
    context.udp_migrate_id = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    monitor.opened(flow, context);

    let connection = &monitor.connections_value()["connections"][0];
    assert_eq!(connection["localAddr"], "");
    assert_eq!(connection["network"]["underlyingType"], "");
    assert_eq!(connection["udpMigrateId"], "");
}

#[test]
fn monitor_merges_late_socket_metadata_without_allocating_a_new_connection() {
    let monitor = ConnectionMonitor::new();
    let (flow, mut initial) = flow();
    initial.inbound = Some("tun".to_owned());
    initial.inbound_name = Some("TUN".to_owned());
    initial.process = Some("/usr/bin/browser".to_owned());
    monitor.opened(flow, initial);
    let mut late = FlowContext::new(Endpoint::ip(flow.key.network, flow.key.destination));
    late.outbound_local_addr = Some(Endpoint::ip(
        Network::Tcp,
        "192.0.2.20:52000".parse().unwrap(),
    ));
    late.protocol = Some("tls".to_owned());
    monitor.opened(flow, late);

    let connections = monitor.connections_value()["connections"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0]["id"], "1");
    assert_eq!(connections[0]["inbound"], "tun");
    assert_eq!(connections[0]["process"], "/usr/bin/browser");
    assert_eq!(connections[0]["localAddr"], "192.0.2.20:52000");
    assert_eq!(connections[0]["network"]["underlyingType"], "tcp");
    assert_eq!(connections[0]["protocol"], "tls");
}

#[test]
fn monitor_preserves_tun_component_and_defaults() {
    let monitor = ConnectionMonitor::new();
    let (flow, mut context) = flow();
    context.component = Some("tun".to_owned());
    monitor.opened(flow, context);
    let connection = &monitor.connections_value()["connections"][0];
    assert_eq!(connection["component"], "tun");
    assert_eq!(connection["inbound"], "tun");
    assert_eq!(connection["inboundName"], "TUN");
}

#[test]
fn monitor_traffic_uses_utc_calendar_buckets_and_skips_empty_ranges() {
    let monitor = ConnectionMonitor::new();
    let january = OffsetDateTime::parse("2024-01-31T23:00:00Z", &Rfc3339)
        .unwrap()
        .unix_timestamp();
    let february = OffsetDateTime::parse("2024-02-01T01:00:00Z", &Rfc3339)
        .unwrap()
        .unix_timestamp();
    let march = OffsetDateTime::parse("2024-03-01T01:00:00Z", &Rfc3339)
        .unwrap()
        .unix_timestamp();
    {
        let mut state = monitor.lock();
        state.buckets.insert(january, (11, 7));
        state.buckets.insert(february, (13, 17));
        state.buckets.insert(march, (19, 23));
    }

    let value = monitor.traffic_value_range("month", january, march + 3_600);
    assert_eq!(value["interval"], "month");
    assert_eq!(value["items"].as_array().unwrap().len(), 3);
    assert_eq!(value["items"][0]["start"], "2024-01-01T00:00:00Z");
    assert_eq!(value["items"][0]["download"], "11");
    assert_eq!(value["items"][1]["start"], "2024-02-01T00:00:00Z");
    assert_eq!(value["items"][1]["upload"], "17");
    assert_eq!(value["items"][2]["start"], "2024-03-01T00:00:00Z");
}

#[test]
fn monitor_emits_snapshot_add_and_remove_events() {
    let monitor = ConnectionMonitor::new();
    let mut receiver = monitor.subscribe();
    let (flow, context) = flow();
    monitor.opened(flow, context);
    assert_eq!(receiver.try_recv().unwrap().kind, "connections_added");
    assert_eq!(monitor.initial_event().kind, "connections_added");
    monitor.closed(flow.key);
    let event = receiver.try_recv().unwrap();
    assert_eq!(event.kind, "connections_removed");
    assert_eq!(event.payload["ids"][0], "1");
}

#[test]
fn monitor_coalesces_connection_history_by_go_key() {
    let monitor = ConnectionMonitor::new();
    let (flow, context) = flow();
    monitor.opened(flow, context.clone());
    monitor.closed(flow.key);
    monitor.opened(flow, context);
    monitor.closed(flow.key);

    let history = monitor.all_history_value();
    assert_eq!(history["items"].as_array().unwrap().len(), 1);
    assert_eq!(history["items"][0]["count"], "2");
}

#[tokio::test]
async fn monitor_does_not_restore_live_counters_without_live_connections() {
    let store = ConfigStore::open_memory().await.unwrap();
    let monitor = ConnectionMonitor::load_with_store(store.clone())
        .await
        .unwrap();
    let (flow, context) = flow();
    monitor.opened(flow, context);
    monitor.bytes(flow.key, TunFlowDirection::Upload, 11);
    monitor.shutdown().await.unwrap();

    let reloaded = ConnectionMonitor::load_with_store(store).await.unwrap();
    assert!(
        reloaded.connections_value()["connections"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        reloaded.total_flow_value()["counters"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    assert_eq!(reloaded.total_flow_value()["upload"], "11");
    reloaded.shutdown().await.unwrap();
}

#[test]
fn monitor_preserves_close_requests_until_data_plane_consumes_them() {
    let monitor = ConnectionMonitor::new();
    let (flow, context) = flow();
    monitor.opened(flow, context);
    assert_eq!(monitor.request_close(&["1".to_owned()]), 1);
    assert_eq!(monitor.take_close_requests(), vec![flow.key]);
    assert!(monitor.take_close_requests().is_empty());
}

#[tokio::test]
async fn monitor_wakes_non_tun_relays_for_close_requests() {
    let monitor = ConnectionMonitor::new();
    let (flow, context) = flow();
    monitor.opened(flow, context);
    let waiter = {
        let monitor = monitor.clone();
        tokio::spawn(async move { monitor.wait_for_close(flow.key).await })
    };
    tokio::task::yield_now().await;
    assert_eq!(monitor.request_close(&["1".to_owned()]), 1);
    tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .expect("close waiter should wake")
        .expect("close waiter should not panic");
}

#[test]
fn monitor_records_coalesced_failed_history() {
    let monitor = ConnectionMonitor::new();
    monitor.record_failure("http", "example.com:443", "connection refused");
    monitor.record_failure("http", "example.com:443", "timeout");
    let history = monitor.failed_history_value();
    assert_eq!(history["items"][0]["failedCount"], "2");
    assert_eq!(history["items"][0]["error"], "timeout");
}

#[test]
fn monitor_surfaces_transport_failures_without_packet_logs() {
    let monitor = ConnectionMonitor::new();
    monitor.record_failure("http2", "proxy.example:443", "connection lost");
    let (flow, _) = flow();
    monitor.failed(flow.key, "tcp-connect", "timeout after 30s");

    let logs = monitor.logs().snapshot();
    assert!(
        logs.iter()
            .any(|line| line.contains("outbound connection failed")
                && line.contains("proxy.example:443"))
    );
    assert!(
        logs.iter()
            .any(|line| line.contains("TUN flow failed") && line.contains("tcp-connect"))
    );
    assert!(logs.iter().all(|line| !line.contains("packet")));
}

#[test]
fn monitor_telemetry_respects_time_range_limit_and_failures() {
    let monitor = ConnectionMonitor::new();
    let (flow, context) = flow();
    monitor.opened(flow, context);
    monitor.bytes(flow.key, TunFlowDirection::Upload, 7);
    monitor.bytes(flow.key, TunFlowDirection::Download, 11);
    monitor.record_failure("http", "example.com:443", "timeout");

    let now = unix_seconds();
    let value = monitor.telemetry_value_range(now - 3_600, now + 3_600, 1);
    let protocol = value["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["dimension"] == "protocol")
        .unwrap();
    assert_eq!(protocol["items"].as_array().unwrap().len(), 1);
    assert_eq!(protocol["items"][0]["value"], "tcp");
    assert_eq!(protocol["items"][0]["download"], "11");
    assert_eq!(protocol["items"][0]["upload"], "7");

    let failures = monitor.telemetry_value_range(now - 3_600, now + 3_600, 10);
    let failure_protocol = failures["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["dimension"] == "protocol")
        .unwrap();
    assert!(
        failure_protocol["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["value"] == "http" && item["failures"] == "1")
    );
    let failure_process = failures["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["dimension"] == "process")
        .unwrap();
    assert!(
        failure_process["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["failures"] == "0")
    );
    monitor.record_failure_with_process(
        "http",
        "example.com:443",
        "timeout",
        Some("/usr/bin/browser"),
    );
    let failures = monitor.telemetry_value_range(now - 3_600, now + 3_600, 10);
    let failure_process = failures["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["dimension"] == "process")
        .unwrap();
    assert!(
        failure_process["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| { item["value"] == "/usr/bin/browser" && item["failures"] == "1" })
    );
}

#[test]
fn monitor_telemetry_includes_daily_buckets_that_overlap_a_partial_day() {
    let monitor = ConnectionMonitor::new();
    let day = 1_704_067_200_i64; // 2024-01-01T00:00:00Z
    {
        let mut state = monitor.lock();
        state.telemetry_buckets.insert(
            (
                day,
                TELEMETRY_DAILY_BUCKET_SECONDS,
                "protocol".to_owned(),
                "tcp".to_owned(),
            ),
            (100, 50, 2),
        );
        state.telemetry_buckets.insert(
            (
                day + TELEMETRY_DAILY_BUCKET_SECONDS,
                TELEMETRY_HOURLY_BUCKET_SECONDS,
                "protocol".to_owned(),
                "tcp".to_owned(),
            ),
            (3, 4, 1),
        );
        state.telemetry_buckets.insert(
            (
                day + 11 * 3_600,
                TELEMETRY_HOURLY_BUCKET_SECONDS,
                "protocol".to_owned(),
                "tcp".to_owned(),
            ),
            (70, 80, 9),
        );
    }

    let value = monitor.telemetry_value_range(
        day + 12 * 3_600,
        day + TELEMETRY_DAILY_BUCKET_SECONDS + 12 * 3_600,
        8,
    );
    let protocol = value["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["dimension"] == "protocol")
        .unwrap();
    assert_eq!(protocol["items"][0]["value"], "tcp");
    assert_eq!(protocol["items"][0]["download"], "103");
    assert_eq!(protocol["items"][0]["upload"], "54");
    assert_eq!(protocol["items"][0]["failures"], "3");

    let after_daily = monitor.telemetry_value_range(
        day + TELEMETRY_DAILY_BUCKET_SECONDS + 12 * 3_600,
        day + 2 * TELEMETRY_DAILY_BUCKET_SECONDS,
        8,
    );
    let protocol = after_daily["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["dimension"] == "protocol")
        .unwrap();
    assert!(protocol["items"].as_array().unwrap().is_empty());
}

#[test]
fn monitor_exposes_block_history_in_the_route_contract_shape() {
    let monitor = ConnectionMonitor::new();
    let (flow, mut context) = flow();
    context.route_mode = RouteMode::Block;
    context.original_domain = Some(yuhaiin_core::DomainName::new("blocked.example").unwrap());
    context.process = Some("/usr/bin/browser".to_owned());
    monitor.opened(flow, context);
    monitor.closed(flow.key);

    let mut second = FlowContext::new(Endpoint::ip(flow.key.network, flow.key.destination));
    second.route_mode = RouteMode::Block;
    second.original_domain = Some(yuhaiin_core::DomainName::new("blocked.example").unwrap());
    second.process = Some("/usr/bin/browser".to_owned());
    monitor.opened(flow, second);
    monitor.closed(flow.key);

    let value = monitor.block_history_value();
    // History uses the same application-protocol field as connections;
    // an un-sniffed blocked flow must not fall back to its TCP transport.
    assert_eq!(value["items"][0]["protocol"], "");
    assert_eq!(value["items"][0]["host"], "blocked.example");
    assert_eq!(value["items"][0]["blockCount"], "2");
    assert_eq!(value["dumpProcessEnabled"], true);
}

#[test]
fn monitor_keeps_failed_history_processes_separate_and_exposes_the_flag() {
    let monitor = ConnectionMonitor::new();
    monitor.record_failure_with_process(
        "http",
        "example.com:443",
        "timeout",
        Some("/usr/bin/browser"),
    );
    monitor.record_failure("http", "example.com:443", "connection refused");

    let value = monitor.failed_history_value();
    assert_eq!(value["items"].as_array().unwrap().len(), 2);
    assert_eq!(value["dumpProcessEnabled"], true);
    assert!(
        value["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| { item["process"] == "/usr/bin/browser" && item["failedCount"] == "1" })
    );
}

#[test]
fn monitor_bounds_block_history_to_the_go_public_window() {
    let monitor = ConnectionMonitor::new();
    for index in 0..=GO_HISTORY_SIZE {
        let (flow, mut context) = flow();
        context.route_mode = RouteMode::Block;
        context.original_domain =
            Some(yuhaiin_core::DomainName::new(&format!("blocked-{index}.example")).unwrap());
        context.process = Some(format!("process-{index}"));
        monitor.opened(flow, context);
        monitor.closed(flow.key);
    }
    assert_eq!(
        monitor.block_history_value()["items"]
            .as_array()
            .unwrap()
            .len(),
        GO_HISTORY_SIZE
    );
}

#[test]
fn monitor_connection_uses_http_authority_for_placeholder_socket_tuple() {
    let monitor = ConnectionMonitor::new();
    let key = TunFlowKey {
        network: Network::Tcp,
        source: "127.0.0.1:40000".parse().unwrap(),
        destination: "0.0.0.0:0".parse().unwrap(),
    };
    let flow = TunFlow { key };
    let mut context =
        FlowContext::new(Endpoint::ip(Network::Tcp, "127.0.0.1:443".parse().unwrap()));
    context.original_domain = Some(yuhaiin_core::DomainName::new("example.test").unwrap());
    monitor.opened(flow, context);

    let connection = &monitor.connections_value()["connections"][0];
    assert_eq!(connection["addr"], "example.test:443");
    assert_eq!(connection["destination"], "example.test:443");
}

#[test]
fn monitor_connection_uses_socket_authority_for_resolved_udp_tuple() {
    let monitor = ConnectionMonitor::new();
    let key = TunFlowKey {
        network: Network::Udp,
        source: "127.0.0.1:40000".parse().unwrap(),
        destination: "127.0.0.1:443".parse().unwrap(),
    };
    let flow = TunFlow { key };
    let mut context = FlowContext::new(Endpoint::domain(
        Network::Udp,
        yuhaiin_core::DomainName::new("example.test").unwrap(),
        443,
    ));
    context.inbound = Some("127.0.0.1:1080".to_owned());
    context.original_domain = Some(yuhaiin_core::DomainName::new("example.test").unwrap());
    monitor.opened(flow, context);

    let connection = &monitor.connections_value()["connections"][0];
    assert_eq!(connection["destination"], "example.test:443");
    assert_eq!(connection["addr"], "example.test:443");
}

#[test]
fn monitor_persists_totals_and_history_through_the_config_store() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let store = ConfigStore::open_memory().await.unwrap();
        let monitor = ConnectionMonitor::load_with_store(store.clone())
            .await
            .unwrap();
        let (flow, context) = flow();
        monitor.opened(flow, context);
        monitor.bytes(flow.key, TunFlowDirection::Upload, 13);
        monitor.closed(flow.key);
        monitor.shutdown().await.unwrap();

        let reloaded = ConnectionMonitor::load_with_store(store).await.unwrap();
        assert_eq!(reloaded.total_flow_value()["upload"], "13");
        let now = unix_seconds();
        assert_eq!(
            reloaded.telemetry_value_range(now - 3_600, now + 3_600, 10)["groups"]
                .as_array()
                .unwrap()
                .len(),
            GO_TELEMETRY_DIMENSIONS.len()
        );
        assert_eq!(
            reloaded.all_history_value()["items"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        reloaded.shutdown().await.unwrap();
    });
}

#[tokio::test(flavor = "current_thread")]
async fn failed_history_callback_does_not_wait_for_the_store_lock() {
    let path = monitor_test_database_path();
    remove_monitor_test_database(&path);
    let store = ConfigStore::open(&path).await.unwrap();
    let monitor = ConnectionMonitor::load_with_store(store).await.unwrap();
    monitor.shutdown().await.unwrap();

    let lock_path = PathBuf::from(format!("{}-yuhaiin-write-lock", path.display()));
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap();
    lock.lock().unwrap();

    let callback_monitor = monitor.clone();
    let callback = std::thread::spawn(move || {
        callback_monitor.record_failure("http", "example.com:443", "database busy");
    });
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        callback.is_finished(),
        "failure callback must not synchronously wait for SQLite"
    );
    drop(lock);
    callback.join().unwrap();
    remove_monitor_test_database(&path);
}

#[tokio::test(flavor = "current_thread")]
async fn monitor_shutdown_does_not_wait_for_the_store_lock() {
    let path = monitor_test_database_path();
    remove_monitor_test_database(&path);
    let store = ConfigStore::open(&path).await.unwrap();
    let monitor = ConnectionMonitor::load_with_store(store).await.unwrap();
    let lock_path = PathBuf::from(format!("{}-yuhaiin-write-lock", path.display()));
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)
        .unwrap();
    lock.lock().unwrap();

    monitor.record_failure("http", "example.com:443", "database busy");
    let result = tokio::time::timeout(Duration::from_secs(1), monitor.shutdown())
        .await
        .expect("monitor shutdown must not wait for SQLite lock");
    assert!(result.is_err());
    drop(lock);
    remove_monitor_test_database(&path);
}

#[tokio::test]
async fn failed_history_checkpoint_keeps_all_failures() {
    let store = ConfigStore::open_memory().await.unwrap();
    let monitor = ConnectionMonitor::load_with_store(store.clone())
        .await
        .unwrap();
    let expected = 1_280;
    for _ in 0..expected {
        monitor.record_failure("http", "example.com:443", "connection refused");
    }

    monitor.shutdown().await.unwrap();
    let statistics = store.load_go_statistics().unwrap();
    assert_eq!(statistics.failed_history.len(), 1);
    assert_eq!(statistics.failed_history[0].count, expected as u64);
}

#[tokio::test]
async fn monitor_projects_go_statistics_for_an_independent_reader_before_shutdown() {
    let path = monitor_test_database_path();
    remove_monitor_test_database(&path);
    let writer_store = ConfigStore::open(&path).await.unwrap();
    let reader_store = ConfigStore::open(&path).await.unwrap();
    let monitor = ConnectionMonitor::load_with_store(writer_store)
        .await
        .unwrap();
    let (flow, context) = flow();
    monitor.opened(flow, context);
    monitor.bytes(flow.key, TunFlowDirection::Upload, 23);
    monitor.closed(flow.key);

    let observed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let statistics = reader_store.load_go_statistics().unwrap();
            if statistics.total_upload == 23 && statistics.history.len() == 1 {
                break statistics;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("independent reader should observe the runtime Go projection");
    assert_eq!(observed.total_upload, 23);
    assert_eq!(observed.history[0].count, 1);

    monitor.shutdown().await.unwrap();
    drop(reader_store);
    remove_monitor_test_database(&path);
}

#[tokio::test]
async fn monitor_flushes_incremental_statistics_on_the_next_interval() {
    let store = ConfigStore::open_memory().await.unwrap();
    let monitor = ConnectionMonitor::load_with_store(store.clone())
        .await
        .unwrap();
    let (flow, context) = flow();
    monitor.opened(flow, context);
    monitor.bytes(flow.key, TunFlowDirection::Upload, 13);

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if store.load_go_statistics().unwrap().total_upload == 13
                && store.get_config(PERSISTENCE_KEY).await.unwrap().is_none()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("initial checkpoint should be written");

    monitor.bytes(flow.key, TunFlowDirection::Upload, 17);
    tokio::time::timeout(
        PERSISTENCE_CHECKPOINT_INTERVAL + Duration::from_secs(1),
        async {
            loop {
                if store.load_go_statistics().unwrap().total_upload == 30 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        },
    )
    .await
    .expect("dirty update should be persisted on the next interval");
    monitor.shutdown().await.unwrap();
}

#[test]
fn monitor_force_abort_child() {
    let Some(path) = std::env::var_os("YUHAIIN_RUNTIME_MONITOR_CRASH_CHILD_PATH") else {
        return;
    };
    let path = PathBuf::from(path);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let store = ConfigStore::open(&path).await.unwrap();
        let monitor = ConnectionMonitor::load_with_store(store).await.unwrap();
        let (flow, context) = flow();
        monitor.opened(flow, context);
        monitor.bytes(flow.key, TunFlowDirection::Upload, 29);
        monitor.closed(flow.key);
        monitor.record_failure("tcp", "resolver.example:443", "selected tcp node not found");

        // Keep the process alive so the parent can kill it before any
        // graceful monitor shutdown or Drop-based cleanup can run.
        tokio::time::sleep(Duration::from_secs(10)).await;
    });
}

#[test]
fn monitor_recovers_checkpoint_after_force_abort() {
    let path = monitor_test_database_path();
    remove_monitor_test_database(&path);
    let executable = std::env::current_exe().unwrap();
    let mut child = Command::new(executable)
        .arg("--exact")
        .arg("monitor::tests::monitor_force_abort_child")
        .arg("--nocapture")
        .env("YUHAIIN_RUNTIME_MONITOR_CRASH_CHILD_PATH", &path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // The persistence worker's first interval tick is immediate; this
    // leaves enough time for the checkpoint write while still ensuring
    // the child is terminated far before its ten-second sleep ends.
    std::thread::sleep(Duration::from_millis(700));
    child.kill().unwrap();
    let status = child.wait().unwrap();
    assert!(!status.success(), "crash child must not exit gracefully");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let store = ConfigStore::open(&path).await.unwrap();
        let monitor = ConnectionMonitor::load_with_store(store).await.unwrap();
        assert_eq!(monitor.total_flow_value()["upload"], "29");
        assert_eq!(monitor.all_history_value()["items"][0]["count"], "1");
        let go_statistics = monitor
            .persistence
            .as_ref()
            .unwrap()
            .store
            .load_go_statistics()
            .unwrap();
        assert_eq!(go_statistics.total_upload, 29);
        assert_eq!(go_statistics.history[0].count, 1);
        assert_eq!(go_statistics.failed_history[0].count, 1);
        assert_eq!(go_statistics.failed_history[0].host, "resolver.example:443");
        monitor.shutdown().await.unwrap();
    });
    remove_monitor_test_database(&path);
}

#[test]
fn monitor_takes_over_go_statistics_when_runtime_checkpoint_is_absent() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let store = ConfigStore::open_memory().await.unwrap();
        let observed_store = store.clone();
        store
            .replace_go_statistics(&GoStatisticsSnapshot {
                total_download: 23,
                total_upload: 19,
                history: vec![GoConnectionHistoryRecord {
                    protocol: "tcp".to_owned(),
                    addr: "203.0.113.10:443".to_owned(),
                    process: "/usr/bin/browser".to_owned(),
                    count: 4,
                    last_seen: 1_700_000_000,
                    connection_json: br#"{
                            "network":{"connType":"tcp"},
                            "addr":"203.0.113.10:443",
                            "process":"/usr/bin/browser"
                        }"#
                    .to_vec(),
                }],
                ..GoStatisticsSnapshot::default()
            })
            .unwrap();

        let monitor = ConnectionMonitor::load_with_store(store).await.unwrap();
        assert_eq!(monitor.total_flow_value()["download"], "23");
        assert_eq!(monitor.total_flow_value()["upload"], "19");
        assert_eq!(monitor.all_history_value()["items"][0]["count"], "4");
        assert_eq!(monitor.all_history_value()["dumpProcessEnabled"], true);
        assert!(
            monitor.all_history_value()["items"][0]["connection"]
                .get(INTERNAL_GO_PROTOCOL_KEY)
                .is_none()
        );
        assert!(
            monitor.all_history_value()["items"][0]["connection"]
                .get("protocol")
                .is_none()
        );
        monitor.shutdown().await.unwrap();
        assert_eq!(
            observed_store.load_go_statistics().unwrap().history[0].protocol,
            "tcp"
        );
    });
}

#[tokio::test]
async fn monitor_migrates_legacy_runtime_blob_into_go_tables_once() {
    let store = ConfigStore::open_memory().await.unwrap();
    let bucket = 1_700_000_000;
    let persisted = PersistedMonitor {
        version: PERSISTENCE_VERSION,
        next_id: 9,
        total_upload: 7,
        total_download: 11,
        counters: BTreeMap::new(),
        buckets: BTreeMap::from([(bucket, (11, 7))]),
        telemetry: vec![],
        telemetry_buckets: vec![PersistedTelemetryBucket {
            bucket,
            span_seconds: TELEMETRY_HOURLY_BUCKET_SECONDS,
            dimension: "protocol".to_owned(),
            value: "tcp".to_owned(),
            download: 11,
            upload: 7,
            failures: 0,
        }],
        history: vec![json!({
            "connection": {"protocol": "tcp", "addr": "example.com:443"},
            "count": "2",
            "time": "2024-01-01T00:00:00Z"
        })],
        failed_history: vec![],
        block_history: vec![],
    };
    store
        .put_config(PERSISTENCE_KEY, &serde_json::to_vec(&persisted).unwrap())
        .await
        .unwrap();

    let monitor = ConnectionMonitor::load_with_store(store.clone())
        .await
        .unwrap();
    assert_eq!(monitor.total_flow_value()["upload"], "7");
    assert_eq!(monitor.all_history_value()["items"][0]["count"], "2");
    assert!(store.get_config(PERSISTENCE_KEY).await.unwrap().is_none());
    let statistics = store.load_go_statistics().unwrap();
    assert_eq!(statistics.total_upload, 7);
    assert_eq!(statistics.history[0].count, 2);
    monitor.shutdown().await.unwrap();
}
