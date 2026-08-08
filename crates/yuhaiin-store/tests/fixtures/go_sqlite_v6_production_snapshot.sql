-- Production-shaped snapshot assembled from the current Go migrations.go.
-- It includes configuration, legacy compatibility, FakeIP, route-list and
-- compact telemetry tables.  The Rust importer must read the v2 contract
-- tables without deleting the tables/fields it does not model yet.
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE migrate (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL);
INSERT INTO metadata VALUES ('schema_version', '6');
INSERT INTO migrate VALUES
    (1, 'initial_schema', 100),
    (2, 'fakeip_cache', 101),
    (3, 'plain_contract_model', 102),
    (4, 'plain_route_lists', 103),
    (5, 'telemetry_dimensions', 104),
    (6, 'compact_telemetry_dimensions', 105);

CREATE TABLE android_extra_preferences (
    key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE settings_kv (
    section TEXT NOT NULL, key TEXT NOT NULL, value_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL, PRIMARY KEY (section, key)
);
INSERT INTO settings_kv VALUES ('android', 'dark_mode', '{"enabled":true}', 110);
CREATE TABLE dns_settings (
    id INTEGER PRIMARY KEY, server TEXT NOT NULL, fakedns_enabled INTEGER NOT NULL,
    fakedns_ipv4_range TEXT NOT NULL, fakedns_ipv6_range TEXT NOT NULL
);
INSERT INTO dns_settings VALUES (1, 'dns-udp', 1, '198.18.0.0/15', 'fc00::/18');
CREATE TABLE dns_resolvers (
    name TEXT PRIMARY KEY, resolver_type INTEGER NOT NULL, host TEXT NOT NULL,
    subnet TEXT NOT NULL, tls_servername TEXT NOT NULL, data_json TEXT NOT NULL
);
CREATE TABLE dns_hosts (host TEXT PRIMARY KEY, target TEXT NOT NULL);
INSERT INTO dns_hosts VALUES ('legacy.example', '192.0.2.10');
CREATE TABLE dns_fakedns_lists (kind TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (kind, value));
INSERT INTO dns_fakedns_lists VALUES ('ipv4', '198.18.0.0/15');
CREATE TABLE inbound_settings (
    id INTEGER PRIMARY KEY, hijack_dns INTEGER NOT NULL,
    hijack_dns_fakeip INTEGER NOT NULL, sniff_enabled INTEGER NOT NULL
);
INSERT INTO inbound_settings VALUES (1, 1, 1, 0);
CREATE TABLE inbounds (
    name TEXT PRIMARY KEY, enabled INTEGER NOT NULL, inbound_type TEXT NOT NULL,
    listen_host TEXT NOT NULL, updated_at INTEGER NOT NULL, data_json TEXT NOT NULL
);
CREATE TABLE nodes (
    id INTEGER PRIMARY KEY, hash TEXT NOT NULL, group_name TEXT NOT NULL,
    name TEXT NOT NULL, origin INTEGER NOT NULL, selected_tcp INTEGER NOT NULL,
    selected_udp INTEGER NOT NULL, search_text TEXT NOT NULL, updated_at INTEGER NOT NULL,
    data_json TEXT NOT NULL
);
CREATE TABLE node_tags (
    tag_name TEXT NOT NULL, target_kind TEXT NOT NULL, target_id TEXT NOT NULL,
    updated_at INTEGER NOT NULL, PRIMARY KEY (tag_name, target_kind, target_id)
);
CREATE TABLE subscriptions (name TEXT PRIMARY KEY, updated_at INTEGER NOT NULL, data_json TEXT NOT NULL);
INSERT INTO subscriptions VALUES ('production', 206, '{"url":"https://rules.example/sub","unknown_subscription_field":true}');
CREATE TABLE publishes (name TEXT PRIMARY KEY, updated_at INTEGER NOT NULL, data_json TEXT NOT NULL);
CREATE TABLE route_settings (
    id INTEGER PRIMARY KEY, direct_resolver TEXT NOT NULL, proxy_resolver TEXT NOT NULL,
    resolve_locally INTEGER NOT NULL, udp_proxy_fqdn INTEGER NOT NULL
);
INSERT INTO route_settings VALUES (1, 'system', 'dns-prod', 1, 0);
CREATE TABLE route_rules (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, priority INTEGER NOT NULL,
    disabled INTEGER NOT NULL, updated_at INTEGER NOT NULL, data_json TEXT NOT NULL
);
CREATE TABLE route_lists (name TEXT PRIMARY KEY, kind TEXT NOT NULL, updated_at INTEGER NOT NULL, data_json TEXT NOT NULL);
CREATE TABLE route_list_refresh (
    name TEXT PRIMARY KEY, refresh_interval INTEGER NOT NULL,
    last_refresh_time INTEGER NOT NULL, last_error TEXT NOT NULL
);
CREATE TABLE backup_settings (id INTEGER PRIMARY KEY, updated_at INTEGER NOT NULL, data_json TEXT NOT NULL);
CREATE TABLE statistics_kv (key TEXT PRIMARY KEY, value_int INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE traffic_hourly (
    bucket_start_utc INTEGER PRIMARY KEY, upload_bytes INTEGER NOT NULL,
    download_bytes INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE connection_sessions (
    id INTEGER PRIMARY KEY, opened_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL,
    closed_at INTEGER, state TEXT NOT NULL, protocol INTEGER NOT NULL,
    process_name TEXT NOT NULL, inbound TEXT NOT NULL, inbound_name TEXT NOT NULL,
    outbound TEXT NOT NULL, network TEXT NOT NULL, destination TEXT NOT NULL,
    host TEXT NOT NULL, upload_bytes INTEGER NOT NULL, download_bytes INTEGER NOT NULL,
    summary_json TEXT NOT NULL
);
CREATE TABLE connection_history (
    protocol INTEGER NOT NULL, addr TEXT NOT NULL, process_name TEXT NOT NULL,
    hit_count INTEGER NOT NULL, last_seen_at INTEGER NOT NULL,
    last_connection_json TEXT NOT NULL, PRIMARY KEY (protocol, addr, process_name)
);
CREATE TABLE failed_connection_history (
    protocol INTEGER NOT NULL, host TEXT NOT NULL, process_name TEXT NOT NULL,
    failed_count INTEGER NOT NULL, last_seen_at INTEGER NOT NULL,
    last_error TEXT NOT NULL, PRIMARY KEY (protocol, host, process_name)
);
CREATE TABLE fakeip_entries (
    family INTEGER NOT NULL, prefix TEXT NOT NULL, domain TEXT NOT NULL,
    ip BLOB NOT NULL, created_at INTEGER NOT NULL, last_used_at INTEGER NOT NULL,
    PRIMARY KEY (family, prefix, domain)
);
INSERT INTO fakeip_entries VALUES (4, '198.18.0.0/15', 'legacy.example', X'C6120001', 120, 121);
INSERT INTO fakeip_entries VALUES (6, 'fc00::/18', 'legacy6.example', X'FC000000000000000000000000000001', 123, 124);
CREATE TABLE fakeip_cursors (
    family INTEGER NOT NULL, prefix TEXT NOT NULL, cursor_ip BLOB NOT NULL,
    cursor_idx INTEGER NOT NULL, updated_at INTEGER NOT NULL,
    PRIMARY KEY (family, prefix)
);
INSERT INTO fakeip_cursors VALUES (4, '198.18.0.0/15', X'C6120002', 2, 122);
INSERT INTO fakeip_cursors VALUES (6, 'fc00::/18', X'FC000000000000000000000000000002', 2, 125);

CREATE TABLE settings_json (
    id INTEGER PRIMARY KEY, version INTEGER NOT NULL, data_json TEXT NOT NULL, updated_at INTEGER NOT NULL
);
INSERT INTO settings_json VALUES (1, 12, '{"mode":"proxy","resolve_strategy":"prefer_ipv4","unknown":{"keep":true}}', 200);
CREATE TABLE inbounds_v2 (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, enabled INTEGER NOT NULL,
    network_type TEXT NOT NULL, protocol_type TEXT NOT NULL,
    transport_types_json TEXT NOT NULL, updated_at INTEGER NOT NULL, data_json TEXT NOT NULL
);
INSERT INTO inbounds_v2 VALUES
    ('tun-main', 'tun', 1, 'tcpudp', 'tun', '["tun"]', 204,
     '{"name":"tun","network":"tcpudp","mtu":1500,"unknown_field":"preserve"}');
CREATE TABLE nodes_v2 (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, group_name TEXT NOT NULL, origin TEXT NOT NULL,
    enabled INTEGER NOT NULL, chain_types_json TEXT NOT NULL, updated_at INTEGER NOT NULL, data_json TEXT NOT NULL
);
INSERT INTO nodes_v2 VALUES
    ('node-prod', 'Production node', 'remote', 'remote', 1, '["yuubinsya","tls"]', 201,
     '{"name":"Production node","protocol":"yuubinsya","password":"redacted","unknown_field":42}');
CREATE TABLE node_tags_v2 (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, members_json TEXT NOT NULL, updated_at INTEGER NOT NULL
);
INSERT INTO node_tags_v2 VALUES ('tag-prod', 'production', '["node-prod"]', 202);
CREATE TABLE resolvers_v2 (
    id TEXT PRIMARY KEY, resolver_type TEXT NOT NULL, host TEXT NOT NULL,
    updated_at INTEGER NOT NULL, data_json TEXT NOT NULL
);
INSERT INTO resolvers_v2 VALUES
    ('dns-prod', 'doh', 'https://dns.example/dns-query', 203,
     '{"type":"doh","host":"https://dns.example/dns-query","bootstrap":["1.1.1.1"],"unknown_resolver_field":{"keep":true}}');
CREATE TABLE route_rules_v2 (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, priority INTEGER NOT NULL,
    disabled INTEGER NOT NULL, action_mode TEXT NOT NULL, match_type TEXT NOT NULL,
    tag TEXT NOT NULL, updated_at INTEGER NOT NULL, data_json TEXT NOT NULL
);
INSERT INTO route_rules_v2 VALUES
    ('rule-prod', 'production-domain', 10, 0, 'proxy', 'domain', 'production', 204,
     '{"name":"production-domain","match":{"domain":"example.com"},"mode":"proxy","unknown_field":true}');
CREATE TABLE route_lists_v2 (
    name TEXT PRIMARY KEY, list_type TEXT NOT NULL, source_type TEXT NOT NULL,
    updated_at INTEGER NOT NULL, data_json TEXT NOT NULL
);
INSERT INTO route_lists_v2 VALUES
    ('remote-prod', 'domain', 'remote', 205, '{"url":"https://rules.example/list","etag":"v1","unknown_list_field":[1,2,3]}');

CREATE TABLE telemetry_dimension_values (
    id INTEGER PRIMARY KEY, dimension TEXT NOT NULL, value TEXT NOT NULL
);
INSERT INTO telemetry_dimension_values VALUES (1, 'source', 'yuubinsya');
CREATE TABLE traffic_dimension_hourly (
    bucket_start_utc INTEGER NOT NULL, value_id INTEGER NOT NULL,
    upload_bytes INTEGER NOT NULL, download_bytes INTEGER NOT NULL,
    PRIMARY KEY (bucket_start_utc, value_id)
);
CREATE TABLE traffic_dimension_daily (
    bucket_start_utc INTEGER NOT NULL, value_id INTEGER NOT NULL,
    upload_bytes INTEGER NOT NULL, download_bytes INTEGER NOT NULL,
    PRIMARY KEY (bucket_start_utc, value_id)
);
CREATE TABLE failure_dimension_hourly (
    bucket_start_utc INTEGER NOT NULL, value_id INTEGER NOT NULL,
    failed_count INTEGER NOT NULL, PRIMARY KEY (bucket_start_utc, value_id)
);
CREATE TABLE failure_dimension_daily (
    bucket_start_utc INTEGER NOT NULL, value_id INTEGER NOT NULL,
    failed_count INTEGER NOT NULL, PRIMARY KEY (bucket_start_utc, value_id)
);
INSERT INTO traffic_dimension_hourly VALUES (1000, 1, 10, 20);
INSERT INTO traffic_dimension_daily VALUES (0, 1, 100, 200);
INSERT INTO failure_dimension_hourly VALUES (1000, 1, 2);
INSERT INTO failure_dimension_daily VALUES (0, 1, 3);
