-- Minimal on-disk fixture copied from the current Go SQLite contract shape.
-- It intentionally keeps JSON as TEXT, as the Go store does.
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE migrate (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at INTEGER NOT NULL
);
INSERT INTO metadata(key, value) VALUES ('schema_version', '6');
INSERT INTO migrate(version, name, applied_at) VALUES
    (1, 'initial_schema', 100),
    (2, 'fakeip_cache', 101),
    (3, 'plain_contract_model', 102),
    (4, 'plain_route_lists', 103),
    (5, 'telemetry_dimensions', 104),
    (6, 'compact_telemetry_dimensions', 105);

CREATE TABLE settings_json (
    id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL,
    data_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
INSERT INTO settings_json VALUES
    (1, 12, '{"mode":"proxy","resolve_strategy":"prefer_ipv4"}', 200);

CREATE TABLE nodes_v2 (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    group_name TEXT NOT NULL,
    origin TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    chain_types_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    data_json TEXT NOT NULL
);
INSERT INTO nodes_v2 VALUES
    ('node-a', 'Node A', 'remote', 'remote', 1, '["yuubinsya"]', 201,
     '{"name":"Node A","protocol":"yuubinsya","password":"redacted"}');

CREATE TABLE resolvers_v2 (
    id TEXT PRIMARY KEY,
    resolver_type TEXT NOT NULL,
    host TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    data_json TEXT NOT NULL
);
INSERT INTO resolvers_v2 VALUES
    ('dns-udp', 'udp', '1.1.1.1:53', 202, '{"type":"udp","host":"1.1.1.1:53"}');

CREATE TABLE route_rules_v2 (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    priority INTEGER NOT NULL,
    disabled INTEGER NOT NULL,
    action_mode TEXT NOT NULL,
    match_type TEXT NOT NULL,
    tag TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL,
    data_json TEXT NOT NULL
);
INSERT INTO route_rules_v2 VALUES
    ('rule-a', 'proxy-example', 10, 0, 'proxy', 'domain', '', 203,
     '{"name":"proxy-example","match":{"domain":"example.com"},"mode":"proxy"}');

CREATE TABLE inbounds_v2 (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    network_type TEXT NOT NULL,
    protocol_type TEXT NOT NULL,
    transport_types_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    data_json TEXT NOT NULL
);
INSERT INTO inbounds_v2 VALUES
    ('tun-main', 'tun', 1, 'tcpudp', 'tun', '["tun"]', 204,
     '{"name":"tun","network":"tcpudp","mtu":1500}');
