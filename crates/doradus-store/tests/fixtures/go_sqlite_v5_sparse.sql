-- Sparse Go v5 state: historical columns and unmodeled tables are present,
-- but most optional tables are empty.  This mirrors a newly installed or
-- partially used profile rather than the dense production snapshot.
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE migrate (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at INTEGER NOT NULL
);
INSERT INTO metadata VALUES ('schema_version', '5');
INSERT INTO migrate VALUES
    (1, 'initial_schema', 100),
    (2, 'fakeip_cache', 101),
    (3, 'plain_contract_model', 102),
    (4, 'plain_route_lists', 103),
    (5, 'telemetry_dimensions', 104);

CREATE TABLE settings_kv (
    section TEXT NOT NULL,
    key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (section, key)
);
CREATE TABLE dns_resolvers (
    name TEXT PRIMARY KEY,
    resolver_type INTEGER NOT NULL,
    host TEXT NOT NULL,
    subnet TEXT NOT NULL DEFAULT '',
    tls_servername TEXT NOT NULL DEFAULT '',
    data_json TEXT NOT NULL
);
CREATE TABLE route_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    priority INTEGER,
    disabled INTEGER,
    updated_at INTEGER,
    data_json TEXT NOT NULL
);
INSERT INTO dns_resolvers VALUES
    ('sparse-dns', 1, '192.0.2.53:53', '', '',
     '{"type":"udp","host":"192.0.2.53:53","unknown_sparse_field":"keep"}');
CREATE TABLE legacy_unmodeled (
    key TEXT PRIMARY KEY,
    payload BLOB NOT NULL
);
INSERT INTO legacy_unmodeled VALUES ('sparse-row', X'00FF1065');

-- Optional v5 telemetry tables exist but are empty in this profile.
CREATE TABLE traffic_dimension_hourly (
    bucket_start_utc INTEGER NOT NULL,
    dimension TEXT NOT NULL,
    value TEXT NOT NULL,
    upload_bytes INTEGER NOT NULL DEFAULT 0,
    download_bytes INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (bucket_start_utc, dimension, value)
);
CREATE TABLE failure_dimension_hourly (
    bucket_start_utc INTEGER NOT NULL,
    dimension TEXT NOT NULL,
    value TEXT NOT NULL,
    failed_count INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (bucket_start_utc, dimension, value)
);
