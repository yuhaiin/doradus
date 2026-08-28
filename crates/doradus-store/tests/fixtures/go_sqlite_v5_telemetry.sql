-- Snapshot at the end of Go migration version 5.  These telemetry tables
-- are intentionally not modeled by the first Rust repository, but opening
-- the database must preserve them byte-for-byte for a later importer.
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
INSERT INTO traffic_dimension_hourly VALUES
    (1700000000, 'source', 'http2.h-20-2127.0.0.1:52001', 10, 20, 1700000000),
    (1700000000, 'source', 'http2.h-21-2example.com:443', 30, 40, 1700000000),
    (1700000000, 'source', 'http2.h-22-2[2407:cdc0::1]:52002', 50, 60, 1700000000);
INSERT INTO failure_dimension_hourly VALUES
    (1700000000, 'source', 'http2.h-20-2127.0.0.1:52001', 3, 1700000000);
