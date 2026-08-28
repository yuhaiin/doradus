-- Compact de-identified Go v6 plain-contract edge snapshot.
-- This is intentionally small enough for normal CI; the full production
-- snapshot remains a separate ignored migration fixture.
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE migrate (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL);
INSERT INTO metadata VALUES ('schema_version', '6');
INSERT INTO migrate VALUES (6, 'compact_telemetry_dimensions', 105);

CREATE TABLE fakeip_entries (
    family INTEGER NOT NULL,
    prefix TEXT NOT NULL,
    domain TEXT NOT NULL,
    ip BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    PRIMARY KEY (family, prefix, domain)
);
CREATE TABLE fakeip_cursors (
    family INTEGER NOT NULL,
    prefix TEXT NOT NULL,
    cursor_ip BLOB NOT NULL,
    cursor_idx INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (family, prefix)
);

-- The old rows are deliberately expired for the test TTL.  The cursor is
-- still present, so reopening must reclaim rows without resetting allocation.
INSERT INTO fakeip_entries VALUES
    (4, '198.18.0.0/15', 'expired-v4.example', X'C6120001', 1, 1),
    (6, 'fc00::/18', 'expired-v6.example', X'FC000000000000000000000000000001', 1, 1);
INSERT INTO fakeip_cursors VALUES
    (4, '198.18.0.0/15', X'C6120002', 2, 2000000000),
    (6, 'fc00::/18', X'FC000000000000000000000000000002', 2, 2000000000);

-- Unknown fields are retained by the compatibility importer rather than
-- being interpreted as FakeIP columns.
CREATE TABLE settings_json (
    id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL,
    data_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
INSERT INTO settings_json VALUES
    (1, 12, '{"mode":"proxy","fakeip_edge_unknown":{"keep":true}}', 200);
