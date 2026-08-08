-- Go v1 database before the plain-contract *_v2 tables existed.
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE migrate (version INTEGER PRIMARY KEY, name TEXT NOT NULL);
INSERT INTO metadata VALUES ('schema_version', '1');
INSERT INTO migrate VALUES (1, 'initial_schema');

CREATE TABLE dns_resolvers (
    name TEXT PRIMARY KEY,
    resolver_type INTEGER NOT NULL,
    host TEXT NOT NULL,
    subnet TEXT NOT NULL DEFAULT '',
    tls_servername TEXT NOT NULL DEFAULT '',
    data_json TEXT NOT NULL CHECK (json_valid(data_json))
);
INSERT INTO dns_resolvers VALUES
    ('bootstrap', 1, '', '', '',
     '{"host":"","type":"udp","unknown_resolver_field":"kept"}'),
    ('legacy-dot', 4, 'dns.example:853', '', 'dns.example',
     '{"host":"dns.example:853","type":"dot","tls_servername":"dns.example","unknown_resolver_field":"kept"}');

CREATE TABLE route_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    priority INTEGER,
    disabled INTEGER,
    updated_at INTEGER,
    data_json TEXT NOT NULL CHECK (json_valid(data_json))
);
INSERT INTO route_rules (name, priority, disabled, updated_at, data_json) VALUES
    ('legacy-domain', 20, 0, 120,
     '{"name":"legacy-domain","mode":"proxy","tag":"proxy-a","rules":[{"rules":[{"host":{"list":"domains"}}]}],"unknown_route_field":{"keep":true}}'),
    ('legacy-empty', 30, 1, 121,
     '{"name":"legacy-empty","mode":"bypass","rules":[],"unknown_route_field":42}');
