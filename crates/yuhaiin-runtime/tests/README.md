# Runtime integration tests

`service_chain.rs` starts the real `yuhaiin` executable built by Cargo, changes
its SQLite-backed configuration through `/api/v2`, waits for the inbound
supervisor to reload, and then sends traffic through the configured listener.
It is process-level coverage rather than a unit test that calls the router
directly.

The current scenarios cover:

- `api_contract.rs` starts one real service process and round-trips the main
  React management contracts: settings/backup, hosts/FakeDNS, resolver and
  inbound CRUD, node selection/active state, users, publishes/subscriptions,
  route config/lists/rules/tags/apply, connections/statistics, SSE, tools and
  representative 404 errors. It also checks the fresh default mixed inbound's
  UDP contract and runs direct-node domain latency against a real loopback HTTP
  server. It keeps an enabled HTTP inbound alive while testing node selection
  so `nodes.active` observes a real selector after reload rather than a
  synthetic enabled row.
- HTTP inbound → domain route rule → fixed + HTTP CONNECT outbound, including
  live connection metadata, traffic counters, route testing, and node latency.
- HTTP inbound + mixed UDP inbound → TLS + HTTP/2 + Yuubinsya UDP-over-TCP
  outbound, including TCP echo, UDP echo, live connection metadata, traffic,
  telemetry, failed-history, closed-flow history, and node latency through the
  same configured node.
- HTTP inbound → domain route rule → fixed + SOCKS5 outbound, including
  proxy-side domain framing, live metadata, and node latency.
- HTTP inbound → fixed + HTTP/2 + authenticated HTTP CONNECT outbound, and
  HTTP inbound → fixed + HTTP/2 + authenticated SOCKS5 outbound, including
  prior-knowledge H2 stream relay, route metadata, payload echo, and latency.
- mixed inbound → SOCKS5 UDP framing → direct UDP, including the Go-compatible
  mixed UDP mode and a conflicting default `127.0.0.1:1080` listener.
- authenticated SOCKS5 TCP inbound and Yuubinsya TCP inbound → direct echo in
  the same real runtime process, including protocol handshakes and live
  inbound/outbound metadata.
- `scripts/integration/tun-service.sh` builds the real
  `tun-service-smoke` runtime binary, writes a Go-shaped TUN inbound to a
  reusable SQLite state directory, and runs the same `inbound::run_until`
  owner in a privileged Podman `--network=none` container. It checks that the
  kernel TUN device appears and is removed by the common shutdown path.
- `scripts/integration/dns-source-bind.sh` runs the existing UDP/TCP resolver
  source-address tests inside a host-network Podman container. It confirms
  that the configured local IPv4 address reaches the DNS server for both
  transports; build and Podman logs are kept under
  `~/.cache/yuhaiin-rust/integration/dns-source-bind`.
- `scripts/integration/doh-source-bind.sh` runs a real RustCrypto DoH/HTTP2 and
  DoT/TLS resolver pair in a host-network Podman container. It asserts that
  both TLS transports reach their server from the configured local IPv4
  address; logs are kept under `~/.cache/yuhaiin-rust/integration/doh-source-bind`.
- `scripts/integration/socks5-udp-associate.sh` runs the real SOCKS5 control
  handshake, UDP ASSOCIATE, UDP echo, shared direct outbound and monitor
  assertion in a host-network Podman container. It keeps logs under
  `~/.cache/yuhaiin-rust/integration/socks5-udp-associate`.
- `scripts/integration/node-latency-dns.sh` saves a direct node through the
  API-layer fixture, invokes `node_latency` with a real UDP DNS server, and
  checks the selected proxy datagram path and DNS transaction in Podman. Logs
  are kept under `~/.cache/yuhaiin-rust/integration/node-latency-dns`.
- `stats_concurrency.rs` starts the real runtime process, keeps an HTTP inbound
  flow active while concurrent readers query connections, totals, traffic,
  telemetry, history, and failed-history, then restarts the same SQLite state
  and verifies persisted traffic/history remain readable. The reusable Podman
  entry point is `scripts/integration/stats-concurrency.sh`; logs are kept
  under `~/.cache/yuhaiin-rust/integration/stats-concurrency`.
- `scripts/integration/api-contract.sh` runs the frontend management API
  process contract in Podman, including CRUD, reload, selection, connections,
  statistics, SSE, and representative error responses. It uses host networking
  so the subprocess and loopback fixtures share one namespace; build/runtime
  logs are kept under `~/.cache/yuhaiin-rust/integration/api-contract`.
- standalone Go HTTP/2 transport wire compatibility is covered separately in
  `crates/yuhaiin-chain/tests/standalone_http2.rs`: fixed endpoint resolution,
  plaintext prior-knowledge H2, `CONNECT http://localhost`, raw bidirectional
  bytes, pool ping/close, and the fail-closed raw final-proxy boundary. The
  final HTTP/SOCKS5 compositions are covered by the process tests above and
  intentionally remain TCP-only over a raw H2 parent.

Run the tests from the repository root:

```bash
cargo test -p yuhaiin-runtime --all-features --offline --test api_contract -- --nocapture
cargo test -p yuhaiin-runtime --all-features --offline --test service_chain -- --nocapture
scripts/integration/api-contract.sh
```

By default each test stores its SQLite state below
`~/.cache/yuhaiin-rust/integration/<scenario>/<pid>`. To retain a reusable
scenario directory for inspection or a Podman job, set an explicit cache path:

```bash
YUHAIIN_INTEGRATION_DIR="$HOME/.cache/yuhaiin-rust/integration-reusable" \
  cargo test -p yuhaiin-runtime --all-features --offline --test service_chain -- --nocapture
```

The runtime-owned TUN process smoke uses the same cache convention:

```bash
scripts/integration/tun-service.sh
```

The fixtures only use loopback sockets. A container runner should use
`--network=host` when it needs the same loopback behavior and mount the chosen
cache directory under `~/.cache`; no test state is written to `/tmp`.
