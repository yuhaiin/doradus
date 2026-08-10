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
- `api_reload_flow.rs` keeps one SQLite state and two real HTTP CONNECT
  fixtures, changes the selected node through `PUT /api/v2/nodes/{id}`, moves
  the HTTP inbound listener through `PUT /api/v2/inbounds/{id}`, and changes a
  route from proxy to direct through `PUT /api/v2/route/rules/{name}/{index}`.
  It proves each mutation on the real data path, checks node latency and live
  traffic/history, and reads the same node, moved inbound, totals, and history
  after a process restart. Run the reusable Podman entry point with
  `make api-reload-flow-smoke`; logs are kept under
  `~/.cache/yuhaiin-rust/integration/api-reload-flow`.
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
- prior-knowledge HTTP/2 inbound → route rule → fixed + HTTP CONNECT outbound,
  including the inner HTTP CONNECT framing, proxy-side domain authority,
  live connections, upload/download counters, and shutdown.
- TLS + HTTP/2 inbound → route rule → fixed + HTTP CONNECT outbound, including
  TLS ALPN `h2` negotiation and the same live data-plane assertions.
- mixed inbound → SOCKS5 UDP framing → direct UDP, including the Go-compatible
  mixed UDP mode and a conflicting default `127.0.0.1:1080` listener.
- authenticated SOCKS5 TCP inbound and Yuubinsya TCP inbound → direct echo in
  the same real runtime process, including protocol handshakes and live
  inbound/outbound metadata.
- SOCKS5 inbound and Yuubinsya inbound → TLS + HTTP/2 + Yuubinsya outbound,
  including domain targets, shared route match history, live connection
  metadata, payload echo, and node latency in one runtime process.
- TLS termination → HTTP proxy inbound → direct outbound, using the Go-shaped
  certificate transport configuration, a real Rust TLS client, CONNECT framing,
  payload echo, and live connection metadata. This is also available through
  `make service-chain-smoke`.
- `scripts/integration/tun-service.sh` builds the real
  `tun-service-smoke` runtime binary, writes a Go-shaped TUN inbound to a
  reusable SQLite state directory, and runs the same `inbound::run_until`
  owner in a privileged Podman `--network=none` container. It checks that the
  kernel TUN device appears and is removed by the common shutdown path.
- `scripts/integration/tun-chain-service.sh` runs the same real kernel TUN
  inbound with a SQLite-selected `fixed -> TLS -> HTTP/2 -> Yuubinsya` TCP
  outbound and a loopback echo target. It deliberately half-closes the client
  immediately after writing, covering bidirectional HTTP/2 half-close behavior.
  State and logs remain under `~/.cache/yuhaiin-rust/integration/tun-chain-service`;
  run it with `make tun-chain-service-smoke`.
- `scripts/integration/transparent-service.sh` runs an isolated privileged
  Linux namespace with a host `iptables` helper, redirects a non-root TCP
  client into the Rust `redir` inbound, verifies `SO_ORIGINAL_DST`, direct
  outbound echo, flow counters, and shutdown, and probes the TPROXY socket
  capability. Host firewall state is not modified; rule changes are confined
  to the Podman network namespace and removed by a trap.
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
- `startup_logs.rs` starts the real runtime executable without
  `YUHAIIN_QUIET`, verifies that database/API/supervisor startup progress is
  visible on stderr, and then checks a clean SIGTERM shutdown. This protects
  the foreground behavior that makes a manually launched binary distinguishable
  from a hung process.
- `service_chain.rs` also creates a schema-v6 central basic user through the
  real API after the HTTP inbound is already running. It waits for the inbound
  owner to reload, proves invalid credentials are rejected, then sends an
  authenticated CONNECT through the same router and HTTP outbound fixture.
- `scripts/integration/api-contract.sh` runs the frontend management API
  process contract in Podman, including CRUD, reload, selection, connections,
  statistics, SSE, and representative error responses. It uses host networking
  so the subprocess and loopback fixtures share one namespace; build/runtime
  logs are kept under `~/.cache/yuhaiin-rust/integration/api-contract`.
- `scripts/integration/go-rust-stats.sh` starts Go and Rust in separate Podman
  network namespaces against one shared SQLite file. Both mixed inbounds write
  traffic while both management APIs read connections/statistics concurrently;
  build and process logs are kept under
  `~/.cache/yuhaiin-rust/integration/go-rust-stats`.
- `scripts/integration/production-parity.sh` discovers stopped SQLite snapshots
  in the sibling Go checkout (or uses `YUHAIIN_SOURCE_DB`), then runs the full
  Go/Rust management parity smoke for each one. Copies and logs live under
  `~/.cache/yuhaiin-rust/production-parity`.
- standalone Go HTTP/2 transport wire compatibility is covered separately in
  `crates/yuhaiin-chain/tests/standalone_http2.rs`: fixed endpoint resolution,
  plaintext prior-knowledge H2, `CONNECT http://localhost`, raw bidirectional
  bytes, pool ping/close, and the fail-closed raw final-proxy boundary. The
  final HTTP/SOCKS5 compositions are covered by the process tests above and
  intentionally remain TCP-only over a raw H2 parent.

## Opt-in throughput benchmark

`throughput.rs` is an integration benchmark, not a microbenchmark. It starts
the release runtime, configures the data plane through the API, sends a known
loopback payload, and samples the runtime's Linux `/proc` RSS and CPU ticks.
`scripts/benchmark/throughput.sh` runs both the short HTTP CONNECT path and the
full TLS → HTTP/2 → Yuubinsya path, printing one `BENCHMARK {...}` JSON line per
scenario. All build/runtime output is stored below `~/.cache`.

The current H2 relay deliberately uses h2's own flow-control queue after a
reservation-based adapter exposed a deadlock at partial window updates. The
relay submits fixed 16 KiB frames, but the producer-side queue is not yet a
strict memory bound; the 64 MiB TLS/H2/Yuubinsya baseline therefore records RSS
as a regression signal until a separately tested bounded adapter replaces it.

Run it with:

```bash
make benchmark-throughput
YUHAIIN_BENCH_BYTES=$((256 * 1024 * 1024)) make benchmark-throughput
```

The result is only comparable when the machine, profile, payload, network
namespace, and fixture are held constant. The benchmark matrix currently
covers HTTP inbound → route → HTTP CONNECT outbound and HTTP inbound → route →
TLS → HTTP/2 → Yuubinsya TCP-over-stream outbound. TUN currently has a privileged
Podman packet benchmark (`make benchmark-tun-throughput`) in addition to the
device/lifecycle smoke (`scripts/integration/tun-service.sh`). The TUN runner
uses one real `tun-rs + smoltcp + fixed proxy + loopback echo` stream and
defaults to a stable 4 MiB transfer; increase `YUHAIIN_TUN_BENCH_BYTES` only
when investigating long-stream behavior. WireGuard is intentionally not
implemented in the current scope, so no WireGuard performance number is
reported.

The 2026-08-10 Linux verification completed the lifecycle smoke and the
default 4 MiB benchmark. The Podman run created and removed `yrtun0`, relayed
the fixed-proxy loopback echo, and reported `55.769740794235275 MiB/s`,
`12440 KiB` peak RSS, and `12` CPU ticks. These numbers are a baseline for
this host, not a cross-machine performance promise.

Run the tests from the repository root:

```bash
cargo test -p yuhaiin-runtime --all-features --offline --test api_contract -- --nocapture
cargo test -p yuhaiin-runtime --all-features --offline --test service_chain -- --nocapture
scripts/integration/api-contract.sh
make service-chain-smoke
```

By default each test stores its SQLite state below
`~/.cache/yuhaiin-rust/integration/<scenario>/<pid>`. To retain a reusable
scenario directory for inspection or a Podman job, set an explicit cache path:

```bash
YUHAIIN_INTEGRATION_DIR="$HOME/.cache/yuhaiin-rust/integration-reusable" \
  cargo test -p yuhaiin-runtime --all-features --offline --test service_chain -- --nocapture
```

固定目录会保留日志和 fixture 文件，便于复盘；如果要从干净的 SQLite
配置开始，设置 `YUHAIIN_RESET_INTEGRATION_STATE=1`，或直接运行
`make service-chain-smoke`。reset gate 只删除该 service-chain fixture 的
`state.sqlite`、`-wal` 和 `-shm`，不会清理整个缓存目录。

The runtime-owned TUN process smoke uses the same cache convention:

```bash
scripts/integration/tun-service.sh

make tun-service-smoke

make transparent-service-smoke

make benchmark-tun-throughput
YUHAIIN_TUN_BENCH_BYTES=$((16 * 1024 * 1024)) make benchmark-tun-throughput
```

The fixtures only use loopback sockets. A container runner should use
`--network=host` when it needs the same loopback behavior and mount the chosen
cache directory under `~/.cache`; no test state is written to `/tmp`.
