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
  `.cache/yuhaiin-rust/integration/api-reload-flow`.
- `tun_api_process.rs` starts the real foreground binary, writes a user TUN
  inbound through `/api/v2/inbounds/{id}`, and observes the actual interface
  in `/proc/net/dev` while toggling disabled/enabled across reloads. It is
  ignored in the normal workspace run because it needs `/dev/net/tun` and
  `CAP_NET_ADMIN`; run `make tun-api-process-smoke` so the process and test
  execute in the disposable Podman namespace under `.cache`.
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
- `make tun-reload-smoke` runs the same fixture with
  `YUHAIIN_TUN_RELOAD=1`: it changes the persisted Go inbound `enabled` field,
  waits for the real device to disappear, enables it again, waits for the same
  device name to return, and repeats that disable/enable boundary (four cycles
  by default) before shutting down. Set
  `YUHAIIN_TUN_RELOAD_ONLY=1` (the Make target does this) to test lifecycle
  switching without requiring a working namespace route or proxy traffic. The
  script passes `/dev/net/tun` explicitly when the host exposes it, so a
  rootless Podman connection can still exercise the real device lifecycle and,
  when `--privileged` permits the device, the packet smoke as well. The
  separate transparent/TProxy path still requires a rootful namespace.
- `scripts/integration/tun-chain-service.sh` runs the same real kernel TUN
  inbound with a SQLite-selected `fixed -> TLS -> HTTP/2 -> Yuubinsya` TCP
  outbound and a loopback echo target. It deliberately half-closes the client
  immediately after writing, covering bidirectional HTTP/2 half-close behavior.
  State and logs remain under `.cache/yuhaiin-rust/integration/tun-chain-service`;
  run it with `make tun-chain-service-smoke`.
- `scripts/integration/transparent-service.sh` runs an isolated privileged
  Linux namespace with a host `iptables` helper, redirects a non-root TCP
  client into the Rust `redir` inbound, verifies `SO_ORIGINAL_DST`, direct
  outbound echo, flow counters, and shutdown, and probes the TPROXY socket
  capability. Rootless Podman records a deterministic TPROXY skip; explicitly
  setting `YUHAIIN_TPROXY_ENABLED=1` now fails fast with a clear rootful/
  `CAP_NET_ADMIN` requirement instead of entering a partial nested namespace.
  Host firewall state is not modified; rule changes are confined to the
  Podman network namespace and removed by a trap.
- `scripts/integration/dns-source-bind.sh` runs the existing UDP/TCP resolver
  source-address tests inside a host-network Podman container. It confirms
  that the configured local IPv4 address reaches the DNS server for both
  transports; build and Podman logs are kept under
  `.cache/yuhaiin-rust/integration/dns-source-bind`.
- `scripts/integration/doh-source-bind.sh` runs a real ring-backed DoH/HTTP2 and
  DoT/TLS resolver pair in a host-network Podman container. It asserts that
  both TLS transports reach their server from the configured local IPv4
  address; logs are kept under `.cache/yuhaiin-rust/integration/doh-source-bind`.
- `scripts/integration/socks5-udp-associate.sh` runs the real SOCKS5 control
  handshake, UDP ASSOCIATE, UDP echo, shared direct outbound and monitor
  assertion in a host-network Podman container. It keeps logs under
  `.cache/yuhaiin-rust/integration/socks5-udp-associate`.
- `scripts/integration/node-latency-dns.sh` saves a direct node through the
  API-layer fixture, invokes `node_latency` with a real UDP DNS server, and
  checks the selected proxy datagram path and DNS transaction in Podman. Logs
  are kept under `.cache/yuhaiin-rust/integration/node-latency-dns`.
- `stats_concurrency.rs` starts the real runtime process, keeps an HTTP inbound
  flow active while concurrent readers query connections, totals, traffic,
  telemetry, history, and failed-history, then restarts the same SQLite state
  and verifies persisted traffic/history remain readable. The reusable Podman
  entry point is `scripts/integration/stats-concurrency.sh`; logs are kept
  under `.cache/yuhaiin-rust/integration/stats-concurrency`.
- `startup_logs.rs` starts the real runtime executable without
  `YUHAIIN_QUIET`, verifies that database/API/supervisor startup progress is
  visible on stderr, and then checks a clean SIGTERM shutdown. This protects
  the foreground behavior that makes a manually launched binary distinguishable
  from a hung process.
- `make go-protocol-interop-smoke` compiles the ignored cross-language
  harnesses on the host and runs them in Podman: Go Yuubinsya, WebSocket→H2,
  H2 v1, VLESS, VMess, and Trojan. The Go checkout and all scratch state are
  mounted from `.cache/yuhaiin-rust`; the normal workspace test run does not
  start external Go processes.
- `make go-termination-parity-smoke` starts the Go and Rust services with the
  same semantic API configuration and sends raw TLS `reverse_http` traffic
  through both the `tls_termination → http_termination` chain and the
  standalone `tls_termination` chain to a reusable HTTP target. It checks the
  request path/Host, response body, live `connections` entry, and upstream
  `502` behavior in both services for 6/6 cases. The Go test moves its proxy rule before the built-in
  LAN rule; the Rust test uses the equivalent route priority. Build/runtime logs
  remain under
  `.cache/yuhaiin-rust/integration/go-termination-parity`.
- `make service-chain-smoke` includes a process-level 3-case protocol matrix:
  the API writes a Go-shaped fixed+VLESS/VMess/Trojan node, an HTTP inbound
  routes `example.test` through it, and the Podman test checks payload echo,
  connection metadata, match history, traffic totals, and the node latency
  probe through each protocol outbound.
- `service_chain.rs` also creates a schema-v6 central basic user through the
  real API after the HTTP inbound is already running. It waits for the inbound
  owner to reload, proves invalid credentials are rejected, then sends an
  authenticated CONNECT through the same router and HTTP outbound fixture. The
  same process then updates the credential and proves the old credential is
  rejected, deletes the user, and proves the inbound returns to its no-auth
  behavior after each reload.
- `scripts/integration/api-contract.sh` runs the frontend management API
  process contract in Podman, including CRUD, reload, selection, connections,
  statistics, SSE, and representative error responses. It uses host networking
  so the subprocess and loopback fixtures share one namespace; build/runtime
  logs are kept under `.cache/yuhaiin-rust/integration/api-contract`.
- `scripts/integration/go-rust-stats.sh` starts Go and Rust in separate Podman
  network namespaces against one shared SQLite file. Both mixed inbounds write
  traffic while both management APIs read connections/statistics concurrently;
  build and process logs are kept under
  `.cache/yuhaiin-rust/integration/go-rust-stats`.
- `scripts/integration/production-parity.sh` discovers stopped SQLite snapshots
  in the sibling Go checkout (or uses `YUHAIIN_SOURCE_DB`), then runs the full
  Go/Rust management parity smoke for each one. Copies and logs live under
  `.cache/yuhaiin-rust/production-parity`.
- `make maxmind-smoke` downloads the selected `Country-without-asn.mmdb` into
  `.cache/yuhaiin-rust/fixtures` with a pinned SHA-256, then runs the ignored
  real-database IPv4/IPv4-mapped-IPv6 query test in Podman.
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
scenario. All build/runtime output is stored below `.cache`.

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
namespace, and fixture are held constant. The benchmark matrix covers HTTP
inbound → route → HTTP CONNECT outbound, HTTP inbound → route → TLS → HTTP/2 →
Yuubinsya TCP-over-stream outbound, a real TUN packet path, and the Cloudflare
BoringTun userspace packet path. The TUN runner uses one real
`tun-rs + smoltcp + fixed proxy + loopback echo` stream. The WireGuard runner is
kept separate from the runtime relay benchmark and measures BoringTun packet
encryption/decryption without a public peer.

The latest Podman release run was completed on 2026-08-14 with a single 64 MiB
loopback payload. It recorded the following same-host regression baseline:

| Scenario | Throughput | Peak RSS | CPU ticks | Samples |
| --- | ---: | ---: | ---: | ---: |
| HTTP inbound → HTTP CONNECT | 152.08 MiB/s | 19,616 KiB | 35 | 21 |
| HTTP inbound → TLS/H2/Yuubinsya | 54.26 MiB/s | 21,804 KiB | 98 | 57 |
| TUN inbound → fixed → loopback | 47.82 MiB/s | 13,280 KiB | 241 | 35,591 |
| BoringTun userspace packet | 542.52 MiB/s | 3,732 KiB | 11 | 190 |

The raw `BENCHMARK {...}` lines are kept in
`.cache/yuhaiin-rust/benchmarks/{http-throughput,tun-throughput,wireguard}/podman.log`.
These figures are intended for regression tracking on the same host with the
same profile, payload, namespace, and fixture. They are not a cross-machine,
public-network, or WARP performance guarantee.

Run the tests from the repository root:

```bash
cargo test -p yuhaiin-runtime --all-features --offline --test api_contract -- --nocapture
cargo test -p yuhaiin-runtime --all-features --offline --test service_chain -- --nocapture
scripts/integration/api-contract.sh
make service-chain-smoke
```

By default each test stores its SQLite state below
`.cache/yuhaiin-rust/integration/<scenario>/<pid>`. To retain a reusable
scenario directory for inspection or a Podman job, set an explicit cache path:

```bash
YUHAIIN_INTEGRATION_DIR=".cache/yuhaiin-rust/integration-reusable" \
  cargo test -p yuhaiin-runtime --all-features --offline --test service_chain -- --nocapture
```

The fixed directory retains logs and fixture files for later inspection. To start
with a clean SQLite configuration, set `YUHAIIN_RESET_INTEGRATION_STATE=1`, or
run `make service-chain-smoke`. The reset gate removes only the `state.sqlite`,
`-wal`, and `-shm` files for that service-chain fixture; it does not clear the
entire cache directory.

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
cache directory under `.cache`; no test state is written to `/tmp`.
