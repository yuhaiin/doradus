# Runtime integration tests

`service_chain.rs` starts the real `yuhaiin` executable built by Cargo, changes
its SQLite-backed configuration through `/api/v2`, waits for the inbound
supervisor to reload, and then sends traffic through the configured listener.
It is process-level coverage rather than a unit test that calls the router
directly.

The current scenarios cover:

- HTTP inbound → domain route rule → fixed + HTTP CONNECT outbound, including
  live connection metadata, traffic counters, route testing, and node latency.
- HTTP inbound + mixed UDP inbound → TLS + HTTP/2 + Yuubinsya UDP-over-TCP
  outbound, including TCP echo, UDP echo, live connection metadata, and node
  latency through the same configured node.
- mixed inbound → SOCKS5 UDP framing → direct UDP, including the Go-compatible
  mixed UDP mode and a conflicting default `127.0.0.1:1080` listener.

Run the tests from the repository root:

```bash
cargo test -p yuhaiin-runtime --all-features --offline --test service_chain -- --nocapture
```

By default each test stores its SQLite state below
`~/.cache/yuhaiin-rust/integration/<scenario>/<pid>`. To retain a reusable
scenario directory for inspection or a Podman job, set an explicit cache path:

```bash
YUHAIIN_INTEGRATION_DIR="$HOME/.cache/yuhaiin-rust/integration-reusable" \
  cargo test -p yuhaiin-runtime --all-features --offline --test service_chain -- --nocapture
```

The fixtures only use loopback sockets. A container runner should use
`--network=host` when it needs the same loopback behavior and mount the chosen
cache directory under `~/.cache`; no test state is written to `/tmp`.
