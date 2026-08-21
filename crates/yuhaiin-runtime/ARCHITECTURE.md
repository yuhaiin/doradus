# Runtime crate boundaries

`yuhaiin-runtime` is the data-plane runtime used by the management/API host.
Its public facade remains `src/lib.rs`, but the implementation is grouped by
responsibility:

| Directory | Owns | Should not own |
| --- | --- | --- |
| `src/control` | `RuntimeController`, `RuntimeHandle`, reload coordination, monitor persistence | protocol parsing or socket accept loops |
| `src/plane` | DNS/TUN execution, inbound listener owners, outbound proxy selection and flow I/O | persisted configuration mutation |
| `src/plane/inbounds/adapters` | Runtime adapters that turn accepted SOCKS/Trojan/VLESS/Yuubinsya/reverse streams, HTTP forward capabilities and transparent listener owners into shared runtime flows | reusable wire framing/server codecs, protocol parsing, and route/snapshot construction |
| `src/plane/outbound_layers` | Runtime-only outbound contract wrappers such as HTTP termination | reusable protocol codecs |
| `src/policy` | resolver/route/settings compilation and runtime defaults | listener lifecycle or per-flow I/O |
| `src/support` | socket/interface helpers, latency probes, loopback detection and TLS helpers | snapshot publication |
| `src/maintenance` | runtime log/update support | selecting or relaying proxy flows |

The current step is deliberately a source-tree refactor. `lib.rs` uses
`#[path]` so existing crate-level module paths and re-exports remain stable
while the files move behind the responsibility boundaries. This lets future
changes introduce narrower internal APIs or separate crates based on measured
dependency edges instead of guessing at the split.

The Go correspondence is intentional: `pkg/net/proxy/*` contains reusable
wire/proxy implementations and their server sides, while `pkg/inbound/*`
and `pkg/register/point.go` adapt those implementations to listener and
chain/runtime policy. In Rust, `yuhaiin-protocol` is the former boundary;
`yuhaiin-runtime/src/plane/inbounds/adapters` is the latter. For example,
Trojan/VLESS/SOCKS5/Yuubinsya UDP servers and their wire messages live in
`yuhaiin-protocol`, while runtime keeps authentication configuration, route
selection, listener ownership, and TUN/UDP flow lifetime. HTTP server semantics
and Linux transparent socket handling are also protocol-side; runtime only
supplies the route/relay callbacks around them.

The protocol/runtime hand-off is expressed by runtime-neutral contracts in
`yuhaiin-types`:

- `InboundStreamHandler<S>` receives an authenticated SOCKS4A/Trojan/VLESS/
  Yuubinsya stream and its parsed destination;
- `InboundBasicAuth` lets protocol code validate central users without knowing
  the runtime's user store;
- `InboundUdpCodec` carries endpoint/payload identity for UDP sessions.

`yuhaiin_protocol::http_server` owns the HTTP server loop and asks runtime's
`HttpForwardHandler<S>` capability to open a routed outbound stream and record
flow bytes. CONNECT hand-off uses the shared `InboundStreamHandler<S>` contract;
the runtime does not write HTTP responses.
`yuhaiin_protocol::reverse_http` likewise owns sniffing, prefix restoration,
HTTP parsing and path/Host rewriting; runtime only routes, connects, wraps TLS,
relays and accounts bytes.
`yuhaiin_protocol::transparent` owns Linux TPROXY/REDIRECT socket options,
original-destination decoding and the transparent UDP codec; runtime only
connects these to `InboundHandler` and `InboundUdpSession`.

`yuhaiin-runtime::InboundUdpFlowPolicy` is intentionally separate because
`TunFlowKey` and close-request handling are runtime concerns. The same rule is
why route selection, monitor accounting, TLS wrapping and relay lifetime stay
in runtime even though protocol servers live in `yuhaiin-protocol`.

The pure flow data contracts (`FlowContext`, `RouteMode`, `ResolverPolicy` and
route match records) also live in `yuhaiin-types`; `yuhaiin-core` re-exports
them while retaining Tokio-based `AsyncProxy`, `AsyncDatagram`, stream and
NAT implementations.

The intended dependency direction is:

```text
policy + support  ->  runtime snapshot / control  ->  data plane
                                      \-> maintenance observers
```

In practice, some legacy crate-level references still cross these groups. New
code should depend on the narrowest public type or helper available and avoid
adding another direct dependency from policy/support into listeners or proxy
flow execution.
