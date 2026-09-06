# doradus Architecture and Change Guide

This developer-oriented map explains where to start reading, how requests move
through the system, and where a change belongs. It follows the current
workspace layout and the ownership boundaries in the source tree.

## 1. Runtime is an assembly layer

The workspace has four broad layers:

1. doradus-types contains public types and capability contracts that do not
   depend on Tokio, an operating system, or a concrete network implementation.
2. doradus-core, doradus-dns, doradus-trie, doradus-protocol, and doradus-chain
   contain reusable domain implementations.
3. doradus-store, doradus-tun, doradus-wireguard, and doradus-geo provide
   persistence, platform data planes, and external capability adapters.
4. doradus-runtime and doradus-api assemble configuration, routing, proxy
   selection, inbounds, TUN, DNS, and the management API into a running service.

Classify a problem before editing:

| Concern | Start here | Do not put it here |
| --- | --- | --- |
| Public traits, addresses, and DNS values | doradus-types | A second equivalent trait in runtime |
| DNS wire format, cache, UDP/TCP, DoH, or DoT | doradus-dns | DNS encoding in an API handler or inbound |
| Flow context, route mode, or resolver strategy | doradus-types; core keeps compatibility re-exports | Tokio socket/proxy traits in types |
| Async socket/proxy primitives and NAT | doradus-core | Runtime configuration in a protocol crate or a parallel blocking proxy API |
| Route rules and tries | doradus-trie plus runtime/src/policy/route.rs | Independent rule matching in every inbound |
| Nodes, chains, and protocol composition | doradus-chain plus doradus-protocol | Handshake assembly in an HTTP API handler |
| Configuration, migration, and Go compatibility | doradus-store | Direct SQLite writes in a handler |
| Runtime snapshots, reload, selectors, and owners | doradus-runtime | Live sockets or tasks held by store |
| REST/RPC, authentication, and service lifecycle | doradus-api | A protocol data plane depending on the API router |

## 2. Workspace overview

Workspace members are defined in Cargo.toml. The current workspace contains 15
crates:

~~~mermaid
graph TD
    TYPES[doradus-types<br/>Public types and contracts]
    DNS[doradus-dns<br/>DNS wire, cache, and transports]
    CORE[doradus-core<br/>Flow, proxy, NAT, and process]
    TRIE[doradus-trie<br/>Domain, CIDR, and route matching]
    PROTOCOL[doradus-protocol<br/>Protocol handshakes and sessions]
    CHAIN[doradus-chain<br/>Node chains and UDP/UOT]
    STORE[doradus-store<br/>SQLite, Go schema, and FakeIP]
    TUN[doradus-tun<br/>TUN packet/socket engine]
    GEO[doradus-geo<br/>GeoIP and Geo metadata]
    WG[doradus-wireguard<br/>WireGuard adapter]
    BACKUP[doradus-backup<br/>Backup model and transport]
    MASQUE[doradus-masque<br/>MASQUE transport]
    ANDROID[doradus-android<br/>Android JNI bridge]
    RUNTIME[doradus-runtime<br/>Snapshot, controller, and data plane]
    API[doradus-api<br/>HTTP API and service host]

    TYPES --> DNS
    TYPES --> CORE
    TYPES --> STORE
    DNS --> CORE
    CORE --> TRIE
    CORE --> PROTOCOL
    PROTOCOL --> CHAIN
    STORE --> DNS
    STORE --> CORE
    STORE --> TRIE
    RUNTIME --> TYPES
    RUNTIME --> DNS
    RUNTIME --> CORE
    RUNTIME --> TRIE
    RUNTIME --> PROTOCOL
    RUNTIME --> CHAIN
    RUNTIME --> STORE
    RUNTIME --> TUN
    RUNTIME --> GEO
    RUNTIME --> WG
    API --> RUNTIME
    API --> STORE
    API --> CORE
    API --> BACKUP
    MASQUE --> CORE
    MASQUE --> TUN
    ANDROID --> API
    ANDROID --> RUNTIME
    ANDROID --> TUN
~~~

### 2.1 Crate responsibilities and entry points

| Crate | Responsibility | Suggested reading order |
| --- | --- | --- |
| doradus-types | DomainName, Endpoint, Network, FlowContext, route policy, errors, future aliases, DNS/inbound contracts | lib.rs → dns.rs → net.rs → inbound.rs |
| doradus-dns | DNS model, wire codec, cache, hosts, FakeIP view, and UDP/TCP/QUIC/DoH/DoT transports | dns.rs/cache.rs → dns_resolver.rs → transport.rs |
| doradus-core | Async socket/proxy primitives, NAT, process information, sniffing, and compatibility re-exports | lib.rs → flow.rs → proxy.rs → nat.rs → process.rs |
| doradus-trie | Domain, CIDR, on-disk trie, and combined route indexes | router.rs → ondisk.rs → lib.rs |
| doradus-protocol | Async base proxy factory plus SOCKS, HTTP, VLESS, VMess, Trojan, Shadowsocks, H2, WebSocket, and Yuubinsya | proxy_factory.rs → session.rs/tls.rs |
| doradus-chain | Composition of nodes, transports, and protocols into outbound chains, including TLS/WebSocket/H2/UOT, retries, and UDP | config.rs → go_node.rs → lib.rs |
| doradus-store | Typed repositories, SQLite, schema, Go v6/legacy compatibility, FakeIP mapping, statistics, and state | lib.rs → sqlite.rs/schema.rs → repository.rs |
| doradus-tun | OS TUN descriptor, smoltcp packet/socket engine, dispatcher, proxy runtime, and packet write-back | runtime.rs → dispatcher.rs → packet.rs → proxy_runtime.rs → proxy_flow.rs/proxy_tasks.rs |
| doradus-geo | GeoIP/Geo metadata loading and lookup | lib.rs |
| doradus-wireguard | WireGuard engine, driver, and proxy adapter | config.rs → engine.rs → proxy.rs |
| doradus-backup | Backup data format and transport helpers | lib.rs |
| doradus-masque | MASQUE transport, codec, proxy, and TLS support | config.rs → proxy.rs → codec.rs |
| doradus-android | Android JNI bridge for API, runtime, and TUN integration | lib.rs |
| doradus-runtime | Runtime snapshot, controller, selector, resolver bridge, inbounds, and TUN/DNS supervisors | lib.rs → control/ → plane/ → policy/ |
| doradus-api | Service entry point, HTTP router, authentication, API handlers, and runtime lifecycle | bin/doradus.rs → service/runtime.rs → api.rs |

## 3. Where public contracts belong

Cross-crate contracts independent of a concrete runtime converge on
doradus-types. This is the Rust-side public boundary corresponding to the Go
netapi boundary. Not every trait should be moved there mechanically.

### 3.1 Current public contracts

| Contract | Location | Why it belongs in types |
| --- | --- | --- |
| BoxFuture, LocalBoxFuture | types/src/lib.rs | Describes future sendability without binding to Tokio |
| DomainName, Error, Result, IpSet | types/src/lib.rs | Needed by DNS, proxy, route, and store code |
| Network, Endpoint | types/src/net.rs | Shared address and network vocabulary |
| DnsHandler, AsyncDnsHandler, AsyncIpResolver | types/src/dns.rs | DNS consumers should not depend on a concrete transport |
| DnsRecordType, DnsResponse, SVCB/HTTPS models | types/src/dns.rs | Keeps DNS data beyond IP addresses available |
| InboundDnsHandler, InboundBasicAuth | types/src/inbound.rs | Socket inbounds and TUN can intercept DNS without exposing user storage |
| InboundStreamHandler, HttpForwardHandler, InboundUdpCodec | types/src/inbound.rs | Protocol servers parse wire data; runtime supplies routing and relay |

doradus-types contains lib.rs, dns.rs, net.rs, and inbound.rs; it does not
contain a proxy module. AsyncProxy, AsyncDatagram, and AsyncStream remain in
doradus-core::proxy because they carry FlowContext, Tokio I/O streams, and async
resource lifetimes. Moving them into types would expose runtime-specific
contracts from the lowest-level public crate.

Use the canonical paths in new code:

~~~rust
use doradus_types::{AsyncDnsHandler, AsyncIpResolver, Endpoint, InboundDnsHandler};
use doradus_core::proxy::{AsyncDatagram, AsyncProxy, AsyncStream};
~~~

The old StreamConnector, BlockingStreamProxy, synchronous HTTP/SOCKS
connectors, and doradus-protocol/src/tls_sync.rs were deliberately removed.
The project does not maintain a blocking proxy API for theoretical runtime
neutrality. Inject async proxy implementations at a test or OS boundary when
replacement is needed.

### 3.2 Contracts that should not move downward

- AsyncProxy and AsyncDatagram need Tokio streams, cancellation, and async proxy
  lifetimes, so they belong to the doradus-core async capability layer.
- RuntimeProxySelector and ProxyBuild depend on RuntimeSnapshot, store
  configuration, node tags, and reload slots, so they belong to runtime.
- Runtime inbound adapters need InboundSpec, monitoring, DNS policy, and UDP
  sessions/workers. Protocol servers hand off through the types ports.
- ResolverTransportFactory and ResolverProxyBridge know resolver endpoints,
  selectors, NAT/UDP transport, and failure records, so they are runtime
  resolver adapters.
- FlowObserver is tied to FlowKey lifecycle and statistics semantics. It remains
  in doradus-core::flow and is implemented by the runtime monitor.

If a trait signature contains only Endpoint, DomainName, IpSet, byte slices, and
public errors, consider doradus-types. If it contains RuntimeSnapshot, Tokio
streams, store, monitor, selector, platform descriptors, or route reloads, keep
it in the corresponding implementation layer.

## 4. Feature flags: compilation is not feature completeness

The default doradus-runtime features are:

~~~text
tun, tun-routes, doh-tls, websocket, http-termination
~~~

~~~mermaid
graph LR
    API[API defaults] --> HTTPAPI[http-api]
    HTTPAPI --> UPDATE[update]
    API --> TUN[tun]
    TUN --> RUNTIME_TUN[runtime/tun]
    RUNTIME_TUN --> TUNCRATE[doradus-tun async runtime]
    ROUTES[tun-routes] --> TUN
    ROUTES --> TUNROUTES[doradus-tun/tun-routes]
    TUNROUTES --> LINUX[Linux route installation]
    DOH[doh-tls] --> H2[http2]
    DOH --> DNS_TLS[DNS TLS and QUIC]
    DOH --> RUSTLS[Ring-backed TLS support]
    WS[websocket] --> WS_PROTO[protocol/websocket]
    TERM[http-termination] --> DOH
    TERM --> HYPER[Hyper HTTP termination]
~~~

doradus-api defaults to http-api, tun, tun-routes, doh-tls, websocket, and
http-termination. doradus-runtime does not include the management API by
default, but includes the same data-plane capabilities apart from http-api.
tun is a compatibility/assembly feature; the async doradus-tun implementation
always compiles, while tun-routes additionally enables the route manager.

The old async-proxy, async-dns, and synchronous TLS features were removed from
the workspace feature graph. When changing feature-gated code, verify default
features, no-default-features, the distinction between tun and tun-routes, and
whether an async boundary needs BoxFuture or LocalBoxFuture. Only a handler
that crosses threads needs Send.

## 5. Startup: from main to the supervisors

### 5.1 Entry-point call chain

~~~mermaid
sequenceDiagram
    participant P as doradus binary
    participant S as RuntimeService
    participant DB as ConfigStore
    participant C as RuntimeController
    participant I as inbound supervisor
    participant D as DNS supervisor
    participant A as HTTP API
    participant R as route-list refresh

    P->>P: main()
    P->>P: main_result()
    P->>S: RuntimeService::start(ServiceOptions)
    S->>DB: ConfigStore::open(database)
    S->>C: build_controller(store)
    S->>S: bind API listener
    S->>I: spawn run_until_with_selector_ready()
    S->>D: wait for selector_ready_rx
    S->>A: spawn serve_until(listener, state, shutdown)
    S->>R: spawn run_route_list_refresh_loop()
    I-->>D: selector ready
    D->>D: run_dns_supervisor()
    P-->>S: shutdown signal
    S->>D: abort/await DNS task
    S->>I: abort/await inbound task
    S->>R: await refresh task
    S->>DB: persist_monitor()
~~~

Important locations:

- main presents process-level errors.
- main_result parses arguments, default paths, and service options.
- RuntimeService::start is the assembly root: it opens the store, builds the
  controller, binds the API, and starts API/inbound/DNS/route-refresh work.
- build_controller assembles ConfigStore and resolver/proxy factories into the
  RuntimeController.
- service/lifecycle.rs handles shutdown, child-task waiting, and fallback abort
  on drop.

### 5.2 Why selector readiness precedes DNS

A DNS resolver may use the proxy selector for outbound traffic. Startup must
build and publish the selector in the inbound supervisor before starting
run_dns_supervisor; otherwise a proxy resolver may bind before its selector
exists or recursively construct itself. The oneshot channel in
RuntimeService::start is a readiness signal, not merely a task-spawn signal.

## 6. Runtime snapshots, controller, and reload

### 6.1 Responsibilities of the three objects

| Object | Responsibility |
| --- | --- |
| RuntimeSnapshot | Immutable view of one complete configuration load: settings, resolver registries, hosts/FakeIP, routes, Geo data, proxy configuration, and NAT policy |
| RuntimeBuilder | Builds a snapshot from the store and an injected upstream resolver; it never publishes a partial snapshot |
| RuntimeController | Owns the store, RuntimeHandle, monitor, reload channels, and live selector; serializes rebuilds and owner lifetimes |

An old flow may keep its old snapshot while new flows see the new snapshot
after a successful build. Reload must not mutate a shared set of mutable
objects in place.

~~~mermaid
flowchart LR
    STORE[(ConfigStore)] --> BUILDER[RuntimeBuilder::build]
    BUILDER --> SNAP[RuntimeSnapshot<br/>immutable]
    SNAP --> HANDLE[RuntimeHandle::replace]
    HANDLE --> NEW[new flow or listener]
    OLD[old flow] -.keeps old Arc.-> SNAP_OLD[old snapshot]
    CTRL[RuntimeController] --> HANDLE
    CTRL --> OWNER[Inbound, DNS, and TUN owners]
    EVENT[API mutation] --> CTRL
    CTRL --> RELOAD[InboundReload All, One, or DNS]
~~~

Runtime assembly is split by responsibility rather than kept in one startup
file:

- assembly_config_loader.rs reads store-backed runtime inputs, system hosts,
  FakeIP compatibility settings, and other startup-only configuration.
- assembly.rs is the orchestration layer: it builds resolver registries,
  FakeIP/router state, and the final snapshot without owning persistence
  parsing details.
- assembly_snapshot.rs owns RuntimeSnapshot and the immutable helpers used by
  route, resolver, and NAT selection.

The RuntimeBuilder helpers set runtime-only options, inject resolver factories
or bridges, load hosts/FakeIP, build resolvers/routes/proxies, and form one
complete snapshot. RuntimeController::reload rebuilds and publishes everything;
mutate_and_reload writes and rebuilds under one control lock;
mutate_and_reload_inbound reloads one inbound; mutate_and_reload_dns notifies
only the DNS supervisor; rebuild_locked_with_events publishes the handle and
sends events under the reload lock.

RuntimeProxySelector also publishes one coherent selector generation at a
time. It stores an `ArcSwap<SelectorState>` containing the current TCP/UDP
routed selectors, tagged proxies, closed/retargeted node sets, metadata, and
runtime settings. Reload constructs the complete SelectorState and swaps one
Arc. A single route_context or select operation therefore never observes a
mixture of old tags with new metadata or old UDP state with new TCP state.

The selector implementation is physically separated into:

- selector.rs for SelectorState, reload, close/retarget, and proxy ownership.
- selector_routing.rs for FakeIP restoration, hosts override, route_context,
  and final proxy selection.
- selector_metadata.rs for node/tag/endpoint observability metadata.

The trait boundary still permits a reload between a caller's route_context
and later select call. True per-flow generation pinning would require changing
FlowContext or the selector trait; do not fake that guarantee in one adapter.

### 6.2 Reload boundaries

| Configuration change | Must trigger | Must not trigger incidentally |
| --- | --- | --- |
| One inbound listen address, protocol, or auth | InboundReload::One(id) and replacement of that owner | Other inbounds, FakeIP, or global hosts |
| Global inbound settings | InboundReload::All | A full stop for an ordinary route-list refresh |
| DNS listener address or transport | DNS reload and UDP/TCP rebind | Rebinding every inbound |
| Hosts, FakeIP, route list, or route rule | New snapshot; new flows use new selector metadata | Deleting old flows just because hosts changed |
| Node selection or selector slot | Update the selector live slot | Treating an unrelated DNS listener as a node owner |
| TUN device name, descriptor, address, or system route | Rebuild the TUN owner | Pretending a device reload is only a selector change |

The central maintenance rule is: the resource owner controls its resources and
restart, the snapshot owns immutable data, and the controller coordinates both.

## 7. Complete TCP socket flow

### 7.1 From listener to protocol parsing

~~~mermaid
sequenceDiagram
    participant L as TcpListener
    participant O as start_inbounds
    participant S as serve_listener_with_protocol_plan
    participant H as ProtocolHandler
    participant P as protocol server
    participant IH as runtime handler port
    participant X as RuntimeProxySelector
    participant C as chain or protocol proxy
    participant T as target

    O->>L: bind one listener per Go inbound record
    O->>S: serve_listener_with_protocol_plan(listener, spec, kind, plan, selector, monitor, tls)
    S->>L: accept()
    S->>S: prepare_inbound_stream()
    S->>H: serve_connection(stream, peer, handler)
    H->>H: ProtocolHandler::handle()
    H->>P: protocol server handle()
    P->>P: parse destination, auth, and headers
    P->>IH: InboundStreamHandler or HttpForwardHandler hand-off
    IH->>IH: create FlowContext
    IH->>X: select/connect(context)
    X->>C: selected proxy connect(context)
    C->>T: protocol handshake and TCP connect
    IH->>IH: relay_counted_with_*()
    IH-->>P: relay/close
~~~

The path is run_until or run_until_with_selector_ready, then run_until_inner
and start_inbounds, serve_listener_with_protocol_plan, serve_connection,
ProtocolHandler::handle, and finally the protocol handler port. Runtime creates
FlowContext, stream or datagram state, and selector operations after protocol
parsing. Test-only listener wrappers may compile a plan for compact fixtures;
production startup passes the plan compiled by InboundPlan.

### 7.2 FlowContext is the cross-layer connection envelope

| Field | Filled by | Consumed by |
| --- | --- | --- |
| source, local_addr | Listener or TUN tuple | Loopback detection, statistics, and policy |
| original_domain | Protocol input or FakeIP reverse lookup | SNI, remote-domain framing, and routing |
| resolved_destination | Resolver or direct connect | Final socket |

Do not create another ConnectionContext in a protocol crate. Extend FlowContext
when metadata is needed by inbound, TUN, DNS, and proxy layers; keep temporary
wire-protocol parsing state in the protocol/session structure.

### 7.3 Route-to-outbound decision

RuntimeSnapshot::apply_route fills route-list membership with
RouteListSnapshot::matching_names, calls RouterRuntime::apply_to_context, and
writes the resolver ID back to the context. RouteRule::matches_with_context
then evaluates disabled/exclusion patterns, domain/list membership,
source/destination networks, ports, process metadata, and remaining predicates.
Update the route model and serialization before adding a context-sensitive
condition; do not decide the proxy early in one InboundHandler.

## 8. UDP inbound: sessions dispatch; workers perform network I/O

This is one of the easiest lifecycle designs to break.

### 8.1 Object relationships

~~~mermaid
flowchart LR
    CODEC[InboundUdpCodec<br/>wire framing only]
    SESSION[Inbound UDP session<br/>read request and write response]
    MANAGER[InboundUdpManager<br/>source to worker map]
    WORKER[UdpFlowWorker<br/>one source-owned flow]
    PROXY[AsyncDatagram<br/>route and network I/O]
    CODEC --> SESSION --> MANAGER
    MANAGER --> WORKER --> PROXY
~~~

InboundUdpRequest and InboundUdpResponse bridge codec and session.
InboundUdpCodec defines recv and send without DNS, route, proxy, or network
I/O. InboundUdpFlowPolicy is a runtime-only close/flow hook. Transparent Linux
socket setup, SO_ORIGINAL_DST, ancillary destination data, and transparent UDP
framing remain in doradus-protocol.

UdpSourceKey is inbound_id + session_id + source + authentication; it
intentionally excludes target so one full-cone source can use many destinations.
InboundUdpManager::dispatch uses a bounded data queue. UdpFlowWorker owns
AsyncDatagram, flow observation, idle timing, reply metadata, and every
potentially blocking DNS/route/open/send/receive operation.

### 8.2 Queue and close semantics

- A full packet-data queue may drop packets: UdpDispatchResult::Dropped is
  intentional data-plane backpressure.
- Manager commands, manager flow events, and per-session FlowOpened events use
  bounded Tokio channels. Lifecycle commands/events use async send and must not
  be silently discarded when the queue is full.
- pending_close handles close arriving before a worker finishes opening.
- generation prevents an old Closed event from deleting a replacement.
- Sessions and managers must not await worker network I/O.
- Idle cleanup closes the datagram and releases FlowObserverGuard.

There are no unbounded channels in the normal inbound UDP module. Do not
replace bounded lifecycle sends with try_send merely to make a path look more
"non-blocking"; losing a close event just moves cleanup into an idle timeout.

When changing UDP, choose one clear boundary among codec, manager, and worker,
then test full queues, close-before-open, replacement, multiple targets, idle
timeout, and DNS interception.

## 9. TUN data plane

### 9.1 TUN runtime path

~~~mermaid
flowchart LR
    OS[OS TUN device] --> R[TunRuntime]
    R --> D[TunDispatcher::poll]
    D --> S[smoltcp socket state]
    S --> I[ProxyInput]
    I --> P[TunProxyRuntime]
    P --> X[RuntimeProxySelector]
    X --> O[AsyncProxy]
    O --> P
    P --> D
    D --> R
    R --> OS
~~~

TunRuntime owns the platform device, smoltcp device, read/write queues, and
optional route setup. TunDispatcher handles IP version, TCP/UDP tuples, ICMP,
fragmentation/extension headers, and packet write-back.
run_tun_device_until_ref is the runtime supervisor; it chooses proxy IDs,
builds TunProxyRuntime, creates the interceptor/dispatcher, and waits for
shutdown or matching inbound reload. The runtime helper
build_tun_proxy_runtime_with_dns_and_udp connects TUN, DNS interception,
UDP/full-cone NAT, and selector behavior.

TunProxyRuntime is now primarily an orchestrator. FlowTracker owns tracked-flow
lifetime, NAT bindings, process metadata cache/refcounts, and flow cleanup.
Transport task ownership is split across three managers:

- TcpTaskManager owns TCP task spawn/register/send/abort/shutdown and pending
  TUN output state.
- UdpTaskManager owns source-scoped UDP task creation, flow-to-source binding,
  task removal, shutdown, and full-cone source sharing.
- IcmpTaskManager owns ICMP task IDs, spawn, flow lookup, and abort.

ProxyTaskRuntime carries the shared task-launch environment (output sender,
channel capacity, timeouts, observer, and UDP buffer size). TunProxyRuntime
prepares FlowContext, applies routing, selects a proxy, and asks the owning
manager to spawn or reuse a task; it should not grow another parallel task map.

Payload allocation was benchmarked before introducing a buffer pool. Reusing a
1500-byte UDP Vec improved the isolated copy/allocation micro-benchmark by about
1.24x, while 16 KiB TCP was about 1.02x. That is not sufficient evidence for a
cross-queue buffer pool or project-wide Bytes conversion. Keep the current
owned Vec boundary unless profiling a real workload shows allocation as a
material bottleneck.

### 9.2 TUN and socket inbounds share policy

Both create FlowContext, use the same snapshot and selector, may use
InboundDnsHandler for DNS packets, and record connections and bytes through
FlowObserver and the monitor. A socket inbound reads/writes a client stream;
TUN turns IP packets into proxy input and encodes results back into device
packets.

## 10. DNS: from public contract to transport

### 10.1 Layers

~~~mermaid
flowchart TD
    CONTRACT[doradus-types DNS model and handlers]
    CODEC[doradus-dns wire codec]
    POLICY[Runtime resolver policy]
    TRANSPORT[UDP, TCP, QUIC, DoH, DoT]
    CACHE[Cache, hosts, and FakeIP]
    CONTRACT --> CODEC
    CONTRACT --> POLICY
    POLICY --> CACHE
    POLICY --> TRANSPORT
    CODEC --> TRANSPORT
~~~

Keep DNS models and handler contracts independent from concrete transport.
Resolver policy chooses a transport; the wire codec validates and decodes
packets; cache, hosts, and FakeIP policy remain separate from upstream choice.

### 10.2 Two DNS use cases

1. Address resolution: proxies and TUN call AsyncIpResolver::resolve when they
   need an IpSet.
2. Complete DNS packets: listeners, interception, or callers that need
   PTR/HTTPS/SVCB records call query_packet or AsyncDnsHandler::answer. They
   must not reduce every answer to IP addresses.

The default AsyncIpResolver::query maps A/AAAA answers to ResolveStrategy and
returns the minimum TTL. A transport may preserve ptr_names, service bindings,
and the authoritative TTL.

Dual-stack async address resolution sends A and AAAA queries concurrently for
Default, PreferIpv4, and PreferIpv6. AsyncDnsResolver does this in both Local
and Send paths, and the direct AsyncUdpDnsClient/AsyncTcpDnsClient convenience
resolve APIs follow the same behavior. Preference controls result/error
ordering; it does not serialize the two network round trips. OnlyIpv4 and
OnlyIpv6 still issue one query.

### 10.3 RoutedDnsClient query flow

1. query/query_packet applies TimeoutResolver.
2. encode_query creates a standard wire packet and validate_query_packet checks
   the input.
3. Resolver kind selects UDP, TCP, DoH, DoT, or QUIC.
4. Proxy mode uses ResolverProxyBridge through the selector; direct mode uses
   the direct open/connect path.
5. validate_response_packet and response_is_truncated check the response;
   truncated UDP may be retried over TCP.
6. decode_response produces DnsResponse, after which cache/FakeIP/hosts policy
   determines the final answer.

DNS-over-QUIC uses bounded send and receive queues. QuinnDatagram::try_send maps
a full outbound queue to WouldBlock, and its custom AsyncUdpSocket poller only
reports writable after capacity actually returns. The sender worker wakes the
poller when it consumes a queue slot; the receiver awaits bounded delivery
instead of growing an unbounded packet backlog. Keep the post-waker capacity
recheck in the poller: it closes the otherwise easy lost-wakeup race between
checking a full queue and registering the task waker.

Do not read API or SQLite directly from RoutedDnsClient. RuntimeBuilder loads
typed configuration from the store; the client consumes constructed endpoints,
factories, and bridges.

### 10.4 DNS listener supervisor

run_dns_supervisor reads the configured address, gets the current snapshot and
handler, independently attempts UDP and TCP binds, waits for DNS reload or
shutdown, and rebinds only DNS listeners after reload. This is the server-side
DNS entry point; resolver transports are the client-side upstream path.

### 10.5 FakeIP, hosts, and inbound DNS policy

- hosts maps names to fixed addresses or targets through a separate HostsTable.
- Global FakeIP and inbound-interception FakeIP may use separate pools.
- FlowContext::original_domain preserves the domain after FakeIP reverse lookup;
  fake_ip records the synthetic address visible to the application.
- InboundDnsHandler decides whether to intercept and what packet to return; it
  does not choose every ordinary resolver transport.

## 11. Proxy plans, protocol, and chain relationships

### 11.1 Three layers

- doradus-core provides async socket connect, stream/datagram primitives, and
  FlowContext; it no longer provides synchronous connectors.
- doradus-protocol performs protocol handshakes over acquired capabilities:
  SOCKS5, VLESS, VMess, Trojan, Shadowsocks, H2, WebSocket, and Yuubinsya.
- BaseProxyConfig::build creates Direct, Reject, Drop, Fixed, HTTP, SOCKS5, and
  Yuubinsya UDP capabilities. HTTP CONNECT is an async HttpProxy around
  FixedAsyncProxy.
- RustCryptoTlsProxy wraps an existing AsyncProxy for async TLS and ALPN.
- doradus-chain combines nodes, TLS, WebSocket, H2, UOT, and UDP stages.
  ChainClient owns connection/cache/retry behavior; ChainProxy and ChainDatagram
  expose the capability to runtime.
- runtime/src/plane/proxy_plan.rs is the typed compatibility boundary between
  persisted Go-shaped configuration and protocol construction. It validates
  and normalizes standard protocols, HTTP/TLS/H2/WebSocket/AEAD/Yuubinsya,
  SOCKS5, WireGuard/WARP, and related transport plans before a proxy is built.
- runtime/src/plane/outbound.rs consumes typed plans and registers the resulting
  objects with RuntimeProxySelector. It should not become another raw JSON
  protocol parser.
- runtime/src/plane/protocol_factory.rs builds protocol capabilities from typed
  plans. Protocol implementations do not read ConfigStore or Go records.

The direction is:

~~~text
Go node/proxy config
  -> proxy_plan compile/validation
  -> protocol_factory / BaseProxyConfig::build or ChainClient
  -> TLS, HTTP, and protocol-session wrappers
  -> runtime relay or TUN proxy task
~~~

StandardProxyPlan uses a typed StandardProtocol enum for Shadowsocks,
ShadowsocksR, Trojan, VLESS, and VMess. Required passwords/UUIDs/methods and
legacy defaults are validated once during plan compilation instead of being
re-read from serde_json::Value inside the protocol builder. The same rule
applies to inbound startup: compile compatibility-shaped configuration once,
then pass a typed plan through the runtime.

InboundPlan owns InboundProtocolKind, InboundProtocolPlan,
InboundTransportPlan, InboundSpec compatibility data, and the TLS acceptor.
After central auth is applied, prepare_runtime refreshes the typed protocol
plan once. Production listener paths then pass the already compiled kind/plan
through ListenerStartContext into stream/UDP/transparent listeners,
ProtocolHandler, InboundHandler, and Trojan/Yuubinsya adapters. Production
code must not recompile a protocol plan from spec.password or spec.protocol.
Small #[cfg(test)] wrappers may compile plans for concise fixtures.

AsyncProxy is a core runtime-facing capability. It should not move to
doradus-types merely because it is a trait; only runtime-independent DNS,
inbound policy, endpoint, and network models belong there.

### 11.2 Adding an outbound protocol

Add persisted compatibility parsing/validation to runtime/plane/proxy_plan.rs,
add typed factory dispatch in protocol_factory.rs (or the appropriate reusable
protocol constructor), implement handshake/session without reading store or
controller, reuse chain stages for H2/WebSocket/TLS/UOT transports, complete
Go-node conversion, and add plan, protocol, chain, selector, and workspace
tests.

Avoid direct ConfigStore dependencies in protocol crates, wire framing inside
the runtime selector, a stream-only trait shared by UDP and TCP, or a global
mutable singleton for node selection.

### 11.3 Direct, bypass, proxy, and block

Routing selects a proxy capability rather than making the protocol crate decide
policy. Direct uses the direct connector, bypass/direct modes avoid the selected
proxy, proxy mode uses the selected chain, and reject/drop produce an intentional
terminal result. Keep these decisions in route policy and selector code.

## 12. Store, schema, and Go compatibility

### 12.1 Store boundary

doradus-store owns SQLite setup, schema validation, migration, Go-compatible
records, typed repositories, FakeIP persistence, and runtime statistics
persistence. It must not own live sockets, supervisors, or handshakes.

The main ConfigStore CRUD core is synchronous because rusqlite work is
synchronous. open_sync/open_memory_sync/get_config_sync/list_config_sync,
put_config_sync/delete_config_sync/apply_sync and related primitives are the
real storage boundary; async compatibility methods are thin wrappers. Runtime
startup or mutation paths that might block a Tokio worker use spawn_blocking or
the runtime run_blocking_store helper. Do not add fake async to new SQLite
helpers merely to match an old call-site spelling.

Store source files are also separated by physical responsibility: lib.rs is
the facade and core CRUD/transaction boundary, snapshot.rs owns database
staging/sidecar/manifest/restore file operations, and row.rs owns SQLite row
decoding and typed validation. Keep new restore-file helpers out of lib.rs and
new row extraction helpers out of repositories.

### 12.2 Startup loading and migration

Native startup opens a Doradus database, validates or repairs its schema, loads
records, and constructs a snapshot through RuntimeBuilder. A database with the
legacy metadata/migration tables is reserved for an explicit future migration
workflow; normal startup does not import it. The controller publishes only a
complete snapshot. Native checkpoints support abnormal-exit recovery; final
Go-compatible projections are written during normal shutdown. Startup smoke
alone is not proof of production migration compatibility.

### 12.3 Safe order for a configuration field change

1. Confirm the Go record and JSON shape.
2. Update schema and typed repository conversion.
3. Add empty, legacy, and round-trip fixtures.
4. Load the field into RuntimeSnapshot.
5. Apply it at the correct selector, resolver, inbound, or TUN owner.
6. Expose it through the API value handler and reload boundary.
7. Test fresh state, old state, round trips, reload, and restart.

## 13. API and control plane

### 13.1 API composition

The API owns Axum routing/authentication/static assets/SSE, normalization of
operation/path/body data, and typed repository writes followed by the correct
controller reload.

~~~mermaid
sequenceDiagram
    participant C as HTTP client
    participant R as router()
    participant A as authenticate
    participant X as RPC dispatcher
    participant V as value handler
    participant S as ConfigStore
    participant RC as RuntimeController

    C->>R: HTTP request
    R->>A: authentication middleware
    A->>X: RPC route
    X->>V: normalized operation, path, and body
    V->>S: typed repository read/write
    V->>RC: mutate_and_reload* on write
    RC-->>V: snapshot/reload result
    V-->>C: JSON or SSE response
~~~

api.rs uses outer handlers such as nodes_get and node_put to adapt extractors,
and inner handlers such as get_node_value and save_node_value to implement the
shared JSON contract. Find the value handler before editing an /api/v2 route.

API writes follow this shape:

~~~text
inbound_put
  -> parse body and normalize public fields
  -> save_inbound_value
  -> repository.put/delete_go_inbound
  -> controller.mutate_and_reload_inbound(id, operation)
  -> RuntimeBuilder::build
  -> RuntimeHandle::publish
  -> InboundReload::One(id)
  -> owner stop/restart
  -> JSON response
~~~

Route-list activation may first write activation state, then let a refresh loop
download and compile the list before route snapshot reload. Node selection mainly
updates selected metadata and the selector slot.

### 13.2 Inbound runtime status, events, and statistics

`enabled` is persisted configuration, not proof that a listener is alive. The
runtime keeps the actual owner state in memory (`disabled`, `starting`,
`running`, `degraded`, `failed`, or `stopping`) and publishes it through
`GET /api/v2/inbounds/status`. A bind or owner failure affects only that inbound;
the state remains `failed` with `lastError` until the UI calls
`POST /api/v2/inbounds/{id}/retry`.

Lifecycle observations are append-only rows in `inbound_runtime_events` and are
read through `GET /api/v2/inbounds/{id}/events`. Rows are retained for 30 days
and capped at the newest 1000 rows per inbound. Aggregate TCP/UDP flow counts
and upload/download bytes are kept hot in the monitor, periodically checkpointed
to `inbound_statistics`, and restored on restart; active flow counts are reset
to zero because active sockets are not persisted.

ConnectionMonitor no longer uses API JSON as its runtime data model.
ConnectionRecord stores the typed fields read by lifecycle/statistics logic
(route mode, protocol, host, process, node, inbound id, and TUN marker) while a
serde_json::Value projection is retained for API/SSE compatibility. Runtime
code should read the typed fields; only projection code should depend on JSON
field names.

Monitor implementation is split by responsibility:

- monitor_runtime.rs: construction and shared runtime glue.
- monitor_lifecycle.rs: open/close/failure/close-request lifetime.
- monitor_traffic.rs: byte counters, traffic shards, inbound statistics.
- monitor_projection_runtime.rs: connections/traffic/telemetry/history views.
- monitor_runtime_persistence.rs: durable snapshots, deltas, and restore.
- monitor_dns.rs plus monitor_projection.rs/monitor_persistence.rs/
  monitor_statistics.rs: DNS and supporting projection/persistence helpers.

Hot traffic accounting is sharded; control/lifecycle state is not held under
the traffic lock. Do not collapse those locks back into one convenient Mutex.

The API embeds the Vite output under `crates/doradus-api/web` at compile time.
The repository keeps that directory as an empty `.gitkeep` placeholder; the
GitHub Actions release workflow checks out `yuhaiin-react`, builds it once, and
copies `dist` into the directory before compiling each platform binary. A
local build without generated frontend assets returns 404 for the embedded
fallback. When assets are present and no external web root is configured, the
embedded handler serves them and falls back to `index.html` for React routes.
`with_external_web` remains an explicit override for development and
integration tests.

## 14. Supporting components

### 14.1 doradus-geo

GeoDb opens MaxMind data and implements GeoLookup. The database manager publishes
metadata and Arc<GeoDb> as one GeoSnapshot; refresh downloads temporary content,
validates it, and replaces the snapshot. Route matching should not open files.

### 14.2 doradus-wireguard

~~~text
WireGuardConfig::from_json_or_ini / from_wireguard_ini
  -> WireGuardEngine::from_config
  -> WireGuardProxy::connect/open_datagram
~~~

Parsing belongs in config.rs, the engine in engine.rs, and the runtime adapter in
proxy.rs. Crypto and driver state should remain in the final adapter.

### 14.3 doradus-backup

S3Client depends on S3Transport; put and get implement signed object requests.
API backup/restore handlers pass encoded database or snapshot data to the client.
Restoration must return through ConfigStore::restore_database, migration, and
controller rebuild before data becomes live.

## 15. Common change tasks

### 15.1 Add a public DNS, inbound, or network trait

Put runtime-independent values and contracts in doradus-types, preserve
compatibility re-exports, and test at least two implementations. Keep Tokio
streams, sockets, store, monitor, selector, and platform descriptors out of the
low-level public contract.

### 15.2 Add an inbound protocol

Implement framing and handshake in doradus-protocol, hand parsed data to the
existing ports, and add a runtime adapter only for routing, monitoring,
lifecycle, and protocol preparation. Test startup, authentication, TCP relay,
UDP if applicable, reload, and shutdown.

### 15.3 Change a route condition

Update the route model and serialization, then the trie/index,
RouteRule::matches_with_context, and runtime route application. Test matching,
exclusion, list membership, and flow context.

### 15.4 Change a DNS transport

Keep packet encoding/validation in doradus-dns, transport selection in resolver
policy, and connection setup in the resolver bridge. Test timeouts, truncation
fallback, source binding, cache behavior, and complete record preservation.

### 15.5 Change TUN behavior

Start with packet inspection and dispatcher tests, then follow proxy
input/output. Keep synchronous smoltcp polling separate from async workers, and
verify device lifecycle, DNS interception, UDP ownership, route installation,
and reload on the target platform.

### 15.6 Change persistence or migration

Compare with the Go schema, update repository and migration fixtures, and verify
fresh, legacy, invalid, round-trip, reload, restart, and restore-copy behavior.
Keep production credentials and databases out of fixtures.

## 16. Debugging by symptom

### 16.1 Configuration writes but has no effect

Check the API value handler, repository write, controller reload call, published
snapshot, and owner event. A field owned by one inbound should produce
InboundReload::One(id), not a global restart.

### 16.2 A rule does not match

Inspect normalized domain, source/destination, port, list membership, process
metadata, rule order, exclusions, and the flow's route snapshot. Test
RouteRule::matches_with_context independently before inspecting the proxy.

### 16.3 DNS appears not to use the proxy

Separate inbound interception from upstream transport. Check resolver ID,
route mode, selector readiness, bridge direct/proxy path, and whether hosts or
FakeIP answered the packet before transport.

### 16.4 Memory or task count keeps growing

Identify the owner first: inbound map, UDP worker, TUN task map, DNS supervisor,
monitor, cache, or buffer queue. Reproduce repeated workload and measure target
device RSS/heap behavior; a one-time allocation observation is not proof of a
leak or an improvement.

## 17. Recommended test matrix

| Area | Minimum checks |
| --- | --- |
| Types and DNS | Model round trips, wire validation, TTL, SVCB/HTTPS, and handler contracts |
| Core and trie | NAT/process, route order, exclusions, list membership, and flow context |
| Protocol and chain | Handshake, framing, UDP, TLS/ALPN, H2/WebSocket/UOT, and Go interoperability |
| Store | Fresh and legacy schema, migration, repository round trip, FakeIP, statistics, and restart |
| TUN | Packet/fragmentation, TCP/UDP, DNS interception, route setup, device lifecycle, and reload |
| Runtime | Snapshot build, selector, resolver, inbound owner, TUN/DNS supervisor, and reload boundaries |
| API | Contract, CRUD, authentication, reload, SSE, statistics, backup, and error responses |
| Platforms | Basic macOS/Linux smoke, Linux TUN/route capability, and service lifecycle |

Use process-level and privileged-container smoke tests for listeners, TUN, route
installation, transparent proxying, and shutdown. Classify listener conflicts,
missing capabilities, and sandbox limitations separately from source failures.

## 18. Quick code index

| Need to inspect | Start at |
| --- | --- |
| Public contracts | crates/doradus-types/src/{lib,dns,net,inbound}.rs |
| Runtime assembly | crates/doradus-runtime/src/{assembly,assembly_config_loader,assembly_snapshot}.rs |
| Controller/reload | crates/doradus-runtime/src/control/ |
| Selector state/routing/metadata | crates/doradus-runtime/src/plane/{selector,selector_routing,selector_metadata}.rs |
| Inbound owners | crates/doradus-runtime/src/plane/inbounds/ |
| TUN and DNS supervisors | crates/doradus-runtime/src/plane/data_plane*.rs |
| Route policy | runtime/src/policy/route.rs and doradus-trie/src/router.rs |
| Outbound plan/construction | runtime/src/plane/{proxy_plan,outbound,protocol_factory}.rs and protocol/src/composition/base_proxy.rs |
| Chain validation and connect | doradus-chain/src/{config,go_node,chain_client}.rs |
| Persistence | doradus-store/src/{lib,sqlite,schema,repository,migration,snapshot,row}.rs |
| Monitor lifecycle/traffic/projection | runtime/src/control/monitor*.rs |
| HTTP API | doradus-api/src/api.rs and src/service/ |

## 19. Change checklist

- [ ] Identify the owning layer and resource owner.
- [ ] Check the Go contract when compatibility is involved.
- [ ] Preserve immutable snapshot semantics and the correct reload boundary.
- [ ] Keep Tokio-specific types at runtime/infrastructure edges.
- [ ] Add or update focused unit and integration tests.
- [ ] Run formatting, targeted tests, and the relevant feature matrix.
- [ ] Repeat runtime smoke tests for platform, TUN, DNS, or lifecycle changes.
- [ ] Check git diff --check and scan changed text for accidental credentials or non-English documentation.

## 20. Internal component index by crate

### 20.1 doradus-types: shared vocabulary

This crate should remain small and runtime-neutral. It is the canonical home of
address/network models, flow metadata, DNS models, inbound handler ports, public
errors, and future aliases. New code should use these canonical definitions.

### 20.2 doradus-dns: model, codec, and transports

Separate model, wire codec, cache/hosts/FakeIP policy, resolver orchestration,
and transport implementations. Keep packet validation and transport I/O
independently testable. Async UDP owns its socket and timeout state and must not
make runtime-controller or API decisions.

### 20.3 doradus-core: flow, socket, NAT, and observation

Core owns async stream/datagram capability, flow lifecycle, NAT, process metadata,
socket policy, and sniffing. Pure flow data is in doradus-types; Tokio I/O and
cancellation remain in core or infrastructure adapters.

### 20.4 doradus-trie: pattern to immutable router

The route index combines domain patterns, CIDR/network matching, and on-disk
host data. Compilation produces an immutable snapshot published as part of
RuntimeSnapshot. Preserve rule order and explicit exclusions.

### 20.5 doradus-protocol: framing and sessions

Protocol modules perform handshake, authentication, framing, and session
management over capabilities supplied by core or chain. They should not read
runtime configuration or own API/service lifecycle. Wire-specific reverse HTTP,
transparent sockets, TLS, H2, WebSocket, and Yuubinsya logic stays here.

### 20.6 doradus-chain: validation, connection, and UDP

Chain configuration converts Go-shaped nodes into an ordered validated chain.
ChainClient handles connection caching and retries; wrappers retain protocol
ordering, including repeated transport wrappers. Preserve Vec<ChainNode> order
and repeated nodes during chain folding or compatibility conversion.

### 20.7 doradus-store: persistence and runtime data

ConfigStore::open owns native database setup, schema checks, and repository
access. Explicit future migration helpers use a separate legacy-open boundary.
Typed repositories group configuration, users, routes, FakeIP, statistics, and
backup operations. Store code produces data for runtime; it does not hold live
resources.

### 20.8 doradus-tun: packet engine and proxy tasks

The TUN loop polls smoltcp synchronously, turns socket events into owned proxy
inputs, and writes proxy outputs back to the device. Async workers must not
await while borrowing smoltcp sockets; use owned event queues across the
boundary.

### 20.9 Runtime auxiliary components

Runtime also owns monitoring, latency probing, loopback detection, interface
discovery, bounded logs, defaults, update control, and proxy wrappers. These
should not become a second configuration store or owner supervisor.

RuntimeProxySelector publishes a coherent ArcSwap<SelectorState>. New
route/select operations read one selector generation; already acquired proxy
objects remain owned by existing flows. Resolver, local-bind policy, connect
budgets, and loopback tracking are separate wrappers rather than one untestable
connect function. Keep route behavior in selector_routing.rs and observability
metadata in selector_metadata.rs instead of growing selector.rs back into a
single reload/routing/metadata file.

### 20.10 doradus-api: HTTP adapter, RPC, and service management

API routing, authentication, value handlers, repository calls, SSE, backup
transport, and OS service installation are separate concerns. Keep process-host
startup and child-task joining in service/; keep JSON normalization and
operation dispatch in API modules.

### 20.11 Geo, WireGuard, and backup

These are edge adapters. Geo publishes validated immutable snapshots, WireGuard
keeps crypto/driver state below the generic proxy capability, and backup returns
through store migration and controller rebuild before data becomes live.

## 21. End-to-end paths by user action

### 21.1 Create or modify a node

~~~mermaid
sequenceDiagram
    participant UI as React or API client
    participant API as save_node_value
    participant REP as ConfigRepository
    participant CTRL as RuntimeController
    participant BUILDER as RuntimeBuilder
    participant PB as ProxyBuild
    participant CHAIN as ChainClient
    participant SLOT as RuntimeProxySelector

    UI->>API: PUT node/{id}
    API->>REP: put_go_node(record)
    API->>CTRL: mutate_and_reload()
    CTRL->>BUILDER: build()
    BUILDER->>REP: list nodes, tags, resolvers, and routes
    BUILDER->>PB: build_proxy(id)
    PB->>CHAIN: ChainClient::from_go_json / new
    CHAIN-->>PB: ChainProxy or protocol proxy
    PB-->>BUILDER: ProxyBuild
    BUILDER-->>CTRL: RuntimeSnapshot
    CTRL->>SLOT: publish snapshot and replace selector
    CTRL-->>API: reload result
~~~

When adding a chain type, update both Go-node conversion and build_proxy; a
selector-slot change alone is incomplete because resolver and route metadata
must be rebuilt with it.

### 21.2 Modify an inbound

~~~text
API inbound_put/delete
  -> repository.put/delete_go_inbound
  -> mutate_and_reload_inbound(id)
  -> build new RuntimeSnapshot
  -> publish snapshot
  -> broadcast InboundReload::One(id)
  -> owner waits for matching reload
  -> old listener exits and drops its socket
  -> start_inbounds(... only_id=Some(id))
~~~

The old listener must drop its socket before the new owner binds. A shared
mutex around InboundSpec is not a substitute for owner lifecycle management.

### 21.3 TUN TCP flow

~~~text
OS TUN packet
  -> TunRuntime::recv_from_tun
  -> TunDispatcher::poll
  -> inspect_ip_packet / smoltcp socket
  -> ProxyInput::TcpOpened
  -> ProxyInputInterceptor::intercept
  -> TunProxyRuntime::handle_proxy_input
  -> context_for_flow (process and FakeIP context)
  -> selector.route_context
  -> selector.select
  -> TcpTaskManager::spawn
  -> run_tcp_proxy
  -> AsyncProxy::connect
  -> bidirectional relay
  -> process_proxy_outputs
  -> dispatcher.write_tcp
  -> smoltcp TUN TX queue
  -> fragment_ip_packet
  -> OS TUN
~~~

### 21.4 Socket inbound UDP flow

~~~text
client datagram
  -> SOCKS5/Trojan/transparent UDP codec recv
  -> InboundUdpRequest{id, peer, target, payload}
  -> InboundUdpManager::dispatch (try_send)
  -> UdpSourceKey lookup
  -> spawn_udp_flow / UdpFlowWorker::run
  -> InboundHandler::answer_datagram (DNS interception branch)
  -> FlowContext + route_context
  -> AsyncProxy::open_datagram
  -> datagram.send_to
  -> datagram.recv_from
  -> InboundUdpResponse
  -> codec.send
~~~

Socket UDP and TUN UDP share source-owned/full-cone semantics but have different
owners: socket inbound uses InboundUdpManager, while TUN uses
TunProxyRuntime::udp_tasks. Do not merge them into one global map.

### 21.5 DNS interception flow

~~~text
TUN or socket receives UDP/TCP DNS packet
  -> InboundDnsHandler::should_hijack(destination_port, packet)
  -> RuntimeDnsHandler / InboundHandler::answer_datagram
  -> FakeIP, hosts, and policy decision
  -> RuntimeSnapshot::dns_resolver_for_route_mode
  -> RoutedDnsClient::query_packet
  -> ResolverProxyBridge (direct or proxy)
  -> validate, rewrite, and encode response
  -> packet/socket response queue
~~~

When DNS interception or inbound FakeIP policy changes, inspect resolver_by_id,
dns_resolver_by_id, and inbound_resolver_by_id. They distinguish flow
resolution, listener resolution without FakeIP, and inbound policy resolution.

## 22. Tests are component documentation

When behavior is unclear, read matching tests before changing implementation:

| Behavior | Test entry points |
| --- | --- |
| DNS wire/SVCB/cache/UDP | doradus-dns tests, host tests, and tests/dns_quic.rs |
| Core NAT/process | doradus-core nat_tests.rs and tests/nat_process.rs |
| Trie route flow | doradus-trie p0_flow.rs and router tests |
| Protocol and Go compatibility | protocol and chain go_*_interop.rs tests |
| H2/WebSocket/UOT | H2/WebSocket chain tests and protocol tunnel tests |
| Store schema/migration | store schema/import/snapshot/storage tests and fixtures |
| FakeIP | store FakeIP tests and NDJSON/SQL fixtures |
| TUN packet/proxy | TUN unit/proxy tests, route tests, and tun_smoke |
| Runtime resolver/TUN/reload | runtime DoH/legacy tests and controller/data-plane tests |
| API contract/reload | API contract, reload, startup-log, and statistics-concurrency tests |
| Backup | backup S3-local tests and API backup tests |
| WireGuard | WireGuard unit/external tests and API chain tests |

The FakeIP smoke binary verifies that DNS reaches the common async datagram
proxy path rather than a TUN-only side channel. A test named
reloadable_tun_dns_handler_switches_snapshots_without_rebuilding_owner
expresses a lifecycle constraint: DNS handler state may change while the TUN
owner remains intact.

## 23. Navigation decision tree

~~~mermaid
flowchart TD
    START[Change a behavior] --> Q1{Shared across crates?}
    Q1 -->|Yes, no Tokio or platform dependency| TYPES[doradus-types]
    Q1 -->|No| Q2{DNS packet input or output?}
    Q2 -->|Yes| DNS[doradus-dns]
    Q2 -->|No| Q3{Protocol framing or crypto?}
    Q3 -->|Yes| PROTO[doradus-protocol]
    Q3 -->|No| Q4{Node chain or transport layering?}
    Q4 -->|Yes| CHAIN[doradus-chain]
    Q4 -->|No| Q5{Packet, TUN, or platform?}
    Q5 -->|Yes| TUN[doradus-tun]
    Q5 -->|No| Q6{Persistence, schema, or Go compatibility?}
    Q6 -->|Yes| STORE[doradus-store]
    Q6 -->|No| Q7{Route, selector, reload, or owner?}
    Q7 -->|Yes| RUNTIME[doradus-runtime]
    Q7 -->|No| Q8{API JSON or service lifecycle?}
    Q8 -->|Yes| API[doradus-api]
    Q8 -->|No| REVIEW[Confirm boundary before copying logic]
~~~

### 23.1 Minimum reading set before a change

| Change | Read first | Then test |
| --- | --- | --- |
| New public trait | Corresponding types trait and old re-exports | types plus two implementations |
| New resolver | AsyncIpResolver, RoutedDnsClient::query_packet, ResolverTransportFactory | Packet, timeout, and single-flight tests |
| New outbound | BaseProxyConfig::build, selector proxy build, ChainClient::connect_* | Protocol and chain interop |
| New inbound | start_inbounds, ProtocolHandler::handle, InboundHandler | API reload and protocol server |
| New route matcher | Route compiler, RouteRule::matches_with_context, router apply | Trie flow and route tests |
| New TUN packet behavior | Packet inspection, TunDispatcher::poll, TUN proxy input handler | Packet, fragmentation, and proxy tests |
| New configuration field | Repository list/put, RuntimeBuilder::build, API value handler | Empty, legacy, and reload fixtures |

## 24. Documentation scope and use

This guide covers the 15 workspace crates, production source modules, major tests,
startup/control plane, TCP/UDP/TUN/DNS data planes, routing, proxy/protocol/
chain/store/API boundaries, and the main change entry points. Complete means
that each component has an indexed responsibility, boundary, main flow, and
change location; trivial getters are intentionally not copied line by line.

For code reading, use this order:

1. Read the crate graph in section 2.
2. Read sections 5 and 6 for startup, snapshots, controllers, reload, and owners.
3. Jump to sections 7–14 for the relevant data plane.
4. Use section 20 for an implementation entry point.
5. Use sections 21–23 to verify the end-to-end path and tests.

Source line numbers change as code evolves. Function names and paths are the
stable index; links with line numbers are only navigation hints.

## 25. Current architecture quick reference

The 2026 maintenance pass deliberately moved compatibility parsing, runtime
state, task ownership, and observability toward explicit boundaries without
adding new crates for every concern:

| Concern | Current boundary | Important invariant |
| --- | --- | --- |
| Public address/DNS/inbound contracts | doradus-types | Keep Tokio/store/platform ownership out |
| Persisted outbound compatibility data | runtime/plane/proxy_plan.rs | Validate/normalize once, then build from typed plans |
| Persisted inbound compatibility data | inbounds/InboundPlan | prepare_runtime refreshes typed plan once; production listeners consume it directly |
| Runtime immutable configuration | assembly_snapshot.rs / RuntimeSnapshot | Publish only complete snapshots |
| Live selector generation | ArcSwap<SelectorState> | Swap TCP/UDP/tag/metadata/settings coherently |
| Selector routing vs metadata | selector_routing.rs / selector_metadata.rs | Do not recombine unrelated change reasons |
| Monitor runtime data | typed ConnectionRecord + JSON projection | Runtime logic reads typed fields, API reads projection |
| Monitor hot traffic | sharded traffic state | Never take the control-state lock per byte update |
| Inbound UDP queues | bounded data/control/event channels | Packet data may drop under pressure; lifecycle events must not silently disappear |
| DoQ socket adapter | bounded queues + real Quinn writable poller | Full queue reports WouldBlock and wakes on capacity return |
| TUN async task ownership | Tcp/Udp/IcmpTaskManager + FlowTracker | Runtime orchestrates; managers own spawn/register/abort |
| SQLite execution | synchronous ConfigStore core + blocking runtime bridge | Do not pretend rusqlite I/O is async |
| Store file/row helpers | snapshot.rs / row.rs | Keep lib.rs as facade rather than a utility dump |

The preferred maintenance rule is now conservative: preserve these ownership
boundaries, measure before changing hot-path allocation or containers, and do
not split a cohesive protocol implementation merely because the source file is
large. QUIC and AEAD modules may legitimately be long when one wire protocol
owns the handshake, framing, session, and UDP behavior.

Adding a public trait still does not mean putting every proxy trait in
doradus-types. First decide whether it expresses a platform-independent value
or contract. If it needs FlowContext, Tokio I/O, socket metadata, store state,
or async resource lifetime, keep it in the corresponding
core/protocol/runtime layer.
