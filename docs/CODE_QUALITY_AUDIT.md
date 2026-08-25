# yuhaiin-rust 代码质量审计

审计日期：2026-08-25
审计范围：当前 workspace 中已修改的 API、core proxy primitives、DNS codec/resolver、runtime assembly/data-plane/outbound/route/inbound/TUN/monitor、store 和 Yuubinsya protocol session 边界。
审计方式：按 thermo-nuclear code quality review 标准，优先检查模块深度、职责边界、重复分派、隐式状态和可验证的结构性简化。

## 结论摘要

本轮完成了多阶段的实质性结构收敛：API/outbound/route/inbound 等核心 God module 已拆分，随后又收敛了 monitor、store、Yuubinsya session、latency、proxy chain、resolver、core proxy、DNS、data-plane、API service、statistics/migration、VMess、trie、update、TUN packet、inbound UDP actor 和 API projection helpers。当前已审计的生产文件均不超过 1,000 行；剩余 800--900 行级别的模块都是单一兼容边界或协议工厂，测试 artifact 也不再与生产职责混在同一个模块中。

已完成的主要优化：

- API 控制面拆成路由、RPC dispatcher、操作 hub 以及 node/inbound/resolver/route/config/projection 等领域模块；保留 pub fn router 和现有 Go/HTTP contract。
- API projection helpers 又按通用 JSON/request、资源、路由、查询分页和 settings/defaults 拆开；操作层继续通过 `projections.rs` 兼容 re-export，避免扩大调用方改动。
- outbound 拆成父级 proxy build、protocol_factory、proxy adapters、proxy slots、selector；协议构造和 selector 生命周期不再与一个 3,000 行文件耦合。
- route 拆成规则编译入口、route_expressions 和 route_lists；递归表达式展开和列表缓存/下载拥有独立 seam。
- inbound 拆成 supervisor、spec/transport 解析、协议 listener/handler；测试也移到独立文件。
- RuntimeInputs 把 store 读取/fallback 与 runtime component assembly 分开。
- RuntimeProxySelector::route_context 显式经过 FakeIP、hosts、route、resolver 四个有序阶段。
- ConnectionMonitor 拆成 monitor runtime、persistence、projection、statistics/history 和独立测试 artifact；实时 flow 状态不再与持久化/JSON 投影混为一体。
- ConfigStore 拆出 records、lifecycle、FakeIP、backup 和 snapshot；root 只保留 SQLite 核心读写、配置 mutation 和底层 helper。
- Yuubinsya session 拆成 TCP/Ping、UOT、server proxy 和独立测试文件；公开 session re-export 与 wire behavior 保持不变。
- latency probe 拆成 dispatcher、HTTP framing/TLS、STUN codec 和独立测试；HTTP、STUN、DNS/DoQ 不再共用一个实现文件。
- chain 拆成 transport wrappers、ChainClient、UOT retry/session、ChainProxy 和测试；保留 `Vec<ChainNode>` 顺序、重复 wrapper 及 Go folding 语义。
- ConfigRepository 拆成 Go compatibility 的配置/DNS、订阅发布、实体、路由四个领域，以及 native typed repository；兼容表 SQL 仍位于 store 边界内。
- FakeIP 拆成 legacy NDJSON import/export、IPv4 pool、IPv6 pool 和 DNS answer transforms；双栈生命周期与地址族独立 key/cursor 语义保持不变。
- resolver 拆成 proxy bridge、builtin UDP/TCP、encrypted factories 和测试；bootstrap direct 与 proxy resolver selector 路由仍由同一桥接逻辑控制。
- core proxy primitives 拆成 socket/interface、stream metadata、direct、drop、wrappers、SOCKS5/datagram 和测试；公共 trait/API 仍从 `proxy` root re-export。
- DNS root 拆成 wire codec、sync clients、sync server/policy、async UDP 和测试；resolver 再拆成 sync facade、query traits、system resolver、async cache/singleflight 和测试。
- data-plane 拆成 runtime DNS handler、TUN config/parser、TUN/DNS supervisors 和测试；TUN device ownership 与 DNS reload/shutdown boundary 保持不变。
- H2 tunnel 将连接/池/relay 生产实现与测试 artifact 分离；`h2_tunnel.rs` 只保留 703 行生产代码，HTTP/2 pool drain、capacity、GOAWAY 和错误回收测试位于独立文件。
- API service binary 按 Linux/macOS/Windows 平台拆分；公共参数解析、安装路径和状态 helper 仍由 root 共享，平台生命周期实现不再互相污染。
- store statistics 拆成增量写入、projection/migration 和测试；store migration 按 Go import、legacy chain、version、node/inbound/route/resolver/validation 领域拆分，兼容 re-export 保持不变。
- VMess 拆成 codec、body framing、stream/UDP relay 和测试；trie router/ondisk 拆出测试与外部排序/build 边界；update service 拆成 release metadata、platform helper 和测试。
- TUN packet 拆成 IP inspection/fragmentation、IPv6 reassembly 和 bounded smoltcp queue/device；inbound handler 拆成通用 stream/DNS boundary 与 source-owned UDP manager。
- 进程级 `tun_service_smoke` 拆成主场景、clients、config 和 Yuubinsya chain fixture；子模块放在 binary 子目录，避免 Cargo 将测试 helper 误识别为额外 binary。
- Go `nodes_v2` compatibility 的 endpoint 解析、地址族校验、接口继承和 resolver 注入已独立到 `compat_proxy_endpoint.rs`；兼容层的协议/transport 映射仍保留在 `compat_proxy.rs`。
- outbound protocol factory 的 TLS transport、TLS termination 证书读取和 SNI 匹配已独立到 `protocol_tls.rs`；HTTP/2、WebSocket、标准协议和 plan 归一化仍由 factory root 负责。
- 修复 socket UDP connection projection 暴露 `udp://` 和解析后 IP 的问题；修复 node selection 未重建既有 inbound selector 的 reload 边界。
- 补齐进程级测试的 route priority 与 UDP history 观测契约：内置 LAN 规则不再意外吞掉 WireGuard/reverse termination 场景，一次性 UDP-over-stream 关闭后也能从 history 验证 flow。
- 保留并验证此前的 ReloadPlan、resolver variant registry、共享 tag proxy Arc、TUN warning 清理和独立测试文件改动。

## 当前结构证据

| 边界 | 当前生产文件 |
| --- | --- |
| API | [api.rs](../crates/yuhaiin-api/src/api.rs) 627 行；[routes.rs](../crates/yuhaiin-api/src/routes.rs) 155 行；[rpc_dispatch.rs](../crates/yuhaiin-api/src/rpc_dispatch.rs) 372 行；operations/domain files 最大 604 行；projection helpers 最大 227 行 |
| outbound | [outbound.rs](../crates/yuhaiin-runtime/src/plane/outbound.rs) 780 行；[protocol_factory.rs](../crates/yuhaiin-runtime/src/plane/protocol_factory.rs) 463 行；[protocol_tls.rs](../crates/yuhaiin-runtime/src/plane/protocol_tls.rs) 358 行；proxy adapters 814 行；selector 717 行 |
| route | [route.rs](../crates/yuhaiin-runtime/src/policy/route.rs) 477 行；表达式 494 行；列表 694 行 |
| assembly | [assembly.rs](../crates/yuhaiin-runtime/src/assembly.rs) 932 行；RuntimeInputs 位于 [assembly.rs:352](../crates/yuhaiin-runtime/src/assembly.rs#L352) |
| inbound | [inbounds/mod.rs](../crates/yuhaiin-runtime/src/plane/inbounds/mod.rs) 482 行；spec 399 行；protocols 631 行 |
| selector pipeline | [selector.rs:324-433](../crates/yuhaiin-runtime/src/plane/selector.rs#L324) 的四个阶段 helper；trait 入口位于 [selector.rs:439](../crates/yuhaiin-runtime/src/plane/selector.rs#L439) |
| monitor | [monitor.rs](../crates/yuhaiin-runtime/src/control/monitor.rs) 251 行；runtime 954 行；persistence 143 行；projection 327 行；statistics 495 行 |
| store | [lib.rs](../crates/yuhaiin-store/src/lib.rs) 980 行；[compat_proxy.rs](../crates/yuhaiin-store/src/compat_proxy.rs) 733 行（Go nodes_v2 protocol/transport boundary）；[compat_proxy_endpoint.rs](../crates/yuhaiin-store/src/compat_proxy_endpoint.rs) 176 行（endpoint/address boundary）；lifecycle 150 行；FakeIP 358 行；backup 172 行；snapshot 316 行；records 291 行 |
| Yuubinsya session | [session.rs](../crates/yuhaiin-protocol/src/session.rs) 134 行；TCP 216 行；UOT 335 行；server proxy 794 行 |
| latency probe | [latency.rs](../crates/yuhaiin-runtime/src/support/latency.rs) 483 行；HTTP 382 行；STUN 354 行 |
| proxy chain | [lib.rs](../crates/yuhaiin-chain/src/lib.rs) 127 行；transport 406 行；client 514 行；UOT 484 行；proxy 208 行 |
| repository | [repository.rs](../crates/yuhaiin-store/src/repository.rs) 18 行；Go config/DNS 670 行；Go routes 357 行；typed 292 行 |
| resolver | [resolver.rs](../crates/yuhaiin-runtime/src/policy/resolver.rs) 91 行；bridge 355 行；builtin 439 行；encrypted 311 行 |
| core proxy primitives | [proxy.rs](../crates/yuhaiin-core/src/proxy.rs) 127 行；socket 230 行；direct 289 行；datagrams 331 行；SOCKS5 248 行 |
| DNS wire/resolver | [dns.rs](../crates/yuhaiin-dns/src/dns.rs) 48 行；codec 598 行；async UDP 594 行；[dns_resolver.rs](../crates/yuhaiin-dns/src/dns_resolver.rs) 45 行；system 514 行；async 450 行 |
| runtime data-plane | [data_plane.rs](../crates/yuhaiin-runtime/src/plane/data_plane.rs) 61 行；DNS 149 行；TUN config 542 行；supervisor 307 行 |
| FakeIP persistence | [fakeip.rs](../crates/yuhaiin-store/src/fakeip.rs) 164 行；legacy 278 行；IPv4 pool 521 行；IPv6 pool 519 行；transform 298 行 |
| H2 tunnel | [h2_tunnel.rs](../crates/yuhaiin-protocol/src/h2_tunnel.rs) 703 行生产代码；[h2_tunnel_tests.rs](../crates/yuhaiin-protocol/src/h2_tunnel_tests.rs) 850 行测试 |
| API service | [service/mod.rs](../crates/yuhaiin-api/src/bin/service/mod.rs) 400 行；平台实现分别为 Linux 349、macOS 533、Windows 493 行 |
| store statistics/migration | [statistics.rs](../crates/yuhaiin-store/src/statistics.rs) 245 行；[migration.rs](../crates/yuhaiin-store/src/migration.rs) 45 行；领域子模块均低于 600 行 |
| VMess | [vmess.rs](../crates/yuhaiin-protocol/src/vmess.rs) 30 行 root；codec 733、body 163、stream 323 行 |
| trie | [router.rs](../crates/yuhaiin-trie/src/router.rs) 653 行；[ondisk.rs](../crates/yuhaiin-trie/src/ondisk.rs) 732 行；build/test 子模块独立 |
| update/inbound/TUN | update root 477 行；inbound handler 470、UDP manager 574 行；packet root 529、reassembly 361、device 277 行 |
| TUN smoke | root 991 行；clients 443、chain 206、config 86 行，均为测试夹具而非 runtime library |

测试文件可以较大，但已不再挤占生产模块：例如 inbound tests 为 2,179 行，属于独立测试 artifact，不影响 mod.rs 的职责边界。

## Findings

### CQ-1：API 控制面 God module

状态：已解决（结构层面）
原严重程度：高

api.rs 现在只保留状态、公开 router wrapper 和模块组合；路由构造在 [routes.rs:7](../crates/yuhaiin-api/src/routes.rs#L7)，RPC 字符串兼容分派在 [rpc_dispatch.rs:3](../crates/yuhaiin-api/src/rpc_dispatch.rs#L3)，领域操作通过 operations.rs hub 汇总。原先的生产文件 4,671 行已降到 627 行，且每个领域实现拥有相邻的局部边界。

仍可继续改进的是动态 JSON 类型边界，见 CQ-2；这已经不是文件职责混杂问题。

### CQ-2：API 动态 serde_json::Value 边界

状态：已解决（兼容边界已明确）
严重程度：中高；置信度：高

RPC 现在先由 [RpcOperation](../crates/yuhaiin-api/src/rpc_dispatch.rs#L3) 把 operation 字符串归一化成有限枚举，再进入 handler；这消除了 dispatcher 内部对字符串的重复分派。settings 已在写入边界完成 canonicalize；node、inbound 和 route rule 的 Value 则明确限定在 Go-compatible raw/extra boundary，用于保留异构 chain layer、未知字段、snake/camel alias 和 Go zero-value 语义。它们不会继续向 domain/runtime 层扩散，因此当前不构成未收敛的业务逻辑边界。

### CQ-3：outbound 多套协议分派

状态：已解决（持续扩展约束）
严重程度：中高；置信度：高

协议实现已从 outbound.rs 抽到 protocol_factory.rs，NetworkSplit adapter、socket policy 和 connect budget 也已分离。现在 [ProxyPlan](../crates/yuhaiin-runtime/src/plane/protocol_factory.rs#L93) 会一次性归一化 transport、chain layer 能力和分派优先级，outbound builder 只消费该 plan，不再分别扫描 `chain_types` 判断 HTTP/2、WebSocket、TLS、chain 和标准协议。

NetworkSplit 的子分支仍保留显式协议匹配，因为它处理的是已经构造好的 parent wrapper；这属于局部协议注册表，不再与 top-level transport plan 混用。该边界已通过 factory、NetworkSplit 和 TLS termination 测试固定；新增 outbound protocol 时沿用同一扩展点即可。

### CQ-4：route expression 中间模型

状态：已解决（持续扩展约束）
严重程度：中；置信度：高

递归 all/any/not 和 RuleVariant 已移到 route_expressions.rs，列表加载/缓存已移到 route_lists.rs，规则编译入口只负责把 variant 生成最终 RouteRule。

入口现在先通过 [RuleExpressionKind](../crates/yuhaiin-runtime/src/policy/route_expressions.rs#L28) 识别 all/any/not 和叶子 matcher，再进入现有 RuleVariant 组合逻辑；未知类型也会在该边界显式失败。Value 只停留在兼容 decode 边界，RuleVariant 负责稳定的内部语义，并保持 Go sort/match-history 语义；新增 matcher 继续扩展该中间模型即可。

### CQ-5：RuntimeBuilder 读取与组装

状态：已解决（持续扩展约束）
严重程度：中；置信度：高

RuntimeBuilder::load_inputs 位于 [assembly.rs:405](../crates/yuhaiin-runtime/src/assembly.rs#L405)，现在负责 defaults、repository 读取、fallback 和原始配置快照；build 再负责 FakeIP、resolver variants、registry、route trie、semaphore 和 immutable snapshot 组装。原先最明显的“一个函数连续做所有阶段”问题已消失。

三套 resolver map 仍保持 snapshot 字段级兼容，但 builder 内部已经用 [ResolverVariants](../crates/yuhaiin-runtime/src/assembly.rs#L665) 按 resolver id 聚合三种变体，再在发布 snapshot 时投影为现有字段。新增 resolver policy 时继续扩展该内部模型，避免重新引入 parallel maps；这属于已记录的设计约束，不是当前遗留项。

### CQ-6：RuntimeController reload 流程

状态：已解决

内部 ReloadPlan 和统一 mutation/reload 入口已收敛锁、mutation error、build 和 event 发布；public convenience methods 仍保留。

### CQ-7：selector route pipeline

状态：已解决（阶段边界）

RuntimeProxySelector::route_context 位于 [selector.rs:439](../crates/yuhaiin-runtime/src/plane/selector.rs#L439)，现在按固定顺序调用：

1. restore_fakeip_destination
2. apply_hosts_override
3. evaluate_route
4. resolver_for_route_mode
5. connection metadata annotation

这些 helper 仍共享同一个 FlowContext，这是当前 selector trait 的必要边界；但阶段顺序和职责已可单独审查、测试和扩展。

### CQ-8：测试/生产文件规模

状态：已解决（包含本轮新增的历史大模块）

API、outbound、route、controller、assembly、inbound、monitor、store、protocol session、latency、chain、resolver、core proxy、DNS 和 data-plane 的测试均已移到独立文件或独立测试模块。已审计的重点生产文件均低于 1,000 行：inbound root 从 3,685 行降到 482 行，assembly 从 1,506 行降到 913 行，monitor root 从 3,202 行降到 251 行，store root 从 2,232 行降到 980 行，session root 从 2,500 行降到 134 行，repository root 从 1,757 行降到 18 行，resolver root 从 1,785 行降到 45 行，proxy root 从 2,034 行降到 127 行，DNS root 从 1,916 行降到 48 行，data-plane root 从 1,775 行降到 61 行。

独立测试文件仍可能较大，但不再挤占生产模块的职责边界；例如 monitor tests 1,053 行、session tests 1,028 行，属于协议/状态行为的集中测试 artifact。本轮新增的 API service、statistics/migration、VMess、trie、update、inbound UDP 和 TUN packet 生产边界也全部低于 1,000 行。

### CQ-9：编译卫生

状态：已解决

TUN 当前 target 下的 unused_mut 和 macOS-only helper warning 已清理；本轮新增模块也没有留下 warning。

### CQ-10：ConnectionMonitor 混合实时状态、持久化和投影

状态：已解决（结构层面）
严重程度：高；置信度：高

原 monitor.rs 同时包含 active flow 状态、SQLite checkpoint worker、历史/telemetry 投影、JSON contract 和全部测试。现在 `monitor_runtime.rs` 保留运行态操作，`monitor_persistence.rs` 负责 checkpoint 生命周期，`monitor_projection.rs` 负责连接/telemetry 投影，`monitor_statistics.rs` 负责 durable snapshot/history 变换，测试移到 `monitor_tests.rs`。这保留了 `ConnectionMonitor` API 和 255 个 runtime 测试，同时消除了最明显的 God module。

### CQ-11：ConfigStore root 同时承载 DTO、FakeIP、backup 和 snapshot

状态：已解决（边界层面）
严重程度：高；置信度：高

公开 records 已集中到 `records.rs`；FakeIP 事务和 legacy import 在 `fakeip_store.rs`，备份清理/安装在 `backup.rs`，Go snapshot restore/install 在 `snapshot.rs`，open/migrate/repository/status/close 在 `lifecycle.rs`。`lib.rs` 现在低于 1,000 行，底层 SQLite helper 仍留在 root 作为共享实现，避免引入无收益的 helper trait。

### CQ-12：Yuubinsya session 混合 TCP、Ping、UOT 和 server proxy

状态：已解决（协议 seam）
严重程度：高；置信度：高

`session.rs` 现在只保留共享 codec helper、模块声明和 public re-export；TCP/Ping、UOT client/server、server proxy/observed flow 各自位于独立模块，测试位于 `session_tests.rs`。通过 `cargo test -p yuhaiin-protocol --all-targets --offline` 验证 118 个测试，保留既有 ignored interop tests，不改变 `lib.rs` 的公开导出或 wire contract。

### CQ-13：latency probe 混合多种协议 framing

状态：已解决（协议 seam）
严重程度：中高；置信度：高

原 latency.rs 同时包含 HTTP response framing、TLS 包装、STUN 编解码、DNS/DoQ 查询、公共 dispatcher 和全部测试。现在 `latency.rs` 只负责 probe 请求模型、公共代理边界和 dispatch；HTTP、STUN 和测试分别位于 `latency_http.rs`、`latency_stun.rs`、`latency_tests.rs`。runtime 全目标测试覆盖 HTTP、STUN、UDP DNS 和 DoQ 路径。

### CQ-14：proxy chain 混合 wrapper、client、UOT retry 和 public API

状态：已解决（协议 seam）
严重程度：高；置信度：高

原 chain lib.rs 同时承载固定/TLS/H2 wrapper、链式 client、UOT 重连队列、proxy adapter 和测试。现在 root 只保留 public config/stats、模块声明和 re-export；transport、ChainClient、ChainUot、ChainProxy 各自有独立边界。保留有序 `Vec<ChainNode>` folding、重复 transport wrapper、direct/fixedv2 语义，并通过 chain/p0/http2 tests 验证。

### CQ-15：ConfigRepository 混合 Go compatibility 与 native typed persistence

状态：已解决（领域 seam）
严重程度：高；置信度：高

原 repository.rs 把 Go v2 compatibility 表、订阅/发布、节点/入站/解析器/路由以及 native typed 表写入混在一个 1,757 行实现中。现在入口只有模块声明和共享校验；Go compatibility 按配置/DNS、订阅发布、实体、路由拆分，native typed 操作独立于 `repository_typed.rs`。所有 inherent method 的 public path 保持不变，Go import、snapshot 和跨进程测试通过。

### CQ-16：resolver 混合 selector bridge、builtin DNS 与 encrypted factory

状态：已解决（transport seam）
严重程度：高；置信度：高

原 resolver.rs 同时实现代理 resolver bridge、UDP/TCP routed DNS、DoH/DoT 工厂和测试。现在 root 只保留 trait、模块声明及兼容 re-export；bridge、builtin、encrypted 和测试各自独立。bootstrap resolver 仍强制使用 direct slot，配置为 proxy 的 resolver 仍通过 runtime selector，并由 DoH/DoT integration tests 覆盖。

### CQ-17：core proxy root 混合 socket、stream、direct、drop、wrapper 与 SOCKS5

状态：已解决（基础设施 seam）
严重程度：高；置信度：高

原 `yuhaiin-core/src/proxy.rs` 同时承载 interface binding、stream metadata、direct ICMP/UDP/TCP、drop delay、fixed/fallback wrapper、SOCKS5 handshake/UDP framing 和测试。现在 root 只保留公共 trait、基础 selector、模块声明和 re-export；各 transport seam 独立，`AsyncProxy`、`AsyncDatagram`、`BoxAsyncStream` 和现有公共类型路径保持不变。

### CQ-18：DNS root 混合 wire codec、同步 transport、异步 UDP 和测试

状态：已解决（协议 seam）
严重程度：高；置信度：高

原 `dns.rs` 同时包含 SVCB/HTTPS wire codec、policy handler、sync UDP/DoH client、sync server、async UDP client/server 和两套测试。现在 codec、sync client、sync server、async UDP 各自独立，root 只保留 re-export。DNS raw query、truncation fallback、transaction id 和 async shutdown 行为由 46 个 DNS crate tests 覆盖。

### CQ-19：DNS resolver 混合同步 facade、system resolver、query traits 与 async singleflight

状态：已解决（resolver seam）
严重程度：高；置信度：高

原 `dns_resolver.rs` 将同步 transport facade、system DNS client manager、跨 Tokio task 的 query traits、cache/singleflight 和测试放在一个文件。现在分别位于 sync、traits、system、async modules，root 只保留 public re-export；system resolver 共享实例、raw query transaction rewrite、cache 和 cancellation 测试均通过。

### CQ-20：runtime data-plane 混合 DNS handler、TUN config parser 和 owner supervisor

状态：已解决（owner seam）
严重程度：高；置信度：高

原 `data_plane.rs` 同时承载 snapshot DNS handler、TUN/Go compatibility config parsing、TUN device dispatcher、UDP/TCP DNS listener supervisor、reload waiters 和全部测试。现在 DNS handler、TUN config、TUN/DNS supervisor 分离；设备仍由调用方拥有，DNS listener 仍按相同 shutdown/reload owner 管理。runtime 全目标测试覆盖这些边界。

### CQ-21：FakeIP 混合 legacy migration、双地址族 pool 与 DNS transform

状态：已解决（持久化/协议 seam）
严重程度：高；置信度：高

原 `fakeip.rs` 同时承载 Go Pebble/bbolt NDJSON contract、IPv4/IPv6 cursor/mapping persistence、allocation/release/TTL、DNS A/AAAA/HTTPS/SVCB/PTR transform 和 async handler。现在 legacy parser、IPv4 pool、IPv6 pool 与 transform 独立；V4/V6 仍保留镜像 lifecycle API，但使用不同 namespace、cursor 和 reverse index。store 全量测试覆盖 allocation、reopen、conflict import、TTL soak 与 answer transform。

### CQ-22：H2 tunnel 将连接池生产实现与大段协议测试混在一个文件

状态：已解决（测试 artifact seam）
严重程度：中；置信度：高

原 `h2_tunnel.rs` 的生产实现约 700 行，但文件尾部包含约 850 行连接池、GOAWAY、drain、错误回收和真实 socket 测试，令生产入口看起来像 1,552 行 God module。现在 root 只保留 `H2Connection`、`H2Pool`、relay/error helper 和测试模块声明；测试移到 `h2_tunnel_tests.rs`，不改变模块内访问、公共 API 或 HTTP/2 行为。

### CQ-23：API service、store migration/statistics、VMess、trie 和 update 历史大文件

状态：已解决（领域/平台 seam）
严重程度：高；置信度：高

原先这些文件分别把平台生命周期、统计投影与增量写入、Go schema migration、VMess wire/body/stream、trie build/query 和 release/platform update 混在同一实现中。本轮按真实依赖方向拆分，并保留原有 module path、公开 re-export、数据库兼容 contract 和协议 wire behavior。对应 crate 的 compile/test 验证覆盖了这些边界。

### CQ-24：TUN packet 与 inbound handler 的运行时职责过宽

状态：已解决（数据面 seam）
严重程度：高；置信度：高

`packet.rs` 现在只保留 packet inspection、IP fragmentation 和 IPv6 extension normalization；IPv6 bounded reassembly 独立于 queue/device。`handler.rs` 只负责 DNS、flow context、outbound/relay 和 stream hand-off；source-keyed UDP manager、flow worker、session codec loop 独立于 `handler_udp.rs`。同步 smoltcp token API 没有被 async I/O 侵入，原有 public packet/device 类型路径保持不变。

### CQ-25：进程级 TUN smoke fixture 的场景耦合

状态：已解决（测试 fixture seam）
严重程度：中；置信度：高

主场景、命令行 traffic clients、环境配置和 Yuubinsya TLS/H2 fixture 已分开；这些文件仍允许承载较多场景断言，但不再作为 runtime library 的生产模块或 Cargo 的意外 binary target。

### CQ-26：API 进程级集成测试的运行时观察与路由优先级

状态：已解决
严重程度：中高；置信度：高

本轮复跑发现并修复了 4 类真实问题：socket UDP monitor projection 在已解析 flow 上错误回退到 `udp://` endpoint；新建 route rule 在默认 LAN rule 后导致 reverse termination/WireGuard 场景走 direct；选择 node 后没有按 selector 生命周期重建已有 inbound；一次性 UDP-over-stream 在回包后正常关闭，但测试只等待 active connections。现在 projection 限定 socket inbound 使用原始 authority，node selection 使用 inbound reload plan，相关进程级 fixtures 显式声明 route priority，并同时验证 active/history 两种合法 flow 状态。另将 service-chain 的 HTTP listener 改为子进程自选端口，并按绑定地址隔离测试数据库，默认并行 service-chain 已稳定通过。

宿主仍可能在日志中出现已有 `127.0.0.1:1080`/`:5353` listener 的 `Address already in use`，但 supervisor 会跳过冲突的默认 listener，其他目标不再因它失败；这属于可容忍的环境噪声，不再是当前测试 blocker。

## 验证结果

- cargo fmt --all -- --check：通过。
- git diff --check：通过。
- cargo check --workspace --all-targets --offline：通过。
- cargo clippy --workspace --all-targets --offline -- -D warnings：通过。
- cargo test -p yuhaiin-runtime --all-targets --offline：265 passed。
- cargo test -p yuhaiin-protocol --all-targets --offline：128 passed，2 ignored；H2 tunnel 测试已在独立 artifact 中继续通过，Go interop fixtures 继续按环境条件 ignored。
- cargo test -p yuhaiin-store --all-targets --offline：141 passed，5 ignored；cross_process：6 passed，1 ignored。
- cargo test -p yuhaiin-chain --all-targets --offline：20 个 crate tests passed；p0/http2/standalone integration tests passed，既有 interop/netns 条件测试继续 ignored。
- cargo test -p yuhaiin-core --all-targets --offline：43 passed；nat_process：1 passed。
- cargo test -p yuhaiin-dns --all-targets --offline：54 passed。
- FakeIP 相关 store tests 随 `cargo test -p yuhaiin-store --all-targets --offline` 通过：141 passed，5 ignored；cross_process：6 passed，1 ignored。
- cargo test -p yuhaiin-tun --all-targets --offline：73 passed。
- cargo test -p yuhaiin-trie --all-targets --offline：38 unit tests、8 p0 tests passed；ondisk benchmark completed，build 约 1.33s、HWM 增量约 9.1 MiB。
- API 单元测试：53 个测试在 RUST_MIN_STACK=16777216 下全部通过。
- API service binary tests：14 passed；API contract tests 4 passed。
- API `service_chain` 默认并行进程级测试：33 passed，1 ignored；串行复跑同样通过。
- API `wireguard_chain` 串行进程级测试：3 passed。
- workspace 目标包含 9 个 doh-tls integration tests 和已存在的 legacy fixture ignored test；runtime 全目标测试均通过。
- `RUST_MIN_STACK=16777216 cargo test --workspace --all-targets --offline --no-fail-fast -- --test-threads=1`：串行全量通过；可运行测试全部 passed，剩余均为既有 ignored/environment-gated fixtures。
- 默认并行 workspace 运行时，service-chain 的固定端口和共享数据库竞态已消除；宿主已有 `1080/5353` listener 仍可能产生可忽略的默认 listener 日志。

## 持续约束（非未完成项）

本轮没有发现必须继续处理的结构性遗留：没有生产文件超过 1,000 行，也没有未拆分的职责混合模块。后续维护只需遵守已经落地的扩展点：

1. 新增 API operation 时扩充 RpcOperation；settings 继续经过 canonicalize，异构 Go payload 继续限制在 raw/extra boundary。
2. 新增 outbound protocol 时扩充 ProxyPlan/factory，并覆盖 NetworkSplit 与 top-level 两类路径。
3. 新增 route matcher 时扩充 route_expressions 中间模型，不绕过 RuleVariant 直接在 builder 中增加分支。
4. 新增 resolver policy 时扩展 ResolverVariants，不重新引入 parallel maps。
5. service-chain 已使用子进程自选端口和按绑定地址隔离的 fixture namespace；宿主已有 `1080/5353` listener 产生的日志仍是环境噪声，不影响测试结果。

## 审计结论

本轮已经完成从“多个高风险 God module”到“可局部审查的生产模块”的结构性改进，并补上了 API operation、outbound protocol plan、route expression discriminator、resolver variants、monitor persistence/projection、store snapshot/repository boundary、Go endpoint/TLS compatibility boundary、Yuubinsya session、latency、chain、core proxy、DNS、resolver、data-plane、H2 tunnel、API service、statistics/migration、VMess、trie、update、TUN packet、inbound UDP boundary 和 node-selection lifecycle。生产结构层面已收敛，相关 workspace 进程级集成目标也已通过；当前没有必须留给下一轮的审计修复项。
