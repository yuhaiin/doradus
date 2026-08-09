# yuhaiin-rust 实现清单

这份清单和 `MIGRATION.md` 配套使用。`[x]` 只表示该项已经有代码和自动化测试；`[~]` 表示设计已经确定但尚未完成实现；`[ ]` 表示尚未开始或仍有未解决的验收项。

更新时间：2026-08-09

## 当前进度

- [x] 建立 Rust workspace 与无平台依赖的 `yuhaiin-core`
- [~] 建立 `yuhaiin-chain`：配置解析、纯 Rust TLS、HTTP/2 CONNECT、Yuubinsya TCP/UOT 组合，并已接入统一 `AsyncProxy`；fixed endpoint pool、多 stream、同 endpoint 多连接、stream 上限、idle 回收、应用层 drain、连接级 relay shutdown/EOF、UOT coalesce、bounded retry/replay、Ping cache、断连后有限次重建、peer GOAWAY 观察与 pool replacement、TLS/H2 listener、Yuubinsya 服务端 dispatcher、同 migrate ID 的上游 datagram 复用、服务端并发 endpoint demux、真实 TLS/H2 多连接迁移、连续两次 UOT stream loss 后第三次迁移成功、达到重连上限后有界失败、datagram close 取消 pending recv/send/reconnect、隔离 network namespace 内 0/25/50/75/100% kernel loopback loss、可复现随机 loss state machine、发送侧有界重连、`ChainRuntimeStats`/Prometheus pull snapshot 和 TLS identity pool isolation 已完成；client-side 主动 GOAWAY frame 因 h2 公共 API 限制接受为非阻塞延期，application-level drain 已满足当前使用
- [~] WebSocket transport：共享 core byte-stream adapter、standalone inbound、WebSocket+HTTP/2 inbound，以及 `fixedv2 -> websocket -> http2 -> yuubinsya` outbound loopback、Go 实例级互操作和 TLS+WebSocket 组合已完成；inbound 已兼容 Go `early_data: base64`（有界 2048 字节首包注入并返回 `early_data: true`），仍需补 outbound lazy early-data、子协议等低频兼容边界
- [x] 实现域名 Trie、IPv4/IPv6 CIDR LPM Trie、组合查找
- [~] SQLite 配置/状态存储（rusqlite 0.40 + bundled SQLite；generic KV、事务、重启读回、typed proxy/router/DNS/TUN/NAT/MaxMind repository、schema v3、route geo_country、route_settings runtime writeback、Go v5 未建模 telemetry 保留、Go v6 minimal/production-shaped 双栈 snapshot import、Go inbound/node/tag/resolver/route-rule/route-list compatibility views 的结构化读写回、WAL/NORMAL、busy_timeout、有限 busy/snapshot retry、并发 file connection writer、按数据库路径串行化 startup/migration/quick_check、已提交 WAL 恢复、未提交事务 force-stop 恢复、损坏文件 fail-closed、Go import 失败回滚/修复重试、malformed/negative Go schema version 与非法 Go JSON fail-closed、同名 legacy table 保留和字段差异报告、8 writer × 32 条与 4 reader × 24 次 reopen 压力、8 个独立子进程并发初始化/写入、12 个 batch writer + 6 个 reader 的跨进程 WAL 压力、跨进程未提交事务 force-stop 恢复、typed migration 事务回滚/列名/声明类型/可空性/主键/索引 contract 校验、未来 schema fail-closed、NAT full-cone 缺省/删除兼容、Go exporter manifest/hash 和 Rust CLI 强制校验已完成；更多真实生产库快照已移入 P-END）
- [x] SQLite 后端决策：已停止 fsqlite 实验后端；在同一份真实 Go v5 FTS-free snapshot 上，rusqlite bundled SQLite 已完成文件复制、WAL/NORMAL 配置、schema/row 查询和资源 probe。当前生产 adapter 只暴露本地 typed wrapper，`libsqlite3-sys` 是明确批准的 bundled SQLite 例外，不再把 fsqlite 作为待选生产依赖。
- [~] FakeIP IPv4/IPv6 池、独立 cursor/key namespace、旧数据 snapshot 导入、cursor 与重启恢复、释放后的磁盘反向映射清理、A/AAAA/PTR/HTTPS/SVCB DNS answer transform、纯 owner-future 形态的 `FakeIpAsyncDnsHandler` 和支持双栈合并的只读 `FakeIpView` 已完成；本轮补齐 typed `fakeip_entries`/`fakeip_cursors`、family/prefix 隔离、TTL 过期回收、容量 LRU 复用、延迟 touch flush、生产形态 Go v6 双栈 row/cursor 读取、IPv4/IPv6 对称的版本化 Go Pebble NDJSON 解析与事务导入、force-stop 未提交行恢复、4,096 次唯一域名 allocate/release 文件增长 soak、双栈各 1,024 次 soak，以及显式 ignored 的 8,192 次双栈 allocate/release + 16 次数据库重开长 soak；新增由当前 Go `sqlite.Open` 全新 bootstrap 生成的原生 schema v6 双栈 row/cursor direct-open 回归；更多真实生产 snapshot 已移入 P-END
- [~] 连接观测扩展字段：共享 `FlowContext` 已保留 Go 兼容的 `hosts`、`tlsServerName`、`httpHost`、`interface`、`outboundGeo` 契约；core sniffer 已按 Go 规则解析 TLS ClientHello SNI 和 HTTP Host，共享 TCP relay 以 55ms 有界窥探并回放首包，覆盖 HTTP/SOCKS/Yuubinsya/Trojan/VLESS 等 raw relay，且在 `FlowObserverGuard` 建立前写入 monitor。hosts resolver source、实际 socket interface 和 selected outbound Geo 仍需由对应 resolver/socket/geo adapter 提供真实来源，不能用伪造值填充
- [~] DNS resolver/server、UDP、TCP fallback、DoH/DoT（wire、Go resolver runtime transport 解析、统一同步/异步 `DnsResolver` facade、同步/异步 UDP client/server、纯 Tokio 异步 RFC 1035 TCP client/handler/server、持久 TCP connection 多 frame、并发 connection accept、异步 H2 DoH query adapter、RFC 1035 TCP/DoT length-prefix client/server、`AsyncUdpDnsHandler` packet adapter、`AsyncUdpDnsServer`、A/AAAA/PTR/HTTPS/SVCB query decode/response encode、未知 SvcParam 保留、同步/异步 handler boundary、policy、owner-future cancellation、异步 DNS upstream timeout、HTTP/2 DoH framing、`H2DohDnsHandler` packet adapter、TTL/容量 DNS cache、可复用 `HostsTable` A/AAAA override、同步/异步 hosts handler、TUN DNS hijack 和 FakeIP 组合闭环已完成；runtime TCP resolver 已切换到 `AsyncTcpDnsClient`，不再为每次 TCP fallback 占用 `spawn_blocking` 线程；`yuhaiin-runtime` 新增可注入 TLS/proxy connector 的 `H2DohResolverFactory`，以及复用 RustCrypto TLS dialer 的 `RustCryptoH2Connector`/`RustCryptoDohResolverFactory`/`RustCryptoDotResolverFactory`/`RustCryptoResolverFactory`，后者可在同一 registry 中混用 DoH 与 DoT；真实 TLS/H2 DoH、TLS/DoT framing、证书/ALPN/HTTP 状态/content-type/响应超时和混合 registry 回归已通过；DoQ/DoH3 和 P2 平台路径仍待补
- [x] Router：域名规则、CIDR 规则、country Geo rule、优先级、不可变 snapshot 发布/回滚、失败热更新保留旧 snapshot、resolver policy 应用、FakeIP 生产 dispatch 和基于 `RouterRuntime` 的动态 proxy selector 已完成；8 个 reader 各 50,000 次 lookup/selection 与 50,000 次 publish 的长压力回归已通过
- [~] Proxy：direct、drop、fixed、HTTP proxy、SOCKS4A/SOCKS5、Shadowsocks AEAD TCP + `obfs_http` outbound、ShadowsocksR auth_aes128_md5 TCP/UDP、Trojan TCP/UDP ASSOCIATE、VLESS TCP/UDP、VMess modern AEAD TCP/UDP、同步 connector 的 async blocking boundary、统一 stream/datagram/ping/close 契约、connect/read/write/idle timeout、bounded output backpressure、graceful/force close、backpressure 时显式关闭底层 transport、关闭后拒绝新 flow 和 `tls-rustcrypto` provider 已完成；`yuhaiin-protocol` 统一放置 Shadowsocks/Trojan/VLESS/VMess/ShadowsocksR wire codec、HTTP obfuscation、可组合 outbound wrapper 和 TLS/WebSocket transport，`fixedv2 -> TLS -> Trojan`、`fixedv2 -> TLS -> Shadowsocks`、`fixedv2 -> obfs_http -> Shadowsocks`、`fixedv2 -> WebSocket -> VLESS` 与 `fixedv2 -> WebSocket -> VMess` 已接入 runtime；Shadowsocks 的 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305、Go-compatible MD5 password KDF/HKDF-SHA1 framing 已通过 Rust codec 和 Rust client→Go server 互操作，`obfs_http` HTTP Upgrade 请求/响应剥离已通过 Rust 单测和 Go `NewHTTPOBFS` wrapper 互操作，ShadowsocksR 的 auth_aes128_md5、AES/ChaCha 流密码和 Go client→Rust wire server 互操作已完成，VLESS v0 TCP/UDP framing 已通过 Rust client→Go server 互操作，VMess modern AEAD 请求/响应/分块 framing 已通过 Go client→Rust wire server 互操作；新增 `BaseProxyConfig` 工厂统一构造 direct/drop/fixed/HTTP CONNECT/SOCKS5/native Yuubinsya UDP，Go `nodes_v2` 可转换为保留 tagged layer 的 proxy runtime snapshot，Go fixed/fixedv2 字面量地址可转换为现有 chain 的 host/port 端点，`fixedv2 -> yuubinsya` 纯 UDP 节点会复用同一 resolver 构造认证 datagram，`parse_go_node` 与 `ChainClient::from_go_json`/`ChainProxy::from_go_json` 已能把真实 Go tagged node payload 接入 fixedv2 -> TLS -> HTTP/2 -> Yuubinsya 链，并在连接时异步解析 fixed 上游域名；core 新增 hosts→upstream resolver layer，store 新增双栈 FakeIP resolver，`yuhaiin-runtime::RuntimeBuilder/RuntimeSnapshot` 已把它们和 Go compatibility proxy records 组合，并可用同一 resolver 构造 direct/HTTP/SOCKS5/native UDP/chain proxy；`RuntimeSnapshot::build_proxy_selector` 已把 shared proxy records 组装为可刷新 TUN selector，空 direct/bypass/drop 使用内置安全实现，空 proxy 明确 fail-closed；`RuntimeController` 会在发布新 snapshot 前预构建并原子替换已注册 selector，代理构建失败时保留旧 snapshot；新增 `ResolverTransportFactory` registry，内置 System/UDP/TCP，按 resolver ID 生成独立 wrapped resolver；route rule 的 domain/CIDR、action、network/port、resolver policy 已编译进 `RouterRuntime`，route settings 可按 direct/proxy mode 选择 resolver；query-level fallback、构建失败策略（fail-build/keep-unavailable）和同一 store 的 snapshot reload 回归已完成，不支持的旧 matcher fail-closed；DoH/DoT 已有直连 RustCrypto TLS/H2/TCP connector，同时保留代理/自定义 bootstrap 的注入式 connector；基础 proxy builder 已提供 `to_base_proxy_config_with_resolver`，同时保留系统 `ToSocketAddrs` 兼容入口；HTTP/SOCKS4A/SOCKS5/Shadowsocks/`obfs_http`/Trojan/VLESS/VMess/ShadowsocksR/fixed/drop、HTTP/2 pool、多 stream、多连接、idle/drain、native UDP wrapper、Ping cache 与 Yuubinsya TCP/UOT 均有 fixture；SOCKS4A 独立 inbound 与 mixed 分派已通过真实 loopback→shared outbound 回归；client-side GOAWAY 已接受为非阻塞延期，ShadowsocksR auth_chain、tls1.2_ticket_auth、`http_simple/http_post/random_head`、legacy alter-id、QUIC/WireGuard/Reality/Mux 和完整平台关闭 parity 仍待补
- [~] Yuubinsya：认证 UDP、UOT framing、bounded coalesce（实际 ChainUotSession 由 owner flush task 低流量及时排空）、bounded retry/replay、migrate id codec、同步/异步 TCP session、native UDP client/server socket、Ping client/server session、异步 UOT handshake/frame、可注入上游的服务端 TCP/Ping/UOT dispatcher、TLS/H2 listener 已完成；客户端/服务端 datagram 已验证断链后复用 migrate ID、首帧写入后响应丢失仍能重放、真实 TLS/H2 多连接并发迁移、连续两次 UOT stream loss 后第三次迁移成功、达到重连上限后有界失败、反序回包、服务端并发 stream 按 endpoint 分发、server close 唤醒 pending stream、pending datagram close cancellation、隔离 user namespace 的 0/25/50/75/100% kernel loopback loss/recovery、可复现随机 loss state machine、异步 frame reader 的 512 个有界随机/截断样本不挂死、retry queue frame/byte bound 与精确确认、随机 wire 输入不 panic、512 个 IPv4/IPv6/域名多帧序列和全截断边界回归；新增真实 Go fixed+Yuubinsya client→Rust server 互操作验收，覆盖 TCP/UOT/native UDP/Ping；Rust Yuubinsya inbound 的 native UDP 使用 Go 默认的无 SOCKS5 prefix 格式；client-side 主动 GOAWAY 因 h2 公共 API 限制接受为非阻塞延期，不影响当前使用
- [x] NAT：按 source/migrate ID 的 endpoint-independent full-cone mapping、任意外部源回包、真实本地 translated endpoint、connection tracking、idle timeout、touch、sweep、显式 close 和 UDP relay 已完成；forward/reverse index 使用单一原子状态锁，TUN proxy 按 source 聚合 UDP 上游 datagram，同 source 多目标共享 mapping，真实 datagram 建立后会 rebind translated endpoint，响应 endpoint 做反向 flow 选择，dispatcher 写失败、runtime drop、finished TCP task、UDP input/output backpressure、128 次双目标长 flow、32 轮双目标 transport error、512 轮多目标/多 peer full-cone matrix、6 source × 256 轮多 source full-cone matrix、16 代 × 256 轮反复创建/释放 relay 的 full-cone soak、真实 Direct UDP + smoltcp TUN 的 64 轮双目标/未预授权 peer 回包、relay drop RAII 清理和 source sweep 会清理整个 binding；多 task abort、真实 UDP socket 关闭竞态、runtime 重建、同步 DNS task owner 清理、`NatStats`/Prometheus pull snapshot，以及真实跨进程 worker 的未预授权 peer 回包、force-stop 后端口重绑和第二代 runtime 重建已有回归；`tun-routes` 已加入可注入 route backend、反向 rollback、失败删除重试、幂等 close、Linux 纯 Rust netlink backend、capability probe、真实设备 shutdown、SIGKILL route/device 清理和多进程同名 TUN 独占/重启回归
- [~] TUN：`tun-rs AsyncDevice + smoltcp` 单一路径、TCP/UDP dispatcher、异步 proxy bridge、DNS hijack、Router selector、FakeIP reverse lookup、NAT tracking、`run_dispatcher_until` 生命周期 runner、可注入 route lease/rollback、`open_with_routes` 启动失败回滚、解析后的设备名和显式 `TunRuntime::shutdown` 已完成（不并行实现 tun2socket）；Go `inbounds_v2` 的 `network.type=empty` + `protocol.type=tun` 现在是主配置源，解析 `tun://` 名称、portal、routes/excludes，旧 `tun.runtime` 仍兼容回退；桌面 binary 已不再单独启动 TUN，`yuhaiin-runtime::inbound::run_until` 与 SOCKS5/HTTP/Yuubinsya listener 共同拥有 TUN 的启动、reload、shutdown；accepted flow 使用 `FlowObserverGuard`，强制 abort 也会回收 monitor live connection/history。Podman 特权无网络容器已通过真实 TUN 创建/关闭和 route smoke；Android/iOS host 可传入 `TunRuntime::from_async_device`；Linux 设备消失/namespace teardown 和 Android/macOS fd 实机路径仍待补
- [~] MaxMindDB 查询（reader、坏库错误、IPv4-mapped IPv6 归一化、共享只读句柄和 `GeoLookup` route boundary 已接入，`RuntimeBuilder/RuntimeSnapshot` 已按 store metadata 加载 reader 并注入 route snapshot）；真实 GeoLite fixture、下载校验、并发 reader 热替换和重启恢复仍待补
- [x] Linux namespace/容器网络验收（TUN 创建、sysfs 存在、真实 ICMP ingress、smoltcp ICMP socket、软件 checksum 和 kernel ping echo 已通过）
- [ ] Android/macOS 平台构建和权限验收
- [x] 第一版管理面与可执行服务：`yuhaiin-runtime` 提供与 `yuhaiin-react` 现有 client 对齐的 `/api/v2/rpc/<operation>`，可管理 nodes/outbounds、inbounds、resolvers、hosts/FakeDNS、route config/lists/rules/tags、settings 和 TUN 配置；`yuhaiin` binary 负责 SQLite、runtime reload、HTTP listener、可选 DNS UDP server 和 `tun-rs + smoltcp` 数据面启动
- [x] Inbound 运行时统一 owner：`yuhaiin-runtime::inbound::run_until` 同时拥有 TUN、TCP/HTTP/WebSocket/HTTP2 和 UDP listener；accepted TCP/WebSocket flow 由 listener `JoinSet` 管理，reload/shutdown/abort 不遗留 live connection；`FlowObserverGuard` 覆盖强制取消后的 monitor close/history/SSE/traffic，Yuubinsya HTTP/2 多 stream 共享 listener 级 server/migrate session
- [x] 管理面真实运行验收：Podman Debian testing host-network smoke 已验证 HTTP inbound→direct outbound、SQLite restart readback、live connections 查询、数字 ID close、connections SSE 初始/新增/移除事件，以及 inbound PUT reload 后旧端口关闭、新端口可用；临时目录统一使用 `~/.cache`，不使用 `/tmp`
- [x] 统计持久化生命周期：`ConnectionMonitor` 拥有可等待的 SQLite writer，服务在 inbound/DNS owner 收敛后执行 final flush 并等待 writer，再进行 backup restore；单测和 Podman 立即退出/重启 smoke 均验证最后一条 history、traffic 不依赖 2 秒周期即可读回
- [x] TUN inbound 服务级验收：管理 API 写入 Go `inbounds_v2` 的 `empty/tun` 后，privileged `--network=none` runtime 通过 `inbound::run_until` 真实创建命名 TUN；`/sys/class/net`、SIGTERM graceful shutdown、设备消失和同名设备重新打开均通过，supervisor 失败也会进入 monitor 日志
- [x] 连接元数据契约：普通 HTTP/SOCKS5/Yuubinsya inbound 的 `component` 保持空值，TUN flow 才输出 `component=tun` 并默认 `inbound=tun/inboundName=TUN`；monitor 序列化与 TUN 上下文注入均有回归测试
- [x] 路由解释元数据链：`RouterRuntime` 会把选中的 Go rule/tag/host-process list/Geo 写入共享 `FlowContext`，runtime selector 提供统一 `route_context` 钩子，HTTP/SOCKS4A/SOCKS5/Trojan/VLESS/Yuubinsya/TUN 在代理选择前调用；monitor 与 `route.rules.test` 输出 Go 兼容的 `matchHistory`/`lists`/`resolver`/`geo`，并有 trie、route compiler、monitor 单测
- [x] FakeIP/TUN flow 元数据链：TUN runtime 在 snapshot 边界生成 SQLite-free 双栈 `FakeIpView`，新 flow 按目的 IP 恢复原始域名后再执行 Router，并在 `connections` 中保留 `fakeIp`；覆盖 FakeIP pool snapshot、controller runtime 和 monitor 序列化回归
- [~] 连接观测扩展字段：`FlowContext`/monitor 已提供 Go 字段契约；共享 TCP relay 已完成 Go 兼容的 TLS SNI/HTTP Host bounded sniff、55ms 超时和首包回放，并在 connection open 前记录 `tlsServerName/httpHost`。hosts 来源、实际 socket interface 和 outbound Geo 仍待接入对应 resolver/socket/geo 生命周期

## 未完成项与下一阶段计划

以下条目按迁移目标拆分。`[~]` 表示已有可复用底座但还不能视为功能闭环；`[ ]` 表示尚未实现。每项都写明完成条件，后续完成代码后直接勾选并补充测试命令。

### 未完成项总览（执行入口）

下面的条目是当前仍不能标记为完成的全部事项；模块章节中的说明必须与本表同步。Full Cone NAT 是硬约束：任何后续 NAT、TUN、代理或平台实现都不得重新引入基于“已见过的远端 endpoint”才能接收回包的受限映射。

> **P1 结论（2026-08-08）：** resolver/proxy chain、FakeIP/SQLite、DNS/TUN、Router、Full Cone NAT 和 Yuubinsya 的原有业务闭环均已完成并通过关联测试。Go 自定义 AEAD transport 是本轮新增的 P1（~）兼容项，仍需完成 Go UDP 实例互操作等验收。下表保留 P1 条目作为迁移证据索引；其余内容已经明确标为 P2 或 P-END，不再阻塞进入 P2。

| ID | 优先级 | 未完成事项 | 当前状态 / 完成门槛 |
| --- | --- | --- | --- |
| P1-H2 | P-END（记录） | HTTP/2 client-side 主动 GOAWAY | 已接受延期且不阻塞 P1：本地锁定的 `h2 0.4.15` 源码只在 server builder 暴露 GOAWAY 发送 API，client builder 没有主动 GOAWAY 方法；当前 application-level drain、peer GOAWAY 观察和连接重建已满足使用需求。未来只有公开 API 支持后才重新评估，不使用私有 API/raw frame hack。 |
| P1-PROXY-WS | P1（~） | WebSocket inbound/outbound 与 HTTP/2 组合 | 共享 `yuhaiin-core::websocket::WebSocketIo` 已接入 runtime inbound 和 chain outbound；standalone WebSocket、WebSocket+HTTP/2 inbound、Go client 实例互操作、TLS+WebSocket、`fixedv2 -> websocket -> http2 -> yuubinsya -> direct` outbound loopback 已通过。inbound 已兼容 Go `early_data: base64`：RawStd base64 首包有界解码（最多 2048 字节）、注入协议读取流并返回 `early_data: true`，已有握手/分片读取回归；outbound lazy early-data、子协议仍待补。 |
| P1-PROXY-AEAD | P1（~） | Go 自定义 AEAD transport inbound/outbound | `yuhaiin-protocol::aead` 已实现 P-256/Ed25519 handshake、ChaCha20/XChaCha20 stream、Go nonce+ciphertext UDP packet 和可组合 `AeadProxy`；store/runtime 已接入 `fixedv2 -> aead`、AEAD SOCKS5 TCP/UDP inbound，以及 AEAD 外层 Yuubinsya UDP。Rust 本地 TCP/UDP、AEAD→SOCKS5 inbound→direct outbound 和 Go↔Rust TCP/UDP 双向实例互操作已通过；更多 TLS/HTTP2/组合场景、API/reload 与平台验收仍待补。 |
| P1-PROXY-TROJAN | P1（~） | Trojan protocol layer | `yuhaiin-protocol` 已实现 Go-compatible lowercase SHA-224 token、TCP CONNECT、UDP ASSOCIATE frame、inbound/outbound wrapper；runtime 已接入 `fixedv2 -> trojan` 与 `fixedv2 -> tls -> trojan`，并通过 TCP/UDP inbound→direct、outbound loopback 和 config construction 测试。MUX command、Go 实例级互操作和更完整证书 fixture 仍待补。 |
| P1-PROXY-SS | P1（~） | Shadowsocks AEAD protocol layer | `yuhaiin-protocol` 已实现 Go-compatible MD5 password KDF、HKDF-SHA1 subkey、AES-128-GCM/AES-256-GCM/ChaCha20-Poly1305、TCP record framing 和 UDP packet codec；runtime 已接入 `fixedv2 -> shadowsocks`、`fixedv2 -> tls -> shadowsocks` 和 `fixedv2 -> obfs_http -> shadowsocks`，Rust client→Go server 与 Go `NewHTTPOBFS` wrapper 互操作已通过。更高阶链组合和 UDP obfs 仍需按 Go 配置继续补齐。 |
| P1-PROXY-SSR | P1（~） | ShadowsocksR protocol layer | `yuhaiin-protocol` 已实现 `auth_aes128_md5` 的认证首帧、后续分帧、UDP packet、AES-128/192/256 CFB/CTR/OFB、ChaCha20/ChaCha20-IETF/none 以及 `origin/plain`，runtime/store 已接入 `shadowsocksr` tagged layer；Rust 单测和 Go client→Rust wire server 互操作已通过。`auth_chain_*`、`auth_sha1_v4`、`tls1.2_ticket_auth`、`http_simple/http_post/random_head` 等变体仍显式 unsupported。 |
| P1-PROXY-OBFS | P1（~） | Shadowsocks HTTP obfuscation layer | 独立 `yuhaiin_protocol::http_obfs::HttpObfsProxy` 已实现 Go simple-obfs 的 HTTP Upgrade 首包、响应头剥离、跨 read 分片缓存和 bounded header；runtime 支持 `fixedv2 -> obfs_http -> shadowsocks`，并通过 Go `NewHTTPOBFS` wrapper wire 互操作。该层按 Go 语义只提供 outbound TCP，SSR `http_simple/http_post` 不复用此格式。 |
| P1-PROXY-VLESS | P1（~） | VLESS protocol layer and transport composition | `yuhaiin-protocol` 已实现 VLESS v0 UUID、TCP CONNECT、UDP-over-TCP length framing、inbound/outbound wrapper；runtime 已接入 VLESS TCP/UDP 入站到共享 outbound、`fixedv2 -> vless`、`fixedv2 -> tls -> vless` 和 `fixedv2 -> websocket -> vless`，VLESS wire 已通过 Rust client→Go server 互操作，WebSocket byte-stream 已有真实 loopback。仍需补 Go VLESS+WebSocket 组合互操作、HTTP/2 transport 变体和更高级 flow/XTLS 语义。 |
| P1-PROXY-VMESS | P1（~） | VMess modern AEAD protocol layer and runtime composition | `yuhaiin-protocol` 已实现 alter-id=0 的 AEAD request/response header、AES-128-GCM/ChaCha20-Poly1305/none chunk stream、domain/IPv4/IPv6 地址、固定目标 UDP packet mode 和 `fixedv2 -> vmess`、TLS、WebSocket runtime 组合；Go `nodes_v2` 的 `id/aid/security` 已接入 compatibility parser，Go client→Rust wire server 已实际完成 AES-GCM TCP 请求/响应/分块互操作，UDP 双向 framing 和独立方向计数器已有单元回归。legacy alter-id 和更复杂 transport 变体仍显式 unsupported。 |
| P1-CLOSE | P2（平台验收） | proxy/Yuubinsya 完整 close parity | P1 业务闭环已完成：graceful/force close、取消、relay shutdown、关闭后拒绝新 flow、低流量 coalescing flush、backpressure 指标、真实 loopback TCP socket teardown 和异常/半关闭回归均已通过；TUN 以及 HTTP/SOCKS5/Yuubinsya 入站的 TCP/UDP flow 都订阅管理面的 close request，关闭后会回收 relay、datagram 和 live connection；连接级主动 GOAWAY 仍受 h2 API 限制。剩余仅是 Android/macOS 目标平台 parity 验收。 |
| P1-PROXY-RESOLVER | P1 | 运行时统一 resolver 组装 | core 的 hosts layer、store 的双栈 FakeIP layer、`ResolverTransportFactory` registry 和 `yuhaiin-runtime::RuntimeBuilder/RuntimeSnapshot` 已完成；内置 System/UDP/TCP，route rule→`RouterRuntime` 编译、route settings 按 direct/proxy mode 选 resolver、query-level fallback、构建失败策略和同一 store 的 reload 回归已完成，chain/base proxy 共享同一个 `Arc<dyn AsyncIpResolver>`；`RuntimeSnapshot::build_proxy_selector` 已完成 direct/proxy/bypass/drop 到 TUN selector 的实际组装，缺失 proxy 不会静默直连；`RuntimeController` 已支持注册 selector，并在新 snapshot publish 前完成代理实例准备与原子替换，失败时保留旧 snapshot；新 Rust store 也会创建 `nodes_v2`、`inbounds_v2`、`node_tags_v2`、`resolvers_v2`、`route_rules_v2`、`route_lists_v2` compatibility 写表，fresh DB 可直接接受 typed Go record 写入；`RuntimeHandle` 增加 revision、条件 publish 和原子 `load_with_revision`，`RuntimeController` 统一配置 mutation→持久化→串行 reload，并提供 `last_reload_error()` 给未来管理状态接口，防止并发 HTTP reload 的陈旧构建覆盖较新 snapshot，也避免管理接口读到不匹配的版本；`RustCryptoResolverFactory` 可在同一 registry 中按配置混用 DoH/DoT，两个 direct data plane 均覆盖 resolver 级超时；DoQ/DoH3 仍待实现或由上层注入。 |
| P1-FAKEIP | P1 | FakeIP 生产 schema 与长时间回收 | typed `fakeip_entries`/`fakeip_cursors`、family/prefix 隔离、TTL、容量 LRU、touch flush、生产 Go v6 双栈 row/cursor 读取、IPv4/IPv6 版本化 Go Pebble NDJSON 解析与事务导入、重启和 force-stop 回归、IPv4/IPv6 各 1,024 次 allocate/release 双栈文件增长 soak，以及显式 ignored 的 8,192 次双栈 allocate/release + 16 次数据库重开长 soak 已完成；本轮用实际 Go v5→v6 migration snapshot 验证 15,483 条 IPv4 + 11,956 条 IPv6 mapping 和双 cursor 读取，并用当前 Go 全新 bootstrap 的原生 schema v6 验证双栈 mapping/cursor、node/resolver/route direct-open；legacy marker 现于同一 `BEGIN IMMEDIATE` 事务内原子占用，重复或冲突快照不会覆盖已导入状态；更多未经本地升级的真实 Go v6 生产 snapshot 已移入 P-END。
| P1-DNS-TUN | P1 | 真实 TUN DNS 生产组合 | `tun-fakeip-smoke` 已在特权隔离容器完成 `H2DohClient → FakeIpAsyncDnsHandler → SQLite FakeIP pool → 真实 TUN UDP → DNS 回写`；`H2DohDnsHandler` 现在可把原始异步 DNS packet 直接接到 HTTP/2 DoH，并保留客户端 transaction ID；新增 `dns_hosts`、`dns_settings`、`dns_fakedns_lists`、`route_settings` compatibility 读取，`load_go_fakeip_runtime_config()` 可将 Go 双栈 CIDR 配置还原为 FakeIP pool 起止地址，`load_go_route_runtime_config()` 保留 UDP FQDN 的 `0/1/2` 枚举语义，core `HostsTable` 提供同步/异步静态覆盖层；支持配置注入静态 A/AAAA 与 FakeDNS 范围；pending async resolver、upstream timeout、Full Cone flow cleanup、shutdown、无 `CAP_NET_ADMIN` 创建失败、失败后特权重开、设备消失后的 route install fail-closed，以及 route 配置失败后的设备回滚/同名恢复均已有回归；剩余是 P2 平台路径。 |
| P1-DB | P1 | SQLite 兼容性收尾 | Go v5 未建模 telemetry 保留、Go v6 typed compatibility view 与 Go v1 `go_legacy_*` 显式升级/字段映射、未知 JSON 保留、`dns_settings`/`dns_fakedns_lists`/`route_settings` 等旧配置读取、所有 Go v6 compatibility JSON 边界（nodes/inbounds/node-tags/route-lists）fail-closed、失败回滚/修复重试、归档源表和 `_v2` 写回策略、健康原生 Go v5/v6 数据库直接打开、可供 reload/HTTP 管理层复用的 `ConfigStore::status()`、Go FTS-free consistent snapshot exporter、版本化 manifest/hash、Rust `install_go_snapshot` staging/checkpoint/atomic rename 首次迁移入口、Rust state 的一致性 backup/restore、按 freelist 阈值触发的 compact、Rust-owned typed schema 的声明类型/可空性/主键/索引 contract 校验已完成；后端已改为经过验证的 `rusqlite` bundled SQLite。当前真实 Go v5/v6 数据库直接打开回归已加入 ignored 验收；另有实际 415,334,400 bytes Go v5 snapshot 经 Go exporter 导出、manifest 校验、Rust 原子安装并通过读回验证（206 nodes、27,439 FakeIP rows，IPv4/IPv6 两个 cursor）。健康 FTS5 可直接打开；损坏/非一致 FTS5 或带非空 WAL 的源库仍会被 Rust fail-closed；更多生产库 fixture、逐版本异常 migration 注入和未知字段组合已移入 P-END。 |
| P1-NAT-ROUTE | P1 | NAT/TUN 系统资源生命周期 | Full Cone mapping、跨进程 force-stop、端口重绑和第二代 runtime、route lease、真实 TUN shutdown、SIGKILL 清理、无 `CAP_NET_ADMIN` fail-closed，以及多进程 TUN 名称独占/重启均已完成；后续仅保留 P2 Linux 的真实设备 MTU/fragment 矩阵、设备不存在和 namespace teardown 验收。 |
| P-END-DATA | P-END | 更多真实 Go 生产快照与逐版本 migration 故障注入 | 当前功能、兼容 fixture、事务回滚、重启/force-stop 和已有 Go v5/v6 direct-open 验收已足够支撑主线；后续补未经本地升级的生产组合、未知字段样本和逐版本异常注入，不阻塞 P1 业务数据面。 |
| P2-LINUX | P2 | Linux route lifecycle 与能力探测 | TUN namespace 基础验收、无权限 fail-closed、MTU/fragment 单元边界和 Linux `CAP_NET_ADMIN`/tun multi-queue 只读探测已有；仍需真实设备 MTU/fragment 矩阵、设备不存在、namespace teardown 及所有 post-up 失败的反向回滚。 |
| P2-ANDROID | P2 | Android VpnService 路径 | Rust core 已提供 `TunRuntime::from_async_device` 注入边界，Android `/proc` socket→pid/uid/exe matcher 也复用 Linux 实现；仍需 Android target 构建、VpnService fd/JNI 桥接、权限/MTU/IPv4/IPv6 route、前后台切换和强制终止恢复。 |
| P2-MACOS | P2 | macOS utun 路径 | `tun-rs + smoltcp` 的 `aarch64-apple-darwin` core 编译边界已通过，仍需 utun 实机 fd/系统 route、权限/签名/启动卸载、异常退出恢复；上层继续复用同一个 dispatcher。 |
| P2-GEO | P2 | MaxMindDB 生产链路 | `yuhaiin-geo` 已完成：官方固定 GeoLite2 test fixture 覆盖 v4/v6/mapped/miss/坏库，下载长度/hash 校验、目录 fsync + atomic replace、并发热替换、旧 reader 生命周期、启动恢复和 selected-outbound API refresh 均有测试；仅更多真实生产库组合归入 P-END。 |
| P2-SOAK | P2 | 性能、内存、电量与长稳基线 | 仍需 Go/Rust 同场景吞吐、延迟、RSS、分配、wakeups、FakeIP/SQLite 增长、Android 电量和长时间 soak 报告；在报告前不宣称 Rust 性能收益。 |
| P2-AUDIT | P2 | 安全、依赖与发布审计 | 仍需 TLS provider 互操作/证书验证、依赖 license、纯 Rust/C binding、日志脱敏、release profile、交叉编译和 reproducible build 审计。 |
| P2-API | P2 | 管理 HTTP 与前端对接 | 第一版 RPC/前端兼容边界已完成；本轮补充 route-list 内容加载、真实 itemCount/errorCount/preview、HTTP(S) refresh、`~/.cache/yuhaiin-rust/rules` 原子缓存、Go 嵌套 host/network/port/geoip/all/any/not/process/inbound 规则进入 immutable Router snapshot，并通过 runtime/API/本地 HTTP server 回归；`not` 使用 DNF 变体和编译后的域名/CIDR exclusion trie，并有 De Morgan、负 network/port/context 回归；node latency 已接入 proxy-aware HTTP/TCP/IP/STUN；route-list refresh 现在读取 selected node 并经共享 outbound transport 下载，直连兼容入口仍保留；connections close 严格校验 Go 兼容的数字 ID 并能唤醒所有普通入站 relay/UDP flow；traffic/telemetry 现在严格校验 RFC3339 `from/to`、时间范围和 telemetry `limit`，并按持久化小时桶返回范围内数据。仍需平台进程枚举、DoQ latency 和更多真实 Go 生产列表 fixture。 |
| P2-ROUTE-LISTS | P2 | Go route-list 内容与嵌套 matcher parity | 已完成 local/file/cache-remote 内容解析、hosts_as_host、原子 HTTP refresh、缺失列表的 fail-closed 不匹配和 host/network/port/geoip/all/any/not/process/inbound 展开；`not` 已覆盖单 leaf、排除 pattern trie、负 network/port/context 和 `not any` 的 De Morgan 组合；process/inbound 已通过 `FlowContext` 注入式 metadata 参与运行时匹配并有回归；新增可注入 `RouteListTransport`/`ProxyRouteListTransport`，API 刷新会使用 selected outbound，HTTP 下载覆盖解析/分块响应/loopback proxy path。仍需平台进程枚举、真实生产列表格式矩阵和更复杂 proxy/bootstrap 互操作。 |
| P2-BINARY | P2 | 可直接运行的服务进程 | 已完成：`cargo run -p yuhaiin-runtime --bin yuhaiin --all-features` 可启动 HTTP 服务；默认数据库在 `$XDG_DATA_HOME/yuhaiin-rust/state.sqlite` 或 `~/.local/share/yuhaiin-rust/state.sqlite`，测试临时数据使用 `~/.cache`，不使用 `/tmp`；`YUHAIIN_TUN=1` 启用 TUN，`YUHAIIN_HTTP`/`YUHAIIN_DB` 可覆盖监听和数据库路径。 |

### 未完成事项的可执行 checklist

以下是从上表展开的实际待办。完成一项后，同时补充对应命令、环境、结果和限制；没有真实设备或外部条件时，不把“代码可编译”当作平台验收完成。

验证策略：日常改动先跑与改动直接相关的 crate/test filter；跨 crate 的公共接口或迁移契约改动，再跑依赖它的集成测试；只有 schema/存储格式、跨模块协议、发布前或定期验收时才跑完整 workspace。长时间 soak、真实生产 snapshot 和需要特权/网络 namespace 的测试保持显式命令，不作为每次小改动的阻塞项。

当前状态：P1 的 FakeIP、hosts/异步 resolver 基础层、UDP/TCP DNS、Router snapshot、proxy chain、TUN 单一路径、Full Cone NAT、SQLite Go compatibility、`RuntimeBuilder` 组装底座和直连 RustCrypto TLS/H2 DoH/DoT 已有代码与相关测试；`fsqlite` 已明确放弃，配置存储固定使用 `rusqlite 0.40.1 + bundled SQLite`。下面的未完成项只保留 DoQ/DoH3、真实外部数据、目标平台和发布验收，不把已有测试桩或派生 fixture 重复算作完成。

### P1 业务实现结论

按“功能能否工作”而不是“是否已经拿到所有真实设备/生产样本”统计，P1 业务闭环已经完成：FakeIP 双栈、DNS UDP/TCP/DoH/DoT、域名/CIDR Router、direct/fixed/drop/HTTP/SOCKS4A/SOCKS5/mixed/TLS/HTTP2/Yuubinsya TCP/UOT/UDP、单一路径 TUN、endpoint-independent Full Cone NAT、SQLite 配置/状态、Go v5/v6 兼容导入和 runtime reload 均已有实现与关联测试。入站认证语义已按 Go 对齐：SOCKS4A/SOCKS5/HTTP/Yuubinsya 使用 inbound protocol 自身凭据；mixed 入站会在同一 listener 上分派 SOCKS4A、SOCKS5 和 HTTP；HTTP 缺少凭据返回 407，凭据错误返回 403。TCP/UDP 入站在 router 前还会复用纯 Rust `/proc` socket ownership resolver 写入 process/pid/uid，使进程规则、实时 connections 和 block history 能看到与 Go 对应的元数据。`RuntimeSnapshot::new_full_cone_nat()` 还把持久化 Full Cone NAT timeout 接入了 TUN 组装，`RuntimeController::build_tun_proxy_runtime()` 进一步保证 selector、NAT 和 timeout 来自同一个 snapshot。

当前仍标为 `[~]` 的 P1 项，不再表示缺少上述业务代码，而表示目标平台的 Android/macOS 实机 close/权限 parity；h2 公共 API 不支持的 client-side GOAWAY 按明确决策延期，不阻塞使用。未经本地升级的真实 Go v6 生产库、更多异常 migration 注入和低价值边界矩阵统一放在 P-END，不阻塞业务实现。

下一步执行顺序：

1. DoH/DoT 直连数据面已经完成；DoQ/DoH3 按低优先级保留为后续 feature，代理链/自定义 bootstrap 继续走现有注入式 connector。
2. `P-END-DATA` 统一承接未经本地升级的真实 Go v6 生产 snapshot、生产规模字段差异和逐版本 migration 异常注入；已有的 schema 缺列、Go v6 JSON、manifest/hash、非空 WAL 和 staging 失败回滚测试不重复实现。
3. 在拿到 macOS/Android 目标环境后执行 P1-CLOSE-01 的 socket、权限、异常退出和数据库锁 parity；Linux 结果不能替代目标平台验收。当前仅完成 macOS target 的 core/chain 编译边界检查。
5. P1-H2-01 已记录为非阻塞延期：h2 公开 client API 暂不支持主动 GOAWAY，继续使用 application-level drain，不引入私有 API 或 raw frame hack。
6. P2 的 MTU/fragment、GeoLite 热替换、Android 电量和 Go/Rust 性能基线在上述 P1 门槛完成后推进。

本轮 DoH/DoT 验收结果：

- DoH 使用 `application/dns-message` 和 HTTP/2，DoT 使用 RFC 1035 两字节长度 framing；两者复用现有 DNS codec 并保留 transaction ID。
- DoH 已覆盖证书/ALPN/HTTP 状态/content-type/响应超时；DoT 已覆盖真实 TLS 建连、TLS server name 和 framing 数据面。
- DoH/DoT 失败不静默降级为 system DNS；是否使用 `resolver_query_fallback` 仍由 runtime 配置决定，并有失败策略测试。
- 只运行 `yuhaiin-core`、`yuhaiin-runtime`、`yuhaiin-chain` 的相关测试；通过后再更新本表和 `MIGRATION.md`，不默认跑完整 workspace。

#### P1 收尾

- [~] **P1-PROXY-RESOLVER-01：** 已新增 `yuhaiin-runtime::RuntimeBuilder/RuntimeSnapshot`，把 hosts、双栈 FakeIP、上游 resolver、Go route/proxy records 组成可原子替换的 runtime snapshot；`RuntimeHandle` 负责为 TUN、代理和未来 HTTP/reload handler 提供无 DTO 的稳定 `Arc` 读取、原子 publish、revision 条件 publish、原子 `load_with_revision` 和“重建失败/陈旧重建保留旧 snapshot”；新增 `RuntimeController` 统一 `ConfigMutation`/typed repository 持久化、串行 reload、旧 snapshot 保留和 `last_reload_error()` 状态，供未来 HTTP handler 复用；`ResolverTransportFactory` 已提供按 ID 构造 System/UDP/TCP resolver 的 registry，route rule 的 domain/CIDR、action、network/port 和 resolver policy 已编译进 `RouterRuntime`，route settings 可按 direct/proxy mode 选择 resolver，query-level fallback、构建失败策略和同一 store 的 snapshot reload 回归已通过，并可用共享 resolver 构造 direct/HTTP/SOCKS5/chain proxy；新增 `RuntimeSnapshot::build_proxy_selector`/`RuntimeProxySelector`，实际组装 TUN 所需的 direct/proxy/bypass/drop slots，并由 controller 在 publish 前完成已注册 selector 的原子刷新，缺失 proxy fail-closed；新 Rust store 创建全部 Go v6 compatibility 写表，fresh DB 可直接写入 nodes/inbounds/tags/resolvers/route-rules/route-lists。新增 `RustCryptoDohResolverFactory`/`RustCryptoH2Connector`/`RustCryptoDotResolverFactory`，并补充 `RustCryptoResolverFactory` 让一份 persisted resolver list 同时构造 DoH/DoT；真实 TLS/H2 DoH、DoT TCP framing、证书/ALPN/HTTP 错误、resolver 超时和混合 registry 回归已通过；仍待 DoQ/DoH3 数据面验收。
- [x] **P1-NAT-RUNTIME-01：** `RuntimeBuilder` 读取 `nat_config.default` 并把 Full Cone policy 与 idle timeout 放入共享 `RuntimeSnapshot`；`RuntimeSnapshot::new_full_cone_nat()` 可直接为 TUN 创建 `NatTable` 和持久化 timeout，`RuntimeController::build_tun_proxy_runtime()`/`build_tun_proxy_runtime_with_dns()` 在同一 snapshot 下完成 selector/NAT 组装并可注入已有 packet-level DNS handler，遇到 restricted/非法配置 fail-closed。
- [~] **P1-H2-01（非阻塞延期）：** client-side GOAWAY 不影响当前使用；`h2 0.4.15` 没有公开 client API，当前保持 application-level drain、peer GOAWAY 观察和 connection replacement，未来升级 h2 后再评估，不调用私有 API、不手写 raw frame hack。
- [~] **P1-CLOSE-01：** 已补平台无关的真实 loopback TCP 回归：TCP session 半关闭、对端 EOF、重复 shutdown，以及 UOT 对端退出唤醒 recv、重复 shutdown；TCP/Ping/UOT session 的成功 shutdown 现在幂等。`x86_64-apple-darwin` 与 `aarch64-apple-darwin` 的 core/chain `cargo check --all-features` 均已通过，且修复了 Linux-only capability probe import 的 macOS warning；仍需在 macOS/Android 等目标平台实际运行 socket/权限/异常退出 parity，不能用交叉编译结果替代。
- [x] **P1-FAKEIP-01：** 已完成显式 long soak：双栈共 8,192 次 allocate/release，分 16 批、每批重开数据库；正反向映射清空、两个 cursor 可恢复，database+WAL 小于 128 MiB。测试保留 `ignored`，避免拖慢普通 CI。
- [~] **P1-FAKEIP-02：** 已加入小型脱敏 Go v6 edge snapshot，覆盖过期 v4/v6 mapping、空的可见映射池、双栈 cursor 和未知 JSON 字段；另有 legacy v4 未知字段与重复地址冲突 fixture，均已验证 fail-closed/原子失败。legacy v4/v6 marker 检查已移入 typed-row 同一事务，重复 marker 的不同快照也有“不覆盖原状态”回归。真实 Go v5 snapshot、由真实 Go v5 数据经 Go 当前 migration 升级得到的 schema v6 snapshot，以及当前 Go 全新 bootstrap 生成的原生 schema v6 snapshot 均已通过 Rust direct-open；原生 v6 回归读回 1 node、1 resolver、1 route rule、IPv4/IPv6 mapping 和双 cursor，源 hash `53e874f94d1cf081b7915434604be6fcf2ac2e56eebe93d82f761a5c3c32d9a6`（446,464 bytes）保持不变。更多真实生产库组合已移入 `P-END-DATA`。
- [~] **P1-DB-01：** 已新增 Go v5 sparse fixture，覆盖历史 schema、空 telemetry 表、旧 resolver 列、未建模 BLOB 表、未知 JSON 字段，并验证两次 reopen 后数据/空表仍保持；真实 Go v5 数据副本已由 Go 当前 migration 升到 schema v6，再由 exporter 生成 FTS-free v6 snapshot，Rust 读回 206 nodes、27,439 FakeIP rows、双栈 cursor，source 与 output 均 `quick_check=ok`；缓存中的 444,293,120-byte raw Go v6 FTS-free production-shaped source 也已通过只读导入回归，但它仍属于已有 Go v5 数据经当前 Go migration 的派生样本；新增当前 Go `sqlite.Open` 全新 bootstrap 产生的 446,464-byte native v6 direct-open 回归，覆盖 node/resolver/route、双栈 FakeIP row/cursor 和 source hash 不变；Rust state 新增一致性 `backup_to`/`restore_database`，通过 staging、启动完整性校验、原子替换和损坏源保留目标库回归；`compact_if_needed` 仅在 freelist 达阈值时执行 checkpoint/VACUUM。更多真实 Go v6 生产库组合已移入 `P-END-DATA`。
- [~] **P1-DB-02：** 长时间跨进程压力已完成：24 个 batch writer×128 条、10 个 reader×240 次，committed rows、`quick_check` 和 Full Cone NAT 默认值均保持正确；schema v2→v3 的 `geo_country` 增量迁移、Go v1 的 `dns_resolvers`/`route_rules` legacy table rename collision、Go v6 compatibility 表缺列（7 张表逐表矩阵）、Rust base/typed schema 的声明类型、可空性、主键和 FakeIP 索引 mismatch matrix、未知 SQL 列兼容，以及 Go snapshot staging 文件导入失败后的临时文件清理和修复重试都已加入“故障→回滚→修复→重试”回归；本轮又补齐 Go v6 importer 的关键 ID/时间戳 fail-closed、compatibility JSON 读写校验、精简旧表兼容，以及 metadata/migrate 两个版本源逐行校验和一致性检查；更多逐版本 migration 故障点已移入 `P-END-DATA`。
- [~] **P1-DB-03：** 已完成版本化导出 manifest：Go exporter 写出 `<snapshot>.manifest.json`，包含 format/tool version、source schema、FakeIP 行数、移除的 FTS 表、snapshot 字节数和 SHA-256；Rust CLI 强制校验 manifest、长度、hash、非空 WAL、destination 文件和 destination sidecar 保护。fixture 篡改 manifest 会 fail-closed；真实 415,334,400 bytes Go v5 snapshot 和 60,973,056 bytes schema v6 snapshot 均已通过 manifest 校验并安装。新增兼容回归：Go exporter 在没有 FTS 表时写出的 `removed_virtual_tables: null` 仍可被 Rust 接受，同时 exporter 后续固定写 `[]`；snapshot/restore 失败路径不会删除无关 destination sidecar；更多版本/生产组合的迁移故障注入已移入 `P-END-DATA`。

P1 的明确边界：Full Cone NAT、rusqlite bundled 后端、真实 Go v5 FTS-free 导出/安装、真实 Go v5 数据经当前 Go v6 migration 的派生 v6 安装、当前 Go 全新 bootstrap 的原生 v6 direct-open、已有 migration failure matrix 和 Linux 行为回归均属于已完成或已验证范围；更多真实生产库组合和目标平台运行时 close/权限 parity 仍是未完成项；h2 client-side 主动 GOAWAY 已接受为不影响使用的非阻塞延期。后续不得因为 Linux 编译通过、派生 v6 通过或 application-level drain 可用而提前勾选目标平台条目。

#### P2 Linux / 平台

第一版 lite 的主线验收以 Linux `tun-rs + smoltcp` 单队列路径为准；Android/macOS 和极端设备行为是同一数据面的后续平台验收，不阻塞当前 Linux 服务进程和前端管理闭环。

- [~] **P2-LINUX-01：** `TunConfig::mtu` 由 tun-rs 配置，smoltcp ingress/egress 对每个 wire fragment 执行 MTU 边界校验，并分类 IPv4/IPv6 fragment；真实设备上的 kernel fragmentation/PMTU 矩阵仍需目标环境补测。
- [~] **P2-LINUX-02：** route lease、启动失败 rollback、无权限 fail-closed、设备消失和 namespace 基础路径已有测试；外部删除/极端 teardown 矩阵仍需目标环境补测。
- [~] **P2-LINUX-03：** 第一版明确使用单队列，`queue_capacity` 有界并可配置；Linux 现在可只读探测 tun driver 的 multi-queue 参数，但不会未经显式配置创建多队列设备，真实多队列性能/生命周期仍待后续优化。
- [~] **P2-ANDROID-01：** Rust 已提供 `TunRuntime::from_async_device`，`yuhaiin-runtime::run_tun_device_until` 也能复用同一 snapshot/dispatcher 运行外部设备；桌面设备创建与 Android 外部 `VpnService` fd 已在接口层分开；仍需安装 Android target 后构建、完成 fd/JNI 桥接，并验证权限、MTU、IPv4/IPv6 route、前后台切换和重启。
- [ ] **P2-ANDROID-02：** 验收 Android 强制终止恢复、fd/数据库锁清理，并完成最小 JNI/FFI 边界审计。
- [~] **P2-MACOS-01：** `tun-rs` 已覆盖 utun 创建/AsyncDevice，Rust core 的 `aarch64-apple-darwin` 编译边界已通过；仍需实机系统 route、权限/签名和启动/卸载生命周期。
- [ ] **P2-MACOS-02：** 验收 macOS 异常退出、断电/强制退出后的 route、socket、配置和旧 reader 恢复。

#### P2 Geo、稳定性与发布

- [x] **P2-GEO-01：** `crates/yuhaiin-geo/tests/fixtures/GeoLite2-Country-Test.mmdb` 为固定官方 fixture，覆盖 IPv4、IPv6、IPv4-mapped IPv6、未命中和坏库；Geo country lookup 已注入 immutable Router snapshot。
- [x] **P2-GEO-02：** `GeoDatabaseManager` 已完成 bounded download、可选长度/hash 校验、MaxMind decode、同目录临时文件、文件/目录 sync、atomic rename、并发 generation、旧 snapshot 保持和启动 metadata 恢复；runtime API refresh 复用 selected outbound 并把 metadata 写回 SQLite。
- [ ] **P2-SOAK-01：** 建立 Go/Rust 同场景 TCP/UDP 吞吐、延迟、RSS、分配、wakeups、连接数和 SQLite/FakeIP 增长基线。
- [ ] **P2-SOAK-02：** 在真实 Android 设备上补电量、后台存活、前后台切换和长时间运行报告；在报告前不宣称 Rust 性能或省电收益。
- [ ] **P2-AUDIT-01：** 审计 TLS provider 互操作、密码套件、证书验证、日志脱敏和凭据/token 泄漏风险。
- [ ] **P2-AUDIT-02：** 审计依赖 license、纯 Rust/C binding、release profile、交叉编译和 reproducible build，并保存锁文件对应结果。

#### P2 管理面与服务进程验收

- [x] **P2-API-01：** `POST /api/v2/rpc/nodes.post|get`、`resolvers.post|get`、`route.rules.post|get`、`resolver.hosts.put|get` 和 `route.config.put|get` 与前端扁平 JSON request body 兼容。
- [x] **P2-API-02：** API 写入统一经过 SQLite typed compatibility table/config key 和 `RuntimeController::mutate_and_reload`；构建失败不替换旧 snapshot。
- [x] **P2-API-03：** 节点、入站、resolver、route rule/list 原始 JSON 保存在兼容记录 `data_json`，未知字段不因 HTTP DTO 转换丢失；列表响应包含前端需要的 `items/page/pageSize/total`。
- [~] **P2-API-04：** route list 已从“只保存 JSON”推进到 runtime 内容：local/file/缓存 remote、HTTP(S) refresh、`~/.cache/yuhaiin-rust/rules` 原子替换、itemCount/errorCount/preview 和 host/network/port/geoip/all/any/not/process/inbound 规则展开均有实现与测试；`not` 使用 DNF 变体和编译后的域名/CIDR exclusion trie，并有 De Morgan、负 network/port/context 回归；process/inbound matcher 已按 `FlowContext` 的 inbound/process metadata 参与 immutable Router 决策，Linux/Android TUN 以及 SOCKS4A/SOCKS5/HTTP/mixed/Yuubinsya 入站已接入缓存的纯 Rust `/proc` socket→pid/uid/exe resolver，route-list refresh 已通过 `RouteListTransport` 使用 selected outbound；`tools.interfaces` 已拆为独立模块，Linux 通过 rtnetlink 同时返回 IPv4/IPv6 CIDR、排除 loopback 并保留无地址接口，响应契约有 Go 语义单测。仍需 macOS 原生进程枚举、真实生产列表 fixture 和更完整平台验收。入站协议回归现覆盖 SOCKS4A、SOCKS5、HTTP CONNECT、Yuubinsya 和 mixed 的真实 TCP 到共享 outbound 链路；HTTP inbound 的 Go 兼容认证状态码以及注入/真实 socket process enrichment 也有回归。
- [x] **P2-API-05：** `/api/v2/nodes/{id}/latency` 与 RPC `node.latency` 已复用同一 `AsyncProxy` 构造链；独立 latency 模块支持 HTTP/TCP、IP body、STUN UDP/TCP（含 STUN XOR address 与 TCP length-prefix），响应字段与 Go contract 对齐；DoQ/DoH3 仍按低优先级延期。
- [x] **P2-BINARY-01：** `yuhaiin` binary 直接启动 HTTP listener；默认创建内置 direct node，支持 `YUHAIIN_DB`、`YUHAIIN_HTTP`、`YUHAIIN_TUN`，Unix 生命周期同时由 SIGINT/SIGTERM 与 watch shutdown 收敛；无默认 feature 的 `http-api` 最小构建也不会错误导入 TUN API，Podman `stop --time` 已验证优雅 exit code 0。
- [x] **P2-BINARY-02：** 启用 TUN 时由 `inbound::run_until` 以 inbound owner 启动单一路径 `tun-rs AsyncDevice + smoltcp`，selector/NAT/DNS handler 来自同一个 runtime snapshot；配置 reload/shutdown 与 SOCKS5/HTTP/Yuubinsya listener 同一生命周期，可选 UDP DNS server 使用同一 resolver snapshot；Go `inbounds_v2` 的 TUN record 优先于兼容性的 `tun.runtime`。
- [x] **P2-INBOUND-04：** Go TUN inbound 配置映射已接入：`empty/tun` record 由 TUN owner 消费、不会被 TCP listener 当作 socket，`tun://name`、portal/portalV6 和 routes/excludes 有解析单测；当前单设备 runtime 对多个 TUN record fail-closed。
- [x] **P2-INBOUND-03：** TCP/HTTP/WebSocket listener 的 accepted task 由 `JoinSet` 归属，普通结束、API close、reload abort 和进程 shutdown 都会让 `ConnectionMonitor` 收到有效 close；Yuubinsya server 在 listener 级共享 HTTP/2 多 stream 的 migrate session，并在 owner 结束时关闭上游 session。

#### 可选增强（不阻塞主线）

- [ ] **OPT-01：** TUN FIN/RST 全状态矩阵、确定性 timer、同端口多 flow。
- [ ] **OPT-02：** 同步 connector 的细粒度 cancellation、认证失败和多地址矩阵。
- [ ] **OPT-03：** cargo-fuzz 长时间 target 和完整 route/DNS/proxy/TUN 生产配置 schema 对照 fixture。

#### P-END：业务完成后的低优先级检查

- [ ] **P-END-01：** 为 Go FakeDNS IPv4/IPv6 CIDR 转换补充非法 CIDR、越界 prefix、host bits 和空范围的单元测试矩阵。
- [ ] **P-END-02：** 为旧配置 compatibility view 补缺表、缺列、非法 bool/时间戳和多行 singleton 配置的专门失败回归。
- [ ] **P-END-03：** 补齐所有 typed repository 的字段差异报告与完整 schema fixture 对照；不阻塞当前运行时业务链路。
- [x] **P-END-04：** 修复 `p0_tun` fixture 在 H2 response queued 后立即 abort driver 导致的 Yuubinsya TCP/UOT 回写超时；现在 fixture 会让 driver 获得一个调度机会，组合测试连续运行通过。

上面的 `OPT-*` 只是不阻塞主线的回归增强，不应与 P1/P2 验收混记。

明确不进入当前主线：DoQ、DoH3、tun2socket、用户态完整 TCP/IP stack、Windows 平台；只有在上述基础数据面和目标平台路径稳定后才重新评估。

### P0：先把 TUN 到代理的数据面打通

- [x] **TUN dispatcher 与 flow 生命周期**
  - 已完成：定义 `TunFlowKey`、`TunFlow`、`TunEvent`；dispatcher 在 smoltcp poll 前创建 TCP/UDP socket，三次握手完成后发出 `TcpOpened`，发出 data/half-close/close/datagram 事件；支持 bounded channel、socket remove 和异常关闭。
  - 已验证：TCP SYN/SYN-ACK、建立后双向 payload、UDP datagram round-trip、IPv4/IPv6 packet validation、队列 backpressure 和 async proxy event relay。
  - P0 验收：`TunRuntime::run_dispatcher_until` 统一负责 TUN read、smoltcp poll、事件转发、proxy output、NAT sweep、TX flush 和 shutdown close；`TunProxyRuntime::Drop` 会 abort 未完成 flow task，`poll_outputs` 会回收已结束但未发出 close output 的 TCP task。
  - 后续增强：FIN/RST 全状态矩阵、deterministic timer 和多并发同端口 flow；真实 OS 的 ICMP ingress/echo 与 TCP proxy echo 已在特权、无外网容器通过。

- [x] **TUN → Router → Proxy → TUN 的 TCP/UDP 集成**
  - 已完成：direct TCP/UDP 双向 relay、drop/fixed async proxy、blocking HTTP/SOCKS5 adapter、不可变 Router snapshot selector、Yuubinsya `ChainProxy` 和 NAT flow tracking；`p0_flow` 已验证 HTTP CONNECT、SOCKS5、fixed、drop、half-close、timeout、cancel、task abort，`p0_tun` 已验证 fixed→TLS→HTTP/2→Yuubinsya TCP 与 UOT UDP，包括同一 ChainProxy 先 TCP 后 UOT 的组合场景。
  - DNS 分支也已闭环：`p0_flow` 覆盖 DNS 产生 FakeIP、`FakeIpView` 恢复 original domain、CIDR Router 选择 proxy，再回写 TUN UDP payload。
  - 后续增强：多 flow、native Yuubinsya UDP 和更完整 FIN/RST 矩阵归入后续可靠性验收；`YUHAIIN_TUN_PROXY_ECHO=1` 的真实特权 TUN smoke 已通过。

- [x] **DNS 劫持、FakeIP 和 TUN 路由闭环（P0 基线）**
  - 已完成：DNS UDP payload 可被 TUN runtime 劫持并回写；`answer_query`、`AsyncDnsHandler` 可复用 server/dispatcher；store 提供 `FakeIpAsyncDnsHandler<R>`，在 owner future 中执行 upstream→FakeIP transform；`p0_flow` 已覆盖“DNS 查询 → FakeIP 响应 → TUN UDP flow → 域名恢复 → Router 选择 → Proxy 回写”。
  - 后续增强：配置变更清理过期映射；IPv4/IPv6 pool、typed `fakeip_entries`/`fakeip_cursors`、TTL/LRU/touch flush、AAAA/PTR/HTTPS/SVCB hint transform、PTR 未命中回源、重启后 cursor/映射一致性、policy/cancellation 和真实 TUN DoH 组合已有测试；双栈长时间文件增长 soak 已通过，后续只补更多真实生产 snapshot。

- [x] **统一异步 Proxy runtime（P0 基线）**
  - 已完成：`AsyncProxy`、`AsyncStream`、`AsyncDatagram`、`AsyncProxySelector`、bounded flow channels 和 `TunProxyRuntime`；direct/drop/fixed、同步 HTTP/SOCKS5 blocking boundary、Yuubinsya `ChainProxy` 均有接入点。
  - 已验证：同一个 `TunProxyRuntime` 调度 direct/drop/fixed、HTTP CONNECT、SOCKS5 和 Yuubinsya chain；TCP 有本地 echo、超时、半关闭、取消和 owner-drop 回收测试，UDP 有 UOT round-trip。
  - 后续增强：同步 connector 更细的 cancellation 语义、认证失败/多地址矩阵和统一错误分类。

P0 结论：当前“可扩展的最小数据面”已经具备可运行实现、本地自动化闭环和 Linux 特权 TUN TCP proxy echo 验收。未完成项集中在生产配置 schema、平台 fd 生命周期和协议 parity，不再阻塞开始 P1。

### P1：补齐协议 parity 和连接可靠性

- [~] **HTTP/2 连接池与多路复用**
  - 当前：`H2Pool` 按 fixed endpoint 保存连接，每个连接可复用多个 CONNECT stream；bounded relay 隔离 stream flow-control，连接有可配最大 stream 数，池支持同 endpoint 多连接和 idle 回收。
  - 已验证：本地 h2 fixture 的两个 CONNECT stream 共享一个底层连接；达到 stream 上限后建立第二连接；idle 只回收无 active stream 的连接；应用层 drain 会拒绝新 stream 并在 deadline 后关闭；TLS→HTTP/2→Yuubinsya Ping 的第二次 probe 复用 pool/session。
  - 已完成：失败 CONNECT response 会释放预留 stream slot；断连后的新连接重建已有测试；连接 drain 会通过级联 shutdown signal 让已有 relay 和应用侧 stream 在 deadline 后退出并收到 EOF。
  - 已完成：peer GOAWAY 会结束 active relay、拒绝新 stream，并由 pool 走 connection replacement；主动 client-side GOAWAY frame 仍因 h2 0.4 公开 client API 未提供而采用 application-level drain。
  - 已完成（本轮补充）：H2 driver 自身结束（peer GOAWAY/transport error）会广播 relay cancellation，不再只依赖 response body 自行出现 EOF；active stream slot 会归零，应用侧收到 EOF/错误后可安全走 pool replacement。
  - 已完成（本轮补充）：`H2Pool::close()` 并行 drain 所有连接；多连接未结束 stream 的关闭耗时受单个 drain deadline 约束，不会按连接数串行叠加。
  - 已完成：`H2PoolStats` 提供连接尝试/失败、stream capacity rejection 和 stream open failure 的单调计数；`ChainRuntimeStats` 将连接数、active streams 和 pool counters 合并为一个可采样的运行时观测接口；`ChainRuntimeStats::render_prometheus()`/`ChainClient::prometheus_metrics()` 提供无后台 task 的 pull exporter；pool key 现在包含 fixed `SocketAddr`、configured TLS identity 和 ALPN，同 identity 才允许复用，不跨不同 proxy chain 合并；有 stream-capacity→第二连接、不同 TLS identity→不同连接及指标回归。
  - 运行时接入边界：transport crate 只提供 snapshot 和 Prometheus text encoder，由 app 层负责 HTTP listener、认证、采样周期和日志脱敏，不在库内启动全局 exporter。
  - 完成条件：并发 TCP flow 共享连接且互不串包；GOAWAY/断连后新 flow 自动重建，旧 flow 按规定失败；池关闭后没有后台 task、socket 或 stream 泄漏。

- [~] **Yuubinsya UOT coalesce、UDP runtime 和 ping**
  - 当前：认证 UDP、UOT framing、异步 handshake/frame、64 KiB/32 frame bounded coalesce、native UDP client/server boundary 和 hostname-keyed Ping cache 已有。
  - 已验证：coalesce 多 frame flush/解码、native UDP client/server auth/decode、非法 peer 拒绝、Ping session follow-up probe、ChainClient 第二次 Ping 复用 h2 pool。
  - 已完成：`YuubinsyaServerProxy` 可注入任意 `AsyncProxy`，把 TCP、Ping、UOT dispatcher 到上游；`YuubinsyaH2Server` 提供 rustls ALPN h2、H2 CONNECT bridge 和 listener 生命周期；相同 migrate ID 的多个独立 UOT stream 只创建一个上游 datagram，服务端 worker 只消费一个上游 reader 并按 endpoint 回送到对应 stream；已有真实 TLS/H2 多连接迁移、反序回包、TLS/H2/TCP/Ping/UOT/断链重建、碎片化/最大 payload/截断和随机 wire 回归。
  - 已完成：异步 frame reader 的有界随机/截断 matrix、server close 唤醒 pending stream、peer GOAWAY active relay 和 client datagram close cancellation。
  - 已完成：隔离 user namespace 的真实 kernel loopback 0/25/50/75/100% loss matrix、可复现随机 loss state machine，以及发送侧和接收侧统一的有限 reconnect budget；客户端 UOT datagram 已验证失败后有限次复用 migrate id、连续两次 stream loss 后第三次迁移成功、达到上限后有界失败、首帧已写入但响应丢失时的 bounded replay，Ping/UOT server session 与真实 Tokio UDP socket boundary 已通过回归。
  - 非阻塞延期：client-side 主动 GOAWAY；由于当前 h2 公开 client API 不提供该 frame，已固定使用 application-level drain，不使用私有 API/raw frame hack；未来升级到公开支持该能力的 h2 API 后再评估。
  - 完成条件：批量发送/单帧发送都能在丢包、乱序、截断和大 payload 下正确解码；UDP flow 可取消和回收；服务端重启或连接迁移不导致永久等待。

- [x] **简化 fixed → Yuubinsya UOT runtime：** Go `fixed/fixedv2 -> yuubinsya(udp_over_stream=true)` 不再被强制当作四层 TLS/HTTP2 chain；`yuhaiin-chain` 直接 TCP 建连，完成 migrate-ID handshake、UOT frame/coalesce、域名 resolver、有限重连和 `AsyncProxy` datagram 接入；活动 datagram 由 proxy close 统一回收，close 后拒绝新 flow；完整 TLS/HTTP2 chain 保持原路径。
- [~] **关闭、取消、超时和资源回收 parity**
  - 当前：TUN proxy 已定义 connect/read/write/idle 四类 timeout；bounded command/output channel、共享 deadline 下的 TCP/UDP graceful shutdown broadcast、idle close 和 force-abort 路径已经接入，HTTP/2 relay 也能被 connection drain 唤醒。
  - 已完成：`ChainDatagram` 使用 watch cancellation signal，`close()` 会唤醒 pending recv/send/reconnect；TUN UDP output backpressure 会显式关闭底层 datagram；HTTP/2 relay 已接入 connection drain 的级联 shutdown signal；`H2Connection` 持有 relay task handles，在 graceful deadline 后等待或 abort，并在 drop 时 abort driver/relay；TCP half-close、UDP flow close、Yuubinsya session close、关闭后拒绝新 flow、ChainClient ping/pool close 顺序、低流量 UOT coalescing flush、force-stop 和 graceful shutdown 均有回归。
  - 非阻塞延期：client-side 主动 GOAWAY frame；h2 0.4 公开 client API 不提供该 frame，兼容决策已记录，当前使用 application-level drain，不影响当前使用。
  - 完成条件：所有长期 task 都有 owner 和退出条件；异常、主动关闭、对端断开三种路径都能回收 NAT mapping、连接池引用、FakeIP 临时状态和文件句柄。

- [x] **协议健壮性测试与 fuzz/property 测试**
  - 已完成：UOT 65535 字节边界、碎片化 header/frame、截断 frame、超长 payload 拒绝、随机 wire bytes 不 panic、CONNECT 失败释放 H2 stream slot、服务端 UOT session 复用和真实 H2 stream rollover、HTTP/2 随机对等端握手输入、有效 SETTINGS 后 7 类非法帧、Yuubinsya 512 个 IPv4/IPv6/域名多帧序列和全截断边界、DNS 2048 个有界随机 wire 样本、HTTP proxy 16KiB 未结束 header 边界、SOCKS5 malformed method/auth/reply matrix、TUN IPv4/IPv6/TCP/UDP 2048 个有界随机 packet、FakeIP 1024 个 cursor/release/reverse-view 操作、IPv4/IPv6 CIDR 各 2048 个随机查询对照、domain trie 2048 个随机 parent/wildcard 查询对照等回归。
  - 后续可选增强：接入 cargo-fuzz 长时间运行 target；当前 P1 所需的可复现边界、随机序列和最小失败回归已覆盖。
  - 完成条件：针对截断、长度溢出、非法地址、重复 frame、超大 payload、随机字节和状态机乱序加入 fuzz/property target；将发现的最小样本固定为 regression test。

### P1：配置、状态和运行时路由

- [~] **SQLite typed schema 与 repository**
  - 当前：schema v3 已有 proxy node、route rule（含 nullable `geo_country`）、DNS resolver、TUN、full-cone NAT、MaxMind metadata typed tables/repositories；事务、重启读回、schema v1→v3 migration、schema v2→v3 增量 migration、Go v6 minimal/production-shaped snapshot import、幂等 marker、`yuhaiin_meta/yuhaiin_config` 与 typed schema 的列名/声明类型/可空性/主键/索引 contract、malformed/negative Rust/Go schema version fail-closed 和字段差异报告已通过测试。
  - 已完成：文件连接默认 WAL/NORMAL/foreign_keys，启动 `quick_check`；同一数据库路径的多 handle startup/migration/quick_check 通过 gate 串行，避免 SQLite WAL bootstrap 竞态；已提交 WAL、未提交事务 force-stop、截断数据库 fail-closed、typed delete 幂等、Go import 中途失败回滚并在修复后重试、Go v1 同名 `dns_resolvers`/`route_rules` 兼容重命名和未知表/字段保留、typed DDL/版本号原子回滚、DDL index object conflict、base/typed 表缺列/声明类型/可空性/主键/索引 schema fail-closed 后修复重试、Rust negative/future 与 Go future schema version 和 malformed fallback version type fail-closed 均有回归；schema partial-repair 已有回归。
  - 已完成（本轮补充）：`NatConfigRecord::default()` 和 `get_nat_config_or_default()` 默认 `full_cone=true`、30 秒 idle；缺失、删除及旧写入方省略列的 NAT 配置均有回归；写入或读取 `full_cone=false` 都 fail-closed，不允许配置层出现未实现的受限 NAT 模式。
  - 已完成：`ConfigRepository` 提供 `list_go_*` 结构化读取和对应 `put_go_*`/`delete_go_*` 回写；写入只面向明确的 Go v6 `_v2` 表，所有已知列经过校验，原始 `data_json` 和未知字段继续原样保留。
  - 已完成：12 个 batch writer 与 6 个 reader 的独立进程 WAL 压力通过；同一数据库文件使用 sidecar `File::lock()` 串行化 startup/migration 和写事务、保留并发读，`quick_check`、所有 committed rows 和 Full Cone NAT 默认配置均保持正确；force-stop 后 sidecar 锁可由操作系统释放。
  - 已完成（本轮补充）：Go v1 `dns_resolvers`/`route_rules` 在建 Rust typed schema 前重命名为 `go_legacy_*`，空 `_v2` 表按 Go 实际枚举/规则分组规则事务性升级；已有 `_v2` 数据保持权威，不被旧表覆盖；源表只读归档，`put_go_*` 只写 `_v2`，未知 JSON 字段保留；marker、重复启动、非法枚举/JSON rollback 与修复重试均有回归。
  - 已完成（本轮补充）：健康原生 Go v5 数据库可由当前迁移路径直接打开；若 FTS5 派生索引损坏或源库存在非空 WAL，则仍使用 Go `pkg/storage/sqlite.ExportRustSnapshot`、`pkg/legacy/migrate.ExportRustSnapshot` 和 `cmd/yuhaiin-rust-export` 生成一致副本，移除可重建的 FTS5 virtual/shadow tables，源库只读且 destination 必须不存在；实际生产数据库导出和健康原生数据库直接打开均由 rusqlite bundled SQLite 回归通过。
  - 已完成：Go exporter 生成 FTS-free consistent snapshot 和版本化 `.manifest.json`（schema/tool version、FakeIP 行数、移除的 FTS 表、字节数、SHA-256）；Rust `install_go_snapshot_with_manifest`/`go_snapshot_migrate` 强制校验 manifest，随后复制到 sibling staging file，执行完整 schema/import、checkpoint 和 atomic rename；源库、已有 destination、非空 WAL source、manifest hash 不匹配都不会被静默接受。真实 415MB export 已由 rusqlite bundled SQLite 安装为 Rust state，并读回 206 nodes、27,439 FakeIP rows 和双栈 cursor。
  - 已完成（本轮结构整理）：store 主 API/repository 保留在 `src/lib.rs`，schema contract 在 `src/schema.rs`，Go migration/import 在 `src/migration.rs`，typed/Go repository 在 `src/repository.rs`，SQLite adapter 在 `src/sqlite.rs`，FakeIP 在 `src/fakeip.rs`；单元测试按 storage/schema/Go import/snapshot/repository 拆到 `src/tests/`，避免继续把测试和生产逻辑堆在一个文件。
  - 已完成（本轮结构整理）：FakeIP 测试移到 `src/fakeip_tests.rs`，FakeIP 生产实现保持在 `src/fakeip.rs`；core 的 NAT 测试移到 `src/nat_tests.rs`，TUN 测试按 support/unit/proxy-runtime/lifecycle-runtime 拆到 `src/tun_test_support.rs`、`src/tun_unit_tests.rs`、`src/tun_proxy_tests.rs`、`src/tun_runtime_tests.rs`，并保持 Full Cone NAT 回归覆盖。
  - P-END：更多真实 Go 生产库快照和剩余未建模兼容表的异常 migration 注入；24 writer/10 reader 的跨进程长时间压力已通过，当前 `nodes_v2`、`resolvers_v2`、`route_rules_v2`、`inbounds_v2`、`node_tags_v2`、`route_lists_v2` 和 `settings_json` 已有逐表/逐 JSON 边界失败回滚矩阵。
  - 完成条件：新库初始化、逐版本 migration、事务提交、异常中断恢复、force-stop 后重启读回全部有测试；旧 Go 配置至少有一套真实 fixture 和字段差异报告。

- [x] **Router runtime、热更新、resolver policy 和连接解释元数据**
  - 当前：域名 Trie、CIDR LPM Trie、组合 lookup、country Geo lookup、优先级、不可变 compiled snapshot 的 publish/rollback 和 resolver policy 应用已完成。
  - 已完成：非法规则编译失败时不会持有写锁或替换当前 snapshot，旧 flow/new flow snapshot 与并发 publish 已有回归；长压力为 50,000 次 publish、8 个 reader 各 50,000 次 lookup，动态 selector 另有 8 个 reader 各 50,000 次 proxy selection。
  - 已完成：Geo country rule 通过 `Arc<dyn GeoLookup>` 接入 IP route dispatch；无数据库、未命中和查询错误均回 fallback，`RouterRuntime` 发布新 snapshot 时可同时替换 Geo reader；FakeIP DNS→TUN→Router→动态 proxy selector 的生产形态集成、旧 flow 保留原 proxy 与新 flow 观察新 snapshot 的对照回归均已通过。
  - 已完成：选中的 rule name、tag、列表名称、列表匹配结果和 Geo country 会随 `FlowContext` 进入普通 inbound/TUN monitor；runtime selector 的 route-context 钩子保证“实际选择的 proxy”和 connections API 的解释字段使用同一个快照；`route.rules.test` 不再固定返回空 `lists`/`matchResult`。
  - 完成条件：规则增删改、并发 lookup、热更新和失败回滚都有测试；旧 flow 使用旧快照，新 flow 使用新快照；规则优先级和域名规范化与 Go 行为有对照 fixture。

- [~] **NAT 与 proxy/TUN 的完整生命周期**
  - 当前：NAT table 已按 source/migrate ID 做 endpoint-independent full-cone mapping；同源多目标共享 translated endpoint，反向查找不检查外部 source，UDP relay 不再维护受限 peer allowlist。
  - 已验证：真实本地 UDP socket 从未见过的外部 peer 收包，并在 idle sweep 后拒绝迟到回包；同源多目标、translated endpoint 冲突、source close 和反向索引引用计数也有单元测试。
  - 已完成：TUN proxy task 建立/退出、dispatcher 输出写失败、runtime drop、已结束但未发出 close output 的 TCP task 都会 untrack/释放对应 NAT source；UDP task 按 source 聚合，同 source 多目标共享一个上游 datagram，返回 endpoint 映射到原始 flow；relay close 和 source 全量释放已有回归。
  - 已完成：NAT entry 可在 async datagram 建立后绑定真实 local endpoint；FakeIP reverse lookup 进入 `FlowContext::effective_destination`，每个 UDP command 保留自己的 domain target；同 source 两个目标共享一个 datagram、分别回包且不串，FakeIP release/reopen 已有回归。
  - 已完成：forward/reverse index 并发反查与 sweep 使用同一锁状态，TUN TCP idle close、graceful signal、force-drop 和 NAT 释放均有回归。
  - 已完成：UDP input/output 双向 backpressure、idle close、source-shared relay close、runtime drop 和 NAT 全量释放回归；sweep 与新建 flow 竞态、FakeIP 重启后 release 已覆盖。
  - 已完成：128 次同 source 双目标 UDP flow 只创建一个 relay/full-cone binding，force close 后 task 与 NAT 全量释放。
  - 已完成：同一 source 的双 destination 在 32 轮 transport error 后都能关闭共享 datagram、移除全部 flow 引用和 NAT mapping；真实 relay 仍保持 full-cone 的任意外部 peer 接收语义。
  - 已完成：真实 UDP relay 进行 512 轮、4 个 destination、8 个未预先授权 peer 的 full-cone matrix 后仍只有一个 binding；另有 6 个 source 各 256 轮的多 relay matrix，覆盖每轮任意 peer 回包、显式 `close()` 和直接 `drop()`；新增 16 代、每代 256 轮的重复创建/释放 soak，周期性 sweep 与任意外部源 reverse lookup 均保持通过，最终所有 source binding 均清理。
  - 已完成：`TunProxyRuntime` 统一登记同步 DNS task 和 tracked flow；6 个真实 UDP socket 同时阻塞在 `recv_from` 时 force-abort，所有 socket drop、source mapping 清理和 task 清理均通过；同一 `NatTable` 重建第二代 runtime 后可重新创建全 cone mapping。
  - 已完成：跨进程第一代 runtime 被 SIGKILL 后，第二代 worker 可在同一 translated UDP 端口重新建 Full Cone mapping，并再次接受未预授权 peer 回包；测试失败时 worker guard 也会清理子进程。
  - 已完成：`tun-routes` 提供 `TunRoute` 校验/规范化、注入式 `TunRouteBackend`、反向 rollback、失败删除重试、幂等 close；Linux 使用纯 Rust `route_manager` netlink backend，真实 isolated namespace 已通过 `lo` route add/delete/重复 close。
  - 已完成：真实 TUN 显式 shutdown 删除设备和 route；SIGKILL smoke 确认 kernel 删除 TUN 后不残留 `198.18.0.0/15` route；无 `CAP_NET_ADMIN` 的 Linux route add 失败并 fail-closed。
  - 已完成：多进程同时持有同名 TUN 时第二个 owner 失败；首个 owner 被终止后，第三个 owner 可重新使用同名设备。
  - 已完成：无特权单测覆盖 IPv4/IPv6 fragment 分类、每个 fragment 的 MTU 边界、超 MTU TX 丢弃，以及 Linux effective `CAP_NET_ADMIN` 和 tun driver multi-queue 只读探测；不引入 TUN 重组栈。
  - 待做：真实设备 MTU/fragment、设备外部删除和 namespace teardown 矩阵。
  - 完成条件：长连接、短连接、UDP 空闲、主动关闭、异常退出和大量并发 flow 均能稳定回收；没有重复 relay、幽灵 mapping 或 sweep 后仍可写的 entry。

### P2：平台、Geo 和发布质量

- [ ] **Android TUN/VpnService 路径**
  - 待做：Rust crate 的 Android target 构建；从 `VpnService` 接收 fd；权限、MTU、IPv4/IPv6 route、生命周期和前后台切换；JNI/FFI 仅保留最小边界并单独审计。
  - 完成条件：真实 Android 设备或可重复 emulator fixture 能启动、停止、重启 VPN；强制终止后再次启动不残留 fd、数据库锁或旧配置。

- [ ] **macOS utun 路径**
  - 待做：utun fd 创建/关闭、系统 route 安装和回滚、权限/签名/启动方式；与 Linux TUN 共用上层 dispatcher，不复制协议栈实现。
  - 完成条件：真实 macOS 环境可安装、启动、停止和卸载；断电/强制退出后的 route、socket 和配置状态可恢复。

- [ ] **Linux route lifecycle 与能力探测**
  - 当前：特权 namespace 已验证 TUN 创建、IPv4/IPv6 ingress、smoltcp ICMP 和 kernel echo。
  - 已完成：`tun-routes` 的 Linux netlink route add/delete、route capability probe、反向 rollback、失败删除重试和 isolated namespace route lease 验收。
  - 待做：MTU/fragment 行为、设备不存在、namespace teardown 和多队列能力探测。
  - 完成条件：启动失败可回滚所有已应用系统状态；停止和异常退出都不留下 route、设备或后台 task。

- [~] **MaxMindDB/Geo 生产链路**
  - 当前：reader、坏库错误、共享只读句柄、IPv4-mapped IPv6 归一化和 Router country rule 已有；真实 GeoLite fixture 尚未纳入。
  - 待做：加入脱敏/固定版本 fixture；定义数据库热替换、下载、hash 校验、atomic rename 和旧 reader 生命周期。
  - 完成条件：命中、未命中、坏库、替换中并发读取和重启恢复都有测试；Geo 结果真正影响 route dispatch。

- [ ] **性能、内存、电量和长时间稳定性基线**
  - 待做：TCP/UDP 吞吐与延迟、RSS、分配次数、wakeups、连接数、FakeIP/SQLite 增长、Android 电量和后台存活对照；覆盖 Go 版本与 Rust 版本的同场景测试。
  - 完成条件：先产出可重复 benchmark/soak 报告，再决定是否自行替换现成纯 Rust 库；不把“Rust 可能更快”当作已验证结论。

- [ ] **安全、依赖和发布审计**
  - 待做：TLS provider 的互操作/密码套件/证书验证审计；依赖 license 和纯 Rust 约束审计；日志中的域名、凭据、token 脱敏；release profile、交叉编译和 reproducible build。
  - 完成条件：除已批准的 rusqlite bundled SQLite 外，默认构建不引入未经审计的 C binding；每次升级锁文件后重新检查 `bindgen`、`libsqlite3-sys`、`ring`、OpenSSL/native-tls 等路径，并保存审计结果。

## 当前建议顺序

1. P1 的 resolver、proxy chain、TUN selector、controller 原子刷新、FakeIP/SQLite 和 Full Cone NAT 业务闭环均已完成；`P1-H2-01` 是上游 h2 API 依赖，暂不通过私有 API 强行实现。
2. 进入 `P2-LINUX-01..03`；Full Cone NAT 是硬约束，所有新增 TUN/UDP 测试必须保留未预授权 peer 回包回归。
3. 有目标设备后执行 `P2-ANDROID-*`、`P2-MACOS-*`，完成本轮 TUN/proxy close parity 的 fd、权限和异常退出验收；未经本地升级的真实 Go v6 样本、逐版本异常 migration 和未知字段兼容统一放到 `P-END-DATA`。
4. 最后执行 `P2-GEO-*`、`P2-SOAK-*`、`P2-AUDIT-*`，再决定是否扩展 DoQ/DoH3 等明确降级项。

DoQ、DoH3、tun2socket、用户态完整 TCP/IP stack、Windows 平台不进入当前主线；除非基础数据面和移动端平台路径稳定，否则不提前实现这些低优先级分支。

## 已验证命令

后续每完成一个模块，都要把命令和结果补到这里：

```text
cargo fmt --all
cargo test --workspace
```

已在 `/home/asutorufa/Documents/Programming/yuhaiin-rust` 工作区运行：

- `cargo fmt --all -- --check`：通过（格式化结果已同步到源码）
- `cargo test -p yuhaiin-protocol --offline aead::tests`：通过；覆盖 Go AEAD 两种 stream cipher、密码别名、UDP nonce+ciphertext packet 和错误密码拒绝
- `cargo test -p yuhaiin-runtime --offline aead_socks5_inbound_routes_through_shared_outbound`：通过；覆盖 AEAD inbound TCP 解包、共享 SOCKS5 listener 和 direct outbound relay
- `cargo test -p yuhaiin-runtime --offline go_aead_layer_builds_`：通过；覆盖 `fixedv2 -> aead` TCP/UDP outbound
- `cargo test -p yuhaiin-protocol --test go_aead_interop --offline -- --ignored --nocapture`：通过（4 tests）；Go↔Rust AEAD TCP/UDP 双向实例互操作，Go 临时目录位于 `~/.cache/yuhaiin-rust/go-tmp`，不使用 `/tmp`
- `cargo test --workspace --all-features --offline`：本轮最终通过；chain 单元 32、chain `p0_tun` 10（另有 2 个显式 ignored netem 验收）、core 单元 86 + `nat_process` 跨进程集成 1、store 单元 63 + 4 个跨进程集成（另有 2 个 ignored：真实生产快照、长双栈 FakeIP soak）、trie 单元 21、trie `p0_flow` 8、doc tests 全部通过；随后 `cargo fmt --all -- --check` 和 `git diff --check` 通过
- `cargo test -p yuhaiin-core --features tun --offline`：上一轮通过；覆盖独立 TUN/smoltcp dispatcher、UDP/TCP/ICMP、NAT、FakeIP 相关 core 基础
- `cargo test -p yuhaiin-core --all-features --offline --lib nat -- --nocapture`：通过；28 个 NAT/Full Cone 关联测试，覆盖任意外部 peer、多目标共享 mapping、translated endpoint rebind、sweep/close/drop、并发 source 争抢和长 flow
- `cargo test -p yuhaiin-core --all-features --offline --lib tun -- --nocapture`：通过；32 个 TUN unit/runtime 关联测试，覆盖 dispatcher、TCP/UDP/ICMP、DNS/proxy lifecycle、backpressure、shutdown 和 Full Cone cleanup
- `cargo test -p yuhaiin-store --all-features --offline --lib fakeip -- --nocapture`：通过；34 个 FakeIP 关联测试、1 个显式 ignored 长 soak，覆盖双栈池、cursor、TTL/LRU、旧数据导入、DNS answer transform、重启和原子失败
- `cargo test -p yuhaiin-core --all-features --offline --lib dns_hosts -- --nocapture`：通过；6 个 hosts 关联测试，覆盖双栈静态地址、去重/热更新、A/AAAA override、alias 链/未解析 alias/循环、未知域名与非地址记录回源，以及异步 packet handler
- `cargo test -p yuhaiin-core --all-features --offline --lib http2 -- --nocapture`：通过；3 个 HTTP/2/DoH 关联测试，覆盖绝对 endpoint 约束、keep-alive response 生命周期，以及 `H2DohDnsHandler` 保留原始 DNS transaction ID 的异步 packet 适配
- `cargo test -p yuhaiin-core --all-features --offline --lib dns_udp_async -- --nocapture`：通过（2 tests）；覆盖真实 loopback UDP response、原始 DNS transaction ID 回写，以及 `AsyncUdpDnsServer::serve_until` 在 owner signal 后停止且不遗留下一次 recv
- `cargo test -p yuhaiin-core --all-features --offline --lib dns_tcp -- --nocapture`：通过；1 个 RFC 1035 两字节 length-prefix TCP client/server loopback 关联测试，覆盖完整 DNS response framing 和 transaction ID 解码
- `cargo test -p yuhaiin-core --all-features --offline --lib dns_tcp_async -- --nocapture`：通过（3 tests）；纯 Tokio RFC 1035 TCP client/server loopback、同一连接多 frame、多个连接并发 accept、shutdown、两字节 length framing 和 transaction ID 解码
- `cargo test -p yuhaiin-core --all-features --offline --lib dns_resolver -- --nocapture`：通过；统一 resolver facade 的 DoH transport 注入、DNS cache 复用和 `DnsHandler` 组合测试
- `cargo test -p yuhaiin-core --all-features --offline --lib dns_resolver_async -- --nocapture`：通过；异步 UDP/query adapter、缓存复用和 packet transaction ID 保持测试
- `cargo check -p yuhaiin-core --all-features --offline`、`cargo check -p yuhaiin-chain --all-features --offline`、`cargo check -p yuhaiin-store --all-features --offline`：通过；统一 `AsyncIpResolver`、系统 resolver fallback、chain fixed endpoint 注入和基础 proxy builder 注入路径均可编译
- `cargo test -p yuhaiin-chain --all-features --offline --lib -- --nocapture`：通过（38 tests）；Go node chain、fixed host/port、TLS/H2/Yuubinsya 组合和注入 resolver 的 chain 路径回归通过
- `YUHAIIN_GO_ROOT=/home/asutorufa/Documents/Programming/yuhaiin cargo test -p yuhaiin-chain --all-features --offline --test go_yuubinsya_interop -- --ignored --nocapture`：通过（1 test）；使用 Go 真实 `fixed` + `yuubinsya` client 连接 Rust server，覆盖 TCP、UDP-over-TCP、native authenticated UDP 和 Ping；native UDP 明确验证 Go 默认无 SOCKS5 三字节 prefix
- `cargo test -p yuhaiin-store --all-features --offline --lib compat_proxy_async -- --nocapture`：通过（2 tests）；固定域名 proxy endpoint 可由注入 resolver 解析，不依赖系统 DNS
- `cargo test -p yuhaiin-store --all-features --offline --lib go_import -- --nocapture`：通过（21 passed，3 ignored）；Go compatibility/import 回归继续通过，包含 native Go v5/v6 direct-open ignored 验收入口
- `cargo test -p yuhaiin-core --all-features --offline --lib dns_resolver_stack -- --nocapture`：通过（1 test）；hosts override 优先于 upstream，且 resolver strategy 在 layer 边界保持双栈 family 语义
- `cargo test -p yuhaiin-store --all-features --offline --lib resolver -- --nocapture`：通过（4 tests）；双栈 FakeIP resolver 复用持久映射、OnlyIpv4/OnlyIpv6 过滤和 skip-check-upstream 分支通过
- `cargo test -p yuhaiin-runtime --all-features --offline --lib -- --nocapture`：通过（24 tests）；RuntimeBuilder/RuntimeHandle/RuntimeController 生成、ConfigMutation 和 typed repository mutation 持久化后 reload、revision 条件 publish、原子 `load_with_revision`、防陈旧 reload 覆盖、失败时保留旧 snapshot 与 `last_reload_error()` 状态，注册 proxy selector 在 reload 成功时原子刷新、代理构建失败时保留旧 snapshot，ResolverTransportFactory 内置 System/UDP/TCP 构造和数字 DNS server 解析，route rule domain/CIDR/action/network/port/policy 编译、禁用/不支持 matcher fail-closed，HTTP/2 DoH factory，RuntimeSnapshot 基础 proxy 构造和 direct/proxy/bypass/drop selector 组装回归通过
- `cargo test -p yuhaiin-runtime --all-features --offline data_plane -- --nocapture`：通过（5 tests）；外部 TUN host 可读取共享 `tun.runtime` 配置，Go `inbounds_v2` TUN record 可读取 portal/route/name，默认配置保持禁用且不会在加载阶段创建设备；disabled supervisor 会在成功 runtime reload 后唤醒，不必重启服务
- Podman runtime smoke：通过；Debian testing host-network 容器内启动 `target/debug/yuhaiin`，API 创建 HTTP inbound 后，宿主机 HTTP proxy 请求成功，`connections.history` 记录 `http -> direct`，`connections.total` 记录 upload/download，重启容器后 inbound/history 从 SQLite 读回；状态目录位于 `~/.cache/yuhaiin-rust-podman.*`
- Podman route metadata smoke：通过；Debian testing host-network 容器内创建 HTTP inbound、CIDR route rule 和延迟 upstream，在真实请求保持 live 的窗口读取 `/api/v2/connections`，确认 `tag`、`matchHistory[0].ruleName`、`mode=direct` 与实际选择一致；另以 `route/rules/test` 验证 host-list 的 `lists`/`matchResult` 非空。测试状态目录位于 `~/.cache`。
- `cargo test -p yuhaiin-runtime --all-features --offline --lib -- --nocapture`：通过（27 tests）；除既有 runtime/controller/route/proxy 回归外，新增验证 builtin TCP resolver 经纯 Tokio DNS TCP server 完成真实 loopback 查询
- `cargo test -p yuhaiin-runtime --offline --lib -- --nocapture`：通过（13 tests）；追加 route settings 的 direct/proxy resolver 选择、primary resolver 失败/空结果回退，以及同一 ConfigStore 重建新 snapshot 后旧/新 route 行为隔离回归
- `cargo test -p yuhaiin-runtime --all-features --offline --lib -- --nocapture`：通过（15 tests）；额外覆盖 `H2DohResolverFactory` 使用注入 connector 构造缓存 DoH resolver，以及 route_settings repository reload 读取
- `cargo test -p yuhaiin-runtime --all-features --offline --test doh_tls -- --nocapture`：通过（7 tests）；真实 RustCrypto TLS/H2 DoH 与 DoT TCP framing 成功解析、同一 `RustCryptoResolverFactory` 混合构造 DoH/DoT、证书失败、缺少 h2 ALPN、非 2xx/content-type 和 resolver timeout/cancellation 回归通过
- `cargo test -p yuhaiin-runtime --all-features --offline`：通过（84 个 runtime 单元测试 + 7 个 DoH/DoT 集成测试）；新增 `connections.close` 数字 ID fail-closed、monitor close event 唤醒、真实 SOCKS5 TCP relay 和 SOCKS5 UDP flow 关闭后 live connection 回收，以及 traffic/telemetry RFC3339 范围、limit、失败维度和 telemetry 小时桶持久化回归
- `cargo test -p yuhaiin-core --all-features --offline --lib http2 -- --nocapture`：通过（3 tests）；DoH keep-alive response lifecycle、packet transaction ID 和 URI 校验继续通过
- `cargo check -p yuhaiin-runtime --offline`：通过；默认 feature 不依赖 TLS/H2 connector，注入式 `H2DohResolverFactory` 边界保持可编译
- `cargo test -p yuhaiin-trie --all-features --offline --lib -- --nocapture`：通过（21 tests）；RouterRuntime route decision/publish/rollback、Geo country、resolver policy、domain/CIDR LPM 和动态 proxy selector 关联测试通过
- `cargo test -p yuhaiin-store --all-features --offline --lib imports_production_shaped_go_snapshot_without_losing_legacy_tables -- --nocapture`：通过；同一 production-shaped snapshot 额外验证 DoH resolver runtime transport、host 和 route/DNS compatibility 组合读取
- `cargo test -p yuhaiin-store --all-features --offline --lib go_resolver_runtime_preserves_supported_transport_kinds -- --nocapture`：通过；验证 Go resolver 的 UDP/TCP/DoH/DoT/DoQ/DoH3/system 配置枚举均能进入 runtime bridge
- `cargo test -p yuhaiin-store --all-features --offline --lib imports_production_shaped_go_snapshot_without_losing_legacy_tables -- --nocapture`：通过；生产形状 Go snapshot 读回 `dns_hosts` compatibility 行，并保持其他 legacy/config 表不丢失
- 同一 production-shaped snapshot 还通过 `list_go_dns_settings()`、`load_go_fakeip_runtime_config()`、`list_go_dns_fakedns_lists()`、`list_go_route_settings()`、`load_go_route_runtime_config()` 读回并转换 FakeDNS 双栈范围、列表项和 resolver route 开关/UDP FQDN 枚举，未触碰源 legacy 表。
- `cargo test -p yuhaiin-core --all-features --offline`：116 个单元测试和 1 个 `nat_process` 跨进程集成测试通过，新增 PTR、HTTPS/SVCB query/response codec、DoH keep-alive response lifecycle、route lease canonicalization/rollback/close、pending async DNS shutdown/timeout/full-cone cleanup 回归；同时覆盖 `tun`、`http2`、`tls-rustcrypto`、full-cone NAT、translated endpoint rebind/source-sharing、任意外部 peer、多 destination relay、6 source 多 relay 长流、16 代 × 256 轮 full-cone soak、真实 Direct UDP + smoltcp TUN 64 轮双目标/未预授权 peer 回包、6 个真实 UDP socket 多 task abort/关闭竞态/runtime 重建、同步 DNS task owner 清理、NAT 单锁并发反查/sweep、`NatStats` Prometheus pull snapshot、graceful/force close、connect/read/write/idle timeout、TCP/UDP idle task 清理、128 次同 source 双目标 full-cone flow、32 轮双目标 transport error、512 轮四目标/八 peer full-cone matrix、relay drop RAII cleanup、TUN IPv4/IPv6/TCP/UDP 有界随机 packet property、SOCKS5 malformed protocol matrix、DNS cache/policy/cancellation、UDP DNS server 和 Yuubinsya native UDP client/server socket；跨进程测试验证未预授权 peer 回包、SIGKILL 后 socket 端口重绑和 cache 临时文件清理
- `cargo test -p yuhaiin-core --features tun --offline --lib tun -- --nocapture`：14 个 TUN 单元测试通过；覆盖 IPv4/IPv6 fragment 分类、每个 fragment 的 MTU 边界、超 MTU TX 丢弃、bounded RX/TX、TCP/UDP/ICMP dispatcher 和随机 malformed packet 不 panic
- `cargo test -p yuhaiin-core --features tun-routes --offline`：59 个单元测试和 1 个 `nat_process` 跨进程集成测试通过，新增 route canonicalization、非法 family、反向 rollback、失败删除重试、幂等 close 和 Linux capability probe；Full Cone NAT 全部回归保持通过
- `unshare -Urn cargo test -p yuhaiin-core --features tun-routes --offline --test tun_routes -- --ignored --nocapture`：通过；隔离 network namespace 中先启用 loopback，再用纯 Rust netlink backend 添加/删除 `198.18.0.0/15` route，并验证重复 close
- `unshare -Ur cargo test -p yuhaiin-core --features tun-routes --offline --test tun_routes -- --ignored route_permission_error_fails_closed_without_a_lease --nocapture`：通过；无 host network namespace 的 `CAP_NET_ADMIN` 时，Linux route add 返回权限错误，不产生半成品 lease
- `unshare -Ur cargo test -p yuhaiin-core --features tun-routes --offline --test tun_routes -- --ignored tun_open_without_net_admin_fails_closed --nocapture`：通过；无 host network namespace 的 `CAP_NET_ADMIN` 时，TUN 创建返回权限错误，不绕过 kernel 权限边界
- `unshare -Urn cargo test -p yuhaiin-core --features tun-routes --offline --test tun_routes -- --ignored tun_permission_failure_does_not_poison_later_privileged_open --nocapture`：通过；子进程无 `CAP_NET_ADMIN` 创建失败后，父进程仍可打开并关闭新的 TUN
- `unshare -Urn cargo test -p yuhaiin-core --features tun-routes --offline --test tun_routes -- --ignored route_install_fails_closed_after_device_disappears --nocapture`：通过；外部删除 TUN 后 route install 失败且不保留 lease，后续 shutdown 安全完成
- `unshare -Urn cargo test -p yuhaiin-core --features tun-routes --offline --test tun_routes -- --ignored tun_open_with_routes_rolls_back_device_and_allows_recovery --nocapture`：通过；route backend 在启动阶段失败时，已创建设备被回收，同名 TUN 可再次打开
- `unshare -Urn cargo test -p yuhaiin-core --features tun-routes --offline --test tun_routes -- --ignored tun_shutdown_removes_device_and_owned_route --nocapture`：通过；真实 `TunRuntime::shutdown` 先删 route 再释放设备，`ip link` 验证设备消失
- `cargo build -p yuhaiin-core --all-features --offline --bin tun-smoke && unshare -Urn cargo test -p yuhaiin-core --features tun-routes --offline --test tun_routes -- --ignored tun_name_is_exclusive_and_reusable_after_process_stop --nocapture`：通过；第二个进程无法抢占同名 TUN，首个进程终止后第三个进程可重新启动
- `cargo build -p yuhaiin-core --all-features --offline --bin tun-smoke && unshare -Urn ... YUHAIIN_TUN_ROUTE_SMOKE=1 ...`：通过；真实 TUN 安装 `198.18.0.0/15` 后 SIGKILL，隔离 namespace 中设备和 route 均不残留
- `cargo build -p yuhaiin-core --all-features --offline --bin tun-smoke && podman run --rm --privileged --network=none -v /home/asutorufa/Documents/Programming/yuhaiin-rust/target:/work/target:ro -e YUHAIIN_TUN_DNS_ECHO=1 -e YUHAIIN_TUN_HOLD_MS=50 docker.io/library/archlinux:latest /work/target/debug/tun-smoke`：通过；隔离特权容器中真实 TUN 完成 DNS query → async handler hijack → UDP response 回写，输出 `tun-dns-echo-ok`
- `cargo build -p yuhaiin-store --features tun-fakeip-smoke --offline --target x86_64-unknown-linux-musl --bin tun-fakeip-smoke && podman run --rm --privileged --network=none -v /home/asutorufa/Documents/Programming/yuhaiin-rust/target:/work/target:ro -v /home/asutorufa/.cache/yuhaiin-rust-check:/work/cache -e YUHAIIN_TUN_FAKEIP_DB=/work/cache/tun-fakeip-smoke-final.sqlite docker.io/library/archlinux:latest /work/target/x86_64-unknown-linux-musl/debug/tun-fakeip-smoke`：通过；隔离特权容器中真实 TUN 完成 DoH HTTP/2 → FakeIP 持久池 → DNS 回写，输出 `tun-fakeip-doh-echo-ok fake_ip=198.18.0.10`
- `cargo test -p yuhaiin-core --all-features --offline --test nat_process`：通过；第一代子进程创建 Full Cone mapping，独立 UDP peer 回包，force-stop 后第二代子进程在同一 translated socket 重新建 mapping 并再次接受 peer 回包
- `cargo build -p yuhaiin-core --features tun --bin tun-smoke --offline`：通过
- `cargo test -p yuhaiin-chain --all-features --offline`：34 个单元测试和 10 个非 ignored `p0_tun` 集成测试通过，另有 2 个显式 ignored netem 验收；覆盖 fragmented UOT、低流量 coalesced flush、最大 payload、截断、异步 frame reader 有界随机输入、retry queue 边界/确认、服务端 dispatcher、server close 唤醒 pending migrated stream、peer GOAWAY active relay、driver cancellation 后 active stream 归零、多连接并行 close、并发 migrated stream endpoint demux、连续两次 UOT stream loss 后第三次迁移、达到重连上限后有界失败、可复现随机 loss state machine、HTTP/2 随机握手/非法帧、真实 loopback TCP teardown、H2 pool、TLS identity key isolation、capacity metrics、Prometheus pull snapshot、关闭后拒绝新 ping 和 session rollover
- `cargo check -p yuhaiin-core --all-features --target x86_64-apple-darwin --offline` 与 `cargo check -p yuhaiin-chain --all-features --target x86_64-apple-darwin --offline`：通过；仅作为 macOS 编译边界检查，不替代真实 utun/socket/权限和异常退出 runtime 验收
- `cargo test -p yuhaiin-chain --all-features --offline --lib real_loopback -- --nocapture`：通过；真实 loopback TCP 覆盖 TCP 半关闭/EOF/重复 shutdown，以及 UOT 对端退出唤醒 recv/重复 shutdown。测试本身不依赖 Linux 专有 API，但当前实际执行环境仍为 Linux。
- `cargo build -p yuhaiin-chain --bins --offline`：通过
- 给定远端配置真实 smoke：TCP `tcp-probe-reply-bytes=828`；UOT DNS `source=udp://1.1.1.1:53 bytes=61`
- `cargo test -p yuhaiin-core --features 'tun,async-proxy' --offline`：50 个测试通过，覆盖 dispatcher TCP/UDP、async direct proxy、HTTP CONNECT/SOCKS5 adapter、DNS hijack、NAT tracking/drop cleanup、同 source UDP full-cone sharing、NAT 并发 sweep/source 争抢、DNS cancellation/policy 和 native Yuubinsya UDP client/server
- `cargo test -p yuhaiin-runtime --all-features --offline`：117 个 runtime 单元测试和 7 个 DoH/TLS 集成测试通过；新增 inbound listener abort 后 accepted SOCKS5 relay 自动关闭并从 monitor live connections/history 收敛，覆盖 TCP/HTTP/SOCKS4A/SOCKS5/mixed/Trojan/VLESS/Yuubinsya、TLS/WebSocket/HTTP2 transport 和 API close/traffic 共享链路
- `cargo test -p yuhaiin-chain -p yuhaiin-core --all-features --offline`：chain 42 个单元测试、p0_tun 12 个非 ignored 集成测试、core 116 个单元测试、nat_process 1 个跨进程测试通过；FlowObserverGuard 覆盖 Yuubinsya observed TCP/UOT、TUN flow 和代理取消后的 close
- `cargo build -p yuhaiin-core --bin tun-smoke --all-features --offline && podman run --rm --privileged --network=none -v /home/asutorufa/Documents/Programming/yuhaiin-rust/target/debug/tun-smoke:/usr/local/bin/tun-smoke:ro --entrypoint /bin/sh docker.io/library/debian:testing -c 'YUHAIIN_TUN_NAME=yuhaiin-codex0 YUHAIIN_TUN_HOLD_MS=250 /usr/local/bin/tun-smoke'`：通过，容器内真实 TUN 输出 `tun-opened`；同环境加 `YUHAIIN_TUN_ROUTE_SMOKE=1` 输出 `tun-route-installed` 和 `tun-opened`
- `cargo build -p yuhaiin-core --features 'tun,async-proxy' --bin tun-smoke --offline`：通过，包含 `YUHAIIN_TUN_PROXY_ECHO=1` 真实代理 echo smoke 模式
- `cargo test -p yuhaiin-trie --all-features --offline`：21 个单元测试和 8 个 `p0_flow` 集成测试通过，覆盖 Router publish/rollback、失败 publish 保留旧 snapshot、Geo country route dispatch、Geo reader hot publish、FakeIP domain/CIDR priority、动态 `RouterRuntime` proxy selector、随机 IPv4/IPv6 LPM 和 domain parent/wildcard 对照、resolver policy、50,000 次 publish + 8 个 reader 各 50,000 次 lookup、动态 selector 另有 8 个 reader 各 50,000 次 selection、旧/new flow selector 对照和 P0 flow
- `cargo test -p yuhaiin-store --all-features --offline --lib`：当前完整运行 86 个单元测试通过，另有 2 个 ignored（真实生产快照、长双栈 FakeIP soak）；覆盖 Go v1 legacy rename collision rollback/retry、Go v5 sparse fixture 的空表/旧列/未建模 BLOB/未知 JSON 与重复 reopen、Go v5 telemetry 未建模数据保留、typed `fakeip_entries`/`fakeip_cursors`、生产形态 Go v6 双栈 row/cursor 按 family/prefix 读取、Go v6 edge snapshot 的空映射池/过期 mapping/双栈 cursor/未知 JSON、IPv4/IPv6 版本化 Go Pebble NDJSON 解析与混合 metadata 拒绝、未知字段 fail-closed、重复地址冲突原子失败、启动过期清理、TTL 过期、容量 LRU、延迟 touch flush、10,000 步 deterministic touch soak、4,096 次唯一域名 allocate/release 文件增长 soak、双栈各 1,024 次 allocate/release 文件增长 soak、force-stop 未提交 FakeIP row、旧 Pebble snapshot 重复地址/现有映射冲突原子失败、typed repository/delete、Go v1 legacy resolver/route 显式升级与归档写回、Go schema version 异常注入失败后修复重试、Go v6 `nodes_v2`/`resolvers_v2`/`route_rules_v2`/`inbounds_v2`/`settings_json` 逐表回滚矩阵、所有 Go v6 compatibility JSON 边界 fail-closed 后修复重试、Go v6 inbound/node/tag/resolver/route-rule/route-list compatibility views 读写回、base/typed schema 声明类型/可空性/主键/FakeIP 索引 mismatch matrix、schema/WAL/legacy import、Go snapshot atomic install/non-empty WAL/manifest hash fail-closed、Rust state backup/restore、freelist 阈值 compact 和 NAT full-cone 缺失/删除/旧列默认兼容
- `cargo test -p yuhaiin-store --all-features --offline --lib opens_sparse_go_v5_fixture_preserving_empty_and_unmodeled_tables_across_reopen`：通过；Go v5 sparse fixture 两次重开后空 telemetry 表、未建模 BLOB 和未知 resolver JSON 均保持。
- `cargo test -p yuhaiin-store --all-features --offline --lib v6_edge_snapshot_reclaims_expired_rows_and_preserves_dual_cursors`：通过；加载 compact Go v6 edge snapshot 后回收过期 v4/v6 rows，保留两个 cursor 并从 cursor 继续分配。
- `cargo test -p yuhaiin-store --all-features --offline --lib versioned_go_pebble_ndjson_rejects_unknown_fields_and_conflict_snapshot_is_atomic`：通过；未知 legacy 字段 fail-closed，重复地址 snapshot 导入失败且不留下 FakeIP rows。
- `GOEXPERIMENT=jsonv2,greenteagc go test ./pkg/storage/sqlite ./pkg/legacy/migrate ./cmd/yuhaiin-rust-export`：通过；覆盖 Go FTS-free exporter 的一致快照、源库不修改、派生 FTS 删除、manifest/hash、FakeIP/版本报告和禁止覆盖已有 output/manifest
- `GOEXPERIMENT=jsonv2,greenteagc go run ./cmd/yuhaiin-rust-export -source /home/asutorufa/.config/yuhaiin/state.db -output ~/.cache/yuhaiin-rust-check/real-go/export-manifest-20260808-b.sqlite`：通过；实际 Go v5 数据库导出 415,334,400 bytes，生成 309 字节 manifest，SHA-256=`8dd0b73f2cc0359b5155498f70f7ee0f3df8d7738770a7d3826da91b145f457e`，移除 `[nodes_fts]`，保留 27,439 条 FakeIP rows，源 snapshot 无 WAL
- 临时 Go bootstrap helper（验证后已移入回收站）：通过；对 Go v5 FTS-free 生产副本执行当前 Go migration，实际升级为 schema 6、6 个 migrations，保留 27,439 条 FakeIP rows；live `/home/asutorufa/.config/yuhaiin/state.db` 未修改。
- `GOEXPERIMENT=jsonv2,greenteagc go run ./cmd/yuhaiin-rust-export -source ~/.cache/yuhaiin-rust-check/real-go/go-v6-production-20260808.sqlite -output ~/.cache/yuhaiin-rust-check/real-go/export-v6-production-20260808-b.sqlite`：通过；真实生产数据的 schema v6 FTS-free snapshot 为 60,973,056 bytes，manifest `removed_virtual_tables=[]`，SHA-256=`17267850b6cbca45b20515742f9008e1658547ce3daeeb85fd8dbbd6249dcccc`，保留 27,439 条 FakeIP rows。
- `cargo test -p yuhaiin-store --all-features --offline dual_stack_allocate_release_soak_keeps_family_namespaces_independent`：通过；IPv4/IPv6 各 1,024 次 allocate/release，正反向映射都清空、两个 family cursor 均可重开，database+WAL 小于 64 MiB
- `cargo test -p yuhaiin-store --all-features --offline long_dual_stack_allocate_release_reopen_soak_keeps_state_bounded -- --ignored --nocapture`：通过；8,192 次双栈 allocate/release、16 次数据库重开，正反向映射清空、两个 cursor 可恢复，database+WAL 小于 128 MiB，耗时 406.27 秒
- `cargo test -p yuhaiin-store --all-features --offline imports_production_shaped_go_snapshot_without_losing_legacy_tables`：通过；额外验证 `dns_fakedns_lists`、`subscriptions`、`route_settings` 等未建模 Go 行在 typed import 后仍保留
- `cargo test -p yuhaiin-store --all-features --offline each_go_v6_import_table_failure_rolls_back_all_typed_rows`：通过；新增 node-tags/route-lists schema 异常注入，修复后可重试且不留下半迁移 typed rows
- `cargo test -p yuhaiin-store --all-features --offline 'go_snapshot' -- --nocapture`：通过；4 个测试覆盖 staging、Rust import、WAL checkpoint、atomic destination install、源库不变、禁止覆盖、非空 WAL fail-closed 和 manifest hash 篡改 fail-closed
- `cargo run -p yuhaiin-store --all-features --offline --bin go_snapshot_migrate -- --source ~/.cache/yuhaiin-rust-check/real-go/export-manifest-20260808-b.sqlite --destination ~/.cache/yuhaiin-rust-check/real-go/installed-rusqlite-20260808.sqlite`：通过；真实 415,334,400 bytes Go export 经 manifest 校验后安装为 415,461,376 bytes Rust state，读回 206 nodes、27,439 FakeIP rows、15,483 IPv4 + 11,956 IPv6 mappings 和两个 cursor。
- `cargo run -p yuhaiin-store --all-features --offline --bin go_snapshot_migrate -- --source ~/.cache/yuhaiin-rust-check/real-go/export-v6-production-20260808-b.sqlite --destination ~/.cache/yuhaiin-rust-check/real-go/installed-v6-production-20260808-b.sqlite`：通过；schema v6 真实生产 snapshot 安装为 61,194,240 bytes Rust state，source/destination 均 `quick_check=ok`，读回 schema 6、206 nodes、27,439 FakeIP rows、15,483 IPv4 + 11,956 IPv6 mappings 和两个 cursor。
- `YUHAIIN_GO_PRODUCTION_DB=~/.cache/yuhaiin-rust-check/real-go/export-v6-production-20260808-b.sqlite cargo test -p yuhaiin-store --all-features --offline imports_real_go_production_snapshot_without_touching_source -- --ignored --nocapture`：通过；ignored 生产 snapshot 回归从 schema v6 source 读回 206 nodes、6 resolvers、6 route rules、10 inbounds、9 tags、10 lists、15,483 IPv4 + 11,956 IPv6 FakeIP rows 和两个 cursor，source 不被修改。
- `sqlite_backend_probe`：通过；同一实际 FTS-free snapshot 使用 rusqlite bundled SQLite 完成复制、WAL/NORMAL 配置和 schema/row 查询，输出 `copy_ms=53 configure_ms=232 VmPeak=7588 kB,VmHWM=5588 kB,VmRSS=5588 kB`；此前 fsqlite 迁移在 90 秒内未完成且 RSS 约 1.28 GiB，已停止继续采用该后端。
- `cargo test -p yuhaiin-store --all-features --offline allocate_release_soak_keeps_persistent_state_bounded`：通过；4,096 次唯一域名 allocate/release 后正反向 FakeIP rows 为空、cursor 可重开，database+WAL 小于 64 MiB
- `cargo test -p yuhaiin-store --all-features --offline --test cross_process force_stopped_fakeip_transaction`：通过；已提交 mapping 在子进程 SIGKILL 后保留，未提交 FakeIP row 被丢弃，重启后正反向查询和 typed row 数量一致
- `cargo test -p yuhaiin-store --all-features --offline --test cross_process long_cross_process_wal_pressure_preserves_rows_and_full_cone_default -- --ignored --nocapture`：通过；24 个 batch writer×128 条、10 个 reader×240 次，所有 committed rows 保留，`quick_check=ok`，Full Cone NAT 默认值保持 `true`
- `cargo test -p yuhaiin-store --all-features --offline schema_v2_geo_migration_failure_rolls_back_and_retries_after_repair -- --nocapture`：通过；schema v2→v3 `geo_country` 增量迁移故意经过 view 失败，确认 schema version/legacy config 回滚，修复为 table 后重试成功，Full Cone NAT 默认值仍为 `true`
- `cargo test -p yuhaiin-store --all-features --offline --lib legacy_table_rename_collision_rolls_back_and_retries_after_repair -- --nocapture`：通过；Go v1 `dns_resolvers` 重命名遇到已存在的 `go_legacy_dns_resolvers` 时 fail-closed，确认旧表/冲突表保留；删除冲突表后重试成功，resolver 导入成功且 Full Cone NAT 默认值仍为 `true`
- `cargo test -p yuhaiin-store --all-features --offline --lib legacy_route_table_rename_collision_rolls_back_and_retries_after_repair -- --nocapture`：通过；Go v1 `route_rules` 重命名遇到已存在的 `go_legacy_route_rules` 时 fail-closed，确认旧表/冲突表及原始 route row 保留；删除冲突表后重试成功，route rule 导入成功且 Full Cone NAT 默认值仍为 `true`
- `cargo test -p yuhaiin-store --all-features --offline --lib legacy_table_rename_is_atomic_when_second_table_collides_and_retries -- --nocapture`：通过；两张 Go v1 legacy 表连续准备时，第二张 `route_rules` 冲突会使第一张 `dns_resolvers` 的 rename 一并回滚，旧表与行数保持不变；修复冲突后两张表均可重试导入，Full Cone NAT 默认值仍为 `true`
- `cargo test -p yuhaiin-store --all-features --offline --lib failed_go_snapshot_staging_cleans_up_and_retries_after_source_repair`：通过；rusqlite bundled SQLite 在 staging 导入遇到损坏 Go v6 row 时 fail-closed，destination 不出现、临时 staging/sidecar 全部清理；修复 source、更新 manifest 后可重试安装并读回 typed node
- `cargo test -p yuhaiin-store --all-features --offline --lib go_v6_import_missing_column_fails_closed_and_retries_after_schema_repair`：通过；Go v6 `nodes_v2` 缺少 `data_json` 时 typed rows/marker 均不落盘，恢复原表结构后下一次启动成功导入
- `cargo test -p yuhaiin-store --all-features --offline --lib each_go_v6_missing_required_column_fails_closed_and_retries -- --nocapture`：通过；`nodes_v2`、`resolvers_v2`、`route_rules_v2`、`inbounds_v2`、`node_tags_v2`、`route_lists_v2`、`settings_json` 七张 Go v6 compatibility 表逐表缺列均 fail-closed，typed rows 回滚，修复原表后可重试且 Full Cone NAT 默认保持
- `cargo test -p yuhaiin-store --all-features --offline --lib go_v6 -- --nocapture`：通过（8 tests）；Go v6 已知字段导入、坏值/非法 JSON、7 张表缺列故障矩阵、未知 SQL 列兼容、typed writeback 和 Full Cone NAT 默认均通过
- `cargo test -p yuhaiin-store --all-features --offline --lib go_import -- --nocapture`：通过（21 passed，3 ignored）；Go v6 精简/生产形状兼容、关键 ID/时间戳坏值、非法 JSON、逐表缺列、metadata/migrate 版本源负数/未来/不一致、事务回滚/修复重试和 Full Cone NAT 默认均通过
- `YUHAIIN_GO_NATIVE_DB=/home/asutorufa/.cache/yuhaiin-rust-check/go-native-v5-direct-628611-1786196018458296137.db cargo test -p yuhaiin-store --all-features --offline --lib tests::go_import::opens_native_go_v5_database_directly_and_keeps_source_unchanged -- --ignored --exact --nocapture`：通过（1 test，19.91s）；当前真实 native Go v5 副本可由 `ConfigStore::open` 直接迁移，读回非空 Go nodes/FakeIP/cursor，source SHA-256 `54642b40691429d19656260d90be8294bdd55edb7b57259dd37038bcc7142532` 保持不变
- `YUHAIIN_GO_NATIVE_V6_DB=/home/asutorufa/.cache/yuhaiin-rust-check/native-go/state-native-v6.sqlite cargo test -p yuhaiin-store --all-features --offline --lib tests::go_import::opens_native_go_v6_database_directly_and_keeps_source_unchanged -- --ignored --exact --nocapture`：通过（1 test，0.20s）；当前 Go 全新 bootstrap 的 native schema v6 副本可由 `ConfigStore::open` 直接迁移，读回 node/resolver/route、双栈 FakeIP/cursor，source SHA-256 `53e874f94d1cf081b7915434604be6fcf2ac2e56eebe93d82f761a5c3c32d9a6` 保持不变
- `cargo test -p yuhaiin-store --all-features --offline --lib schema -- --nocapture`：通过（21 tests）；Rust schema、Go schema version、legacy rename、typed DDL/index contract 和迁移失败回滚均通过
- `cargo test -p yuhaiin-store --all-features --offline --lib snapshot -- --nocapture`：通过（13 tests，1 ignored）；Go v1/v5/v6 snapshot、compatibility typed writeback 的非法 JSON、staging 回滚和 source 保持不变均通过
- `YUHAIIN_GO_PRODUCTION_DB=~/.cache/yuhaiin-rust-check/real-go/go-v6-production-20260808.sqlite cargo test -p yuhaiin-store --all-features --offline --lib imports_real_go_production_snapshot_without_touching_source -- --ignored --nocapture`：通过；444,293,120-byte raw schema v6 FTS-free production-shaped source 只读导入，206 nodes、6 resolvers、6 route rules、10 inbounds、9 tags、10 lists、15,483 IPv4 + 11,956 IPv6 FakeIP rows 和两个 cursor 均读回，source 未修改；该 source 仍是既有 Go v5 数据经当前 Go migration 的派生 v6 样本
- `cargo test -p yuhaiin-store --all-features --offline --lib sqlite_backup_restore_is_consistent_and_atomic -- --nocapture`：通过；backup/restore 对缺失 destination 的外部 WAL sidecar fail-closed 且不删除 sidecar，已有目标库的原子恢复语义保持
- `cargo test -p yuhaiin-store --all-features --offline --lib repository -- --nocapture`：通过（5 tests）；typed repository 与 Full Cone NAT 缺省、删除、受限模式 fail-closed 均通过
- `cargo test -p yuhaiin-store --all-features --offline --lib future_go -- --nocapture`：通过（2 tests）；Go `schema_version=7` 以及缺少 metadata 时 `migrate.version=7` 均在未审计前 fail-closed，不落 typed rows/marker；修回当前支持的 v6 后可重试导入，并保持 Full Cone NAT 默认值
- `cargo test -p yuhaiin-store --all-features --offline --lib go_migration -- --nocapture`：通过（2 tests）；缺少 metadata 时 `migrate.version` 的错误 TEXT 类型 fail-closed，修复为 INTEGER v6 后可重试导入；未来整数版本 7 同样 fail-closed
- `cargo test -p yuhaiin-store --all-features --offline --lib nat_config_ -- --nocapture`：通过（2 tests）；缺失/删除/旧列默认仍为 Full Cone，`full_cone=false` 的新写入和历史行读取均 fail-closed
- `cargo test -p yuhaiin-store --all-features --offline --lib typed_schema_index_conflict_rolls_back_and_retries_after_repair`：通过；FakeIP index 名称冲突导致 DDL 阶段失败时，已创建 typed table 和 schema version 一并回滚；删除冲突对象后可重试，Full Cone NAT 默认值保持正确
- `cargo test -p yuhaiin-store --all-features --offline --lib sqlite_backup_restore_is_consistent_and_atomic -- --nocapture`：通过；`VACUUM INTO` 捕获已提交 WAL 数据，backup 不覆盖既有文件，损坏 backup 不改变目标库，合法 backup 经 staging/完整性校验后原子恢复并移除恢复前新增配置
- `cargo test -p yuhaiin-store --all-features --offline --lib sqlite_compact_is_thresholded_and_preserves_state -- --nocapture`：通过；freelist 未达阈值时不写库，删除大块配置后按阈值执行 checkpoint/VACUUM，重开后状态保持正确
- `cargo test -p yuhaiin-store --all-features --offline --lib storage -- --nocapture`：通过（12 tests）；ConfigStore 状态读回、schema/reopen、WAL force-stop、backup/restore、compact、并发文件连接和 Full Cone NAT 默认均通过
- `cargo test -p yuhaiin-store --all-features --offline --lib legacy_import -- --nocapture`：通过（3 tests）；legacy v4 marker 在同一事务内原子占用，重复 marker 的冲突快照不会覆盖原 mapping，重复地址/已有冲突仍 fail-closed 且无半成品
- `cargo test -p yuhaiin-store --all-features --offline --lib versioned_go_pebble -- --nocapture`：通过（4 tests）；IPv4/IPv6 版本化 Go Pebble NDJSON 导入、cursor、未知字段和冲突快照继续通过
- `cargo test -p yuhaiin-store --features async-dns --offline`：上一轮通过；覆盖 owner-future DNS resolver → FakeIP transform、Go fixture/import、partial migration recovery 和 FakeIP release/reopen
- `cargo test -p yuhaiin-trie --all-features --offline --test p0_flow`：8 个集成测试通过，覆盖 DNS/FakeIP/Router UDP、HTTP CONNECT、SOCKS5、fixed、drop、half-close、timeout、cancel 和 task abort
- `cargo test -p yuhaiin-chain --offline --test p0_tun`：10 个非 ignored 集成测试通过，另有 2 个显式 network namespace/netem 验收；覆盖真实 TLS/H2 Yuubinsya server、TCP/UOT dispatcher、多 TLS/H2 连接上的 migrated UOT、反序回包、首帧响应丢失后的 replay、连续两次 H2/UOT stream loss 后 migrate rollover、达到重连上限后有界失败、可复现随机 loss state machine、pending recv close cancellation、Ping cache/pool reuse、关闭后拒绝新 ping，以及 kernel loopback loss recovery
- `unshare -Urn ... cargo test -p yuhaiin-chain --test p0_tun chain_datagram_survives_kernel_loopback_loss -- --ignored --nocapture`：通过；隔离 user network namespace 中用 `tc netem` 验证 100% loopback TCP/TLS/H2/UOT loss 后恢复，普通 workspace 测试不会修改宿主网络
- `unshare -Urn ... cargo test -p yuhaiin-chain --test p0_tun chain_datagram_survives_kernel_loopback_loss_matrix -- --ignored --nocapture`：通过；隔离 user network namespace 中用 `tc netem` 验证 0/25/50/75/100% loopback loss matrix，普通 workspace 测试不会修改宿主网络

协议证书 fixture 和其他临时文件统一放在 `/home/asutorufa/.cache/yuhaiin-rust-check`，不使用 `/tmp`；Cargo 的普通构建产物保留在工作区 `target`。

依赖审计：SQLite 后端使用 `rusqlite 0.40.1` 的 `bundled` feature，由成熟 SQLite amalgamation 构建；这是用户明确允许的 C binding 例外，目的是优先保证真实 Go SQLite 文件、WAL、FTS-free snapshot 和迁移性能的验证结果。`yuhaiin-store` 通过本地 `sqlite.rs` typed adapter 隔离 rusqlite API，业务 repository 不直接依赖 rusqlite 类型。当前锁文件存在 `libsqlite3-sys`，但没有 `bindgen`；升级 rusqlite/SQLite 时必须重新执行真实 snapshot、WAL/崩溃恢复、`cargo tree -i libsqlite3-sys` 和构建产物审计。可选 `tun-routes` 使用 `route_manager 0.2.13` 的 Rust netlink packet/client，不链接 native route library，也不执行 `ip` 命令；它仍通过 `libc` 访问 Linux OS ABI，与 `tun-rs` 的 TUN fd 边界同属平台系统调用层。
TLS 审计：`cargo tree -p yuhaiin-core --all-features -i ring` 和 `-i bindgen` 均无 active path；lockfile 中可能保留其他可选目标的元数据，但默认/all-features 实际图不选用 ring 或 bindgen。

Podman `--privileged --network=none` Arch/Debian namespace smoke 已通过：`tun-smoke` 实际创建 `yhsmoke` TUN，读取到 IPv6 控制包后继续读取 IPv4 Echo Request（84 bytes），smoltcp 生成带有效 checksum 的 `src=10.0.0.2 dst=10.0.0.1` 回包；`ping` 收到 1/1，0% loss，约 0.145 ms。
同样的特权、无外网容器运行 `YUHAIIN_TUN_PROXY_ECHO=1` 已通过：内部 TCP client 经真实 TUN 进入 smoltcp TCP dispatcher，由 fixed async proxy 连接容器内 TCP echo target，最终输出 `tun-proxy-echo-ok`。

## 模块验收门槛

| 模块 | 最低自动化覆盖 |
| --- | --- |
| core | 域名规范化、非法输入、Endpoint key、FlowContext 默认值 |
| trie/router | 精确域名、父域、单标签通配符、IPv4/IPv6 LPM、规则优先级 |
| store/config | schema migration、事务原子性、重启读回、异常中断后的恢复 |
| fakeip | 分配/回收、持久化 cursor、冲突检查、旧 snapshot 幂等导入 |
| dns | UDP query/server codec、事务 ID、超时边界、DoH transport boundary、HTTP/2 framing；可注入 `tls-rustcrypto`，alpha provider 仍需审计 |
| proxy | direct/drop/fixed、HTTP CONNECT、SOCKS5 framing/auth、TLS 注入 boundary、HTTP/2 pool/multi-stream/multi-connection/rebuild/idle/drain、native UDP client/server socket boundary、Ping cache；client-side GOAWAY frame 待评估 |
| yuubinsya | header、salt、认证 UDP、UOT length framing/coalesce、migrate id、同步/异步 TCP session、native UDP client/server socket、Ping session/cache、客户端 rollover、注入式服务端 TCP/Ping/UOT dispatcher、TLS/H2 listener、碎片化/截断/最大 payload、并发 migration 和丢包矩阵；client-side GOAWAY frame 待评估 |
| nat | full-cone source mapping、同源多目标复用、任意外部源回包、touch、idle timeout、sweep、UDP relay、关闭回收、并发 sweep/source 争抢 |
| tun | packet round-trip、IPv4/IPv6、软件 checksum、bounded queue、UDP、TCP SYN/SYN-ACK、ICMP echo、`tun-smoke` ingress、特权 namespace kernel echo |
| geo | MaxMindDB 命中、未命中、坏数据库和并发只读 |
