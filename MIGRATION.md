# yuhaiin Go -> Rust 迁移设计与实施文档

> 文档状态：架构基线，2026-08-09
>
> 目标目录：`/home/asutorufa/Documents/Programming/yuhaiin-rust`
>
> 本文覆盖网络运行时的第一批高优先级能力：fakeip、DNS、router、proxy、`pkg/net/nat`、TUN、MaxMindDB 和 SQLite 配置存储。
> 不把整个 yuhaiin 一次性翻译成 Rust，也不把 Go 的包边界机械复制过来。

> 当前实现快照：可编译 workspace 已落地为 `yuhaiin-core`、`yuhaiin-chain`、`yuhaiin-trie`、`yuhaiin-store`、`yuhaiin-geo`、`yuhaiin-protocol` 和 `yuhaiin-runtime` 七个 crate。FakeIP 位于 `yuhaiin-store::fakeip`，MaxMindDB 位于独立的 `yuhaiin-geo`，协议 wire codec/可组合 transport 位于 `yuhaiin-protocol`，TUN 位于 feature-gated 的 `yuhaiin-core::tun`；`yuhaiin-runtime::RuntimeSnapshot` 负责应用层组装和原子 reload，`yuhaiin-runtime::api` 提供与现有 `yuhaiin-react` client 对齐的管理面和 Rust-native pprof endpoint，`yuhaiin-runtime::run_tun_device_until` 负责已创建设备的数据面生命周期，`yuhaiin-runtime::inbound::run_until` 统一拥有 TUN、TCP/HTTP/WebSocket 和 UDP inbound 的启动、reload、shutdown 及 accepted-flow 生命周期，`src/bin/yuhaiin.rs` 只负责桌面 host/API/DNS wiring。HTTP 层复用 Go compatibility records，不新增一套配置 DTO，也不把平台权限细节泄漏到上层。

> 2026-08-09 Go statistics takeover bridge：`yuhaiin-store` 新增 Go 统计表的 typed projection boundary。Rust 启动时在没有 `statistics.runtime` checkpoint 的情况下读取 `statistics_kv`、`traffic_hourly`、`connection_history`、`failed_connection_history` 以及 v6 telemetry dimension 表；`ConnectionMonitor` 的 history 按 Go 的 `(protocol, addr, process)` key 合并，并保留 `dumpProcessEnabled`、计数、最近时间和 JSON connection。正常 `shutdown()` 先写 Rust checkpoint，再在同一个 SQLite 写事务中替换 Go 兼容统计投影，使旧 Go 管理面可以继续看到最终 totals/traffic/history/telemetry。频繁写入仍使用紧凑 checkpoint，故 force-abort 后“checkpoint 可恢复”与“Go 统计表已更新”是两个明确边界，生产库版本矩阵和异常中断验证继续列在 checklist。

> 2026-08-09 统计运行期投影：保留 2 秒级紧凑 `statistics.runtime` checkpoint 作为 crash recovery；checkpoint 成功后首次触发 Go 表投影，之后最多每 30 秒重写一次 `statistics_kv`、traffic/history/failure/telemetry 投影，避免每个 flow 都重写整套 Go 表。最终 shutdown 仍执行一次完整原子投影；异常中断时 Go 表只保证最近一次低频投影，完整恢复以 checkpoint 为准，跨进程可见性仍需 Podman/进程级验证。

> 2026-08-09 统计投影重试：Go 兼容表投影只有在 `replace_go_statistics` 成功后才推进 30 秒节流时间点；SQLite 暂时锁冲突或其他写入失败不会被误记为成功，后续 checkpoint 会继续尝试。新增独立文件库 reader 回归，在 monitor shutdown 前验证另一 `ConfigStore` 已能读到 totals/history。

> 2026-08-09 路由规则 API 兼容性：GET/DELETE 忽略旧 URL 中的 `index`，PUT 更新已有名称时保留原 `priority`，并以公开 `name` 作为 Go 兼容表的 canonical `id`；删除按 `name` 完成并重新编号。这样前端重复编辑同一规则不会生成 `name:index` 重复行，旧数据中的非 canonical id 也会在更新时收敛。

> 2026-08-09 管理 API 错误分类：Rust API 的核心 `ErrorKind` 现在在统一边界按 Go v2 RPC 语义映射：`InvalidInput/Unsupported` 为 400 `bad_request`，`NotFound` 为 404，`Closed/Timeout` 为 503 `unavailable`，I/O、协议和存储错误保留 500 `internal_error`。新增状态分类回归，避免有效的前端参数错误被误报为服务器故障。

> 2026-08-09 节点选择契约：Go 的 `node.use` 与 `nodes.selected` 使用独立的 `selected_tcp_node_v2` / `selected_udp_node_v2` 选择，并在一次 use 操作中同时更新 TCP、UDP。Rust API 现在在配置 overlay 中持久化两套选择，也读取/回写 Go `metadata` 表中的原始字符串；`nodes.selected` 分别返回两套节点；入站 outbound 选择优先读取 TCP 选择，并保留旧 `selected.node` 单选择作为读取回退。无选择时管理 API 不再擅自把第一个 enabled 节点伪装成已选节点；数据面仍按 Go 运行时语义回退到可用 enabled 节点或 direct。新增独立 TCP/UDP selection、use 返回空对象和双写回读单测。

> 2026-08-09 节点 active 状态契约：Go `nodes.active` 暴露的是 `NodeRuntime` 已注册的 proxy entries，不是节点表中所有 `enabled` 行。Rust 现在从 `RuntimeController` 的 live selector registry 汇总实际 proxy slot 的节点 ID，过滤已释放 selector 后返回 active nodes；新增 selector 创建、释放和 idle enabled node 不出现在 active 列表的回归。

> 2026-08-09 节点关闭生命周期：Go `node.close` 只从 `ProxyStore` 删除运行时实例、调用底层 `Proxy.Close`，不删除节点配置；Rust `RuntimeController::close_node` 现在对所有 live selector 的匹配 slot 原子替换为 fail-closed proxy，再在锁外关闭旧实例，因此已有引用会收到 closed 语义，新 flow 不会继续使用旧实例，配置仍可读，下一次成功 reload 会按持久化配置重新构造 slot。空 ID 和未知 ID 保持 Go 的幂等 no-op；新增关闭、active、配置保留及 reload 重建回归。

> 2026-08-09 统计 force-abort 验收：新增真实子进程回归，子进程打开 `~/.cache` 下的 SQLite、写入连接/流量后由父进程调用 `Child::kill`，不执行 graceful shutdown；父进程重新打开同一数据库，确认 Rust `statistics.runtime` checkpoint、Go 兼容统计表、history 和 WAL/sidecar 恢复均可读。这样明确了 checkpoint 与 Go 表投影的实际进程级边界，后续仍需长时间投影失败和 Go 并发读写压力验收。

> 2026-08-09 管理列表 query 契约收口：Rust API 不再对 nodes、inbounds、resolvers、route lists、route rules 统一搜索整个 JSON，而是按 Go handler 的字段集合过滤，并在过滤后计算分页 `total`。节点只搜索 `id/name/group/origin/chain.type`，入站只搜索 `id/name/network.type/protocol.type`，resolver 搜索 `id/type/host/subnet/tlsServerName`，路由列表/规则分别使用 Go 的四个字段。查询仍保持大小写不敏感、分页字段兼容 camelCase；列表 API 的完整 response/error/reload 语义逐项验收仍在 checklist。

> 2026-08-09 管理 mutation response 契约：对照 Go 的 `NodeRuntime.Save`、`saveInbound` 和 `ResolverCtr.SaveContract`，Rust node 保存现在强制持久化并返回 `origin=manual`；inbound 保存后重新读取 typed repository 返回 persisted contract，而不是直接回显请求 JSON；resolver 仍按 Go 返回原请求对象，同时将 trimmed ID、默认 type/host 和 system 标志写入持久化 JSON。新增 API 回归覆盖 node response/list、disabled TUN inbound persisted response 以及 system resolver 的存储后规范化；route 和剩余 detail/error/reload side effect 仍列在 checklist。

> 2026-08-09 route detail 规范化：对照 Go `RouteListStore.decodeRouteListDetail` 与 `RouteRuleStore.decodeRouteRule`，Rust route list/rule 的 detail GET 不再直接回显原始 JSON；保存时持久化 trimmed name、默认 `host/local` source 和默认 `bypass` mode，remote/local section 也按 Go 互斥规范化。mutation response 仍保留 Go 的请求回显语义；新增空 source/type/mode 的 API 回归，priority/apply side effect 继续单独验收。

> 2026-08-09 route activation 合并：对照 Go `ScheduleApply`、列表 host-index refresh 和 `route.apply`，Rust route rule 保存/删除/排序及 route list 保存/删除现在写入兼容的 pending activation 时间；`route.activation` 同时合并 `route.lists.activation.hostIndexRefreshAt` 与 `route.activation.ruleApplyAt`，显式 apply 会原子清理两类状态。数据面仍在 typed repository mutation 后立即 reload，activation 只表达管理面可见的 pending/apply 生命周期；新增 priority、list mutation、combined status 和 clear regression。

> 2026-08-09 route activation 生命周期：Rust 管理面按 Go 的一分钟 timer 语义处理过期 deadline；`route.activation` 与 `route.lists.activation` 读取时会将已过期状态报告为 0，避免进程重启或无后台 timer 时前端进度永久卡住。route list refresh 的 `hostIndexRefreshAt` 改为当前时间后一分钟，`lastRefreshAt` 仍保留实际刷新时间；新增过期状态和 refresh deadline 回归。

> 2026-08-09 route list settings 接管：Go 生产库的 `route_extra.refresh_config` 与 `route_extra.maxminddb_geoip` 位于 `settings_kv`，Rust `/api/v2/route/lists/config` 现在优先读取这些 canonical rows，并将保存/refresh 的结果同时写回 `settings_kv` 与 Rust overlay；没有 Go 表的新库继续使用 `yuhaiin_config` fallback。`refreshInterval` 按 Go 的无符号十进制字符串解析，响应只返回规范化 contract；新增 canonical mapping、数字字符串和未知字段回归。

> 2026-08-09 runtime socket policy：`useDefaultInterface/netInterface` 已在 immutable snapshot 中解析为接口 IPv4/IPv6 source addresses；统一 `SocketPolicyProxy` 将策略传递到 direct/fixed、HTTP CONNECT、SOCKS5、协议 wrapper、HTTP/2 Yuubinsya、直连 UOT 和 native UDP socket。连接建立按目标地址族选择 source address，selector reload 会替换策略而不影响旧 flow。新增 FlowContext/connector/runtime reload 回归，`cargo test -p yuhaiin-core --all-features --offline --lib` 通过 121 项，`cargo test -p yuhaiin-runtime --all-features --offline --lib` 通过 137 项；inbound listen socket 的平台专用绑定仍保留为平台验收项。

> 2026-08-09 Go empty-store object graph：新增 `runtime::defaults::ensure_go_defaults`。真正没有 inbound/resolver/route settings/route rule/route list 的新 SQLite store 首次构建时，会一次性写入 Go 兼容的 mixed（`127.0.0.1:1080`）、禁用的 TUN、禁用的 Yuubinsya、`bootstrap` UDP resolver、LAN host list、direct LAN rule 和 route settings；通过 `yuhaiin_config` marker 保证重复启动幂等，也保证用户删除默认行后不会被下次启动强行恢复。默认对象仍复用现有 typed repository 和 API/runtime reload boundary；新增默认 JSON、非空 store 不修改、重复 build 和中断恢复回归，`cargo test -p yuhaiin-runtime --all-features --offline` 通过 157 个 runtime 单测、2 个 binary tests、7 个 DoH/DoT 集成测试。

> 2026-08-09 DNS resolver socket policy：`ResolverTransportFactory` 增加带 source-address policy 的默认扩展入口；内置 UDP/TCP DNS client 和 RustCrypto DoH/DoT direct dialer 已按目标地址族绑定接口地址，旧的自定义 factory 不实现扩展时仍走原有 `build`。新增 UDP/TCP/runtime resolver 回归；完整 workspace 测试继续通过。

> 2026-08-09 SOCKS5 UDP outbound：基础 SOCKS5 outbound 不再把所有能力限制在 blocking TCP CONNECT；`Socks5AsyncProxy` 现在实现 RFC 1928 username/password、UDP ASSOCIATE、domain/IPv4/IPv6 UDP framing，并保持控制 TCP 连接存活直到 datagram close。`BaseProxyConfig::build` 已使用原生 async 实现，因此 SOCKS5 节点可以服务 TUN、DNS、Yuubinsya/NAT 等 UDP 路径；新增认证、指定 source address、domain request/response 的真实 Tokio loopback 回归。

> 2026-08-09 node latency DNS/UDP：runtime `latency` 的 `dns`/`udp` 不再返回 unsupported，改为通过共享 `AsyncProxy::open_datagram` 发送 DNS A 查询并校验 transaction ID/响应 codec；默认 resolver `223.5.5.5:53` 和目标 `www.google.com` 与 Go 版一致，DoQ 仍按低优先级延期。新增真实 UDP resolver loopback 回归。

> 2026-08-09 node latency IP：修复 Rust `ip` 探测此前复制同一个 HTTP 请求、没有真正区分地址族的兼容性缺口。API 现在把 immutable runtime snapshot 的 resolver 注入 latency boundary；A/AAAA 两条探测并行按 `OnlyIpv4`/`OnlyIpv6` 解析，选择的具体 `SocketAddr` 交给同一个 outbound proxy，HTTP `Host` 和 HTTPS SNI 仍使用原始域名。新增 resolver、proxy endpoint 和 IPv4/IPv6 返回值回归；这只证明行为和结构兼容，不宣称跨网络环境性能等同 Go。

> 2026-08-09 inbound owner：修正 TUN 虽位于 `inbounds` 模块、却由 `run_until` 外部独立 `tun_task` 管理的生命周期偏差。现在 `start_listeners` 从 Go TUN inbound record 加载配置，并把 device/packet loop 的 task 放入与 SOCKS5、HTTP、Yuubinsya、UDP listener 相同的 owner 集合；reload 先统一 abort/cleanup，再重建全部 enabled inbounds，shutdown/force-abort 也使用同一边界。TUN 仍保留 `tun.runtime` 兼容回退和移动端注入 `AsyncDevice` 入口。重建 runtime binary 后，在 privileged、`--network=none` 的 Debian testing Podman 中检测到真实 `yhrtun30822` 设备，SIGTERM 后进程以 0 退出。

> 2026-08-09 mobile TUN inbound：补齐 `inbound::run_until_with_tun_runtime`，移动端可先用 `TunRuntime::from_async_device` 接管 `VpnService`/平台 fd，再让同一个 inbound supervisor 同时拥有 TUN、SOCKS5、HTTP、Yuubinsya 和 UDP listeners。注入设备不会在 reload 时被重新打开或丢弃；`run_tun_device_until_ref` 只重建 snapshot 对应的 proxy runtime/dispatcher，并在最终 shutdown/abort 时统一释放。Android target check 通过；真实 VpnService 权限、route 和功耗仍需设备验收。

> 2026-08-09 Go service CLI compatibility：Rust binary 现在接受 Go service command 使用的 `-host/-path/-u/-p/-eweb/-nfs-mode` 参数，也支持 `run`、`version`、`help` 和 `update-helper` 入口。`-path DIR` 按 Go `paths.PathGenerator.State` 使用 `DIR/state.db`，默认 HTTP 地址改为 `0.0.0.0:50051`；`-eweb DIR` 通过 `tower-http::ServeDir` 在同一 listener 提供静态资源，并将未知前端路径回退到 `index.html`；`YUHAIIN_DB`/`YUHAIIN_HTTP` 仍可用于测试和显式覆盖。这样 systemd/launchd 直接替换 executable 时不会因 flag、端口、state 文件名或外部 web root 不一致而启动到另一套运行环境；服务安装、backup/rollback 和旧 Go 并行切换仍需现场演练。

> 2026-08-09 reverse inbound bridge：Rust 接入 Go contract 中的 `reverse_tcp` 与 `reverse_http`。`reverse_tcp.host` 解析为保留域名语义的 TCP `Endpoint`；`reverse_http.url` 解析为目标 endpoint、path、authority 和 HTTPS 标志。两者都在 `yuhaiin-runtime::proxy::reverse` 中构造共享 `FlowContext`，调用 live router/selector 后再进入 counted relay；reverse HTTP 会改写请求 path/Host，非 HTTP 首段回退为原始流，HTTPS target 使用 RustCrypto TLS。新增真实 loopback inbound→direct→upstream 回归；Linux `tproxy`/`redir` 仍需原始目标地址和权限验收。

> 2026-08-09 Linux transparent inbound acceptance：修正 `SO_ORIGINAL_DST` 与 `IP_ORIGDSTADDR` IPv4 地址的 native/network endian 转换，并加入回归测试。Podman 中通过真实 `REDIRECT` 规则验证 TCP inbound→direct→upstream，返回 `transparent-ok` 且 history 记录正确目标；同样的 rootless Podman veth 环境即使使用 privileged，也无法将非本地目标的 `TPROXY` UDP 包交给透明 socket，独立 Python `IP_TRANSPARENT`/`IP_RECVORIGDSTADDR` 探针结果一致。因此 TPROXY UDP 实现保留，真实验收明确依赖宿主机/真正 network namespace 的 CAP_NET_ADMIN；Go contract 中 redir 的 UDP 仍保持禁用，TLS/WS 等透明 transport 继续 fail-closed。

> 2026-08-09 Go zero-configuration baseline：`RuntimeSettings::default()` 对齐 Go `DefaultSetting` 的 IPv6、HTTP system proxy、debug/save 日志默认值；`api::default_settings` 直接复用同一默认对象，避免管理面与数据面漂移。DNS supervisor 在没有 `resolver.server` overlay 和 `dns_settings` row 时使用 Go 默认监听地址 `127.0.0.1:5353`；默认 inbound/route object 的 store 初始化已由上一条完成。

> 2026-08-09 inbound protocol compatibility：补齐 Go contract 的 `none` noop inbound（接受后关闭，不进入 router），并归一化旧 JSON 中的 `mix`、`reverseHttp`、`reverseTcp` 拼写；section 查找同时兼容旧字段名，避免协议名归一化后丢失认证/目标配置。新增 alias 解析和 noop close 回归。

> 2026-08-09 cross-target boundary：`yuhaiin-core` 的 `async-proxy,tun` 已通过 `aarch64-linux-android` 和 `aarch64-apple-darwin` 的 `cargo check`。在 Android 上使用 `/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang`、对应 `clang++`、`llvm-ar` 和 Cargo linker 后，`yuhaiin-runtime --all-features` 的 `aarch64-linux-android` target check 也通过；bundled SQLite 的 C 编译边界已验证。macOS runtime check 仍需要 macOS SDK/clang，Android VpnService fd、权限和实机生命周期仍未由此命令行检查替代。

> 2026-08-09 update service：补齐 `/api/v2/update/check`、`update.apply`、`update.status` 的真实 Rust 实现。服务按 Go 的 stable/beta/main channel 过滤和排序 GitHub releases，要求目标平台 asset 与 `checksums.txt`，下载时持续更新状态并在 SHA-256 不匹配时删除 staged 文件；临时文件放在 `~/.cache/yuhaiin-rust/updates`，helper 会复制到安装目录后再做替换和 service restart，失败恢复 `.update-backup`。reqwest 使用 rustls no-provider + RustCrypto，`cargo tree` 未发现 ring/OpenSSL/native-tls；网络端点和不同发行版 service manager 仍需现场验收。

> 2026-08-09 Rust pprof 与 MaxMind fixture：runtime 使用纯 Rust `pprof-rs` 提供 `/debug/pprof/` index 和 `/debug/pprof/profile?seconds=N` protobuf profile endpoint；沿用 Go settings 的 `pprof` 开关，关闭时返回 404，并有 API 回归覆盖 index、profile 和 reload。profile 格式遵循 Rust crate，不承诺 Go wire compatibility。MaxMind 使用用户指定的 `Country-without-asn.mmdb` 下载地址；真实库文件只保存在 `~/.cache/yuhaiin-rust-maxmind`，未进入仓库，8.2 MiB fixture 的 SHA-256 为 `1d900f73aa4644d255793548319410ff559ef9294a662ec1a0354f106c794155`，真实 IPv4、IPv4-mapped IPv6 查询和已有 atomic refresh/concurrency 测试均通过。

> 已实现的代码包括：SQLite 配置事务与 schema v3 typed repository、Go v6 fixture/import/字段差异报告、FakeIP IPv4/IPv6 分配/持久化/旧 snapshot 幂等导入与 A/AAAA/PTR/HTTPS/SVCB hint answer transform、域名/CIDR/Geo country Router snapshot publish/rollback、独立 `yuhaiin-geo` 的 MaxMindDB reader/校验下载/atomic refresh、带 TTL/容量淘汰的 DNS cache、同步/异步 UDP DNS client/server/policy/cancellation boundary、DoH transport boundary、注入 connector 的 HTTP/2 DoH framing、可直接接入异步 DNS/TUN packet pipeline 的 `H2DohDnsHandler`、可复用的 RustCrypto TCP→TLS→ALPN h2 DoH connector 和 DoT TCP framing resolver、同时组装 System/UDP/TCP/DoH/DoT 的 `RustCryptoResolverFactory`、hosts→upstream→FakeIP 的可注入异步 resolver stack、`yuhaiin-runtime` 的 Go compatibility snapshot 组装与 direct/HTTP/SOCKS5/Shadowsocks/Trojan/VLESS/chain proxy 构造、direct/fixed/drop/HTTP CONNECT/SOCKS5、独立 `yuhaiin-protocol` 的 Shadowsocks/Trojan/VLESS TCP/UDP codec、inbound/outbound wrapper、TLS 和 WebSocket transport 组合、feature-gated `rustls-rustcrypto` TLS client、共享 WebSocket byte-stream transport（standalone、VLESS 和 WebSocket+HTTP/2 inbound/outbound）、Yuubinsya native UDP client/server socket、UOT/TCP/coalesce/Ping client/server session、full-cone NAT UDP relay、唯一的 `tun-rs AsyncDevice + smoltcp` TUN adapter，以及独立的 `yuhaiin-chain`（fixedv2 → 可选 TLS/WebSocket → HTTP/2 pool/CONNECT → Yuubinsya TCP/UOT/Ping）。TLS provider 仍是 alpha，DoQ/DoH3、WebSocket early-data/子协议和特权 Linux namespace/Android/macOS 验收仍是独立门槛，未用 C TLS 代替。
>
> 本轮新增 Go 自定义 AEAD transport：它与 Shadowsocks AEAD 不同，使用 P-256/Ed25519 handshake、ChaCha20/XChaCha20 方向 stream，以及 Go 兼容的 `nonce || ciphertext` UDP packet。协议 codec、TCP/UDP outbound wrapper、SOCKS5 AEAD inbound 和 AEAD 外层 Yuubinsya UDP 已接入；Rust 本地回归与 Go↔Rust TCP/UDP 双向实例互操作通过，更完整组合仍列为 P1 验收项。

> 2026-08-09 管理面补齐 `tools.interfaces` 的替换契约：Go 返回所有非 loopback 接口及其 `net.Interface.Addrs()` CIDR 字符串；Rust 现在在 Linux 通过纯 Rust netlink packet API 读取 RTM_GETADDR，同时使用 sysfs 的接口索引映射名称，覆盖 IPv4/IPv6、无地址接口和 loopback 过滤。实现位于 `yuhaiin-runtime::interfaces`，API 继续直接序列化共享 `InterfaceInfo`，没有新增 HTTP DTO；netlink 不可用时回退到无 loopback 的 sysfs/IPv6 发现。`cargo test -p yuhaiin-runtime --all-features --offline` 已通过 117 个 runtime 单测及 7 个 DoH 集成测试，最小 `http-api` library 构建也已验证。

> 2026-08-09 inbound 生命周期收口：TUN 不再由 binary 单独启动；`yuhaiin-runtime::inbound::run_until` 与 SOCKS5、HTTP、Yuubinsya、WebSocket、HTTP/2 listener 共享同一个 inbound owner。普通 TCP/WebSocket accepted task 由 `JoinSet` 归属 listener，reload/shutdown/abort 会回收子任务；`yuhaiin-core::flow::FlowObserverGuard` 让正常结束、管理面 close 和强制取消都能完成 monitor close、history/SSE/traffic 收敛。Yuubinsya server 也提升到 listener 级，HTTP/2 多 stream 可共享 migrate ID 的 UDP session，listener 结束时显式 close 上游 session。runtime 新增 listener abort 后 live connection 清理回归；`yuhaiin-runtime` 117 个单测、`yuhaiin-chain` 42 个单测和 `yuhaiin-core` 116 个单测均通过。Podman 特权无网络容器中 `tun-smoke` 的真实 TUN 创建/关闭和 route smoke 也通过。
> 2026-08-09 TUN 配置边界收口：Go 的 `inbounds_v2` 中 `network.type=empty`、`protocol.type=tun` 现在是 Rust TUN supervisor 的主配置源，按 Go `TunProtocol` 读取 `tun://` 名称、`portal`/`portalV6`、`routes`/`excludes`；旧 `tun.runtime` 仅作为没有 Go TUN inbound 时的兼容回退。普通 TCP/UDP listener 会跳过 TUN record，单设备 runtime 遇到多个 TUN record fail-closed。新增 Go inbound 配置解析回归，runtime 全部 118 个单测和 7 个 DoH 集成测试通过；此前 Podman 特权无网络容器中的真实 TUN 创建/关闭及 route smoke 仍通过。
> 2026-08-09 Podman runtime smoke：用 `cargo build -p yuhaiin-runtime --bin yuhaiin --all-features --offline` 构建 binary，在 Debian testing `--network=host` 容器中通过 API 创建 HTTP inbound；宿主机经 `127.0.0.1:18083` 访问本地 HTTP server，验证 API reload、HTTP inbound→direct outbound、history/traffic 统计。停止并重启同一容器后，`inbounds.get` 和 `connections.history` 均从 SQLite 读回。容器状态目录使用 `~/.cache/yuhaiin-rust-podman.*`，不使用 `/tmp`。
> 2026-08-09 Podman live management smoke：在 Debian testing `--network=host` 容器中让 HTTP upstream 延迟响应，真实验证 `/api/v2/connections` 返回 live connection、非法 close ID 返回 `400`、合法 `connections/close` 返回 `200` 并使 relay 退出，随后 `/connections` 为空且 `/connections/history` 使用 Go 兼容的 `items` 形状；EventSource 收到初始 `connections_added`、建立连接的 `connections_added` 和关闭后的 `connections_removed`。另通过 `/api/v2/inbounds/{id}` PUT reload 验证旧 inbound 端口变为 `000`、新端口返回 `200`。测试临时目录均在 `~/.cache/yuhaiin-rust-*`。
> 2026-08-09 统计持久化生命周期收口：`ConnectionMonitor` 现在拥有 SQLite persistence worker，并提供显式 `shutdown()`；inbound/DNS owner 收敛后，binary 会先执行 final flush、等待 writer 退出，再处理 backup restore，避免短连接/低流量统计丢失或与恢复竞态。新增回归不等待 2 秒周期即可重启读回最后一条 history/traffic；Podman Debian testing host-network smoke 已验证服务立即 SIGINT 退出后同一 SQLite 直接读回 history 和 total。
> 2026-08-09 服务信号生命周期收口：Unix binary 同时监听 SIGINT 和 SIGTERM，并复用同一个 shutdown watch；Podman `stop --time 10` 已验证 inbound owner、DNS owner、统计 final flush 完成后以 exit code 0 退出，不再因只监听 Ctrl-C 而退化到 SIGKILL。
> 2026-08-09 TUN inbound 服务级验收：先通过管理 API 写入 Go `inbounds_v2` 的 `empty/tun` 记录，再在 privileged、`--network=none` 的 Debian testing 容器中复用同一 SQLite 启动 runtime；容器内 `/sys/class/net/<tun-name>` 证实 TUN 由 `inbound::run_until` 持有，Podman SIGTERM 后设备消失且 exit code 为 0，随后独立 TUN probe 可重新打开同名设备。测试状态目录使用 `~/.cache/yuhaiin-rust-*`。
>
> 2026-08-09 连接元数据契约修复：monitor 不再把所有 `TunFlow` 统一序列化为 `component=tun`；普通 inbound 的 component 为空，只有 TUN runtime 注入 `component=tun`，并保留 TUN 的默认 inbound 标识。新增普通 inbound/TUN 双路径回归。
> 2026-08-09 路由解释元数据链补齐：`RouterRuntime` 现在把命中的 Go rule name、tag、host/process list、match history 和 Geo country 写回共享 `FlowContext`；runtime selector 增加统一的可变 `route_context` 钩子，HTTP/SOCKS4A/SOCKS5/Trojan/VLESS/Yuubinsya/TUN 都在选择 outbound 前调用，因此普通连接与 TUN 连接的实际 proxy 选择、`connections` 实时字段和 `route.rules.test` 使用同一条路由快照。`resolver` 同步记录 route settings 选择的 resolver ID。新增 trie、route compiler、monitor 回归；Podman Debian testing host-network smoke 进一步创建真实 HTTP inbound 和 CIDR route rule，延迟 upstream 期间读取 `/api/v2/connections`，确认 live connection 返回 `tag=local-test`、`matchHistory[0].ruleName=local-rule`、`mode=direct`，再完成真实 HTTP 请求。
> 2026-08-09 FakeIP/TUN 上下文链补齐：`RuntimeController::build_tun_proxy_runtime_with_dns` 在构造同一份 snapshot 的 TUN runtime 时，把 FakeIP 池转换成 SQLite-free 的双栈 `FakeIpView`；每个新 TUN flow 在 router 选择前按目的 IP恢复 `original_domain`，并在 monitor 的 Go 兼容 connection 对象中保留 `fakeIp`。共享 view 会在 resolver 分配新地址后替换，不把 SQLite 放进 packet callback；新增 controller、store snapshot 和 monitor 回归，避免 FakeIP TUN 流量只能按合成 IP 路由或显示。
> 2026-08-09 连接观测扩展：共享 `FlowContext` 增加 Go `connections` 所需的 `hosts`、`tlsServerName`、`httpHost`、`interface` 和 `outboundGeo` 可选字段，monitor 序列化这些值时不再硬编码为空；HTTP forward inbound 已把真实 `Host` 写入上下文，并有头部/monitor 单测。TLS SNI、hosts resolver source、实际 socket interface 和 selected outbound Geo 仍由后续 sniff/resolver/socket adapter 填充，当前保持空值而不是伪造兼容数据。
> 2026-08-09 bounded stream sniff：`yuhaiin-core::sniff` 以纯 Rust 解析完整 TLS ClientHello 的 SNI 和 HTTP request 的 Host（含 IPv4/IPv6 authority port 处理）；共享 TCP relay 在打开 `FlowObserverGuard` 前最多等待 55ms 读取首段，写入 `tlsServerName/httpHost` 后通过 `PrefixedStream` 原样回放，避免窥探吞掉首包。HTTP/SOCKS/Yuubinsya/Trojan/VLESS 等复用该 relay 的路径因此获得一致观测行为；core parser、relay prefix preservation 和 monitor-before-open 均有回归。hosts resolver source、实际 socket interface、outbound Geo 以及 TUN packet-level sniff 仍是独立适配项。
> 2026-08-09 connection metadata adapter：`RuntimeProxySelector::route_context` 现在复用同一份 runtime snapshot 检查 Go 持久化 hosts 命中，并在 selected direct/fixed/HTTP/SOCKS5/Trojan/VLESS/Yuubinsya/chain endpoint 解析后填充 `FlowContext.hosts`、`interface` 和 `outboundGeo`；interface 先按非 loopback 本机 CIDR 匹配，Linux 再按 `/proc/net/route`/`ipv6_route` 最长前缀回退，Geo 使用 snapshot 已加载的 MaxMind reader。新增 selector、IPv4/IPv6 CIDR 和 snapshot reload metadata 回归；系统 `/etc/hosts`、握手后才可见的底层 socket interface、Android/macOS 路径仍未伪造兼容。
> 2026-08-09 system hosts overlay：runtime snapshot 在持久化 Go `dns_hosts`/兼容配置之前加载平台 hosts 文件（Unix `/etc/hosts`，Windows 使用系统 hosts 路径），并用 `HostsTable::overlay` 保证显式配置覆盖系统值；同一层同时供 `AsyncHostsResolver` 和 connection metadata selector 使用。新增注释、IPv4/IPv6、别名/非法行与覆盖优先级回归；握手后才可见的底层 socket interface、Android/macOS 原生 interface backend 仍未伪造兼容。
> 2026-08-09 runtime settings 应用：新增 `RuntimeSettings`，由 persisted `settings` JSON 解析并随 `RuntimeSnapshot` 原子 reload；`ipv6` 现在统一约束共享 resolver、按 ID resolver、DNS answer 和 TUN `portalV6`，默认 pprof 兼容 Go 的历史默认值。新增 settings parser、IPv6 resolver、snapshot reload 和 TUN 配置回归；`useDefaultInterface/netInterface` 真实 socket bind、buffer/semaphore 调优和 pprof endpoint 仍未宣称完成。`cargo test -p yuhaiin-runtime --all-features --offline` 当前 133 个单测、7 个集成测试通过；Podman Debian testing privileged TUN smoke 输出 `tun-opened`，route smoke 输出 `tun-route-installed`。
> 2026-08-09 Go settings KV compatibility：进一步补齐真实 Go SQLite 的 `settings_kv(section,key,value_json)`。Rust 在没有 `settings` overlay 时从该表读取全局 settings，`settings.get` 返回同一前端字段形状；Rust `settings.put` 在旧表存在时回写已知 scalar keys，未知 platform/application rows 保持不变。生产形状 Go v6 fixture 已覆盖读取与回写，避免把配置保存到 Rust 私有 key 后 Go 兼容层看不到。真实 socket bind、buffer/semaphore 调优和 pprof endpoint 仍未完成。
> 2026-08-09 DNS server compatibility：`run_dns_supervisor` 与 resolver server API 现在遵循 Go 的来源优先级：Rust `resolver.server` overlay 优先，否则读取/回写 `dns_settings.server`；因此真实 Go SQLite 导入后配置的监听地址不再被遗漏。新增 Go v6 fixture server 读写和 overlay precedence 回归；DNS server 的完整 TCP/UDP/DoH/DoT transport 组合及 DoQ/DoH3 仍按清单推进。
> 2026-08-09 DNS server UDP/TCP owner：Rust runtime DNS supervisor 现在在同一配置地址同时启动 UDP 与 RFC 1035 TCP listener，共用 immutable snapshot 的 `RuntimeDnsHandler`，reload/shutdown 同时收敛两条 listener；runtime 新增同地址双协议回归，Podman Debian host-network smoke 实际查询 UDP/TCP 均返回答案。DoQ/DoH3 仍按低优先级延期。
> 2026-08-09 runtime settings data-plane policy：`relayBufferSize` 已进入 HTTP/SOCKS4A/SOCKS5/Trojan/VLESS inbound 的 counted relay；`udpBufferSize` 与 `udpRingbufferSize` 已进入 SOCKS5/Trojan/VLESS/Yuubinsya UDP loop 和 runtime DNS UDP listener；`happyEyeballsSemaphore` 通过 snapshot-owned connect budget 限制 TCP 建连并在 live selector reload 时替换。新增 buffer、UDP loop、selector reload 的编译/运行时覆盖；这不是完整 IPv4/IPv6 happy-eyeballs racing，`useDefaultInterface/netInterface` 的真实 socket bind 与 pprof endpoint 仍待完成。

## 1. 目标、边界和完成定义

### 1.1 目标

Rust 版本的第一阶段必须能够独立提供以下能力，并且可以逐步替换 Go 进程中的对应链路：

1. FakeIP：IPv4/IPv6 地址池、域名正向映射、IP 反向映射、持久化、旧数据迁移。
2. DNS：resolver、DNS server、UDP、DoH/HTTP2、DoT；异步 UDP server 提供可由 owner future 取消的 `serve_until` 生命周期入口；TCP 作为 UDP 截断后的回退，DoQ/DoH3 延后。
3. Router：域名 trie、通配符、CIDR 最长前缀匹配、规则列表、resolver 选择、proxy/direct/block 决策。
4. Proxy：`yuubinsya` 的 TCP、原生 UDP、UDP-over-TCP、迁移 ID、ping；TLS、HTTP/2、SOCKS5、HTTP CONNECT、direct、fixed、drop。
5. NAT：`/home/asutorufa/Documents/Programming/yuhaiin/pkg/net/nat` 的按源/迁移 ID 建流、UDP 转发、反向地址映射、目标解析缓存、空闲回收和有界背压。
6. TUN：系统 TUN 设备、IPv4/IPv6 packet loop、现成用户态 IP stack、TCP/UDP/ICMP 分发和平台路由生命周期；第一阶段只维护一条数据面路径。
7. MaxMindDB：GeoIP/GeoLite 数据库加载、IP/域名查询、热替换、关闭和 route matcher 注入。
8. SQLite：配置、规则、节点、resolver、inbound、统计和 FakeIP 状态的 schema/migration/repository；为兼容真实 Go SQLite 文件并控制资源占用，默认构建使用经过验证的 `rusqlite` bundled SQLite，并把 C binding 限定在数据库适配边界。

### 1.2 非目标

第一阶段不实现或不阻塞主线的内容：

- DoQ、DoH3：保留 transport trait 和 feature 位置，等纯 Rust TLS/QUIC 后端经过审计后再实现。
- 透明代理、iptables/nftables、完整进程识别和所有平台网络配置的自动化细节；TUN 先完成 Linux/Android 主路径，再扩展平台。
- 完整复刻 Go UI、订阅系统、连接历史和所有高级协议；第一版必须提供可供现有前端使用的核心管理 HTTP API，但高级 endpoint 可以明确返回未实现错误。
- 为了“看起来完整”而先加入大量协议。未经过互操作测试的协议不应进入默认 feature。

### 1.3 完成定义

一个模块只有同时满足下列条件才算迁移完成：

- 有与 Go 行为对应的 trait/API 和错误语义，而不是只实现 happy path。
- 有纯本地单元测试、边界测试、并发测试；协议 parser 有 property/fuzz 测试。
- 有 Go/Rust 互操作测试，至少覆盖当前 yuhaiin 的 client/server 一端对另一端。
- 有可直接启动的 Rust 服务进程：SQLite 配置、管理 HTTP API、runtime reload，以及 Linux 上的单一路径 TUN 数据面能够组合运行。
- 有关闭、超时、取消、半关闭、重连和资源回收测试。
- `cargo tree` 中没有未经批准的 C/C++/系统库绑定；SQLite 的 `libsqlite3-sys` 仅作为已批准的 bundled backend 例外，默认 feature 仍不启用 `native-tls`、OpenSSL、`ring` 或 `aws-lc-sys`。
- 失败时能区分：输入错误、超时、远端拒绝、连接关闭、取消、资源耗尽和内部错误。

## 2. 当前 Go 实现的事实基线

迁移以当前 Go 源码为准，而不是以旧文档或包名猜测为准。对应入口如下：

| 能力 | Go 参考实现 |
| --- | --- |
| FakeIP | `pkg/net/dns/fakeip/fakeip.go`、`pool.go`、`sqlite.go` |
| DNS resolver | `pkg/net/dns/resolver/dns.go`、`udp.go`、`tcp.go`、`doh.go`、`dot.go`、`group.go` |
| DNS server | `pkg/net/dns/server/server.go` |
| 通用 trie | `pkg/net/trie/trie.go`、`domain/*`、`cidr/*` |
| Router | `pkg/route/route.go`、`rule.go`、`list.go`、`runtime_types.go` |
| Yuubinsya | `pkg/net/proxy/yuubinsya/header.go`、`packet.go`、`client.go`、`server.go`、`uot.go` |
| 其他 proxy | `pkg/net/proxy/direct`、`fixed`、`drop`、`http`、`http2`、`socks5`、`tls` |
| NAT | `pkg/net/nat/table.go`、`source.go`、`migrate.go` |
| TUN | `pkg/net/proxy/tun/tun.go`、`gvisor/*`、`tun2socket/*`、`pkg/net/netlink/tun.go` |
| MaxMindDB | `pkg/net/trie/maxminddb/db.go`、`pkg/route/list.go` |
| SQLite/config | `pkg/storage/sqlite/*`、`pkg/store/*`、`pkg/legacy/chore/sqlite_db.go` |

必须保留的已知行为：

- FakeIP 不是简单的内存哈希：当前实现会保存 cursor、映射和 `last_used_at`，并且旧安装可能同时存在历史 fakeip bucket、SQLite fakeip 表和旧 Pebble 数据。
- resolver 的 A/AAAA 查询通常并行；UDP 响应按 DNS ID 加 question 匹配；TC 响应需要用 TCP 重试；DoH 使用 `application/dns-message`，并通过自定义 dialer 走 yuhaiin proxy。
- 域名匹配是反向 label trie，不是普通字符串前缀；CIDR 匹配需要最长前缀语义。
- Router 先把匹配列表和 resolver policy 写入 flow context，再选择实际 proxy；不能在每一层重新解析并覆盖这些状态。
- Yuubinsya 的认证 token 是 `SHA256(password + "+s@1t")`，不是密码本身；wire protocol 需要保留历史 protocol number 和 UDP migration ID。
- NAT 的 key 为 `MigrateID`，没有 migration ID 时使用源地址 comparable key；一个 key 对应一个长期 UDP flow，不能为每个数据包重新建连接。

## 3. 总体架构

### 3.1 推荐 workspace

建议第一步就建立 workspace，但只创建空的、可编译的 crate；每个 crate 只依赖更底层的 crate。

```text
yuhaiin-rust/
├── Cargo.toml                 # workspace、统一 lint 和依赖版本
├── MIGRATION.md
├── crates/
│   ├── yuhaiin-core/          # 地址、flow context、错误、基础 trait
│   ├── yuhaiin-io/            # tokio socket、dial、监听器、stream/datagram 封装
│   ├── yuhaiin-crypto/        # hash、密码 token、TLS provider 适配
│   ├── yuhaiin-trie/          # domain/cidr/combined trie，纯数据结构
│   ├── yuhaiin-store/         # SQLite schema/repository、redb 可选缓存、迁移接口
│   ├── yuhaiin-fakeip/        # FakeIP pool 和 DNS answer 变换（初版暂在 yuhaiin-store::fakeip）
│   ├── yuhaiin-dns/           # DNS message、resolver transports、server
│   ├── yuhaiin-proxy/         # proxy trait、direct/fixed/drop 等基础实现
│   ├── yuhaiin-proxy-yuubinsya/ # Yuubinsya wire codec、client、server
│   ├── yuhaiin-proxy-http/    # HTTP CONNECT、HTTP/2、SOCKS5、TLS wrapper
│   ├── yuhaiin-protocol/      # 可组合协议 wire codec/transport（Shadowsocks/Trojan/VLESS/WebSocket）
│   ├── yuhaiin-chain/          # 当前可运行的 fixedv2 -> 可选 TLS/WebSocket -> HTTP/2 -> Yuubinsya 组合
│   ├── yuhaiin-router/        # list snapshot、rule matcher、route dispatch
│   ├── yuhaiin-nat/           # UDP NAT table/source control
│   ├── yuhaiin-tun/           # tun-rs device + smoltcp adapter、TCP/UDP/ICMP ingress（初版暂在 yuhaiin-core::tun）
│   ├── yuhaiin-geo/           # MaxMindDB reader、GeoIP snapshot、热替换
│   ├── yuhaiin-config/        # SQLite migrations、typed repositories、backup/export
│   ├── yuhaiin-runtime/       # RuntimeSnapshot、hosts/FakeIP/resolver/proxy 组装和 reload
│   └── yuhaiin-interop/       # 仅测试：Go/Rust 互操作 fixture 和 harness
└── deny.toml                  # 依赖许可证、来源和 native link 审计
```

如果早期实现量较小，可以先把后三个 proxy crate 合并到 `yuhaiin-proxy`，但代码目录仍按
`codec/transport/client/server` 分开。拆 crate 的目的是依赖方向和测试隔离，不是为了增加层次。

### 3.2 依赖方向

```text
core
 ├── io
 ├── crypto
 ├── trie
 └── store
       └── fakeip
              └── dns

proxy  ───────────────┐
fakeip/dns ────────────┼──> router ───> nat
core/io/crypto ────────┘

config/sqlite ────────> store ───> fakeip/dns/router
geo ──────────────────> router
tun ──────────────────> router/nat/proxy
```

实际依赖不允许 `proxy -> dns`。resolver 通过 trait 注入，Proxy 只接收
`Dialer`/`Resolver` trait；`router` 或 app 负责把具体 resolver 和 proxy 组装起来。这样可以避免：

- proxy 为连接远端域名时反向调用完整 router，造成递归；
- DNS 为 DoH 建连接时又进入 DNS，造成死循环；
- NAT 的 `skip_route` 语义被某个 wrapper 丢失。

`ConfigStore::status()` 提供 schema version、Go import marker、journal mode、page/freelist、`quick_check`
和 Full Cone NAT 状态；它直接返回 store 的共享记录，供未来 HTTP/reload handler 使用，不复制一套 DTO。

当前 `yuhaiin-runtime` 只依赖已有的 compatibility/runtime structs：`RuntimeBuilder` 读取
hosts、FakeIP、resolver、route 和 proxy records，发布一个 `RuntimeSnapshot`；`RuntimeHandle`
为 TUN、代理和未来 HTTP/reload handler 提供共享 `Arc<RuntimeSnapshot>`，只在完整构建成功后
原子 publish；`revision`/条件 publish 会拒绝陈旧的并发 reload，`load_with_revision()` 在同一
读锁内返回版本和 snapshot，重建失败或被更新覆盖时保留旧 snapshot，不再额外引入 DTO；
`RuntimeController` 在同一个共享边界中提供 `ConfigMutation`/typed repository 持久化、串行 reload、
失败时保留旧 snapshot 和 `last_reload_error()` 状态；未来 HTTP handler 可以直接复用它，而不需要
自己管理 SQLite transaction、revision 或 DTO。`AsyncHostsResolver` 与 `FakeIpResolver` 按
hosts→upstream→FakeIP 顺序组合，proxy
通过同一个 `Arc<dyn AsyncIpResolver>` 构造。`RuntimeController::build_proxy_selector` 会注册
TUN selector，并在 reload 发布前准备新的 proxy slots；任一 proxy 构造失败时不发布新 snapshot，
已运行的 selector 和旧 flow 继续使用旧实例。`ResolverTransportFactory` registry 已提供
`RuntimeBuilder` 同时读取 `nat_config` 的 `default` 记录并把它放入同一个 snapshot；
`RuntimeSnapshot::new_full_cone_nat()` 将持久化 idle timeout 转换为 TUN 可直接使用的
`(NatTable, Duration)`，遇到 `full_cone=false` 或非法 timeout 会 fail-closed，避免运行时
悄悄退化成 restricted NAT。`RuntimeController::build_tun_proxy_runtime()`（或带 DNS
handler 的 `build_tun_proxy_runtime_with_dns()`）在同一个
reload 锁和同一个 snapshot 下组装 selector、Full Cone NAT 与 timeout，避免 TUN 启动时
读到彼此不一致的配置；packet-level DNS handler 继续由 DNS 层注入，不在 runtime 层
重复实现 DoH/UDP/FakeIP policy。
System/UDP/TCP 的按 ID 构造，route rule 的常见 domain/CIDR matcher、action、network/port
和 resolver policy 会编译为 `RouterRuntime`；route settings 可按 direct/proxy mode 选择
resolver，已构造 resolver 在查询失败或空结果时可回退到 shared resolver，构建失败可选择
fail-build 或 keep-unavailable，并已有同一 store 重建新 snapshot 的 reload 回归；无法表达的旧
matcher fail-closed。DoH 已提供 `RustCryptoDohResolverFactory` 的直连 TCP/TLS/ALPN h2
实现，并以 resolver timeout 取消完整响应 future；需要代理链或自定义 bootstrap 时仍使用
注入式 connector。启用 runtime `doh-tls` feature 后，`RustCryptoDohResolverFactory` 和
`RustCryptoDotResolverFactory` 提供直连 TCP/TLS 数据面；DoQ/DoH3 不允许无提示地回退 system
DNS，避免 DoH bootstrap 反向进入自身 proxy chain。启用 runtime `http2` feature 后，`H2DohResolverFactory` 复用 core
`H2DohClient`，由上层注入 TLS/proxy connector；
`RuntimeBuilder` 同时读取
`maxmind_metadata` 的第一条记录，用独立 `yuhaiin-geo::GeoDatabaseManager` 加载纯 Rust MaxMindDB 并注入 route snapshot；
reload 时旧 snapshot 继续持有旧 reader，不会被新 reader 提前关闭。

### 3.3 生命周期和并发原则

- 所有外部 I/O 使用显式 `CancellationToken` 或 request context；不要依赖全局 runtime 或线程局部变量。
- 配置和路由表使用不可变 snapshot：写入时构造新 snapshot，完成后一次性替换 `Arc`；查询只读取一个 snapshot。
- 不在 mutex、SQLite/redb transaction 或连接池锁中 `.await`。
- `close()` 必须幂等，先停止 producer，再停止 worker，再关闭 socket；不能让后台 task 永久持有 `Arc`。
- stream 和 datagram 是不同的能力；不要用一个“万能连接”把 `AsyncRead/Write` 强行模拟成 UDP。
- parser 只处理 bytes，不接触全局状态；验证、解码、业务处理三步分离，便于 fuzz。

## 4. 核心契约设计

### 4.1 Address

不能直接用 `SocketAddr` 作为全局地址类型，否则会丢失远端域名、FakeIP 原始域名和是否允许远端解析。

```rust
pub enum Endpoint {
    Ip { network: Network, addr: SocketAddr },
    Domain { network: Network, host: DomainName, port: u16 },
}

pub enum Network { Tcp, Udp, Icmp, Any }
```

要求：

- `DomainName` 在构造时做大小写、尾点、label 长度和非法字节校验；wire 层仍保留需要的原始表示。
- 提供 `comparable_key()`，key 必须区分 network、IP/domain、host、port 和必要的 scope id。
- 提供 `to_socks5_addr()`、`from_socks5_addr()`，仅由地址 codec 使用。
- `Endpoint::Domain` 在 route/proxy 传递链中保持不变；只有显式 `resolve_locally` 或 transport 需要 IP 时才解析。

### 4.2 Stream、Datagram 和 Proxy

建议使用 object-safe 的 boxed future，或者使用 `async_trait`，但不要把每个 proxy 的泛型暴露给上层：

```rust
pub trait Proxy: Send + Sync {
    fn connect(&self, ctx: &FlowContext, target: Endpoint) -> BoxFuture<'_, Result<BoxStream>>;
    fn open_datagram(&self, ctx: &FlowContext, target: Endpoint)
        -> BoxFuture<'_, Result<BoxDatagram>>;
    fn ping(&self, ctx: &FlowContext, target: Endpoint) -> BoxFuture<'_, Result<Duration>>;
    fn close(&self) -> BoxFuture<'_, Result<()>>;
}
```

`BoxStream` 需要支持 `AsyncRead + AsyncWrite + Unpin + Send`；`BoxDatagram` 至少提供：

```rust
trait Datagram: Send + Sync {
    fn send_to(&self, payload: &[u8], target: Endpoint) -> BoxFuture<'_, Result<usize>>;
    fn recv_from(&self, buf: &mut [u8]) -> BoxFuture<'_, Result<(usize, Endpoint)>>;
    fn local_addr(&self) -> Result<Endpoint>;
    fn close(&self) -> BoxFuture<'_, Result<()>>;
}
```

实际代码可用 `async_trait` 简化，但所有 trait 必须满足 `Send + Sync`，并且错误中包含操作名和目标。

### 4.3 FlowContext

把 Go `netapi.Context` 中会影响路由和 DNS 的状态显式化：

```rust
pub struct FlowContext {
    pub source: Option<Endpoint>,
    pub destination: Endpoint,
    pub inbound: Option<Endpoint>,
    pub network: Network,
    pub route_mode: RouteMode,
    pub resolver_policy: ResolverPolicy,
    pub resolver: Arc<dyn Resolver>,
    pub lists: Arc<ListMatchSnapshot>,
    pub original_domain: Option<DomainName>,
    pub fake_ip: Option<String>,
    pub udp_migrate_id: Arc<AtomicU64>,
    pub skip_route: bool,
    pub sniff_host: Option<DomainName>,
}
```

实现时可以把不变字段放在 `Arc<FlowMeta>`，把 migration ID 等少量可变字段放在独立的
`Arc<AtomicU64>`。禁止用一个大 `Mutex<FlowContext>` 包住整个连接生命周期。

### 4.4 Error taxonomy

`yuhaiin-core` 定义统一错误，底层错误通过 `source` 保留：

```text
InvalidInput
ProtocolViolation
AuthenticationFailed
ResolveFailed
DialFailed
Timeout
Cancelled
ConnectionClosed
Backpressure
Unsupported
Internal
```

对外日志需要带 `operation`、`target`、`proxy/resolver name`、`flow key`；密码、token、完整 DNS message 不进入普通日志。

## 5. FakeIP 迁移方案

### 5.1 行为模型

每个 address family 和 prefix 一个独立 pool：

```text
FakeIpManager
 ├── ipv4: FakeIpPool(prefix, max_entries)
 └── ipv6: FakeIpPool(prefix, max_entries)
```

接口：

```rust
trait FakeIpPool: Send + Sync {
    fn prefix(&self) -> IpNet;
    fn ip_for_domain(&self, domain: &DomainName) -> Result<IpAddr>;
    fn domain_for_ip(&self, ip: IpAddr) -> Result<Option<DomainName>>;
}
```

分配规则：

1. prefix 先 mask；cursor 初始为 prefix 的前一个地址。
2. 先查 domain -> IP；命中时更新访问时间，不重新分配。
3. 未命中时串行分配，二次查找避免并发重复映射。
4. cursor 在 prefix 内递增；到末尾后从头循环。
5. 先复用达到 TTL 的旧映射；仍达到 `max_entries` 时按 `last_used_at` 的 LRU 复用一个旧地址，再分配空闲 IP；池满时不能无限循环。
6. IPv4/IPv6、prefix、domain 都是查询 key 的组成部分；更换 prefix 不得误用旧映射。
7. 反查只能返回当前 pool 且仍有效的映射；不存在时返回 `None`，不能把池内任意 IP 当成域名。

Go 当前 SQLite 实现的 `last_used_at` touch 是延迟批量刷盘。Rust 的 `FakeIpPoolOptions::touch_interval_seconds` 在内存中更新命中时间，达到间隔后才写 typed 表；`flush_touches` 在关闭/配置替换前把所有 dirty touch 以一个事务刷盘。当前池不自行启动后台 worker，runtime 必须显式调用 flush 并处理错误，不能静默丢失 touch。

### 5.2 持久化：SQLite 主库，redb 可选

SQLite 不能省略：它是配置、规则、节点、resolver、inbound、统计和迁移兼容性的主存储格式；FakeIP
也应优先使用同一个 SQLite state DB，而不是另起一个与配置无关的数据库。

`yuhaiin-config` 负责 schema/migration/repository，`yuhaiin-store` 提供 typed repository trait，
FakeIP、Router、DNS 和控制面只依赖 trait，不直接拼 SQL。建议保留当前 Go schema 的主要表名和字段语义：

```text
metadata, migrate
settings_kv, settings_json
dns_settings, dns_resolvers, dns_hosts, dns_fakedns_lists
route_settings, route_rules, route_lists, route_list_refresh
inbounds, nodes, node_tags, subscriptions, backup_settings
statistics_kv, traffic_hourly, connection_sessions, connection_history
fakeip_entries, fakeip_cursors
```

FakeIP 的 SQLite schema：

```sql
CREATE TABLE fakeip_entries (
  family INTEGER NOT NULL,
  prefix TEXT NOT NULL,
  domain TEXT NOT NULL,
  ip BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  PRIMARY KEY (family, prefix, domain),
  UNIQUE (family, prefix, ip)
);

CREATE INDEX fakeip_entries_ip_idx
  ON fakeip_entries(family, prefix, ip);

CREATE INDEX fakeip_entries_lru_idx
  ON fakeip_entries(family, prefix, last_used_at);

CREATE TABLE fakeip_cursors (
  family INTEGER NOT NULL,
  prefix TEXT NOT NULL,
  cursor_ip BLOB NOT NULL,
  cursor_idx INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (family, prefix)
);
```

正向和反向索引必须在同一个 SQLite transaction 中更新。分配事务的最小步骤：

```text
begin write
  re-check domain
  count/reuse one IP
  remove old reverse entry if reusing
  insert domain entry
  insert reverse entry
  update cursor
commit
```

不要用两个独立 transaction 写正向和反向索引，否则崩溃后可能出现“正向存在、反向不存在”。当前 `ConfigStore::replace_fakeip_entry`、`delete_fakeip_entries` 和 `touch_fakeip_entries` 都只从 `yuhaiin-store` 暴露 typed transaction boundary，FakeIP pool 不直接拼 SQL。

`FakeIpPool::open_with_prefix` 用显式 canonical prefix（例如 `198.18.0.0/15`）加载生产表；旧的通用 KV `fakeip/map/*`、`fakeip/ipv6/map/*` 只作为一次性兼容输入，成功写入 typed rows/cursor 后在同一事务内删除。`open` 仍为只有 start/end 的旧调用者生成稳定的 range prefix。`FakeIpPoolOptions` 同时约束 TTL、容量和 touch 间隔，`allocate_at` 供 deterministic clock 测试使用。

#### SQLite engine 选择

- 当前实现使用 `rusqlite 0.40.1` 的 `bundled` feature，由 SQLite amalgamation 构建，并通过 `crates/yuhaiin-store/src/sqlite.rs` 的小型 typed adapter 隔离底层 API。选择依据是实测而不是语言纯度：在同一份 415,334,400-byte 的真实 Go v5 FTS-free snapshot 上，rusqlite 完成复制、WAL/NORMAL 配置和行查询，probe 输出约 53 ms copy、232 ms configure、RSS 约 5.6 MiB；此前 fsqlite 在相同迁移场景超过 90 秒仍未完成，RSS 约 1.28 GiB。因此 fsqlite 不再作为生产后端，纯 Rust 实现保留为未来可替换 adapter 的研究方向。
- 真实 Go v5 snapshot 仍必须先移除可重建的 `nodes_fts` 派生索引、校验 manifest/hash，再交给 Rust 安装；未移除 FTS5 的原库仍然 fail-closed，不能把 exporter 边界问题误判为普通 SQLite 数据损坏。当前 rusqlite bundled SQLite 已通过 206 nodes、27,439 FakeIP rows、IPv4/IPv6 双 cursor 的真实导入读回，以及 store 全量单元/跨进程 WAL 测试。FakeIP typed schema 的 8,192 次双栈长 soak 已通过；后续仍需更多真实生产 snapshot。
- 在同一份实际生产数据副本上运行当前 Go migration version 6 后，Go exporter 生成的 60,973,056-byte schema v6 FTS-free snapshot 也已由 Rust 安装；source/destination `quick_check` 均为 `ok`，206 nodes、27,439 FakeIP rows、15,483 IPv4 + 11,956 IPv6 mappings 和两个 cursor 均保持。这个结果证明了“真实旧数据 + 当前 Go v6 migration + Rust 安装”链路，但不替代未经本地升级的原生 Go v6 生产快照。
- 当前 Go v5 telemetry、Go v6 plain-contract 最小 fixture、生产形状 fixture、Go v1 legacy 显式升级和未建模字段策略记录在 [GO_COMPATIBILITY.md](GO_COMPATIBILITY.md)；Rust 已覆盖 Go schema import 的幂等 marker、schema v1→v3 与 v2→v3 迁移、部分 typed 表创建后的下一次启动修复，以及六类 `_v2` compatibility view 的事务性 typed writeback/delete。Go v1 源表改名后只读归档，空 `_v2` 表才执行 resolver/route 字段映射；已有 `_v2` 保持权威。未知 JSON 字段保留，`nodes_v2`、`inbounds_v2`、`node_tags_v2`、`route_lists_v2` 等 Go v6 compatibility JSON 边界统一 fail-closed，非法 legacy/Go v6 JSON 会回滚并在修复后重试；未建模的 Go v5 telemetry 表和数据保持不删除。仍需用更多真实生产库/异常中断注入补充文件级 WAL/损坏恢复。
- Rust migration 在事务提交前校验 `yuhaiin_meta`、`yuhaiin_config` 以及 Rust-owned typed 表的列名、声明类型、可空性、主键位置和 FakeIP 唯一/二级索引；缺失的 FakeIP 反向唯一索引会在事务内安全补建；已有同名索引但列/唯一性不匹配时 fail-closed，保留原表和 schema version，修复后可重试。Go v6 importer 对实际导入字段的 ID、时间戳和 JSON 做 fail-closed 校验，同时保留精简旧 compatibility 表的列兼容；Go compatibility repository 的 JSON 读写也使用同一校验边界。Go `metadata.schema_version` 与 `migrate.version` 会逐行检查负数、NULL、错误类型和未来版本，并要求两个来源一致，避免一个合法来源掩盖另一个损坏来源。backup、restore 和 Go snapshot install 对 destination sidecar 做保护：缺失目标但存在 WAL/journal/锁 sidecar 时拒绝操作，失败路径不清理外部 destination sidecar。负 Rust schema version 会 fail-closed。Full Cone NAT 的 `full_cone=1` 兼容约束仍由 repository 的读写校验强制，避免破坏旧 Go/Rust 数据表。
- 当前 `yuhaiin-store` 按职责拆分为 `src/lib.rs`（公开类型、ConfigStore 生命周期和基础事务）、`src/schema.rs`（Rust schema contract/SQLite introspection）、`src/migration.rs`（Go import/legacy upgrade）、`src/repository.rs`（typed/Go repository）、`src/sqlite.rs`（backend adapter）和 `src/fakeip.rs`（FakeIP runtime）；测试按 `src/tests/{storage,schema,go_import,snapshot,repository}.rs` 与 `src/fakeip_tests.rs` 分组。core 的 `nat.rs`/`tun.rs` 也将测试拆到 `nat_tests.rs`、`tun_test_support.rs`、`tun_unit_tests.rs`、`tun_proxy_tests.rs`、`tun_runtime_tests.rs`，避免协议实现文件继续膨胀；TUN 仍只采用 `tun-rs AsyncDevice + smoltcp` 一条路径，NAT 仍保持 endpoint-independent Full Cone 语义。
- `rusqlite` bundled SQLite 是当前批准的生产后端；`sqlx-sqlite`、`libsql` 等候选不进入默认构建，除非重新通过真实文件兼容、资源占用、WAL/崩溃恢复和跨进程测试。
- 如果必须打开一个由官方 SQLite/Go 生成的任意历史数据库，先用 fixture 验证 SQLite 文件格式、JSON/FTS/transaction/pragma 兼容性。当前 Go 的 `nodes_fts` 是可从 `nodes` 重建的派生索引，正式迁移前应由 Go/export bridge 生成一致快照并排除该 FTS5 shadow table，再交给 rusqlite；不满足时使用 Go 导出 NDJSON/SQL dump，再导入 Rust。Rust 侧的真实 snapshot 回归必须使用该 FTS-free export，并同时保留未处理原库的 fail-closed 回归。
- 正式导出命令为 `GOEXPERIMENT=jsonv2,greenteagc go run ./cmd/yuhaiin-rust-export -source /path/to/state.db -output ~/.cache/yuhaiin-rust-check/go-state-<unique>.sqlite`。它用 `VACUUM INTO` 获取包含 WAL 已提交数据的一致副本，在副本事务中删除可重建的 FTS5 virtual table，执行 `quick_check`，生成带 schema/tool version、FakeIP 行数、移除表、字节数和 SHA-256 的 `.manifest.json`，并拒绝覆盖已有 output/manifest；source 不会被修改。停止 Go 写入者是迁移边界的一部分，不能把正在写入的 live file 当作静态 fixture。
- Go snapshot 生成后，执行 `cargo run -p yuhaiin-store --all-features --offline --bin go_snapshot_migrate -- --source ~/.cache/yuhaiin-rust-check/go-state-<unique>.sqlite --destination ~/.cache/yuhaiin-rust-check/rust-state-<unique>.sqlite`。Rust 入口会自动校验同名 manifest、拒绝非空 WAL source，先在 sibling staging file 中完成 schema/import，再 checkpoint 并 atomic rename；destination 已存在、manifest/hash 不匹配、导入失败或 source 不符合 consistent snapshot 契约时不会覆盖最终 state。
- `redb` 只作为可选的高速 cache、临时索引或未来的纯 Rust 替代后端，不能成为配置数据的唯一来源，也不能让 FakeIP 和配置 DB 产生两套不一致的事实源。
- repository 通过本地 typed SQLite adapter 接入底层 backend；未来如果需要第二个 backend，再把该 adapter 提升为明确的 `DatabaseEngine` trait。当前 `ConfigStore::backup_to` 使用写锁内的 `VACUUM INTO` 生成一致快照，随后用 staging 数据库启动/完整性校验、checkpoint 和 atomic rename 安装；`restore_database` 要求运行中的目标 `ConfigStore` 先关闭，校验 backup 后再原子替换目标，损坏 backup 不会改动目标文件；`compact_if_needed` 读取 `freelist_count`，只有达到调用方阈值才执行 checkpoint/VACUUM。backup/restore、schema migration、transaction、vacuum/compact 和 corruption recovery 均有独立测试。

#### 配置 repository 规则

- `Database::open(path)` 只负责打开文件、设置 busy timeout/WAL 等策略、执行幂等 migrations 和返回连接句柄；不能在构造过程中启动 resolver、TUN 或下载 GeoIP。
- 单个 repository 方法代表一个完整业务写事务，例如 `save_route_rule`、`save_resolver`、`save_tun_settings`、`save_fakeip_entry`；上层不能拿裸 connection 跨 crate 修改表。
- SQLite 中的 bool 使用 `INTEGER NOT NULL CHECK (value IN (0, 1))`，enum 使用稳定的整数或字符串 code；JSON 只用于扩展字段，核心字段必须是可索引列。
- 任何“配置写入 + runtime apply”流程先 commit SQLite，再构造新 runtime snapshot；新 snapshot 成功后原子替换，旧资源在锁外 close。runtime apply 失败不能回滚已经成功的配置写入，但必须记录 error/status，重启时可以重试。
- `dns_hosts` 先通过 `ConfigRepository::list_go_dns_hosts()` 读取为兼容记录，再由上层通过 `HostsTable::insert_target()` 转换；HostsTable 同时可注入同步 `HostsDnsHandler` 和异步 packet handler，A/AAAA 命中静态地址或 alias 链，其他 record type 或未解析 alias 继续走 upstream。target 仍保留为字符串，store 层不擅自改变原始配置。
- schema version、migration name、applied timestamp 和 source format 写在 `migrate`/`metadata`；migration 必须事务化、可重复探测，禁止依赖“当前表是否存在”推断半迁移状态。
- backup 采用 SQLite consistent snapshot 或 repository export；恢复先写临时文件并执行 integrity check，再原子替换。恢复期间不能让运行中的 resolver/TUN 持有旧 DB connection。
- 统计和连接历史属于可清理数据，不得与 route/DNS/TUN 配置共用不可回收的 transaction；提供 retention/compact 测试。

### 5.3 DNS answer 行为

`yuhaiin-fakeip` 只负责 answer transform，不负责选择 route：

- A/AAAA：按 resolver policy 生成 fake address；IPv6 disabled 时返回空 AAAA。
- FakeIP skip-check 关闭时，先请求 upstream，只有 upstream 有对应记录时才生成 fake answer。
- PTR：把 `in-addr.arpa`/`ip6.arpa` 反解为 fakeip pool 的 domain；无映射时回源 resolver。
- HTTPS/SVCB：从 upstream message 取 IP hint，写入对应 FakeIP pool 的正反向映射；返回给客户端前把 `ipv4hint`/`ipv6hint` 替换为 FakeIP，其他 target、priority、ALPN、ECH 和未知 SvcParam 原样保留，避免客户端绕过 FakeIP。
- 非 A、AAAA、PTR、HTTPS、SVCB 查询直接交给 upstream。
- hosts override 位于 resolver upstream 之前：已知 host 的 A/AAAA 返回配置地址（缺少对应 family 时返回空集合），alias 可沿有限链解析，未解析 alias 和未知 host 回源，PTR/HTTPS/SVCB 继续回源；同步、异步 handler 共用同一个可热更新 `HostsTable`，alias cycle 作为配置错误返回。
- 非法 domain 返回 NXDOMAIN/输入错误，不把任意字符串写入 pool。

`Raw` 变换必须保持 request ID、question、rcode、TTL 和 EDNS 相关字段的合法性，并增加固定 wire fixture 测试。

### 5.4 旧数据迁移

迁移顺序：

1. 启动时读取迁移 metadata；已完成且 source fingerprint 未变化时跳过。
2. 优先支持当前 Go SQLite fakeip schema（`fakeip_entries`、`fakeip_cursors`）。
3. 支持旧 Pebble 的 `prefix.String()` bucket 以及历史 `fakedns_cache`/`fakedns_cachev6` 布局。
4. 对每条记录检查 family、prefix、IP 是否合法，非法记录计数并跳过；不能让一条坏记录阻塞全库。
5. 迁移写入 SQLite 的正向/反向索引和 cursor，单批事务提交。
6. 完成后写 metadata；失败时不写完成标记，重启可幂等重试。
7. 在新实现稳定前保留 Go 导出工具：将旧 SQLite/Pebble 转成版本化 NDJSON，再由 Rust `LegacyFakeIpExport::parse_ndjson`（IPv4）或 `LegacyFakeIpV6Export::parse_ndjson`（IPv6）完成严格校验，最后交给对应的事务性 importer 导入。这是无法安全解析旧 SQLite 文件时的后备路径；Rust 不直接打开 Pebble 文件。两个 address family 使用独立 marker、typed scope 和 cursor，迁移失败不会留下半成品。Go v6 `_v2` 配置导入还会主动校验 `data_json`，即使损坏数据库绕过原始 `json_valid` 约束，也必须 fail-closed 并在修复后重试。

迁移不应在 resolver 的全局锁、DNS server listener 或 NAT source lock 中执行。先读取配置 snapshot，再创建 FakeIP manager，最后把 manager 注入 resolver；关闭旧 resolver/DB 必须在保护锁外执行。

### 5.5 FakeIP 验收测试

- 同一 domain 并发 1000 次只生成一个 IP。
- IPv4/IPv6 两个 pool 相互隔离；prefix 改变后旧 entry 不命中。
- cursor 重启后继续而非从头覆盖。
- 池满、循环、过期复用、反查和错误 IP 全覆盖。
- SQLite transaction 在中途注入错误后，正向/反向索引保持一致；跨进程 force-stop 不能留下未提交 FakeIP row。
- Go 生成的 fakeip DNS request/response 与 Rust 结果逐字节或按允许字段比较。
- 旧 SQLite/Pebble fixture 可重复导入，第二次导入不产生重复数据。
- 配置 schema 从空库、旧版本库、缺失 migration marker 和部分失败 migration 恢复；重复启动不重复执行 migration。
- DNS codec 与 FakeIP owner-future handler 已覆盖 A/AAAA/PTR/HTTPS/SVCB；SVCB/HTTPS target、priority、ALPN、ECH、未知 SvcParam 和 root target 可 round-trip，本地 `in-addr.arpa`/`ip6.arpa` 命中在调用 upstream 前返回，未知映射保留 upstream fallback；服务 binding 的 IPv4/IPv6 hint 会分别映射到对应 FakeIP pool。
- SQLite busy timeout、并发读、单写者、WAL/checkpoint、VACUUM/compact、备份恢复和损坏数据库错误都要有测试。

当前跨进程验收还覆盖 12 个 batch writer 与 6 个 reader 的 WAL 压力、FakeIP typed row
force-stop，以及独立进程
force-stop/reopen。`ConfigStore` 对每个文件数据库使用同目录 sidecar 的标准库
`File::lock()` 串行化 startup/migration 和写事务，读操作仍可并发；对 busy/locked
和 SQLite 并发 WAL/lock 的明确瞬态错误执行有界退避。持久化
`quick_check`/WAL frame integrity 错误仍 fail-closed，不会被无限重试掩盖。测试
runner 会串行调度不同数据库 fixture，避免测试进程复用相同的缓存路径；每个 fixture
内的 writer/reader 仍保持真实并发。sidecar 文件随数据库
路径生成，异常退出时由操作系统释放锁，测试清理它但不把它当作数据库内容。

## 6. DNS resolver 与 server

### 6.1 分层

```text
Resolver (LookupIP / Raw / Close)
 ├── Cache + singleflight
 ├── A/AAAA policy and parallel lookup
 ├── Group (staggered fallback / first success)
 ├── Transport: UDP / TCP / DoT / DoH2
 └── optional FakeIP / Hosts wrapper
```

`Transport` 只接受已经编码的 DNS message，并返回解析后的 message；它不负责 route policy 和 fakeip。这样 UDP、DoH、TCP 都能共享 message/cache/TC fallback。

### 6.2 Resolver client 行为

- `LookupIP` 的 PreferIPv4/PreferIPv6 只查询对应 qtype；默认 A 和 AAAA 并行。
- 两个 family 都失败时合并错误，但保留 family 信息。
- raw cache key 至少为 normalized name + qtype；TTL 取答案中可用 TTL，最小 TTL/最大 TTL 由配置限制。
- 同一个 raw query 使用 singleflight；超时的 caller 不能取消其他 caller 已经在用的 request，除非它是唯一 owner。
- request ID 必须与 response ID 相同；question 不匹配视为协议错误。
- response `TC` 时丢弃该答案并用 TCP/DoT 重试；TCP message 使用两字节 big-endian length。
- HTTPS/SVCB answer 的 IPv4Hint/IPv6Hint 由 FakeIP wrapper 分别替换为 v4/v6 fake address；service binding 的其他字段和未知参数不丢失。
- resolver close 要取消 transport worker、释放 UDP socket、停止 refresh worker 和关闭 HTTP2 pool。

### 6.3 UDP transport（第一优先级）

采用单个 transport 级 UDP socket 加 response dispatcher：

```text
query task -> bounded write channel (capacity ~200)
                         |
                    UDP socket
                         |
                read loop / parser
                         |
     (dns id, name, qtype) -> pending request
```

要求：

- 远端是 domain 时通过注入的 bootstrap resolver 解析；不能调用正在初始化的 resolver 自身。
- response map key 保留 Go 的 `id:name|qtype` 语义；同 ID 但 question 不同不能错误唤醒。
- read timeout 后关闭 socket，下一次写请求再 lazy reconnect。
- write 和 read 都有独立 deadline；ctx cancel 必须移除 pending request。
- UDP message 大小受 `MaxSegmentSize` 限制；超大或无法 decode 的包丢弃并记录计数。
- server 端 UDP 每个请求复制独立 bytes，并受 semaphore 限制，不能让单个客户端无限占用 task。

### 6.4 DoH/HTTP2

第一版实现 DoH POST：

```text
POST /dns-query
Content-Type: application/dns-message
Accept: application/dns-message
body = packed DNS message
```

- 支持 URL 没有 path 时默认 `/dns-query`。
- TLS ServerName 默认取 URL hostname，可被配置覆盖。
- HTTP dial 使用 `Proxy::connect`，不能直接调用系统 `TcpStream::connect`，否则 route/proxy 和 bootstrap 规则会失效。
- 使用 HTTP/2 connection pool、idle timeout、read-idle ping；response status 非 200、body 为空、超过上限或 DNS decode 失败都返回错误。
- DoH client 发送 request body 前保持 request stream open；单次 query 只等待完整 response body，同时继续驱动 HTTP/2 connection，不等待服务端主动关闭长连接。这样既避免 `end_stream` 提前结束造成的 H2 frame error，也允许标准 keep-alive DoH server 正常返回。
- GET/base64url 可以作为兼容扩展，但不是第一阶段的主路径。
- DoH JSON API 只作为低优先级管理/诊断接口，不代替 wire-format DoH。

### 6.5 DNS group

保留 Go `Group` 的语义：第一个 transport 立即启动，后续 transport 默认间隔约 100ms 启动；前一个快速失败时可提前启动下一个。第一个成功且 `Rcode=Success` 的 response 胜出；若全部是非成功 response，保留第一个可用 fallback message。

实现为一个 cancellation-aware coordinator，不让每个 transport 自己创建无界 task。关闭 group 时广播 cancel 并等待 children 退出。

### 6.6 DNS server

支持 UDP 和 TCP：

- UDP：decode request、并发限制、调用 `resolver.raw`、恢复 request ID、encode response、写回源地址。
- TCP：两字节长度前缀，读取完整 message，处理一次 request 后按当前 Go 行为关闭连接；以后可增加 keep-alive。
- 每个 request 创建带 timeout 的 `FlowContext`；`force_fakeip` 写入 resolver policy，而不是修改全局 FakeIP 开关。
- 空 question、非法 packet、超长 length、写回失败都必须是明确错误。
- server close 要同时关闭 UDP/TCP listener，并等待 in-flight requests 或取消它们。

### 6.7 DoQ/DoH3 后置

为 `DnsTransport` 保留 `doq`/`doh3` 类型注册点，但默认不编译。它们需要同时回答：QUIC 实现、TLS provider、HTTP/3、0-RTT 和证书验证是否满足纯 Rust 审计；在此之前不能偷偷把 `quinn` 默认 crypto feature 带入主依赖。

## 7. Trie 与 Router

### 7.1 Trie 数据结构

`yuhaiin-trie` 只包含数据结构和匹配语义，不依赖 Tokio、DNS 或 proxy。

#### Domain trie

- domain 按 label 反向插入：`www.example.com` 的查询顺序为 `com -> example -> www`。
- 完整域名优先于父域名；父域规则能匹配子域名。
- `*` 是单个 label 的 wildcard，必须严格实现当前 Go trie 的 wildcard fallback 语义。
- 规范化大小写和尾点；不要把 `example.com.evil.com` 当成 `example.com`。
- 插入、删除构造新 snapshot；查询无锁读取 `Arc<DomainTrie<T>>`。

#### CIDR trie

- IPv4、IPv6 分开根节点。
- 查询返回最长匹配 prefix 的 mark。
- insert/remove 后 snapshot 替换，不在查询中修改节点。
- 覆盖 `/0`、host route、重叠 prefix、IPv4-mapped IPv6 和非法 prefix。

#### Combined matcher

```rust
pub struct Matcher<T> {
    pub domain: DomainTrie<T>,
    pub cidr: CidrTrie<T>,
}

pub fn search(&self, endpoint: &Endpoint) -> Vec<T>;
```

如后续添加 process trie、MaxMindDB，使用新的 matcher source，不把数据塞进 domain/cidr 节点。

### 7.2 Router 决策顺序

保留当前 `Route::dispatch` 的阶段顺序：

1. 创建/取得 flow context，执行 loopback/cycle guard。
2. 读取进程信息（若平台能力存在）；没有平台能力时返回 unknown，而不是模拟 direct。
3. 设置默认 resolver。
4. 查询 geo/list snapshot，把命中的 list 写入 match history。
5. 按 matcher 顺序运行：context route mode -> normal mode；第一个非 unspecified mode 胜出。
6. 根据 resolve strategy 设置 resolver policy：only/prefer IPv4/IPv6。
7. 根据 UDP proxy FQDN strategy 决定是否 resolve target。
8. 选择 mode、tag、resolver；若 `resolve_locally` 且为 proxy，再显式把 domain 替换成 IP，同时保留 original domain。
9. `Conn` 调用 proxy 的 stream，`PacketConn` 调用 proxy 的 datagram；block 使用 drop 或 reject policy，不通过 direct。

`Dispatch` 是 NAT 和某些 transport 使用的“只把逻辑地址变成实际地址”接口，必须支持 `skip_route`。NAT 第一次建 flow 时可以 route，后续同一 destination 复用 dispatch/resolve cache，避免 UDP 每包重新决策。

### 7.3 规则配置与生效

规则表和 runtime matcher 分离：

```text
RuleStore -> RuleCompiler -> immutable MatcherSnapshot -> Router
```

规则保存可以立即持久化，但 runtime apply 可以延迟。保留 `apply_at`、版本号和成功清零的 status，便于 UI/控制面知道 list 何时真正生效。apply 过程不能在旧 snapshot 的读锁中 close/rebuild trie。

### 7.4 MaxMindDB

Go 端的 `pkg/net/trie/maxminddb` 只需要按 IP 查询国家 ISO code，并在目标是域名时先通过当前 flow resolver 得到候选 IP。Rust 版将它作为独立的 `yuhaiin-geo` provider：

```rust
pub trait GeoIp: Send + Sync {
    fn lookup_ip(&self, ip: IpAddr) -> Result<Option<CountryCode>>;
    fn lookup_endpoint(&self, ctx: &FlowContext, endpoint: &Endpoint)
        -> BoxFuture<'_, Result<Option<CountryCode>>>;
}
```

- 使用现成的 [`maxminddb`](https://docs.rs/maxminddb/latest/maxminddb/) crate；它支持 GeoIP2/GeoLite2，默认内存读取，`mmap` 是可选 feature，依赖树不需要 C library。
- 数据文件不放进 SQLite blob；SQLite 只保存下载 URL、版本、sha256、文件路径、last refresh、error 状态。
- 下载到临时文件，校验长度/sha256/MaxMind metadata 后 atomic rename；打开新 reader 成功后用 `Arc` 一次性替换旧 snapshot。
- 下载失败、文件损坏或 schema 不匹配时保留旧 reader，SQLite 记录 error；不能因为 GeoIP 更新失败让 Router 没有任何 geo provider。
- lookup 只返回纯数据 `CountryCode`；不把 MaxMind reader 的生命周期暴露给 route matcher。
- 域名查询遵循当前行为：使用 flow 的 `RouteIPs`/resolver 得到候选地址，逐个查询，首个成功 country 胜出；不能为了 geo 查询再次进入完整 route 造成递归。
- reader close 必须在 snapshot 替换完成且不再被引用后执行；不要持有 geo mutex 调用文件 I/O。

MaxMindDB 测试至少包含：官方 test database fixture、IPv4/IPv6、未命中、损坏文件、并发 lookup、热替换期间旧 reader 可用、关闭后 lookup 返回明确错误，以及域名解析失败不影响普通 route。

### 7.5 TUN 数据面

TUN 不是一个普通 proxy wrapper，而是系统入口：

```text
OS TUN device
      |
  packet reader
      |
IPv4/IPv6 parser + checksum/MTU validation
      |
  TCP / UDP / ICMP dispatcher
      |
FlowContext -> Router -> Proxy/NAT
      |
  packet writer -> OS TUN device
```

Rust 侧拆成三层：

1. `TunDevice`：设备创建、读写、batch、MTU、packet-info header、multi-queue、persist、close。
2. `IpStack`：IP packet decode/encode、TCP/UDP/ICMP socket state、fragment/MTU 和 timer。
3. `TunHandler`：把 TCP stream、UDP datagram、DNS request、ping 交给现有 Router/Proxy/NAT。

#### 第一阶段唯一实现路径：tun-rs + smoltcp

第一阶段不同时实现 tun2socket 和另一套用户态 stack。直接采用：

```text
tun-rs AsyncDevice
        |
smoltcp device adapter
        |
smoltcp Interface + TCP/UDP/ICMP sockets
        |
yuhaiin-tun adapter -> FlowContext -> Router -> Proxy/NAT
```

- `tun-rs` 负责创建/持有 TUN、异步读写、MTU、multi-queue、packet-info 和平台设备配置。
- `smoltcp` 负责 IP/TCP/UDP/ICMP packet parsing、checksum、socket state machine、timer 和回包构造。
- `yuhaiin-tun` 只做 adapter：把 smoltcp socket event 转成统一的 `StreamMeta`/`Packet`/`PingMeta`，把 Router/Proxy/NAT 的结果写回 smoltcp socket。
- UDP tuple mapping、TCP connection lifetime、DNS request 识别、FakeIP、route block/direct/proxy 由 adapter 与现有 NAT/Router 组合完成，不再复制一套 tun2socket NAT。
- `tun-routes` 是显式可选的系统 route 边界：`TunRouteLease` 先校验并规范化所有 route，再按顺序 add、失败时逆序 rollback、close 时逆序 remove；生产 Linux backend 使用纯 Rust `route_manager` netlink，不执行 `ip` shell 命令。route lease 只管理系统资源，不参与 NAT lookup；NAT 始终保持按 source/migrate ID 的 endpoint-independent Full Cone 语义。
- 首版只启用 smoltcp 实际支持且测试通过的 IPv4/IPv6 TCP+UDP/ICMP 子集；缺失能力返回明确的 `Unsupported`，不悄悄切换到第二套 stack。

这是“先用现成高性能库”的策略：先用真实 benchmark 和行为 fixture 验证 smoltcp。如果未来发现某项能力（例如特定 TCP option、分片、拥塞控制或平台 offload）无法满足，再把 `IpStackAdapter` 替换为自研实现；那是后续替换，不是第一阶段并行维护。

当前 Go 的 gVisor/tun2socket 只作为行为参考和互操作测试对象：双栈 gateway、UDP timeout、DNS request 判定、MTU、回写、关闭顺序都要覆盖，但 Rust 不照搬两套实现。

#### TUN 设备和平台边界

- 首选评估 [`tun-rs`](https://docs.rs/tun-rs/latest/tun_rs/) 的 async API；它覆盖 Linux、macOS、Windows、Android、iOS、BSD，并提供 multi-queue、MTU、persist、owner/group 和 async device 能力。
- TUN 创建最终仍然需要平台 fd/ioctl/driver API。第三方 crate 是否含 `libc`/系统 FFI 必须在 `cargo tree` 和源码审计中单独记录；“纯 Rust runtime”不等于可以忽略 OS ABI 边界。
- 所有平台 unsafe/FFI 只能集中在 `yuhaiin-platform`/`yuhaiin-tun`，上层不得直接操作 fd、ioctl 或平台路由命令。
- Linux 先覆盖 `/dev/net/tun`、netlink route、multi-queue、close-on-exec；Android 通过 VpnService/传入 fd；macOS 使用 utun；Windows 使用 Wintun 或传入已有 fd/handle。每个平台都要有 capability probe，缺能力时返回 Unsupported，不静默降级为普通 socket。当前 Linux probe 只读检查 `/dev/net/tun`、effective `CAP_NET_ADMIN`、route dump 和 tun driver 的 `multi_queue` 参数；不通过创建设备来探测，未知能力保持 `Unknown`。
- TUN portal、IPv4/IPv6 prefix、routes、MTU、gateway、DNS hijack、driver 和名称冲突处理写入 SQLite 配置，并在启动前做 prefix/MTU/route 校验。
- 设备创建成功后再设置地址和 route；任一 post-up 步骤失败必须按反向顺序清理设备和已安装 route。`TunRuntime::close_routes` 可重复调用，失败删除会继续保留 route lease 供显式重试；`Drop` 只做最后一次 best-effort cleanup，平台 app 必须优先调用显式 close 并记录错误。

#### TUN 测试

- 无权限环境测试 `TunDevice` builder 的配置校验、packet-info offset、MTU、名称冲突和 close 顺序，不要求真实设备。
- privileged CI 在 Linux 用 network namespace 创建临时 TUN，测试 tun-rs + smoltcp 的 IPv4/IPv6 TCP echo、UDP echo、DNS hijack、FakeIP、route block/direct/proxy 和回写。
- 单独测试 malformed IP header、短 TCP/UDP/ICMP、错误 checksum、fragment、超 MTU、未知 protocol、队列满和 reader close。当前 packet adapter 会分类 IPv4/IPv6 fragment，保留每个合法 fragment，不做第二套重组；ingress/egress 对每个 wire fragment 执行 MTU 边界检查。
- 用 deterministic clock 测试 smoltcp TCP retransmission、socket timer、UDP mapping timeout、NAT idle timeout 和 TUN shutdown；不要依赖真实 sleep 才能判定。
- TUN 与 Yuubinsya native UDP/UOT、SOCKS5 UDP、DoH endpoint、MaxMindDB domain lookup 做组合测试。

当前 Rust 实现已覆盖无权限的 UDP、TCP SYN/SYN-ACK、ICMP echo、IPv4/IPv6 fragment 分类、per-fragment MTU、超 MTU TX 丢弃和 TX queue backpressure 单元测试，并提供 `yuhaiin-core` 的 `tun-smoke` binary。Podman 特权 namespace 已验证设备创建、真实 IPv6 控制包过滤、IPv4 ICMP ingress、smoltcp ICMP socket 收包、真实 checksum 回包和 Linux kernel ping echo（0% loss）。

#### TUN 当前代码入口

- `yuhaiin_core::tun::TunRuntime::open` 是桌面最小设备入口，`TunRuntime::from_async_device` 是 Android/iOS `VpnService`/PacketTunnelProvider 外部 fd 注入入口，`open_with_routes` 是需要系统路由时的事务式启动入口；`yuhaiin-runtime::load_tun_config` 只读取共享配置，`run_tun_device_until` 接收已经创建的 `TunRuntime`，统一组装 DNS handler、snapshot selector、Full Cone NAT、dispatcher 和 reload/shutdown 生命周期。这样平台 host 只负责 fd/JNI/driver 权限，不需要复制 Go/TUN 上层 wiring。`TunRuntime::name()` 返回内核最终确认的接口名或外部设备配置名，`TunRuntime::shutdown` 提供显式的 route-before-fd-drop 关闭边界；不并行实现 tun2socket 或用户态第二套 IP stack。`open_with_routes` 的 route 配置失败会回收已创建设备并允许同名恢复；`tun-smoke` 的 `YUHAIIN_TUN_ROUTE_SMOKE=1` 会安装纯 Rust netlink route，便于在隔离 namespace 验收 shutdown、SIGKILL 和 route/device 清理；多进程验收还确认同名 TUN 不能被第二个 owner 抢占，首个 owner 终止后可重新启动。
- `TunRuntime::install_routes` 接收注入式 backend；Linux 使用 `install_linux_routes` 创建 `route_manager` netlink backend。route add/delete 和 rollback 可以在无 root 的 fake backend 单测中验证，真实 netlink 验收放在隔离 network namespace，避免测试修改宿主路由。
- `SmoltcpTunDevice` 的 RX/TX 队列有界，队满返回 `WouldBlock`，不会静默丢包或无限增长；TUN 是软件 checksum 边界，不能把 checksum capability 标成 `ignored`。
- `add_ip_address`/`replace_ip_addresses` 只修改 smoltcp 地址集合，不偷偷修改 OS 路由；这让 gateway/service 地址分离可以由上层明确配置。
- `TunProxyRuntime` 不会在 TUN packet event loop 内直接等待 pending async DNS resolver；`AsyncDnsHandler` 的 owner future 进入本地 `FuturesUnordered`，由 `poll_outputs` 逐步收割，并使用 `ProxyTimeouts.read` 作为 upstream timeout。超时和错误都会生成 `UdpClosed`，关闭时丢弃 pending future 并清理 Full Cone flow；`close_graceful` 会在 deadline 内继续轮询已完成的 DNS task。
- `tun-smoke` 支持 `YUHAIIN_TUN_READ_ONCE=1` 验证真实 ingress，`YUHAIIN_TUN_ECHO=1` 验证 ICMPv4 socket、checksum 和 Linux kernel echo，`YUHAIIN_TUN_PROXY_ECHO=1` 验证真实 TUN TCP → `TunRuntime` → fixed async proxy → local echo，`YUHAIIN_TUN_DNS_ECHO=1` 验证真实 TUN DNS query → async handler hijack → UDP response 回写；`yuhaiin-store` 的 `tun-fakeip-smoke` 进一步验证真实 TUN DNS query → HTTP/2 DoH → `FakeIpAsyncDnsHandler` → SQLite FakeIP pool → FakeIP response 回写。临时 build target 和 fixture 统一放在 `/home/asutorufa/.cache/yuhaiin-rust-check`，不使用 `/tmp`。

### 7.6 可运行的 HTTP/2 + WebSocket + Yuubinsya 链

`yuhaiin-chain` 对 Go node 的常用链形状采用显式结构，保留无 TLS 的 WebSocket 组合以及 TLS+WebSocket 组合：

```text
fixedv2 TCP address
        -> optional TLS (Rustls RustCrypto provider, WebSocket 时不强制 ALPN h2)
        -> optional WebSocket HTTP/1.1 Upgrade + binary byte stream
        -> HTTP/2 CONNECT stream
        -> Yuubinsya TCP header or UOT migrate/frame session
```

TLS server name 与 Go 兼容：`<bilibili_mcdn>.suffix` 会生成随机 `xy...xy.suffix`，不会把尖括号直接传给 Rustls；JSON 中经 HTML 转义的 `&lt;...&gt;` 也会规范化。HTTP/2 每个 CONNECT stream 使用 bounded duplex relay，h2 flow-control 由 relay 独占处理。Yuubinsya UOT 首先发送 `UdpWithMigrateId` header，读取 server 分配的 u64，再使用 `[Socks address][u16 length][payload]` frame。

本地测试覆盖配置顺序校验、TLS SNI 规则、WebSocket standalone 与 WebSocket+HTTP/2 双向 relay、TLS+WebSocket 的 HTTP/1.1 Upgrade、HTTP/2 双向 CONNECT relay/GOAWAY 重建、Yuubinsya TCP header、UOT client/server migrate/frame 和 Ping client/server probe。给定的远端配置还通过了真实互操作 smoke：

```text
YUHAIIN_CHAIN_TARGET=example.com:80 \
YUHAIIN_CHAIN_PROBE=1 \
/home/asutorufa/.cache/yuhaiin-rust-check/target/debug/chain-smoke CONFIG.json tcp
# tcp-probe-reply-bytes=828

YUHAIIN_CHAIN_TARGET=1.1.1.1:53 \
YUHAIIN_CHAIN_PROBE=1 \
/home/asutorufa/.cache/yuhaiin-rust-check/target/debug/chain-smoke CONFIG.json uot
# uot-reply source=udp://1.1.1.1:53 bytes=61
```

另外，`crates/yuhaiin-chain/tests/interop/yuubinsya_go_client.go` 使用 Go 仓库里的真实 `fixed` 和 `yuubinsya` client，由 ignored Rust 集成测试启动 Rust Yuubinsya server，实际验收 TCP、UDP-over-TCP、native authenticated UDP 和 Ping 四条路径。Go 的 Yuubinsya server/client 默认 native UDP packet 不带 SOCKS5 三字节 prefix，因此 Rust runtime 的 Yuubinsya inbound 也使用无 prefix 模式；SOCKS5 UDP association 的 prefix 仍由对应 SOCKS5 boundary 单独启用。

`crates/yuhaiin-chain/tests/interop/websocket_go_client.go` 使用 Go 仓库里的真实 `fixed -> websocket -> http2/v2 -> yuubinsya` client，由 ignored Rust 集成测试启动 Rust WebSocket+HTTP/2 server；测试已在 `GOEXPERIMENT=jsonv2,greenteagc` 下通过。2026-08-09 起，Rust WebSocket inbound 兼容 Go 的 `early_data: base64`：握手阶段按 RawStd base64 解码 `Sec-WebSocket-Key`，最多接收 2048 字节并注入后续协议读取流，同时返回 `early_data: true`；该行为已有 tungstenite 握手和分片读取单测。outbound lazy early-data 需要把握手延迟到首个 protocol write，暂留后续；subprotocol 也仍未纳入默认配置路径。

这里的 `CONFIG.json` 只作为用户外部配置读取，密码和 CA 不复制进仓库。当前 `concurrency` 同时限制 bounded CONNECT pipe 容量；Rust 版已经有按 fixed endpoint 的 HTTP/2 pool、多 stream 复用、有 owner flush task 的有界 UOT coalesced writer、application-level drain、peer GOAWAY 观察和连接重建，且已有优雅 drain/session rollover 验收。由于 `h2 0.4` 的公开 client API 不提供主动发送 GOAWAY frame，Rust 版接受将 client-side GOAWAY 作为非阻塞延期，不调用私有 API 或引入 raw frame hack；当前关闭策略已满足使用需求，未来只有升级到公开支持该能力的 h2 API 才重新评估主动 GOAWAY。

## 7.7 第一版管理 HTTP 与服务进程

### 7.7.1 与 yuhaiin-react 的真实调用方式

现有前端的 `requestJSON` 会把 REST 风格调用转换成扁平 JSON body，并发送：

```text
POST /api/v2/rpc/<operation>
Content-Type: application/json
```

Rust 版管理面位于 `yuhaiin-runtime::api`，不要求前端改写。第一版已覆盖：

- `nodes.*` / `node.*`：作为 outbound/node 管理，保存 Go `nodes_v2` 兼容行；
- `inbounds.*`：保存并回读 Go `inbounds_v2` 原始 JSON，TUN、SOCKS5、HTTP proxy、Yuubinsya 及其 transport listener 都由同一 inbound supervisor 组装；TUN 使用 `network.type=empty` + `protocol.type=tun`，而不是新的 Rust 专属配置表；
- `resolvers.*`、`resolver.hosts.*`、`resolver.fakedns.*`、`resolver.server.*`：UDP/TCP/System 和可选 RustCrypto DoH/DoT registry；
- `route.config.*`、`route.lists.*`、`route.rules.*`、`route.tags.*`：规则/列表原文持久化，常见 domain/CIDR/host-list 表达式编译到当前 Router；
- `settings.*`、`tun.config.*`、`info`：管理进程和数据面启动配置。

`connections` 由 `yuhaiin-runtime::ConnectionMonitor` 统一维护，TUN、HTTP/SOCKS5/Yuubinsya 入站都使用同一 live snapshot、流量计数、SSE 事件和历史统计。`connections.close` 先按 Go 合约严格校验十进制数字 ID，再通过 per-flow close event 唤醒 TCP relay 或 UDP flow；因此前端关闭普通入站连接时不会只改变列表而遗留底层 socket。TUN 是 inbound supervisor 下的一条 packet dispatcher 路径，和 TCP/UDP listener 共享 `ConnectionMonitor` 的状态、持久化统计及 shutdown/reload owner。statistics runtime checkpoint 是频繁 crash-recovery 路径；如果接管 Go state DB 时 checkpoint 不存在，则读取 Go 统计表，正常 shutdown 时再把当前 snapshot 原子投影回 Go 表。history 按 Go 的 `(protocol, addr, process)` 合并，旧 Go JSON connection 可直接恢复。traffic/telemetry 管理接口也按 Go 的 RFC3339 `from < to` 合约校验请求；traffic 查询按 Go 相同的 UTC 小时、日历日、日历月边界聚合，只返回范围内实际有数据的桶；telemetry 以 UTC 小时桶持久化流量和失败维度，查询时按时间范围聚合并执行每个 dimension 的 `limit` 排序截断，旧版没有小时桶的统计状态仍可用聚合兼容读取。

列表响应保持 `{items, page: {page, pageSize, total}}`，记录的未知字段保留在 store 的 `data_json`，secret 脱敏和完整 Go 高级协议属于后续兼容范围。每个写操作先提交 SQLite，再由 `RuntimeController::mutate_and_reload` 串行重建；重建失败时旧 snapshot 继续服务，并通过错误响应告知前端。

### 7.7.2 可运行 binary

```bash
cargo run -p yuhaiin-runtime --bin yuhaiin --all-features
```

默认监听 `127.0.0.1:18080`，数据库使用 `$XDG_DATA_HOME/yuhaiin-rust/state.sqlite`，没有 `XDG_DATA_HOME` 时使用 `~/.local/share/yuhaiin-rust/state.sqlite`。`YUHAIIN_HTTP` 和 `YUHAIIN_DB` 可覆盖这两个值；测试和迁移临时文件放在 `~/.cache`，不使用 `/tmp`。

写入 Go `inbounds_v2` 的 TUN record（`network.type=empty`、`protocol.type=tun`）后，或在兼容场景设置 `YUHAIIN_TUN=1`/`tun.runtime.enabled=true`，`inbound::run_until` 启动单路径 `tun-rs AsyncDevice + smoltcp`，从同一个 runtime snapshot 组装 selector、Full Cone NAT 和 DNS handler；配置 reload 会由同一个 inbound owner 关闭旧设备/dispatcher 后重建。Go TUN 的 `name` 支持 `tun://tun0`（会剥离 scheme），`portal`/`portalV6` 写入 IPv4/IPv6 地址，`routes` 与 `excludes` 走同一可回滚 route lease；旧 `tun.runtime` 仍支持 `ipv4`/`ipv6` 对象形式。第一版默认 MTU 1500、单队列、有界 channel；当前单设备 runtime 对多个 TUN record fail-closed。系统权限、route 和设备创建失败会 fail-closed，不能把失败降级成 direct。

## 8. Proxy 迁移顺序与契约

### 8.1 基础 proxy

补充：Go 的 `fixed/fixedv2 -> yuubinsya` 且 `udp_over_stream=false` 节点现在由 core 的 native Yuubinsya UDP proxy 直接构造；它复用统一 resolver 解析 fixed endpoint，并且明确只提供 datagram，不会把 UDP 节点错误降级成 TCP stream。`udp_over_stream=true` 或包含 TLS/HTTP2 的链继续交给 `yuhaiin-chain`。

`yuhaiin-chain` 现在也支持 Go 的简化 `fixed/fixedv2 -> yuubinsya(udp_over_stream=true)`：直接 TCP 建连后执行 migrate-ID handshake 和 UOT frame，支持 coalesce、域名 resolver、有限重连、proxy close 时回收活动 datagram 和原有 `AsyncProxy` datagram 契约；完整 `fixedv2 -> TLS -> HTTP/2 -> Yuubinsya` 继续使用 H2 pool，不改变既有链路。

Trojan 独立放在 `yuhaiin-protocol`：`TrojanProxy` 可包裹任意已连接的 `AsyncProxy`，支持 Go wire-compatible 的 lowercase SHA-224 password token、TCP CONNECT、UDP ASSOCIATE frame 和有界 payload；runtime 的 inbound 只负责读取 request、注入 `FlowContext`、选择 outbound 和记录 connection/traffic。常用的 `fixedv2 -> tls -> trojan` 由独立 RustCrypto TLS wrapper 组合，不把 TLS 状态写进 Trojan codec；MUX command 保持显式 unsupported，不静默当成 CONNECT。

配置迁移先经过 `yuhaiin-store` 的 `GoProxyRuntimeConfig` 边界：它从 Go `nodes_v2` 的 `chain_types_json` 和 tagged `data_json` 选择可构造的基础 transport，保留有序 protocol layer、启用状态及完整原始 JSON。基础 direct/drop/fixed/HTTP CONNECT/SOCKS5 由 `yuhaiin-core::proxy_factory::BaseProxyConfig` 统一构造；fixed/fixedv2 的 Go 字面量 `{host, port}` 地址由 `yuhaiin-chain::parse_go_node` 归一化，`ChainClient::from_go_json`/`ChainProxy::from_go_json` 可直接从原始 Go node payload 构造当前 `fixedv2 -> 可选 TLS/WebSocket -> HTTP/2 -> Yuubinsya` runtime，并在连接时异步解析 fixed 上游域名。`yuhaiin-runtime::RuntimeBuilder` 现在读取这些 shared runtime structs，使用同一个 `Arc<dyn AsyncIpResolver>` 构造 direct/HTTP/SOCKS5 或 chain proxy；`RuntimeSnapshot::build_proxy_selector` 再把这些 shared proxy records 组装成 TUN 的 direct/proxy/bypass/drop selector，缺少 proxy 配置时 fail-closed；通过 `RuntimeController` 注册的 selector 会在 reload publish 前原子替换 proxy slots，失败时保留旧 snapshot。新 Rust store 也初始化 `nodes_v2`、`inbounds_v2`、`node_tags_v2`、`resolvers_v2`、`route_rules_v2`、`route_lists_v2`，fresh DB 可直接通过 repository 保存 Go compatibility records。基础 builder 的 `to_base_proxy_config_with_resolver` 允许 HTTP、SOCKS5 和 fixed 域名复用 hosts/FakeIP/cache policy。同步 `to_base_proxy_config` 仍保留系统 `ToSocketAddrs` 兼容入口。应用启动和配置 reload 不能让各 proxy 自己创建全局 resolver。当前不会把域名静默当作 `0.0.0.0` 或 direct。`GoProxyTransport::Unknown` 只表示“暂未实现的协议”，运行时 builder 必须显式报错或提供对应实现，禁止未知节点静默变成 direct。

HTTP 层暂不复制一套 DTO：`GoProxyRuntimeConfig`、`GoProxyLayer`、resolver/route/FakeIP runtime structs 作为共享 wire model，使用稳定的 camelCase 字段；`data_json` 不参与序列化，proxy layer 的 password/secret/token/private_key 在 Serialize 时统一打码。未来 handler 只需加鉴权、分页和状态码映射，不改变这些核心模型或 SQLite repository。

#### direct

- TCP 使用 Happy Eyeballs；hostname 由 resolver 注入解析，不强制系统 resolver。
- UDP 使用绑定地址、interface、目标 hint；目标是 domain 时先选一个 IP 作为 socket hint，但保留原目标供上层。
- `close` 幂等；direct 不拥有全局 bootstrap resolver。

#### fixed

- 配置一个主地址和 alternate addresses。
- 多地址连接采用 Happy Eyeballs，当前 Go 行为约 650ms stagger，并保存最近成功 index。
- 主地址连续失败可按当前行为退避/刷新；不能把 alternate 失败永久缓存成成功。
- fixed 可以包在另一个 proxy 上，也可以直接走 direct；这由构造时注入的 parent dialer 决定。

#### drop

- `connect` 返回一个可写但读端按 delay 后 EOF 的 fake stream；`send_to` 接受 payload 但不发到网络。
- 按目标共享短期 delay cache，失败次数指数增长并有上限；ping 返回 block/drop error。
- drop 不创建真实 socket，不应因为它被 route 选择而触发 DNS。

### 8.2 TLS wrapper

- 只包装 stream；datagram 原样委托 parent，除非后续明确实现 DTLS/QUIC。
- 支持固定 SNI、多个 server name 随机池、CA、insecure、ALPN；握手必须绑定 caller context。
- TLS config pool 只读共享；每个连接 clone 可变字段，不修改共享 config。
- 默认纯 Rust 审计：`rustls` 使用 `default-features = false`；不得意外启用 `aws-lc-rs` 或 `ring`。RustCrypto provider 当前仍是实验性实现，正式发布前必须进行协议覆盖、性能、证书验证和安全评审；如果不能达到要求，TLS 功能必须明确标为未完成，而不是换成系统 C TLS。

### 8.3 HTTP CONNECT proxy

- 先通过 parent `connect` 建到 proxy endpoint。
- 发送 HTTP/1.1 CONNECT，Host 为目标地址，可选 Basic `Proxy-Authorization`。
- 必须检查完整 response status；非 2xx 关闭底层连接。
- response body 和 buffered reader 的生命周期要挂在返回 stream 上，避免读掉 tunnel 后的字节。
- 用户名/密码只在内存中使用，日志打码。

### 8.4 SOCKS5

- 实现 RFC 1928 method negotiation、username/password（RFC 1929）、CONNECT、UDP ASSOCIATE、BIND 的明确 unsupported response。
- 地址 codec 支持 IPv4、IPv6、domain；保留 domain 传给远端的能力。
- UDP ASSOCIATE 使用 SOCKS5 的 `RSV=0, FRAG=0, ATYP...` framing；要兼容当前 yuhaiin 的 `WithSocks5Prefix(true)`，为其提供 compatibility test，不要让通用 codec 把三个前缀字节误当成 payload。
- TCP 控制连接关闭时，UDP association 一并关闭；读取 control stream 的 EOF 必须能停止 datagram。

### 8.5 HTTP/2 proxy

当前 Go 实现是明文 HTTP/2 prior knowledge CONNECT，不是 TLS-wrapped HTTP/2。Rust 版先保持这一点：

- pool 内 stream 和 datagram 使用不同的 connection store。
- 每条 connection 有 concurrency 上限；GOAWAY、连接错误或 Reserve 失败时移除并关闭。
- CONNECT request 的 body 贯穿 tunnel 生命周期；不能因 parent request context 结束而过早关闭 body。
- `http2` 自身不解析目标地址，目标由 parent proxy/route 决定。
- 后续如需 TLS HTTP/2，作为新的 config/transport，不改变 prior-knowledge wire behavior。

GOAWAY 兼容决策：peer GOAWAY 仍由 h2 connection driver 观察，active relay 会收到 shutdown signal，pool 会移除旧 connection 并为新 flow 建立 replacement；本地 client-side graceful close 使用上述 application-level drain。这样不会依赖 h2 私有结构，也不会为了一个控制帧破坏纯 Rust、可升级和可测试的 transport 边界。

### 8.6 Yuubinsya

Yuubinsya 要先写独立 codec，再写 client/server；不能在 client 中散落 magic number。

#### 认证

```text
auth = SHA256(password bytes || "+s@1t")
```

比较必须 constant-time，长度和类型先检查；错误只返回 authentication failed。

#### TCP header

```text
protocol: 1 byte
if protocol == UDPWithMigrateID: migrate_id: u64 big endian
auth: 32 bytes
if TCP or Ping: SOCKS5 address
```

当前 protocol network bits：

```text
TCP             = 0b00000010
Ping            = 0b00000100
UDP             = 0b00000101   # legacy
UDPWithMigrateID= 0b00000110
```

必须拒绝未知 protocol、短 header、错误 token、非法 address 和超过 deadline 的半连接。Rust 已提供异步 Ping/UOT server session 的 header 校验和 migration boundary；真实 listener 的约 16 秒 header deadline 仍应成为上层配置，而不是散落常量。

#### 原生 UDP

client/server 之间的 packet 格式：

```text
auth[32]
optional socks5_prefix[0,0,0]
destination socks5 address
payload
```

Native UDP 使用底层 datagram；单包最大 payload 必须扣除 auth、prefix 和 address header。解码前先验证最小长度和 constant-time auth，不能 panic。

#### UDP-over-TCP

连接建立后，首包是带 migration ID 的 header。server 如果收到 ID=0 生成一个新的 ID，并回写 u64；client 保存它到 `FlowContext.udp_migrate_id`。

随后每个 frame：

```text
destination socks5 address
payload_len: u16 big endian
payload[payload_len]
```

payload 不足时必须完整读取/丢弃剩余 frame；大于接收 buffer 时返回实际数据并丢弃尾部，不能把下一 frame 当成当前 payload。coalesce 是可选的 bounded batch writer，不能无界积压；实际 ChainUotSession 使用 owner flush task 在低流量时及时排空，达到 64 KiB/32 frame 仍立即 flush；flush 错误需要取消整个 packet connection。

#### Ping

- Ping header 携带目标地址；成功回写 u64 elapsed，失败回写全 `0xff` 八字节。Rust 已提供 client session、server accept 和 follow-up probe handler boundary。
- client 可按 hostname 缓存 ping connection，空闲约 30 秒回收；同一连接同一时刻只允许一个 ping in flight。
- server 读取后续 ping 每次约 30 秒 deadline；关闭时移除 cache。

#### Yuubinsya server

server 同时处理 TCP listener 和 UDP listener：

- TCP header 决定 stream、UOT、ping；每个 accepted connection 独立 task。
- UOT packet 转成 `Packet { source, destination, payload, migrate_id, write_back }` 交给 handler。
- native UDP packet 同样交给 handler，write-back 用同一 packet codec。
- server close 必须取消两个 accept/serve loop，并关闭 listener；不能只取消 context 留下阻塞的 accept。

### 8.7 Proxy 兼容矩阵

| Proxy | Stream | Datagram | Ping | 第一阶段 |
| --- | --- | --- | --- | --- |
| direct | 是 | 是 | 可选 | 必须 |
| fixed | 是 | 是 | 委托 | 必须 |
| drop | fake | fake | error | 必须 |
| HTTP CONNECT | 是 | 否/委托 | 否/委托 | 必须 |
| SOCKS5 | 是 | UDP ASSOCIATE | 可选 | 必须 |
| TLS | wrapper | 委托 | 委托 | 必须 |
| Shadowsocks AEAD | 是 | 加密 UDP packet | 委托 | 已实现（TCP/codec/Go 互操作；`obfs_http` outbound TCP 已实现） |
| ShadowsocksR | 是 | 加密 UDP packet | 委托 | 已实现（auth_aes128_md5、origin/plain、AES/ChaCha stream cipher、Go wire 互操作；auth_chain/SSR HTTP obfs 仍待补） |
| Trojan | 是 | UDP-over-TCP ASSOCIATE | 委托 | 已实现 |
| VLESS | 是 | UDP-over-TCP length framing | 委托 | 已实现（TCP/UDP codec、inbound/outbound、WebSocket transport composition、Go wire 互操作） |
| VMess modern AEAD | 是 | 固定目标 UDP packet | 委托 | 已实现（alter-id=0 TCP/UDP codec、TLS/WebSocket composition、Go client→Rust wire 互操作） |
| Go AEAD transport | 是 | nonce+ciphertext packet | 委托 | 已实现（TCP/UDP codec、inbound/outbound wrapper、Go↔Rust TCP/UDP 双向实例互操作） |
| HTTP/2 prior knowledge | CONNECT stream | CONNECT stream | 委托 | 必须 |
| Yuubinsya | 是 | native + UOT | 是 | 最高优先级 |

Shadowsocks AEAD 独立放在 `yuhaiin-protocol`：`ShadowsocksProxy` 包裹任意已连接的
`AsyncProxy` parent，使用 Go 当前实现兼容的 MD5 password KDF、HKDF-SHA1 `ss-subkey`
派生、随机 salt、little-endian 计数 nonce 和有界 TCP record；支持
`AEAD_AES_128_GCM`、`AEAD_AES_256_GCM` 与 `AEAD_CHACHA20_POLY1305`，UDP codec 也保留
标准 salt + target-address + payload 形式。runtime 从 `nodes_v2` 的 tagged layer 读取
`method/password`，可组合 `fixedv2 -> tls -> shadowsocks`；协议层不自己创建 resolver，
也不把 ShadowsocksR 的 obfs/auth-chain 状态错误地当成普通 Shadowsocks。

普通 Shadowsocks 的 `obfs_http` 由独立 `HttpObfsProxy` 包裹 parent，严格放在
Shadowsocks framing 之前：首个加密写入会生成 Go simple-obfs HTTP Upgrade 请求，首个响应
会剥离 HTTP headers 后再交给 Shadowsocks。它目前按 Go 实际注册点只提供 outbound TCP；
SSR 的 `http_simple/http_post` 不使用这套格式。

ShadowsocksR 目前由独立的 `ShadowsocksrProxy` 负责，不复用 Shadowsocks AEAD 的 framing。
首个已迁移组合是 Go 当前实现兼容的 `auth_aes128_md5`，支持 `origin/plain`、TCP 认证首帧、
后续 little-endian HMAC 分帧、UDP packet，以及 Go 支持的 AES CFB/CTR/OFB、ChaCha20 和
none 流密码。Go tagged `shadowsocksr` 已能进入 runtime；`auth_chain_*`、`auth_sha1_v4`、
`tls1.2_ticket_auth` 和 SSR HTTP obfs 会在构造阶段返回显式 unsupported。

VLESS 同样独立放在 `yuhaiin-protocol`：`VlessProxy` 使用 v0 UUID、TCP request/response
header 和固定目标的 UDP-over-TCP length frame，同时支持作为 inbound parser 将请求交给共享
`RuntimeProxySelector`。runtime 可以把 fixed parent 依次包成 TLS、WebSocket，再包 VLESS；
WebSocket 只负责 HTTP upgrade 和 byte-stream framing，不把 VLESS 逻辑复制到 transport 层。
VLESS 的 UUID、IPv4/domain/IPv6 地址编码、TCP/UDP framing、Rust→Go wire 互操作和
`fixedv2 -> websocket -> vless` runtime 构造均有自动化测试；HTTP/2 VLESS、early-data、
XTLS/flow 等高级变体仍明确保持 unsupported，而不是静默降级。

VMess 当前按 Go yuhaiin 的 outbound-only modern path 迁移：`VmessProxy` 使用
`alter_id=0` 的 AEAD request header、响应 header 和有界 chunk stream，支持 AES-128-GCM、
ChaCha20-Poly1305 与 none body security；runtime 从 Go layer 的 `id/uuid`、`aid` 和
`security` 读取配置，并可在 fixed parent 上组合 TLS/WebSocket。响应方向按 Go 语义使用
request body key/IV 的 SHA-256 前 16 字节派生 key/IV；跨语言 fixture 已由 Go VMess client
连接 Rust wire server，验证请求、响应和双向 AES-GCM 分块；UDP packet mode 使用同一
`CMD_UDP` request，并通过固定目标和独立方向计数器维持 Go 的 symmetric-NAT 语义，已有
双向 framing 单元回归。legacy alter-id、HTTP/2/early-data 等变体必须返回显式 unsupported，
不得静默按 modern TCP 处理。

### 8.10 Go AEAD transport

Go 代码中的 `pkg/net/proxy/aead` 是独立的自定义 transport，不是 Shadowsocks 的 AEAD
framing，不能复用 Shadowsocks 的 salt、record 或 UDP 地址编码。Rust 实现放在
`yuhaiin-protocol::aead`，边界如下：

- handshake 使用 P-256 ephemeral key、Ed25519 header signature 和带时间校验的加密时间戳；
- TCP 使用独立方向的 ChaCha20 或 XChaCha20 stream cipher，并保留有界 record framing；
- UDP 使用 Go 兼容的 `nonce || ciphertext` packet，packet key 由 password 派生；
- `AeadProxy` 只负责 transport wrapping，parent、resolver、TLS 和上层协议由 runtime/chain
  组装；store 保留 Go tagged layer，避免把它误解析为 Shadowsocks；
- inbound 在进入 SOCKS5/Yuubinsya protocol dispatcher 前解包，TCP/UDP 都复用既有 listener
  生命周期和 outbound selector。

当前已通过 Rust stream/packet 单测、`fixedv2 -> aead` TCP/UDP loopback、AEAD SOCKS5
inbound→direct outbound，以及 Go↔Rust TCP/UDP 双向实例互操作。更多 TLS/HTTP2 组合、API/reload
及 Android/macOS 验收仍是后续门槛。

## 9. NAT 迁移设计

### 9.1 数据模型

```text
NatTable
 └── FlowKey (migrate_id || source comparable)
       └── SourceControl
             ├── bounded sent queue
             ├── bounded received queue
             ├── one worker / one outbound datagram
             ├── endpoint-independent translated mapping: source/migrate id -> one external endpoint
             ├── dispatch cache: logical destination -> routed endpoint
             ├── resolved cache: logical domain -> UDP socket address
             ├── reverse NAT: returned endpoint -> original logical endpoint
             └── idle/closed state
```

`SourceControl` 内部保持单 writer；这样可以保留 Go 实现中“同一个 UDP flow 尽量向同一个真实 IP 发包”的行为，同时减少锁。

### 9.2 写入路径

1. `NatTable::write` 检查 closed；确定 key。
2. `get_or_create(key)` 创建 `SourceControl`，创建失败不插入半初始化对象。
3. 把 packet 放入 bounded sent queue；满时递增 dropped counter 并返回 backpressure/drop error。
4. worker 第一次处理 packet 时构造 flow context，设置 source、destination、inbound、UDP、resolver mode。
5. 调用 proxy/router 的 `open_datagram`；保存 UDP migration ID 和 resolver snapshot。
6. 对 destination 做 dispatch cache；是 domain 且允许 resolve 时，只解析一次并缓存实际 `SocketAddr`。
7. 发送后设置 read deadline 为 UDP idle timeout；如果 logical target 与真实返回地址不同，写入 reverse NAT。

Full-cone 约束：同一 `source`/`MigrateID` 的不同 logical destination 共享一个 translated endpoint；入站回包只按 translated endpoint 找 mapping，不按首次 outbound destination 或 remote peer 过滤。关闭一个 destination 只删除该 flow 引用，最后一个 destination 关闭后才释放 mapping。

后续包优先走 `resolved_cache`；不能因为 FakeIP/domain 每次看起来不同而重新建立 remote datagram connection。

### 9.3 回写路径

- 每个 source control 有一个 read loop，从 remote datagram 读到 bounded received queue。
- 如果曾经发生 reverse NAT，先用返回地址 comparable key 查原始 logical endpoint；否则直接使用 remote address。
- write-back 使用创建 packet 时保存的 callback；回写连续失败超过阈值则关闭 flow。
- 关闭/超时要释放所有 queued packet buffer；Rust 中用 owned `Bytes`/`BytesMut`，避免 Go refcount 等价物扩散到全局。

### 9.4 Idle、迁移 ID 和 hash

- `NatTable` 周期性扫描 source controls；只有 worker 已停止且 stop time 超过 `udp_idle_timeout` 才删除。
- `MigrateID != 0` 优先于 source key；Yuubinsya UOT 和 NAT 必须共享同一 flow context 的 migration ID。
- NAT 默认是 full-cone，而不是 restricted-cone；不能把 remote peer 写入 allowlist，也不能为同一 source 的每个 destination 分配独立 mapping。
- 配置层同样只接受 Full Cone：新建 `nat_config` 使用 `CHECK (full_cone = 1)`，typed write 的 `full_cone=false` 和旧库中读到的受限值都会 fail-closed；当前没有 restricted-cone runtime，避免配置与数据面语义不一致。
- `GenerateID` 使用服务启动时间作为 keyed hash key，对 `src.String()` 做 64-bit Blake2b；Rust 版固定 endian、输入规范化和测试向量，不能直接改用随机 UUID，否则跨语言调试和 fixture 不一致。
- `MaxSegmentSize` 是全局协议上限；所有 Yuubinsya/NAT/DNS packet path 都使用一个 core 常量或注入配置，不能各自定义不同上限。

### 9.5 NAT 验收测试

- 同一 source 的并发 packet 只创建一个 SourceControl。
- 同一 migration ID 即使 source 地址变化仍复用同一 flow。
- bounded queue 满时可观测丢包，worker 恢复后不死锁。
- domain target 只解析一次；FakeIP target 和真实 target 的 reverse NAT 能正确回写。
- remote socket 超时会关闭 flow；table close 会关闭所有 children 并让新写入失败。
- Yuubinsya native UDP、UOT、SOCKS5 UDP 与 NAT 组合测试。
- loom 或等价模型测试覆盖 close/write/read 的竞争；特别检查“remove 后 worker 仍回写”的 use-after-close 逻辑错误。

## 10. 分阶段实施计划

### Phase 0：契约和 fixture（先做）

- 建 workspace、lint、依赖审计和 `yuhaiin-core`。
- 从 Go 测试提取 address codec、DNS message、Yuubinsya header/packet、FakeIP cursor 的 fixture。
- 定义 `FlowContext`、`Proxy`、`Resolver`、`Datagram`、`Route` trait。
- 交付标准：只有 core/codec 也能 `cargo test`，没有 Tokio/C TLS/SQLite 依赖；SQLite 只由 store/config 层承载。

### Phase 1：FakeIP

- `yuhaiin-trie` 的 domain/cidr 基础结构。
- `yuhaiin-config` SQLite engine adapter、schema migrations、typed repositories 和 backup/export。
- `yuhaiin-store` 的 SQLite fakeip schema、cursor、正反向索引和 touch worker；redb 只保留可选 backend/cache。
- `yuhaiin-fakeip` answer transform、PTR、HTTPS/SVCB hints（已完成 codec、未知参数保留和双栈 hint 替换）。
- 交付标准：本地 DNS fakeip 测试、重启测试、旧数据 fixture 导入测试、schema migration/rollback/backup 恢复测试通过。

### Phase 2：DNS UDP、TCP fallback、DoH2、server

- 先写 hickory-proto adapter 和 raw message model。
- 实现 UDP single socket/pending dispatcher。
- 实现 TCP length-prefix fallback，再实现 DoH2。Rust 版同时提供同步 `dns_tcp::TcpDnsClient`/`TcpDnsServer` 和纯 Tokio 的 `dns_tcp_async::AsyncTcpDnsClient`/`AsyncTcpDnsServer`/`AsyncTcpDnsHandler`；异步 server 支持同一连接多 frame、多个连接并发 accept 与 owner shutdown；runtime TCP resolver 使用异步实现，复用 DNS wire codec，并通过 loopback framing 与 runtime factory 查询回归。
- 实现 UDP/TCP DNS server，接入 FakeIP。
- UDP/TCP/DoH client 由 `dns_resolver::DnsResolver` 统一暴露，缓存和具体 DoH HTTP/proxy transport 通过注入边界组合；不把同步 socket 或 HTTP client 细节带入 Router/TUN。
- `dns_resolver_async::AsyncDnsResolver` 以 query-level `AsyncDnsQuery` 组合异步 UDP 与 HTTP/2 DoH，并输出现有 packet-level `AsyncDnsHandler`；缓存、hosts、policy、FakeIP 可以继续按 handler 链组合。
- 交付标准：Rust resolver/server 互通；Go resolver/server 互通；TC、超时、取消和并发限制通过。

### Phase 3：Router

- immutable domain/CIDR matcher snapshot。
- route mode、resolver policy、list match history、dispatch/resolve local。
- 接入 `yuhaiin-geo` 的 MaxMindDB provider；先使用 injected process provider，不把平台进程识别塞进 Router。
- 交付标准：规则顺序、通配符、最长 CIDR、proxy FQDN strategy 与 Go fixture 一致。

### Phase 4：基础 proxy

- direct、fixed、drop。
- HTTP CONNECT、SOCKS5 TCP/UDP。
- TLS stream wrapper和HTTP/2 prior-knowledge pool。
- 交付标准：所有 proxy 的 local echo、超时、关闭、auth、multi-address 和 pool test 通过。

### Phase 5：Yuubinsya

- codec -> native UDP -> TCP stream -> UOT/migration -> ping -> server。
- 每一步都和 Go server/client 做互操作，而不是只做 Rust 两端自测。
- 交付标准：密码错误、未知 protocol、short frame、coalesce、reconnect、migration ID、ping cache 全通过。

### Phase 6：NAT

- 先实现单 SourceControl，再实现 Table、idle scanner、reverse NAT。
- 通过 Router/Proxy trait 注入实际 dialer。
- 交付标准：direct、Yuubinsya native UDP/UOT、SOCKS5 UDP、FakeIP domain target 组合测试通过。

### Phase 7：TUN 和平台网络入口

- `yuhaiin-tun` 的 tun-rs device wrapper、smoltcp adapter、Linux namespace test、IPv4/IPv6 TCP/UDP/ICMP。
- 接入 Router/NAT，完成 DNS hijack、FakeIP、route block/direct/proxy、portal 地址和回写。
- 先用 benchmark 和 Go/gVisor 行为 fixture 验证 smoltcp；只有明确不满足时，才设计 `IpStackAdapter` 的自研替换，不并行实现 tun2socket。
- 交付标准：无权限 unit test、Linux privileged integration test、Android/macOS/Windows capability probe 通过。

### Phase 8：替换边界

- 提供一个最小 app/harness，启动 SQLite config + DNS + FakeIP + MaxMindDB + Router + 选定 proxy + NAT + TUN。
- 以 feature 或环境变量选择 Go/Rust backend，而不是同时修改所有控制面。
- 先替换 SQLite/config、DNS/FakeIP，再替换 Yuubinsya/NAT，最后切换 TUN 数据面和平台集成。

## 11. 纯 Rust 依赖政策

### 11.1 建议 allowlist

版本以 workspace lockfile 统一管理，不在文档中永久锁死“最新版本”；升级必须重新跑依赖审计。

| 用途 | 首选 | 备注 |
| --- | --- | --- |
| runtime | `tokio` | 只在 io/transport 层使用 |
| async utility | `futures`, `tokio-util` | cancellation、codec、stream |
| bytes | `bytes` | packet ownership 和 buffer |
| error/log | `thiserror`, `tracing` | 不用字符串 error 作为 API |
| serialization | `serde` | 只用于 config/fixture，不用于 wire parser 的隐式兼容 |
| DNS wire | `hickory-proto` | 低层 DNS message/record codec |
| SQLite-compatible config DB | `rusqlite` + `bundled` | 经过真实 Go snapshot/WAL/跨进程测试的 SQLite amalgamation；通过 `yuhaiin-store::sqlite` typed adapter 隔离 C API，升级后复审 `libsqlite3-sys` 与构建产物 |
| embedded cache | `redb` | 纯 Rust、事务型 KV；只能作为可选 cache/backend，不能替代 SQLite 配置事实源 |
| trie/IP | `ipnet` + 自研 trie | 需要精确控制 wildcard/LPM 语义 |
| MaxMindDB | `maxminddb` | 纯 Rust reader；`mmap` 可选，读 GeoIP2/GeoLite2 |
| TUN device | `tun-rs` | async、多平台、multi-queue；平台 FFI/unsafe 仍需隔离审计 |
| Linux route lifecycle | `route_manager` | 可选 `tun-routes` feature；通过纯 Rust netlink packet/client 管理 route，不绑定系统 `ip` 命令；底层 OS ABI 仍需 capability/权限测试 |
| userspace IP stack | `smoltcp` | 第一阶段唯一 stack；raw/ICMP/TCP/UDP，需验证与 Go gVisor 行为差异 |
| hash | `blake2`, RustCrypto crates | Yuubinsya token 使用 SHA-256 |
| HTTP | `hyper`, `hyper-util`, `http-body-util` | 通过自定义 connector 走 Proxy |
| TLS | `rustls`, `tokio-rustls` | 必须禁用默认 native/crypto backend |
| pure TLS provider | `rustls-rustcrypto` 或自研 RustCrypto provider | 当前是 alpha/实验性，不能跳过上线前审计 |
| testing | `proptest`, `loom`, `criterion` | protocol/property/concurrency/perf |

### 11.2 明确禁止

- `native-tls`、`openssl`、`openssl-sys`、`tokio-native-tls`。
- `sqlite3`、`sqlx-sqlite`、`libsql` 及依赖系统 SQLite 的任何默认 feature；`rusqlite` + `bundled` 和对应 `libsqlite3-sys` 是本项目明确批准的数据库例外。
- `ring`、`aws-lc-rs`、`aws-lc-sys` 作为默认或传递依赖；如某个低优先级 feature 必须使用它，必须隔离并在构建产物中明确标记，不得进入默认构建。
- 依赖 `build.rs` 编译 C/C++/汇编的协议实现。
- 未审计的 system resolver、system TLS、system proxy 自动 fallback。

### 11.3 CI 审计

CI 至少执行：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo tree -e features
cargo deny check bans licenses sources
```

另加一个脚本检查 Cargo metadata 中的 `links` 字段和依赖名：

```text
拒绝 links 非空；拒绝 native-tls/openssl/ring/aws-lc-sys/libsqlite3-sys；
允许列表外的 build script 必须人工 review。
```

DoQ/DoH3 使用独立 CI job，不得因为测试 `--all-features` 把它们的 crypto backend 带入默认 release。

### 11.4 依赖参考

实现时以 crate 自己的文档和 lockfile 为准，以下链接用于确认本设计中的关键判断：

- [`hickory-proto`](https://docs.rs/hickory-proto/latest/hickory_proto/)：低层 DNS message、record 和 binary codec。
- [`redb`](https://docs.rs/redb/latest/redb/)：纯 Rust、事务型嵌入式 KV store。
- [`rusqlite`](https://docs.rs/rusqlite/latest/rusqlite/)：成熟 SQLite binding；本项目使用其 `bundled` feature，避免依赖宿主机 SQLite 版本，并用 typed adapter 限制 API 扩散。
- [`maxminddb`](https://docs.rs/maxminddb/latest/maxminddb/)：GeoIP2/GeoLite2 reader，支持可选 mmap。
- [`tun-rs`](https://docs.rs/tun-rs/latest/tun_rs/)：跨平台 TUN/TAP 和 async device 候选。
- [`smoltcp`](https://docs.rs/smoltcp/latest/smoltcp/)：纯 Rust 的 raw/ICMP/TCP/UDP userspace stack 候选。
- [`rustls`](https://docs.rs/rustls/latest/rustls/)：支持可替换 `CryptoProvider`；默认 feature 会启用 `aws-lc-rs`，因此必须显式关闭。
- [`rustls-rustcrypto`](https://docs.rs/rustls-rustcrypto/latest/rustls_rustcrypto/)：纯 Rust provider 方向，但当前文档明确标记为 alpha/不建议直接用于生产，必须先做安全和覆盖率评审。
- [`quinn`](https://docs.rs/quinn/latest/quinn/)：DoQ/DoH3 的候选 QUIC 实现；默认标准 crypto 路径依赖 rustls/ring，所以不能直接进入本项目默认 feature。

## 12. 测试、互操作和发布门槛

### 12.1 测试层次

1. Pure codec：不需要 runtime，不开端口，覆盖所有短包/坏包/边界。
2. Local transport：loopback TCP/UDP、mock DNS、mock proxy，测试 deadline/cancel/close。
3. Cross-language：Go server <-> Rust client，Rust server <-> Go client。
4. Composition：Router + DNS + FakeIP + Proxy + NAT。
5. Persistence：SQLite migrations、transaction rollback、backup/restore、concurrent readers、busy/locked、FakeIP cursor 和 crash recovery。
6. Platform: TUN namespace、device capability probe、route apply/rollback；没有 root 的 CI 只跑 fake device 和 packet parser。
7. Soak：长时间 UDP、HTTP2 pool、fakeip touch/flush、route snapshot reload、MaxMindDB reload。

### 12.2 单元测试最低门槛

每个 crate 都必须有不依赖外网、不依赖 root 的单元测试。最低覆盖如下：

| crate/模块 | 必测内容 |
| --- | --- |
| `core` | Endpoint 规范化、domain/IP 区分、comparable key、错误分类、FlowContext clone/override |
| `trie` | domain 反向 label、父域、wildcard、删除、IPv4/IPv6 LPM、重叠 prefix、snapshot 并发读取 |
| `config` | 空库 bootstrap、每个 migration、重复 migration、失败回滚、JSON 校验、旧 schema、备份恢复、单写多读 |
| `fakeip` | 并发同域、cursor、满池 LRU、prefix 隔离、正反向一致、touch flush、非法 entry、A/AAAA/PTR/HTTPS/SVCB hint transform |
| `dns` | message pack/unpack、ID/question 匹配、A/AAAA/PTR/HTTPS/SVCB codec、target/root/未知 SvcParam 保留、A/AAAA 并行、TC fallback、UDP pending cancel、DoH status/body 限制、server length prefix |
| `geo` | MaxMind fixture lookup、IPv4/IPv6、missing/corrupt database、decode country、snapshot replacement、close race |
| `proxy codec` | SOCKS5 address、Yuubinsya header/auth/packet/frame、short/oversized/malformed input、constant-time auth path |
| `proxy transport` | direct/fixed Happy Eyeballs、HTTP CONNECT、SOCKS5 auth/UDP、TLS handshake cancel、HTTP2 GOAWAY/pool、drop backoff |
| `router` | matcher order、route mode、resolver policy、skip_route、resolve_locally、list apply snapshot、geo fallback |
| `nat` | key selection、single SourceControl、bounded queue、dispatch/resolved/reverse cache、idle close、write-back failure |
| `tun` | IP header/tuple parser、checksum、MTU/fragment、UDP mapping、gateway port、DNS request detection、device lifecycle |

对每个 parser 增加至少一组 `proptest`：任意 bytes 不 panic；对 stateful 模块增加模型测试：reference map/table 与实现逐步执行结果一致。时间相关逻辑使用可注入 clock，禁止单元测试用 `sleep(1s)` 等待后台 worker。

单元测试不等于集成测试：需要真实网络 namespace、权限、IPv6、TUN driver 或外部 MaxMind 下载的测试必须显式标记并单独 job；失败时报告为环境测试失败，不伪装成纯 Rust 单元测试通过。

### 12.3 必须保存的 fixture

- Domain trie：精确域名、父域、wildcard、大小写、尾点。
- CIDR：IPv4/IPv6 重叠 prefix 和 LPM。
- DNS：A、AAAA、PTR、HTTPS/SVCB、TC、NXDOMAIN、EDNS subnet。
- Yuubinsya：四种 protocol byte、auth、TCP header、native UDP prefix、有/无 coalesce 的 UOT frame、migration ID、ping success/failure。
- SOCKS5：IPv4/IPv6/domain address、CONNECT、UDP associate、auth failure。
- FakeIP：prefix/cursor、满池复用、旧 schema import、正反向一致性。
- SQLite：Go 当前 schema、旧版本 migration、`settings_kv`/`route_rules`/`dns_resolvers`/`fakeip_entries` 的最小数据库和损坏/半迁移数据库。
- MaxMindDB：GeoLite/Country test database、缺失 country 字段和未知 record schema。
- TUN：IPv4/IPv6 TCP/UDP/ICMP packet、fragment、checksum 错误、packet-info header 和不同 MTU。

### 12.4 性能观测

第一阶段不追求微优化，但必须暴露这些 metrics：

- DNS query、命中/未命中、transport error、TC fallback、耗时。
- FakeIP hit/miss、分配、复用、反查失败、touch flush error。
- Router trie match duration、snapshot version、规则 apply delay。
- Proxy connect/datagram/ping error、HTTP2 pool in-flight、Yuubinsya auth/frame error。
- NAT active flows、queue depth、send/receive/drop、reverse NAT count、idle close。
- SQLite migration duration、transaction rollback、busy/locked、checkpoint/compact、backup restore error。
- TUN packet read/write/drop、MTU drop、TCP/UDP active flow、mapping allocation/reuse、route apply/rollback。
- MaxMindDB lookup latency、hit/miss、reload success/failure、old snapshot lifetime。

使用 `tracing` span 关联 flow key；禁止把密码、完整域名列表和用户原始 packet 写入 info 日志。

当前 P1 观测边界：`yuhaiin-chain::ChainRuntimeStats::render_prometheus()` 和
`ChainClient::prometheus_metrics()` 输出 HTTP/2 pool 的连接/stream gauge 与连接、
失败、capacity rejection、stream open failure counter；`yuhaiin-core::nat::NatTable::stats()`
和 `NatStats::render_prometheus()` 输出 Full Cone active binding、logical destination、
reverse mapping、allocation/reuse、reverse lookup、translated rebind 和回收 counter。
这些 API 只生成 pull-format snapshot，不启动 listener、后台 task 或全局 registry；HTTP
端点、认证、采样周期和日志脱敏由上层 app 负责。这样 Android、macOS 和 Linux 可以共享
数据面而不绑定某个 exporter/runtime。

## 13. 主要风险和决策点

| 风险 | 处理方式 |
| --- | --- |
| 纯 Rust TLS provider 还不成熟 | 使用 feature-gated `rustls-rustcrypto` 完成实际 client adapter；provider 可替换，未通过安全/互操作审计前不宣称生产可用 |
| SQLite backend 兼容性/资源占用风险 | SQLite schema 作为稳定契约；用 Go 生成 FTS-free fixture 做 SQL/file/transaction 对比；rusqlite bundled 通过真实 snapshot、WAL、跨进程和资源 probe 后作为默认后端；纯 Rust backend 只作为未来可替换实验 |
| 旧 SQLite/Pebble 数据格式复杂 | 优先导出 fixture；导入幂等、逐条校验、metadata 标记；不要阻塞主 resolver 锁 |
| TUN 平台 FFI 和权限差异 | 平台 unsafe 集中隔离；Linux namespace 做真实测试；其他平台先做 capability probe 和 fd 注入测试 |
| userspace IP stack 与 gVisor 行为不同 | 第一阶段只用 smoltcp；先补 adapter/配置和 fixture，确认无法满足后再替换 `IpStackAdapter`，不维护第二套并行数据面 |
| MaxMindDB 更新损坏 | 下载临时文件、校验后原子替换；失败保留旧 snapshot，SQLite 仅记录错误 |
| DNS/Proxy 递归解析 | 所有远端 endpoint 使用显式 bootstrap resolver 或 parent dialer；禁止隐藏系统 resolver |
| Route snapshot 替换期间 close 旧资源 | 构造新资源 -> 原子替换 -> 锁外 close；禁止持锁 await |
| UOT 长连接泄漏 | migration ID、idle deadline、cancel token 和 close test 必须一起实现 |
| UDP 洪泛导致内存增长 | 所有 channel/ring/HTTP2 pool 有上限；满时可观测 drop/backpressure |
| Go/Rust 地址语义不一致 | Domain endpoint 不能提前变 SocketAddr；保存 original target 和 resolved target 两个字段 |
| “all features” 引入 C 依赖 | DoQ/DoH3/TLS provider 做 feature/CI 隔离，检查 `links` 和 native backend |

## 14. 建议的第一批提交顺序

```text
1. workspace + core traits + error/address fixture
2. trie domain/cidr + snapshot tests
3. SQLite engine adapter + schema/migrations/repositories + persistence tests
4. SQLite-backed fakeip pool + cursor/reverse lookup
5. fakeip DNS transform + Go fixture interop
6. DNS message/client + UDP transport + TCP fallback
7. DoH2 + DNS server
8. MaxMindDB provider + snapshot/reload tests
9. router dispatch + route/list/geo snapshot
10. direct/fixed/drop
11. yuubinsya codec + native UDP
12. yuubinsya TCP/UOT/migration/ping + server interop
13. HTTP CONNECT/SOCKS5/TLS/HTTP2
14. NAT table/source control + composition tests
15. tun-rs device + smoltcp adapter + Linux namespace tests
```

每个提交都应可编译、可测试、可回退；不要在一个提交中同时加入新的协议、配置格式和平台集成。

## 15. 最终验收场景

迁移到可用状态前，至少手工/自动验证以下完整链路：

1. Client -> Router -> FakeIP -> DNS UDP -> direct：域名返回 fake IPv4/IPv6，PTR 能恢复域名。
2. Client -> Router -> DoH2：DoH endpoint 本身通过 bootstrap/指定 proxy 连接，不发生 DNS recursion。
3. Client -> Router -> Yuubinsya TCP -> server -> direct TCP：认证、半关闭、超时和 server close 正常。
4. Client -> Router -> Yuubinsya native UDP -> NAT -> destination：同一 flow 复用 socket，reply reverse NAT 正确。
5. Client -> Router -> Yuubinsya UOT -> NAT：migration ID 从握手到 NAT 全程一致，coalesce 开关不改变 payload 语义。
6. Client -> Router -> HTTP2 prior knowledge：多 stream、GOAWAY、连接池清理和 datagram/stream 分池正确。
7. route list 热更新：旧请求继续使用旧 snapshot，新请求使用新 snapshot，apply status 最终清零。
8. 进程重启：SQLite migration、FakeIP cursor、映射、NAT 清理、HTTP2 pool、resolver pending request、MaxMindDB snapshot 都没有脏状态导致启动卡死。
9. TUN：Linux namespace 中 IPv4/IPv6 TCP、UDP、DNS hijack、FakeIP、direct/proxy/block 和回写都能完成；设备/route 失败会反向清理。
10. 配置：修改 route/DNS/proxy/TUN/MaxMindDB 设置后，SQLite transaction 原子提交，重启后配置与 runtime snapshot 一致。

这十个场景全部通过后，才把 Rust backend 作为默认数据面；在此之前不要用“能够连通一个网站”作为迁移完成标准。

## 16. 2026-08-09 inbound settings compatibility

Go 的 `pkg/store/inbound_settings.go` 和 `pkg/httpapi/v2.go` 定义了前端不变的三项设置：`hijackDns`、`hijackDnsFakeIp`、`sniff`，空配置默认均为 `true`。Rust 现在使用共享的 `yuhaiin_store::InboundSettings`，避免 API、存储和 runtime 各自维护 DTO：

- 有 Go `inbound_settings(id=1)` 表时，读取/写入原表，保留真实 Go 数据库的可见性；没有该表时，使用 `yuhaiin_config` 的 `inbounds.config` JSON overlay。
- `RuntimeBuilder` 将设置放进不可变 `RuntimeSnapshot`；`inbounds.config` PUT 通过 `RuntimeController::mutate_and_reload` 提交，失败时保留旧 snapshot。
- TUN inbound 在 `hijackDns=false` 时不安装异步 DNS handler，53 端口回到普通代理链；`hijackDnsFakeIp=false` 时使用未包 FakeIP 的 DNS resolver；`sniff=false` 时公共 TCP relay 不等待首包嗅探。
- `ConnectionMonitor` 持有当前 snapshot 的 socket-safe DNS handler；公共 TCP relay、SOCKS5/Trojan/VLESS/Yuubinsya/透明 UDP adapter 都只负责自己的 framing 和回写。Yuubinsya TCP/UOT 由 `yuhaiin-chain::YuubinsyaDnsHandler` 在 chain 内接入，避免把 chain session 实现搬进 inbound。
- 所有这些入口先执行 DNS query 判定；合法 query 走本地 resolver/FakeIP，非法或非 query 保留原始 framing 转发；成功 reload 会同时替换 TUN 与 socket/chain handler。

本次新增 store legacy/overlay、runtime snapshot、API reload、disabled-sniff relay、公共 TCP DNS framing、Yuubinsya chain TCP/UOT DNS 以及多线程 `Send` 边界单测；各协议 UDP adapter 复用同一 request predicate，并通过 Podman/交叉编译门槛继续验收。

## 17. 2026-08-09 Go 互操作与 DoH server 范围核对

本轮重新在存在 Go 工具链和 sibling checkout 的环境中显式运行了此前默认 ignored 的互操作测试，结果如下：

| 测试组 | 结果 |
| --- | --- |
| Yuubinsya TCP/UOT/native UDP/Ping | `yuhaiin-chain` Go interop 1 项通过 |
| WebSocket/HTTP2 | `yuhaiin-chain` Go interop 1 项通过 |
| AEAD transport | `yuhaiin-protocol` 4 项通过 |
| Shadowsocks/legacy wire fixture | 1 项通过 |
| Trojan/VLESS/VMess | 各 1 项通过 |
| HTTP obfs 与 ShadowsocksR codec fixture | 各 1 项通过 |

执行时使用：

```text
YUHAIIN_GO_ROOT=/home/asutorufa/Documents/Programming/yuhaiin
GOEXPERIMENT=jsonv2,greenteagc
cargo test -p yuhaiin-chain --test go_yuubinsya_interop --offline -- --ignored --nocapture
cargo test -p yuhaiin-chain --test go_websocket_interop --offline -- --ignored --nocapture
cargo test -p yuhaiin-protocol --tests --offline -- --ignored --nocapture
```

实际测试文件仍保留 `#[ignore]`，因为没有 sibling Go checkout 的 CI 不应因此失败；在本机显式提供 `YUHAIIN_GO_ROOT` 时，上述协议路径已实际跨语言运行，而不是只依赖 Rust 对 Rust 的 codec 单测。

同时对照 Go `pkg/net/dns/server/server.go` 确认：Go 的本地 DNS server 只监听配置地址上的 UDP 和 TCP；DoH/DoH3 是 resolver 的上游 transport，并不是本地管理 server endpoint。Rust 因此保持同一边界：`resolver.server` 管理本地 UDP/TCP listener，DoH/HTTP2 位于 resolver client factory；checklist 不再把不存在于 Go 的本地 DoH listener 当作未完成项。

另外以 `yuhaiin-react/src/api/generated.ts` 的 88 个 RPC operation 和 legacy route 为基准做了静态逐项核对：Rust RPC switch 覆盖全部前端可通过 `requestJSON` 调用的 operation；`connections.events`、`tools.logs` 两个流式 operation 按 Go contract 走直接 SSE route，不应被误判为普通 JSON RPC 缺失。Rust 额外保留的 `tun.config.*` 是旧管理面兼容入口，不改变前端已有 operation。connections 的 `network` 对象、历史/失败历史字段以及 traffic 的 UTC 日历聚合已加入 Rust 单测；剩余工作仍是完整响应字段和真实生产数据的逐项快照核对，不把“路径存在”当作 schema 已完全等价。

## 18. 2026-08-09 statistics projection backoff

统计 checkpoint 与 Go 兼容表投影现在分离处理：checkpoint 仍由 persistence worker 高频写入，用于异常退出恢复；Go `statistics_*`、traffic、history 和 telemetry 表继续按首次成功及 30 秒间隔低频投影。若 SQLite 被 Go 进程或其他 writer 锁住，投影重试由 2 秒起按指数退避，最大 60 秒，成功后恢复 30 秒周期，避免锁竞争期间每个 dirty 事件都发起写事务。

正常 shutdown 先通知并等待 persistence worker 结束，再执行最终 checkpoint/Go projection；因此最终 flush 不会与尚未完成的后台写事务并发，也能在 worker 异常时继续尝试最终持久化。`monitor` 的 180 个 runtime 单测已通过，新增退避倍增与封顶边界回归。

## 19. 2026-08-09 release replacement handbook

新增 `docs/RELEASE_REPLACEMENT.md`，把 Rust binary 直接替换现有 Go service 时的边界写成可执行流程：Android `aarch64` 使用 `/opt/android-ndk/.../aarch64-linux-android35-clang`，状态库先停服务再做 SQLite backup/quick-check，systemd 与 launchd 分别执行 stop/bootout、binary 替换、启动和 `/api/v2/info` 健康检查；回滚同时覆盖 binary 与数据库 backup。

文档明确 Go/Rust 只能使用独立数据库副本并行做对照，不能同时写同一个 `state.db`；WAL、`state.db-wal`、`state.db-shm` 和 sidecar lock 不得在未确认进程退出前手工删除。Windows service 与真实发行版 service manager 仍保留为现场验收项。

## 20. 2026-08-09 transparent UDP ancillary coverage

`yuhaiin-runtime::proxy::transparent` 新增 Linux 本机 socket 回归：启用 `IP_ORIGDSTADDR` 与 `IPV6_ORIGDSTADDR`，分别发送 IPv4/IPv6 UDP packet，并通过真实 `recvmsg` ancillary 解析 peer、payload 和 original destination。该测试不修改宿主路由，也不伪装成完整 TPROXY 网络 namespace 验收；需要 `CAP_NET_ADMIN` 的非本地转发、iptables/nftables 和多 flow 生命周期仍按 checklist 单独执行。

## 21. 2026-08-09 macOS cross-target evidence

当前 Linux 主机上 `cargo check -p yuhaiin-core --features async-proxy,tun --target aarch64-apple-darwin --offline` 通过；`yuhaiin-runtime --all-features` 则在 `libsqlite3-sys` bundled SQLite 编译阶段失败，因为主机 `/usr/bin/clang` 不识别 macOS 专用的 `-arch arm64` 与 `-mmacosx-version-min=11.0`，且环境没有 `xcrun`/macOS SDK。该结果确认 Rust core 代码可过 target check，但不能替代 macOS SDK/clang 下的 runtime 编译和 utun/LaunchDaemon 实机验收。

## 22. 2026-08-09 service smoke

使用 `target/debug/yuhaiin -host 127.0.0.1:55123 -path ~/.cache/yuhaiin-rust/service-smoke-<pid>` 启动独立 Rust service，未使用 `/tmp`，并通过 `/api/v2/info`、`/api/v2/settings`、`/api/v2/nodes`、`/api/v2/connections/total` 实际请求后收到 200 响应。空库幂等初始化出 built-in `direct` node，生成 `state.db`、WAL、SHM 和 sidecar lock；随后向该自有 smoke 进程发送 SIGTERM，进程正常退出。该结果覆盖 CLI path/host、SQLite 初始化和最小前端管理面链路，不替代代理流量和 TUN namespace 验收。

## 23. 2026-08-09 管理 API Go/Rust 最小对照

在 sibling Go checkout 构建 `cmd/yuhaiin` 后，使用独立的 `~/.cache/yuhaiin-rust/go-service-smoke-rpc2-<pid>` 状态目录启动 Go service；没有复用 Rust 的 `state.db`，也没有停止宿主机已有服务。Go v2 非流式接口的实际 RPC 路径是 `/api/v2/rpc/{operation}`，请求体为 `{}`。以下四个只读操作均收到 HTTP 200：

```text
info
settings.get
nodes.get
connections.total
```

结果确认：Rust 与 Go 的四个响应都保持相同的顶层 JSON 契约（info、settings、分页 nodes、字符串计数器/空 counters），可由现有 React generated client 解码。空库默认值的差异是有意的：Rust 初始化内置 `direct` node，并将 advanced buffer 使用运行时默认值；Go 的 fresh state 返回空 node 列表和 zero advanced values。这里验证的是路径、状态码和字段形状，不把默认值差异误报为协议不兼容；生产库逐表、逐字段和 mutation/reload side effect 快照仍是 checklist 的未完成项。

首次尝试旧的 `/api/v2/info`、`/api/v2/settings` 路径得到 Go 静态文件 fallback 的 404，随后按 Go `v2RoutePattern` 修正为 RPC 路径。该记录保留这个陷阱，避免后续把旧路由 404 当成服务启动失败。

## 24. 2026-08-09 Go fresh SQLite takeover

用上一个 Go RPC smoke 生成的独立 `state.db`，在 Go 进程退出后直接启动 Rust binary；Rust 首次启动曾因严格拒绝 `dns_hosts` 中 Go fresh state 自带的 `example.com -> example.com` self-mapping 而失败。Go 将这类记录当作合法 no-op，Rust 现在在 `insert_target` 兼容加载时忽略该 self-mapping，普通 alias cycle 仍由解析阶段拒绝。

修复后 Rust 成功打开并接管同一 Go fresh state，实际请求 `/api/v2/info`、`/api/v2/settings`、`/api/v2/nodes`、`/api/v2/connections/total` 均收到 HTTP 200，并通过 SIGTERM 正常退出。该回归覆盖了真实 Go SQLite 文件的 hosts/migration/open/runtime 初始化边界；生产库中的更多 hosts、route、resolver、统计异常快照仍需按 checklist 扩充。

## 25. 2026-08-09 live statistics counter semantics

Go `pkg/statistics/statistic.go` 的 `Connections.Remove` 会同时删除连接和其 per-flow counter；`connections.total.counters` 不是历史累计表，而是当前活动 flow 的视图。Rust 之前在 `monitor.close` 后保留 counter，并在重启时从 checkpoint 恢复没有对应 socket 的 counter，导致前端看到已关闭/不存在的连接仍出现在 counters 中。

Rust 现在在关闭 flow 时删除 live counter；恢复旧版 `statistics.runtime` 时继续接受旧 `counters` 字段，但因为活动 socket 不会恢复而清空该 map。新增关闭后与重启后的回归，保留 totals/history/telemetry 的持久化。`yuhaiin-runtime` all-features 单测本轮为 183 项通过。

## 26. 2026-08-09 frontend RPC read/mutation smoke

在独立 `~/.cache/yuhaiin-rust/api-read-matrix-<pid>` 状态目录启动 Rust service，fresh state 下实际调用 generated client 对应的 31 个核心只读 RPC：info、settings、backup、tools、nodes、inbounds、resolvers、hosts/FakeDNS/server、subscriptions get、publishes、users、connections 统计/历史、route activation/config/lists/rules/tags，全部收到 HTTP 200。统计请求使用真实 RFC3339 时间范围和 limit 边界，不是只发空 body。

另一份独立 fresh state 完成 hosts put/get、route config put/get、resolver create/get/delete、node create/get/use/selected/close/delete、disabled inbound create/get/delete、前端真实形状的 local route list create/get/delete、route rule create/get/delete；每个 mutation 均收到 200 且 reload 后读取到持久化结果。一次故意缺少 Go priority API 所需 `source`/`target` 的请求收到 400，确认错误分类而非把非法请求当成功。订阅 refresh/delete-users 仍按范围明确延期。

## 27. 2026-08-09 native Rust SQLite reverse-open compatibility

此前 Rust fresh state 只创建了 Rust typed tables，没有记录 Go `metadata`/`migrate` 的已应用版本。Go 打开该数据库时会把现有 Rust 表误判为尚未迁移的数据库，并在 Go v1 DDL 中重复创建 `dns_resolvers`，最终以 `table dns_resolvers already exists` 失败。

现在 native Rust 初始化会直接创建 Go runtime 仍会读取的兼容表，并记录 Go migration 1--6、legacy migration marker 和 `schema_version=6`；Go v1-v6 的 DDL 不会在同一份 native 数据库上重复执行。旧 Rust 库升级时还会幂等补齐 `route_rules`/`dns_resolvers` 的 nullable Go projection columns。该处理保留 `rusqlite + bundled SQLite`，没有重新引入 fsqlite。

本轮验收：`cargo test --workspace --all-features --offline --quiet` 全部通过；其中 store 为 113 passed/4 ignored，runtime 为 183 passed。独立 `~/.cache/yuhaiin-rust` fresh Rust state 已被 Go binary 重新打开，日志出现 `plain model migration finished`，且没有缺失兼容表告警；旧 Rust state 也已实际完成 projection column upgrade 后被 Go 重新打开。该 smoke 覆盖的是启动、migration 和表存在性边界；非空生产库中 route/resolver projection 的逐行语义、统计最终投影和真实 rollback 仍需使用生产形状 fixture 继续验收，不能据此宣称完整双向数据等价。

## 28. 2026-08-09 settings/backup 双向进程级接管

对照 Go `SettingsStore.Load/Save` 与 `BackupStore.Get/Save`，Rust 管理面不再把 settings 的 `backup` reference 和完整 `backup.config` 混为一层：settings API 使用 Go contract 默认值、只投影已知字段、写入 Go `settings_kv`；backup config API 使用 Go 的单行 `backup_settings`，保留完整 `data_json` 以避免丢失 S3 或未来字段。Rust 的私有 `yuhaiin_config` 仍作为没有 Go 表时的 fallback。

新增 repository/API 单测，并用真实独立 SQLite 做双向进程级验证：

- Rust 写入 settings（含 `65536/65535/5000/0` 边界值）和 S3 backup 后，Go 重新打开同一库，读回 settings 与完整 backup config。
- Go 写入 settings 与 backup config 后，Rust 重新打开同一库，读回字段、数值和 `backup` reference 形状。
- 测试状态目录均位于 `~/.cache/yuhaiin-rust`，没有使用 `/tmp`；现有 `backup.run/restore` 的真实 S3 上传和跨发行版 service-manager 验收仍保持在 checklist。

## 29. 2026-08-09 非空生产 schema-4 接管与单端口规则兼容

从 sibling Go checkout 的真实非空 schema-4 `state.db` 制作只读副本到 `~/.cache/yuhaiin-rust` 后，Rust 首次启动暴露了一个实际 Go 数据兼容问题：`route_rules_v2` 的 `direct` 规则包含 `{"type":"port","port":{"ports":"6969"}}`。Go 的 `NewPort` 把没有连字符的字符串当作单个端口，Rust 原先只接受 `start-end`，因此错误退出并没有启动 HTTP listener。

Rust 现在把字符串单值规范化为 `(port, port)`，仍拒绝空值、非数字、超过 `u16`、多余连字符和反向范围；新增 runtime router 回归验证 `6969` 命中而 `6970` 不命中。修复后使用同一份副本启动 `target/debug/yuhaiin`，实际读取并收到成功响应的接口包括：

- `/api/v2/info`、`settings`、`backup/config`；
- `/api/v2/nodes`（206 条）、`inbounds`（12 条）、`resolvers`（6 条）；
- `/api/v2/route/rules`（6 条）、`route/lists`（11 条）；
- `/api/v2/connections/total`、`history`、`failed-history`；
- 带 RFC3339 `from/to` 的 `/api/v2/connections/traffic` 和 `telemetry`。

状态副本和启动目录均位于 `~/.cache/yuhaiin-rust`，未使用 `/tmp`；原始 Go 数据库没有被写入。该 smoke 证明真实生产 route JSON 能完成启动和管理面读取，但不等价于已经覆盖所有节点协议的出站连通性，也不替代 Go/Rust 并发写入、异常终止和未建模表的逐字段快照验收。

## 30. 2026-08-09 schema-7 接管与生产 history 合并

本机另有一份真实 Go schema-7 状态：`metadata.schema_version=7`，包含 206 个 `nodes_v2`、13 个用户和 73 条 `subscription_nodes_v2` 关联。虽然当前 Go checkout 的迁移列表以 v6 为主，这份旧生产状态仍可被 Go 的 `Bootstrap` 打开；Rust 原先在读取 metadata/migrate 时直接拒绝 v7，无法完成直接替换。

Rust 现在明确支持这个“仅新增用户/订阅关联表”的 v7 形状：共享 v2 表继续导入，Rust 暂不实现订阅刷新，但未知订阅表不删除、不重建，后续仍可由 Go 读取。实际接管后 `/api/v2/info`、settings、nodes、inbounds、resolvers、route/rules、connections/total 均返回 200。

同一 smoke 还暴露了统计边界：历史 checkpoint 中存在多个相同 `(protocol, addr, process)` 的旧记录，Go 的 `connection_history` 主键不允许直接写入重复行。Rust 现在在 checkpoint 恢复、history API 和 Go projection 前统一合并 count，并保留最新连接详情/时间；修复后真实 schema-7 状态优雅停止成功，最终 `connection_history` 无重复主键，checkpoint history 从 1270 条归并为 1258 条。

这次验证使用的副本和响应文件均位于 `~/.cache/yuhaiin-rust`，未修改 Go 原始数据库，也没有使用 `/tmp`。schema-8 及更高版本仍 fail-closed，直到完成对应表结构和枚举语义审计。

## 31. 2026-08-09 Go 协议互操作与 namespace TUN netem

本机 `go version` 为 `go1.26.5-X:nodwarf5`，显式运行此前默认 `#[ignore]` 的跨语言测试，所有已覆盖的 wire contract 均通过：AEAD TCP/UDP 双向各 1 项、Trojan、VLESS、VMess、Shadowsocks、HTTP obfs、ShadowsocksR、WebSocket/HTTP2 和 Yuubinsya listener 均无失败。测试的 Go 构建临时目录使用 `~/.cache/yuhaiin-rust` 下的路径，没有使用 `/tmp`。

workspace ignored 测试第一次直接在宿主运行时，两个 `p0_tun` netem 测试因 `tc qdisc` 返回 `Operation not permitted` 失败；随后在独立的 rootless user/network namespace 中重新运行同一 `p0_tun` 测试，`chain_datagram_survives_kernel_loopback_loss` 和 matrix 两项均通过。该结果证明测试本身和内核 loopback loss 路径可运行，但仍不替代 Android/macOS TUN、真实宿主 CAP_NET_ADMIN 下的透明转发与长期 MTU/fragment 验收。

前端 generated.ts 的 88 个 RPC operation 已完成静态集合核对；`connections.events` 和 `tools.logs` 是 Go 明确标记的 streaming endpoint，Rust 使用直接 SSE route，不应作为普通 JSON RPC 缺失。剩余 API 缺口是生产数据库上的逐字段 response、错误语义和 reload/apply side-effect 快照，而不是 operation 路由集合缺失。

## 32. 2026-08-09 schema-7 生产节点选择双副本回归

使用真实 Go 数据库 `/home/asutorufa/Documents/Programming/yuhaiin/tmp/v2/state.db` 的独立副本，分别启动 Go 与 Rust 服务；副本和日志位于 `~/.cache/yuhaiin-rust/api-compare-selected-20260809`，没有读取写回原始数据库，也没有使用 `/tmp`。源库确认 schema 7 同时存在 `nodes`、`nodes_v2`，并在 Go `metadata` 中以纯字符串保存：

```text
selected_tcp_node_v2 = a549f6c7-3ba1-42bc-9708-3a069f5e61b2
selected_udp_node_v2 = a549f6c7-3ba1-42bc-9708-3a069f5e61b2
```

修复前 Rust `nodes.selected` 返回 `{}`，原因是只读取 `yuhaiin_config` 中形如 `{"id": ...}` 的 JSON。修复后 Rust 在缺少 overlay 时从 `metadata` 回读两个 ID，真实副本的 `nodes.selected` 已返回与 Go 相同的 TCP/UDP 节点；通过 Rust `node.use` 后，两个 Go metadata key 也都写回相同的原始 ID，重读仍返回选中节点。新增 API 单测覆盖 metadata-only 读取和 use 双写。

同一快照中 `resolvers.get` 的 6 条记录及有效 `page/page_size` 分页总数一致；route list 的 remote cache 统计仍会因副本缓存文件和网络环境不同而不同，不能据此宣称逐字段完全一致。生产管理面剩余工作仍是逐操作 response/error/reload side-effect 差异快照。

## 33. 2026-08-09 route tags Go contract 双副本回归

Rust route tags 之前读写私有 `yuhaiin_config` 的 `route.tag.*` key，与 Go 当前使用的 `node_tags_v2(name, members_json, updated_at)` 不一致，导致 Rust 接管真实 Go 状态时看不到已有 tags。现在 list/put/delete 均使用 `node_tags_v2`；响应对象按 Go `TagItem` 返回 `name/type/hash`，空 type 规范化为 `node`，list query 在 name/type/hash 上过滤，delete 按公开 name 删除并对不存在记录返回 404。

使用真实 schema-7 Go 数据库的两个独立副本分别启动 Go 与 Rust，生成的 RPC `route.tags.get` 输出完全一致：9 条生产 tags、`page/pageSize/total` 分页字段和每条的 name/type/hash 均一致。随后对两个进程分别执行 put、按 query 读取、delete 和重复 delete；HTTP 状态序列均为 `200/200/200/404`，Rust 删除后 `node_tags_v2` 行数为 0。副本、请求和日志均保存在 `~/.cache/yuhaiin-rust/api-compare-tags-20260809` 与 `api-compare-tags-mutation-20260809`，没有使用 `/tmp`；本次证据以 React generated client 使用的 RPC 路径为准。

## 34. 2026-08-09 TLS 公共根证书兼容

Go `pkg/net/proxy/tls.ParseTLSConfig` 先加载系统证书池，再追加节点 `ca_cert`，并支持 `insecure_skip_verify`。Rust chain 之前要求每个 TLS 节点至少提供一份 `ca_cert`，且忽略了 `insecure_skip_verify`，使使用公共 CA 或自签名测试证书的 Go 节点无法直接接管。现在 chain 使用纯 Rust `webpki-roots` 作为默认公共根，并继续追加 PEM/DER 格式的 `ca_cert`；空 `ca_cert` 合法，私有 CA 仍必须随节点配置提供；`insecure_skip_verify` 只跳过证书链/主机名校验，仍验证 TLS 握手签名。

新增配置、根证书池和 TLS+HTTP/2+Yuubinsya TCP/UOT through TUN 回归；其中专项回归实际使用空 CA + `insecure_skip_verify=true` 完成 TLS、TCP 和 UOT 握手。`yuhaiin-chain` 全部 47 个单元/集成测试通过。该实现与 Go 的系统证书池在企业私有根集合上仍可能不同，生产私有 CA 应显式配置，不能把 WebPKI 根集合当作平台证书池的逐字节等价物。

## 35. 2026-08-09 协议层 TLS transport 兼容

同一 Go TLS 配置还会作为 Trojan/VLESS/VMess 等协议的独立 transport layer 使用。Rust 原先只在 chain builder 处理公共根和自定义 CA，`protocol::tls::RustCryptoTlsProxy` 仍忽略 `insecure_skip_verify`，并且配置自定义 CA 时不会追加公共根。现在两条构建路径统一：公共 WebPKI 根始终存在，自定义 CA 追加到同一 root store，`insecure_skip_verify` 使用 Rustls custom verifier，同时保留握手签名验证；连接池/协议包装不再因配置形态不同而改变证书语义。

runtime 的 Trojan TLS builder 回归已覆盖 `insecure_skip_verify=true` 和空自定义 CA；workspace 全量测试通过。该回归验证的是构建和选项传递，协议层真实远端证书仍需按具体 Trojan/VLESS/VMess fixture 继续做 wire-level 长连接验收。

## 36. 2026-08-09 Makefile musl 构建

Makefile 新增 `MUSL=1`、`build-musl` 和 `build-release-musl`。默认目标为
`x86_64-unknown-linux-musl`，使用 Rust toolchain 自带的 `rust-lld` 生成 static-pie；
本机实测 `make build MUSL=1` 和 `make build-release-musl` 均成功，debug binary 可执行
`yuhaiin version`，`file`/`ldd` 均显示静态 musl 产物。直接使用本机 `musl-gcc` 生成的
Rust binary 在当前环境的 musl loader 初始化阶段会段错误，因此 Makefile 不默认选择它；
交叉 musl target 可通过 `MUSL_TARGET` 和 `MUSL_LINKER` 显式覆盖。所有临时状态仍放在
`~/.cache/yuhaiin-rust`，未使用 `/tmp`。

## 37. 2026-08-09 generated RPC route coverage guard

此前虽然已经静态核对 React `generated.ts` 的 88 个 operation，但单个 operation
后续被删路由时，workspace 测试不会自动报警。现在 `yuhaiin-runtime` 的 API 单测维护
React operation inventory：87 个 JSON-RPC operation 逐个发空 JSON 请求并断言不能返回
404；`connections.events`、`tools/logs` 和 `tools/logs/v2` 的直接 GET/SSE 路由另外断言
200 及 `text/event-stream`。该测试不要求 mutation 的空参数成功，因此不会掩盖参数校验；
它专门保证前端可见 operation 仍然进入 Rust handler。`cargo test -p yuhaiin-runtime
every_generated_frontend_rpc_operation_has_a_route --all-features` 已通过。

## 38. 2026-08-09 telemetry daily projection 与 Go v5→v6 接管

真实生产副本回归发现了两层统计兼容边界：一份 compact telemetry 库缺少
`traffic_dimension_daily` / `failure_dimension_daily`，会让 Go 的
`connections.telemetry` 在长时间范围直接返回 `no such table`；另一份 schema-7
生产库虽然仍只有 Go v5 的文本维度 hourly 表，但 `metadata.schema_version` 已经被
历史迁移版本复用，Go 当前迁移不会再执行 compact telemetry 转换，启动时会同时出现
`telemetry_dimension_values` 缺失和 daily maintenance 不能读取 `value_id`。

Rust `crates/yuhaiin-store/src/statistics.rs` 现在在同一个写事务中：

- 创建 Go v6 兼容的 `telemetry_dimension_values`、traffic/failure hourly 和 daily
  表及 lookup index；
- 以 UTC 小时为边界保留最近 30 天 hourly，将更早数据按
  `(bucket_start_utc / 86400) * 86400, value_id` 聚合到 daily；
- 对旧的文本维度 hourly 表使用临时 compact 表写入 snapshot，成功后删除旧表并
  原子 rename 为 Go v6 表；失败会回滚，不会留下半套 schema；
- loader 同时合并 hourly/daily，避免 Rust 重启后丢失历史流量或失败计数。

新增 store 单测覆盖缺 daily 表、同日多个小时的 traffic/failure 合并、Go v6 fixture
回写以及 Go v5 文本维度到 compact 表的转换。随后从
`/home/asutorufa/Documents/Programming/yuhaiin/tmp/v2/state.db` 制作独立副本到
`~/.cache/yuhaiin-rust/api-production-20260809/legacy-compat-*`，Rust 服务优雅停止后
确认 SQLite 中存在 compact telemetry 相关表；再用 Go 服务打开同一副本，调用
`POST /api/v2/rpc/connections.telemetry`（2020–2030，limit 50）返回 HTTP 200，且不再
出现缺表/`value_id` 错误。该验证没有修改原始数据库，也没有使用 `/tmp`。

## 39. 2026-08-09 service-chain integration regression

新增 `crates/yuhaiin-runtime/tests/service_chain.rs` 与共享 fixture
`crates/yuhaiin-runtime/tests/support/mod.rs`。测试启动 Cargo 构建出的真实
`yuhaiin` 子进程，使用 SQLite 和 `/api/v2` 写入 node、inbound、route rule，等待
runtime reload 后再通过 loopback socket 发送实际流量，而不是只调用 Rust router
函数。HTTP 场景验证了 HTTP inbound → `example.test` route rule → fixed + HTTP
CONNECT outbound，并检查 outbound 收到的 CONNECT authority、live connection 的
inbound/outbound/mode/match history、traffic total、`route.rules.test` 和 node
latency。

同一组测试还验证了 Go `mixed` inbound 的 UDP 语义：mixed 即使没有显式
`protocol_udp` 字段，也必须启动 SOCKS5 UDP listener；UDP packet 经过 mixed →
SOCKS5 UDP framing → direct relay 后由 loopback target 回显，并在 connections 中
显示为 `mixed`/`direct`。此外，单个默认 mixed listener 占用 1080 时只记录 bind
错误并跳过该 inbound，不再让整个 inbound supervisor 提前退出，因此随后通过 API
添加的自定义 inbound 仍能启动。

本次也修复了管理 API 直接构造 proxy 时的域名目标问题：只有 direct transport 在
进入 socket connect 前通过 runtime resolver 解析 endpoint；HTTP/SOCKS5/TLS/
HTTP2/Yuubinsya 等需要把域名交给远端或握手层的 proxy 保留原始 domain。这样
`direct async proxy requires an already-resolved IP endpoint` 不再出现在 direct
latency/管理面调用中，同时不会破坏 proxy-side DNS 和 TLS SNI。

运行命令：

```bash
cargo test -p yuhaiin-runtime --all-features --offline --test service_chain -- --nocapture
# 或使用可重复检查的 cache-owned 目录：
bash scripts/integration/service-chain.sh
```

测试默认将状态放在 `~/.cache/yuhaiin-rust/integration/<scenario>/<pid>`；设置
`YUHAIIN_INTEGRATION_DIR` 可保留 SQLite 供本地或 Podman `--network=host` 任务检查，
不使用 `/tmp`。

## 40. 2026-08-09 runtime TLS/H2/Yuubinsya service-chain regression

在同一份 `service_chain.rs` 进程级测试中加入真实的 TLS + HTTP/2 + Yuubinsya
出口 fixture。fixture 使用 `yuhaiin-chain::YuubinsyaH2Server`、RustCrypto TLS
和一个 loopback TCP/UDP target；Rust runtime 通过 `/api/v2/nodes` 写入 Go 形状的
`fixed → tls → http2 → yuubinsya` chain，再通过 `/nodes/{id}/use` 使其成为活动
节点。测试随后通过 HTTP inbound 发送 domain CONNECT，确认 TCP payload 从
inbound 经 route rule、TLS、H2 CONNECT、Yuubinsya 到 target 后回显；同一节点再由
mixed UDP inbound 发送 SOCKS5 UDP domain frame，确认 UDP-over-TCP session、server
side UDP relay 和回包均工作。

测试还检查两条 flow 的 `connections` 均显示正确 inbound/outbound/mode，且同一个
chain node 的 TCP latency API 返回成功；同时使用前端实际的 RFC3339 `from/to` 查询
traffic、telemetry、failed-history，并在 TCP flow 关闭后确认 history 已生成。fixture 中 direct target 的域名映射只存在
测试 server 侧，用来保留客户端发出的 `example.test`，不依赖宿主机 DNS，也没有把
测试专用解析逻辑带入生产 runtime。

执行：

```bash
cargo test -p yuhaiin-runtime --all-features --offline --test service_chain -- --nocapture
```

## 46. 2026-08-10 React management API process contract

新增 `crates/yuhaiin-runtime/tests/api_contract.rs`，用真实 `yuhaiin` 子进程和
`~/.cache/yuhaiin-rust/integration` 下的 SQLite 状态执行一轮管理面契约验收，而不是只在
Axum router 内调用 handler。该测试覆盖：

- settings/backup、hosts/FakeDNS、resolver 和 inbound 的读写及 CRUD；
- node 保存、TCP/UDP selection、真实 inbound selector reload 后的 `nodes.active`；
- user credential view、publishes/subscriptions；
- route config、lists、rules、rule test、tags、activation/apply；
- connections、total、traffic、telemetry、history、failed-history、close；
- tools、SSE 和代表性的 404 错误响应。

验证过程中保留了两个重要契约边界：`nodes.active` 反映 live proxy selector，而不是仅
有 `enabled` 的节点行；selection 变更需要等待 inbound owner 收到 reload 后才会反映到
活动 slot。User 的 token credential 采用 generated contract 的嵌套形状
`{"type":"token","token":{"token":"..."}}`，返回值再由 Rust 转成 frontend 的
`CredentialView`。

执行：

```bash
cargo test -p yuhaiin-runtime --all-features --offline --test api_contract -- --nocapture
```

## 43. 2026-08-09 SOCKS5 outbound process-chain regression

新增可复用的纯 Rust SOCKS5 loopback fixture，并通过真实 runtime API 配置
`fixed → socks5` outbound。HTTP inbound 发送 `example.test:<port>` 的 CONNECT 请求，
请求经过 route rule 和 SOCKS5 outbound 后由 fixture 映射到 loopback echo target；fixture
会记录 SOCKS5 domain request，确认 runtime 没有提前把代理侧域名错误地解析成 IP。

该场景同时验证 outbound connection metadata、route match history、双向 payload 和
`/api/v2/nodes/{id}/latency`，因此当前 service-chain 已覆盖 direct、HTTP CONNECT、
SOCKS5、TLS/H2/Yuubinsya TCP，以及 Yuubinsya UOT UDP 的真实进程组合。

## 44. 2026-08-09 standalone HTTP/2 transport compatibility

Go `pkg/net/proxy/http2/v2` 的 client/server 是明文 prior-knowledge HTTP/2：client
对每条 raw tunnel 发送 `CONNECT http://localhost`，收到 `200` 后把 request body 和
response body 当作双向字节流；它不携带 Yuubinsya password，也不把最终目标地址编码进
HTTP/2 request。Go inbound contract 则把 HTTP/2 作为 transport，外层仍由 HTTP、SOCKS5、
Yuubinsya 等 protocol 处理目标地址。

Rust `yuhaiin-chain` 现在允许 Go chain 的最后一层为 `http2`，并复用原有
fixed/DNS/TLS/WebSocket/H2 pool；`ChainClient::connect_raw_with_bind` 提供 raw
CONNECT stream，支持多 stream、多连接、idle/drain、ping 和 close。原有
`fixed → tls → http2 → yuubinsya` 路径保持不变。为避免把“只有 transport、没有目标
protocol”的节点误当成最终出站，`ChainProxy::from_go_json*` 对 `[fixedv2,http2]`
节点仍 fail-closed；现在由 `yuhaiin-protocol::{http,socks5}` 在同一个 raw stream
boundary 上提供 `[fixedv2,http2,http]` 和 `[fixedv2,http2,socks5]` 的 TCP protocol
wrapper，不复制 H2 pool 或 TLS 实现。

HTTP wrapper 使用 Go 兼容的 `CONNECT host:port HTTP/1.1`、Host、User-Agent 和可选
Basic auth；SOCKS5 wrapper 保持 Go 的双 method greeting、username/password、domain/IP
CONNECT framing，并保留 `hostname/override_port` 字段供后续 UDP 语义。raw H2 没有
datagram parent，因此这两种 wrapper 的 UDP 入口都会返回明确的 unsupported，而不会把
UDP 静默伪装成 TCP。

新增 `crates/yuhaiin-chain/tests/standalone_http2.rs`，使用真实 loopback TCP listener
跑 H2 server，检查 Go-compatible CONNECT URI、双向 raw bytes、second-stream ping、
pool close 和 final-proxy capability error；同时新增 Go JSON parser 单测。已有
runtime H2 inbound 单测继续验证 HTTP/2 transport 到 HTTP protocol 的 CONNECT/header/body
桥接。

执行：

```bash
cargo test -p yuhaiin-chain --all-features --offline --test standalone_http2 -- --nocapture
cargo test -p yuhaiin-runtime --all-features --offline --lib http2_transport_bridges_each_connect_stream_to_the_protocol_server -- --nocapture
```

这项现记为 `[x]`：raw transport、HTTP/SOCKS5 final wrapper 和 inbound 都有 wire-level
覆盖；`[fixedv2,http2]` 单独仍按设计只能作为 transport，必须由上层 protocol wrapper
提供目标地址和 TCP/UDP 语义。

新增执行：

```bash
cargo test -p yuhaiin-chain --all-features --offline --test http2_protocol -- --nocapture
cargo test -p yuhaiin-runtime --all-features --offline --test service_chain http_inbound_routes_through_http2 -- --nocapture
```

前一组验证 raw H2 与 HTTP CONNECT/SOCKS5 wire 组合及双向 payload，后一组启动真实
`yuhaiin` 子进程，经 SQLite/API 配置 inbound、route 和 outbound，再验证 connection
metadata、route history、payload 和 node latency。

## 45. 2026-08-10 HTTP/2 final protocol composition

本轮把 standalone H2 从“只能打开 raw stream”推进到可复用的协议组合边界：

- `ChainProxy::final_proxy` 以 raw `ChainProxy` 作为 parent，按配置选择
  `yuhaiin_protocol::http::HttpProxy` 或 `Socks5Proxy`，因此 H2 pool、TLS、WebSocket 和
  fixed endpoint 逻辑不复制到协议 wrapper；
- `ChainConfig`/Go node parser 接受最后一层 `http`、`http_proxy` 或 `socks5`，仍保留
  `yuubinsya` 兼容字段，并拒绝没有目标协议的 raw H2 final proxy；
- HTTP CONNECT 支持 domain/IP authority、Go `Proxy-Authorization` Basic 头和有界响应
  header parser；SOCKS5 支持 Go 兼容 greeting、两种认证方法、domain/IPv4/IPv6 TCP
  CONNECT response framing；UDP over raw H2 明确失败，后续需要真正的 datagram-capable
  parent 才能实现；
- 新增 protocol 单测、H2 loopback composition test，以及 runtime process-level test：
  `HTTP inbound → route → fixed → HTTP/2 → HTTP/SOCKS5 → payload/latency`。

这项不改变 `[fixedv2,http2]` 的语义：它仍是没有目标地址的 transport，不能直接作为
最终 outbound；可运行的 TCP 组合是 `[fixedv2,http2,http]` 或 `[fixedv2,http2,socks5]`。

## 41. 2026-08-09 运行验收与跨平台构建边界

在 service-chain 统计回归之后又执行了当前仓库的最小容器和交叉构建验收：

- `tun-smoke` 在 Debian testing 的 Podman `--privileged --network=none` 容器中成功创建
  TUN，输出 `tun-opened`；启用 `YUHAIIN_TUN_ROUTE_SMOKE=1` 时成功安装
  `198.18.0.0/15` route 并正常退出。状态和构建产物仍只使用仓库外的
  `~/.cache/yuhaiin-rust`，没有写入 `/tmp`。
- `make android-aarch64` 实际使用
  `/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang`
  和 `llvm-ar` 构建出 Android 35 的 `aarch64` runtime ELF；这只证明交叉编译和链接边界，
  不替代 Android `VpnService` fd、权限、route、功耗和生命周期实机验收。
- `cargo check -p yuhaiin-core --no-default-features --features async-proxy,tun
  --target aarch64-apple-darwin --offline` 通过；完整 runtime 仍需要 macOS SDK/clang
  编译 bundled SQLite，本 Linux 主机的系统 clang 不能伪装成该验收条件。
- `make build MUSL=1` 继续产出 static-pie `x86_64-unknown-linux-musl` runtime，
  说明 Makefile 的 `rust-lld` 路径没有被新增测试或文档改动破坏。

这些结果把 Linux/TUN、Android 交叉构建和 macOS 源码 target check 分开记录；平台行仍保持
`[~]`，直到有对应系统的 native SDK、权限和设备运行证据。

## 42. 2026-08-09 required inbound process-chain regression

为避免只验证 HTTP inbound 而误判 inbound 矩阵已完成，`service_chain.rs` 新增一个真实
子进程场景：通过 `/api/v2/inbounds` 同时写入带用户名密码的 SOCKS5 TCP inbound 和
Yuubinsya TCP inbound，等待同一个 inbound owner reload 后分别完成协议握手，再经共享
router/selector 的 direct 出口连接 loopback echo target。

该场景确认：

- SOCKS5 username/password negotiation、CONNECT response 和双向 relay 正常；
- Yuubinsya header authentication、destination framing 和双向 relay 正常；
- 两种 inbound 都进入同一个 `FlowContext`/`ConnectionMonitor`，connections 中的
  `inbound`, `inboundName`, `outbound=direct` 字段正确；
- listener 就绪通过可复用的 retry fixture 等待，不依赖固定 sleep，失败仍会保留
  SQLite/cache 状态供 Podman 或本地复现。

执行：

```bash
cargo test -p yuhaiin-runtime --all-features --offline --test service_chain -- --nocapture
```

## 47. 2026-08-10 runtime-owned TUN process smoke

此前的 `tun-smoke`、`tun-fakeip-smoke` 和 `p0_tun` 已经覆盖 core 设备、DNS/FakeIP、NAT
以及局部 packet relay，但缺少一个可直接证明“真实 runtime binary 把 TUN 当作 inbound
并由同一个 owner 负责关闭”的可复用入口。本轮新增：

- `crates/yuhaiin-runtime/src/bin/tun_service_smoke.rs`：写入 Go-shaped `inbounds_v2`
  TUN record 和 direct node，创建 `RuntimeController`，调用生产路径
  `inbound::run_until`，等待 `/sys/class/net/<name>` 出现，再通过同一个 shutdown
  receiver 关闭 listener owner，并确认设备已消失；没有复制第二套 TUN 实现。
- `scripts/integration/tun-service.sh`：构建该真实 runtime binary，在 Debian testing
  的 Podman `--privileged --network=none` 中运行，SQLite fixture 和构建产物都位于
  `~/.cache/yuhaiin-rust`，不使用 `/tmp`；重复运行会复用同一 state 目录。
- `Makefile` 新增 `build-tun-service-smoke`，便于本地或 CI 单独构建验收二进制。

实际执行结果：

```text
runtime-tun-opening name=yrtun0 database=/state/state.sqlite
runtime-tun-opened name=yrtun0
runtime-tun-closed name=yrtun0
```

这项强化了 Linux TUN inbound 的进程级证据，但不改变 Android/macOS 的 `[~]` 状态；
外部 `VpnService`/utun fd、权限、route 和资源实测仍需对应平台环境。

## 48. 2026-08-10 DNS resolver source-address Podman smoke

为把 resolver 的 source-address policy 从单元测试推进到可复用的容器验收，新增
`scripts/integration/dns-source-bind.sh` 和 `make dns-source-smoke`：脚本复用
`yuhaiin-core` 中已有的 UDP/TCP async client/server 测试，在 host-network Debian testing
容器内分别从 `127.0.0.2` 发起请求，并由 `127.0.0.1` 的 DNS server 回包。

这项确认了：

- UDP client 在发送前按地址族绑定配置的本地地址；
- TCP client 使用 `TcpSocket` 先绑定本地地址再连接；
- DNS packet transaction、响应解码和两种 transport 的 client/server 闭环未被容器运行时
  破坏；
- 构建日志和 Podman 日志保存在 `~/.cache/yuhaiin-rust/integration/dns-source-bind`，
  没有使用 `/tmp`。

实际执行结果：

```text
test dns_udp_async::tests::async_udp_client_and_handler_round_trip_with_original_transaction ... ok
test dns_tcp_async::tests::async_tcp_client_and_server_round_trip_preserves_transaction ... ok
[dns-source-bind] passed
```

当时 DoH/DoT 以及 SOCKS5 UDP/node latency 的网络验收仍保留在 checklist 下一步；后续的
DoH/DoT fixture 见下节，本次没有把 UDP/TCP 的已有覆盖重复实现一套。

## 49. 2026-08-10 RustCrypto DoH/DoT source-address Podman smoke

在 UDP/TCP resolver smoke 之后，继续把加密 DNS transport 的 source-address policy 做成
真实网络验收。`crates/yuhaiin-runtime/tests/doh_tls.rs` 的 server fixture 现在把接入方
peer 传回测试，并新增 `rustcrypto_encrypted_resolvers_honor_local_bind_address`：同一个
`RustCryptoResolverFactory` 分别构造 DoH/HTTP2 和 DoT/TLS resolver，调用统一的
`build_with_policy`，要求两端都从 `127.0.0.2` 连接并检查返回地址。

`scripts/integration/doh-source-bind.sh` 与 `make doh-source-smoke` 在 host-network Debian
testing Podman 中执行该测试；构建和运行日志位于
`~/.cache/yuhaiin-rust/integration/doh-source-bind`，没有使用 `/tmp`。

实际执行结果：

```text
test rustcrypto_encrypted_resolvers_honor_local_bind_address ... ok
[doh-source-bind] passed
```

因此 DNS 的 UDP/TCP/DoH/DoT source-address 已分别有单测和 Podman 入口；SOCKS5 UDP
ASSOCIATE 的真实 inbound 链路见下节，node latency 的 DNS/UDP 网络 fixture 仍待补。

## 50. 2026-08-10 real SOCKS5 UDP ASSOCIATE chain smoke

原有 `connections_close_removes_a_live_socks5_udp_flow` 直接调用 UDP loop，不能发现真实
SOCKS5 控制连接与 UDP socket 端口不同的问题。本轮新增
`socks5_udp_associate_routes_through_the_shared_outbound`，完整走：

```text
SOCKS5 greeting/request(UDP ASSOCIATE)
  -> advertised UDP relay
  -> SOCKS5 UDP packet
  -> router/RuntimeProxySelector
  -> direct AsyncDatagram
  -> UDP echo target
  -> monitor connections
```

同时修复了两个真实协议问题：

- UDP ASSOCIATE 按 client IP 验证来源，而不是错误地要求 UDP 源端口等于 TCP 控制端口；
  首个合法 UDP peer 会成为回包目标；
- BND.ADDR 不再把 wildcard `0.0.0.0` 直接暴露给客户端，而是用控制连接的 peer IP 和
  relay port 生成可达地址。

`scripts/integration/socks5-udp-associate.sh` 与 `make socks5-udp-associate-smoke` 已在
host-network Debian testing Podman 中通过，并且断言 inbound metadata 与 `outbound=direct`。
构建和运行日志位于 `~/.cache/yuhaiin-rust/integration/socks5-udp-associate`，没有使用
`/tmp`。node latency 的 DNS/UDP API fixture 见下节；其余更复杂 outbound/重试场景仍在
checklist 的增强项中。

## 51. 2026-08-10 node latency DNS/UDP API chain smoke

为验证 latency API 不只是调用底层 probe 的 mock，新增
`direct_node_latency_dns_uses_the_selected_proxy_datagram`：测试保存一个 direct node，
通过 snapshot 的 `build_proxy` 取得选中的 outbound，再调用 `node_latency_value` 的 DNS
分支；本地 UDP server 解码并回写真实 DNS transaction，响应必须为成功。

`scripts/integration/node-latency-dns.sh` 和 `make node-latency-dns-smoke` 在 host-network
Debian testing Podman 中执行同一测试，日志位于
`~/.cache/yuhaiin-rust/integration/node-latency-dns`，没有使用 `/tmp`。

实际执行结果：

```text
test api::tests::direct_node_latency_dns_uses_the_selected_proxy_datagram ... ok
[node-latency-dns] passed
```

这补齐了当前 checklist 中 node latency 的基础 DNS/UDP 网络闭环；更复杂 outbound、失败
重试和长生命周期统计仍属于后续增强项。

## 52. 2026-08-10 concurrent statistics process smoke

为补充统计项的进程级证据，新增 `tests/stats_concurrency.rs` 和
`scripts/integration/stats-concurrency.sh`。测试启动真实 runtime 子进程，建立 HTTP
inbound → HTTP outbound 的长连接，在流量持续更新期间并发读取以下管理接口：

- `connections`
- `connections/total`
- `connections/traffic`
- `connections/telemetry`
- `connections/history`
- `connections/failed-history`

流量连接关闭后，测试停止 runtime，再用同一个 SQLite 状态重启并确认最终 traffic/history
仍可读取。Podman 入口使用 Debian testing host-network，构建产物和日志均位于
`~/.cache/yuhaiin-rust/integration/stats-concurrency`，没有使用 `/tmp`。

实际执行结果：

```text
test concurrent_stats_readers_survive_flow_updates_and_restart ... ok
[stats-concurrency] passed
```

这只证明 Rust runtime 自身的并发 reader、流量更新和重启读回边界；它不替代 Go 进程并发
读写、生产数据库逐字段快照及升级期间锁竞争验收，因此 checklist 的统计项仍保持 `[~]`。

## 53. 2026-08-10 fresh-state default projection parity

Go 新库除了 inbound、resolver 和 route 表，还会写入 settings KV 与 route-extra 元数据；Rust
现在在首次初始化同一组默认图时同步写入这些兼容行：IPv6/默认网卡/HTTP system proxy、
debug/save 日志、bootstrap resolver 的 `system=true`、MaxMind 下载状态、LAN route list
与 priority=1 的 LAN rule。

同时移除了 Rust service 启动时额外持久化的 `rust-builtin/direct` node。Go 的 direct 是
selector 的内置 fallback，不属于 `nodes_v2` 配置列表；Rust runtime 仍在空 proxy ID 时使用
direct fallback，因此空库 `nodes.get` 与 Go 一样为空，而 inbound/TUN 数据面仍可 direct。

API 展示也按 Go contract 收敛：route list preview 只返回第一项，bootstrap resolver 保留
`system=true`。`crates/yuhaiin-runtime/tests/api_contract.rs` 增加了 fresh settings、空节点、
resolver、route preview/index 和 route-list config 断言；实际 Rust 二进制与 Go fresh process
的 RPC 对照已在 `~/.cache/yuhaiin-rust/api-parity` 完成。宿主机已有 `127.0.0.1:1080` 时，
默认 mixed listener 会报告 bind 冲突，这只影响 listener/active-node smoke，应在 Podman
network namespace 中执行完整 API contract，不应把它误判为 API JSON 不兼容。

## 54. 2026-08-10 mixed UDP normalization and direct diagnostic

`mixed` inbound 的 UDP 能力由 protocol 语义决定，不依赖 `protocol_udp` 字段；因此
`network.tcp_udp.udp=enabled` 的 mixed 配置必须进入 SOCKS5 UDP listener 分支。协议类型
现在在进入 listener dispatch 前会 trim 并按 ASCII 小写规范化，避免带首尾空白的导入配置
落入 `protocol has no UDP mode` 兜底日志；新增单测覆盖 `" MIXED "` 和 UDP mode。

direct transport 的 socket connect 仍由 runtime resolver 在最后一跳解析 domain，保留
`FlowContext` 中的原始 domain 给 TLS/SNI、HTTP/2、Yuubinsya 和远端代理层；当前 direct
node latency、direct DNS/UDP latency 以及 TLS+HTTP/2+Yuubinsya 进程级链路均已通过。
如果运行中的二进制仍出现这两个旧错误，先用 `make build` 后执行 Makefile 打印的
`~/.cache/yuhaiin-rust/cargo-target/debug/yuhaiin`，不要混用旧的 `target/debug/yuhaiin`；
两条报错分别对应旧 listener normalization 和旧 direct build 路径，不是当前源码的预期行为。

## 55. 2026-08-10 runtime readiness and API contract runner

前台启动日志现在会报告实际 HTTP API 绑定地址，并在 DNS、inbound 和 HTTP API
supervisor 都启动后输出 `runtime ready`；使用 `--host 127.0.0.1:0` 时也不会再只显示
不可连接的 `:0` 占位地址。设置 `YUHAIIN_QUIET=1` 仍会关闭 console mirror，管理 API
中的 `tools.logs`/SSE 不受影响。

新增 `scripts/integration/api-contract.sh` 和 `make api-contract-smoke`，统一在
`~/.cache/yuhaiin-rust/integration/api-contract` 保存构建及 Podman 日志，构建出的 runtime
和 API contract test binary 从同一个 cache target 挂载，使用 host network 复用 loopback
fixture。当前真实进程 contract 已通过；`--network=none` 会让该测试受到容器 loopback
命名空间差异影响，不作为 API contract 的默认验收模式。

## 56. 2026-08-10 direct/mixed process regression

为避免旧二进制或旧配置掩盖运行时回归，`tests/api_contract.rs` 现在包含两个真实
runtime 子进程断言：fresh state 的 `/api/v2/inbounds/mixed` 必须保留
`network.tcp_udp.udp=enabled`，并启动一个 loopback HTTP server，通过
`/api/v2/nodes/{id}/latency` 验证 direct node 的域名目标会先经 resolver 解析后再建立
socket。`scripts/integration/api-contract.sh` 不再只运行管理面大测试，而是运行该文件的
全部 process tests；当前 Podman host-network 结果为 2/2 通过。

## 57. 2026-08-10 process throughput benchmark

新增 `crates/yuhaiin-runtime/tests/throughput.rs` 与
`scripts/benchmark/throughput.sh`。它使用 release runtime 和真实 SQLite/API
配置边界，执行 HTTP inbound → route rule → fixed + HTTP CONNECT outbound 的单流
loopback echo，并在 runtime 子进程上采样 Linux `VmRSS` 与 `/proc/<pid>/stat` CPU ticks。
输出固定的 `BENCHMARK` JSON 行，构建产物、状态库和日志均放在
`~/.cache/yuhaiin-rust/benchmarks/http-throughput`，没有使用 `/tmp`。

当前 benchmark 矩阵：

| 场景 | 状态 | 说明 |
| --- | --- | --- |
| HTTP inbound → router → HTTP CONNECT outbound | 已有可执行基准 | `make benchmark-throughput`；默认 64 MiB、单流、loopback |
| TUN inbound | 设备/生命周期 smoke | `scripts/integration/tun-service.sh`；真实带宽基准仍需 packet generator/namespace fixture |
| WireGuard | 未实现/不报告性能 | 当前范围没有 WireGuard backend，不用虚构结果 |

benchmark 数值只能用于同机、同 profile、同 payload 和同 namespace 的回归比较，不能
直接解释为 Go 与 Rust 的跨机器性能结论。

本机首次基线（2026-08-10，release、Podman host network、64 MiB、单流）：

```text
BENCHMARK {"bytes":67108864,"cpu_ticks":26,"elapsed_ms":309.641875,"mib_per_sec":206.69039030977316,"peak_rss_kib":16496,"proc_samples":15,"scenario":"http-inbound-route-http-connect-loopback"}
```

该数值是当前机器和当前构建的基线，不是验收阈值；后续改动应在相同参数下重复运行并
记录变化原因。
