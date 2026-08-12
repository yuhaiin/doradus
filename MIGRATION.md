# yuhaiin Go -> Rust 迁移设计与实施文档

> 文档状态：架构基线，2026-08-09
>
> 目标目录：`/home/asutorufa/Documents/Programming/yuhaiin-rust`
>
> 本文覆盖网络运行时的第一批高优先级能力：fakeip、DNS、router、proxy、`pkg/net/nat`、TUN、MaxMindDB 和 SQLite 配置存储。
> 不把整个 yuhaiin 一次性翻译成 Rust，也不把 Go 的包边界机械复制过来。

> 2026-08-11 启动可诊断性与 checklist 重排：foreground binary 默认把启动、API bind、runtime ready、shutdown/stopped 写到 stderr；
> `YUHAIIN_QUIET` 只有 `1/true/yes/on` 才会关闭这些 console notice，避免环境中设置 `YUHAIIN_QUIET=0` 时误以为没有日志。
> `IMPLEMENTATION_CHECKLIST.md` 现在按 crate 模块树、协议矩阵、未完成项和验收命令组织；rootful TUN route lease、RST/reconnect 与 TPROXY UDP delivery/idle/force-stop 已有独立 VM 现场证据，但 TUN kernel fragment、Android/macOS 和生产/发布现场仍保留为 `[~]`，不能从单元测试覆盖率推导为完整替换。

> 2026-08-12 inbound reload boundary：对照 Go `Inbound.SaveContract`，Rust 不再让所有配置变更
> 中断全部 socket listeners。普通 node/route/resolver/backup/settings reload 只构建并原子替换已注册
> `RuntimeProxySelector`；inbound、中心用户、selected-node 和全量 apply 变更才发布专用 inbound
> reload，由 owner latest-wins 重绑监听。新增 controller 通知边界单测，并在 Podman 的
> `make api-reload-flow-smoke` 中保持同一 HTTP CONNECT 隧道跨 route reload 连续 echo；同时修正
> 运行中新增/切换节点时 selector 角色 ID 需要重建的兼容路径。普通 reload 不再误杀已有 flow，真正
> 的 inbound 结构/认证变化仍明确触发 listener replacement。

> 2026-08-12 TUN DNS hot-reload closure：TUN dispatcher 的 DNS 劫持不再把初始
> `RuntimeSnapshot` 中的 resolver 永久捕获。controller 现在持有可热替换的、跨线程安全的
> `RuntimeDnsHandler` 快照；resolver/FakeIP/inbound DNS policy reload 后，下一条 TUN DNS
> query 使用新快照，进行中的 query 仍完成旧快照。`inbounds/config` 变更同时走专用 inbound
> reload，使 `hijackDns` 开关能唤醒 TUN owner；不重建设备，也不打断无关既有 flow。新增
> `reloadable_tun_dns_handler_switches_snapshots_without_rebuilding_owner` 单测，并由
> Podman `make workspace-tests` 和 `make tun-api-process-smoke` 回归。

> 2026-08-12 WireGuard runtime UDP closure：进程级 `wireguard-chain-smoke` 新增
> `SOCKS5 UDP ASSOCIATE → CIDR router → Cloudflare BoringTun outbound → smoltcp UDP peer`
> 的真实回环链路。首次 UDP send 可能先触发 Noise handshake；旧 adapter 会丢弃同一 IP
> packet，TCP 因为通常在握手完成后才写入所以没有暴露该问题。现在每个 peer 对握手期间的
> IP packet 使用有界队列（256 个），握手完成后重试；队列仍保持 userspace、无第二个 OS TUN
> 的边界。Podman 回归同时断言 peer UDP echo、connections 的 inbound/node/matchHistory 和
> total counters，HTTP/TCP 链保持通过。

> 2026-08-12 benchmark refresh：在当前工作树上重新运行三类 Podman release benchmark。
> HTTP inbound → router → HTTP CONNECT 为 `102.18 MiB/s`、peak RSS
> `19,188 KiB`；HTTP inbound → router → TLS → HTTP/2 → Yuubinsya 为 `26.03 MiB/s`、
> peak RSS `20,904 KiB`；TUN → fixed → loopback 为 `31.23 MiB/s`、peak RSS
> `13,236 KiB`；BoringTun userspace packet 为 `588.64 MiB/s`、peak RSS `3,460 KiB`。
> 这些数字只用于相同机器、profile、payload 和 Podman namespace 的回归比较，原始日志和
> JSON 位于 `~/.cache/yuhaiin-rust/benchmarks/{http-throughput,tun-throughput,wireguard}`，
> 未使用 `/tmp`，不作为 Go 对比或公网性能结论。

> 2026-08-12 update helper rollback coverage：`run_update_helper` 现在把 platform
> stop/restart 作为内部可注入边界，文件替换事务仍保持“先 staged、再 backup、后 install、成功
> restart 才清理 staged”的顺序。Podman `make workspace-tests` 已覆盖成功安装并保留
> `.update-backup`，以及 restart 失败时恢复旧 binary、删除临时 backup、保留 staged 供重试；真实
> macOS launchd/Windows SCM 权限和服务管理器现场仍是独立验收项。

> 2026-08-12 runtime observability/cache boundary：SSE endpoint 显式补齐 Go 的
> `Cache-Control: no-cache` 与 `Connection: keep-alive` 响应头，避免前端 EventSource 在
> 代理/浏览器缓存层被误处理；`connections.events` 的首屏 snapshot、added/removed event 和
> tools log stream 仍共用 axum 的 bounded broadcast。新增 `make cache-prune`，只清理缓存中超过
> 1 天的 integration/parity/benchmark 场景目录，默认保留 `cargo-target` 与 `fixtures`，所有
> 路径仍位于 `~/.cache/yuhaiin-rust`，不使用 `/tmp`。如果确认没有 cargo/rustc 占用缓存，
> `YUHAIIN_CACHE_PRUNE_DEBUG=1 make cache-prune` 还可以释放 `cargo-target/debug` 的依赖中间产物，
> 但会保留已生成的 debug 二进制。

> 2026-08-12 no-argument startup log closure：前台二进制默认启动路径现在由
> `make startup-logs-smoke` 按用户实际方式验证：Podman 只提供隔离的 `HOME`/`XDG_CONFIG_HOME`，
> 不传命令、不设置 `YUHAIIN_DB`、`YUHAIIN_HTTP` 或 `YUHAIIN_QUIET`，直接运行 `./yuhaiin`。
> 默认 stderr 会输出 database、API bind、runtime ready、shutdown/stopped；只有显式设置
> `YUHAIIN_QUIET=1` 才关闭这些前台进度日志。

> 2026-08-12 replacement parity recheck：当前提交在 Podman 重新通过停止态 Go 快照的
> API read/mutation/error matrix（单快照和 3 份 production parity）、Go/Rust live-flow
> statistics、Go protocol interop 9/9（新增 RustCrypto TLS → VLESS → Go server、Go VLESS UDP → Rust server，以及 Go TLS → WebSocket → HTTP/2 → Yuubinsya → Rust server），以及 4 次连续 `api-reload-flow-smoke`。本轮没有发现
> 新的 API、统计、协议或 inbound reload 回归；剩余 `[~]` 主要是第三方 WARP、真实跨平台权限、
> 远程 Actions 和更广生产现场矩阵。

> 2026-08-12 TUN Podman data-plane recheck：当前 rootless Podman 连接在显式传入宿主
> `/dev/net/tun`、`--privileged`、`--network=none` 后，已实际通过 runtime-owned TUN
> device lifecycle、普通 `fixed` TCP packet echo、disable/enable reload 后 packet echo 和
> connection metadata、`fixed -> TLS -> HTTP/2 -> Yuubinsya` packet chain，以及 MTU
> `576/1280/1500/9000/9216` 五档矩阵。smoke 的 traffic client 改为同容器内独立子进程，
> 避免被 runtime 自身的 loopback process guard 当成代理自环；生产 loopback guard 没有关闭。
> `scripts/integration/tun-service.sh`、`tun-mtu.sh` 和 `scripts/benchmark/tun-throughput.sh` 现在
> 按实际 `/dev/net/tun` 能力探测，不再因为 rootless 标志本身跳过；透明 TPROXY/内核路由
> takeover 仍需 rootful `CAP_NET_ADMIN` namespace，不能由上述 TUN packet 证据替代；独立 rootful 证据见下方验收记录。
> 当前 16 MiB release TUN benchmark sample 为 51.75 MiB/s、peak RSS 12,756 KiB，原始日志位于
> `~/.cache/yuhaiin-rust/benchmarks/tun-throughput/`。

> 2026-08-12 MaxMind real-fixture smoke：新增 `make maxmind-smoke`，按用户指定的
> `Country-without-asn.mmdb` URL 下载到 `~/.cache/yuhaiin-rust/fixtures`，先校验固定
> SHA-256 `1d900f73aa4644d255793548319410ff559ef9294a662ec1a0354f106c794155`，再把真实
> 数据库和 Rust test harness 挂载到无网络 Podman 中，执行 IPv4 与 IPv4-mapped IPv6
> country lookup。下载采用 cache-backed partial 文件和 rename，不使用 `/tmp`。

> 2026-08-12 TUN API process switch regression：真实前台 `yuhaiin` 进程现在在 Podman
> disposable user/network namespace 中通过 `/api/v2/inbounds/{id}` 处理 TUN inbound 的
> disable/enable 生命周期。fresh store 的 Go 兼容默认 `tun` 记录是禁用的，Rust 之前把它
> 与 API 新增的启用 TUN 一起判定为“multiple enabled/defined”，导致 supervisor 永远不
> 会打开用户配置；现在选择逻辑只拒绝多个 enabled TUN，启用项优先，全部禁用时取最新编辑
> 定义。`make tun-api-process-smoke` 已通过真实 `/dev/net/tun` 和 `/proc/net/dev` 的
> disabled → enabled → disabled → enabled → disabled visibility 检查；Linux 接口名也按
> IFNAMSIZ 限制保持在 15 字节以内。该证据不替代 rootful route/firewall matrix。

> 2026-08-12 TUN disposable namespace validation：为让 rootless Podman 的验收条件可复现，
> TUN integration/benchmark 脚本现在会根据宿主 `CAP_NET_ADMIN` 自动在容器内进入
> `unshare -Urn` 的 disposable user/network namespace；这不是 fake queue，而是通过传入的
> `/dev/net/tun` 创建真实 kernel TUN，并用 `/proc/net/dev` 检查当前 network namespace 的
> device。traffic smoke 只在测试 namespace 内通过 safe netlink 把 `lo` 置为 up，生产代码的
> loopback guard 没有关闭。当前已重新通过 `make tun-reload-traffic-smoke`（3 个 disable/
> enable cycle、不可达检查、reopen、traffic、close）、`make tun-mtu-smoke`（576/1280/
> 1500/9000/9216）、`make tun-chain-service-smoke`（TUN→fixed→TLS→HTTP/2→Yuubinsya）和
> `make tun-connection-metadata-smoke`（component/node/outbound/localAddr）。这组证据仍不
> 覆盖 rootful 宿主 route takeover 或 TPROXY UDP；`YUHAIIN_TUN_USER_NAMESPACE=0` 用于显式
> 验证具备真实宿主权限的场景。

> 2026-08-12 Debian VM rootful TUN/TPROXY 验收：使用用户提供的 `root@192.168.122.2` Debian
> VM，内核 6.5、Podman 5.8.3、`rootless=false`、`/dev/net/tun` 和 `CAP_NET_ADMIN` 均可用；
> 二进制从宿主已编译产物同步到 VM 的 `~/.cache/yuhaiin-rust-vm`，VM 只负责 Podman 运行。
> rootful `tun-service-smoke` 已通过普通 256B packet echo、3 次 disable/enable reload、
> MTU `576/1280/1500/9000/9216`、`TLS -> HTTP/2 -> Yuubinsya` chain 和 force-stop 后的
> reopen/traffic/close。启用 `tun-routes` 的 `tun-smoke` 另外确认 `198.18.0.0/15` 在 TUN
> 设备存活期间存在，进程正常结束后已移除；后续 3-route graceful/SIGKILL matrix 见文末最新记录。
>
> 同一 VM 的 rootful TPROXY UDP 首次试验未闭环：Rust runtime 的 transparent socket probe、
> `iptables` TPROXY rule（计数增长到 49）以及 `fwmark -> table 100 -> local lo` 都成功，
> 但 client netns 的 UDP packet 没有到达 transparent socket；独立 Python `recvmsg` kernel
> probe 得到相同结果。该历史失败后来定位为测试入口 veth 的 Linux `accept_local` 策略；修正后的
> iptables/nft 结果记录在本文末尾。保留这段记录用于防止把第一次 kernel 行为误判成 Rust
> ancillary bug。透明测试脚本已支持
> `YUHAIIN_SKIP_BUILD=1`、预编译 binary 覆盖、Debian multiarch xtables module 探测和可选
> `YUHAIIN_TPROXY_MODE=redirect` 对照；所有状态仍在 `~/.cache`，没有使用 `/tmp`。

> 同日 release packet benchmark：Cloudflare BoringTun userspace adapter 在 16 MiB 双 peer
> 加解密回归中为 554.65 MiB/s、peak RSS 3,348 KiB；这是 `--network=none` 的同机 packet
> baseline，不代表公网/WARP 链路吞吐。原始日志位于
> `~/.cache/yuhaiin-rust/benchmarks/wireguard/`。

> 2026-08-11 Go/Rust live flow parity：新增
> `scripts/integration/go-live-flow-parity.sh` 与 `make go-live-flow-parity-smoke`。测试会在
> `~/.cache/yuhaiin-rust/integration/go-live-flow-parity/<run>/` 下分别启动 Go/Rust 进程和
> SQLite 状态，配置 HTTP inbound、host list route、fixed + HTTP CONNECT outbound，接入
> 本地 Python CONNECT fixture 并实际回显 payload；随后逐端校验 live connections、累计
> upload/download、traffic、telemetry、node latency 和 history。当前 smoke 已通过。脚本
> 不使用 `/tmp`；Go 的显示型 inbound name、node ID 前缀和部分 protocol 字段会在比较层
> 做语义归一化，不把两个实现的展示差异误判为数据面失败。

> 同一 live flow 还暴露了 Rust monitor 的兼容性边界：HTTP CONNECT inbound 使用占位
> packet tuple 时，`flow.key.endpoint()` 可能是 `0.0.0.0:0`，但原始 authority 已在
> `FlowContext::original_domain`。`connections.addr/destination` 现在优先输出该 authority，
> 并按 Go `net.Addr.String()` 输出裸 `host:port`，新增
> `monitor_connection_uses_http_authority_for_placeholder_socket_tuple` 回归测试。

> 2026-08-11 refact-user CRUD 进程验收：从 Go 仓库的 `refact-user` 分支编译真实 Go
> binary，与 Rust 分别打开同一份停止状态快照的副本，通过 `/api/v2/rpc/users.post`、
> `user.put`、`user.get`、`users.get`、`user.delete` 完成 basic/UUID/token 创建、
> 缺省 credential 更新、查询和删除；同时覆盖被节点引用时的 409 conflict，以及
> missing-user 的 404 错误矩阵。两端返回的用户视图和归一化错误体一致。第一次试验
> 发现 Go 的 list `query` 按用户名称匹配而不是 credential.username，修正测试后
> 两端全部通过。日志保存在 `~/.cache/yuhaiin-rust/integration/refact-user-parity/`，
> 没有使用 `/tmp`。
> 可重复命令为 `YUHAIIN_SOURCE_DB=... make refact-user-parity-smoke`；Go 分支 worktree
> 默认使用 `~/.cache/yuhaiin-rust/go-refact-user`。

> 2026-08-11 process/inbound/negative route matcher API parity：扩展
> `scripts/integration/go-api-parity.sh` 的 mutation fixture，加入 process list、inbound
> list、嵌套 `all(host-list, process-list, inbound-names, port, not(port))`，并逐响应对照
> Go/Rust 的创建、读取、apply、test、删除和错误矩阵。过程中发现测试 fixture 原先把 Go
> `SourceRef` 错写成不支持的 `inbound.list`；Go typed decoder 会忽略该未知字段，Rust 则
> 保留输入 JSON，造成假差异。改为合法的 `inbound.names` 后完整 parity 通过。日志和副本
> 位于 `~/.cache/yuhaiin-rust/integration/go-api-parity/`，没有使用 `/tmp`。
> 可重复命令：`YUHAIIN_SOURCE_DB=... YUHAIIN_PREPARE=1 make go-api-parity-smoke`。

> 2026-08-11 TUN flow isolation and smoke hardening：rootless Podman 现场复测发现，单个 outbound task 在 TUN packet 到达前结束时，旧逻辑会把 `TUN proxy flow channel: channel closed` 当成 supervisor 级错误，关闭整个 TUN inbound。现在 `TunRuntime` 将 `Closed/NotFound` stale-flow 错误限制在对应 TCP/UDP flow，主动关闭该 kernel flow 后继续处理其他 flow；协议、IO、超时等真正的 dispatcher 错误仍会终止 runtime。新增错误分类单测。`scripts/integration/tun-service.sh` 同时增加默认 45 秒超时、命名容器和退出清理，rootless 缺少 netdev/route 时不会无限挂起。当前环境 `CapEff=0`，所以 rootful TUN/route 证据仍待具备 `CAP_NET_ADMIN` 的干净 namespace。

> 2026-08-11 central inbound auth process chain：`InboundAuth` 的 immutable user snapshot 现在有完整的 SOCKS5/Yuubinsya 进程级覆盖。测试通过真实 API 添加 `usage=inbound` 的 basic user，在已有 inline credentials 的两个 listener 上等待 reload，确认错误 SOCKS5 basic credentials 和错误 Yuubinsya password 都被拒绝；随后用 central credentials 分别建立 TCP flow，验证 payload echo、同一 domain route rule、HTTP outbound 和 `connections` 的 inbound/protocol/mode/outbound/matchHistory。HTTP inbound 已覆盖同一用户的 add/update/delete reload；因此当前缺口仅是本地 Go main 没有 refact-user handler 时的逐响应 parity，不再是 Rust runtime central auth 主路径。并行 service-chain 测试还修复了 API 端口预留与子进程 bind 之间的测试竞态。

> 2026-08-11 inbound live switch 修复：普通 socket inbound 的 API reload 流程新增了 disable → listener closed → enable → traffic restored 的真实进程回归。此前注入式 TUN（Android/VpnService 等）路径只捕获初始 `TunRuntimeConfig`，reload 后即使持久化的 TUN inbound 已变成 `enabled=false`，仍会继续运行 dispatcher；现在 `run_until_with_tun_runtime` 在每次 reload 后重新读取 Go inbound/`tun.runtime`，关闭时停止 packet dispatcher，重新开启时复用外部 device 重建 proxy runtime。没有持久化 TUN 记录的宿主仍使用传入的 fallback config。新增 data-plane config tests；真实 VpnService/utun 现场仍待平台验收。

> 2026-08-11 WireGuard 评估与依赖审计（历史记录）：Go 的 `pkg/net/proxy/wireguard` 不是普通 socket proxy，而是 `wireguard-go` userspace device + custom `NetTun`/`PacketConn`；`boringtun` 只提供协议核心，不直接提供 yuhaiin 所需的 socket stack。该审计结论保留作为边界说明，后续已采用独立 `yuhaiin-wireguard` adapter 补上 userspace stack。

> 2026-08-12 WireGuard userspace adapter：新增 `crates/yuhaiin-wireguard`。配置层兼容 Go 的 `secretKey`、`endpoint`、`peers`、PSK、keepAlive、AllowedIPs、MTU 和 Cloudflare WARP `reserved`（JSON base64）；Cloudflare `boringtun 0.7.1` 负责 Noise/WireGuard handshake、session、timer 和 packet crypto，smoltcp 负责虚拟 IP/TCP/UDP socket，UDP underlay 与 runtime `AsyncProxy` 在同一 adapter 内管理。`GoProxyTransport::Wireguard` 只在 runtime 分支构造这个有状态 proxy，不会误走普通 fixed builder，也不会给 inbound 再增加第二套 OS TUN。`make wireguard-smoke` 在 Podman `--network=none` 中通过两端 userspace peer、handshake/data、TCP SYN/RST、reserved 字节、JSON 配置和 5 个单测；`make benchmark-wireguard-throughput` 已补上 release packet 加解密回归基线。真实第三方 peer、NAT roaming、source-interface policy 和真实链路性能仍待外部验收。

> 2026-08-12 Go protocol interoperability：扩展 `make go-protocol-interop-smoke`，宿主只编译 ignored harness，Podman `--network=host` 挂载 Go checkout、GOROOT 和 module cache 后执行：真实 Go Yuubinsya client 覆盖 TCP/UOT/native UDP/Ping，Go WebSocket→HTTP/2 client，Go HTTP/2 v1 client，以及 VLESS、VMess、Trojan 各一条 Go/Rust wire round-trip；当前 6/6 通过。workspace 默认仍将这些测试标为 ignored，避免普通无 Go 环境运行时启动外部进程；Go checkout 通过 `YUHAIIN_GO_ROOT` 注入，专用入口的 Go scratch、日志和缓存均位于 `~/.cache/yuhaiin-rust/integration/go-protocol-interop/`，不使用 `/tmp`。更广的 runtime listener/outbound、TLS/WebSocket/UDP 组合仍保留在 checklist 的 `[~]`。

> 2026-08-11 direct UDP 域名目标修复：TCP direct 的旧错误只会出现在 `0bae7c1` 之前的 binary；当前 release 已不再包含 `direct async proxy requires an already-resolved IP endpoint`。另外补齐了 direct UDP datagram 的第二层边界：`open_datagram` 解析初始目标后，后续 `send_to` 收到 SOCKS5 UDP 域名目标时也会按本地 socket 的 IPv4/IPv6 family 解析并逐个尝试发送，不再在第一包处要求预先转换成 IP。新增 TCP direct、UDP domain send 单测；mixed UDP 的 Go 兼容判定回归仍通过。请使用最新 `make build-release` 产物，不要复用 2026-08-09 以前的旧 binary。

> 2026-08-11 TUN reload traffic smoke：新增 `make tun-reload-traffic-smoke`，与只验证设备生命周期的 `make tun-reload-smoke` 区分；前者在持久化 TUN disable/enable 后继续通过真实 TUN 发送并校验 echo payload。两者都把 Podman 状态和日志放在 `~/.cache/yuhaiin-rust/integration/tun-service`。

> 2026-08-11 注入式 TUN supervisor：宿主传入的 fd 在 proxy snapshot 暂不可构建时不再永久退出；supervisor 会保留 fd 所属的 inbound 生命周期并等待下一次 API reload 后重试。当前 rootless Podman（宿主 `CapEff=0`）中，TUN smoke 在 reload 前后都停在 0 字节，属于缺少 `CAP_NET_ADMIN`/route 的环境证据，不能作为 Rust TUN 数据面通过。

> 2026-08-11 RuntimeService host boundary：将 SQLite 打开、resolver/controller、API、DNS、普通 inbound、注入式 TUN 和 shutdown/persist 编排提取到 `yuhaiin_runtime::service::RuntimeService`；CLI 已使用该入口，未来 Android JNI/AAR 只需提供 `ServiceOptions` 与 host TUN fd，不再复制一套 runtime supervisor。JNI/AAR 本身仍未实现。

> 2026-08-11 TCP/UDP selected node data-plane parity：Go `NodeRuntime.Get` 按网络分别读取 `selected_tcp_node_v2` 与 `selected_udp_node_v2`；Rust 原先在 inbound/TUN supervisor 中只读取 TCP selection，导致 UDP 也走 TCP 节点。现在 `RuntimeProxySelector` 同时维护 TCP/UDP routed slots，TCP flow、UDP flow、SOCKS5/Yuubinsya UDP 和 TUN UDP 按 `FlowContext.network` 选择对应节点；reload、`close_node`、active-node 汇总、outbound metadata 和旧单 selection API 均同步覆盖双路。新增 selector 单测；runtime 223 个单测、core 136 个单测和 `make service-chain-smoke` 13 条真实进程链全部通过。service-chain smoke 的共享等待窗口也从 2 秒扩大到 10 秒，避免并行 Podman/进程负载下 monitor 可见性偶发超时。

> 2026-08-10 TUN live connection metadata fixture：`tun-service-smoke` 增加可选的 `YUHAIIN_TUN_ASSERT_CONNECTIONS=1` 模式，并提供 `make tun-connection-metadata-smoke`。它在真实 TUN traffic 仍存活时读取同一 `ConnectionMonitor`，要求 `component=tun`、选中 node、非空 outbound endpoint、非空 localAddr，避免只用 payload echo 掩盖 connections 元数据丢失。当前 rootless Podman 运行现场只能看到 `runtime-tun-opened`，随后客户端无法建立回显流；容器内 `/proc/net/dev`/`/sys/class/net` 未出现稳定的 `yrtun0`，因此该 smoke 尚未作为通过证据，需 rootful 或干净网络 namespace 重跑。失败现场保留在 `~/.cache/yuhaiin-rust/integration/tun-*`，未使用 `/tmp`。

> 2026-08-10 loopback outbound endpoint wiring：`AsyncStream` 现在可以携带可选的真实本地 `SocketAddr` 元数据；direct/fixed、blocking HTTP CONNECT、SOCKS5、RustCrypto TLS、HTTP/2 pool 以及 Yuubinsya TCP/UOT 均保留该元数据。`RuntimeProxySelector` 对选中的 proxy 统一包一层 stream/datagram lifetime guard，注册采用引用计数，连接释放或 datagram close 后自动移除；UOT reconnect 会更新当前底层 endpoint；新增 core/H2 metadata 单测。真实 TUN 自环现场验收和未暴露 socket 的内存 transport 仍按安全降级处理。

> 2026-08-10 loopback route guard：对照 Go `pkg/route/loopback.go`，Rust 新增 runtime 级 `LoopbackDetector`，并在 `RuntimeProxySelector::route_context` 的统一入口执行入站监听地址自环检查、当前代理进程 path/PID 检查，以及出站本地端点引用计数注册。命中后设置 `RouteMode::Block` 与 `skip_route`，不会再被 trie 规则覆盖；普通未解析域名在没有 FakeIP/hosts 元数据时保留 Go 的例外。新增 detector 单测和真实 selector 拦截测试；`cfg(test)` 不注入测试可执行文件自身身份，避免同进程 fixture 被误判；剩余是真实 TUN 自环现场验收。

> 2026-08-10 SQLite startup compaction parity：Go 状态库启动时先执行 `wal_checkpoint(TRUNCATE)`，再按空闲页的字节数（至少 4 MiB）或数据库占比（至少 10%）决定是否 `VACUUM`，完成后再次 checkpoint。Rust `ConfigStore::open` 现在在迁移完成并释放初始化锁后执行同一策略；健康数据库不会因每次启动而重写，达到阈值才回收可复用页。`sqlite_startup_compacts_reusable_space_with_go_thresholds` 覆盖写入、删除、关闭、重开后的 freelist 回收，`yuhaiin-store` 全部 127 个可运行单元测试通过。

> 2026-08-10 hash-only inbound auth fail-closed：中心 basic 用户的 `allowAnyPassword` 可以被 HTTP/SOCKS5 的明文认证表达，但 Yuubinsya/Trojan 只能接收具体密码哈希。Rust 现在在 listener 构建阶段识别这个不可表达的配置并跳过入站、写入明确 warning；Yuubinsya server 构造器也拒绝空 password-hash 列表，不再因清空 inline password 而退回全零哈希。具体密码、多用户 hash 仍保持兼容，Wildcard 认证单测和 13 条 service-chain 集成测试通过。

> 2026-08-10 统计与透明入站复核：`make service-chain-smoke` 的 13 条真实 inbound→router→outbound 链全部通过；`make go-rust-stats-smoke` 验证 Go/Rust 共享 SQLite 上的真实流量、统计读取和跨进程接管，`make stats-concurrency-smoke` 验证并发统计读取、优雅重启和 force-stop 后恢复；node latency DNS 与 SOCKS5 UDP ASSOCIATE smoke 也通过。`make transparent-service-smoke` 已通过 IPv4/IPv6 REDIRECT TCP；rootless Podman 的 TPROXY UDP 仍不作为通过证据，显式 `YUHAIIN_TPROXY_ENABLED=1` 现在在启动容器前以 exit 77 明确提示需要 rootful/CAP_NET_ADMIN。新的 64 MiB release benchmark 为 HTTP CONNECT 116.14 MiB/s、peak RSS 17,516 KiB，TLS/H2/Yuubinsya 为 19.59 MiB/s、peak RSS 19,120 KiB；原始结果位于 `~/.cache/yuhaiin-rust/benchmarks/http-throughput`，本轮未使用 `/tmp`。

> 当前实现快照：可编译 workspace 已落地为 `yuhaiin-core`、`yuhaiin-chain`、`yuhaiin-trie`、`yuhaiin-store`、`yuhaiin-geo`、`yuhaiin-protocol`、`yuhaiin-platform` 和 `yuhaiin-runtime` 八个 crate。FakeIP 位于 `yuhaiin-store::fakeip`，MaxMindDB 位于独立的 `yuhaiin-geo`，协议 wire codec/可组合 transport 位于 `yuhaiin-protocol`，平台 FD/权限边界位于 `yuhaiin-platform`，TUN 位于 feature-gated 的 `yuhaiin-core::tun`；`yuhaiin-runtime::RuntimeSnapshot` 负责应用层组装和原子 reload，`yuhaiin-runtime::api` 提供与现有 `yuhaiin-react` client 对齐的管理面和 Rust-native pprof endpoint，`yuhaiin-runtime::run_tun_device_until` 负责已创建设备的数据面生命周期，`yuhaiin-runtime::inbound::run_until` 统一拥有 TUN、TCP/HTTP/WebSocket 和 UDP inbound 的启动、reload、shutdown 及 accepted-flow 生命周期，`src/bin/yuhaiin.rs` 只负责桌面 host/API/DNS wiring。HTTP 层复用 Go compatibility records，不新增一套配置 DTO，也不把平台权限细节泄漏到上层。

> 2026-08-10 Go/Rust publishes 与 update status parity：`publishes` 不再存于 Rust overlay，而是通过 `yuhaiin-store::ConfigRepository` 读写 Go 原生 `publishes(name, updated_at, data_json)` 表。API 只在 storage boundary 解码 Go Publish 的已知字段（`name/points/path/password/address/insecure`），未知 JSON 字段继续由存储层保留；resolve 与 Go 一致：不存在或 path/password 不匹配返回 `points: null`，匹配时返回空数组或现存节点列表，删除不存在的 publish 返回 404。`update.status` 初始 `stage` 也与 Go zero value 一致为空字符串。`go-api-parity.sh` 已加入 update.status 以及 publishes 的稳定读取和 put/resolve/delete 变更序列，三份停止的 Go 生产快照均已通过；日志位于 `~/.cache/yuhaiin-rust/production-parity`。

> 2026-08-10 central users schema/runtime integration：React 当前生成的 `users.*` 契约来自 Go `refact-user` 分支（本地 Go `main` 尚未包含这组 handler），Rust 已按该分支的 schema-v6 原生表实现 `users_v2`、`user_basic_v2`、`user_uuid_v2`、`user_token_v2` 及 migration reference 表。`ConfigRepository` 提供 create/update/delete、query/pagination、credential view 和 node/migration reference conflict；API 不再使用 Rust overlay。运行时构建代理快照时，节点 JSON 中的出站 `userId` 会解析为临时 basic/UUID/token 字段，原始 `nodes_v2.data_json` 只保留 `userId`，不会回写 secret。覆盖了 basic、UUID、token、HTTP/SOCKS5/Yuubinsya/VMess/VLESS/Tailscale 字段映射、缺失用户和禁用/错误 usage 的 fail-closed 单测；剩余是 HTTP/SOCKS5/Yuubinsya inbound 的中心用户认证，以及以 refact-user Go handler 运行的逐响应 parity，不应把该项误报为已完成的 Go main parity。

> 2026-08-10 inbound/proxy runtime 修复：`mixed`/`mix` 入站按 Go 语义继承 SOCKS5 UDP mode，不再因 `protocol_udp=false` 错误跳过 UDP listener；`DirectAsyncProxy` 的 TCP 与 UDP fallback，以及 TLS/HTTP2 等 blocking transport 使用的 `DirectConnector`，在直接收到域名 endpoint 时分别通过 Tokio/system resolver 解析，再连接/绑定 socket，避免 `direct async proxy requires an already-resolved IP endpoint`。现有测试覆盖低层 async/sync direct、真实 runtime direct node latency 和 mixed UDP supervisor。透明/SOCKS5/Yuubinsya/Trojan UDP flow 统一记录最后活动时间，按 Go 的 90 秒 `UDPIdleTimeout` 回收空闲 datagram，并有边界单测。`make transparent-service-smoke` 在 rootless Podman 中通过 REDIRECT TCP 并明确记录 TPROXY skip；强制 TPROXY gate 仍要求 rootful/宿主机 `CAP_NET_ADMIN`，不能把 rootless 下的规则命中误报成完整 UDP 验收。

> 2026-08-10 TUN host FD boundary：`yuhaiin_core::tun::TunRuntime::from_owned_fd` 新增安全的 Unix `OwnedFd` 接管入口，先校验共享 `TunConfig`，再把 FD 的唯一所有权转移给 `tun-rs::AsyncDevice`；`yuhaiin-runtime::inbound::run_until_with_tun_fd` 将它直接接入与 SOCKS5/HTTP/Yuubinsya/UDP 相同的 inbound owner、reload 和 shutdown 生命周期。Android `VpnService`、iOS `PacketTunnelProvider` 和 macOS utun host 不需要复制 router/proxy/dispatcher wiring；真实平台权限、route、功耗和设备生命周期仍保持 `[~]`，当前 Linux 无特权测试只验证非法配置在接管 FD 前 fail-closed。

> 2026-08-10 UDP flow teardown：透明、SOCKS5、Yuubinsya 和 Trojan 的每个 UDP flow 现在保存对应的 receiver `JoinHandle`；close request、idle reap、listener exit 都先 abort 并 await receiver，再关闭 outbound datagram。新增 receiver cancellation 单测，避免仅依赖 `AsyncDatagram::close()` 导致旧 receiver 持有 `Arc` 残留；这不改变 Go 的 90 秒 idle 语义，只收紧 Rust 的任务所有权和强制终止路径。

> 2026-08-10 transparent multi-flow acceptance：`transparent-service.sh` 的 rootless Podman REDIRECT TCP 场景现在在同一个 transparent inbound listener 上连续建立两条 TCP flow，分别校验 payload echo、累计 upload/download 统计和服务关闭；当前输出为 `flows=2 bytes=68 upload=68 download=68`。TPROXY UDP 仍按权限明确 skip；IPv6 REDIRECT 已由独立 strict gate 覆盖，rootful TPROXY gate 和异常 teardown 矩阵保留为后续验收。

> 2026-08-10 transparent IPv6 acceptance：`YUHAIIN_TRANSPARENT_IPV6=1 make transparent-service-smoke` 在隔离 Podman namespace 中为 service/client veth 配置 `nodad` IPv6 地址，真实执行 IPv4+IPv6 REDIRECT TCP 各两条 flow，覆盖 `IP6T_SO_ORIGINAL_DST`、direct outbound、payload 和统计；当前输出为 `flows=4 bytes=136 upload=136 download=136`。IPv6 默认 gate 仍关闭以兼容无 IPv6 kernel 的 CI，rootful TPROXY UDP 仍待宿主机 `CAP_NET_ADMIN`。

> 2026-08-10 HTTP/2 inbound chain acceptance：`service_chain.rs` 新增真实 runtime 进程的 prior-knowledge HTTP/2 inbound → route rule → fixed + HTTP CONNECT outbound 链路；客户端通过 H2 CONNECT 发送内层 HTTP CONNECT 和 payload，验证 HTTP proxy fixture 收到正确 domain authority、echo、connections inbound/protocol/outbound、累计 upload/download 以及服务关闭。完整 `service-chain-smoke` 现为 11 条场景，workspace 全量测试通过。

> 2026-08-10 TLS + HTTP/2 inbound acceptance：同一进程级矩阵新增 TLS ALPN `h2` → HTTP/2 inbound → route rule → fixed + HTTP CONNECT outbound，验证 TLS handshake、H2 CONNECT、内层 HTTP framing、proxy authority、connections metadata、payload echo 和 shutdown。

> 2026-08-10 connections socket/protocol metadata：对照 Go `statistics.getConnection`，共享 `FlowContext` 新增 socket-backed inbound 的 `local_addr` 与应用层 `protocol`；`InboundSpec` 统一注入监听 endpoint，并为 TLS transport 标记 `tls`，HTTP proxy 在消费 CONNECT/forward headers 后保留 `http`，共享 relay sniff 则按 TLS 优先、HTTP 次之填充协议。monitor 以 Go `net.Addr.String()` 的裸 `host:port` 格式输出 `localAddr`，由 endpoint network 填充 `network.underlyingType`，`connections.protocol` 不再错误复用 `tcp/udp`，未识别时为空。新增 monitor/common relay 单测和真实 HTTP inbound → outbound API 集成断言；TUN/无 socket 的 packet-only flow 仍保留平台可提供元数据的扩展边界。

> 2026-08-10 connections outbound endpoint：对照 Go `getConnection` 的 `getRemote(conn)`，`FlowContext` 新增 `outbound_addr`；selector 根据当前 route mode 记录实际出站 proxy socket endpoint，monitor 将 `connections.outbound` 输出为裸 `IP:port`，同时保留 `nodeId/nodeName` 作为配置节点身份。真实 direct、HTTP、SOCKS5、TLS/HTTP2/Yuubinsya、TCP/UDP service-chain 均新增 endpoint 断言，避免把节点 ID 与实际远端地址混用。

> 2026-08-10 Go schema-7 production takeover：真实 Go v6/v7-shaped state 可能保留 `metadata.schema_version=6`，但在 `migrate` 中记录新增的 `subscription_node_user_links=7`；Go 会正常打开，Rust 原先却因强制要求两个版本相等而拒绝启动。`yuhaiin-store::read_go_schema_version` 现在仅在已知 `subscription_nodes_v2`/`subscription_users_v2` 表存在时放行该增量形态，未知版本和任意其他不一致仍 fail-closed。新增回归，并用三份停止的生产快照重新通过 Go/Rust API 读、写和错误矩阵 parity；测试状态和临时副本均位于 `~/.cache/yuhaiin-rust`，未使用 `/tmp`。

> 2026-08-10 TUN 组合链路验收：新增 `make tun-chain-service-smoke`，在 privileged、`--network=none` 的 Podman 容器中用同一个 `inbound::run_until` 和 SQLite 配置验证真实 kernel TUN → `fixed` → RustCrypto TLS → HTTP/2 → Yuubinsya TCP → loopback echo。测试客户端写入后立即半关闭，修复并回归 HTTP/2 relay 只关闭请求方向、仍持续转发响应方向的语义；同时让 H2 server 等待 response bridge 排空，避免已回写的数据在 `serve_connect` 返回时被 abort。状态与日志统一放在 `~/.cache/yuhaiin-rust/integration/tun-chain-service`，不使用 `/tmp`。Android/macOS TUN fd/route/lifecycle 和 UDP 版 runtime chain 仍是独立验收项。

> 2026-08-10 多 inbound 组合验收：`service_chain.rs` 新增同一真实 runtime 进程中的 SOCKS5 inbound、Yuubinsya inbound → TLS → HTTP/2 → Yuubinsya outbound 测试。两条 inbound 都使用域名目标进入共享 router，验证 payload echo、`connections` 的 inbound/outbound/mode/matchHistory 和 node latency，避免只证明 HTTP inbound 能工作而遗漏其他实际入口。

> 2026-08-09 Go statistics takeover bridge：`yuhaiin-store` 新增 Go 统计表的 typed projection boundary。Rust 启动时在没有 `statistics.runtime` checkpoint 的情况下读取 `statistics_kv`、`traffic_hourly`、`connection_history`、`failed_connection_history` 以及 v6 telemetry dimension 表；`ConnectionMonitor` 的 history 按 Go 的 `(protocol, addr, process)` key 合并，并保留 `dumpProcessEnabled`、计数、最近时间和 JSON connection。正常 `shutdown()` 先写 Rust checkpoint，再在同一个 SQLite 写事务中替换 Go 兼容统计投影，使旧 Go 管理面可以继续看到最终 totals/traffic/history/telemetry。频繁写入仍使用紧凑 checkpoint，故 force-abort 后“checkpoint 可恢复”与“Go 统计表已更新”是两个明确边界，生产库版本矩阵和异常中断验证继续列在 checklist。

> 2026-08-10 Go telemetry daily-range parity：Go 的 `statistics.telemetryDimension` 对 `traffic_dimension_daily`/`failure_dimension_daily` 使用“bucket 与查询区间重叠”条件，而 Rust 之前只按 bucket 起点过滤，导致从非午夜开始的长范围漏掉前一天的 daily 数据。`GoTelemetryBucketRecord`、`ConnectionMonitor` 内存状态和 `statistics.runtime` checkpoint 现在保留 hourly/daily `span_seconds`；查询使用半开区间 overlap，实时流继续写 1 小时 bucket，旧 checkpoint 缺失该字段时按 hourly 兼容。新增跨日单测，并通过 `make go-rust-stats-smoke` 与 `make stats-concurrency-smoke`。

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

> 2026-08-10 Go v1 state.db 直接导入：旧 Go 数据库的 `nodes`、`inbounds`、`route_lists`、`node_tags` 表现在由 `yuhaiin-store::migration` 在同一 `BEGIN IMMEDIATE` 导入事务内幂等投影到 v2 contract。节点会把旧 oneof `protocols` 转成 `chain`，空链按 Go 行为补 `direct`，并恢复 `selected_tcp_node_v2`/`selected_udp_node_v2`；入站会把 `tcpudp/empty`、`transport` 和协议 oneof 转成 `network/transports/protocol`，其中 `tcp_udp_control_all` 明确转为 `udp=enabled`，因此旧 mixed 配置不会再丢 UDP；路由列表和标签也按 Go 的 `source`、`name/type/hash` contract 生成。原始 v1 表不删除，未知字段不参与猜测性转换，v2 已有数据时以 v2 为权威，四个 meta marker 防止重复导入。新增确定性 v1 fixture 和 `imports_real_go_v1_snapshot_without_touching_source` ignored 测试；后者已用 `/home/asutorufa/Documents/Programming/yuhaiin/tmp/state.db` 的只读副本通过，源库未修改。
> 2026-08-10 Go v1 runtime snapshot gate：在 store 行级导入测试之外，新增 `crates/yuhaiin-runtime/tests/legacy_v1_runtime.rs` 和 `make legacy-v1-runtime-smoke`。它复制旧 `state.db` 到 `~/.cache/yuhaiin-rust/integration/legacy-v1-runtime`，确认旧 mixed/TUN/Yuubinsya 三个 inbound、节点和代理链进入同一个 `RuntimeController`/`RuntimeSnapshot`，并在真实 `/home/asutorufa/Documents/Programming/yuhaiin/tmp/state.db` 副本上通过；测试不会修改源库，也不使用 `/tmp`。

> 2026-08-10 完整替换回归与 benchmark：重新执行 `make production-parity-smoke`，三份停止的 Go v5/v6 生产快照均通过管理 API 读/写/错误矩阵对照；`make service-chain-smoke` 的 11 条 inbound→router→outbound 链、`make api-contract-smoke` 的 3 条真实进程管理面用例、`make api-reload-flow-smoke`、`make tun-chain-service-smoke` 和 `make stats-concurrency-smoke`（并发读、优雅重启、force-stop 接管）均通过。当前 Podman release benchmark 结果为 HTTP CONNECT 135.01 MiB/s、TLS→HTTP/2→Yuubinsya 10.10 MiB/s、TUN→fixed 36.87 MiB/s；对应 peak RSS 分别为 17,096 KiB、72,912 KiB、12,456 KiB。原始日志和 JSON 结果位于 `~/.cache/yuhaiin-rust/{production-parity,integration,benchmarks}`，本轮仍未使用 `/tmp`。

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
> 2026-08-09 TUN 配置边界收口：Go 的 `inbounds_v2` 中 `network.type=empty`、`protocol.type=tun` 现在是 Rust TUN supervisor 的主配置源，按 Go `TunProtocol` 读取 `tun://` 名称、`portal`/`portalV6`、`routes`/`excludes`；旧 `tun.runtime` 仅作为没有 Go TUN inbound 时的兼容回退。普通 TCP/UDP listener 会跳过 TUN record，单设备 runtime 只对多个 enabled TUN fail-closed，禁用的默认/历史 TUN 定义不会阻塞唯一启用项。新增 Go inbound 配置解析回归，runtime 全部 118 个单测和 7 个 DoH 集成测试通过；此前 Podman 特权无网络容器中的真实 TUN 创建/关闭及 route smoke 仍通过。
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
- 所有平台 unsafe/FFI 只能集中在 `yuhaiin-platform`，上层不得直接操作 fd、ioctl 或平台路由命令。
- Linux 先覆盖 `/dev/net/tun`、netlink route、multi-queue、close-on-exec；Android 通过 VpnService/传入 fd；macOS 使用 utun；Windows 使用 Wintun 或传入已有 fd/handle。每个平台都要有 capability probe，缺能力时返回 Unsupported，不静默降级为普通 socket。当前 Linux probe 只读检查 `/dev/net/tun`、effective `CAP_NET_ADMIN`、route dump 和 tun driver 的 `multi_queue` 参数；不通过创建设备来探测，未知能力保持 `Unknown`。
- TUN portal、IPv4/IPv6 prefix、routes、MTU、gateway、DNS hijack、driver 和名称冲突处理写入 SQLite 配置，并在启动前做 prefix/MTU/route 校验。
- 设备创建成功后再设置地址和 route；任一 post-up 步骤失败必须按反向顺序清理设备和已安装 route。`TunRuntime::close_routes` 可重复调用，失败删除会继续保留 route lease 供显式重试；`Drop` 只做最后一次 best-effort cleanup，平台 app 必须优先调用显式 close 并记录错误。

#### TUN 测试

- 无权限环境测试 `TunDevice` builder 的配置校验、packet-info offset、MTU、名称冲突和 close 顺序，不要求真实设备。
- privileged CI 在 Linux 用 network namespace 创建临时 TUN，测试 tun-rs + smoltcp 的 IPv4/IPv6 TCP echo、UDP echo、DNS hijack、FakeIP、route block/direct/proxy 和回写。
- 单独测试 malformed IP header、短 TCP/UDP/ICMP、错误 checksum、fragment、超 MTU、未知 protocol、队列满和 reader close。当前 packet adapter 会分类 IPv4/IPv6 fragment；IPv4 交给 smoltcp bounded reassembly，IPv6 在 ingress 用 bounded reassembler 处理重叠、超时和乱序，ingress/egress 对每个 wire fragment 执行 MTU 边界检查。
- 用 deterministic clock 测试 smoltcp TCP retransmission、socket timer、UDP mapping timeout、NAT idle timeout 和 TUN shutdown；不要依赖真实 sleep 才能判定。
- TUN 与 Yuubinsya native UDP/UOT、SOCKS5 UDP、DoH endpoint、MaxMindDB domain lookup 做组合测试。

当前 Rust 实现已覆盖无权限的 UDP、TCP SYN/SYN-ACK、ICMP echo、IPv4/IPv6 fragment 分类与重组、重叠/超时丢弃、per-fragment MTU、超 MTU TX 丢弃和 TX queue backpressure 单元测试，并提供 `yuhaiin-core` 的 `tun-smoke` binary。Podman 特权 namespace 已验证设备创建、真实 IPv6 控制包过滤、IPv4 ICMP ingress、smoltcp ICMP socket 收包、真实 checksum 回包和 Linux kernel ping echo（0% loss）。

#### TUN 当前代码入口

- `yuhaiin_core::tun::TunRuntime::open` 是桌面最小设备入口，`TunRuntime::from_owned_fd` 是 Android/iOS `VpnService`/PacketTunnelProvider 和 macOS utun host 的安全 Unix FD 接管入口，`TunRuntime::from_async_device` 仍适用于宿主已经完成 `tun-rs` 包装的场景，`open_with_routes` 是需要系统路由时的事务式启动入口；`yuhaiin-runtime::load_tun_config` 只读取共享配置，`inbound::run_until_with_tun_fd`/`run_until_with_tun_runtime` 将外部设备接入同一个 inbound owner，统一组装 DNS handler、snapshot selector、Full Cone NAT、dispatcher 和 reload/shutdown 生命周期。这样平台 host 只负责 fd/JNI/driver 权限，不需要复制 Go/TUN 上层 wiring。`TunRuntime::name()` 返回内核最终确认的接口名或外部设备配置名，`TunRuntime::shutdown` 提供显式的 route-before-fd-drop 关闭边界；不并行实现 tun2socket 或用户态第二套 IP stack。`open_with_routes` 的 route 配置失败会回收已创建设备并允许同名恢复；`tun-smoke` 的 `YUHAIIN_TUN_ROUTE_SMOKE=1` 会安装纯 Rust netlink route，便于在隔离 namespace 验收 shutdown、SIGKILL 和 route/device 清理；多进程验收还确认同名 TUN 不能被第二个 owner 抢占，首个 owner 终止后可重新启动。
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

UDP framing 遵循当前 Go `PacketConn` 的实际边界：request 后直接读取
`uint16 length + payload`，不发送或等待 TCP 用的 two-byte response header；TCP 仍然严格校验
VLESS response version/addon。该边界由 `go_vless_udp_interop` 在 Podman 中以真实 Go
`fixedv2 -> vless.PacketConn` client → Rust wire server 验证，避免把 `[0,0]` response header
误当成一个空 UDP datagram。

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
React operation inventory：88 个 operation 已按真实传输逐项检查，其中 87 个 JSON-RPC
operation 逐个发空 JSON 请求并断言不能返回 404，`connections.events`、`tools/logs` 和
`tools/logs/v2` 的直接 GET/SSE 路由另外断言
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
配置边界，执行 HTTP inbound → route rule → outbound 协议矩阵的单流 loopback
echo，并在 runtime 子进程上采样 Linux `VmRSS` 与 `/proc/<pid>/stat` CPU ticks。
输出固定的 `BENCHMARK` JSON 行，构建产物、状态库和日志均放在
`~/.cache/yuhaiin-rust/benchmarks/http-throughput`，没有使用 `/tmp`。

当前 benchmark 矩阵：

| 场景 | 状态 | 说明 |
| --- | --- | --- |
| HTTP inbound → router → HTTP CONNECT outbound | 已有可执行基准 | `make benchmark-throughput`；默认 64 MiB、单流、loopback |
| HTTP inbound → router → TLS → HTTP/2 → Yuubinsya TCP-over-stream outbound | 已有可执行基准 | 同一命令运行协议矩阵；真实 SQLite/API 配置、TLS、H2 和 Yuubinsya loopback echo |
| TUN inbound | 已有可执行 packet 基准 | `make benchmark-tun-throughput`；默认 4 MiB、单流、privileged Podman、TUN → smoltcp → fixed proxy → loopback echo；16/64/256 MiB 长流已通过 |
| WireGuard | 已有可执行协议/adapter smoke 和 packet benchmark | `make wireguard-smoke`、`make benchmark-wireguard-throughput`；当前只记录两端 userspace peer 与本地 packet path，不把 5/5 单测或约 575 MiB/s 基线伪装成第三方 peer 或公网带宽结论 |

benchmark 数值只能用于同机、同 profile、同 payload 和同 namespace 的回归比较，不能
直接解释为 Go 与 Rust 的跨机器性能结论。

本机最近基线（2026-08-10，release、Podman host network、64 MiB、单流）：

```text
BENCHMARK {"bytes":67108864,"cpu_ticks":36,"elapsed_ms":437.95469199999997,"mib_per_sec":146.1338379724449,"peak_rss_kib":16660,"proc_samples":21,"runtime_pid":8,"scenario":"http-inbound-route-http-connect-loopback","target":"loopback; one stream; debug/release selected by runner"}
```

同一轮协议矩阵中的 TLS/H2/Yuubinsya 结果为：

```text
BENCHMARK {"bytes":67108864,"cpu_ticks":188,"elapsed_ms":2758.042342,"mib_per_sec":23.204864923716244,"peak_rss_kib":75400,"proc_samples":131,"runtime_pid":18,"scenario":"http-inbound-route-tls-h2-yuubinsya-loopback","target":"loopback; one stream; release; TLS + HTTP/2 + Yuubinsya"}
```

这组历史结果使用的是 h2 自身的 pending send queue；调用方虽然只提交固定 16 KiB
relay frame，但当窗口耗尽时仍可能在 h2 内部排队，因此不能把它当作严格的
producer-side bounded backpressure 基线。后续的 bounded adapter 修复和新基线见 §84。

该数值是当前机器和当前构建的基线，不是验收阈值；后续改动应在相同参数下重复运行并
记录变化原因。

本机 TUN packet 基线（2026-08-10，release、privileged Podman、4 MiB、单流，实际
`tun-rs + smoltcp + fixed proxy + loopback echo`）：

```text
BENCHMARK {"scenario":"tun-inbound-fixed-proxy-loopback","bytes":4194304,"elapsed_ms":71.190321,"mib_per_sec":56.18741345470264,"peak_rss_kib":12440,"cpu_ticks":12,"proc_samples":2041}
```

该 TUN runner 采用 4 MiB smoltcp TCP RX/TX buffer、有界 proxy channel，以及每次
smoltcp poll 最多派发 64 KiB TCP 数据；同时在线程内 runtime loop 主动让出一次执行权，
避免 current-thread Tokio 在 TUN RX 持续 ready 时饿死新建 proxy task。修复后 16/64/256
MiB 长流均在本机通过，结果只能用于同机、同 profile、同 payload 和同 namespace 的回归
比较，不能直接解释为 Go 与 Rust 的跨机器性能结论。

## 58. 2026-08-10 TUN bounded backpressure and long-stream regression

之前的 TUN throughput fixture 使用很大的 proxy channel 来掩盖调度问题：current-thread
Tokio 在 TUN RX 持续 ready 时可能一直处理上传事件，新建的 direct/fixed proxy task 得不到
执行机会；channel 降到正常有界值后会暴露 `no available capacity`，说明不是单纯增大内存
可以解决的问题。

本轮修复了两个数据面边界：`TunDispatcher::collect_events` 每个 flow 每次 poll 最多
派发 64 KiB TCP 数据，剩余数据留在 smoltcp socket 的接收缓冲区；完整 TUN dispatcher
loop 每轮主动 `yield_now()`，保证 proxy task 能消费 command queue 和产生回包。基准 channel
从 `64*1024` 降为 256，仍保持有界内存。

Podman privileged/network=none、release、同一 loopback echo fixture 的实测结果：

```text
4 MiB:   71.190321 ms, 56.1874 MiB/s, peak RSS 12440 KiB
16 MiB:  312.345178 ms, 51.2254 MiB/s, peak RSS 12400 KiB
64 MiB:  1045.700406 ms, 61.2030 MiB/s, peak RSS 12428 KiB
256 MiB: 4040.536757 ms, 63.3579 MiB/s, peak RSS 12328 KiB
```

这证明当前 Linux TUN inbound 的长流背压不再依赖无界积压；Android/macOS 设备和真实
透明网络路径仍按 checklist 的平台状态单独验收。

## 59. 2026-08-10 runtime-owned TUN routed proxy smoke

运行时 TUN smoke 现在不再只验证设备创建/关闭，而是启动真实 runtime inbound，创建
`198.18.0.2:18080` 的内核 TCP 流，经过 route fallback=proxy、选中的 fixed outbound，
再回到同一 Podman 容器内的 loopback echo server。fixture 显式安装
`198.18.0.2/32`，日志与 SQLite 状态仍只保存在
`~/.cache/yuhaiin-rust/integration/tun-service`，不使用 `/tmp`。

为支持真实 TUN 的任意 routed destination，smoltcp interface 启用 AnyIP，TCP dispatcher
使用 wildcard listener；flow key 仍保留原始目标 endpoint，因此 direct/fixed/后续协议链
可以按目标地址路由。没有 route rule 时 runtime 的生产 fallback 仍是 direct，smoke 通过
明确的 `RuntimeBuildOptions.route_fallback=proxy` 验证“配置的 selected outbound”而不是
依赖隐式默认值。

新增回归单测覆盖 AnyIP 下非本地 interface 地址的 TCP SYN；
`scripts/integration/tun-service.sh` 现在把 Podman 输出写到 cache 中，即使命令失败也会
直接打印日志。实际结果：

```text
test tun::tun_unit_tests::tcp_listener_accepts_routed_destination_with_any_ip ... ok
runtime-tun-opened name=yrtun0
runtime-tun-traffic-ok
runtime-tun-closed name=yrtun0
```

## 60. 2026-08-10 Go/Rust production API projection parity

使用已停止且一致的 schema-7 Go `state.db` 副本，在
`~/.cache/yuhaiin-rust/integration/go-api-parity-20260810` 分别启动 Go 与 Rust；源库没有
被写入，也没有使用 `/tmp`。新增 `scripts/integration/go-api-parity.sh` 和
`make go-api-parity-smoke`，Go/Rust 各自使用独立副本，比较前端真实请求体（列表使用
`page_size`）的 `settings.get`、`nodes.get`、`resolvers.get`、`inbounds.get` 和
`connections.total`，列表只按 `id` 规范化顺序。

首次对照发现 Rust 的兼容 JSON 公开投影把协议层内部的 `userId` 返回给了前端；Go 的
公开 `contract.node.Node` 不返回该字段。Rust 现在只在 `node_json` HTTP 投影边界递归
移除 `userId`，SQLite 中的原始 JSON 不变，因此 runtime 仍能使用并由未来 Go 读回。
修复后 206 个生产节点、6 个 resolver、10 个 inbound、settings 和 totals 对照全部
`identical`。该测试同时覆盖了 Rust 前台启动日志和 Go/Rust 独立状态目录约束。

## 61. 2026-08-10 Go telemetry dimension projection

Rust 的连接和流量数据面此前会为缺失字段写入 `unknown` telemetry 维度，并直接使用
`source`、FakeIP 地址和原始 route metadata；这与 Go
`statistics.dimensionsForConnection` 的非空过滤、`inboundName`/`nodeName` 优先级、
FakeIP 地址回退、destination 忽略和最后一个非空 rule 语义不同。

`ConnectionMonitor` 现在从公开 connection contract 统一生成 telemetry dimensions：
source 支持 IPv4/IPv6、端口和 Go HTTP/2 `http2.h-*` 形式的归一化；FakeIP 目标优先使用
domain/hosts 作为 `addr`，并不写入 `destination`；旧 Rust checkpoint 恢复时也会归一化
source。failure telemetry 复用同一维度构造，避免正常流量和失败流量产生两套 key。

验证结果：monitor 相关 23 个单测通过，真实 `service_chain` 7 个测试通过，统计并发读者、
流量更新、停止和 SQLite 重启读回测试通过。此次只使用项目 cache-owned target 和测试目录，
没有使用 `/tmp`。

## 62. 2026-08-10 Go/Rust management API expanded parity

在 §60 的生产 schema-7 对照基础上，`scripts/integration/go-api-parity.sh` 现在先把源库复制到
`~/.cache/yuhaiin-rust/integration/.../prepared`，由一次临时 Rust takeover 创建缺失的 Go v6
telemetry 表，再给 Go/Rust 各自独立副本。这样不会修改源库，也不会把旧 Go v5 telemetry 表的
缺失误报成 HTTP API 差异。

本轮逐项通过了 26 个稳定管理面响应：info、settings、nodes、resolvers、inbounds、connections
及 total/traffic/telemetry/failed-history/history、hosts/FakeDNS/server、route activation/config/
lists/rules/tags，以及 interfaces/licenses。对照中修复了几项真实兼容差异：

- telemetry 公共返回始终保留 Go 规定的 9 个维度和顺序，空维度返回空 `items`；内部写入仍只保留非空 dimension。
- failed/all history 按 Go 的 1000 条上限返回；history 使用本地时区 RFC3339，traffic bucket 继续使用 UTC。
- FakeDNS 从 `dns_fakedns_lists` 按 Go 的 rowid 插入顺序恢复 `whitelist`/`skipCheckList`。
- route list 的 local preview 保留配置数组第一项。remote list 的 itemCount/errorCount/preview 依赖 Go 的 Pebble
  网络缓存或 Rust 的 `~/.cache/yuhaiin-rust/rules`，脚本只比较其稳定 control-plane 字段；licenses 是构建依赖清单，
  interfaces 只规范化宿主机枚举顺序，SSE `tools.logs` 由已有流式测试覆盖。

本轮 workspace 未使用 `/tmp`；对照日志和副本均位于 `~/.cache/yuhaiin-rust`。

## 63. 2026-08-10 TLS inbound process chain

此前 runtime 已有 TLS termination 实现，但服务级测试主要验证 TLS 作为 outbound
transport；fixture 中的证书/私钥也没有覆盖 inbound listener。现在新增可复用的
`configure_tls_http_inbound` fixture：通过前端保持不变的 Go-shaped JSON 配置
`TLS transport → HTTP protocol`，由真实 runtime inbound owner 接收连接，使用
RustCrypto TLS server 解密，再按共享 `FlowContext → selector → direct outbound`
连接 loopback echo。

`tests/service_chain.rs` 新增
`tls_http_inbound_terminates_tls_and_routes_through_direct_outbound`，使用真实 TLS
client、CONNECT 握手、payload echo 和 connections metadata 断言；
`make service-chain-smoke` / `scripts/integration/service-chain.sh` 可重复运行整组
service-chain 测试，状态、日志和构建产物继续放在 `~/.cache/yuhaiin-rust`，不使用
`/tmp`。本次定向测试通过，TLS inbound 的功能条目不再只是静态代码存在，而有真实
子进程数据面证据。

## 64. 2026-08-10 Go/Rust management mutation parity

在 §62 的生产只读 projection 对照上，`scripts/integration/go-api-parity.sh` 增加了基于前端
RPC 边界的变更矩阵。Go 与 Rust 仍使用同一停止快照的两个独立副本；每次运行生成带
`BASHPID` 后缀的临时节点、resolver、inbound、route list、route rule 和 tag，按
create → get → update/use/apply → delete 顺序清理，不改源库。默认状态目录是
`~/.cache/yuhaiin-rust/integration/go-api-parity`，不使用 `/tmp`。

严格逐响应通过的变更包括：

- node create/get/put/use/selected/close/delete；
- inbound create/get/put/delete；
- resolver create/get/put/delete；
- route list 的 create/get/delete、route rule 的 create/get/delete、route tag 的 put/get/delete，以及 `route.apply`。

本轮对照暴露并修复了三个契约边界：Go 手动节点允许空 `group`，Rust 不再把它公开改写成
`default`；Go 的 route rule detail 不公开 Rust 路由编译使用的内部 `match` 字段；route
rule test 的 `afterAddr` 使用 Go 的 authority 形式（例如 `example.com:443`），不带 Rust
内部的 `tcp://` 前缀。对应的 API 单测和真实 Go/Rust 双进程 parity 均通过。

随后又把 `route.rules.test` 纳入严格逐响应矩阵：Rust 现在保留 Go 的按规则分组
`matchResult`，包含未选中规则的 list history、`List ...`/`Port ...`/`Net ...`/`Geoip ...`
诊断项，并从同一 runtime snapshot 的选中 resolver 查询 `ips`。生产 schema-7 副本上的
route rule create → apply → test → delete 对照已通过；后续仍需扩展到 process/inbound/negative
matcher 的真实历史样本，不能把当前单一诊断样本当作所有复杂表达式已逐字段等价。

## 65. 2026-08-10 Go/Rust frontend configuration mutation parity

在 §64 的资源 CRUD mutation 矩阵上继续补齐前端配置写入边界。`scripts/integration/go-api-parity.sh`
现在对 Go 与 Rust 的独立 SQLite 副本逐项执行 settings、backup config、inbound config、hosts、
FakeDNS、resolver server、route config 和 route list config 的 put → get；请求体仍使用 React
现有 contract 的 camelCase 字段，比较保留 Go 行为所需的响应字段，并在失败时保留原始 HTTP body。

本轮 parity 实际发现并修复两个兼容 bug：

- Go 的 `route_settings` 表是单行表，并有 `CHECK (id = 1)`；Rust API 原先写入 `id=0`，在接管
  Go snapshot 后会得到 HTTP 500。现在统一写入 canonical row `id=1`，并新增 repository/API 单测。
- Go `Lists.SaveContractConfig` 不接受客户端覆盖运行时维护的 `lastRefreshTime`，保存时清空顶层
  error；只有 MaxMindDB 下载 URL 变化时才清空已有 GeoIP error。Rust 现在先读当前
  `settings_kv.route_extra`，复用同样的保留/清理规则，并有同 URL、换 URL 的回归测试。

最终对照使用真实停止的 Go schema-7 state snapshot，日志和运行副本位于
`~/.cache/yuhaiin-rust/integration/go-api-route-test-final5`，没有修改源库，也没有使用 `/tmp`；
settings/backup/inbound config/hosts/FakeDNS/server/route config/list config 以及此前的核心资源
mutation，以及 route rule test 全量 history 对照全部通过；复杂 matcher 的更多真实样本仍按
上段列为后续验收项。

## 66. 2026-08-10 Go route-list membership in live flow metadata

Rust 之前在 `Router::apply_to_context` 中把 `FlowContext.lists` 设置为选中规则的
`list_names`。这会让真实 connection metadata 丢失“命中了但没有选择该规则”的 host/process
list；Go 则在 route matcher 运行前调用 host trie 和 process trie，把所有命中的 list 写入
`ConnOptions.Lists()`，随后每个 route rule 只在自己的 match history 中记录诊断结果。

现在 `RouteListSnapshot` 保存规范化 list kind、host/CIDR trie 和 process values，新增
`matching_names(&FlowContext)`；`RuntimeSnapshot::apply_route` 在同一 immutable snapshot
边界先计算全量 membership，并在交给 router 前放入 `FlowContext`，再选择 mode/tag/resolver。
`yuhaiin-trie::Router` 不再用选中规则覆盖这个 membership，同时保留展开后的 priority 顺序，在连接 metadata 中记录选中前已尝试的规则以及
`List ...`/`Net ...`/`Port ...`/`Geoip ...` matcher history，而不是只记录最终规则。这样
TUN、socket inbound、`route.rules.test` 和 connections/telemetry 共用同一 list 结果，不新增
DTO，也不改变现有前端 contract。

验证结果：route-list host/CIDR/process membership 单测、Router rejected-rule/process-gated history 单测、route API 单测、完整 11 条
`service_chain` 数据面测试，以及 Go/Rust 26 个只读响应和 mutation/config parity 全部通过。
对照日志保存在 `~/.cache/yuhaiin-rust/integration/go-api-route-history-final11`，没有使用
`/tmp`；复杂 matcher 的逐项 match history 仍单独列为后续工作。

## 67. 2026-08-10 Go/Rust management error parity

在 §65/§66 的成功响应和 mutation 对照上，`scripts/integration/go-api-parity.sh` 新增了非变更
错误矩阵，并在 `~/.cache/yuhaiin-rust/integration/go-api-error-matrix-7` 使用停止的 Go
schema-7 snapshot 完成 Go/Rust 双进程对照。矩阵严格比较 HTTP status 和 JSON RPC error code；
Go 解码器会把具体 request type 写入校验消息，因此只对这类实现相关 message 做占位归一化，
同时为每个 case 保留 raw body，避免把诊断信息隐藏掉。

本轮先后修复了两个真实请求语义差异：`node.get`、`inbound.get`、`resolver.get`、
`route.list.get`、`route.rule.get` 等 Go typed request 的缺失/`null` 字段要使用零值并让存储层
返回 404，而不是由 Rust API 提前返回 400；`connections.close` 缺失或 `null` 的 `ids` 是
空 slice，Go 将其作为成功空操作，Rust 现在保持相同语义，非法 ID 仍严格返回 400。新增单测
覆盖字符串/数字字段的缺失、`null`、正确类型和错误类型。

最终矩阵覆盖非对象请求、缺失/不存在资源、统计时间范围、telemetry limit、空/非法连接关闭、
route test/priority、backup restore 和 deferred subscription update；同一运行还通过了此前的
26 个只读响应、核心资源 mutation/config 闭环和 route rule test 对照。unknown RPC operation
没有放进业务错误矩阵：Go 的 ServeMux 对动态未知路径返回 plain-text 405，而 Rust 的通用 RPC
handler 返回 JSON 404，这是框架路径表面的差异，不是 generated frontend operation；已保留为
后续专门的 HTTP surface 兼容项。

本轮只使用 `~/.cache/yuhaiin-rust` 保存副本、日志和构建缓存，不使用 `/tmp`。管理 API 仍为
`[~]`，剩余项是完整 response 字段、复杂 matcher history 和更多 production snapshot，不能
因为错误矩阵通过就把整个 API 或 Rust 重写标成完成。

## 68. 2026-08-10 production parity, statistics and data-plane recheck

在 §67 的错误矩阵之后，本轮没有修改生产源库，而是用相同的停止快照和可复用 Podman 测试
重新验证当前替换路径：`production-parity.sh` 对 Go 的 `tmp/v2/state.db`、`tmp/yuhaiin/state.db`
和 `tmp/aws/yuhaiin/state.db` 三份副本全部通过。每份都完成 26 个稳定只读响应、核心资源
mutation/config 闭环、route rule test、错误 status/code 矩阵和空/非法 connections close；日志、
Go/Rust 副本位于 `~/.cache/yuhaiin-rust/production-parity-current`。

`stats-concurrency.sh` 通过了真实 runtime 进程在流量更新期间的并发统计读取、停止、同库重启
和 traffic/history 读回；`transparent-service.sh` 在 rootless Podman 中通过 REDIRECT TCP
原目标恢复、非 root client、双向计数和 shutdown。TPROXY UDP 按环境实际记录为 skip，因为
rootless user namespace 没有宿主机 `CAP_NET_ADMIN`；要完成该项仍需 rootful Podman 或宿主机
network namespace 的策略路由验收。

数据面和可观测性也重新验收：foreground binary 的启动日志默认输出 database、HTTP bind、
ready 和 stopped；runtime-owned TUN 的开关、流量和关闭通过；HTTP inbound → router → HTTP
CONNECT loopback benchmark 为 64 MiB、145.58 MiB/s、peak RSS 17,004 KiB；单路径 TUN
inbound → fixed → loopback benchmark 为 4 MiB、55.73 MiB/s、peak RSS 12,444 KiB。原始日志和
结果分别位于 `~/.cache/yuhaiin-rust/integration/{production-parity-current,
stats-concurrency,startup-logs-current,transparent-service-current,tun-service-current}` 和
`~/.cache/yuhaiin-rust/benchmarks/{http-throughput-current,tun-throughput-current}`。

本轮缓存复核约为 15G，其中主要是可复用的 `cargo-target` 和历史副本；所有临时副本仍在
`~/.cache/yuhaiin-rust`，没有使用 `/tmp`。这轮证据强化了 Linux 主路径，但没有改变 checklist
中 Android/macOS 实机、rootful TPROXY、长时间 production telemetry 和发布回滚等 `[~]` 状态。

## 69. 2026-08-10 runtime-owned TUN MTU boundary matrix

此前 runtime-owned TUN 的进程级 smoke 固定使用 MTU 1500，只能证明默认配置下的设备和
数据面闭环。现在 `crates/yuhaiin-runtime/src/bin/tun_service_smoke.rs` 读取
`YUHAIIN_TUN_MTU`，并与 `TunConfig` 相同地限制在 576–9216；`scripts/integration/tun-service.sh`
也支持通过该变量复用单个用例。新增 `scripts/integration/tun-mtu.sh` 使用每个 MTU 独立的
设备名和 SQLite 状态，在 privileged `network=none` Podman 中启动真实 runtime inbound，检查
设备出现、固定 outbound 回环流量和 shutdown 后设备消失。

本机验证通过以下五个边界/常用值：

```text
576, 1280, 1500, 9000, 9216
```

每个用例均输出 `runtime-tun-opened`、`runtime-tun-traffic-ok` 和 `runtime-tun-closed`；可复用
日志和数据库位于 `~/.cache/yuhaiin-rust/integration/tun-mtu-current`。这补齐了 Linux TUN
MTU 的进程级边界证据，但不把 namespace teardown、fragment 长流或 Android/macOS 设备验收
提前标为完成。当前缓存复核为约 16G，仍全部位于 `~/.cache/yuhaiin-rust`，没有使用 `/tmp`。

## 70. 2026-08-10 mixed UDP、direct 域名解析与 route history parity

本轮复核了运行日志中的两个错误：`protocol "mixed" has no UDP mode` 和
`direct async proxy requires an already-resolved IP endpoint`。它们对应 `0bae7c1` 之前的旧
二进制；当前源码已统一 trim/大小写处理 `mixed`/`mix`，mixed 默认支持 SOCKS5 UDP，且
`DirectAsyncProxy` 会在没有 runtime resolver wrapper 时使用 Tokio resolver，并按 source
interface 偏好 IPv4/IPv6 后逐个尝试连接。当前构建产物中已不存在旧的 direct error 文案。

定向证据：

- `cargo test -p yuhaiin-core --all-features --offline direct_async_proxy_resolves_domain_when_called_without_runtime_wrapper` 通过；
- `cargo test -p yuhaiin-runtime --all-features --offline mixed_inbound_exposes_socks5_udp_and_keeps_supervisor_alive` 通过；
- `make build` 成功，debug binary 位于 `~/.cache/yuhaiin-rust/cargo-target/debug/yuhaiin`。

同时修复了上一轮 route test parity 暴露的真实差异：Go 无规则命中时 `Matchers.Match` 返回
`ProxyMode`，Rust 默认 fallback 改为 `proxy`；route history 现在按 Go nested matcher 的
排序和短路规则记录，expanded variants 不重复吞掉同一 Go list，缺失 list 以 fail-closed
rule 保留其 `List ...: false` history。使用停止的 `tmp/v2/state.db` 独立副本运行
`go-api-parity.sh`，包括 nested `all(host-list, port)`、缺失 list、route rule test、配置
mutation 和错误矩阵，Go/Rust 全部逐响应通过；日志位于
`~/.cache/yuhaiin-rust/integration/go-api-route-history-current3`。源库没有修改，也没有使用
`/tmp`。

## 71. 2026-08-10 nested route all matcher parity

Go 的 route expression 支持在 `all` 中组合多个正向 host/CIDR matcher；此前 Rust
compiler 只能保留一个 `pattern`，遇到两个正向域名/CIDR 条件会返回 unsupported，或者
如果绕过校验会错误地把它们当成 OR。现在 `yuhaiin-trie::RouteRule` 保留一个主候选
pattern，并为其余正向条件编译独立 `CombinedTrie`；候选必须同时命中所有 trie，仍由
同一优先级和 immutable router snapshot 选择出口。不同列表的 expression 顺序也不再被
字典序重排，因此 `route.rules.test` 的 `List ...` history 与 Go 的短路顺序一致。

新增真实进程测试 `route_rule_test_reports_nested_all_match_history`：通过管理 API 写入
两个本地 host list 和一个 `all(host-list, host-list)` drop rule，分别验证共同命中、父
列表单独命中时的 fallback，以及 `matchResult` 中两个 list 的 true/false history。Rust
route unit test 和 API contract test 均通过；功能仍保持 API `[~]`，剩余是更多
process/inbound/negative matcher fixture、完整 response 字段和生产 snapshot parity。

## 72. 2026-08-10 statistics force-stop takeover

统计并发测试现在覆盖两个真实 runtime 子进程生命周期：原有的流量更新期间六类统计 API
并发读取、优雅停止和同库重启，以及新增的 `force_stop_during_stats_reads_reopens_same_database`。
后者在真实 HTTP inbound 流量和 `connections.total` 读取同时进行时直接终止 runtime，随后
立即用同一个 SQLite 文件启动新进程，验证 `connections.total` 的 upload/download 字段仍
保持合法、live connections 不会从上一个进程泄漏，history API 仍可读。测试使用真实
`Child::kill`，不调用 shutdown persistence path，因此覆盖 WAL/sidecar 重开而不是只验证
优雅关闭。

`scripts/integration/stats-concurrency.sh` 已改为在 Podman 中执行该测试文件的全部用例，
本轮本机和 Podman 均为 2/2 通过，日志位于
`~/.cache/yuhaiin-rust/integration/stats-concurrency`。这加强了 connections/统计的进程级
接管证据，但该模块仍保持 `[~]`：长期 production telemetry 的逐字段 Go/Rust 对照，以及
升级期间的 SQLite 锁竞争/退避观测仍未完成。当前缓存约 18G，主要是 `cargo-target` 12G、
integration 3.1G、api-parity 1.2G 和 production parity 副本；本轮未使用 `/tmp`，也没有
删除可复用证据。

## 73. 2026-08-10 TUN runtime long-stream content integrity

runtime-owned TUN smoke 原先只发送几十字节固定字符串，无法发现 TCP 回写的中间字节丢失；
本轮将 `YUHAIIN_TUN_TRAFFIC_BYTES` 接入同一个 SQLite/runtime fixture，客户端用独立 writer
线程分块上传、同时读取回显，并按绝对 offset 生成确定性 payload 逐字节校验。默认新增的
`make tun-long-service-smoke` 使用 1 MiB，避免把普通 debug smoke 变成长时间吞吐基准；需要
更大流量时可显式设置 `YUHAIIN_TUN_TRAFFIC_BYTES`，上限为 512 MiB。

该回归第一次在第 110,796 字节发现真实数据错位。原因是 smoltcp `tcp::Socket::send_slice`
在 bounded TX buffer 不足时会返回 `Ok(partial_bytes)`；Rust runtime 之前只判断 `Err`，把
短写误当成整包成功，直接丢弃 payload 尾部。现在 `TunProxyRuntime::poll_outputs` 在 pending
队列的两个路径都保留 `payload[written..]`，下一个 poll 继续写；`TunDispatcher::write_tcp`
也明确记录了 short-write contract。

修复后的 privileged `network=none` Podman 结果：

```text
make tun-long-service-smoke
runtime-tun-traffic-ok bytes=1048576
runtime-tun-closed name=yrtun0

YUHAIIN_TUN_TRAFFIC_BYTES=1048576 make tun-chain-service-smoke
runtime-tun-chain-ready mode=tls-h2-yuubinsya
runtime-tun-traffic-ok bytes=1048576
runtime-tun-closed name=yrtun0
```

因此当前 runtime-owned Linux TUN 的长流/代理链内容完整性已纳入替换 gate；这不等价于
已经完成 wire fragment 重组、独立 namespace teardown 矩阵或 Android/macOS 实机验收，后三项
继续保留在 checklist 的 `[~]`。

## 74. 2026-08-10 central users runtime resolution and production parity

本轮把 React generated `users.*` 对应的 Go `refact-user` schema-v6 契约接入 Rust 原生 store/API：
`users_v2` 负责用户元数据，`user_basic_v2`、`user_uuid_v2`、`user_token_v2` 分别保存三种
credential，migration source/dedup 表用于阻止删除仍被迁移映射引用的用户。API 层支持 Go
形状的 create/update/delete、query/pagination、credential view 和 node/migration reference
冲突；更新时省略 credential 会保留旧凭据。

运行时不修改 API-facing 的 `nodes_v2.data_json`。构建代理 snapshot 前，store 在内存克隆中
按 `userId` 注入 basic 的 `user/password`、VMess/VLESS 的 UUID、Yuubinsya/Shadowsocks/
ShadowsocksR/Trojan/AEAD 的 password 和 Tailscale token。缺少用户、disabled 用户、usage
不含 outbound 或 credential 类型不匹配都会 fail-closed。SSR 的 `protocol` 字段是内部认证
算法而不是代理层类型；第一次生产启动暴露该优先级错误后，改为优先继承外层 chain `type`，
并加入 SSR 回归，避免真实旧节点被错误判为 unsupported。

验证结果：users/store 定向测试通过，workspace `cargo test --workspace --all-features --offline`
通过；`make production-parity-smoke` 对 `tmp/v2/state.db`、`tmp/yuhaiin/state.db`、
`tmp/aws/yuhaiin/state.db` 三份停止快照逐响应通过，日志在
`~/.cache/yuhaiin-rust/production-parity`；`make build` 成功，产物在
`~/.cache/yuhaiin-rust/cargo-target/debug/yuhaiin`。本轮后 inbound 中心认证已覆盖
HTTP/SOCKS5/mixed，以及 concrete password 的 Yuubinsya TCP/UOT、Trojan 请求头和 AEAD
TCP transport；native Yuubinsya UDP 已补多密码，refact-user Go handler 逐响应 parity 和更广
的 inbound 负向矩阵仍未完成，故本项继续保持部分完成。

## 75. 2026-08-10 inbound central authentication and bounded multi-password handshakes

`yuhaiin-runtime::inbound::InboundAuth` 在 listener reload 时从 `users_v2` 创建不可变内存快照，
只保留 enabled 且 usage 为 `inbound`/`both` 的 basic 用户。HTTP Proxy 和 SOCKS5（因此也包括
mixed）在有可用中心 basic 用户时忽略旧 inbound JSON 中的 inline credential，并用 constant-time
字段比较校验中心用户名/密码；没有相关中心能力时仍保留旧 inline 行为。wildcard username/password
遵守 Go `allowAny*` 语义，但 wildcard password 不会被拿去派生密码 hash。

密码 hash 协议不再为了支持多个用户而复制 listener：Yuubinsya 的首个 header 在多个 hash 中选出
匹配项，后续 TCP/UOT session 沿用选中的 hash；Trojan request header 和 Go AEAD TCP transport
也支持 bounded password set。旧的单密码 public API 继续调用同一套路径。native Yuubinsya UDP
datagram 随后也扩展为 bounded password set；接收时返回命中的 hash，runtime 将认证身份纳入
UDP flow key，异步回包沿用同一 hash，避免同一 peer/target 下不同用户互相串包。AEAD 外层 UDP
仍是单密码设计，暂不声称支持中心多密码。

新增/通过的测试包括：InboundAuth 的 enabled/usage、wildcard、constant-time 和 concrete
password 规则；HTTP central user allow/reject；Yuubinsya `decode_header_any` 与
`decode_udp_packet_any`；native UDP server 的多密码接收/命中 hash 回包；Trojan 多 hash；
AEAD server 多 password。core/runtime 定向单元测试分别通过 129/213 项，真实
`cargo test -p yuhaiin-runtime --test service_chain --all-features --offline` 的 11 个
inbound→router→outbound 场景也全部通过。工作区最终验收继续使用
`~/.cache/yuhaiin-rust` 作为构建、互操作和临时状态目录。

## 76. 2026-08-10 native Yuubinsya UDP central authentication

native Yuubinsya UDP listener 现在从 `InboundAuth` 收集 bounded concrete passwords，派生出有限的
SHA-256 password hash 集合后共用一个 UDP socket。`decode_udp_packet_any` 对固定 32 字节 hash
逐个做 constant-time 比较，并把实际命中的 hash 返回给 server；`YuubinsyaUdpServer` 的旧
`bind/new/recv_from/send_to` API 保持单密码兼容，新增 `*_with_password_hashes` 和
`recv_from_authenticated`/`send_to_with_password_hash` 用于中心用户路径。

runtime 的 UDP flow identity 增加可选 authentication hash。这样同一个 UDP peer 和目标地址同时
使用两个中心用户时会创建两个独立 flow；receiver task 生成的异步 reply 带着原始 flow identity，
回包不会错误使用另一个用户的 hash。DNS 本地应答和正常 outbound reply 都沿用命中 hash。
AEAD 外层 UDP 仍是单密码设计，暂不声称支持中心多密码；它需要单独的 replay/session 生命周期
设计，和 native packet auth 不能混为一项。

验证证据：新增 `udp_packet_accepts_any_bounded_password_hash_and_returns_the_match`、
`yuubinsya_native_udp_server_preserves_the_authenticated_password_for_replies`；`cargo test
-p yuhaiin-core -p yuhaiin-runtime --lib --all-features --offline` 通过 129 + 213 个测试，
并且真实 `service_chain` 进程测试 11/11 通过。构建和测试缓存均在
`~/.cache/yuhaiin-rust`，没有使用 `/tmp`。

## 77. 2026-08-10 user mutation reloads inbound authentication

真实 service-chain 测试发现了一个此前单测无法覆盖的生命周期缺口：`users` API 的 create/update/delete
虽然已经写入 schema-v6 SQLite，但没有调用 `RuntimeController::mutate_and_reload`。因此已经运行的
HTTP/SOCKS5/Yuubinsya listener 仍然持有旧的 `InboundAuth` 快照，前端看见的是新用户，数据面却没有
同步，属于典型的“控制面成功、数据面未更新”。

现在用户 create、update、delete 都与 node/inbound/resolver/route mutation 共用同一个 reload boundary：
事务写入成功后重新构建 snapshot、刷新 live selector、发布 reload event，由 inbound owner 原子重建
listener set。创建用户时保留原有生成 UUID 和返回 view 的语义；更新/删除失败时不会发布半成品 snapshot。

新增 `central_basic_user_authenticates_http_inbound_chain` 进程级回归：先通过 `/api/v2` 写入 inbound、
route 和 HTTP outbound，再创建中心 basic 用户；错误密码得到 HTTP 403，正确密码经 HTTP inbound →
router → HTTP CONNECT outbound → loopback target 双向回显，并检查 live connection 的 inbound/outbound
metadata。随后通过同一 API 更新 credential，验证旧密码失效、新密码仍能完成回显；删除用户后验证
无认证请求恢复成功，覆盖 create/update/delete 的 listener reload boundary。测试使用 create 返回的
UUID，而不是假定请求里的 `id` 会被保留，符合 Go users handler 的生成 ID 语义。该测试与
`api-contract`、`api-reload-flow`、`stats-concurrency` 和 Go/Rust shared SQLite smoke 均通过。前台
启动日志也用当前构建的 binary 实测输出到 stderr；只有显式设置 `YUHAIIN_QUIET=1` 才会关闭 console
logs。

## 78. 2026-08-10 central users lifecycle integration and musl build

`service_chain.rs` 的 central basic 用户场景现已覆盖完整生命周期：create 使用 API 返回的 UUID，
update 后旧凭据返回 403、新凭据可以再次通过 HTTP inbound → router → HTTP CONNECT outbound，delete
后无认证请求恢复成功。`make service-chain-smoke` 的 12 个真实进程场景全部通过。

当前环境也已验证 `make build-musl`：`x86_64-unknown-linux-musl` debug binary 成功生成于
`~/.cache/yuhaiin-rust/cargo-target/x86_64-unknown-linux-musl/debug/yuhaiin`，`file` 确认为
static-pie。`make android-aarch64` 也已实际通过，使用
`/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang`
生成 `~/.cache/yuhaiin-rust/cargo-target/aarch64-linux-android/release/yuhaiin`。这只是交叉编译
证据，尚未把本机编译当作 Android 真机 VpnService 验收。

## 79. 2026-08-10 transparent TPROXY gate reports rootless capability clearly

在本机强制执行 `YUHAIIN_TPROXY_ENABLED=1 make transparent-service-smoke` 时确认：rootless
Podman 可以创建部分 namespace、veth、iptables TPROXY 规则并通过透明 socket capability probe，
但非本地 UDP 包仍不能可靠到达 TPROXY listener，最终以 `Resource temporarily unavailable` 和
`udp_connections=0` 失败。旧脚本在启动前直接退出，反而隐藏了这个证据；现在 `auto` 模式仍保守
跳过，显式 `YUHAIIN_TPROXY_ENABLED=1` 会真正尝试并保留完整 `container.log`、iptables 和 runtime
日志。测试夹具的 TPROXY 默认监听地址也改为 wildcard `0.0.0.0:18083`，避免原目标地址与透明
socket lookup 不匹配。

因此本轮没有把 rootless 的部分成功标成完整 TPROXY UDP；默认 REDIRECT TCP、IPv4+IPv6 REDIRECT
仍通过，完整 UDP 仍需要 rootful Podman 或宿主机 `CAP_NET_ADMIN`，并继续保留在 checklist 的
`[~]`。

## 80. 2026-08-10 native service-manager lifecycle

之前 Rust binary 只兼容 Go service command 的参数形状；执行 `install`、`start`、`stop`、
`restart` 或 `uninstall` 时，仍会把 action 当作运行参数，无法直接替换 Go 的系统服务入口。

现在 `crates/yuhaiin-runtime/src/bin/service/mod.rs` 接管这些 action：Linux 使用
`/usr/local/bin/yuhaiin`、`/etc/systemd/system/yuhaiin.service` 和 `systemctl`，macOS 使用
`/usr/local/bin/yuhaiin`、`/Library/LaunchDaemons/com.asutorufa.yuhaiin.plist` 和 `launchctl`。
安装会检查 root、复制当前 executable、创建数据目录、原子写入 service 配置，然后执行
daemon reload/bootstrap、enable 和 start；已有运行实例则 restart。卸载会停止/禁用或 bootout、
移除配置，并保留 symlink binary。`-host`、`-path`/`-p`、`-nfs-mode` 与 Go service command
保持兼容，路径/host 在 systemd/XML 配置中分别做转义。

已通过 Linux unit renderer 单测、workspace clippy/check，以及重新构建后的非 root fail-fast
验证；当前环境 uid=1000，因此没有触碰宿主机已有的 `/etc/systemd/system/yuhaiin.service`。
完整 systemd/launchd 的现场 install/rollback 仍需相应平台权限，不能用本机 rootless 检查替代。

## 81. 2026-08-10 TUN IPv4 fragment reassembly boundary

smoltcp 0.13 已提供纯 Rust IPv4 fragment reassembly，但 `yuhaiin-core` 之前没有打开
`proto-ipv4-fragmentation` feature；同时 dispatcher 的 `prepare_rx` 会在非首片上直接按
完整 TCP/UDP 包解析，合法的 out-of-order fragment 因此可能被当成 malformed packet。

现在启用 smoltcp 自带的 bounded IPv4 reassembly，并让 dispatcher 对非首片跳过 transport
解析；首片只读取固定 transport header 字段来提前建立 UDP/TCP socket，完整长度、checksum 和
重组后的 payload 仍由 smoltcp 校验。新增
`dispatcher_reassembles_out_of_order_ipv4_udp_fragments`，实际以 second fragment → first
fragment 顺序验证 UDP event 和 source/destination flow identity。

## 82. 2026-08-10 TUN IPv6 fragment ingress reassembly

在 IPv4 smoltcp reassembly 之外，TUN ingress 新增了 IPv6 fragment boundary：按源/目标/identification/
next-header 建立有界 assembly，支持乱序片段和前置 hop/routing/destination/AH extension header，
完成后移除 Fragment Header、修正上一层 next-header 和 IPv6 payload length，再交给同一套 smoltcp
dispatcher。每个 assembly 最多 128 片、32 个并行 datagram、64 KiB 总包，并在 15 秒后过期；任何
重叠、长度冲突或容量超限都 fail-closed 丢弃，不影响后续 TUN 流量。

新增 `ipv6_fragment_reassembler_reassembles_out_of_order_udp`、
`ipv6_fragment_reassembler_drops_overlap_and_expires_assemblies` 与
`ipv6_fragment_reassembler_drops_fragment_count_overflow_without_poisoning`，覆盖 second fragment 先到、完整
UDP payload、重叠冲突、确定性过期、129 片 wire-fragment 上限，以及超限丢弃后同 key 后续 datagram
仍可重组。IPv4 仍使用 smoltcp 自带的 bounded reassembly；真实 namespace teardown、超出有界重组上限的
长流进程级证据，以及 Android/macOS 设备验收仍保持 checklist 的部分状态。

## 83. 2026-08-10 live connections SSE add/remove regression

Go 的 `Connections.Events` 先发送当前连接快照，再持续推送连接新增和删除事件。Rust 原先只在
API 层验证了 SSE route 和空快照，monitor 本身虽然已有事件单测，但没有把 HTTP stream 两端连
起来验证消费行为。

新增 `connections_event_stream_delivers_live_add_and_remove_events`：打开真实 Axum SSE body，先
读取 `connections_added` 空快照，再通过同一个 `ConnectionMonitor` 的 `FlowObserver` 打开/关闭
TCP flow，连续读取并断言 `connections_added` 和 `connections_removed` 事件及 Go 兼容 payload。
这证明前端使用 EventSource 时不只路由存在，live connections 也能从 monitor 穿过 HTTP stream
到达客户端；traffic/telemetry 仍通过独立 API 和进程级统计 smoke 验证，生产长时锁竞争继续保留
在 checklist 的 `[~]`。

## 84. 2026-08-10 H2 producer-side bounded backpressure regression

上一轮 H2 relay 使用 `h2::SendStream::send_data` 直接提交 frame。该 API 在 peer flow-control
window 耗尽时会把未发送的 payload 保留在 h2 自身队列中；调用方 buffer 固定为 16 KiB，仍不能
证明 producer-side 内存有界。更直接的问题是，若 relay 在 `tokio::select!` 的读本地方向分支中
等待发送窗口，就会停止消费远端方向，TLS + HTTP/2 + Yuubinsya 的全双工长流可能互相等待。

现在 `send_h2_data` 先调用 `reserve_capacity`/`poll_capacity`，只把已分配窗口内的最多 16 KiB
提交给 h2；窗口等待被放进独立的 relay send task，主 relay 继续消费另一方向并释放接收窗口。
服务端 `bridge_h2_stream` 使用同一模型，避免 inbound H2 bridge 复现同类死锁。发送 task 在
relay 关闭、shutdown 或远端流结束时会被回收；待发送数据只存在本地固定 buffer、一个当前 frame
和 h2 已明确分配的窗口中。

新增/保留的证据包括：

- `bounded_h2_sender_waits_for_peer_window_before_accepting_more_data`：对 128 KiB payload
  验证 peer window 耗尽时发送 future 保持 pending，而不是继续接收无界数据；
- `cargo test -p yuhaiin-chain --all-features --offline`：51 个 library tests、HTTP/2
  protocol tests 和 12 个 P0 TUN/chain tests 通过；chain clippy `-D warnings` 通过；
- `make service-chain-smoke`：12 个真实进程 inbound/router/outbound 场景通过；
- `make tun-chain-service-smoke`：真实 runtime TUN → fixed → TLS → HTTP/2 → Yuubinsya
  进程链路通过；
- `make benchmark-throughput`：Podman、release、64 MiB、单流 loopback 中，HTTP CONNECT 为
  `125.96 MiB/s`、peak RSS `17,164 KiB`，TLS/H2/Yuubinsya 为 `16.62 MiB/s`、peak RSS
  `18,904 KiB`；两个测试均报告 `test result: ok`。

这次修复确认的是窗口耗尽时的正确性和有界发送行为，不把单机 loopback 数值当作 Go/Rust
跨机器性能结论；并发 stream、超长 soak 和 Android/macOS 设备验收仍按 checklist 保留。

## 85. 2026-08-10 TUN abnormal termination and legacy Go HTTP/2 interoperability

TUN 的正常 shutdown 已有进程级证据，但此前没有把“设备已经打开后宿主进程被强制终止，再
用同一个 SQLite 和同名设备重新启动”固定为可复用 smoke。`scripts/integration/tun-service.sh`
现在接受 `YUHAIIN_TUN_FORCE_STOP=1`：先在 privileged、`network=none` 的 Podman 容器中以
较大的流量上限启动 runtime-owned TUN，等待 `runtime-tun-opened` 后发送 `SIGKILL` 并移除
容器，再运行原有的正常流量/关闭断言。所有日志和状态仍位于 `~/.cache/yuhaiin-rust`，不
使用 `/tmp`。

实际执行 `YUHAIIN_TUN_FORCE_STOP=1 make tun-chain-service-smoke` 通过：第一次强制终止后，
第二次仍使用 `yrtun0` 和同一 SQLite，成功完成 TUN → fixed → TLS → HTTP/2 → Yuubinsya
TCP → loopback echo，输出 `runtime-tun-force-stop-ok`、`runtime-tun-opened`、
`runtime-tun-traffic-ok` 和 `runtime-tun-closed`。这补强了设备/kernel namespace cleanup
和数据库 takeover 的异常终止证据；超过 IPv6 有界重组上限的长 wire-fragment 进程测试及
Android/macOS 设备仍保留在 checklist 的 `[~]`。

同时新增 `crates/yuhaiin-chain/tests/interop/http2_v1_go_client.go` 与 ignored Rust
integration test，使用 Go `golang.org/x/net/http2.Transport` 的旧 v1 client，通过
`DialTLSContext` 接入 prior-knowledge HTTP/2 listener，发送 CONNECT body 并完整读取 Rust
server 的 echo response。显式执行
`cargo test -p yuhaiin-chain --test standalone_http2 --all-features --offline \
legacy_go_http2_v1_client_round_trips_against_rust_server -- --exact --ignored --nocapture`
通过，证明当前 Rust H2 CONNECT wire boundary 不只兼容 Go v2 helper，也兼容 Go v1 transport。

## 86. 2026-08-10 process/inbound route metadata in a real flow

此前 route matcher 的单测能够证明 process、inbound 和 network 条件可以选中规则，但真实
socket flow 暴露出一个兼容性缺口：`RuntimeProxySelector::route_context` 直接调用 trie
router 时没有先用当前 snapshot 计算所有 route-list membership。规则本身仍会选中正确的
HTTP outbound，但连接观测中的 `lists` 为空，无法与 Go `ConnOptions.Lists()` 对齐。

现在 selector 的 metadata snapshot 同时携带 `RouteListSnapshot`。每次 flow route evaluation
先以这份不可变 snapshot 填充 `FlowContext::lists`，再执行 trie 的短路匹配和 history 记录，最后
恢复完整 membership 后写入 connection metadata。这样 reload 时 route rules、list membership
和连接观测使用同一个 snapshot，也不会把“被选中规则携带的 list”误当成全部匹配 list。

新增 Linux 真实进程级 `process_and_inbound_route_matchers_select_real_http_outbound`：通过
HTTP inbound 发送 CONNECT，process list 使用当前测试进程路径，inbound + process + TCP
嵌套 `all` 规则选择 HTTP outbound，随后断言 echo、outbound authority、`process`、
`process-current` membership 和 `proxy-process-inbound` match history。定向测试通过，
`make service-chain-smoke` 的 13 个真实 inbound/router/outbound 场景全部通过。这个入口复用
`~/.cache/yuhaiin-rust/integration-reusable`，不是 Podman；TUN、透明代理和统计等需要
namespace 的测试继续由各自 Podman 脚本负责，所有临时状态均不使用 `/tmp`。

## 87. 2026-08-11 TUN bounded-fragment verification boundary

本轮重新核对 TUN 分片边界后，没有重复增加一个等价的重组器测试：当前实现已经在 ingress
层对 IPv6 assembly 限制并发数量、单个 datagram 的片数和总字节数，所有恶意/资源耗尽分支都会
删除当前 assembly；`recv_from_tun` 对等待后续片段和主动丢弃的 datagram 都返回已成功读取的长度，
不会因为一个坏分片关闭整个 TUN supervisor。

现有 `yuhaiin-core` 证据实际通过：IPv6 的乱序 UDP、重叠/过期、128 片上限和超限后同 key
恢复共 4 个测试，另外 `dispatcher_reassembles_out_of_order_ipv4_udp_fragments` 验证 IPv4
dispatcher 的乱序重组；本轮定向运行结果为 4/4 和 1/1。这里的“完成”只表示代码和单元测试边界，
不等同于真实内核 TUN 进程证据。

因此 checklist 保持 `[~]` 而不是虚构现场通过：剩余项必须在拥有 `CAP_NET_ADMIN` 的干净
Linux namespace 中，让真实 TUN 长流注入超过上限的 IPv6 wire fragments，并同时观察另一条
flow 是否继续、TCP reset/重连、容器/namespace teardown 以及同名设备二次接管。当前 rootless
Podman 的能力不足以完成这些断言，所有临时数据库和日志继续放在 `~/.cache/yuhaiin-rust`。
本轮实际运行 `make tun-chain-service-smoke` 的容器能输出 `runtime-tun-opened`，但真实流量在
`0 bytes` 处收到 `Connection reset by peer`，随后按 45 秒上限退出并清理容器；这证明 smoke
脚本的超时/清理路径生效，也保留了真实 route/CAP_NET_ADMIN 缺口的可复现记录。

## 88. 2026-08-11 TUN inbound live enable/disable smoke

此前 TUN 的 `enabled` reload 主要由配置解析和 supervisor 单测覆盖，缺少真实设备生命周期
断言。本轮扩展已有 `tun-service-smoke`，不改变 TUN 的 inbound 归属：进程启动同一个
`inbound::run_until` owner 后，通过 `RuntimeController::mutate_and_reload` 修改 SQLite 中
Go-shaped TUN inbound 的 `enabled` 字段。

`make tun-reload-smoke` 实际通过，输出顺序为：

```text
runtime-tun-opened name=yrtun0
runtime-tun-disabled name=yrtun0
runtime-tun-reload-ok name=yrtun0
runtime-tun-closed name=yrtun0
```

测试在关闭和重新开启之间分别等待 `/sys/class/net/yrtun0` 消失/出现，证明不是只观察
snapshot 或日志。数据库和 Podman 日志复用 `~/.cache/yuhaiin-rust/integration/tun-service`；
该 smoke 只验证开关生命周期，不把 rootless namespace 的 route/代理流量能力误算成通过。
Android `VpnService`/macOS `utun` 的外部 fd 仍需对应平台实机验收。

## 89. 2026-08-11 containerized Go/Rust live flow parity

此前 `go-live-flow-parity.sh` 的对照服务曾直接在宿主机启动；这不符合当前验收边界，也会让
Go/Rust 的默认 mixed/DNS listener 互相争抢端口。现在脚本只在宿主机编译 Go/Rust binary，
运行时全部放进 Podman：Go 和 Rust 各自使用独立的 `debian:testing` 容器、独立 SQLite，
通过 pasta 网络和宿主随机映射端口提供 API/inbound；每个服务的纯 Python HTTP CONNECT echo
proxy 作为 `--network=container:<service>` sidecar 启动。宿主机只负责启动/清理容器、调用管理
API 和连接已发布端口的测试 client，不启动 proxy/runtime，不创建 TUN，不修改路由。

容器 inbound 使用 wildcard `0.0.0.0:18080`，避免 Podman 端口转发无法到达容器内 loopback；
sidecar 地址由容器实际网络地址发现，避免把宿主 `127.0.0.1` 错当成容器服务。清理时先删除
sidecar 再删除服务容器，避免共享 network namespace 依赖导致容器残留。测试运行中的所有
二进制、SQLite、日志和结果都位于 `~/.cache/yuhaiin-rust`，没有使用 `/tmp`。

`make go-live-flow-parity-smoke` 已在 Podman 中连续通过。两套实现均完成 HTTP inbound →
router host-list rule → HTTP outbound → echo proxy 的真实 flow，并验证：

- Go/Rust live connection 归一化结果完全一致，`connections.diff` 为空；
- CONNECT 200 response、双向 payload echo、Go/Rust proxy CONNECT 和 HTTP latency 请求均有
  sidecar 日志证据；
- `connections.total` 的 upload/download、traffic、telemetry、node latency 和 history
  均可读且满足断言。

最近一次结果保留在
`~/.cache/yuhaiin-rust/integration/go-live-flow-parity/20260811220616-142194`。这补齐了
Linux 普通 inbound/router/outbound 的容器化替换证据，但不改变 rootful TUN、TPROXY、长时间
production telemetry 和 TUN loopback guard 仍待完成的 checklist 状态。

## 90. 2026-08-11 container-only runtime smoke boundary

当前验收边界明确为“宿主机只编译，运行时和集成测试在 Podman”。`startup-logs-smoke` 已从
直接在宿主机 spawn runtime 改为 `network=none` 容器内的 foreground harness：它启动当前
`yuhaiin` binary，检查 database/API bind、HTTP API listening、runtime ready，然后发送 TERM
并检查 shutdown/stopped 日志。实际通过日志保存在
`~/.cache/yuhaiin-rust/integration/startup-logs/podman.log`。

`service-chain-smoke` 也改成宿主机只 build test binary/runtime binary，由 Debian testing
Podman 容器执行完整的 14 条 inbound/router/outbound 场景；容器内测试改为单线程，避免多个
并行 runtime 争用默认 `127.0.0.1:1080` 造成偶发 central-auth fixture 失败。当前连续执行通过
14/14；API contract（3/3）、API reload（1/1）和 Go/Rust live flow parity 也均在 Podman
通过。service-chain 暂保留 Podman 的 host network mode，因为 HTTP/2/TLS/Yuubinsya 多层
fixture 在 `network=none`/pasta namespace 中会在 H2 response 前 reset；这仍是容器内测试，
宿主机未启动 Rust/Go runtime、proxy 或 TUN。API、DNS、DoH、SOCKS5 UDP、stats 和 startup
smoke 已使用 `network=none`，不会接触宿主监听端口。

## 91. 2026-08-11 TUN disabled data-plane assertion

TUN reload fixture 在禁用持久化 inbound 后，除了等待 `/sys/class/net/yrtun0` 消失，现在还在
启用流量模式下尝试访问 `198.18.0.2:18080`，要求该地址在禁用窗口不可达，再重新启用并执行
原有 echo flow。成功时会输出 `runtime-tun-disabled-no-route-ok`。rootless Podman 只能执行
设备生命周期 smoke，流量路径按脚本返回 77；因此本轮没有把这条 rootful-only 断言标记为通过，
需要在 `CAP_NET_ADMIN` 的 Podman namespace 中执行 `make tun-reload-traffic-smoke` 后再更新
checklist。源码编译、`make fmt-check`、`make check`、`make clippy` 以及容器中的 API/chain/
startup/live parity 均已通过，所有运行状态仍写入 `~/.cache`，没有使用 `/tmp`。

## 92. 2026-08-11 SOCKS5 server protocol boundary

此前 SOCKS5 inbound 的握手、地址解析、reply 编码和 UDP framing 与 runtime 的 selector、
`ConnectionMonitor`、UDP flow map 混在 `crates/yuhaiin-runtime/src/inbounds/socks5.rs` 中，
导致 outbound 使用 `yuhaiin-protocol::socks5`，inbound 却有另一份 wire codec。现在新增
`yuhaiin-protocol::socks5_server`：

- `server_handshake` 统一处理 greeting、username/password、CONNECT、UDP ASSOCIATE；
- `read_endpoint`、`parse_endpoint_bytes`、`encode_endpoint` 统一 IPv4/IPv6/domain 地址；
- `parse_udp_packet`、`encode_udp_packet` 统一 RFC 1928 UDP header；
- `write_reply`、`write_reply_endpoint` 统一 server response。

runtime 仍保留 inbound-specific 的认证快照、route/selector、`AsyncDatagram`、UDP idle
reap、连接观察和 AEAD socket adapter，但不再重复维护 SOCKS5 字节协议。这样后续新增
其他 listener 或 transport 时可以复用同一个 server codec，而不让 protocol crate 依赖
runtime 的配置和 monitor 类型。

新增 `make socks5-protocol-smoke`：宿主机只编译 test binary，实际 6 个 protocol tests
在 `debian:testing` Podman、`network=none` 容器内执行；随后重新执行
`make socks5-udp-associate-smoke`（1/1）和 `make service-chain-smoke`（14/14），确认
真实 SOCKS5 UDP chain 以及 HTTP/2/TLS/Yuubinsya 多层链路未回归。构建日志和测试结果位于
`~/.cache/yuhaiin-rust/integration-reusable/`，没有使用 `/tmp`，也没有在宿主机启动
runtime、proxy 或 TUN。

## 93. 2026-08-11 workspace tests container boundary and parity runners

本轮把“不要在本机测试”落实到默认 workspace 入口，而不只约束若干 smoke script。`Makefile`
新增 `workspace-tests` 目标，`make test` 现在只在宿主机执行两类编译动作：构建 runtime binary
以及 `cargo test --workspace --all-features --no-run` 生成测试 harness。所有生成的 harness
随后通过 `scripts/integration/workspace-tests.sh` 在 Podman 执行；runtime 子进程、SQLite
副本、临时目录、XDG cache、integration 日志都映射到 `~/.cache/yuhaiin-rust` 下的 state
目录，不使用 `/tmp`。

workspace harness 按网络和进程隔离需求拆成三个 disposable container：

- 普通 harness 使用 `--network=none --privileged`，覆盖 core、chain、protocol、store、trie、
  geo、API、DNS/DoH、FakeIP、NAT、模拟 TUN、跨进程 SQLite 和启动日志；
- `stats_concurrency` 单独使用 `--network=none --privileged`，避免它的 force-stop 子进程和
  其他 harness 共享 namespace；它仍通过 `/state/tmp`、`/state/cache` 和 `~/.cache` 映射运行，
  不使用 `/tmp`；
- `service_chain` 的 14 个真实 inbound/router/outbound 进程场景单独使用 Podman
  `--network=host` 并强制单线程。这仍然是容器内运行，目的是复用专用 `service-chain-smoke`
  的 loopback 语义；rootless `network=none` 在 HTTP/2 多层 fixture 上会产生无关的 response
  reset。startup harness 的 TERM 信号在 Linux 测试中使用纯 Rust `nix` 直接发送，不依赖
  Debian 精简镜像中可能不存在的外部 `kill` 可执行文件。

本轮最终 workspace 入口报告 40 个 harness；`startup_logs` 在容器中 0.09 秒通过，
`service_chain` 的 14/14 条真实链路通过，其余 harness 也无失败。ignored 项仍按测试自身声明
保留，不被包装脚本误判为通过。这个入口不把 rootful 能力伪装成普通测试：TUN 真实 packet/route、TPROXY ancillary
和 loopback guard 仍需拥有 `CAP_NET_ADMIN` 的独立 Podman namespace，rootless 环境只记录
生命周期/权限 skip。

另外，`go-api-parity.sh` 的 Go 和 Rust 管理服务、Rust takeover preparation 已全部移入
独立 Podman 容器；宿主机只编译 binary、驱动 curl 和收集日志。`tools.interfaces` 比较保留
稳定的 interface/address contract，并忽略每个容器 veth/MAC 派生的 IPv6 link-local 地址，避免
把 network namespace 的实现细节当成 API 差异。`legacy-v1-runtime-smoke` 也改为在 Podman
中加载复制后的 v1 `state.db`，不会让 legacy fixture 触碰宿主运行时。

本轮静态检查通过：`bash -n`、`git diff --check`、`make fmt-check`、`make check` 和
`make clippy`。可重复入口为：

```bash
make workspace-tests
make test
make go-api-parity-smoke
make go-live-flow-parity-smoke
make legacy-v1-runtime-smoke \
  YUHAIIN_GO_LEGACY_PRODUCTION_DB=~/.cache/yuhaiin-rust/fixtures/go-v1/state.db
```

## 94. 2026-08-11 desktop TUN supervisor lifecycle boundary

此前桌面 `inbound::run_until` 把 TUN task 放进普通 TCP/UDP listener 的
`abort_listeners` 集合。任意配置 reload 都会先 abort 整个 listener set，再立即重新打开 TUN；
这会把设备 fd、Linux route lease 和新的 dispatcher 绑定在一次无序 task abort/re-open 中，尤其
容易在快速切换 TUN enabled 或其他 inbound 配置时产生同名设备/路由 teardown 竞态。

现在桌面 TUN 由独立的 `run_desktop_tun_supervisor` 持有。普通 socket listener 仍按 reload
重建；listener supervisor 会合并尚未处理的 pending reload，只按最新 snapshot 重建一次，避免
客户端连上刚 bind 的 socket 后又被同一批旧通知立即 abort。TUN supervisor 会等待当前 dispatcher
通过 shared shutdown/reload future 返回，确保
`TunRuntime` 和它的 route lease 在下一次 `load_tun_config` 前析构；打开失败或 dispatcher 初始化
失败会等待下一次 reload，不会对同一份坏配置忙循环。注入式 Android/host FD 路径继续使用已有
`run_until_with_tun_runtime`，不打开第二个桌面设备，也不改变 FD 的复用边界。

`make tun-reload-smoke` 现在在 Podman 中连续执行四轮 `disable -> device disappears ->
 enable -> same device returns`，最近一次输出包含每轮的 `cycle=1..4`，最终正常打印
`runtime-tun-closed`。这证明了 reload 的 owner 顺序和重复切换边界；rootless Podman 仍不具备
真实 route、代理 packet flow、TPROXY 和 loopback guard 所需的 `CAP_NET_ADMIN`；当时这些
rootful 现场项继续留在 checklist 的 `[ ]`/`[~]`，没有被生命周期 smoke 冒充完成。宿主机只
执行 Cargo 编译和静态检查，smoke binary、SQLite 和日志均由 Podman 运行并落在
`~/.cache/yuhaiin-rust`。

## 95. 2026-08-12 rootful TPROXY 与 TUN route matrix 收口

在 Debian VM `root@192.168.122.2` 上使用 rootful Podman（`rootless=false`、Podman 5.8.3、
`CAP_NET_ADMIN`、`/dev/net/tun`）重跑了新的独立现场夹具。宿主只负责构建和同步 binary，
VM 内的 Podman 承担所有 TUN、netlink、iptables/nftables 和 proxy 数据面运行；状态与日志
都位于 `~/.cache/yuhaiin-rust-vm`，没有使用 `/tmp`。

TUN route matrix 由 `scripts/integration/tun-route-matrix.sh` / `make tun-route-matrix-smoke`
驱动 `tun-smoke --features tun-routes`，实际安装并检查以下 3 条 IPv4 route：

```text
198.18.0.0/15 proto static
192.0.2.0/24 proto static
203.0.113.0/24 proto static metric 42424
```

结果：3 条 route 在 TUN owner 存活期间可见；owner graceful exit 后全部消失；另一个 owner
被 SIGKILL 后全部消失。该 matrix 证明了 `TunRouteLease` 的多路由 netlink ownership 和异常
teardown，不代表 TCP reset/reconnect 或真实 kernel IPv4/IPv6 fragmentation 已经完成；后两项
仍由 checklist 的 `[~]` 保留。fragment overlap、expiry、count/size overflow 和恢复路径已有
纯 Rust dispatcher 单测与模拟 packet 覆盖。

TPROXY UDP 现在在同一 rootful VM 通过两种内核入口：

- `YUHAIIN_TPROXY_BACKEND=iptables`：mangle `TPROXY` + `fwmark 1 -> table 100 -> local lo`；
- `YUHAIIN_TPROXY_BACKEND=nft`：native nft `tproxy` rule，使用同一 policy route。

两种 backend 都通过 transparent socket `IP_TRANSPARENT` readback、2 个不同 UDP source
flow、original destination `10.254.1.2:18082`、local listener `0.0.0.0:18083`、UDP 回包、
source-port rebind 和 monitor upload/download 统计。Rust 的 `recvmsg` ancillary decoder 现在
不需要为这次现场失败增加特殊分支。夹具为 client ingress veth 设置了
`/proc/sys/net/ipv4/conf/service-client/accept_local=1`；这是该隔离拓扑的 Linux martian/local
source 流量前提，不是 runtime 对宿主机的全局副作用。Linux TPROXY 的必要组成仍是
`IP_TRANSPARENT` socket 与 policy routing，可对照 [Linux kernel TPROXY 文档](https://cdn.kernel.org/doc/html/latest/networking/tproxy.html)。

TPROXY 仍保留 `[~]` 的部分是公共 90 秒 idle reap 的 rootful 长时间现场、进程级 SIGKILL
期间的 flow close 观测，以及真实生产 firewall/nftables 组合；公共 flow expiration/close 单测
和 namespace teardown 已通过。WireGuard 同样继续使用 Cloudflare BoringTun userspace adapter，
本地双 peer/Go interop 已通过，第三方/WARP endpoint roaming 仍需外部 peer。

## 96. 2026-08-12 rootful reset/reconnect、TPROXY idle 和 force-stop 收口

继续使用 Debian VM `root@192.168.122.2` 的 rootful Podman，宿主机只编译并同步
binary；所有 TUN、UDP、netlink 和 firewall 数据面仍在 VM 内的 Podman namespace 中运行，
状态与日志位于 `~/.cache/yuhaiin-rust-vm`。

TUN 新增了 `make tun-reset-reconnect-smoke`：direct TUN fixture 先通过
`SO_LINGER=0` 主动制造 TCP RST，target 端接受并清理该连接，随后第二个正常连接完成
echo；rootful 输出包含 `runtime-tun-reset-ok`、`runtime-tun-reconnect-ok` 和
`runtime-tun-closed`。该证据只关闭了 reset/reconnect 缺口，真实 kernel IPv4/IPv6 fragment
matrix 仍未被 userspace packet fixture 冒充完成。

UDP 生命周期 smoke 对生产默认 90 秒保持不变，只在进程级测试中使用
`YUHAIIN_TEST_UDP_IDLE_TIMEOUT_MS=1000`，并等待 2500ms 检查 monitor 从两个 UDP flow 回收
到零。rootful iptables 和 native nft backend 均通过；两种 backend 另以
`YUHAIIN_TPROXY_FORCE_STOP=1` 在两个 UDP flow 已建立后对 runtime service 进程发送 SIGKILL，
均观测到 `status=137`，shell/firewall/namespace cleanup 完成。剩余 TPROXY `[~]` 仅是实际生产
firewall/nftables 组合 matrix，不把隔离 fixture 当作所有发行版规则的证明。

同一轮 rootful TUN metadata smoke 通过了 `component=tun`、`node=tun-fixed`、
`outbound=127.0.0.1:*` 和 `local=198.18.0.1:*`；PID/executable path 仍单独留在 checklist，
因为当前 fixture 的固定断言尚未把这两个字段锁定为非空。

完整 workspace 回归重新在 Podman 中通过：41 个 harness，所有非 ignored 测试通过；本轮还修复
了 `close -> delete selected node` 的 API 边界——删除被选中的节点时，Rust 先把三份 selected
metadata 回退到内置 `direct`，避免旧 selected id 让 runtime reload 访问已删除的 proxy config。

## 97. 2026-08-12 rootful TUN connection metadata 逐字段收口

在同一 Debian VM rootful Podman 环境中重跑 `tun-connection-metadata.sh`，并启用
`YUHAIIN_TUN_ASSERT_PROCESS=1`。fixture 不再只检查 `component=tun`、selected node、outbound
endpoint 和 localAddr，而是在 connection monitor 中要求 `process`、`pid`、`uid` 均为非空，随后
输出固定断言结果：`process=/usr/local/bin/tun-service-smoke`、`pid=7`、`uid=0`。本次现场退出码为
0，真实 TUN traffic 仍完成 1 MiB echo，device 正常关闭。

这项证据关闭的是 loopback/process metadata 的现场缺口，不等同于关闭 TUN 的真实 IPv4/IPv6
kernel fragmentation matrix；后者仍保留在 checklist 的 `[~]` 项中。

## 98. 2026-08-12 rootful runtime TUN UDP path 收口

在 Debian VM `root@192.168.122.2` 的 rootful Podman 中补跑了 runtime-owned TUN UDP
traffic。fixture 使用 `198.18.0.1/15` portal、`198.18.0.2/32` route 和 fixed outbound；同一
个服务先后执行 TCP 与 UDP echo，UDP target 收到 32 字节，UDP-first 顺序也通过，最后设备和
route lease 正常关闭。宿主机只编译并同步 binary，TUN、路由、SQLite 和网络数据面仍在 VM 的
Podman namespace 中运行，日志位于 `~/.cache/yuhaiin-rust-vm`。

这次现场还固定了两个容易误判的问题：smoke 的阻塞式 UDP client 不能直接运行在
current-thread Tokio 主协程中，否则会阻塞 TUN dispatcher；另外 runtime 的 loopback/process
guard 会拒绝同一进程产生的回环 UDP，故测试 client 与已有 TCP fixture 一样改为独立子进程。
这两个调整只影响测试夹具，不放宽生产 loopback guard。生产 TUN 在打开显式 route 时会先把
route destination 加入 smoltcp 的虚拟地址列表，并保持 UDP socket 的精确本地 destination
绑定，确保 routed virtual endpoint 的回包源地址正确。

## 99. 2026-08-12 rootful TUN IPv4 kernel fragmentation matrix 收口

上一轮只验证了小 UDP payload，继续把 runtime-owned TUN 的 rootful Debian VM 测试扩展到
最大合法 IPv4 UDP payload `65507` 字节，并在 MTU `576/1280/1500/9000/9216` 五档分别运行
独立的 privileged、`network=none` Podman 容器。五档均通过：Linux kernel 将 ingress datagram
分片，smoltcp 完成 ingress 重组和 proxy echo，再按 TUN MTU 做 IPv4 出方向分片，Linux kernel
重新组装后 UDP client 收到逐字节一致的 `65507` 字节响应；TCP 32 字节 smoke 和 device/route
lease graceful close 也同时通过。VM 日志位于
`/root/.cache/yuhaiin-rust-vm/integration/tun-mtu-full/`，宿主机只编译并同步 binary，未使用
`/tmp`。

这次现场失败过一次并已定位：smoltcp 0.13 的默认 `FRAGMENTATION_BUFFER_SIZE` 是 1500，
超过该值的 IPv4 出方向 datagram 会被 fragmenter 丢弃，即使每个最终 fragment 都能小于设备
MTU。新增 workspace `.cargo/config.toml` 将它设置为 `65535`，覆盖最大 UDP datagram 加
IPv4/UDP header 的完整缓冲边界；同时新增 `udp_socket_fragments_a_large_datagram_to_the_tun_mtu`
单测，直接校验 8192 字节 datagram 的 fragment 长度、地址、identification 和重组内容。

IPv6 的 ingress fragment reassembly、IPv6 route virtual address 和普通 MTU 路径仍保留；但
smoltcp 0.13 的 `dispatch_ip` 明确没有 IPv6 出方向 fragmentation，低 MTU 下的 IPv6 大 UDP
因此继续在 checklist 标为 `[~]`，没有把 IPv4 现场结果外推成 IPv6 完整支持。

## 100. 2026-08-12 TUN 双栈 wire fragmentation 收口

上一节记录的 IPv4-only 限制已经由 TUN 边界重构解决。本轮没有再引入 tun2socket 或第二套
userspace stack，而是让 smoltcp 的 queue device 接受一个完整 IP datagram，再在唯一的
`TunRuntime::send_to_tun` OS 边界按实际 wire MTU 分片：

- IPv4 复制原始 options/header，重新设置 total length、identification、MF/offset 和 header
  checksum；smoltcp 的 IPv4 `Repr::emit` 默认设置 DF，最终分片边界会清除这个默认标志；已经是
  中间分片的包不会被重复分片。
- IPv6 为 smoltcp 生成的 base-header + transport payload 插入 Fragment Header，保留 next
  header、offset、M flag 和 32-bit identification。smoltcp 当前不会产生 extension header；若
  未来新增这类输出，当前 helper 会 fail-closed，必须先扩展 unfragmentable-header 解析。
- ingress 的 IPv6 wire fragments 先在边界重组；重组后的完整 datagram 可以大于 TUN MTU，但仍
  经过独立的 IP 合法性和最大包长度检查，不能绕过普通 wire packet 的 MTU 校验。
- `TunConfig` 对配置 IPv6 时的 MTU `<1280` 提前返回 InvalidInput；IPv4-only TUN 仍支持已有
  576 档测试。最大重组/生成包上限统一到 IPv6 payload-length 能表达的 `65575` 字节。

对应单测新增/调整了 IPv4 8192-byte fragment/reassembly、IPv6 8192-byte Fragment Header
生成与重组、完整 IPv6 datagram 大于 wire MTU 的入队，以及 IPv6 minimum-MTU validation。
Podman workspace 回归为 41 个 harness，`yuhaiin-core` 142 passed、`yuhaiin-runtime` 229
passed、service-chain 14 passed、WireGuard 5 passed（1 个显式 benchmark ignored）。

真实双栈现场仍全部在 Debian VM 的 rootful Podman `--network=none` 中运行；容器内部显式开启
IPv6 sysctl，没有改 VM 宿主网络。IPv4 65507-byte UDP 在 MTU `576/1280/1500/9000/9216`
五档通过；IPv6 65507-byte UDP 在合法 MTU `1280/1500/9000/9216` 四档通过，均验证了 kernel
ingress 分片、Rust ingress 重组、proxy echo、TUN boundary egress 分片和 kernel egress 重组。
IPv6 MTU 576 的 `EINVAL` 是内核协议最低 MTU 约束，已由配置校验提前 fail-closed。现场日志位于
`/root/.cache/yuhaiin-rust-vm/integration/tun-ipv6-mtu-*`，宿主机只编译/同步 binary，未使用
`/tmp`。

## 101. 2026-08-12 Runtime DNS FakeIP PTR 反向查询收口

审计运行时 DNS handler 时发现，FakeIP allocation/reverse 的 store 单测虽然完整，但
`RuntimeDnsHandler` 只把所有查询转换为 `AsyncIpResolver::resolve` 的 A/AAAA 地址结果。这样
预加载的 FakeIP 映射在 socket DNS、DNS hijack 和 TUN DNS 查询 `in-addr.arpa` 或 `ip6.arpa` 时会
被静默丢掉，前端/代理链无法得到 Go server 的本地反向答案。

现在 `FakeIpPools::lookup_ptr_domain` 在一次异步快照后从双栈 reverse view 查找反向名称，
`RuntimeDnsHandler` 在调用上游前优先返回 TTL 60 的 PTR response；未知映射继续走原有 resolver
边界，不伪造答案。新增 runtime 单测先写入持久 FakeIP mapping，再通过真实 DNS wire query 校验
transaction id、PTR name 和 TTL。

Podman workspace 回归重新通过 41 个 harness：`yuhaiin-core` 143 passed、`yuhaiin-runtime`
230 passed、service-chain 14 passed、WireGuard 5 passed（1 个显式 benchmark ignored）。本次
修复没有改变 TUN、协议链或 SQLite schema；所有临时状态继续位于
`~/.cache/yuhaiin-rust`，未使用 `/tmp`。

## 102. 2026-08-12 Go/Rust API history UTC parity

使用缓存中的停止态 Go `state.db`（只读源副本）运行 `make go-api-parity-smoke` 时，除
`connections.history` 外的 read、core mutation 和 error contract 都已经一致；唯一差异是
Rust 旧 checkpoint 中的历史时间按宿主 `+08:00` 输出，而 Go contract 输出 UTC `Z`。

修复分为两层：新建/更新 history 一律使用 UTC RFC3339；加载旧 Rust persistence 或 Go projection
时，`coalesce_history` 将可解析的旧时间规范化为 UTC。因此不会要求用户清空已有 SQLite 或统计
数据，也不会因为宿主机时区不同而让前端看到不同的历史时间。

新增 `history_times_are_serialized_in_utc` 单测，并在 Podman 中重新通过完整 API parity：
`connections.history`、节点/入站/解析器/设置/路由/发布/备份等所有 read 与 core mutation
均 identical；错误矩阵也 identical，订阅更新保持明确的 deferred contract。现场日志位于
`~/.cache/yuhaiin-rust/integration/go-api-parity/`，源库没有被写入。

## 103. 2026-08-12 FakeDNS whitelist/skipCheckList runtime parity

继续对照 Go `pkg/resolver/fakeip.go` 后确认，FakeDNS 不是简单的“始终把上游地址替换成
FakeIP”：whitelist 命中时必须完整绕过 FakeIP；skip-check 只对 A/AAAA 查询跳过上游检查并
直接分配 FakeIP，且 whitelist 优先级高于 skip-check。此前 Rust 只有一个全局
`fakeip_skip_check_upstream` 开关，已经能分配地址，但没有接入 Go 的两个域名列表。

Rust 现在新增 `FakeIpPolicy`，复用 `yuhaiin-trie::DomainTrie` 做父域、规范化和单标签 wildcard
匹配。运行时同时支持两种来源：

- `resolver.fakedns` JSON 的 `whitelist` / `skipCheckList`（以及 snake_case overlay）；
- 旧 Go SQLite 的 `dns_fakedns_lists(kind, value)`，保持 rowid 顺序读取并忽略未知 kind。

当 Go 数据库仍有 `dns_settings` 兼容行时，前端刚写入的 `resolver.fakedns` overlay 现在优先于
旧行的 enabled/range 值，避免 API 返回新配置但 reload 继续使用旧 FakeIP 开关。PTR、HTTPS/SVCB
仍走上游或本地 reverse/service binding 路径，不会被 A/AAAA skip-check 错误屏蔽。

新增 store policy precedence/query 单测，以及 runtime JSON list 和 overlay enablement 单测。随后
使用 Podman 重跑完整 `make workspace-tests`：41 个 harness 全部通过，其中 core 143、runtime
233、store 128（5 个显式 ignored）、WireGuard 5（1 个 benchmark ignored）、service-chain 14；
定向 policy test 也在 `network=none` 容器中通过。所有构建缓存和测试状态继续位于
`~/.cache/yuhaiin-rust`，未使用 `/tmp`。

## 104. 2026-08-12 普通 VLESS/VMess/Trojan outbound service-chain

此前 VLESS、VMess、Trojan 已有 protocol parser、runtime builder 和 Go wire interop，但缺少从
管理 API 写入节点开始，经过真实 inbound、router 再到协议 outbound 的进程级覆盖。本轮把三种
普通 outbound 加入 `service_chain.rs` 同一套可复用 harness：每个用例都在 API 中创建 Go 形状的
`fixed + protocol` chain，启动 HTTP inbound，写入 `example.test` domain rule，然后由 Podman
内的客户端发送 CONNECT 和 payload 到独立的协议 server。三种协议均完成 200 response、payload
echo、connection metadata、match history 和 upload/download totals 断言。

`make service-chain-smoke` 现为 15/15 通过，其中新增协议矩阵为 3/3；已有的
`make go-protocol-interop-smoke` 仍为 6/6。测试构建产物、SQLite fixture 和日志全部位于
`~/.cache/yuhaiin-rust`，宿主机只负责编译，未启动 runtime/proxy，也未使用 `/tmp`。这补齐了
普通 API→inbound→router→VLESS/VMess/Trojan outbound 的主链路证据，但更广的 TLS/WebSocket/UDP
组合和生产协议样本仍保持 checklist 的 `[~]`。

## 105. 2026-08-12 协议 outbound latency probe

在普通 VLESS/VMess/Trojan 的进程链路已经能够 payload echo 后，又把 Go 兼容的
`POST /api/v2/nodes/{id}/latency` 加入同一个 service-chain 测试。fixture 接受第二条协议
连接：第一条使用 `example.test:443` 验证业务 payload，第二条使用 latency 的默认
`http://example.test/health`（端口 80）返回 HTTP 204。这样测试不仅验证出口能传数据，也验证
管理面可以通过对应协议建立延迟探测。

Podman 中 `make service-chain-smoke` 仍为 15/15，VLESS、VMess、Trojan latency 均为成功；
期间曾由 fixture 误把 latency 端口当作 443 导致 connection reset，已修正并保留端口差异断言。
构建和日志仍位于 `~/.cache/yuhaiin-rust`，未使用 `/tmp`。

## 106. 2026-08-12 statistics extended Podman soak

统计并发测试原本固定为 8 个 readers、每个 40 轮 API 查询和 64 轮 payload 写入，能够覆盖
基本并发与重启，但不足以作为较长 lock-pressure 证据。本轮将规模改为环境变量可调，普通
`make stats-concurrency-smoke` 保持原默认值，新增 `make stats-soak-smoke` 使用 12 个 readers、
每个 160 轮查询和 256 轮写入。

本次在 `--network=none` Podman 中通过 2/2：并发查询 connections、total、traffic、telemetry、
history、failed-history 期间持续 TCP 流量；随后关闭并重启同一 SQLite，确认 totals/history
仍可读；另一个测试覆盖 force-stop 期间的统计读取。结果日志在
`~/.cache/yuhaiin-rust/integration/stats-concurrency/`，未使用 `/tmp`。这加强了统计模块的
现场证据，但生产升级期间的真实长期 projection/锁竞争仍保留 `[~]`。

## 107. 2026-08-12 TUN IPv6 extension-header fragmentation

此前 TUN 出方向分片只支持 smoltcp 实际产生的 IPv6 base-header + transport payload，遇到
Hop-by-Hop、Routing 或 Destination Options 会直接返回 unsupported。现在分片布局解析会把
IPv6、Hop-by-Hop、Routing 和 Routing 前的 Destination Options 作为 unfragmentable prefix，
在其后插入 Fragment Header；Routing 后的 Destination Options 进入 fragmentable part，随
完整 datagram 重组。AH/ESP 也不会被猜测长度，而是在 Fragment Header 后保留原始字节。

新增单测覆盖大包分片、Hop-by-Hop + Routing + 后置 Destination Options 的逐字节重组，以及
已有 Fragment Header 的 fail-closed。Podman `network=none` 中三个定向测试和随后完整
`make workspace-tests` 均通过；本次完整 workspace 为 42 个 harness，core 145/145、runtime
237/237、store 128/128、WireGuard 5/5，15/15 service-chain 通过。真实内核对扩展头组合的
端到端现场和更广泛发行版/firewall matrix 仍保留 `[~]`。

## 108. 2026-08-12 TUN fragmentation regression matrix

为避免扩展头分片改动只通过 core 单测，本轮把验证整理成可复现的
`make tun-ipv6-extension-smoke` 目标：Podman `--network=none` 中固定执行扩展头重组、重复
Fragment Header 拒绝和原有 IPv6 大包分片，3/3 通过。随后执行 `YUHAIIN_SKIP_BUILD=1 make
tun-mtu-smoke`，在 disposable user/network namespace 中以 576、1280、1500、9000、9216
五档 MTU 发送最大合法 65507 字节 UDP，五档均完成 target receive、traffic 和 close。

这两个目标都把日志写到 `~/.cache/yuhaiin-rust/integration/`，没有使用 `/tmp`；MTU 回归
证明原有 IPv4/IPv6 TUN 数据面没有被扩展头布局修复破坏，但真实生产 firewall 和真实内核
扩展头组合仍按 checklist 的 `[~]` 处理。

## 109. 2026-08-12 WireGuard adapter 与生产 snapshot parity 收口

WireGuard outbound 继续采用 Cloudflare `boringtun 0.7.1`，不再维护第二份纯 Rust
WireGuard protocol implementation。`crates/yuhaiin-wireguard` 负责把 BoringTun 协议边界接到
smoltcp TCP/UDP userspace stack 和 runtime `AsyncProxy`；Go 形状的 `secretKey`、本地
`endpoint`、peer `publicKey`/PSK/`keepAlive`/`allowedIps`、MTU 和 Cloudflare WARP 的三字节
`reserved` 均可从 SQLite/API 配置加载。认证后的 endpoint roaming 已由本地双 peer 测试固定，
未认证 datagram 不会改变 peer endpoint；真实第三方/WARP peer 和 source-interface policy
仍需外部环境，不能由 `network=none` 测试推断。

本轮在 Podman `--network=none` 中重新通过 `make wireguard-smoke`：5/5 单测通过，覆盖
配置解析、BoringTun handshake/data、reserved marker、双 userspace peer TCP proxy 和
认证后的 endpoint roaming。随后 `make benchmark-wireguard-throughput` 也通过，64 MiB
release packet benchmark 单次得到约 595.5 MiB/s；该数字只作为同机回归基线，结果位于
`~/.cache/yuhaiin-rust/benchmarks/wireguard/`。期间修复了 benchmark 夹具将不带端口的
`127.0.0.1` 解析成 `SocketAddr` 的问题，生产路径未放宽地址校验。

另外，`make production-parity-smoke` 在三个停止态 Go snapshot（`tmp/v2/state.db`、
`tmp/yuhaiin/state.db`、`tmp/aws/yuhaiin/state.db`）上通过：read、core mutation 和 error
matrix 均与 Rust 一致；每个 snapshot 的副本、运行日志和临时状态都写入
`~/.cache/yuhaiin-rust/production-parity/`，源库保持只读。远程 route list 启动刷新导致的
实现差异和工具/license/log 元数据仍按脚本规则归一化，故 checklist 的生产 projection 项
继续保留 `[~]`。

## 110. 2026-08-12 Remote route-list refresh error projection parity

对照 Go `Lists.RefreshContract` 后确认，Go 会为每个 remote route list 把本轮所有 URL 的下载
结果写回 `route_lists_v2.data_json.errorMsgs`：成功时清空旧错误，失败时保留带 URL 的错误消息；
local list 不参与这次写回。Rust 之前只把错误放在 activation response，重启或再次读取
`route.lists`/`route.list.get` 时会丢失，现已补齐。

`route_lists_refresh_value` 现在把 remote list 的 `errorMsgs`、route config、MaxMind metadata
和 activation 一起放入 `mutate_and_reload`；远程缓存仍使用 sibling `.part` + atomic rename，
因此强停不会产生半写入的 list 或管理面快照。新增单测固定 remote/local 隔离和 stale error
清除语义。

随后在 Podman 中完成 `make workspace-tests`：42 harness，core 145、runtime 241、store 128
（5 个显式 ignored）、WireGuard 5（benchmark 单独 opt-in）、15/15 service-chain 全部通过。
`make production-parity-smoke` 继续在三份停止态 Go snapshot 上通过，所有 read、core mutation
和 error matrix 均 identical；副本、日志和临时状态均位于 `~/.cache/yuhaiin-rust`，未使用
`/tmp`。

## 111. 2026-08-12 Route-list refresh scheduler lifecycle

此前 Rust 只有管理 API 手动调用 `/api/v2/route/lists/refresh` 时才会下载 remote route list；
虽然 `refreshInterval` 已能写入 Go 兼容的 `route_extra.refresh_config`，长期运行的服务却不会按
配置自动更新规则。这会让 UI 显示“已配置刷新”但运行时缓存一直停留在旧版本。

现在 `RuntimeService` 启动一个与 DNS、inbound、HTTP API 同级的 route-list refresh owner：

- `refreshInterval` 按 Go 合约解释为分钟，`0` 禁用，非法或溢出 legacy 值 fail-closed 为禁用；
- controller reload 会唤醒任务，使 route-list 配置修改立即重新计算下一次 timer；
- 定时刷新复用当前选中的 outbound transport，并沿用 `route_lists_refresh_value` 的 atomic cache、
  `errorMsgs`、MaxMind metadata、activation 和 `mutate_and_reload` 事务边界；
- 刷新自身产生的 reload event 会被消费后再重新计时，避免自触发忙循环；服务 shutdown 会停止
  owner，避免后台任务脱离 RuntimeService 生命周期。

新增 API 单测覆盖 Go 分钟换算、零值禁用、定时刷新写入 `lastRefreshTime` 和 shutdown；测试通过
真实 `route_extra` 配置写入路径，避免只写 Rust 私有 config 而漏测 Go 兼容优先级。Podman 中
完整 `make workspace-tests` 通过：42 个 harness，core 145、runtime 241、store 128、WireGuard
5、service-chain 15；宿主机只编译 harness，运行状态仍位于 `~/.cache/yuhaiin-rust`，没有使用
`/tmp`。

## 112. 2026-08-12 Route refresh timestamp/single-flight 与选中节点删除

继续按 Go 源码逐项核对后修正两处边界：`RefreshContract` 持久化的
`lastRefreshTime` 使用 `time.Now().Unix()`，因此 Rust 不再把 Unix 毫秒写入
`route_extra.refresh_config.last_refresh_time`；只有 activation 的
`hostIndexRefreshAt` 保持 Unix 毫秒。手动 API 刷新和后台定时刷新共享一个原子 single-flight
guard，重叠调用返回 Go 同样的 `refreshing` 内部错误，避免并发下载和互相覆盖配置。

另修复选中节点删除时的 live selector 生命周期：删除前先关闭对应运行时 proxy，并将 selector
临时切到 direct fallback，再在同一管理 reload 中清理三个 Go selected-node key。这样删除后
不会因为 selector prepare 仍引用已删除节点而产生 `proxy runtime config ... was not found`；
成功 reload 会清掉临时 retarget 状态。Go/Rust 生产 API parity、`api_contract` 进程测试和完整
Podman `workspace-tests` 均通过。

## 113. 2026-08-12 Statistics process dimensions and bounded history projection

继续核对 Go `pkg/statistics` 和 `pkg/route/history.go` 的公开字段后，补齐两处运行时兼容边界：

- failed history 的 key 由 `(protocol, host)` 扩展为 Go 使用的
  `(protocol, host, process)`；同一目标由不同本地进程失败时不会互相覆盖，且通过 inbound
  上下文传入的 process 会同时进入 failed-history 和 telemetry 的 `process` 维度；
- route block history 的 `dumpProcessEnabled` 依据实际条目计算，不再固定返回 `false`；
  block history 继续使用 Go route history 的 1000 条 LRU 边界，failed history 则保留 Go
  SQLite 的全量持久化语义，仅在 API 查询结果处按 `LIMIT 1000` 截断，避免同时间戳数据因
  Rust 侧提前淘汰而和生产数据库不一致。

新增单测覆盖不同 process 的失败分组、失败 telemetry process 维度和 block history 标志。
之后用 Podman 重跑完整 `make workspace-tests`：42 个 harness，core 145、runtime 243、store
128、WireGuard 5、service-chain 15 全部通过；运行状态和日志仍位于
`~/.cache/yuhaiin-rust`，没有使用 `/tmp`。
随后再次执行 `make production-parity-smoke`，三份停止态 Go `state.db` 的 read、core
mutation、error matrix 和全部统计 response 均 identical；结果位于
`~/.cache/yuhaiin-rust/production-parity/`。
另外重新通过 `make go-protocol-interop-smoke` 的 6 个 Podman 互操作 harness，覆盖 Go
Yuubinsya TCP/UOT/native UDP/Ping、Go WebSocket→HTTP/2、HTTP/2 v1、VLESS、VMess 和 Trojan；
`make tun-chain-service-smoke tun-api-process-smoke stats-soak-smoke` 也通过，分别固定
TUN→TLS→HTTP/2→Yuubinsya、真实前台 binary 的 TUN API 开关、以及 12 readers×160 rounds
和 256 writes 的 SQLite 统计并发/强停恢复。

## 114. 2026-08-12 WireGuard userspace UDP session regression

继续检查 WireGuard 的“纯 UDP”是否只停留在协议包加解密层后，发现原有双 peer 测试虽然覆盖
BoringTun data round-trip，却没有把 `AsyncProxy::open_datagram`、smoltcp UDP socket、加密
封装、对端解封装、反向回包和 session close 串起来。现已在同一个 Podman 双 userspace peer
夹具中补齐完整 UDP echo：第一端通过 WireGuard UDP session 发往第二端虚拟地址，第二端通过
自己的 UDP session 收到后回包，第一端收到原 payload；同时保留 TCP 建连/关闭、reserved
marker、keepAlive 配置解析和 authenticated endpoint roaming 断言。

`make wireguard-smoke` 现为 5 passed、1 ignored benchmark，Podman 日志位于
`~/.cache/yuhaiin-rust/integration/wireguard/podman.log`。这证明 Cloudflare BoringTun
adapter 的本地 TCP/UDP data plane 和 runtime session 生命周期；真实第三方/WARP peer 的
公网 handshake、keepalive、NAT endpoint 变化仍需要用户自己的外部 peer 配置，不能从
`network=none` 的确定性测试推断。对照 Go `Config` 可确认它只有 `secretKey`、`endpoint`、
`peers`、`mtu`、`reserved`，没有 source-interface 配置，因此 Rust 不额外引入不兼容字段。

## 115. 2026-08-12 WireGuard external peer smoke harness

为了不把真实 WARP/第三方 peer 的验证留成一次性手工命令，新增了
`crates/yuhaiin-wireguard/tests/external.rs` 和 `scripts/integration/wireguard-external.sh`。
它们不携带任何密钥或公网配置：调用者通过
`YUHAIIN_WIREGUARD_EXTERNAL_CONFIG` 挂载自己的 Go 形状 JSON，通过
`YUHAIIN_WIREGUARD_EXTERNAL_TCP_TARGET` 或 `YUHAIIN_WIREGUARD_EXTERNAL_UDP_TARGET` 指定
目标；脚本在 Podman `--network=host` 中运行，支持 TCP 建连、可选请求写入，以及 UDP 发包/回包。
没有配置时脚本明确失败，不会把“未测公网”报告成成功。

例如在用户已经有 WARP 配置时可以执行：

```bash
YUHAIIN_WIREGUARD_EXTERNAL_CONFIG="$HOME/.cache/yuhaiin-rust/warp.json" \\
YUHAIIN_WIREGUARD_EXTERNAL_TCP_TARGET=1.1.1.1:443 \\
make wireguard-external-smoke
```

本轮只验证了 harness 编译和普通 WireGuard Podman 回归；没有伪造第三方账号/私钥，
因此公网 handshake、keepalive 和 NAT roaming 仍等待用户提供真实 peer 后再记录结果。

## 116. 2026-08-12 Debian VM rootful data-plane recheck

使用用户提供的 Debian VM `192.168.122.2`，把当前构建的 smoke binary 和脚本放入 VM 的
`~/.cache/yuhaiin-rust` 后重新执行，运行过程没有使用宿主机 TUN 或宿主机网络命名空间：

- rootful TUN：普通 TCP echo、3 次 disable/reload/reopen、force-stop teardown 全部通过；
- rootful TUN UDP：MTU 1280、8192 字节 payload、UDP-first 顺序通过，target 原样收到；
- rootful TUN chain：`TUN inbound → TLS → HTTP/2 → Yuubinsya → echo` 通过；
- transparent service：iptables TPROXY、native nft TPROXY、IPv6 REDIRECT 三种组合均通过，
  包含 original destination、两个 UDP source flow、reply/rebind、monitor counters 和 close。

日志分别保存在 VM 的
`~/.cache/yuhaiin-rust/integration/vm-tun-service*` 和
`~/.cache/yuhaiin-rust/integration/vm-transparent/`。这增强了真实 rootful Linux 的权限、
路由和 firewall 证据，但仍不把生产发行版数量或 IPv6 extension-header 特殊报文现场宣称为
全覆盖；后者需要额外的 raw packet fixture。

## 117. 2026-08-12 Current workspace verification and cache boundary

新增外部 WireGuard harness 后，在 Podman 中重新执行 `make wireguard-smoke` 和
`make workspace-tests`：WireGuard library 为 7 passed、1 ignored benchmark；workspace 为
43 个 harness，core 145、runtime 243、store 128、service-chain 15，外部 peer harness 的
2 个测试保持显式 ignored，0 失败。`make fmt-check`、`make clippy`、shell syntax check 和
`git diff --check` 也通过。

宿主缓存检查时发现 `~/.cache/yuhaiin-rust` 曾达到约 35G，其中约 22G 是可重建的 debug
测试依赖；已将精确的 host debug deps、musl debug deps 和已延期 macOS target 移入桌面回收站，
保留最终二进制、SQLite/GeoIP fixture、验收日志和 `~/.cache/yuhaiin-rust` 下的可复用测试状态，
当前缓存目录约 14G。后续构建会按需重新生成测试依赖，不使用 `/tmp`。

## 118. 2026-08-12 Rust GitHub Actions release matrix

补充 `.github/workflows/rust.yml`，结构与 Go 版 workflow 保持一致但只覆盖当前 desktop
目标：Linux `x86_64/aarch64-unknown-linux-musl`、Darwin `x86_64/aarch64`、Windows
`x86_64/aarch64`。Linux job 下载带 SHA-256 固定校验的 musl-cross toolchain，再由 Cargo
按 target linker 编译；其余平台使用对应 GitHub hosted runner 和 Rust target。每个 job 都只
上传一个经过命名的 runtime 二进制，名称与 `crates/yuhaiin-runtime/src/update.rs` 的
`release_os/release_arch` 结果一致：

```text
yuhaiin-linux-amd64
yuhaiin-linux-arm64
yuhaiin-darwin-amd64
yuhaiin-darwin-arm64
yuhaiin-windows-amd64.exe
yuhaiin-windows-arm64.exe
```

`checks` job 先执行格式检查、Clippy，并通过现有 `make workspace-tests` 在 Podman 中运行
workspace harness；所有 release build 使用 `--locked --all-features`。`v*` tag 会发布稳定
release，push 到 `main` 会生成与 Go 版相同语义的 rolling `main` prerelease，并强制移动
`main` tag。发布 job 合并六个二进制、生成不带目录前缀的 `checksums.txt`（否则运行时的
asset-name 精确匹配会失败）和变更日志。

本地已完成 YAML 解析、六个 target/asset 名称检查、Cargo metadata 和 `git diff --check`；
GitHub runner 的 macOS SDK、Windows ARM64 linker 以及 musl-cross 下载需要 workflow 首次
运行后再记录为现场证据，不能在本机交叉编译成功的假设上提前标 `[x]`。

## 119. 2026-08-12 macOS launchd 与 Windows Service 生命周期

桌面端安装/更新现在不只发布跨平台二进制，而是保留 Go service command 的生命周期边界：

- macOS 使用 `/Library/LaunchDaemons/com.asutorufa.yuhaiin.plist`、`launchctl
  bootstrap/bootout/kickstart`，安装会写入 Go 兼容的 `-host/-path/-nfs-mode` 参数，
  `health` 检查 launchd 状态与未认证 `/health`，`rollback` 恢复上一份 update backup；
- Windows 使用纯 Rust 的 windows-service crate（底层 Windows API，不依赖 C 运行库），
  服务名为 yuhaiin，LocalSystem 自动启动，配置描述、失败自动重启、停止等待、删除等待、
  SCM 状态和 /health 均由 Rust binary 管理；
- Windows update API 先把当前 exe 复制为独立的 yuhaiin.update-helper.exe，helper
  通过 SCM 停止服务后再替换 exe，启动失败会用 `.update-backup` 恢复；macOS updater
  对应执行 launchd bootout、替换、bootstrap/kickstart。成功更新保留单份旧 binary，供
  `rollback` 使用，下一次更新会原子替换这份 backup；
- Linux updater 仍使用 systemd restart；显式的
  YUHAIIN_UPDATE_STOP_COMMAND/YUHAIIN_UPDATE_RESTART_COMMAND 只作为运维覆盖入口，
  Windows 使用 cmd.exe，Unix 使用 sh，不再让 Windows 默认路径调用 Unix shell。

新增的跨平台单测覆盖服务参数、launchd plist、Windows ServiceInfo/启动参数和更新选择逻辑。
本轮实际验证：

- make workspace-tests 在 Podman 中通过：43 个 harness，core 145、runtime 243、store
  128、WireGuard 7（1 个 benchmark ignored）、service-chain 15，0 失败；
- make clippy、make fmt-check、git diff --check、workflow 六 target/asset YAML 检查、
  ast-grep cfg 审计均通过；
- cargo check --locked --tests --target x86_64-pc-windows-gnu -p yuhaiin-runtime
  --all-features 通过，包含 Windows Service test-cfg；Linux host 的 Windows GNU 检查
  只验证编译门禁，不替代 Windows SCM 现场；
- macOS launchd 和 Windows SCM 的真实 root/admin 安装、更新、回滚仍必须在对应平台权限
  环境或 GitHub runner/VM 现场执行，不能用宿主 Linux 的交叉编译结果冒充现场验收。

所有可复现测试状态继续写入 ~/.cache/yuhaiin-rust，不使用 /tmp。

## 120. 2026-08-12 TUN API 实时开关与 musl 当前轮复核

本轮针对“inbound/TUN 实时开关可能只改了 SQLite、没有切换真实设备”的风险重新走了前台
二进制路径。`make tun-api-process-smoke` 在 Podman disposable user/network namespace 中启动
真实 runtime，先通过 `/api/v2/inbounds/{id}` 写入 disabled TUN，再依次执行
enabled、disabled、enabled、disabled；夹具直接读取容器内 `/proc/net/dev`，确认接口按每次
reload 出现或消失，结果为 `1 passed, 0 failed`。因此当前代码不需要为这个已覆盖的竞态再引入
额外 supervisor 分支；TUN owner 仍由 `run_desktop_tun_supervisor` 管理旧设备的退出、配置重读
和新设备创建，正常 listener reload 与 TUN device teardown 保持隔离。

同一轮执行 `make build MUSL=1`，使用 Rust toolchain 的 `rust-lld` 完成
`x86_64-unknown-linux-musl` debug runtime 构建，产物位于
`~/.cache/yuhaiin-rust/cargo-target/x86_64-unknown-linux-musl/debug/yuhaiin`。这只证明
target/linker 构建门禁，不替代 Podman 内的 runtime 运行测试；所有集成测试状态仍留在
`~/.cache/yuhaiin-rust`，没有使用 `/tmp`。

## 121. 2026-08-12 S3 backup object contract

对照 Go `pkg/app/backup.go`、`pkg/s3/s3.go` 和 `pkg/contract/backup/types.go` 后，补上了此前
Rust API 的真实功能缺口：`backup.run` 过去无论配置如何都只创建本地 SQLite 文件，
`backup.restore` 也只接受本地路径；这会让前端配置了 S3 后得到错误的“成功”语义。

新增 `crates/yuhaiin-backup`，使用纯 Rust 的 `reqwest + rustls-rustcrypto + HMAC/SHA-256`
实现 S3 Signature V4，并保留 Go 的 camelCase 配置字段、path-style endpoint、storage class、
`{instanceName}-state.db` object name 和 BLAKE2b-256(`state.db || json(S3)`) 的
`lastBackupHash` 语义。运行流程现在是：

- `backup.run` 先用 SQLite `VACUUM INTO` 得到一致快照；S3 未启用时直接报错，hash 未变化时跳过上传，
  上传成功后才把 `lastBackupHash` 写回同一份 Go backup config；上传失败不会返回成功；
- `backup.restore` 仍兼容显式本地 `path/source/file`，空请求则按 backup config 下载同名 S3
  object 到 `~/.cache/yuhaiin-rust/backups/`，随后沿用 managed-service restore/restart 边界；
- backup crate 的单元测试固定 SigV4 signing key、路径编码和 camelCase；local compatible
  endpoint wire test 覆盖真实 HTTP PUT/GET、Authorization、payload hash 和 storage class；
  runtime API test 覆盖 `backup.run` 上传、`lastBackupHash` 持久化和空参数 restore 下载。

真实 AWS/MinIO 权限现场仍明确标为 `[~]`。选中 outbound proxy 的连接路径已经补齐：
`yuhaiin-backup::S3Transport` 只负责签名请求，runtime 的 `ProxyS3Transport` 通过同一份
`AsyncProxy` 建立 HTTP/HTTPS 请求，并复用 direct、HTTP、SOCKS5、TLS/HTTP2、Yuubinsya 和
WireGuard 等已有出口；这样没有在 backup crate 里复制 proxy 选择逻辑。runtime API 的 local
compatible endpoint test 覆盖了该路径，真实 AWS/MinIO 的权限、重试和服务端行为仍需要现场验收。

本轮 `make workspace-tests` 在 Podman 中最终执行 45 个 harness：core 145、runtime 248、
store 128、WireGuard 7（1 个 benchmark ignored）、service-chain 15，0 失败；S3 backup
新增测试没有改变其它 inbound→router→outbound 链路的通过状态。

## 122. 2026-08-12 WireGuard 与管理面代理链当前回归

WireGuard 按用户决定固定采用 Cloudflare BoringTun，不再计划维护纯 Rust WireGuard 协议实现。
`crates/yuhaiin-wireguard` 的 `boringtun 0.7.1` 负责 Noise handshake、session、定时器和 packet
crypto；smoltcp 只作为 userspace IP/TCP/UDP adapter。依赖审计显示 `ring` 只由 BoringTun 引入，
属于本次明确允许的 Cloudflare 外部实现例外。

本轮在 Podman 中重新执行 `make wireguard-smoke`，结果为 7 passed、1 个显式 ignored benchmark；
`make workspace-tests` 结果为 45 个 harness，runtime 248、core 145、store 128、WireGuard 7、
service-chain 15，0 失败。外部第三方/WARP peer 的两个测试仍要求用户提供真实配置，不把
`network=none` 双 peer 结果冒充公网兼容性。

同时完成了 S3 管理面 transport：`backup.run`/空参数 `backup.restore` 会先按 Go 的 TCP/UDP 选择
构造短生命周期 outbound，再通过该出口发送签名的 HTTP/HTTPS S3 请求；响应大小、chunked body、
timeout 和错误状态均有边界。GitHub Actions checks job 也显式安装并打印 Podman 版本，避免 CI
未预装 Podman 时在真正测试前失败。

backup crate 本轮为 6 个单元测试加 1 个 local compatible endpoint wire test；runtime 新增的
proxy transport、chunked/error boundary 和 API S3 测试均在上述 workspace harness 中通过。

本轮格式检查、`cargo check --locked --workspace --all-features --offline`、Clippy `-D warnings`、
`git diff --check` 和 Podman workspace tests 均通过。该历史检查点的缓存目录约 27G，其中约 18G 为可重建的
`cargo-target`；仍只使用 `~/.cache/yuhaiin-rust`，没有使用 `/tmp`，后续应按精确 target/scenario
目录回收，不做宽泛递归删除。

## 123. 2026-08-12 WireGuard 真实 runtime 链路与 smoltcp TCP EOF 修复

在进程级链路夹具中把验证范围从单独的 `build_proxy` 扩展到真实 `yuhaiin` 子进程：同一个
Podman namespace 内由 BoringTun userspace peer 提供 `192.0.2.1` 虚拟 TCP endpoint，runtime
接收 HTTP CONNECT，经 CIDR route 选中 WireGuard outbound，完成 Noise handshake、加密 TCP
echo、连接 metadata 和 node HTTP latency probe。新增可复现入口：
`make wireguard-chain-smoke`，其构建、runtime、SQLite 和网络执行均在缓存挂载的 Podman 中，
不使用宿主 runtime 或 `/tmp`。

夹具首先发现了一个与 WireGuard 无关但会影响所有 userspace TCP outbound 的真实问题：
`Driver::process_sessions` 使用 smoltcp 的 `may_recv()` 判断数据可读；该函数在 Established
状态下即使接收缓冲区为空也返回 true，导致零长度 `Read` 被推入异步流，HTTP inbound 将其
解释为 EOF 并关闭连接。已改为 `can_recv()`，只在确实有 payload 时转发；现有 EOF/close
生命周期仍由 session close 路径处理。

回归证据：`make wireguard-chain-smoke` 在 Podman 通过 1/1；随后 `make workspace-tests`
在 Podman 通过 46 个 harness，core 145、runtime 249、store 128、WireGuard 7（1 个 benchmark
ignored）、service-chain 15，0 失败。workspace 编排将这个进程级 loopback harness 与
service-chain 一样放入独立 host-network 容器组，避免大量普通 harness 共用 `--network=none`
时触发环境已知的 loopback reset；仍没有把 host-network 容器等同于宿主机运行。

最后检查 `~/.cache/yuhaiin-rust` 约 31G，其中约 22G 为可重建的 Cargo target（debug 约 18G），
集成日志和状态仍全部位于该 cache 根目录；没有使用 `/tmp`，也没有执行宽泛递归删除。

## 124. 2026-08-12 VLESS-over-TLS Go 互操作

为补齐协议组合矩阵，新增 `go_transport_interop.rs` 和独立的 Go TLS/VLESS fixture。
测试由 Rust VLESS client 发起：先通过 `RustCryptoTlsProxy` 完成 TLS 1.2 握手，再发送
VLESS request；Go server 校验 UUID、command、network 和 domain destination，回写 VLESS
response header 后完成 `ping/pong` payload round-trip。证书只在该 fixture 内生成，client
明确使用 `insecure_skip_verify`，不会改变生产配置的 CA/校验默认值。

`scripts/integration/go-protocol-interop.sh` 现在在宿主只编译 ignored harness，并在 Podman
中执行 7 个互操作项：Yuubinsya TCP/UOT/native UDP/Ping、WebSocket→HTTP/2、HTTP/2 v1、
VLESS、VLESS-over-TLS、VMess、Trojan；本轮 `7/7` 通过。Go 的 `GOTMPDIR`、fixture ready
文件、Rust harness 日志和构建状态都位于 `~/.cache/yuhaiin-rust`，没有使用 `/tmp`。
该证据仍是 protocol wire/transport 组合验证，不替代更广的 runtime listener、UDP 和
生产证书/代理链现场矩阵，因此 VLESS/VMess/Trojan 总项继续保持 `[~]`。

## 125. 2026-08-12 Go VLESS UDP framing 互操作

新增 `go_vless_udp_interop.rs` 和 `vless_udp_go_client.go`，用 Go 仓库中的真实
`fixedv2 -> vless.PacketConn` client 连接 Rust wire fixture。fixture 校验 VLESS v0 UUID、
UDP command、domain destination `example.com:53`，然后按 Go 的 UDP contract 完成
`uint16 length + payload` 的 echo。该测试在 Podman host-network 场景中通过，修正前会把
Rust 发送的 `[0,0]` response header 读成空 UDP datagram，Go client 明确返回空响应。

修复将 VLESS response header 限定在 TCP stream：Rust UDP inbound 不再先写 response header，
`VlessDatagram` outbound 也不再等待该 header；UDP 仍保持有界的 length-prefixed packet，TCP
response version/addon 校验和现有 TLS/WebSocket/HTTP2 transport 行为不变。协议单测、runtime
VLESS UDP inbound 回归和完整 `make go-protocol-interop-smoke` 均通过，后者当前为 9/9：
Yuubinsya 四种模式、WebSocket→H2（普通/TLS）、H2 v1、VLESS TCP、VLESS UDP、VLESS-over-TLS、
VMess 和 Trojan。所有 Go scratch、fixture、日志和构建缓存继续位于 `~/.cache/yuhaiin-rust`，
没有使用 `/tmp`。

## 126. 2026-08-12 MinIO S3 backup/restore 现场 smoke

新增 `make s3-minio-smoke`，把此前只经过 local compatible endpoint 的 S3 管理面再推进到真实
S3-compatible server。脚本只在宿主机编译 Rust binary；MinIO、bucket helper 和 runtime 全部运行在
同一个 disposable Podman network，状态、日志、Cargo target 和 Go scratch 均放在
`~/.cache/yuhaiin-rust`，不使用 `/tmp`。

本轮实际通过的步骤包括：启动 MinIO、用 `mc` 创建 bucket；通过 Rust API 写入 Go camelCase
`backup.config`，执行 `backup.run` 并用 `mc stat` 校验 `{instanceName}-state.db` object；读取
64 位十六进制 `lastBackupHash`；最后调用空参数 `backup.restore`，确认 Rust 从 MinIO 下载到
cache-backed `backups/remote-state.sqlite`，并返回 managed-service restart contract。这个 smoke
覆盖了真实 HTTP endpoint、path-style object URL、SigV4 Authorization、PUT/GET 及 restore
生命周期，不把 local compatible endpoint 测试冒充 MinIO 行为。

真实 AWS account、IAM 权限/拒绝矩阵、网络重试和更多损坏/异常快照仍保留在 checklist 的 `[~]`，
因此本轮只把 MinIO 现场从未验证更新为已验证，不宣称 AWS 兼容性已经完成。

## 127. 2026-08-12 workspace 回归与缓存边界收口

在 VLESS UDP framing 和 MinIO smoke 收口后，重新执行 `make workspace-tests`：Podman 中运行 48 个
harness，core 145、runtime 252、store 128、service-chain 16、WireGuard 7 和 WireGuard runtime
chain 2 全部通过；外部第三方/WARP 的 2 个测试、Go 互操作 harness 等需要外部条件的项目仍按
显式 `ignored` 处理。静态检查 `cargo fmt --all -- --check`、脚本 `bash -n` 和 `git diff --check`
也通过。

缓存维护脚本发现 debug cleanup 的旧进程探测会把自身的 grep 命令误判为 cargo/rustc，已改为读取
`/proc/*/cmdline` 并只匹配实际 cargo/rustc 进程；随后安全清理了
`~/.cache/yuhaiin-rust/cargo-target/debug` 下的 `deps/build/.fingerprint/examples/incremental`，
保留 debug binary、release/musl target、fixtures 和集成日志。缓存从约 21 GiB 降到约 9.4 GiB，
仍没有使用 `/tmp`。

## 128. 2026-08-12 VLESS/VMess/Trojan runtime UDP 组合矩阵

在 Go wire interop 已覆盖 VLESS UDP、而 runtime service-chain 主要验证 TCP 的基础上，补充了
`runtime_protocol_outbounds_round_trip_through_mixed_udp_router`。同一测试按 VLESS、VMess、Trojan
三种 outbound 分别创建真实 `yuhaiin` 子进程、mixed UDP inbound、domain/CIDR router 和协议 TCP
listener；UDP inbound 先解析 SOCKS5 UDP frame，再由 runtime 选择协议 outbound，协议服务校验 UDP
command、目标 `8.8.8.8:5353` 和加密/长度 framing，最后把 payload 回传到客户端，并检查 connection
metadata、selected node、mode 和 match history。

`make service-chain-smoke` 在 Podman host-network 中最终通过 16/16；之前的 UDP 首次调试还捕获了
测试地址被默认 LAN direct 规则抢先匹配的问题，改用非 LAN 的 `8.8.8.8` fixture 后确认协议
outbound 确实被打开。该组合把 checklist 中 VLESS/VMess/Trojan 的 UDP runtime 主路径补齐；更广的
TLS/WebSocket/HTTP2、不同目标地址族和真实远端 listener 组合仍保留为 `[~]`，不把单一 fixture
外推成完整 Go 兼容性。

本轮新测试及所有 service-chain 状态均写入 `~/.cache/yuhaiin-rust`，没有使用 `/tmp`。

## 129. 2026-08-12 Trojan WebSocket transport builder 与共享 stream transport

对照 Go 的 contract-point 组合方式检查 outbound builder 后，补上了一个实际兼容缺口：Go
允许 `fixedv2 -> websocket -> trojan`（以及可选 `tls`）这样的协议层组合，Rust 原先会在
`GoProxyRuntimeConfig::ensure_base_transport` 处把 WebSocket 误判为只能交给
`yuhaiin-chain` 的通用 chain。现在 runtime 对 Trojan WebSocket 进入专用 builder，底层固定
endpoint、TLS、WebSocket transport 和 Trojan framing 按同一 stream 顺序组装；VLESS/VMess/Trojan
三者共用 transport-upstream builder，TLS feature 缺失时仍明确 fail-closed。

新增 `runtime_builds_trojan_over_websocket_transport_chain`，并让 store 的 base-transport guard
允许 Trojan WebSocket；真实 service-chain 的 protocol matrix 也加入 Trojan WebSocket，执行
HTTP inbound → router → WebSocket handshake → Trojan framing → payload echo。第一次 workspace
回归确实捕获了 guard 未同步的问题，修复后 `make workspace-tests` 在 Podman 通过 48 个 harness：
core 145、runtime 253、store 128、service-chain 16、WireGuard 7、WireGuard runtime chain 2，
0 失败；`make fmt-check`、Clippy `-D warnings`、ast-grep outline 和 `git diff --check` 也通过。

这只证明 Trojan WebSocket builder 和现有协议边界已经接通，不把单元 builder 证据外推为
真实远端 Trojan WebSocket listener/UDP/地址族完整矩阵；VLESS/VMess/Trojan 总项继续保持
`[~]`，下一步仍是更广 runtime listener/outbound 与远端组合现场。

## 130. 2026-08-12 TLS + WebSocket + Trojan runtime 组合

在上一轮只覆盖明文 WebSocket transport 的基础上，继续把 Go 允许的
`fixedv2 -> tls -> websocket -> trojan` 组合接入同一个真实 service-chain matrix。测试 fixture
使用 RustCrypto TLS server acceptor（只用于测试证书，client 侧明确 `insecure_skip_verify`），然后
接受 HTTP/1.1 WebSocket upgrade，再由同一 Trojan framing handler 校验两条连接的目标地址、payload
和 health request。runtime builder 复用已经存在的 stream transport 顺序：fixed endpoint → TLS →
WebSocket → Trojan，不复制协议实现，也不改变普通 Trojan/VLESS/VMess 的选择逻辑。

`make service-chain-smoke` 在 Podman host-network 中通过 16/16；protocol matrix 现在包含
Trojan→WebSocket 和 TLS→WebSocket→Trojan 两条 TCP 真实链路。随后完整 `make workspace-tests`
再次通过 48 个 harness：core 145、runtime 253、store 128、service-chain 16、WireGuard 7（1 个
benchmark ignored）、WireGuard runtime chain 2，0 失败。workspace 编排也固定让共享持久化状态的
`api_reload_flow` harness 使用 `--test-threads=1`，避免两个 reload case 互相覆盖端口和配置名。
工作区状态和日志仍位于 `~/.cache/yuhaiin-rust`，没有使用 `/tmp`。

这补齐了当前主要 transport builder 的本地组合证据，但不把它外推为真实远端证书、地址族、UDP
或更广 listener/HTTP2 组合的完整 Go 兼容性；VLESS/VMess/Trojan 总项继续保持 `[~]`。

## 131. 2026-08-12 VLESS/VMess TLS + WebSocket runtime 矩阵

继续沿用上一轮的共享 stream transport builder，把真实 service-chain fixture 从 Trojan 扩展到
VLESS 和 VMess。测试服务端把同一套协议 framing handler 泛型化到 `AsyncRead + AsyncWrite`，因此
普通 TCP、TLS+WebSocket TCP、普通 UDP-over-stream 和 TLS+WebSocket UDP 使用相同的 wire 校验，
不会因为测试 fixture 复制协议逻辑而掩盖 transport 差异。

`make service-chain-smoke` 在 Podman 中通过：VLESS/VMess/Trojan 普通及 TLS+WebSocket TCP 共 7/7；
VLESS/VMess 普通及 TLS+WebSocket UDP 共 5/5。每条真实链路都经过 API 配置、HTTP 或 mixed inbound、
domain router、协议 outbound、payload echo、connections metadata/match history 和 node latency；
Trojan WebSocket 继续明确不伪造 UDP 能力。随后 `make workspace-tests` 仍为 48 个 harness，core
145、runtime 253、store 128、service-chain 16、WireGuard 7、WireGuard runtime chain 2，0 失败。

这把当前 Rust builder 支持的 VLESS/VMess/Trojan TLS/WebSocket 主路径从单元证据推进到真实 runtime
TCP/UDP 组合；远端 listener、HTTP/2 组合、地址族、生产证书和完整 Go 现场矩阵仍保留 `[~]`。

## 132. 2026-08-12 直接替换边界复验与缓存回收

为避免只依赖历史日志，本轮在当前 `HEAD` 重新执行了三类最接近直接替换 Go 后端的现场：

- `make production-parity-smoke` 使用停止态 Go v5、v6 和 AWS-shaped 三份 SQLite 快照，三份均完成
  `info/settings/nodes/inbounds/resolvers/routes/publishes/connections` 读取、核心 mutation 和错误矩阵
  对照，结果均为 identical；源数据库未被修改，副本和日志仍在 `~/.cache/yuhaiin-rust`。
- `make go-live-flow-parity-smoke` 与 `make go-rust-stats-smoke` 均通过，确认 Go/Rust 真实
  inbound→router→outbound 流量、connections、traffic/history/telemetry 和共享 SQLite 统计接管仍可用。
- `make tun-chain-service-smoke` 通过真实 TUN inbound → fixed → TLS → HTTP/2 → Yuubinsya → echo，
  同时确认 TUN owner 的 open、route mode、traffic 和 close 生命周期。

依赖边界也重新核对：WireGuard 只在明确允许的 BoringTun 路径中引入 `ring`；SQLite 使用已验证的
`rusqlite + bundled SQLite`，普通 TLS/HTTP 数据面仍走 RustCrypto，不引入 native-tls/OpenSSL。
缓存检查时约 18 GiB，其中可重建的 debug 依赖中间产物约 8 GiB；通过仓库维护脚本仅删除
`cargo-target/debug/deps/build/.fingerprint/examples/incremental` 后降至约 9.8 GiB，debug 二进制、
release/musl target、fixtures 和集成状态均保留，没有使用 `/tmp`。

## 133. 2026-08-12 Go/Rust VLESS、VMess、Trojan transport 互操作矩阵

在 runtime 的本地 service-chain 矩阵之外，补齐协议层的跨语言双向证据。新增 Go VLESS client
连接 Rust wire fixture 的普通 TCP 和 `TLS → WebSocket` 两条测试；已有 Rust VLESS client→Go
server 的 TLS 测试同时加入 TLS+WebSocket 变体。VMess 和 Trojan 也分别加入 Go client→Rust
wire fixture 的普通与 `TLS → WebSocket` 测试。TLS fixture 使用 RustCrypto/rustls 或 Go 标准库
测试证书，只在测试中允许跳过证书校验，不改变生产默认校验策略。

本轮先发现固定 `24446/24447` 端口会让重跑受到残留进程影响，随后把 VLESS-over-TLS fixture
改为监听 `127.0.0.1:0`，ready 文件返回实际地址，并用 child guard 在断言失败时回收 Go 子进程。
`make go-protocol-interop-smoke` 在 Podman host network 中通过 8 个 harness、14/14 个测试用例：
Yuubinsya 及 WebSocket/H2、H2 v1、VLESS 双向普通/TLS/TLS+WebSocket、VLESS UDP、VMess 普通/
TLS+WebSocket、Trojan 普通/TLS+WebSocket。`make clippy`、Rust/Go 格式检查和 `git diff --check`
也通过；Go scratch、ready 文件、日志和构建状态仍全部位于 `~/.cache/yuhaiin-rust`，没有使用
`/tmp`。

这只扩展了 wire/transport 的真实 Go 兼容性证据，不把测试证书或 loopback fixture 外推为生产
远端证书、HTTP/2 listener、地址族、UDP+TLS/WebSocket 或第三方节点的完整矩阵；这些边界继续由
checklist 中的 `[~]` 项跟踪。

## 134. 2026-08-12 前台启动、TUN API 和进程替换路径复验

本轮没有重复修改已经闭合的启动/TUN supervisor 逻辑，而是按用户实际入口重新在 Podman 复验：

- `make startup-logs-smoke` 不传命令，也不注入 `YUHAIIN_DB`、`YUHAIIN_HTTP` 或 `YUHAIIN_QUIET`，真实前台二进制依次输出 database、HTTP bind、runtime ready、shutdown 和 stopped；因此默认 `./yuhaiin` 不是无输出等待。只有显式 `YUHAIIN_QUIET=1` 才关闭前台进度。
- `make tun-api-process-smoke` 通过真实 `/dev/net/tun` 和 `/proc/net/dev` 复验新增 TUN 的 disabled → enabled → disabled → enabled → disabled，确认 API 写入会唤醒 owner、创建并关闭设备，而不是只保存 SQLite 配置。
- 完整 `make workspace-tests` 仍在 Podman 通过 48 个 harness：core 145、runtime 254、store 128、service-chain 16、WireGuard 7（1 个 benchmark ignored）、WireGuard runtime chain 2，0 失败；运行状态仍位于 `~/.cache/yuhaiin-rust`，没有使用 `/tmp`。
- Linux `/proc/<pid>/exe` 在进程被替换后可能带有 ` (deleted)` 后缀；route-list process membership 和 loopback process guard 现在统一按去除该后缀后的路径比较，并由 route/loopback 单元回归覆盖。

本轮仍没有把 rootful firewall/IPv6 extension-header 现场、第三方 WARP peer、真实 AWS、跨平台权限和远程 Actions 误报为完成；它们继续保持 checklist 的 `[~]`。
