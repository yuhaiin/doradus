# Go SQLite 兼容字段报告

状态：生产接管与 fixture/import 基线，2026-08-10；已补 production-shaped snapshot、同名 legacy table 处理、Go v1 legacy 显式升级、Rust schema v3 Geo route 字段、Go v6 typed compatibility views，以及真实 Go schema-7 additive user/subscription-link 状态的保留式接管。

兼容版本边界：Rust 只接受已审计的 Go schema version `0..=7`；v7 仅新增用户/订阅关联表，Rust 当前不实现订阅刷新，但会保留这些表和数据不删除、不重建。已兼容真实 Go 生产快照中 `metadata.schema_version=6`、`migrate` 已记录增量版本 7 的形态，但仅在发现已知 `subscription_nodes_v2`/`subscription_users_v2` 表时放行；其他版本不一致和更高版本仍 fail-closed，避免把未来 Go 数据按旧 schema 静默降级读取。

来源是当前 Go `pkg/storage/sqlite/migrations.go` 的 plain contract schema，当前 fixture 标记为 migration version 6。最小样例位于 `crates/yuhaiin-store/tests/fixtures/go_sqlite_v6_minimal.sql`，生产形状 snapshot 位于 `crates/yuhaiin-store/tests/fixtures/go_sqlite_v6_production_snapshot.sql`；对应测试分别为 `imports_go_v6_fixture_into_typed_records_idempotently` 和 `imports_production_shaped_go_snapshot_without_losing_legacy_tables`。另有 `go_sqlite_v6_fakeip_edge_snapshot.sql` 作为普通 CI 使用的 compact edge fixture，固定覆盖过期 v4/v6 rows、空的可见映射池、双栈 cursor 和未知 JSON 字段；它不是完整真实生产库。Go v5 sparse fixture `go_sqlite_v5_sparse.sql` 额外覆盖空 telemetry 表、旧 resolver 列、未建模 BLOB 和两次重开。另有 `go_sqlite_v5_telemetry.sql` 验证 Rust 打开 Go v5 数据库时保留未建模 telemetry 表和数据。健康的原生 Go v5/v6 state 可由 `ConfigStore::open` 直接迁移；ignored 回归 `opens_native_go_v5_database_directly_and_keeps_source_unchanged` 与 `opens_native_go_v6_database_directly_and_keeps_source_unchanged` 分别使用 `YUHAIIN_GO_NATIVE_DB`/`YUHAIIN_GO_NATIVE_V6_DB` 验证副本读回和源文件 hash 不变。原生 v6 本地验收快照位于 `~/.cache/yuhaiin-rust-check/native-go/state-native-v6.sqlite`，由当前 Go `sqlite.Open` 全新 bootstrap 生成，大小 446,464 bytes、SHA-256 为 `53e874f94d1cf081b7915434604be6fcf2ac2e56eebe93d82f761a5c3c32d9a6`。若 `nodes_fts` FTS5 shadow index 损坏或源库 WAL 非空，则仍必须先由 Go exporter 生成一致副本；`cmd/yuhaiin-rust-export` / `ExportRustSnapshot` 使用现有 SQLite driver 移除可重建 FTS5 virtual/shadow tables 并生成 manifest，415MB FTS-free snapshot 已由 rusqlite bundled SQLite 全库导入验证通过。v6 生产形状 snapshot 现在同时包含 Go typed FakeIP 的 IPv4/IPv6 rows 与 cursors；旧 Pebble FakeIP 的 IPv4/IPv6 版本化导出样例分别位于 `crates/yuhaiin-store/tests/fixtures/go_pebble_fakeip_v1.ndjson` 与 `crates/yuhaiin-store/tests/fixtures/go_pebble_fakeip_v1_v6.ndjson`，另有未知字段和重复地址冲突样例；由 `LegacyFakeIpExport::parse_ndjson` / `LegacyFakeIpV6Export::parse_ndjson` 严格解析后复用对应的事务 importer。

额外的真实生产组合回归：先复制 Go v5 FTS-free snapshot，在副本上运行当前 Go migration version 6，再重新导出 FTS-free snapshot；schema 6 snapshot 为 60,973,056 bytes，包含 206 nodes、27,439 条 FakeIP rows、IPv4/IPv6 两个 cursor。Rust 安装后 source/destination 均 `quick_check=ok`，live state DB 未被修改。该过程是“真实 Go v5 数据 + 当前 Go v6 migration”的验证，不冒充未经升级的原生 Go v6 生产快照；后者仍待取得。

### 真实 Go 数据库导出桥接

健康的 Go FTS5 shadow index 可以由 `ConfigStore::open` 直接读取并迁移；迁移前仍应停止 Go 写入者。若源库包含损坏的 FTS5 shadow index 或非空 WAL，则使用纯 Go/SQLite exporter 生成新的、不覆盖旧文件的 consistent snapshot：

```text
GOEXPERIMENT=jsonv2,greenteagc go run ./cmd/yuhaiin-rust-export \
  -source /path/to/yuhaiin/state.db \
  -output ~/.cache/yuhaiin-rust-check/go-state-<unique>.sqlite
```

exporter 只读取 source，通过 `VACUUM INTO` 复制 WAL 中已提交的数据，再在副本中删除可重建的 FTS5 virtual table；source 不会被修改，output 或对应的 `.manifest.json` 已存在时会失败。它会执行 `quick_check`，并生成版本化 manifest，记录 schema/tool version、FakeIP row 数、被移除的 FTS 表、snapshot 字节数和 SHA-256。Rust 的真实生产回归通过 `YUHAIIN_GO_PRODUCTION_DB=<output>` 指向该副本；不要把 `fts5: corrupt %_data record` 当成普通数据损坏，也不要绕过损坏/非一致源库必须经过 exporter 的边界。

生成副本后，Rust 侧使用 staging + checkpoint + atomic rename 安装成最终 state DB：

```text
cargo run -p yuhaiin-store --all-features --offline --bin go_snapshot_migrate -- \
  --source ~/.cache/yuhaiin-rust-check/go-state-<unique>.sqlite \
  --destination ~/.cache/yuhaiin-rust-check/rust-state-<unique>.sqlite
```

该入口自动读取 `<source>.manifest.json`，拒绝缺失、版本不支持、字节数不一致或 SHA-256 不匹配的 snapshot；同时拒绝已有 destination 和带非空 WAL sidecar 的 source，避免复制主库文件时静默丢失 WAL 中的已提交行。迁移失败只清理 staging 文件；成功后目标库包含 Rust schema、Go compatibility marker 和 typed rows，源库保持只读不变。

## 已导入字段

| Go 表 | Rust 目标 | 保留方式 |
| --- | --- | --- |
| `nodes_v2` | `proxy_nodes` | `id` 保留；`data_json` 原样写入 `config`；`kind` 固定为 `go-node` |
| `resolvers_v2` | `dns_resolvers` | `id`、`resolver_type` 映射为 `id`/`kind`；`data_json` 原样保留 |
| `route_rules_v2` | `route_rules` | `id`、`match_type`、`action_mode`、`priority` 映射；`data_json` 写入 `resolver_policy` |
| `inbounds_v2` | `yuhaiin_config` | 以 `go.inbound.<id>` 保存完整 `data_json`，等待专用 inbound repository |
| `settings_json` | `yuhaiin_config` | 以 `go.settings_json` 保存完整 `data_json` |
| `metadata.schema_version` / `migrate` | `yuhaiin_meta` | 写入 `go_schema_version` 和幂等标志 `go_schema_imported` |

导入前会在同一个事务内验证 `nodes_v2.chain_types_json`、`nodes_v2.data_json`、`inbounds_v2.transport_types_json`、`inbounds_v2.data_json`、`node_tags_v2.members_json`、`route_lists_v2.data_json` 以及已建模的 resolver/rule/settings JSON。任一字段不是合法 JSON 或已知标识/时间字段不合法，整个 typed import rollback，修复源行后可重试。

## 尚未等价建模的字段

以下字段不会在本次导入中丢失，但尚未进入 Rust 的 canonical typed schema。compatibility
views 可以读取和回写其中的已知列；runtime 仍必须显式选择何时把它们转换为 Rust 语义，不能
把 compatibility view 当作已经完成的 canonical 配置迁移：

- node 的 `name`、`group_name`、`origin`、`enabled`、`chain_types_json`、`updated_at`；
- resolver 的 `host`、`updated_at`；
- route rule 的 `name`、`disabled`、`tag`、`updated_at`，以及结构化 match/action 字段；
- inbound 的 `name`、`enabled`、`network_type`、`protocol_type`、`transport_types_json`、`updated_at`；
- Go 的 `dns_settings`、`dns_hosts`、`dns_fakedns_lists`、`route_settings`、`route_lists_v2`、统计/连接历史和 Geo/FakeIP 生产表。

因此当前导入是“可恢复、可审计的兼容导入”，不是宣称所有 Go 配置已经获得 Rust typed API 等价语义。后续每增加一个 typed repository，都应把对应字段从 JSON blob 迁移到可索引列，并增加旧字段/未知字段回归测试。

## Go v6 typed compatibility views

`ConfigRepository` 提供以下读写 API，用于迁移器和运行时逐步消费 Go v6 的已知列，而不让调用方直接依赖 SQLite：

- `list_go_inbounds()`：`id`、`name`、`enabled`、network/protocol、transport JSON、更新时间和原始 JSON。
- `list_go_nodes()` / `list_go_node_tags()`：节点元数据、启用状态、分组、来源、chain/tag members 和原始 JSON。
- `list_go_proxy_runtime_configs()`：在节点 compatibility view 之上解析 Go 的有序 protocol chain 和 tagged layer payload，选择 direct/drop/fixed/http/http_proxy/socks5/yuubinsya 等基础 transport，同时保留 TLS/HTTP2 层、启用状态、元数据和完整 `data_json`；未知协议进入 `GoProxyTransport::Unknown`，等待后续 runtime builder 显式处理，不会静默降级为 direct。`yuhaiin-chain::parse_go_node()` 负责当前 fixed/fixedv2 地址形状的 chain 归一化，固定上游保留 host/port 并在连接时异步解析域名；基础 proxy builder 提供 `to_base_proxy_config_with_resolver`，可注入 core 的 `AsyncIpResolver` 统一解析 HTTP/SOCKS5/fixed 域名，系统 `ToSocketAddrs` 仅作为同步兼容入口。
- `list_go_resolvers()`：resolver type、host、更新时间和原始 JSON；`list_go_resolver_runtime_configs()` 在此基础上解析为可扩展的 `udp/tcp/doh/dot/doq/doh3/system` transport 枚举，并保留 subnet/TLS server name。DoQ/DoH3 这里只完成配置识别，数据面仍按优先级单独实现。
- `list_go_dns_hosts()`：静态 host 与原始 target 字符串；调用方可逐条用 `HostsTable::insert_target()` 转换 IP 或域名 alias。`ConfigRepository::load_go_dns_hosts_table()` 提供批量加载入口，循环和未解析 alias 由 core resolver 层处理。
- `list_go_dns_settings()` / `load_go_fakeip_runtime_config()` / `list_go_dns_fakedns_lists()`：保留 Go FakeDNS 开关、IPv4/IPv6 范围及列表项；`load_go_fakeip_runtime_config()` 将 CIDR 规范化为可直接交给 FakeIP pool 的双栈起止地址，原始字符串仍由 compatibility view 保留。
- `list_go_route_settings()`：保留 direct/proxy resolver、local resolve 和 UDP FQDN 原始枚举值，供 Router/resolver runtime 重建使用。
- `load_go_route_runtime_config()`：将单例 route settings 转成应用中立的 runtime config；`udp_proxy_fqdn` 保留 Go 语义（`0=default`、`1=resolve`、`2=skip_resolve`），未知值按 Go 的向前兼容规则回退到 default。
- `list_go_route_rules()` / `list_go_route_lists()`：规则的 name/priority/disabled/action/match/tag，以及列表来源和原始 JSON。
- `yuhaiin-runtime::RuntimeBuilder` 消费上述 shared records，发布可供 HTTP/reload handler 复用的 `RuntimeSnapshot`；`RuntimeController` 复用同一套 records，提供 `ConfigMutation` 持久化、串行 reload 和失败时保留旧 snapshot；它不复制 Go records 为 DTO，hosts、FakeIP、resolver、route、Geo reader 和 proxy metadata 继续直接使用当前 compatibility structs。`RuntimeSnapshot::build_proxy_selector` 可把相同的 proxy records 组装为 TUN 的 direct/proxy/bypass/drop selector，缺失 proxy 时 fail-closed；controller 注册的 selector 会在新 snapshot publish 前完成 proxy slots 的原子刷新，失败时旧 snapshot 和旧 selector 保持不变。新 Rust store 同时创建 Go v6 compatibility 写表，fresh DB 可直接写入 nodes/inbounds/tags/resolvers/route-rules/route-lists。`ResolverTransportFactory` 可按 resolver ID 注入 transport，内置 registry 已覆盖 System/UDP/TCP，其中 TCP 使用纯 Tokio `AsyncTcpDnsClient`/`AsyncDnsResolver`；启用 runtime HTTP/DoH feature 后，`DnsOverHttpResolverFactory` 复用 core `DnsOverHttp`，由应用提供 TLS/proxy connector，并通过 Hyper 协商 HTTP/1.1 或 HTTP/2；启用 `doh-tls` feature 后，`RustCryptoResolverFactory` 可在同一 registry 中按配置混用 `RustCryptoDohResolverFactory` 和 `RustCryptoDotResolverFactory`，提供直连 TCP→RustCrypto TLS→ALPN h2/http1.1 或 DoT framing 的数据面，并可从应用提供的 `ClientConfig` 复用证书策略；`route_rules` 的常见 domain/CIDR matcher、action、network/port 和 resolver policy 会编译为 `RouterRuntime`，route settings 可按 direct/proxy mode 选择 resolver，已构造 resolver 支持回退到 shared resolver，无法表示的旧 matcher 明确 fail-closed。snapshot 构建支持对不可用 resolver 选择 fail-build 或 keep-unavailable，便于 reload 保留旧 snapshot；MaxMind metadata 的第一条配置会由 `GeoDb` 加载并注入 route snapshot，旧 reader 由旧 snapshot 持有；DoQ/DoH3 不能在没有 connector 时静默回退 system DNS。
- `RuntimeBuilder` 还读取 `nat_config.default`，由 `RuntimeSnapshot::new_full_cone_nat()` 将持久化 idle timeout 转成 TUN 可用的 `(NatTable, Duration)`；`RuntimeController::build_tun_proxy_runtime()`/`build_tun_proxy_runtime_with_dns()` 在同一个 reload 锁和 snapshot 下组装 selector、NAT、timeout，并可注入已有 packet-level DNS handler；`full_cone=false` 或非法 timeout 不会被悄悄降级，而是 fail-closed。
- 对应的 `put_go_inbound()`、`put_go_node()`、`put_go_node_tag()`、`put_go_resolver()`、`put_go_route_rule()`、`put_go_route_list()` 只写入明确的 `_v2` 表和已知列；`put_go_route_settings()`/`delete_go_route_settings()` 复用兼容的 `route_settings` 表，支持 runtime reload 的 direct/proxy resolver 配置；`delete_go_*()` 提供幂等删除。
- 写回统一经过 `BEGIN IMMEDIATE` 和 store sidecar 写锁；已知列校验失败、表不存在、额外约束失败都会回滚。`data_json` 必须由调用方带回，因此未知字段不会被 Rust 结构化层静默删除。

这些 API 不会把未知 JSON 字段解析成未经确认的 Rust 语义。Go v1 被重命名的 `go_legacy_*` 表是只读归档：空的 `_v2` 表会先执行显式字段映射，之后写回只走 `_v2` compatibility API，不对旧表做不可逆反向回写。

## 幂等和失败语义

- Rust 只在 source schema 被识别且 `go_schema_imported` 不存在时执行导入。
- 导入写入在一个 `BEGIN IMMEDIATE` transaction 中完成；失败会 rollback，不写完成标志。
- Go v6 compatibility writeback/delete 也在显式 transaction 中完成；已知列回写和未知 `data_json` 保留有 production-shaped fixture 与约束失败 rollback 回归。
- 原始 JSON 保留在 Rust blob/config 中，未知字段可以在下一版 importer 中重新解释。
- Go v1 的 `dns_resolvers`、`route_rules` 与 Rust typed repository 同名但列结构不同；导入前会分别重命名为 `go_legacy_dns_resolvers`、`go_legacy_route_rules`，避免 `CREATE TABLE IF NOT EXISTS` 静默复用不兼容 schema，同时保留原表数据。
- Go v1 升级规则：resolver 的旧整数枚举按 Go 实现映射为 `udp/tcp/doh/dot/doq/doh3`，`bootstrap` 空 host 映射为 `system`；route rule 按旧 priority/name 排序后从 1 重新编号，`mode/tag/disabled` 和旧分组规则映射到 `_v2` 的 action/match/data JSON。未知 root JSON 字段保留在生成的 `data_json` 中。
- 若 `_v2` 已有数据，则 `_v2` 是权威来源，Go v1 表只标记为归档，避免把较新的 v2 配置覆盖回旧格式。升级 marker 与数据写入同一 transaction；非法 JSON/规则枚举会整批 rollback，修复旧表后下一次启动可重试。
- Go v1 旧 resolver 没有 `updated_at`，Rust 使用确定性的 `0`；route rule 使用旧表的 `updated_at`。这类缺失字段不会伪造当前时间。
- `nat_config` 的缺省语义固定为 full-cone：Rust typed API 的缺失/删除 fallback 和新 schema 默认值均使用 `full_cone=true`、30 秒 idle timeout；旧写入方只写入 `key` 时也按该默认值读取。
- fixture 不依赖外网、`/tmp` 或系统 SQLite；临时数据库统一使用 `~/.cache/yuhaiin-rust-check`。

## FTS-free 生产快照桥接

当 Go state 含有损坏的 `nodes_fts` 等 FTS5 派生索引，或存在非空 WAL 时，不能直接把原文件交给 Rust migration path；原始数据库会 fail-closed。健康的 FTS5 数据库可以直接走 `ConfigStore::open`，迁移前执行：

```text
GOEXPERIMENT=jsonv2,greenteagc go run ./cmd/yuhaiin-rust-export \
  -source /path/to/go/state.db \
  -output ~/.cache/yuhaiin-rust-check/go-rust-snapshot.sqlite
```

命令只读 source，output 必须不存在；它先做一致 snapshot，再移除可重建的 FTS5 virtual/shadow tables，并对 source/exported 两边执行 `quick_check`。Rust 对损坏/非一致源只打开导出结果，生产后端使用 rusqlite bundled SQLite，不依赖宿主机 SQLite 版本；`libsqlite3-sys` 仅限于这个已批准的 store adapter 边界。
