# yuhaiin Go → Rust 发布替换与回滚

本文描述把 Rust binary 替换现有 Go service 的最小安全流程。Rust 与 Go 必须使用同一个状态目录时，只允许一个进程写 `state.db`；WAL、sidecar write lock 和配置迁移并不能让两个 runtime 同时接管同一份状态。

## 1. 发布前检查

先确认 Rust binary、前端目录和状态目录：

```bash
install -m 0755 target/release/yuhaiin "$HOME/.cache/yuhaiin-rust/release/yuhaiin.new"
test -x "$HOME/.cache/yuhaiin-rust/release/yuhaiin.new"
test -f "$HOME/.cache/yuhaiin-rust/release/yuhaiin.new"
```

Linux 默认构建仍使用 host toolchain；需要静态 musl 产物时使用 Makefile。`MUSL=1`
默认使用 Rust toolchain 自带的 `rust-lld`，避免本机 `musl-gcc` 生成的 PIE 在部分
musl loader 版本上无法启动：

```bash
make build MUSL=1          # x86_64-unknown-linux-musl debug
make build-release-musl    # x86_64-unknown-linux-musl release

# 其他 musl target 由调用方提供对应 linker
make build-release-musl \
  MUSL_TARGET=aarch64-unknown-linux-musl \
  MUSL_LINKER=/opt/musl/bin/aarch64-linux-musl-gcc
```

输出位于 `$(CARGO_TARGET_DIR)/$(MUSL_TARGET)/{debug,release}/yuhaiin`，默认
`CARGO_TARGET_DIR` 是 `~/.cache/yuhaiin-rust/cargo-target`；可用 `file` 和直接执行
`yuhaiin version` 检查产物。

如果从源码构建 Android `aarch64` 产物，使用本机 NDK 的 API 35 clang；不要把中间文件放进 `/tmp`：

```bash
ndk_bin=/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ndk_bin/aarch64-linux-android35-clang" \
CC_aarch64_linux_android="$ndk_bin/aarch64-linux-android35-clang" \
CXX_aarch64_linux_android="$ndk_bin/aarch64-linux-android35-clang++" \
AR_aarch64_linux_android="$ndk_bin/llvm-ar" \
cargo build -p yuhaiin-api --bin yuhaiin --all-features \
  --target aarch64-linux-android --release --offline
```

发布前必须在副本上执行：

```bash
cargo test --workspace --all-features --offline --quiet
cargo fmt --all -- --check
git diff --check
```

## 2. SQLite 备份

先停止服务，再备份；不要在 Go/Rust 进程运行时直接复制正在变化的 `state.db`。优先使用 SQLite backup API：

```bash
service_state="$HOME/.local/share/yuhaiin"
backup_dir="$HOME/.cache/yuhaiin-rust/backups"
mkdir -p "$backup_dir"
backup="$backup_dir/state-$(date -u +%Y%m%dT%H%M%SZ).db"

sqlite3 "$service_state/state.db" ".backup '$backup'"
sqlite3 "$backup" 'PRAGMA quick_check;'
```

若环境没有 `sqlite3`，使用 Rust store 的 backup/restore API 或离线备份工具；不要把 `state.db-wal`、`state.db-shm` 与主库拆开复制。备份必须位于状态目录之外，且保留至少一个可回滚版本。

## 3. systemd 替换

Rust binary 继续使用 Go service 的参数语义：`-path DIR` 指向 `DIR/state.db`，默认监听 `0.0.0.0:50051`；如果 service unit 使用显式 `YUHAIIN_DB`/`YUHAIIN_HTTP`，以 unit 为准。

Rust binary 也可以直接接管 Linux service 生命周期。`install` 会原子替换
`/usr/local/bin/yuhaiin`、写入 `/etc/systemd/system/yuhaiin.service`、创建数据目录并执行
`daemon-reload`、`enable` 和 `start`；已有运行实例会自动 `restart`：

```bash
sudo "$HOME/.cache/yuhaiin-rust/release/yuhaiin.new" install \
  -host 0.0.0.0:50051 -path /var/lib/yuhaiin
sudo systemctl is-active yuhaiin.service
```

可用的生命周期命令是 `sudo /usr/local/bin/yuhaiin start|stop|restart`；卸载使用
`sudo /usr/local/bin/yuhaiin uninstall`。`status` 不是 Rust/Go CLI 的服务 action，健康检查仍使用
`systemctl is-active` 和 HTTP `/api/v2/info`。

```bash
sudo systemctl stop yuhaiin.service
if systemctl is-active --quiet yuhaiin.service; then
  echo "yuhaiin.service is still active" >&2
  exit 1
fi

install -m 0755 "$HOME/.cache/yuhaiin-rust/release/yuhaiin.new" \
  /usr/local/bin/yuhaiin
sudo systemctl start yuhaiin.service

curl --fail --retry 10 --retry-delay 1 \
  http://127.0.0.1:50051/api/v2/info
```

若 service 使用 `-eweb DIR`，保留原前端目录；Rust 会在同一 listener 提供静态资源和 SPA fallback。

## 4. launchd 替换

macOS 上先卸载旧 job，再替换 executable，避免旧进程继续持有数据库：

```bash
label=com.asutorufa.yuhaiin
domain="system/$label"
sudo launchctl bootout "$domain" || true

sudo install -m 0755 "$HOME/.cache/yuhaiin-rust/release/yuhaiin.new" \
  /usr/local/bin/yuhaiin
sudo launchctl bootstrap system /Library/LaunchDaemons/$label.plist
sudo launchctl kickstart -kp "$domain"
```

确认 plist 中的 `-path`、`-host`、`-eweb` 和日志路径没有改变；`bootout` 后应确认旧 PID 已退出，再进行 SQLite 备份或替换。

Rust binary 也可以直接安装或重装 LaunchDaemon：

```bash
sudo "$HOME/.cache/yuhaiin-rust/release/yuhaiin.new" install \
  -host 0.0.0.0:50051 -path "/Library/Application Support/yuhaiin"
sudo /usr/local/bin/yuhaiin restart
sudo /usr/local/bin/yuhaiin uninstall
```

安装、重启和卸载都会使用 `/Library/LaunchDaemons/com.asutorufa.yuhaiin.plist`；现场回滚前仍要先备份
SQLite 并确认旧 PID 已退出。

## 5. 回滚

回滚必须先停止新进程。Rust native state 现在会记录 Go migration v6 metadata，并创建 Go runtime 所需的兼容表；fresh state 和旧 Rust state 已通过 Go 重新打开的启动级 smoke。但非空生产库的 route/resolver projection 逐行语义、统计最终投影和完整 rollback 仍未全部验证，因此发布时仍应先恢复 binary，再恢复同一发布前的 SQLite backup，不要把启动级兼容 smoke 当作生产数据级回滚保证。

```bash
sudo systemctl stop yuhaiin.service
sudo install -m 0755 /usr/local/bin/yuhaiin.update-backup /usr/local/bin/yuhaiin

state="$HOME/.local/share/yuhaiin/state.db"
restore="$HOME/.cache/yuhaiin-rust/backups/state-before-rust.db"
sqlite3 "$state" ".restore '$restore'"

sudo systemctl start yuhaiin.service
curl --fail --retry 10 --retry-delay 1 \
  http://127.0.0.1:50051/api/v2/info
```

Rust 的 `update-helper` 在安装失败或 service restart 非零时会尝试恢复 `.update-backup`；重新启动成功后才删除 backup。手工回滚仍应保留一份独立 SQLite backup，避免 binary rollback 成功但数据迁移已改变的情况。

## 6. 并行运行限制

- Go 和 Rust 可以并行读取独立数据库副本，用于 API/协议对照；不能同时写同一个 `state.db`。
- 做兼容对照时，复制已经停止并完成 SQLite backup 的数据库到 `~/.cache/yuhaiin-rust/compare/`，分别启动两个 runtime。
- Rust 的 `statistics.runtime` checkpoint 是异常退出恢复路径；最终 Go-compatible statistics projection 会在正常 shutdown 时写回。切换期间应等待 Rust `/api/v2/info` 健康检查成功后再关闭旧服务的自动重启策略，并保留发布前 backup，直到 Go reverse-open 和生产形状数据验收完成。
- 发现 `SQLITE_BUSY`、sidecar lock 或 migration lock 时停止切换，不要删除 lock/WAL 文件；先确认没有遗留进程，再按备份恢复流程处理。

## 7. 验收顺序

1. `/api/v2/info`、`/api/v2/settings`、`/api/v2/nodes` 可读。
2. DNS server、FakeIP、route snapshot 和一个 direct outbound 可用。
3. SOCKS5/HTTP inbound 到 direct/proxy outbound 建立连接，`connections`、traffic 和 history 有实时变化。
4. 发送 SIGTERM 后重启，检查 totals/history/traffic 与切换前一致。
5. 在副本上强制终止进程，再重启，确认 Rust checkpoint 恢复且最终 Go 表投影可读取。
6. 只有上述检查通过后，才删除旧 binary 和发布 backup。
