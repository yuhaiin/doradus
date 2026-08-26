# yuhaiin Go to Rust Release Replacement and Rollback

This document describes the minimum safe procedure for replacing the existing Go service with the Rust binary. When Go and Rust use the same state directory, only one process may write `state.db`; WAL files, a sidecar write lock, and configuration migration do not make it safe for two runtimes to own the same state concurrently.

## 1. Pre-release checks

First verify the Rust binary, frontend directory, and state directory:

```bash
install -m 0755 target/release/yuhaiin "$HOME/.cache/yuhaiin-rust/release/yuhaiin.new"
test -x "$HOME/.cache/yuhaiin-rust/release/yuhaiin.new"
test -f "$HOME/.cache/yuhaiin-rust/release/yuhaiin.new"
```

The default Linux build continues to use the host toolchain. Use the Makefile when a static musl artifact is required. `MUSL=1` uses the Rust toolchain's `rust-lld` by default, avoiding PIE binaries produced by the local `musl-gcc` that may fail to start with some musl loader versions:

```bash
make build MUSL=1          # x86_64-unknown-linux-musl debug
make build-release-musl    # x86_64-unknown-linux-musl release

# The caller must provide the linker for other musl targets.
make build-release-musl \
  MUSL_TARGET=aarch64-unknown-linux-musl \
  MUSL_LINKER=/opt/musl/bin/aarch64-linux-musl-gcc
```

Artifacts are written to `target/$(MUSL_TARGET)/{debug,release}/yuhaiin`. Set
`CARGO_TARGET_DIR=/path/to/target` to use a separate target directory. Use `file`
and `yuhaiin version` to inspect the artifact.

When building an Android `aarch64` artifact from source, use the local NDK's API 35 clang. Do not put intermediate files in `/tmp`:

```bash
ndk_bin=/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin
CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ndk_bin/aarch64-linux-android35-clang" \
CC_aarch64_linux_android="$ndk_bin/aarch64-linux-android35-clang" \
CXX_aarch64_linux_android="$ndk_bin/aarch64-linux-android35-clang++" \
AR_aarch64_linux_android="$ndk_bin/llvm-ar" \
cargo build -p yuhaiin-api --bin yuhaiin --all-features \
  --target aarch64-linux-android --release --offline
```

Before release, run these checks on a copy:

```bash
cargo test --workspace --all-features --offline --quiet
cargo fmt --all -- --check
git diff --check
```

## 2. SQLite backup

Stop the service before taking a backup. Do not copy a changing `state.db` while a Go or Rust process is running. Prefer the SQLite backup API:

```bash
service_state="$HOME/.local/share/yuhaiin"
backup_dir="$HOME/.cache/yuhaiin-rust/backups"
mkdir -p "$backup_dir"
backup="$backup_dir/state-$(date -u +%Y%m%dT%H%M%SZ).db"

sqlite3 "$service_state/state.db" ".backup '$backup'"
sqlite3 "$backup" 'PRAGMA quick_check;'
```

If `sqlite3` is unavailable, use the Rust store backup/restore API or an offline backup tool. Do not copy `state.db-wal` or `state.db-shm` separately from the main database. Store backups outside the state directory and retain at least one rollback version.

## 3. systemd replacement

The Rust binary keeps the Go service's argument semantics: `-path DIR` points to `DIR/state.db`, and the default listener is `0.0.0.0:50051`. If the service unit explicitly sets `YUHAIIN_DB` or `YUHAIIN_HTTP`, the unit is authoritative.

The Rust binary can also manage the Linux service lifecycle directly. `install` atomically replaces
`/usr/local/bin/yuhaiin`, writes `/etc/systemd/system/yuhaiin.service`, creates the data directory, and runs
`daemon-reload`, `enable`, and `start`; an existing instance is restarted automatically:

```bash
sudo "$HOME/.cache/yuhaiin-rust/release/yuhaiin.new" install \
  -host 0.0.0.0:50051 -path /var/lib/yuhaiin
sudo systemctl is-active yuhaiin.service
```

The lifecycle commands are `sudo /usr/local/bin/yuhaiin start|stop|restart`; uninstall with
`sudo /usr/local/bin/yuhaiin uninstall`. `status` is not a service action supported by the Rust/Go CLI; use
`systemctl is-active` and HTTP `/api/v2/info` for health checks.

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

If the service uses `-eweb DIR`, keep the existing frontend directory. Rust serves its static assets and SPA fallback on the same listener.

## 4. launchd replacement

On macOS, unload the old job before replacing the executable so that the old process cannot keep the database open:

```bash
label=com.asutorufa.yuhaiin
domain="system/$label"
sudo launchctl bootout "$domain" || true

sudo install -m 0755 "$HOME/.cache/yuhaiin-rust/release/yuhaiin.new" \
  /usr/local/bin/yuhaiin
sudo launchctl bootstrap system /Library/LaunchDaemons/$label.plist
sudo launchctl kickstart -kp "$domain"
```

Verify that `-path`, `-host`, `-eweb`, and the log paths in the plist are unchanged. After `bootout`, verify that the old PID has exited before taking the SQLite backup or replacing the binary.

The Rust binary can also install or reinstall the LaunchDaemon directly:

```bash
sudo "$HOME/.cache/yuhaiin-rust/release/yuhaiin.new" install \
  -host 0.0.0.0:50051 -path "/Library/Application Support/yuhaiin"
sudo /usr/local/bin/yuhaiin restart
sudo /usr/local/bin/yuhaiin uninstall
```

Install, restart, and uninstall all use `/Library/LaunchDaemons/com.asutorufa.yuhaiin.plist`. Before an on-site rollback, still back up SQLite and verify that the old PID has exited.

## 5. Rollback

Rollback must stop the new process first. Rust native state records Go migration v6 metadata and creates the compatibility tables required by the Go runtime; fresh state and older Rust state have passed startup-level smoke tests when reopened by Go. However, row-by-row route/resolver projection semantics, the final statistics projection, and a complete rollback of a non-empty production database have not all been verified. During a release, restore the binary first and then restore the SQLite backup from the same pre-release point. Do not treat startup compatibility smoke as a production data rollback guarantee.

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

Rust's `update-helper` attempts to restore `.update-backup` when installation fails or service restart returns a non-zero status; it removes the backup only after a successful restart. Manual rollback should still retain an independent SQLite backup so that a successful binary rollback cannot conceal a changed data migration.

## 6. Parallel-run limitations

- Go and Rust may read independent database copies in parallel for API and protocol comparison; they must not write the same `state.db` concurrently.
- For compatibility comparison, copy a stopped service database after completing the SQLite backup to `~/.cache/yuhaiin-rust/compare/`, then start the two runtimes separately.
- The Rust `statistics.runtime` checkpoint is an abnormal-exit recovery path; the final Go-compatible statistics projection is written during normal shutdown. During cutover, wait for Rust `/api/v2/info` to pass its health check before disabling the old service's automatic restart policy. Retain the pre-release backup until Go reverse-open and production-shaped data checks are complete.
- Stop the cutover if `SQLITE_BUSY`, a sidecar lock, or a migration lock appears. Do not delete lock or WAL files; first verify that no stale process remains, then follow the backup recovery procedure.

## 7. Acceptance order

1. `/api/v2/info`, `/api/v2/settings`, and `/api/v2/nodes` are readable.
2. The DNS server, FakeIP, route snapshot, and one direct outbound work.
3. A SOCKS5/HTTP inbound can connect to direct/proxy outbounds, and `connections`, traffic, and history change in real time.
4. After SIGTERM and restart, totals, history, and traffic match the pre-cutover state.
5. On a copy, force-terminate and restart the process; verify Rust checkpoint recovery and readable final Go-table projections.
6. Delete the old binary and release backup only after all checks above pass.
