#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/startup-logs}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"

mkdir -p "${scenario_dir}"

echo "[startup-logs] building runtime in Podman"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${scenario_dir}" -- \
  cargo build --locked \
  -p yuhaiin-api \
  --all-features \
  --bin yuhaiin \
  >"${scenario_dir}/runtime-build.log"
runtime_binary="${target_dir}/debug/yuhaiin"
test -x "${runtime_binary}"

echo "[startup-logs] running foreground service in Podman"
podman run --rm \
  --network=none \
  -v "${runtime_binary}:/usr/local/bin/yuhaiin:ro" \
  -v "${scenario_dir}:/state" \
  -e HOME=/state/home \
  -e XDG_CONFIG_HOME=/state/config \
  --entrypoint /bin/sh \
  "${image}" \
  -ec '
    set -eu
    : > /state/stdout.log
    : > /state/stderr.log
    /usr/local/bin/yuhaiin >/state/stdout.log 2>/state/stderr.log &
    pid=$!
    ready=0
    for _ in $(seq 1 100); do
      if grep -Fq "runtime ready; DNS, inbound and HTTP API supervisors started" /state/stderr.log; then
        ready=1
        break
      fi
      if ! kill -0 "$pid" 2>/dev/null; then
        break
      fi
      sleep 0.05
    done
    if [ "$ready" -ne 1 ]; then
      cat /state/stderr.log >&2
      kill -KILL "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      exit 1
    fi
    grep -Fq "starting; database=/state/config/yuhaiin/state.db" /state/stderr.log
    grep -Fq "HTTP API listening on" /state/stderr.log
    kill -TERM "$pid"
    wait "$pid"
    grep -Fq "shutdown requested; stopping runtime tasks" /state/stderr.log
    grep -Fq "shutdown requested; stopping runtime tasks (signal=SIGTERM)" /state/stderr.log
    grep -Fq "stopped" /state/stderr.log
    cat /state/stderr.log
  ' \
  | tee "${scenario_dir}/podman.log"

grep -q 'runtime ready; DNS, inbound and HTTP API supervisors started' "${scenario_dir}/podman.log"
grep -q 'stopped' "${scenario_dir}/podman.log"
echo "[startup-logs] passed; logs=${scenario_dir}"
