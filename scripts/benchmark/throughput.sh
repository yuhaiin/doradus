#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${repo_root}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_BENCH_DIR:-${cache_root}/benchmarks/http-throughput}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
bytes="${YUHAIIN_BENCH_BYTES:-67108864}"

mkdir -p "${scenario_dir}"

echo "[throughput] building release runtime and benchmark test in Podman"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${scenario_dir}" -- \
  cargo build \
  -p yuhaiin-api \
  --all-features \
  --release \
  --bin yuhaiin \
  >"${scenario_dir}/runtime-build.log"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${scenario_dir}" -- \
  cargo test \
  -p yuhaiin-api \
  --all-features \
  --release \
  --test throughput \
  --no-run \
  >"${scenario_dir}/build.log"

test_binary="$({
  find "${target_dir}/release/deps" -maxdepth 1 -type f -executable \
    -name 'throughput-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
test -n "${test_binary}"
runtime_binary="${target_dir}/release/yuhaiin"
test -x "${runtime_binary}"

echo "[throughput] running one-stream loopback benchmark in Podman"
podman run --rm \
  --network=host \
  -v "${test_binary}:/usr/local/bin/yuhaiin-throughput:ro" \
  -v "${runtime_binary}:/usr/local/bin/yuhaiin:ro" \
  -v "${scenario_dir}:/state" \
  -e YUHAIIN_RUNTIME_BIN=/usr/local/bin/yuhaiin \
  -e YUHAIIN_INTEGRATION_DIR=/state \
  -e YUHAIIN_BENCH_BYTES="${bytes}" \
  -e YUHAIIN_BENCH_PROFILE=release \
  --entrypoint /bin/sh \
  "${image}" \
  -ec '
    set -eu
    for test_name in \
      http_inbound_route_http_connect_throughput \
      http_inbound_route_tls_h2_yuubinsya_throughput; do
      /usr/local/bin/yuhaiin-throughput "${test_name}" --exact --ignored --nocapture
    done
  ' \
  | tee "${scenario_dir}/podman.log"

test "$(grep -c '^BENCHMARK ' "${scenario_dir}/podman.log")" -eq 2
test "$(grep -c 'test result: ok' "${scenario_dir}/podman.log")" -eq 2
echo "[throughput] matrix: HTTP CONNECT and TLS/H2/Yuubinsya"
echo "[throughput] passed; result/logs=${scenario_dir}"
