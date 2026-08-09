#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_BENCH_DIR:-${cache_root}/benchmarks/http-throughput}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
bytes="${YUHAIIN_BENCH_BYTES:-67108864}"

mkdir -p "${scenario_dir}"

echo "[throughput] building release runtime and benchmark test"
cargo build \
  --manifest-path "${repo_root}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-runtime \
  --all-features \
  --offline \
  --release \
  --bin yuhaiin \
  >"${scenario_dir}/runtime-build.log"
cargo test \
  --manifest-path "${repo_root}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-runtime \
  --all-features \
  --offline \
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
    /usr/local/bin/yuhaiin-throughput --ignored --nocapture
  ' \
  | tee "${scenario_dir}/podman.log"

grep -q '^BENCHMARK ' "${scenario_dir}/podman.log"
grep -q 'test result: ok' "${scenario_dir}/podman.log"
echo "[throughput] passed; result/logs=${scenario_dir}"
