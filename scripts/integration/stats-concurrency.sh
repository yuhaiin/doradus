#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/stats-concurrency}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
reader_count="${YUHAIIN_STATS_READER_COUNT:-8}"
reader_rounds="${YUHAIIN_STATS_READER_ROUNDS:-40}"
write_rounds="${YUHAIIN_STATS_WRITE_ROUNDS:-64}"

mkdir -p "${scenario_dir}"

echo "[stats-concurrency] building runtime integration test binary"
cargo build \
  --manifest-path "${repo_root}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-runtime \
  --all-features \
  --offline \
  --bin yuhaiin \
  >"${scenario_dir}/runtime-build.log"
cargo test \
  --manifest-path "${repo_root}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-runtime \
  --all-features \
  --offline \
  --test stats_concurrency \
  --no-run \
  >"${scenario_dir}/build.log"

test_binary="$({
  find "${target_dir}/debug/deps" -maxdepth 1 -type f -executable \
    -name 'stats_concurrency-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
test -n "${test_binary}"
runtime_binary="${target_dir}/debug/yuhaiin"
test -x "${runtime_binary}"

echo "[stats-concurrency] running concurrent statistics process smoke in Podman"
podman run --rm \
  --network=none \
  -v "${test_binary}:/usr/local/bin/yuhaiin-stats-test:ro" \
  -v "${runtime_binary}:/usr/local/bin/yuhaiin:ro" \
  -e YUHAIIN_RUNTIME_BIN=/usr/local/bin/yuhaiin \
  -e YUHAIIN_STATS_READER_COUNT="${reader_count}" \
  -e YUHAIIN_STATS_READER_ROUNDS="${reader_rounds}" \
  -e YUHAIIN_STATS_WRITE_ROUNDS="${write_rounds}" \
  --entrypoint /bin/sh \
  "${image}" \
  -ec '
    set -eu
    /usr/local/bin/yuhaiin-stats-test \
      --nocapture
  ' \
  | tee "${scenario_dir}/podman.log"

grep -q 'test result: ok' "${scenario_dir}/podman.log"
echo "[stats-concurrency] pressure: readers=${reader_count}, reader-rounds=${reader_rounds}, write-rounds=${write_rounds}"
echo "[stats-concurrency] passed; logs=${scenario_dir}"
