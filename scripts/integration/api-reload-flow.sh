#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/api-reload-flow}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"

mkdir -p "${scenario_dir}"

echo "[api-reload-flow] building runtime and process test"
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
  --test api_reload_flow \
  --no-run \
  >"${scenario_dir}/build.log"

test_binary="$({
  find "${target_dir}/debug/deps" -maxdepth 1 -type f -executable \
    -name 'api_reload_flow-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
test -n "${test_binary}"
runtime_binary="${target_dir}/debug/yuhaiin"
test -x "${runtime_binary}"

echo "[api-reload-flow] running persistent mutation/reload flow in Podman host network"
podman run --rm \
  --network=host \
  -v "${test_binary}:/usr/local/bin/yuhaiin-api-reload-flow:ro" \
  -v "${runtime_binary}:/usr/local/bin/yuhaiin:ro" \
  -v "${scenario_dir}:/state" \
  -e YUHAIIN_RUNTIME_BIN=/usr/local/bin/yuhaiin \
  -e YUHAIIN_INTEGRATION_DIR=/state \
  --entrypoint /bin/sh \
  "${image}" \
  -ec '
    set -eu
    /usr/local/bin/yuhaiin-api-reload-flow --nocapture
  ' \
  | tee "${scenario_dir}/podman.log"

grep -q 'test result: ok' "${scenario_dir}/podman.log"
echo "[api-reload-flow] passed; logs=${scenario_dir}"
