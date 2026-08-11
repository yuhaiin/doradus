#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
cache_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration-reusable}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
mkdir -p "${cache_dir}"

echo "[service-chain] building runtime and process test"
cargo build \
  --manifest-path "${repo_dir}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-runtime \
  --all-features \
  --offline \
  --bin yuhaiin \
  >"${cache_dir}/runtime-build.log"
cargo test \
  --manifest-path "${repo_dir}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-runtime \
  --all-features \
  --offline \
  --test service_chain \
  --no-run \
  >"${cache_dir}/build.log"

test_binary="$({
  find "${target_dir}/debug/deps" -maxdepth 1 -type f -executable \
    -name 'service_chain-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
test -n "${test_binary}"
runtime_binary="${target_dir}/debug/yuhaiin"
test -x "${runtime_binary}"

echo "[service-chain] running inbound/router/outbound matrix in Podman"
podman run --rm \
  --network=host \
  -v "${test_binary}:/usr/local/bin/yuhaiin-service-chain:ro" \
  -v "${runtime_binary}:/usr/local/bin/yuhaiin:ro" \
  -v "${cache_dir}:/state" \
  -e YUHAIIN_RUNTIME_BIN=/usr/local/bin/yuhaiin \
  -e YUHAIIN_INTEGRATION_DIR=/state \
  -e YUHAIIN_RESET_INTEGRATION_STATE=1 \
  --entrypoint /bin/sh \
  "${image}" \
  -ec '
    set -eu
    /usr/local/bin/yuhaiin-service-chain --nocapture --test-threads=1
  ' \
  | tee "${cache_dir}/podman.log"

grep -q 'test result: ok' "${cache_dir}/podman.log"
echo "[service-chain] passed; logs=${cache_dir}"
