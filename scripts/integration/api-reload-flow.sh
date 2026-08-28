#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${DORADUS_CACHE_DIR:-${repo_root}/.cache/doradus}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${DORADUS_INTEGRATION_DIR:-${cache_root}/integration/api-reload-flow}"
image="${DORADUS_TEST_IMAGE:-docker.io/library/debian:testing}"

mkdir -p "${scenario_dir}"

echo "[api-reload-flow] building runtime and process test in Podman"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${scenario_dir}" -- \
  cargo build --locked \
  -p doradus-api \
  --all-features \
  --bin doradus \
  >"${scenario_dir}/runtime-build.log"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${scenario_dir}" -- \
  cargo test --locked \
  -p doradus-api \
  --all-features \
  --test api_reload_flow \
  --no-run \
  >"${scenario_dir}/build.log"

test_binary="$({
  find "${target_dir}/debug/deps" -maxdepth 1 -type f -executable \
    -name 'api_reload_flow-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
test -n "${test_binary}"
runtime_binary="${target_dir}/debug/doradus"
test -x "${runtime_binary}"

echo "[api-reload-flow] running persistent mutation/reload flow in Podman network=none"
podman run --rm \
  --network=none \
  -v "${test_binary}:/usr/local/bin/doradus-api-reload-flow:ro" \
  -v "${runtime_binary}:/usr/local/bin/doradus:ro" \
  -v "${scenario_dir}:/state" \
  -e DORADUS_RUNTIME_BIN=/usr/local/bin/doradus \
  -e DORADUS_INTEGRATION_DIR=/state \
  -e DORADUS_RESET_INTEGRATION_STATE=1 \
  --entrypoint /bin/sh \
  "${image}" \
  -ec '
    set -eu
    /usr/local/bin/doradus-api-reload-flow --nocapture --test-threads=1
  ' \
  | tee "${scenario_dir}/podman.log"

grep -q 'test result: ok' "${scenario_dir}/podman.log"
echo "[api-reload-flow] passed; logs=${scenario_dir}"
