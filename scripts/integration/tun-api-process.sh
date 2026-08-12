#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/tun-api-process}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"

mkdir -p "${scenario_dir}"
if [[ ! -c /dev/net/tun ]]; then
  echo "[tun-api-process] /dev/net/tun is unavailable; skip with exit 77" >&2
  exit 77
fi

source "${repo_dir}/scripts/integration/tun-container-common.sh"
configure_tun_container_namespace tun-api-process /usr/local/bin/tun-api-process

echo "[tun-api-process] compiling runtime and process harness"
cargo build \
  --manifest-path "${repo_dir}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-runtime \
  --all-features \
  --offline \
  --bin yuhaiin \
  >"${scenario_dir}/runtime-build.log"
cargo test \
  --manifest-path "${repo_dir}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-runtime \
  --all-features \
  --offline \
  --test tun_api_process \
  --no-run \
  >"${scenario_dir}/build.log"

test_binary="$({
  find "${target_dir}/debug/deps" -maxdepth 1 -type f -executable \
    -name 'tun_api_process-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
runtime_binary="${target_dir}/debug/yuhaiin"
test -x "${test_binary}"
test -x "${runtime_binary}"

common_args=(
  --privileged
  --network=none
  --device=/dev/net/tun
  -v "${test_binary}:/usr/local/bin/tun-api-process:ro"
  -v "${runtime_binary}:/usr/local/bin/yuhaiin:ro"
  -v "${scenario_dir}:/state:Z"
  -e YUHAIIN_RUNTIME_BIN=/usr/local/bin/yuhaiin
  -e YUHAIIN_INTEGRATION_DIR=/state
  -e YUHAIIN_RESET_INTEGRATION_STATE=1
  -e HOME=/state/home
  -e XDG_CACHE_HOME=/state/cache
  --entrypoint "${TUN_CONTAINER_ENTRYPOINT}"
  "${image}"
)

podman run --rm "${common_args[@]}" "${TUN_CONTAINER_COMMAND_ARGS[@]}" \
  --ignored --nocapture --test-threads=1 \
  | tee "${scenario_dir}/podman.log"

grep -q 'test result: ok' "${scenario_dir}/podman.log"
echo "[tun-api-process] passed; logs=${scenario_dir}"
