#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${repo_dir}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
cargo_home="${YUHAIIN_CARGO_HOME:-${cache_root}/cargo-home}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/tun-api-process}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
build_image="${YUHAIIN_BUILD_IMAGE:-docker.io/library/rust:latest}"

mkdir -p "${scenario_dir}" "${cargo_home}"
if [[ ! -c /dev/net/tun ]]; then
  echo "[tun-api-process] /dev/net/tun is unavailable; skip with exit 77" >&2
  exit 77
fi

source "${repo_dir}/scripts/integration/tun-container-common.sh"
configure_tun_container_namespace tun-api-process /usr/local/bin/tun-api-process

echo "[tun-api-process] compiling runtime and process harness"
podman run --rm --network=host \
  -v "${repo_dir}:/workspace:ro" \
  -v "${target_dir}:/target:Z" \
  -v "${scenario_dir}:/state:Z" \
  -v "${cargo_home}:/cargo-home:Z" \
  --entrypoint /bin/sh \
  "${build_image}" \
  -ec '
    set -eu
    mkdir -p /state/home /state/cache/tmp
    export HOME=/state/home
    export CARGO_HOME=/cargo-home
    export CARGO_TARGET_DIR=/target
    export TMPDIR=/state/cache/tmp
    unset CARGO_NET_OFFLINE
    cd /workspace
    cargo build --locked \
      --manifest-path /workspace/Cargo.toml \
      -p yuhaiin-api \
      --all-features \
      --bin yuhaiin \
      >/state/runtime-build.log 2>&1
    cargo test --locked \
      --manifest-path /workspace/Cargo.toml \
      -p yuhaiin-api \
      --all-features \
      --test tun_api_process \
      --no-run \
      >/state/build.log 2>&1
  '

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
  -e YUHAIIN_CACHE_DIR=/state/cache
  --entrypoint "${TUN_CONTAINER_ENTRYPOINT}"
  "${image}"
)

podman run --rm "${common_args[@]}" "${TUN_CONTAINER_COMMAND_ARGS[@]}" \
  --ignored --nocapture --test-threads=1 \
  | tee "${scenario_dir}/podman.log"

grep -q 'test result: ok' "${scenario_dir}/podman.log"
echo "[tun-api-process] passed; logs=${scenario_dir}"
