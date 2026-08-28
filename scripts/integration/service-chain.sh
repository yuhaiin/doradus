#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${DORADUS_CACHE_DIR:-${repo_dir}/.cache/doradus}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
cargo_home="${DORADUS_CARGO_HOME:-${cache_root}/cargo-home}"
cache_dir="${DORADUS_INTEGRATION_DIR:-${cache_root}/integration-reusable}"
image="${DORADUS_TEST_IMAGE:-docker.io/library/debian:testing}"
build_image="${DORADUS_BUILD_IMAGE:-docker.io/library/rust:latest}"
command -v podman >/dev/null
mkdir -p "${cache_dir}" "${cargo_home}"

echo "[service-chain] compiling runtime and process test in Podman"
podman run --rm --network=host \
  -v "${repo_dir}:/workspace:ro" \
  -v "${target_dir}:/target:Z" \
  -v "${cache_dir}:/state:Z" \
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
    CARGO_TERM_COLOR=never cargo build --locked \
      --manifest-path /workspace/Cargo.toml \
      -p doradus-api \
      --all-features \
      --bin doradus \
      >/state/runtime-build.log 2>&1
    CARGO_TERM_COLOR=never cargo test --locked \
      --manifest-path /workspace/Cargo.toml \
      -p doradus-api \
      --all-features \
      --test service_chain \
      --no-run \
      >/state/build.log 2>&1
  '

test_binary="$({
  find "${target_dir}/debug/deps" -maxdepth 1 -type f -executable \
    -name 'service_chain-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
test -n "${test_binary}"
runtime_binary="${target_dir}/debug/doradus"
test -x "${runtime_binary}"

echo "[service-chain] running inbound/router/outbound matrix in Podman"
podman run --rm \
  --network=host \
  -v "${test_binary}:/usr/local/bin/doradus-service-chain:ro" \
  -v "${runtime_binary}:/usr/local/bin/doradus:ro" \
  -v "${cache_dir}:/state" \
  -e DORADUS_RUNTIME_BIN=/usr/local/bin/doradus \
  -e DORADUS_INTEGRATION_DIR=/state \
  -e DORADUS_RESET_INTEGRATION_STATE=1 \
  --entrypoint /bin/sh \
  "${image}" \
  -ec '
    set -eu
    /usr/local/bin/doradus-service-chain --nocapture --test-threads=1
  ' \
  | tee "${cache_dir}/podman.log"

grep -q 'test result: ok' "${cache_dir}/podman.log"
echo "[service-chain] passed; logs=${cache_dir}"
