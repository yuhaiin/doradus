#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
scenario_dir="${YUHAIIN_TUN_DISTRO_DIR:-${cache_root}/integration/tun-distro}"
target_dir="${YUHAIIN_TUN_DISTRO_TARGET_DIR:-${cache_root}/tun-distro-target}"
image="${YUHAIIN_TUN_DISTRO_IMAGE:-docker.io/library/alpine:latest}"
target="${YUHAIIN_TUN_DISTRO_TARGET:-x86_64-unknown-linux-musl}"
binary="${target_dir}/${target}/release/tun-service-smoke"
namespace_mode="${YUHAIIN_TUN_USER_NAMESPACE:-1}"

mkdir -p "${scenario_dir}"

echo "[tun-distro] building static TUN harness for ${target} in Podman"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" \
  --state-dir "${scenario_dir}/build" \
  --install-target "${target}" \
  --install-musl-toolchain \
  -- cargo build --locked --release --target "${target}" \
    -p yuhaiin-runtime --bin tun-service-smoke --all-features

test -x "${binary}"

echo "[tun-distro] running reload and traffic smoke in ${image}"
YUHAIIN_SKIP_BUILD=1 \
YUHAIIN_TUN_BINARY="${binary}" \
YUHAIIN_TEST_IMAGE="${image}" \
YUHAIIN_TUN_USER_NAMESPACE="${namespace_mode}" \
YUHAIIN_TUN_RELOAD=1 \
YUHAIIN_INTEGRATION_DIR="${scenario_dir}/reload" \
  "${repo_root}/scripts/integration/tun-service.sh"

echo "[tun-distro] running MTU matrix in ${image}"
YUHAIIN_SKIP_BUILD=1 \
YUHAIIN_TUN_BINARY="${binary}" \
YUHAIIN_TEST_IMAGE="${image}" \
YUHAIIN_TUN_USER_NAMESPACE="${namespace_mode}" \
YUHAIIN_TUN_MTU_DIR="${scenario_dir}/mtu" \
  "${repo_root}/scripts/integration/tun-mtu.sh"

echo "[tun-distro] passed; image=${image} target=${target} logs=${scenario_dir}"
