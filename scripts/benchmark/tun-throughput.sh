#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_TUN_BENCH_DIR:-${cache_root}/benchmarks/tun-throughput}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
bytes="${YUHAIIN_TUN_BENCH_BYTES:-4194304}"
binary="${target_dir}/release/tun-smoke"
if [[ ! -c /dev/net/tun ]]; then
  echo "[tun-throughput] /dev/net/tun is not available for the Podman container; skipped (77)" >&2
  exit 77
fi
tun_device_args=(--device=/dev/net/tun)
source "${repo_root}/scripts/integration/tun-container-common.sh"
configure_tun_container_namespace tun-throughput /usr/local/bin/tun-smoke
debug_env=()
if [[ -n "${YUHAIIN_TUN_DEBUG:-}" ]]; then
  debug_env=(-e YUHAIIN_TUN_DEBUG=1)
fi

mkdir -p "${scenario_dir}"

echo "[tun-throughput] building release TUN smoke benchmark"
cargo build \
  --manifest-path "${repo_root}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-core \
  --bin tun-smoke \
  --features tun,async-proxy \
  --offline \
  --release \
  >"${scenario_dir}/build.log"
test -x "${binary}"

echo "[tun-throughput] running packet relay benchmark in privileged Podman"
podman run --rm --privileged --network=none "${tun_device_args[@]}" \
  -v "${binary}:/usr/local/bin/tun-smoke:ro" \
  -v "${scenario_dir}:/state:Z" \
  -e YUHAIIN_TUN_NAME=yrtun-bench0 \
  -e YUHAIIN_TUN_PROXY_THROUGHPUT=1 \
  -e YUHAIIN_TUN_BENCH_BYTES="${bytes}" \
  "${debug_env[@]}" \
  --entrypoint "${TUN_CONTAINER_ENTRYPOINT}" \
  "${image}" \
  "${TUN_CONTAINER_COMMAND_ARGS[@]}" \
  2>&1 | tee "${scenario_dir}/podman.log"

grep -q '^BENCHMARK ' "${scenario_dir}/podman.log"
echo "[tun-throughput] passed; result/logs=${scenario_dir}"
