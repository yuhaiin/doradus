#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_dir="${YUHAIIN_TUN_MTU_DIR:-${HOME}/.cache/yuhaiin-rust/integration/tun-mtu}"
target_dir="${CARGO_TARGET_DIR:-${HOME}/.cache/yuhaiin-rust/cargo-target}"
binary="${target_dir}/debug/tun-service-smoke"

mkdir -p "${cache_dir}"
cd "${repo_dir}"
cargo build --target-dir "${target_dir}" -p yuhaiin-runtime --bin tun-service-smoke --all-features --offline \
  >"${cache_dir}/build.log" 2>&1

for mtu in 576 1280 1500 9000 9216; do
  case_dir="${cache_dir}/mtu-${mtu}"
  database_dir="${case_dir}/state"
  log_path="${case_dir}/podman.log"
  tun_name="yrtun-mtu-${mtu}"
  mkdir -p "${database_dir}"

  if ! podman run --rm --privileged --network=none \
      -e YUHAIIN_DB=/state/state.sqlite \
      -e YUHAIIN_TUN_NAME="${tun_name}" \
      -e YUHAIIN_TUN_MTU="${mtu}" \
      -e YUHAIIN_TUN_TRAFFIC=1 \
      -e YUHAIIN_TUN_HOLD_MS=750 \
      -v "${binary}:/usr/local/bin/tun-service-smoke:ro" \
      -v "${database_dir}:/state:Z" \
      --entrypoint /usr/local/bin/tun-service-smoke \
      docker.io/library/debian:testing >"${log_path}" 2>&1; then
    cat "${log_path}"
    exit 1
  fi

  output="$(<"${log_path}")"
  printf '%s\n' "${output}"
  grep -Fq "runtime-tun-opened name=${tun_name}" <<<"${output}"
  grep -Fq "runtime-tun-traffic-ok" <<<"${output}"
  grep -Fq "runtime-tun-closed name=${tun_name}" <<<"${output}"
  printf 'tun-mtu-case-passed mtu=%s\n' "${mtu}"
done

printf 'tun-mtu-matrix-passed cases=5 dir=%s\n' "${cache_dir}"
