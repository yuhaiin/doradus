#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_dir="${YUHAIIN_INTEGRATION_DIR:-${HOME}/.cache/yuhaiin-rust/integration/tun-service}"
target_dir="${CARGO_TARGET_DIR:-${HOME}/.cache/yuhaiin-rust/cargo-target}"
binary="${target_dir}/debug/tun-service-smoke"
database_dir="${cache_dir}/state"
log_path="${cache_dir}/podman.log"
tun_name="yrtun0"

mkdir -p "${database_dir}"
cd "${repo_dir}"
cargo build --target-dir "${target_dir}" -p yuhaiin-runtime --bin tun-service-smoke --all-features --offline

if ! podman run --rm --privileged --network=none \
    -e YUHAIIN_DB=/state/state.sqlite \
    -e YUHAIIN_TUN_NAME="${tun_name}" \
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
