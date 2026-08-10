#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_dir="${YUHAIIN_INTEGRATION_DIR:-${HOME}/.cache/yuhaiin-rust/integration/tun-service}"
target_dir="${CARGO_TARGET_DIR:-${HOME}/.cache/yuhaiin-rust/cargo-target}"
binary="${target_dir}/debug/tun-service-smoke"
database_dir="${cache_dir}/state"
log_path="${cache_dir}/podman.log"
tun_name="yrtun0"
chain_mode="${YUHAIIN_TUN_CHAIN:-}"

chain_env=()
if [[ -n "${chain_mode}" ]]; then
  chain_env=(-e "YUHAIIN_TUN_CHAIN=${chain_mode}")
fi
if [[ -n "${YUHAIIN_TUN_DEBUG:-}" ]]; then
  chain_env+=( -e "YUHAIIN_TUN_DEBUG=${YUHAIIN_TUN_DEBUG}" )
fi

mkdir -p "${database_dir}"
cd "${repo_dir}"
cargo build --target-dir "${target_dir}" -p yuhaiin-runtime --bin tun-service-smoke --all-features --offline

common_args=(
  --privileged
  --network=none
  -e YUHAIIN_DB=/state/state.sqlite
  -e YUHAIIN_TUN_NAME="${tun_name}"
  -e YUHAIIN_TUN_MTU="${YUHAIIN_TUN_MTU:-1500}"
  "${chain_env[@]}"
  -v "${binary}:/usr/local/bin/tun-service-smoke:ro"
  -v "${database_dir}:/state:Z"
  --entrypoint /usr/local/bin/tun-service-smoke
  docker.io/library/debian:testing
)
run_args=(
  "${common_args[@]:0:${#common_args[@]}-1}"
  -e YUHAIIN_TUN_TRAFFIC=1
  -e YUHAIIN_TUN_TRAFFIC_BYTES="${YUHAIIN_TUN_TRAFFIC_BYTES:-32}"
  -e YUHAIIN_TUN_HOLD_MS=750
  "${common_args[@]: -1}"
)
if [[ "${YUHAIIN_TUN_ASSERT_CONNECTIONS:-0}" == "1" ]]; then
  run_args=(
    "${run_args[@]:0:${#run_args[@]}-1}"
    -e YUHAIIN_TUN_ASSERT_CONNECTIONS=1
    -e YUHAIIN_TUN_CONNECTION_HOLD_MS="${YUHAIIN_TUN_CONNECTION_HOLD_MS:-250}"
    "${run_args[@]: -1}"
  )
fi
force_args=(
  "${common_args[@]:0:${#common_args[@]}-1}"
  -e YUHAIIN_TUN_TRAFFIC=1
  -e YUHAIIN_TUN_TRAFFIC_BYTES=536870912
  -e YUHAIIN_TUN_HOLD_MS=30000
  "${common_args[@]: -1}"
)

if [[ "${YUHAIIN_TUN_FORCE_STOP:-0}" == "1" ]]; then
  force_name="yuhaiin-tun-force-stop-$$"
  force_log="${cache_dir}/force-stop.log"
  : >"${force_log}"
  podman rm -f "${force_name}" >/dev/null 2>&1 || true
  podman run -d --name "${force_name}" "${force_args[@]}" >"${cache_dir}/force-stop-container-id"
  opened=0
  for _ in $(seq 1 150); do
    podman logs "${force_name}" >"${force_log}" 2>&1 || true
    if grep -Fq "runtime-tun-opened name=${tun_name}" "${force_log}"; then
      opened=1
      break
    fi
    if ! podman inspect -f '{{.State.Running}}' "${force_name}" 2>/dev/null | grep -Fq true; then
      break
    fi
    sleep 0.1
  done
  if (( opened == 0 )); then
    cat "${force_log}"
    podman rm -f "${force_name}" >/dev/null 2>&1 || true
    echo "TUN force-stop fixture did not reach an opened device" >&2
    exit 1
  fi
  podman kill --signal KILL "${force_name}" >/dev/null
  podman wait "${force_name}" >/dev/null 2>&1 || true
  podman rm -f "${force_name}" >/dev/null 2>&1 || true
  echo "runtime-tun-force-stop-ok name=${tun_name}"
fi

if ! podman run --rm "${run_args[@]}" >"${log_path}" 2>&1; then
  cat "${log_path}"
  exit 1
fi
output="$(<"${log_path}")"
printf '%s\n' "${output}"
grep -Fq "runtime-tun-opened name=${tun_name}" <<<"${output}"
grep -Fq "runtime-tun-traffic-ok" <<<"${output}"
grep -Fq "runtime-tun-closed name=${tun_name}" <<<"${output}"
if [[ -n "${chain_mode}" ]]; then
  grep -Fq "runtime-tun-chain-ready mode=${chain_mode}" <<<"${output}"
fi
