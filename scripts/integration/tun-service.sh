#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_dir="${YUHAIIN_INTEGRATION_DIR:-${HOME}/.cache/yuhaiin-rust/integration/tun-service}"
target_dir="${CARGO_TARGET_DIR:-${HOME}/.cache/yuhaiin-rust/cargo-target}"
binary="${YUHAIIN_TUN_BINARY:-${target_dir}/debug/tun-service-smoke}"
database_dir="${cache_dir}/state"
log_path="${cache_dir}/podman.log"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
tun_name="yrtun0"
chain_mode="${YUHAIIN_TUN_CHAIN:-}"
container_name="yuhaiin-tun-service-$$"
timeout_seconds="${YUHAIIN_TUN_SMOKE_TIMEOUT_SEC:-45}"
tun_device_args=()
if [[ -c /dev/net/tun ]]; then
  tun_device_args=(--device=/dev/net/tun)
fi

source "${repo_dir}/scripts/integration/tun-container-common.sh"
configure_tun_container_namespace tun-service


cleanup() {
  podman rm -f "${container_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if ! [[ "${timeout_seconds}" =~ ^[1-9][0-9]*$ ]]; then
  echo "YUHAIIN_TUN_SMOKE_TIMEOUT_SEC must be a positive integer" >&2
  exit 2
fi

# The real device is required for both lifecycle and packet traffic. Some
# rootless Podman installations can pass it together with --privileged; probe
# that capability instead of classifying every rootless connection as a skip.
if [[ "${#tun_device_args[@]}" == "0" ]]; then
  cat >&2 <<EOF
[tun-service] smoke needs /dev/net/tun to be passed into the container.
The host does not expose that character device, so this run is skipped with
exit 77.
EOF
  exit 77
fi

chain_env=()
if [[ -n "${chain_mode}" ]]; then
  chain_env=(-e "YUHAIIN_TUN_CHAIN=${chain_mode}")
fi
if [[ -n "${YUHAIIN_TUN_RELOAD:-}" ]]; then
  chain_env+=( -e "YUHAIIN_TUN_RELOAD=${YUHAIIN_TUN_RELOAD}" )
fi
if [[ -n "${YUHAIIN_TUN_RELOAD_CYCLES:-}" ]]; then
  chain_env+=( -e "YUHAIIN_TUN_RELOAD_CYCLES=${YUHAIIN_TUN_RELOAD_CYCLES}" )
fi
if [[ -n "${YUHAIIN_TUN_DEBUG:-}" ]]; then
  chain_env+=( -e "YUHAIIN_TUN_DEBUG=${YUHAIIN_TUN_DEBUG}" )
fi
for tun_fixture_env in YUHAIIN_TUN_PORTAL YUHAIIN_TUN_PORTAL_V6 YUHAIIN_TUN_ROUTE YUHAIIN_TUN_SOURCE YUHAIIN_TUN_IPV6_SOURCE YUHAIIN_TUN_TARGET YUHAIIN_TUN_IPV6_TARGET YUHAIIN_TUN_UDP_TARGET YUHAIIN_TUN_UDP_FIRST YUHAIIN_TUN_IPV6_EXTENSION; do
  if [[ -n "${!tun_fixture_env:-}" ]]; then
    chain_env+=( -e "${tun_fixture_env}=${!tun_fixture_env}" )
  fi
done
if [[ "${YUHAIIN_TUN_RESET_RECONNECT:-0}" == "1" ]]; then
  chain_env+=( -e YUHAIIN_TUN_RESET_RECONNECT=1 )
fi

mkdir -p "${database_dir}"
if [[ "${YUHAIIN_SKIP_BUILD:-0}" != "1" ]]; then
  "${repo_dir}/scripts/integration/podman-cargo.sh" \
    --target-dir "${target_dir}" --state-dir "${cache_dir}" -- \
    cargo build --locked -p yuhaiin-runtime --bin tun-service-smoke --all-features
fi
test -x "${binary}"

common_args=(
  --privileged
  --network=none
  "${tun_device_args[@]}"
  -e YUHAIIN_DB=/state/state.sqlite
  -e YUHAIIN_TUN_NAME="${tun_name}"
  -e YUHAIIN_TUN_MTU="${YUHAIIN_TUN_MTU:-1500}"
  "${chain_env[@]}"
  -v "${binary}:/usr/local/bin/tun-service-smoke:ro"
  -v "${database_dir}:/state:Z"
  --entrypoint "${TUN_CONTAINER_ENTRYPOINT}"
  "${image}"
)
run_args=(
  "${common_args[@]:0:${#common_args[@]}-1}"
  -e YUHAIIN_TUN_HOLD_MS=750
  "${common_args[@]: -1}"
)
if [[ "${YUHAIIN_TUN_RELOAD_ONLY:-0}" != "1" ]]; then
  run_args=(
    "${run_args[@]:0:${#run_args[@]}-1}"
    -e YUHAIIN_TUN_TRAFFIC=1
    -e YUHAIIN_TUN_TRAFFIC_BYTES="${YUHAIIN_TUN_TRAFFIC_BYTES:-32}"
    "${run_args[@]: -1}"
  )
fi
if [[ "${YUHAIIN_TUN_ASSERT_CONNECTIONS:-0}" == "1" ]]; then
  run_args=(
    "${run_args[@]:0:${#run_args[@]}-1}"
    -e YUHAIIN_TUN_ASSERT_CONNECTIONS=1
    -e YUHAIIN_TUN_CONNECTION_HOLD_MS="${YUHAIIN_TUN_CONNECTION_HOLD_MS:-250}"
    "${run_args[@]: -1}"
  )
fi
if [[ "${YUHAIIN_TUN_ASSERT_PROCESS:-0}" == "1" ]]; then
  run_args=(
    "${run_args[@]:0:${#run_args[@]}-1}"
    -e YUHAIIN_TUN_ASSERT_PROCESS=1
    "${run_args[@]: -1}"
  )
fi
if [[ "${YUHAIIN_TUN_UDP_TRAFFIC:-0}" == "1" ]]; then
  run_args=(
    "${run_args[@]:0:${#run_args[@]}-1}"
    -e YUHAIIN_TUN_UDP_TRAFFIC=1
    -e YUHAIIN_TUN_UDP_TRAFFIC_BYTES="${YUHAIIN_TUN_UDP_TRAFFIC_BYTES:-8192}"
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
  podman run -d --name "${force_name}" "${force_args[@]}" "${TUN_CONTAINER_COMMAND_ARGS[@]}" >"${cache_dir}/force-stop-container-id"
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

if ! timeout --foreground "${timeout_seconds}s" podman run --name "${container_name}" "${run_args[@]}" "${TUN_CONTAINER_COMMAND_ARGS[@]}" >"${log_path}" 2>&1; then
  cat "${log_path}"
  if grep -Fq "runtime-tun-opened name=${tun_name}" "${log_path}" \
    && ! grep -Fq "runtime-tun-traffic-ok" "${log_path}"; then
    echo "TUN smoke timed out after ${timeout_seconds}s; this usually means the namespace lacks a route/CAP_NET_ADMIN or the flow chain did not complete" >&2
  fi
  exit 1
fi
output="$(<"${log_path}")"
printf '%s\n' "${output}"
grep -Fq "runtime-tun-opened name=${tun_name}" <<<"${output}"
if [[ -n "${YUHAIIN_TUN_RELOAD:-}" ]]; then
  grep -Fq "runtime-tun-reload-ok name=${tun_name}" <<<"${output}"
fi
if [[ "${YUHAIIN_TUN_RELOAD_ONLY:-0}" != "1" ]]; then
  grep -Fq "runtime-tun-traffic-ok" <<<"${output}"
fi
if [[ "${YUHAIIN_TUN_RESET_RECONNECT:-0}" == "1" ]]; then
  grep -Fq "runtime-tun-reset-ok" <<<"${output}"
  grep -Fq "runtime-tun-reconnect-ok" <<<"${output}"
fi
if [[ "${YUHAIIN_TUN_ASSERT_PROCESS:-0}" == "1" ]]; then
  grep -Fq "runtime-tun-process-ok" <<<"${output}"
fi
if [[ "${YUHAIIN_TUN_UDP_TRAFFIC:-0}" == "1" ]]; then
  if [[ "${YUHAIIN_TUN_IPV6_EXTENSION:-0}" != "1" ]]; then
    grep -Fq "runtime-tun-udp-traffic-ok" <<<"${output}"
  fi
fi
if [[ "${YUHAIIN_TUN_IPV6_EXTENSION:-0}" == "1" ]]; then
  grep -Fq "runtime-tun-ipv6-extension-ok" <<<"${output}"
fi
grep -Fq "runtime-tun-closed name=${tun_name}" <<<"${output}"
if [[ -n "${chain_mode}" ]]; then
  grep -Fq "runtime-tun-chain-ready mode=${chain_mode}" <<<"${output}"
fi
