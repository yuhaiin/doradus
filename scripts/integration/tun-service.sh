#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_dir="${DORADUS_INTEGRATION_DIR:-${repo_dir}/.cache/doradus/integration/tun-service}"
target_dir="${CARGO_TARGET_DIR:-${repo_dir}/.cache/doradus/cargo-target}"
binary="${DORADUS_TUN_BINARY:-${target_dir}/debug/tun-service-smoke}"
database_dir="${cache_dir}/state"
log_path="${cache_dir}/podman.log"
image="${DORADUS_TEST_IMAGE:-docker.io/library/debian:testing}"
tun_name="yrtun0"
chain_mode="${DORADUS_TUN_CHAIN:-}"
container_name="doradus-tun-service-$$"
timeout_seconds="${DORADUS_TUN_SMOKE_TIMEOUT_SEC:-45}"
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
  echo "DORADUS_TUN_SMOKE_TIMEOUT_SEC must be a positive integer" >&2
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
  chain_env=(-e "DORADUS_TUN_CHAIN=${chain_mode}")
fi
if [[ -n "${DORADUS_TUN_RELOAD:-}" ]]; then
  chain_env+=( -e "DORADUS_TUN_RELOAD=${DORADUS_TUN_RELOAD}" )
fi
if [[ -n "${DORADUS_TUN_RELOAD_CYCLES:-}" ]]; then
  chain_env+=( -e "DORADUS_TUN_RELOAD_CYCLES=${DORADUS_TUN_RELOAD_CYCLES}" )
fi
if [[ -n "${DORADUS_TUN_DEBUG:-}" ]]; then
  chain_env+=( -e "DORADUS_TUN_DEBUG=${DORADUS_TUN_DEBUG}" )
fi
for tun_fixture_env in DORADUS_TUN_PORTAL DORADUS_TUN_PORTAL_V6 DORADUS_TUN_ROUTE DORADUS_TUN_SOURCE DORADUS_TUN_IPV6_SOURCE DORADUS_TUN_TARGET DORADUS_TUN_IPV6_TARGET DORADUS_TUN_UDP_TARGET DORADUS_TUN_UDP_FIRST DORADUS_TUN_IPV6_EXTENSION DORADUS_TUN_DNS_TEST DORADUS_TUN_DNS_TARGET; do
  if [[ -n "${!tun_fixture_env:-}" ]]; then
    chain_env+=( -e "${tun_fixture_env}=${!tun_fixture_env}" )
  fi
done
if [[ "${DORADUS_TUN_RESET_RECONNECT:-0}" == "1" ]]; then
  chain_env+=( -e DORADUS_TUN_RESET_RECONNECT=1 )
fi

mkdir -p "${database_dir}"
if [[ "${DORADUS_SKIP_BUILD:-0}" != "1" ]]; then
  "${repo_dir}/scripts/integration/podman-cargo.sh" \
    --target-dir "${target_dir}" --state-dir "${cache_dir}" -- \
    cargo build --locked -p doradus-runtime --bin tun-service-smoke --all-features
fi
test -x "${binary}"

common_args=(
  --privileged
  --network=none
  "${tun_device_args[@]}"
  -e DORADUS_DB=/state/state.sqlite
  -e DORADUS_TUN_NAME="${tun_name}"
  -e DORADUS_TUN_MTU="${DORADUS_TUN_MTU:-1500}"
  "${chain_env[@]}"
  -v "${binary}:/usr/local/bin/tun-service-smoke:ro"
  -v "${database_dir}:/state:Z"
  --entrypoint "${TUN_CONTAINER_ENTRYPOINT}"
  "${image}"
)
run_args=(
  "${common_args[@]:0:${#common_args[@]}-1}"
  -e DORADUS_TUN_HOLD_MS=750
  "${common_args[@]: -1}"
)
if [[ "${DORADUS_TUN_RELOAD_ONLY:-0}" != "1" ]]; then
  run_args=(
    "${run_args[@]:0:${#run_args[@]}-1}"
    -e DORADUS_TUN_TRAFFIC=1
    -e DORADUS_TUN_TRAFFIC_BYTES="${DORADUS_TUN_TRAFFIC_BYTES:-32}"
    "${run_args[@]: -1}"
  )
fi
if [[ "${DORADUS_TUN_ASSERT_CONNECTIONS:-0}" == "1" ]]; then
  run_args=(
    "${run_args[@]:0:${#run_args[@]}-1}"
    -e DORADUS_TUN_ASSERT_CONNECTIONS=1
    -e DORADUS_TUN_CONNECTION_HOLD_MS="${DORADUS_TUN_CONNECTION_HOLD_MS:-250}"
    "${run_args[@]: -1}"
  )
fi
if [[ "${DORADUS_TUN_ASSERT_PROCESS:-0}" == "1" ]]; then
  run_args=(
    "${run_args[@]:0:${#run_args[@]}-1}"
    -e DORADUS_TUN_ASSERT_PROCESS=1
    "${run_args[@]: -1}"
  )
fi
if [[ "${DORADUS_TUN_UDP_TRAFFIC:-0}" == "1" ]]; then
  run_args=(
    "${run_args[@]:0:${#run_args[@]}-1}"
    -e DORADUS_TUN_UDP_TRAFFIC=1
    -e DORADUS_TUN_UDP_TRAFFIC_BYTES="${DORADUS_TUN_UDP_TRAFFIC_BYTES:-8192}"
    "${run_args[@]: -1}"
  )
fi
force_args=(
  "${common_args[@]:0:${#common_args[@]}-1}"
  -e DORADUS_TUN_TRAFFIC=1
  -e DORADUS_TUN_TRAFFIC_BYTES=536870912
  -e DORADUS_TUN_HOLD_MS=30000
  "${common_args[@]: -1}"
)

if [[ "${DORADUS_TUN_FORCE_STOP:-0}" == "1" ]]; then
  force_name="doradus-tun-force-stop-$$"
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
if [[ -n "${DORADUS_TUN_RELOAD:-}" ]]; then
  grep -Fq "runtime-tun-reload-ok name=${tun_name}" <<<"${output}"
fi
if [[ "${DORADUS_TUN_RELOAD_ONLY:-0}" != "1" ]]; then
  grep -Fq "runtime-tun-traffic-ok" <<<"${output}"
fi
if [[ -n "${DORADUS_TUN_DNS_TEST:-}" ]]; then
  grep -Fq "runtime-tun-dns-ok" <<<"${output}"
  grep -Eq "runtime-tun-dns-address=198\.18\." <<<"${output}"
fi
if [[ "${DORADUS_TUN_RESET_RECONNECT:-0}" == "1" ]]; then
  grep -Fq "runtime-tun-reset-ok" <<<"${output}"
  grep -Fq "runtime-tun-reconnect-ok" <<<"${output}"
fi
if [[ "${DORADUS_TUN_ASSERT_PROCESS:-0}" == "1" ]]; then
  grep -Fq "runtime-tun-process-ok" <<<"${output}"
fi
if [[ "${DORADUS_TUN_UDP_TRAFFIC:-0}" == "1" ]]; then
  if [[ "${DORADUS_TUN_IPV6_EXTENSION:-0}" != "1" ]]; then
    grep -Fq "runtime-tun-udp-traffic-ok" <<<"${output}"
  fi
fi
if [[ "${DORADUS_TUN_IPV6_EXTENSION:-0}" == "1" ]]; then
  grep -Fq "runtime-tun-ipv6-extension-ok" <<<"${output}"
fi
grep -Fq "runtime-tun-closed name=${tun_name}" <<<"${output}"
if [[ -n "${chain_mode}" ]]; then
  grep -Fq "runtime-tun-chain-ready mode=${chain_mode}" <<<"${output}"
fi
