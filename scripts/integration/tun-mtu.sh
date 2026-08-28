#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_dir="${DORADUS_TUN_MTU_DIR:-${repo_dir}/.cache/doradus/integration/tun-mtu}"
target_dir="${CARGO_TARGET_DIR:-${repo_dir}/.cache/doradus/cargo-target}"
binary="${DORADUS_TUN_BINARY:-${target_dir}/debug/tun-service-smoke}"
image="${DORADUS_TEST_IMAGE:-docker.io/library/debian:testing}"
tun_device_args=()
if [[ -c /dev/net/tun ]]; then
  tun_device_args=(--device=/dev/net/tun)
else
  cat >&2 <<EOF
[tun-mtu] MTU packet smoke needs /dev/net/tun to be passed into the
container. The host does not expose that character device, so this matrix is
skipped with exit 77.
EOF
  exit 77
fi
source "${repo_dir}/scripts/integration/tun-container-common.sh"
configure_tun_container_namespace tun-mtu

fixture_env=()
for tun_fixture_env in DORADUS_TUN_PORTAL DORADUS_TUN_PORTAL_V6 DORADUS_TUN_ROUTE DORADUS_TUN_SOURCE DORADUS_TUN_TARGET DORADUS_TUN_UDP_TARGET DORADUS_TUN_UDP_FIRST; do
  if [[ -n "${!tun_fixture_env:-}" ]]; then
    fixture_env+=( -e "${tun_fixture_env}=${!tun_fixture_env}" )
  fi
done

mkdir -p "${cache_dir}"
if [[ "${DORADUS_SKIP_BUILD:-0}" != "1" ]]; then
  "${repo_dir}/scripts/integration/podman-cargo.sh" \
    --target-dir "${target_dir}" --state-dir "${cache_dir}" -- \
    cargo build --locked -p doradus-runtime --bin tun-service-smoke --all-features \
    >"${cache_dir}/build.log" 2>&1
fi
test -x "${binary}"

for mtu in 576 1280 1500 9000 9216; do
  case_dir="${cache_dir}/mtu-${mtu}"
  database_dir="${case_dir}/state"
  log_path="${case_dir}/podman.log"
  tun_name="yrtun-mtu-${mtu}"
  mkdir -p "${database_dir}"

  # Exercise the largest legal IPv4 UDP payload by default. Callers can lower
  # it for a faster smoke, but the default catches both smoltcp
  # fragmentation-buffer regressions and kernel reassembly regressions.
  if ! podman run --rm --privileged --network=none "${tun_device_args[@]}" \
      -e DORADUS_DB=/state/state.sqlite \
      -e DORADUS_TUN_NAME="${tun_name}" \
      -e DORADUS_TUN_MTU="${mtu}" \
      -e DORADUS_TUN_TRAFFIC=1 \
      -e DORADUS_TUN_UDP_TRAFFIC=1 \
      -e DORADUS_TUN_UDP_TRAFFIC_BYTES="${DORADUS_TUN_UDP_TRAFFIC_BYTES:-65507}" \
      -e DORADUS_TUN_HOLD_MS=750 \
      "${fixture_env[@]}" \
      -v "${binary}:/usr/local/bin/tun-service-smoke:ro" \
      -v "${database_dir}:/state:Z" \
      --entrypoint "${TUN_CONTAINER_ENTRYPOINT}" \
      "${image}" \
      "${TUN_CONTAINER_COMMAND_ARGS[@]}" >"${log_path}" 2>&1; then
    cat "${log_path}"
    exit 1
  fi

  output="$(<"${log_path}")"
  printf '%s\n' "${output}"
  grep -Fq "runtime-tun-opened name=${tun_name}" <<<"${output}"
  grep -Fq "runtime-tun-traffic-ok" <<<"${output}"
  grep -Fq "runtime-tun-udp-traffic-ok" <<<"${output}"
  grep -Fq "runtime-tun-closed name=${tun_name}" <<<"${output}"
  printf 'tun-mtu-case-passed mtu=%s\n' "${mtu}"
done

printf 'tun-mtu-matrix-passed cases=5 dir=%s\n' "${cache_dir}"
