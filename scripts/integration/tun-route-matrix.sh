#!/usr/bin/env bash
set -euo pipefail

# Rootful-only TUN route lease evidence. The ordinary TUN service smoke is
# intentionally usable in a disposable user namespace; this fixture checks
# the Linux netlink route owner in a normal privileged Podman namespace and
# keeps the process/container split so routes can be inspected after the
# TUN owner exits or is force-stopped.

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_dir="${DORADUS_TUN_ROUTE_DIR:-${repo_dir}/.cache/doradus/integration/tun-route-matrix}"
target_dir="${CARGO_TARGET_DIR:-${repo_dir}/.cache/doradus/cargo-target}"
binary="${DORADUS_TUN_BINARY:-${target_dir}/debug/tun-smoke}"
image="${DORADUS_TEST_IMAGE:-docker.io/library/debian:testing}"
name="doradus-tun-route-matrix-$$"
force_name="${name}-force"
tun_name="${DORADUS_TUN_ROUTE_NAME:-yrtr-$$}"
force_tun_name="${DORADUS_TUN_FORCE_ROUTE_NAME:-yrtf-$$}"
state_dir="${cache_dir}/state"
log_path="${cache_dir}/podman.log"
force_log_path="${cache_dir}/force.log"
host_ip="${DORADUS_IP:-$(command -v ip || true)}"
host_nsenter="${DORADUS_NSENTER:-$(command -v nsenter || true)}"

if [[ "$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || echo true)" == true ]]; then
  echo "[tun-route-matrix] requires rootful Podman (rootless=false); skipping with exit 77" >&2
  exit 77
fi
if [[ ! -c /dev/net/tun ]]; then
  echo "[tun-route-matrix] /dev/net/tun is unavailable; skipping with exit 77" >&2
  exit 77
fi
if [[ ! -x "${host_ip}" || ! -x "${host_nsenter}" ]]; then
  echo "[tun-route-matrix] host ip and nsenter are required; skipping with exit 77" >&2
  exit 77
fi

mkdir -p "${state_dir}"
rm -f "${log_path}" "${force_log_path}" "${state_dir}/force.pid"

cleanup() {
  podman rm -f "${name}" "${force_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

if [[ "${DORADUS_SKIP_BUILD:-0}" != 1 ]]; then
  "${repo_dir}/scripts/integration/podman-cargo.sh" \
    --target-dir "${target_dir}" --state-dir "${cache_dir}" -- \
    cargo build --locked -p doradus-core --bin tun-smoke \
    --features tun-routes >"${cache_dir}/build.log" 2>&1
fi
test -x "${binary}"

common_args=(
  --privileged
  --network=none
  --device=/dev/net/tun
  -e "DORADUS_TUN_NAME=${tun_name}"
  -e DORADUS_TUN_ROUTE_SMOKE=1
  -e DORADUS_TUN_HOLD_MS=2500
  -v "${binary}:/usr/local/bin/tun-smoke:ro"
  -v "${state_dir}:/state:Z"
  --entrypoint /bin/sh
  "${image}"
)

podman rm -f "${name}" >/dev/null 2>&1 || true
podman run -d --name "${name}" "${common_args[@]}" \
  -ceu '/usr/local/bin/tun-smoke; sleep 5' >"${cache_dir}/container-id"
opened=0
for _ in $(seq 1 100); do
  podman logs "${name}" >"${log_path}" 2>&1 || true
  if grep -Fq "tun-route-installed count=3" "${log_path}" \
    && grep -Fq "tun-opened" "${log_path}"; then
    opened=1
    break
  fi
  if ! podman inspect -f '{{.State.Running}}' "${name}" 2>/dev/null | grep -Fq true; then
    break
  fi
  sleep 0.1
done
if (( opened == 0 )); then
  cat "${log_path}"
  echo "[tun-route-matrix] normal owner did not install routes" >&2
  exit 1
fi

normal_ns_pid="$(podman inspect -f '{{.State.Pid}}' "${name}")"
route_output="$("${host_nsenter}" -t "${normal_ns_pid}" -n "${host_ip}" -4 route show dev "${tun_name}")"
printf '%s\n' "${route_output}" | tee "${cache_dir}/route-during.log"
grep -Fq "198.18.0.0/15" <<<"${route_output}"
grep -Fq "192.0.2.0/24" <<<"${route_output}"
grep -Fq "203.0.113.0/24" <<<"${route_output}"
grep -Fq "metric 42424" <<<"${route_output}"

# tun-smoke deliberately holds the device briefly so the route can be
# inspected while it owns the namespace; wait past that hold before checking
# graceful cleanup.
sleep 3
route_after="$("${host_nsenter}" -t "${normal_ns_pid}" -n "${host_ip}" -4 route show dev "${tun_name}" 2>/dev/null || true)"
if grep -Eq '198\.18\.0\.0/15|192\.0\.2\.0/24|203\.0\.113\.0/24' <<<"${route_after}"; then
  printf '%s\n' "${route_after}"
  echo "[tun-route-matrix] routes remained after graceful owner exit" >&2
  exit 1
fi
echo "tun-route-after-graceful=absent"
podman wait "${name}" >/dev/null

podman rm -f "${force_name}" >/dev/null 2>&1 || true
podman run -d --name "${force_name}" \
  --privileged --network=none --device=/dev/net/tun \
  -e "DORADUS_TUN_NAME=${force_tun_name}" \
  -e DORADUS_TUN_ROUTE_SMOKE=1 \
  -e DORADUS_TUN_HOLD_MS=30000 \
  -v "${binary}:/usr/local/bin/tun-smoke:ro" \
  -v "${state_dir}:/state:Z" \
  --entrypoint /bin/sh "${image}" \
  -ceu '(/usr/local/bin/tun-smoke & echo $! >/state/force.pid; wait $!) & child=$!; while kill -0 "$child" 2>/dev/null; do sleep 0.1; done; sleep 5' \
  >"${cache_dir}/force-container-id"

force_opened=0
for _ in $(seq 1 100); do
  podman logs "${force_name}" >"${force_log_path}" 2>&1 || true
  if grep -Fq "tun-route-installed count=3" "${force_log_path}"; then
    force_opened=1
    break
  fi
  if ! podman inspect -f '{{.State.Running}}' "${force_name}" 2>/dev/null | grep -Fq true; then
    break
  fi
  sleep 0.1
done
if (( force_opened == 0 )); then
  cat "${force_log_path}"
  echo "[tun-route-matrix] force-stop owner did not install routes" >&2
  exit 1
fi
force_ns_pid="$(podman inspect -f '{{.State.Pid}}' "${force_name}")"
podman exec "${force_name}" sh -c 'kill -KILL "$(cat /state/force.pid)"'
sleep 0.5
force_route_after="$("${host_nsenter}" -t "${force_ns_pid}" -n "${host_ip}" -4 route show dev "${force_tun_name}" 2>/dev/null || true)"
if grep -Eq '198\.18\.0\.0/15|192\.0\.2\.0/24|203\.0\.113\.0/24' <<<"${force_route_after}"; then
  printf '%s\n' "${force_route_after}"
  echo "[tun-route-matrix] routes remained after owner SIGKILL" >&2
  exit 1
fi
echo "tun-route-after-sigkill=absent"

podman rm -f "${name}" "${force_name}" >/dev/null 2>&1 || true
echo "tun-route-matrix-passed routes=3 graceful=1 sigkill=1 logs=${cache_dir}"
