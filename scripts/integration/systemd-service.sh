#!/usr/bin/env bash
set -euo pipefail

# Exercise the real Linux service lifecycle inside a disposable systemd
# container. The host is only used for the binary and cache-backed logs; the
# unit, binary install path, database, and backups stay inside the container.

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${repo_dir}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_SYSTEMD_DIR:-${cache_root}/integration/systemd-service}"
image="${YUHAIIN_SYSTEMD_IMAGE:-quay.io/fedora/fedora:latest}"
boot_command="${YUHAIIN_SYSTEMD_BOOT:-dnf -y install systemd dbus >/state/bootstrap.log 2>&1 && exec /sbin/init}"
run_id="$(date +%Y%m%d%H%M%S)-$$"
run_dir="${scenario_dir}/${run_id}"
container="yuhaiin-systemd-${run_id}"
binary="${target_dir}/debug/yuhaiin"

command -v podman >/dev/null
mkdir -p "${run_dir}"

echo "[systemd-service] building runtime binary in Podman"
"${repo_dir}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${run_dir}" -- \
  cargo build --locked \
  -p yuhaiin-api \
  --all-features \
  --bin yuhaiin \
  >"${run_dir}/build.log"
test -x "${binary}"

cleanup() {
  podman rm -f "${container}" >"${run_dir}/cleanup.log" 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "[systemd-service] starting ${image}"
podman run -d \
  --privileged \
  --systemd=always \
  --name "${container}" \
  -v "${binary}:/build/yuhaiin:ro" \
  -v "${run_dir}:/state:Z" \
  --entrypoint /bin/sh \
  "${image}" \
  -c "${boot_command}" \
  >"${run_dir}/container-id"

systemd_ready=0
for _ in $(seq 1 60); do
  systemd_state="$(podman exec "${container}" systemctl show --property=SystemState --value 2>/dev/null || true)"
  if [[ "${systemd_state}" == "running" || "${systemd_state}" == "degraded" ]]; then
    systemd_ready=1
    break
  fi
  sleep 1
done
if [[ "${systemd_ready}" -ne 1 ]]; then
  podman logs "${container}" >"${run_dir}/container.log" 2>&1 || true
  echo "[systemd-service] systemd did not become ready; logs=${run_dir}" >&2
  exit 77
fi

exec_service() {
  podman exec "${container}" /build/yuhaiin "$@"
}

echo "[systemd-service] installing and checking service"
exec_service install -host 127.0.0.1:50051 -path /var/lib/yuhaiin
exec_service health -host 127.0.0.1:50051 -path /var/lib/yuhaiin
podman exec "${container}" systemctl restart yuhaiin.service
exec_service health -host 127.0.0.1:50051 -path /var/lib/yuhaiin

echo "[systemd-service] forcing a bad install and verifying automatic rollback"
if exec_service install -host not-an-endpoint -path /var/lib/yuhaiin; then
  echo "[systemd-service] bad install unexpectedly succeeded" >&2
  exit 1
fi
exec_service health -host 127.0.0.1:50051 -path /var/lib/yuhaiin

echo "[systemd-service] exercising explicit rollback"
exec_service rollback -host 127.0.0.1:50051 -path /var/lib/yuhaiin
exec_service health -host 127.0.0.1:50051 -path /var/lib/yuhaiin

podman exec "${container}" systemctl status yuhaiin.service \
  >"${run_dir}/systemctl-status.log" 2>&1 || true
podman logs "${container}" >"${run_dir}/container.log" 2>&1 || true
echo "[systemd-service] passed; logs=${run_dir}"
