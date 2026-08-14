#!/usr/bin/env bash
set -euo pipefail

# This test intentionally mutates the native launchd service paths. It is for
# disposable CI runners; require an explicit CI environment or opt-in so a
# local invocation cannot uninstall a user's yuhaiin service by accident.
if [[ "${CI:-}" != "true" && "${YUHAIIN_NATIVE_SERVICE_ALLOW_GLOBAL:-}" != "1" ]]; then
  echo "[native-service-macos] refusing to touch launchd outside CI; set YUHAIIN_NATIVE_SERVICE_ALLOW_GLOBAL=1 to opt in" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
scenario_root="${YUHAIIN_NATIVE_SERVICE_MACOS_DIR:-${cache_root}/integration/native-service-macos}"
run_id="$(date +%Y%m%d%H%M%S)-$$"
run_dir="${scenario_root}/${run_id}"
binary="${repo_root}/target/release/yuhaiin"
staged="${run_dir}/staged-yuhaiin"
data_dir="${run_dir}/data"

mkdir -p "${run_dir}" "${data_dir}"
port="$(python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
host="127.0.0.1:${port}"
installed=0

cleanup() {
  if [[ "${installed}" == 1 ]]; then
    sudo -n "${binary}" uninstall >"${run_dir}/uninstall.log" 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

echo "[native-service-macos] building release binary in the native runner"
cargo build --locked --release \
  -p yuhaiin-runtime --bin yuhaiin --all-features \
  >"${run_dir}/build.log" 2>&1
test -x "${binary}"

echo "[native-service-macos] installing launchd service on ${host}"
installed=1
sudo -n "${binary}" install --host "${host}" --path "${data_dir}" \
  >"${run_dir}/install.log" 2>&1
sudo -n "${binary}" health --host "${host}" --path "${data_dir}" \
  >"${run_dir}/health-install.log" 2>&1
sudo -n "${binary}" restart --host "${host}" --path "${data_dir}" \
  >"${run_dir}/restart.log" 2>&1
sudo -n "${binary}" health --host "${host}" --path "${data_dir}" \
  >"${run_dir}/health-restart.log" 2>&1

echo "[native-service-macos] applying a staged update and checking rollback"
cp "${binary}" "${staged}"
sudo -n "${binary}" update-helper /usr/local/bin/yuhaiin "${staged}" \
  >"${run_dir}/update.log" 2>&1
sudo -n "${binary}" health --host "${host}" --path "${data_dir}" \
  >"${run_dir}/health-update.log" 2>&1
sudo -n "${binary}" rollback --host "${host}" --path "${data_dir}" \
  >"${run_dir}/rollback.log" 2>&1
sudo -n "${binary}" health --host "${host}" --path "${data_dir}" \
  >"${run_dir}/health-rollback.log" 2>&1

echo "[native-service-macos] passed; logs=${run_dir}"
