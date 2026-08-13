#!/usr/bin/env bash
set -euo pipefail

# Compile and execute the WireGuard harness in isolated Podman containers. The
# test creates two local userspace peers, so it needs no external network and
# does not touch a host WireGuard device.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
integration_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/wireguard}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"

command -v podman >/dev/null
mkdir -p "${integration_dir}"

echo "[wireguard] compiling the harness in Podman"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${integration_dir}" -- \
  cargo test --locked \
  -p yuhaiin-wireguard \
  --all-targets \
  --no-run \
  >"${integration_dir}/build.log" 2>&1

harness_path="$(sed -n 's/^  Executable unittests src\/lib.rs (\(.*\))$/\1/p' "${integration_dir}/build.log" | tail -n 1)"
harness="${harness_path##*/}"
if [[ -z "${harness}" ]]; then
  echo "[wireguard] could not find the current test harness in ${integration_dir}/build.log" >&2
  cat "${integration_dir}/build.log" >&2
  exit 1
fi
if [[ ! -x "${target_dir}/debug/deps/${harness}" ]]; then
  echo "[wireguard] test harness is not executable: ${target_dir}/debug/deps/${harness}" >&2
  exit 1
fi

log_path="${integration_dir}/podman.log"
podman run --rm --network=none \
  -v "${target_dir}:/target:ro" \
  -v "${integration_dir}:/state:Z" \
  --entrypoint "/target/debug/deps/${harness}" \
  "${image}" \
  --nocapture --test-threads=1 \
  | tee "${log_path}"

grep -q 'test result: ok' "${log_path}"
echo "[wireguard] passed; logs=${log_path}"
