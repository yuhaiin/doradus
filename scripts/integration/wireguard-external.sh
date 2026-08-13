#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/wireguard-external}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
config_path="${YUHAIIN_WIREGUARD_EXTERNAL_CONFIG:-}"

if [[ -z "${config_path}" ]]; then
  echo "set YUHAIIN_WIREGUARD_EXTERNAL_CONFIG to a user-supplied WARP/WireGuard JSON or wg-quick INI file" >&2
  exit 2
fi
if [[ ! -r "${config_path}" ]]; then
  echo "WireGuard external config is not readable: ${config_path}" >&2
  exit 2
fi
if [[ -z "${YUHAIIN_WIREGUARD_EXTERNAL_TCP_TARGET:-}" && -z "${YUHAIIN_WIREGUARD_EXTERNAL_UDP_TARGET:-}" ]]; then
  echo "set YUHAIIN_WIREGUARD_EXTERNAL_TCP_TARGET or YUHAIIN_WIREGUARD_EXTERNAL_UDP_TARGET" >&2
  exit 2
fi

mkdir -p "${scenario_dir}"
config_path="$(realpath "${config_path}")"

echo "[wireguard-external] compiling the opt-in harness in Podman"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${scenario_dir}" -- \
  cargo test --locked \
  -p yuhaiin-wireguard \
  --test external \
  --no-run \
  >"${scenario_dir}/build.log" 2>&1

harness_path="$(sed -n 's/^  Executable tests\/external.rs (\(.*\))$/\1/p' "${scenario_dir}/build.log" | tail -n 1)"
harness="${harness_path##*/}"
if [[ -z "${harness}" || ! -x "${target_dir}/debug/deps/${harness}" ]]; then
  cat "${scenario_dir}/build.log" >&2
  echo "[wireguard-external] could not find the external harness" >&2
  exit 1
fi

log_path="${scenario_dir}/podman.log"
podman run --rm --network=host \
  -v "${target_dir}:/target:ro" \
  -v "${config_path}:/state/wireguard.json:ro" \
  -v "${scenario_dir}:/state/logs:Z" \
  -e YUHAIIN_WIREGUARD_EXTERNAL_CONFIG=/state/wireguard.json \
  -e "YUHAIIN_WIREGUARD_EXTERNAL_TCP_TARGET=${YUHAIIN_WIREGUARD_EXTERNAL_TCP_TARGET:-}" \
  -e "YUHAIIN_WIREGUARD_EXTERNAL_TCP_REQUEST=${YUHAIIN_WIREGUARD_EXTERNAL_TCP_REQUEST:-}" \
  -e "YUHAIIN_WIREGUARD_EXTERNAL_TCP_EXPECT=${YUHAIIN_WIREGUARD_EXTERNAL_TCP_EXPECT:-}" \
  -e "YUHAIIN_WIREGUARD_EXTERNAL_UDP_TARGET=${YUHAIIN_WIREGUARD_EXTERNAL_UDP_TARGET:-}" \
  -e "YUHAIIN_WIREGUARD_EXTERNAL_UDP_PAYLOAD_HEX=${YUHAIIN_WIREGUARD_EXTERNAL_UDP_PAYLOAD_HEX:-}" \
  -e "YUHAIIN_WIREGUARD_EXTERNAL_UDP_EXPECT_REPLY=${YUHAIIN_WIREGUARD_EXTERNAL_UDP_EXPECT_REPLY:-1}" \
  --entrypoint "/target/debug/deps/${harness}" \
  "${image}" \
  --ignored --nocapture --test-threads=1 \
  2>&1 | tee "${log_path}"

grep -q 'test result: ok' "${log_path}"
echo "[wireguard-external] passed; logs=${scenario_dir}"
