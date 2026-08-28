#!/usr/bin/env bash
set -euo pipefail

# Compile the process-level chain harness in Podman, then run both the
# runtime child and its deterministic BoringTun peer inside one disposable
# Podman namespace. No host runtime, host network, or /tmp is used.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${DORADUS_CACHE_DIR:-${repo_root}/.cache/doradus}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
integration_dir="${DORADUS_INTEGRATION_DIR:-${cache_root}/integration/wireguard-chain}"
image="${DORADUS_TEST_IMAGE:-docker.io/library/debian:testing}"

command -v podman >/dev/null
mkdir -p "${integration_dir}"

echo "[wireguard-chain] compiling runtime and process harness in Podman"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${integration_dir}" -- \
  cargo build \
  --locked -p doradus-api --bin doradus --all-features \
  >"${integration_dir}/runtime-build.log" 2>&1
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${integration_dir}" -- \
  cargo test \
  --locked -p doradus-api --all-features --test wireguard_chain --no-run \
  >"${integration_dir}/build.log" 2>&1

harness_path="$(sed -n 's/^  Executable tests\/wireguard_chain.rs (\(.*\))$/\1/p' "${integration_dir}/build.log" | tail -n 1)"
harness="${harness_path##*/}"
if [[ -z "${harness}" || ! -x "${target_dir}/debug/deps/${harness}" ]]; then
  echo "[wireguard-chain] could not find the current harness" >&2
  cat "${integration_dir}/build.log" >&2
  exit 1
fi

log_path="${integration_dir}/podman.log"
podman run --rm --privileged --network=none \
  -v "${target_dir}:/target:ro" \
  -v "${integration_dir}:/state:Z" \
  -v "${target_dir}/debug/doradus:/usr/local/bin/doradus:ro" \
  -e DORADUS_RUNTIME_BIN=/usr/local/bin/doradus \
  -e HOME=/state/home \
  -e TMPDIR=/state/cache/tmp \
  -e DORADUS_CACHE_DIR=/state/cache \
  -e DORADUS_CACHE_DIR=/state/cache/doradus \
  -e DORADUS_INTEGRATION_DIR=/state/integration \
  -e DORADUS_RESET_INTEGRATION_STATE=1 \
  --entrypoint /bin/sh \
  "${image}" \
  -ec 'set -eu; mkdir -p "$HOME" "$TMPDIR" "$DORADUS_CACHE_DIR" "$DORADUS_CACHE_DIR" "$DORADUS_INTEGRATION_DIR"; exec "/target/debug/deps/'"${harness}"'" --nocapture --test-threads=1' \
  | tee "${log_path}"

grep -q 'test result: ok' "${log_path}"
echo "[wireguard-chain] passed; logs=${log_path}"
