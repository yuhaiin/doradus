#!/usr/bin/env bash
set -euo pipefail

# Compile test harnesses on the host, then run every generated harness inside
# disposable Podman containers. This keeps loopback, filesystem writes and
# capability failures out of the host runtime while preserving one complete
# workspace-test command.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/workspace-tests}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"

command -v cargo >/dev/null
command -v podman >/dev/null
mkdir -p "${scenario_dir}"

echo "[workspace-tests] compiling test harnesses on the host"
CARGO_TERM_COLOR=never cargo build \
  --manifest-path "${repo_root}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-runtime \
  --all-features \
  --offline \
  --bin yuhaiin \
  >"${scenario_dir}/runtime-build.log" 2>&1
CARGO_TERM_COLOR=never cargo test \
  --manifest-path "${repo_root}/Cargo.toml" \
  --target-dir "${target_dir}" \
  --workspace \
  --all-features \
  --offline \
  --no-run \
  >"${scenario_dir}/build.log" 2>&1

declare -a test_binaries=()
while IFS= read -r binary; do
  [[ -x "${binary}" ]] || continue
  test_binaries+=("/target/debug/deps/$(basename "${binary}")")
done < <(awk '/^ *Executable / { gsub(/[()]/, "", $NF); print $NF }' "${scenario_dir}/build.log")

if (( ${#test_binaries[@]} == 0 )); then
  echo "[workspace-tests] cargo produced no test harnesses" >&2
  exit 1
fi

declare -a isolated_binaries=()
declare -a host_network_binaries=()
declare -a stats_binaries=()
for test_binary in "${test_binaries[@]}"; do
  case "${test_binary##*/}" in
    service_chain-*) host_network_binaries+=("${test_binary}") ;;
    stats_concurrency-*) stats_binaries+=("${test_binary}") ;;
    *) isolated_binaries+=("${test_binary}") ;;
  esac
done

echo "[workspace-tests] running ${#test_binaries[@]} harnesses in Podman"

run_in_podman() {
  local network_mode="$1"
  local log_path="$2"
  shift 2
  if (( $# == 0 )); then
    return 0
  fi

  podman run --rm --privileged --network="${network_mode}" \
    -v "${target_dir}:/target:ro" \
    -v "${scenario_dir}:/state:Z" \
    -v "${target_dir}/debug/yuhaiin:/usr/local/bin/yuhaiin:ro" \
    -e YUHAIIN_RUNTIME_BIN=/usr/local/bin/yuhaiin \
    -e HOME=/state/home \
    -e TMPDIR=/state/tmp \
    -e XDG_CACHE_HOME=/state/cache \
    -e YUHAIIN_CACHE_DIR=/state/cache/yuhaiin-rust \
    -e YUHAIIN_INTEGRATION_DIR=/state/integration \
    -e YUHAIIN_RESET_INTEGRATION_STATE=1 \
    --entrypoint /bin/sh \
    "${image}" \
    -ec '
      set -eu
      mkdir -p "$HOME" "$TMPDIR" "$XDG_CACHE_HOME" "$YUHAIIN_CACHE_DIR"
      for test_binary do
        echo "[workspace-tests] ${test_binary}"
        case "${test_binary##*/}" in
          service_chain-*) "${test_binary}" --nocapture --test-threads=1 ;;
          *) "${test_binary}" --nocapture ;;
        esac
      done
    ' \
    -- "$@" \
    | tee "${log_path}"

  grep -q 'test result: ok' "${log_path}"
}

# Rootless `--network=none` has a known loopback/HTTP2 discrepancy in this
# environment. Keep ordinary harnesses isolated, give the process-level stats
# harness its own disposable namespace because it force-stops child services,
# and run the process-chain harness in the same Podman host-network mode as
# its dedicated smoke test. Every path still executes only inside containers.
run_in_podman none "${scenario_dir}/podman-isolated.log" "${isolated_binaries[@]}"
run_in_podman none "${scenario_dir}/podman-stats.log" "${stats_binaries[@]}"
run_in_podman host "${scenario_dir}/podman-service-chain.log" "${host_network_binaries[@]}"
echo "[workspace-tests] passed; logs=${scenario_dir}"
