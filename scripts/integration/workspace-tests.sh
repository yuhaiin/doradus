#!/usr/bin/env bash
set -euo pipefail

# Compile test harnesses and run every generated harness inside disposable
# Podman containers. This keeps the Rust toolchain, loopback, filesystem writes
# and capability failures out of the host runtime while preserving one
# complete workspace-test command.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${DORADUS_CACHE_DIR:-${repo_root}/.cache/doradus}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${DORADUS_INTEGRATION_DIR:-${cache_root}/integration/workspace-tests}"
cargo_home="${DORADUS_CARGO_HOME:-${cache_root}/cargo-home}"
image="${DORADUS_TEST_IMAGE:-docker.io/library/debian:testing}"
build_image="${DORADUS_BUILD_IMAGE:-docker.io/library/rust:latest}"

command -v podman >/dev/null
mkdir -p "${target_dir}" "${scenario_dir}" "${cargo_home}"

echo "[workspace-tests] compiling test harnesses in Podman"
podman run --rm --network=host \
  -v "${repo_root}:/workspace:ro" \
  -v "${target_dir}:/target:Z" \
  -v "${scenario_dir}:/state:Z" \
  -v "${cargo_home}:/cargo-home:Z" \
  --entrypoint /bin/sh \
  "${build_image}" \
  -ec '
    set -eu
    mkdir -p /state/home /state/cache/tmp
    export HOME=/state/home
    export CARGO_HOME=/cargo-home
    export CARGO_TARGET_DIR=/target
    export TMPDIR=/state/cache/tmp
    # quiche vendored BoringSSL build is driven by CMake.  The Rust image
    # provides the native C/C++ toolchain but does not include CMake.
    apt-get update >/state/apt-update.log
    DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends cmake \
      >/state/apt-install.log
    CARGO_TERM_COLOR=never cargo build \
      --locked \
      --manifest-path /workspace/Cargo.toml \
      -p doradus-api \
      --all-features \
      --bin doradus \
      >/state/runtime-build.log 2>&1
    CARGO_TERM_COLOR=never cargo test \
      --locked \
      --manifest-path /workspace/Cargo.toml \
      --workspace \
      --all-features \
      --no-run \
      >/state/build.log 2>&1
  '

declare -a test_binaries=()
while IFS= read -r binary; do
  binary_name="$(basename "${binary}")"
  [[ -x "${target_dir}/debug/deps/${binary_name}" ]] || continue
  test_binaries+=("/target/debug/deps/${binary_name}")
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
    service_chain-*|wireguard_chain-*) host_network_binaries+=("${test_binary}") ;;
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
    -v "${target_dir}/debug/doradus:/usr/local/bin/doradus:ro" \
    -e DORADUS_RUNTIME_BIN=/usr/local/bin/doradus \
    -e HOME=/state/home \
    -e TMPDIR=/state/cache/tmp \
    -e DORADUS_CACHE_DIR=/state/cache/doradus \
    -e DORADUS_INTEGRATION_DIR=/state/integration \
    -e DORADUS_RESET_INTEGRATION_STATE=1 \
    --entrypoint /bin/sh \
    "${image}" \
    -ec '
      set -eu
      mkdir -p "$HOME" "$TMPDIR" "$DORADUS_CACHE_DIR"
      for test_binary do
        echo "[workspace-tests] ${test_binary}"
        case "${test_binary##*/}" in
          service_chain-*) "${test_binary}" --nocapture --test-threads=1 ;;
          api_reload_flow-*) "${test_binary}" --nocapture --test-threads=1 ;;
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
# serialize the API reload harness because its two cases intentionally share a
# persistent state directory, and run the process-chain harnesses in their own
# Podman host-network mode. Every path still executes only inside containers.
run_in_podman none "${scenario_dir}/podman-isolated.log" "${isolated_binaries[@]}"
run_in_podman none "${scenario_dir}/podman-stats.log" "${stats_binaries[@]}"

# Process-level harnesses can leave child services behind until their test
# process exits. Run each host-network harness in its own disposable
# container, otherwise a fixed listener from one harness can collide with the
# next harness while the parent container is still alive.
host_network_index=0
for test_binary in "${host_network_binaries[@]}"; do
  host_network_index=$((host_network_index + 1))
  run_in_podman host \
    "${scenario_dir}/podman-host-${host_network_index}.log" \
    "${test_binary}"
done
echo "[workspace-tests] passed; logs=${scenario_dir}"
