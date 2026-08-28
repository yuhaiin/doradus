#!/usr/bin/env bash
set -euo pipefail

# Build and execute the legacy snapshot test in disposable Podman containers.
# The source database is copied into the cache; the original Go snapshot is
# never opened for writing.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source_db="${DORADUS_GO_LEGACY_PRODUCTION_DB:?set DORADUS_GO_LEGACY_PRODUCTION_DB to a copied Go v1 state.db}"
cache_root="${DORADUS_CACHE_DIR:-${repo_root}/.cache/doradus}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${DORADUS_INTEGRATION_DIR:-${cache_root}/integration/legacy-v1-runtime}"
image="${DORADUS_TEST_IMAGE:-docker.io/library/debian:testing}"

command -v podman >/dev/null
test -f "${source_db}"
mkdir -p "${scenario_dir}"
cp --reflink=auto "${source_db}" "${scenario_dir}/input-state.db"

echo "[legacy-v1-runtime] building ignored test binary in Podman"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${scenario_dir}" -- \
  cargo test --locked \
  -p doradus-runtime \
  --all-features \
  --test legacy_v1_runtime \
  --no-run \
  >"${scenario_dir}/build.log" 2>&1

test_binary="$({
  find "${target_dir}/debug/deps" -maxdepth 1 -type f -executable \
    -name 'legacy_v1_runtime-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
test -n "${test_binary}"

echo "[legacy-v1-runtime] running snapshot test in Podman"
podman run --rm \
  --network=none \
  -v "${test_binary}:/usr/local/bin/doradus-legacy-v1:ro" \
  -v "${scenario_dir}:/state:Z" \
  -e DORADUS_CACHE_DIR=/state/cache \
  -e DORADUS_GO_LEGACY_PRODUCTION_DB=/state/input-state.db \
  --entrypoint /bin/sh \
  "${image}" \
  -ec '/usr/local/bin/doradus-legacy-v1 --ignored --nocapture' \
  | tee "${scenario_dir}/podman.log"

grep -q 'test result: ok' "${scenario_dir}/podman.log"
echo "[legacy-v1-runtime] passed; logs=${scenario_dir}"
