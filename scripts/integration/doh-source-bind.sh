#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${repo_root}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/doh-source-bind}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"

mkdir -p "${scenario_dir}"

echo "[doh-source-bind] building runtime DoH/DoT test binary in Podman"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${scenario_dir}" -- \
  cargo test --locked \
  -p yuhaiin-runtime \
  --all-features \
  --test doh_tls \
  --no-run \
  >"${scenario_dir}/build.log"

test_binary="$({
  find "${target_dir}/debug/deps" -maxdepth 1 -type f -executable \
    -name 'doh_tls-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
test -n "${test_binary}"

echo "[doh-source-bind] running DoH/DoT source-address check in Podman"
podman run --rm \
  --network=none \
  -v "${test_binary}:/usr/local/bin/yuhaiin-doh-test:ro" \
  --entrypoint /bin/sh \
  "${image}" \
  -ec '
    set -eu
    /usr/local/bin/yuhaiin-doh-test \
      rustls_encrypted_resolvers_honor_local_bind_address \
      --exact --nocapture
  ' \
  | tee "${scenario_dir}/podman.log"

grep -q 'test result: ok' "${scenario_dir}/podman.log"
echo "[doh-source-bind] passed; logs=${scenario_dir}"
