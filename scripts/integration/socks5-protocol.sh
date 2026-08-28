#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${DORADUS_CACHE_DIR:-${repo_dir}/.cache/doradus}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
cache_dir="${DORADUS_INTEGRATION_DIR:-${cache_root}/integration-reusable}"
image="${DORADUS_TEST_IMAGE:-docker.io/library/debian:testing}"
mkdir -p "${cache_dir}"

echo "[socks5-protocol] building protocol unit-test binary in Podman"
"${repo_dir}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${cache_dir}" -- \
  cargo test --locked \
  -p doradus-protocol \
  --all-features \
  --lib \
  --no-run \
  >"${cache_dir}/socks5-protocol-build.log"

test_binary="$({
  find "${target_dir}/debug/deps" -maxdepth 1 -type f -executable \
    -name 'doradus_protocol-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
test -n "${test_binary}"

echo "[socks5-protocol] running protocol tests in Podman"
podman run --rm \
  --network=none \
  -v "${test_binary}:/usr/local/bin/doradus-protocol-tests:ro" \
  --entrypoint /bin/sh \
  "${image}" \
  -ec '/usr/local/bin/doradus-protocol-tests --nocapture socks5' \
  | tee "${cache_dir}/socks5-protocol.log"

grep -q 'test result: ok' "${cache_dir}/socks5-protocol.log"
echo "[socks5-protocol] passed; logs=${cache_dir}"
