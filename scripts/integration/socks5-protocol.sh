#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
cache_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration-reusable}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
mkdir -p "${cache_dir}"

echo "[socks5-protocol] building protocol unit-test binary"
cargo test \
  --manifest-path "${repo_dir}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-protocol \
  --all-features \
  --offline \
  --lib \
  --no-run \
  >"${cache_dir}/socks5-protocol-build.log"

test_binary="$({
  find "${target_dir}/debug/deps" -maxdepth 1 -type f -executable \
    -name 'yuhaiin_protocol-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
test -n "${test_binary}"

echo "[socks5-protocol] running protocol tests in Podman"
podman run --rm \
  --network=none \
  -v "${test_binary}:/usr/local/bin/yuhaiin-protocol-tests:ro" \
  --entrypoint /bin/sh \
  "${image}" \
  -ec '/usr/local/bin/yuhaiin-protocol-tests --nocapture socks5' \
  | tee "${cache_dir}/socks5-protocol.log"

grep -q 'test result: ok' "${cache_dir}/socks5-protocol.log"
echo "[socks5-protocol] passed; logs=${cache_dir}"
