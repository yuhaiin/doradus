#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/dns-source-bind}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"

mkdir -p "${scenario_dir}"

echo "[dns-source-bind] building core test binary"
cargo test \
  --manifest-path "${repo_root}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-core \
  --all-features \
  --offline \
  --lib \
  --no-run \
  >"${scenario_dir}/build.log"

test_binary="$({
  find "${target_dir}/debug/deps" -maxdepth 1 -type f -executable \
    -name 'yuhaiin_core-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
test -n "${test_binary}"

echo "[dns-source-bind] running UDP/TCP source-address checks in Podman"
podman run --rm \
  --network=host \
  -v "${test_binary}:/usr/local/bin/yuhaiin-core-test:ro" \
  --entrypoint /bin/sh \
  "${image}" \
  -ec '
    set -eu
    /usr/local/bin/yuhaiin-core-test \
      dns_udp_async::tests::async_udp_client_and_handler_round_trip_with_original_transaction \
      --exact --nocapture
    /usr/local/bin/yuhaiin-core-test \
      dns_tcp_async::tests::async_tcp_client_and_server_round_trip_preserves_transaction \
      --exact --nocapture
  ' \
  | tee "${scenario_dir}/podman.log"

grep -q 'test result: ok' "${scenario_dir}/podman.log"
echo "[dns-source-bind] passed; logs=${scenario_dir}"
