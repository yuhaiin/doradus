#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${DORADUS_CACHE_DIR:-${repo_root}/.cache/doradus}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${DORADUS_INTEGRATION_DIR:-${cache_root}/integration/dns-source-bind}"
image="${DORADUS_TEST_IMAGE:-docker.io/library/debian:testing}"

mkdir -p "${scenario_dir}"

echo "[dns-source-bind] building core test binary in Podman"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${scenario_dir}" -- \
  cargo test --locked \
  -p doradus-core \
  --all-features \
  --lib \
  --no-run \
  >"${scenario_dir}/build.log"

test_binary="$({
  find "${target_dir}/debug/deps" -maxdepth 1 -type f -executable \
    -name 'doradus_core-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
test -n "${test_binary}"

echo "[dns-source-bind] running UDP/TCP source-address checks in Podman"
podman run --rm \
  --network=none \
  -v "${test_binary}:/usr/local/bin/doradus-core-test:ro" \
  --entrypoint /bin/sh \
  "${image}" \
  -ec '
    set -eu
    /usr/local/bin/doradus-core-test \
      dns::async_udp::tests::async_udp_client_and_handler_round_trip_with_original_transaction \
      --exact --nocapture
    /usr/local/bin/doradus-core-test \
      dns_tcp::async_tcp::tests::async_tcp_client_and_server_round_trip_preserves_transaction \
      --exact --nocapture
  ' \
  | tee "${scenario_dir}/podman.log"

grep -q 'test result: ok' "${scenario_dir}/podman.log"
echo "[dns-source-bind] passed; logs=${scenario_dir}"
