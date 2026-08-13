#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/tun-ipv6-extension}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"

mkdir -p "${scenario_dir}"

echo "[tun-ipv6-extension] compiling core test binary in Podman"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${scenario_dir}" -- \
  cargo test --locked \
  -p yuhaiin-core \
  --all-features \
  --lib \
  --no-run \
  >"${scenario_dir}/build.log" 2>&1

test_binary="$({
  find "${target_dir}/debug/deps" -maxdepth 1 -type f -executable \
    -name 'yuhaiin_core-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
test -n "${test_binary}"

podman run --rm \
  --network=none \
  -v "${test_binary}:/usr/local/bin/yuhaiin-core-test:ro" \
  --entrypoint /bin/sh \
  "${image}" \
  -ec '
    set -eu
    for test_name in \
      tun::tun_unit_tests::ipv6_extension_headers_are_split_at_the_wire_boundary \
      tun::tun_unit_tests::ipv6_output_fragmentation_rejects_an_existing_fragment_header \
      tun::tun_unit_tests::ipv6_large_datagram_is_fragmented_at_the_tun_boundary; do
      /usr/local/bin/yuhaiin-core-test "${test_name}" --exact --nocapture
    done
  ' \
  | tee "${scenario_dir}/podman.log"

grep -q 'test result: ok' "${scenario_dir}/podman.log"

echo "[tun-ipv6-extension] running real kernel TUN packet path in Podman"
YUHAIIN_INTEGRATION_DIR="${scenario_dir}/kernel" \
YUHAIIN_TUN_IPV6_EXTENSION=1 \
YUHAIIN_TUN_PORTAL_V6="fd00:253::1/64" \
YUHAIIN_TUN_ROUTE="fd00:253::2/128" \
YUHAIIN_TUN_IPV6_SOURCE="fd00:253::1" \
YUHAIIN_TUN_IPV6_TARGET="[fd00:253::2]:18080" \
YUHAIIN_TUN_UDP_TRAFFIC=1 \
YUHAIIN_TUN_UDP_TRAFFIC_BYTES=32 \
  "${repo_root}/scripts/integration/tun-service.sh"

echo "[tun-ipv6-extension] passed; logs=${scenario_dir}"
