#!/usr/bin/env bash
set -euo pipefail

# Fetch the user-selected Country-without-asn database into the persistent
# cache, compile the ignored fixture test on the host, and run the test itself
# inside Podman. The source URL is public and the checksum prevents a partial
# or replaced download from becoming a test fixture.
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/maxmind}"
fixture_dir="${YUHAIIN_MAXMIND_FIXTURE_DIR:-${cache_root}/fixtures}"
fixture="${fixture_dir}/Country-without-asn.mmdb"
partial="${fixture}.partial"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
url="https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country-without-asn.mmdb"
expected_sha256="1d900f73aa4644d255793548319410ff559ef9294a662ec1a0354f106c794155"

mkdir -p "${scenario_dir}" "${fixture_dir}"

if [[ ! -f "${fixture}" ]] || [[ "$(sha256sum "${fixture}" | awk '{print $1}')" != "${expected_sha256}" ]]; then
  echo "[maxmind] downloading ${url}"
  rm -f "${partial}"
  curl --fail --location --retry 3 --silent --show-error "${url}" -o "${partial}"
  test "$(sha256sum "${partial}" | awk '{print $1}')" = "${expected_sha256}"
  mv "${partial}" "${fixture}"
fi

echo "[maxmind] compiling the fixture harness on the host"
cargo test \
  --manifest-path "${repo_dir}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-geo \
  --all-targets \
  --no-run \
  --offline \
  >"${scenario_dir}/build.log" 2>&1

harness="$({
  find "${target_dir}/debug/deps" -maxdepth 1 -type f -executable \
    -name 'yuhaiin_geo-*' -printf '%T@ %p\n'
} | sort -nr | head -n 1 | cut -d' ' -f2-)"
test -x "${harness}"

echo "[maxmind] running the real database test in Podman"
podman run --rm --network=none \
  -v "${harness}:/usr/local/bin/maxmind-test:ro" \
  -v "${fixture}:/state/Country-without-asn.mmdb:ro" \
  -e YUHAIIN_MAXMIND_FIXTURE=/state/Country-without-asn.mmdb \
  --entrypoint /usr/local/bin/maxmind-test \
  "${image}" \
  --ignored --nocapture --test-threads=1 downloaded_country_without_asn_fixture \
  | tee "${scenario_dir}/podman.log"

grep -q 'running 1 test' "${scenario_dir}/podman.log"
grep -q 'test result: ok' "${scenario_dir}/podman.log"
echo "[maxmind] passed; fixture=${fixture}; logs=${scenario_dir}"
