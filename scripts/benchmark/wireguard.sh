#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_WIREGUARD_BENCH_DIR:-${cache_root}/benchmarks/wireguard}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
bytes="${YUHAIIN_WIREGUARD_BENCH_BYTES:-67108864}"

command -v cargo >/dev/null
command -v podman >/dev/null
mkdir -p "${scenario_dir}"

echo "[wireguard-throughput] compiling the release harness on the host"
CARGO_TERM_COLOR=never cargo test \
  --manifest-path "${repo_root}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-wireguard \
  --all-targets \
  --no-run \
  --release \
  --offline \
  >"${scenario_dir}/build.log" 2>&1

harness_path="$(sed -n 's/^  Executable unittests src\/lib.rs (\(.*\))$/\1/p' "${scenario_dir}/build.log" | tail -n 1)"
harness="${harness_path##*/}"
if [[ -z "${harness}" ]]; then
  echo "[wireguard-throughput] could not find the current test harness" >&2
  cat "${scenario_dir}/build.log" >&2
  exit 1
fi
if [[ ! -x "${target_dir}/release/deps/${harness}" ]]; then
  echo "[wireguard-throughput] test harness is not executable: ${target_dir}/release/deps/${harness}" >&2
  exit 1
fi

log_path="${scenario_dir}/podman.log"
echo "[wireguard-throughput] running BoringTun packet benchmark in Podman"
podman run --rm --network=none \
  -v "${target_dir}:/target:ro" \
  -v "${scenario_dir}:/state:Z" \
  -e YUHAIIN_WIREGUARD_BENCH_BYTES="${bytes}" \
  --entrypoint "/target/release/deps/${harness}" \
  "${image}" \
  --ignored --exact --nocapture --test-threads=1 \
  tests::wireguard_packet_throughput_benchmark \
  2>&1 | tee "${log_path}"

grep -q 'BENCHMARK ' "${log_path}"
echo "[wireguard-throughput] passed; result/logs=${scenario_dir}"
