#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
go_checkout="${YUHAIIN_GO_DIR:-$(cd "${repo_root}/../yuhaiin" && pwd)}"
cache_root="${YUHAIIN_CACHE_DIR:-${repo_root}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_GO_INTEROP_DIR:-${cache_root}/integration/go-protocol-interop}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"

command -v podman >/dev/null
command -v go >/dev/null
test -d "${go_checkout}"

go_bin="$(readlink -f "$(command -v go)")"
go_root="${YUHAIIN_GOROOT:-$(go env GOROOT)}"
go_mod_cache="${YUHAIIN_GOMODCACHE:-$(go env GOMODCACHE)}"
test -x "${go_bin}"
test -d "${go_root}"
test -d "${go_mod_cache}"

mkdir -p "${scenario_dir}"
mkdir -p "${scenario_dir}/go-tmp"

echo "[go-protocol-interop] compiling Rust harnesses in Podman"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${scenario_dir}" -- \
  env CARGO_TERM_COLOR=never cargo test --locked \
  -p yuhaiin-chain \
  --test go_yuubinsya_interop \
  --test go_websocket_interop \
  --test standalone_http2 \
  --no-run \
  >"${scenario_dir}/build.log" 2>&1

"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${scenario_dir}" -- \
  env CARGO_TERM_COLOR=never cargo test --locked \
  -p yuhaiin-protocol \
  --all-features \
  --test go_vless_interop \
  --test go_vless_udp_interop \
  --test go_transport_interop \
  --test go_vmess_interop \
  --test go_vmess_udp_interop \
  --test go_trojan_interop \
  --test go_trojan_udp_interop \
  --no-run \
  >"${scenario_dir}/protocol-build.log" 2>&1

# podman-cargo compiles with CARGO_MANIFEST_DIR=/workspace. Each runtime
# container therefore mounts the repository at that path as well as at its
# host path, so Go helper sources used by ignored tests resolve correctly.
tests=(go_yuubinsya_interop go_websocket_interop standalone_http2)
for test_name in "${tests[@]}"; do
  harness_path="$(sed -n "s#^  Executable tests/${test_name}\.rs (\(.*\))\$#\1#p" "${scenario_dir}/build.log" | tail -n 1)"
  harness="${harness_path##*/}"
  if [[ -z "${harness}" || ! -x "${target_dir}/debug/deps/${harness}" ]]; then
    echo "[go-protocol-interop] could not find ${test_name} harness" >&2
    cat "${scenario_dir}/build.log" >&2
    exit 1
  fi

  log_path="${scenario_dir}/${test_name}.log"
  echo "[go-protocol-interop] running ${test_name} in Podman"
  podman run --rm --network=host \
    -v "${target_dir}:/target:ro" \
    -v "${scenario_dir}:/state:Z" \
    -v "${repo_root}:/workspace:ro" \
    -v "${repo_root}:${repo_root}:ro" \
    -v "${go_checkout}:${go_checkout}:ro" \
    -v "${go_root}:/go-root:ro" \
    -v "${go_bin}:/usr/local/bin/go:ro" \
    -v "${go_mod_cache}:/go-mod:ro" \
    -e PATH=/usr/local/bin:/usr/bin:/bin \
    -e GOROOT=/go-root \
    -e GOMODCACHE=/go-mod \
    -e GOCACHE=/state/go-build \
    -e GOTMPDIR=/state/go-tmp \
    -e YUHAIIN_CACHE_DIR=/state/cache \
    -e HOME=/state/home \
    -e YUHAIIN_GO_ROOT="${go_checkout}" \
    --entrypoint "/target/debug/deps/${harness}" \
    "${image}" \
    --ignored --nocapture --test-threads=1 \
    2>&1 | tee "${log_path}"

  grep -q 'test result: ok' "${log_path}"
done

protocol_tests=(
  go_vless_interop
  go_vless_udp_interop
  go_transport_interop
  go_vmess_interop
  go_vmess_udp_interop
  go_trojan_interop
  go_trojan_udp_interop
)
for test_name in "${protocol_tests[@]}"; do
  harness_path="$(sed -n "s#^  Executable tests/${test_name}\.rs (\(.*\))\$#\1#p" "${scenario_dir}/protocol-build.log" | tail -n 1)"
  harness="${harness_path##*/}"
  if [[ -z "${harness}" || ! -x "${target_dir}/debug/deps/${harness}" ]]; then
    echo "[go-protocol-interop] could not find ${test_name} harness" >&2
    cat "${scenario_dir}/protocol-build.log" >&2
    exit 1
  fi

  log_path="${scenario_dir}/${test_name}.log"
  echo "[go-protocol-interop] running ${test_name} in Podman"
  podman run --rm --network=host \
    -v "${target_dir}:/target:ro" \
    -v "${scenario_dir}:/state:Z" \
    -v "${repo_root}:/workspace:ro" \
    -v "${repo_root}:${repo_root}:ro" \
    -v "${go_checkout}:${go_checkout}:ro" \
    -v "${go_root}:/go-root:ro" \
    -v "${go_bin}:/usr/local/bin/go:ro" \
    -v "${go_mod_cache}:/go-mod:ro" \
    -e PATH=/usr/local/bin:/usr/bin:/bin \
    -e GOROOT=/go-root \
    -e GOMODCACHE=/go-mod \
    -e GOCACHE=/state/go-build \
    -e GOTMPDIR=/state/go-tmp \
    -e YUHAIIN_CACHE_DIR=/state/cache \
    -e HOME=/state/home \
    -e YUHAIIN_GO_ROOT="${go_checkout}" \
    --entrypoint "/target/debug/deps/${harness}" \
    "${image}" \
    --ignored --nocapture --test-threads=1 \
    2>&1 | tee "${log_path}"

  grep -q 'test result: ok' "${log_path}"
done

echo "[go-protocol-interop] passed; logs=${scenario_dir}"
