#!/usr/bin/env bash
set -euo pipefail

# Compare public management responses from a stopped, consistent Go database
# snapshot. Go and Rust always receive separate copies; neither process may
# write the source fixture or share a live state.db.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
go_root="${YUHAIIN_GO_DIR:-$(cd "${repo_root}/../yuhaiin" && pwd)}"
source_db="${YUHAIIN_SOURCE_DB:?set YUHAIIN_SOURCE_DB to a stopped, consistent Go state.db snapshot}"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/go-api-parity}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
go_http="${YUHAIIN_GO_HTTP:-127.0.0.1:55252}"
rust_http="${YUHAIIN_RUST_HTTP:-127.0.0.1:55251}"

command -v curl >/dev/null
command -v jq >/dev/null
command -v go >/dev/null
test -f "${source_db}"
mkdir -p "${scenario_dir}/go" "${scenario_dir}/rust"

cp --reflink=auto "${source_db}" "${scenario_dir}/go/state.db"
cp --reflink=auto "${source_db}" "${scenario_dir}/rust/state.sqlite"

echo "[go-api-parity] building Go and Rust services"
go_binary="${scenario_dir}/yuhaiin-go"
(cd "${go_root}" && GOEXPERIMENT=jsonv2,greenteagc go build -o "${go_binary}" ./cmd/yuhaiin)
cargo build \
  --manifest-path "${repo_root}/Cargo.toml" \
  --target-dir "${target_dir}" \
  -p yuhaiin-runtime \
  --all-features \
  --offline \
  --bin yuhaiin \
  >"${scenario_dir}/rust-build.log"
rust_binary="${target_dir}/debug/yuhaiin"
test -x "${rust_binary}"

"${go_binary}" -host "${go_http}" -path "${scenario_dir}/go" >"${scenario_dir}/go.log" 2>&1 &
go_pid=$!
YUHAIIN_DB="${scenario_dir}/rust/state.sqlite" \
YUHAIIN_HTTP="${rust_http}" \
  "${rust_binary}" >"${scenario_dir}/rust.log" 2>&1 &
rust_pid=$!

cleanup() {
  kill -TERM "${go_pid}" "${rust_pid}" 2>/dev/null || true
  wait "${go_pid}" 2>/dev/null || true
  wait "${rust_pid}" 2>/dev/null || true
}
trap cleanup EXIT

wait_ready() {
  local address="$1"
  for _ in $(seq 1 120); do
    if curl -fsS --max-time 1 "http://${address}/api/v2/rpc/info" \
      -H 'content-type: application/json' --data '{}' >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "[go-api-parity] service did not become ready: ${address}" >&2
  return 1
}

wait_ready "${go_http}"
wait_ready "${rust_http}"

request() {
  local address="$1"
  local operation="$2"
  local body="$3"
  curl -fsS "http://${address}/api/v2/rpc/${operation}" \
    -H 'content-type: application/json' \
    --data "${body}"
}

normalize() {
  local operation="$1"
  case "${operation}" in
    nodes.get|resolvers.get|inbounds.get)
      jq -S 'if (.items | type) == "array" then .items |= sort_by(.id) else . end'
      ;;
    *)
      jq -S .
      ;;
  esac
}

declare -a operations=(
  'settings.get|{}'
  'nodes.get|{"page":1,"page_size":1000}'
  'resolvers.get|{"page":1,"page_size":1000}'
  'inbounds.get|{"page":1,"page_size":1000}'
  'connections.total|{}'
)

for request_spec in "${operations[@]}"; do
  operation="${request_spec%%|*}"
  body="${request_spec#*|}"
  safe_name="${operation//./-}"
  request "${go_http}" "${operation}" "${body}" | normalize "${operation}" >"${scenario_dir}/go-${safe_name}.json"
  request "${rust_http}" "${operation}" "${body}" | normalize "${operation}" >"${scenario_dir}/rust-${safe_name}.json"
  if ! diff -u "${scenario_dir}/go-${safe_name}.json" "${scenario_dir}/rust-${safe_name}.json" \
    >"${scenario_dir}/${safe_name}.diff"; then
    echo "[go-api-parity] response mismatch: ${operation}" >&2
    sed -n '1,160p' "${scenario_dir}/${safe_name}.diff" >&2
    exit 1
  fi
  echo "[go-api-parity] identical: ${operation}"
done

echo "[go-api-parity] passed; logs=${scenario_dir}"
