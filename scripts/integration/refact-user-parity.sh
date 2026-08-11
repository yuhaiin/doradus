#!/usr/bin/env bash
set -euo pipefail

# Compare the users API against the Go refact-user branch. This is opt-in
# because Go main does not currently carry these handlers.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
source_db="${YUHAIIN_SOURCE_DB:?set YUHAIIN_SOURCE_DB to a stopped Go state.db snapshot}"
go_root="${YUHAIIN_GO_REFAC_USER_DIR:-${cache_root}/go-refact-user}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/refact-user-parity}"
go_http="${YUHAIIN_GO_HTTP:-127.0.0.1:55452}"
rust_http="${YUHAIIN_RUST_HTTP:-127.0.0.1:55451}"
prepare_http="${YUHAIIN_PREPARE_HTTP:-127.0.0.1:55450}"

test -f "${source_db}"
test -f "${go_root}/go.mod" || {
  echo "missing Go refact-user worktree: ${go_root}" >&2
  echo "create it with: git -C ../yuhaiin worktree add --detach ${go_root} refact-user" >&2
  exit 1
}
command -v curl >/dev/null
command -v jq >/dev/null
mkdir -p "${scenario_dir}"

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

go_binary="${YUHAIIN_GO_BIN:-${scenario_dir}/yuhaiin-go}"
if [[ -z "${YUHAIIN_GO_BIN:-}" ]]; then
  (cd "${go_root}" && GOEXPERIMENT=jsonv2,greenteagc go build -o "${go_binary}" ./cmd/yuhaiin)
fi
test -x "${go_binary}"

run_id="${YUHAIIN_USER_SUFFIX:-${BASHPID}}"
run_root="${scenario_dir}/${run_id}"
mkdir -p "${run_root}"
cp --reflink=auto "${source_db}" "${run_root}/source.sqlite"

wait_ready() {
  local address="$1"
  for _ in $(seq 1 120); do
    if curl -fsS --max-time 1 "http://${address}/api/v2/rpc/info" \
      -H 'content-type: application/json' --data '{}' >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "service did not become ready: ${address}" >&2
  return 1
}

stop_pid() {
  local pid="$1"
  if [[ -n "${pid}" ]]; then
    kill -TERM "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  fi
}

prepare_pid=""
go_pid=""
rust_pid=""
cleanup() {
  stop_pid "${prepare_pid}"
  stop_pid "${go_pid}"
  stop_pid "${rust_pid}"
}
trap cleanup EXIT

prepared_db="${run_root}/prepared.sqlite"
cp --reflink=auto "${run_root}/source.sqlite" "${prepared_db}"
YUHAIIN_DB="${prepared_db}" YUHAIIN_HTTP="${prepare_http}" \
  "${rust_binary}" >"${run_root}/prepare.log" 2>&1 &
prepare_pid=$!
wait_ready "${prepare_http}"
stop_pid "${prepare_pid}"
prepare_pid=""

cp --reflink=auto "${prepared_db}" "${run_root}/go.sqlite"
cp --reflink=auto "${prepared_db}" "${run_root}/rust.sqlite"

"${go_binary}" -host "${go_http}" -path "${run_root}/go-path" >"${run_root}/go.log" 2>&1 &
go_pid=$!
YUHAIIN_DB="${run_root}/rust.sqlite" YUHAIIN_HTTP="${rust_http}" \
  "${rust_binary}" >"${run_root}/rust.log" 2>&1 &
rust_pid=$!
wait_ready "${go_http}"
wait_ready "${rust_http}"

rpc() {
  local address="$1"
  local operation="$2"
  local body="$3"
  local output="$4"
  curl --fail-with-body -sS "http://${address}/api/v2/rpc/${operation}" \
    -H 'content-type: application/json' --data "${body}" >"${output}"
}

rpc_status() {
  local address="$1"
  local operation="$2"
  local body="$3"
  local output="$4"
  curl -sS "http://${address}/api/v2/rpc/${operation}" \
    -H 'content-type: application/json' --data "${body}" \
    -o "${output}" -w '%{http_code}'
}

normalize_user() {
  jq -S 'del(.id)'
}

normalize_users() {
  jq -S '.items |= map(del(.id))'
}

run_user_case() {
  local service="$1"
  local credential_kind="$2"
  local address="${go_http}"
  [[ "${service}" == rust ]] && address="${rust_http}"
  local name="refact-user-parity-${credential_kind}-${run_id}"
  local output_prefix="${run_root}/${service}-${credential_kind}"
  local user_body
  case "${credential_kind}" in
    basic)
      user_body="$(jq -cn --arg name "${name}" '{name:$name,enabled:true,usage:"both",credential:{type:"basic",basic:{username:"refact-user",password:"first-secret"}}}')"
      ;;
    uuid)
      user_body="$(jq -cn --arg name "${name}" '{name:$name,enabled:true,usage:"both",credential:{type:"uuid",uuid:{uuid:"123e4567-e89b-42d3-a456-426614174000"}}}')"
      ;;
    token)
      user_body="$(jq -cn --arg name "${name}" '{name:$name,enabled:true,usage:"both",credential:{type:"token",token:{token:"refact-token-secret"}}}')"
      ;;
    *)
      echo "unknown credential kind: ${credential_kind}" >&2
      return 1
      ;;
  esac

  rpc "${address}" users.post "${user_body}" "${output_prefix}-create.json"
  jq -e --arg kind "${credential_kind}" --arg name "${name}" \
    '.name == $name and .credential.type == $kind and .credential.hasSecret == true' \
    "${output_prefix}-create.json" >/dev/null
  normalize_user <"${output_prefix}-create.json" >"${output_prefix}-create.normalized.json"
  local id="$(jq -r .id "${output_prefix}-create.json")"
  local updated_name="${name}-renamed"
  local update_body="$(jq -cn --arg id "${id}" --arg name "${updated_name}" '{id:$id,name:$name,enabled:true,usage:"both"}')"
  rpc "${address}" user.put "${update_body}" "${output_prefix}-update.json"
  jq -e --arg name "${updated_name}" \
    '.name == $name and .credential.hasSecret == true' \
    "${output_prefix}-update.json" >/dev/null
  normalize_user <"${output_prefix}-update.json" >"${output_prefix}-update.normalized.json"

  local get_body="$(jq -cn --arg id "${id}" '{id:$id}')"
  rpc "${address}" user.get "${get_body}" "${output_prefix}-get.json"
  normalize_user <"${output_prefix}-get.json" >"${output_prefix}-get.normalized.json"

  local list_body="$(jq -cn --arg name "${updated_name}" '{page:1,page_size:1000,query:$name}')"
  rpc "${address}" users.get "${list_body}" "${output_prefix}-list.json"
  jq -e --arg name "${updated_name}" \
    '.items | any(.[]; .name == $name and .credential.hasSecret == true)' \
    "${output_prefix}-list.json" >/dev/null
  normalize_users <"${output_prefix}-list.json" >"${output_prefix}-list.normalized.json"

  rpc "${address}" user.delete "${get_body}" "${output_prefix}-delete.json"
  test "$(<"${output_prefix}-delete.json")" = '{}'
}

for credential_kind in basic uuid token; do
  for service in go rust; do
    run_user_case "${service}" "${credential_kind}"
  done
  for operation in create update get list; do
    diff -u "${run_root}/go-${credential_kind}-${operation}.normalized.json" \
      "${run_root}/rust-${credential_kind}-${operation}.normalized.json" \
      >"${run_root}/${credential_kind}-${operation}.diff"
  done
done

for service in go rust; do
  address="${go_http}"
  [[ "${service}" == rust ]] && address="${rust_http}"
  reference_name="refact-user-reference-${run_id}"
  reference_user_body="$(jq -cn --arg name "${reference_name}" '{name:$name,enabled:true,usage:"outbound",credential:{type:"basic",basic:{username:"reference-user",password:"reference-password"}}}')"
  rpc "${address}" users.post "${reference_user_body}" "${run_root}/${service}-reference-user.json"
  reference_user_id="$(jq -r .id "${run_root}/${service}-reference-user.json")"
  reference_node_id="refact-user-reference-node-${run_id}"
  reference_node_body="$(jq -cn --arg id "${reference_node_id}" --arg user_id "${reference_user_id}" '{id:$id,name:"Refact user reference node",group:"parity",enabled:true,chain:[{type:"http",http:{userId:$user_id}}]}')"
  reference_node_status="$(rpc_status "${address}" nodes.post "${reference_node_body}" "${run_root}/${service}-reference-node.json")"
  if [[ "${reference_node_status}" != 2* ]]; then
    echo "nodes.post failed for ${service}: HTTP ${reference_node_status}" >&2
    sed -n '1,120p' "${run_root}/${service}-reference-node.json" >&2
    exit 1
  fi
  reference_delete_status="$(rpc_status "${address}" user.delete "$(jq -cn --arg id "${reference_user_id}" '{id:$id}')" "${run_root}/${service}-reference-delete.json")"
  test "${reference_delete_status}" = 409
  jq -S 'if .error.message? then .error.message = "<validation-message>" else . end' \
    "${run_root}/${service}-reference-delete.json" >"${run_root}/${service}-reference-delete.normalized.json"
  rpc "${address}" node.delete "$(jq -cn --arg id "${reference_node_id}" '{id:$id}')" "${run_root}/${service}-reference-node-delete.json"
  rpc "${address}" user.delete "$(jq -cn --arg id "${reference_user_id}" '{id:$id}')" "${run_root}/${service}-reference-user-delete.json"
done

diff -u "${run_root}/go-reference-delete.normalized.json" \
  "${run_root}/rust-reference-delete.normalized.json" \
  >"${run_root}/reference-delete.diff"

missing_user_id="refact-user-missing-${run_id}"
for operation in user.get user.delete; do
  for service in go rust; do
    address="${go_http}"
    [[ "${service}" == rust ]] && address="${rust_http}"
    status="$(rpc_status "${address}" "${operation}" "$(jq -cn --arg id "${missing_user_id}" '{id:$id}')" "${run_root}/${service}-missing-${operation//./-}.json")"
    test "${status}" = 404
    jq -S 'if .error.message? then .error.message = "<validation-message>" else . end' \
      "${run_root}/${service}-missing-${operation//./-}.json" \
      >"${run_root}/${service}-missing-${operation//./-}.normalized.json"
  done
  diff -u "${run_root}/go-missing-${operation//./-}.normalized.json" \
    "${run_root}/rust-missing-${operation//./-}.normalized.json" \
    >"${run_root}/missing-${operation//./-}.diff"
done

echo "[refact-user-parity] passed; logs=${run_root}"
