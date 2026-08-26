#!/usr/bin/env bash
set -euo pipefail

# Start one Go service and one Rust service with independent SQLite state,
# configure the same HTTP inbound -> router -> HTTP outbound chain, then
# compare the live connection contract and validate traffic/history/latency
# on both implementations. Go, Rust, and the echo proxy run in Podman;
# generated state, binaries, and logs stay in the cache.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${repo_root}/scripts/lib/cache.sh"
go_root="${YUHAIIN_GO_DIR:-$(cd "${repo_root}/../yuhaiin" && pwd)}"
cache_root="${YUHAIIN_CACHE_DIR:-${repo_root}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_root="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/go-live-flow-parity}"
keep_runs="${YUHAIIN_KEEP_RUNS:-3}"

command -v curl >/dev/null
command -v jq >/dev/null
command -v podman >/dev/null
command -v python3 >/dev/null
test -d "${go_root}"
[[ "${keep_runs}" =~ ^[1-9][0-9]*$ ]]
mkdir -p "${scenario_root}"
cache_prune_timestamped_runs "${scenario_root}" "$((keep_runs - 1))"

run_id="$(date +%Y%m%d%H%M%S)-$$"
run_dir="${scenario_root}/${run_id}"
mkdir -p "${run_dir}/go" "${run_dir}/rust"

reserve_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

go_api="$(reserve_port)"
rust_api="$(reserve_port)"
go_inbound="$(reserve_port)"
rust_inbound="$(reserve_port)"
proxy_port="$(reserve_port)"
go_address="127.0.0.1:${go_api}"
rust_address="127.0.0.1:${rust_api}"
container_api="0.0.0.0:50051"
container_inbound="0.0.0.0:18080"

go_binary="${run_dir}/yuhaiin-go"
rust_binary="${target_dir}/debug/yuhaiin"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
proxy_image="${YUHAIIN_PROXY_IMAGE:-localhost/yuhaiin-nettools-python:testing}"
go_container="yuhaiin-go-live-${run_id}"
rust_container="yuhaiin-rust-live-${run_id}"
go_proxy_container="yuhaiin-go-live-proxy-${run_id}"
rust_proxy_container="yuhaiin-rust-live-proxy-${run_id}"
go_flow_pid=""
rust_flow_pid=""

cleanup() {
  for pid in "${go_flow_pid}" "${rust_flow_pid}"; do
    if [[ -n "${pid}" ]]; then
      kill -TERM "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  podman logs "${go_container}" >"${run_dir}/go-container.log" 2>&1 || true
  podman logs "${rust_container}" >"${run_dir}/rust-container.log" 2>&1 || true
  podman logs "${go_proxy_container}" >"${run_dir}/go-proxy.log" 2>&1 || true
  podman logs "${rust_proxy_container}" >"${run_dir}/rust-proxy.log" 2>&1 || true
  # A network-sharing sidecar depends on its service container. Remove the
  # sidecars first so Podman does not leave the service containers behind.
  podman rm -f --ignore "${go_proxy_container}" "${rust_proxy_container}" \
    >/dev/null 2>&1 || true
  podman rm -f --ignore "${go_container}" "${rust_container}" \
    >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "[go-live-flow-parity] building Go and Rust services in Podman"
"${repo_root}/scripts/integration/podman-go.sh" \
  --state-dir "${run_dir}" -- \
  env GOEXPERIMENT=jsonv2,greenteagc go build -o /state/yuhaiin-go ./cmd/yuhaiin
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${run_dir}" -- \
  cargo build --locked \
  -p yuhaiin-api \
  --all-features \
  --bin yuhaiin \
  >"${run_dir}/rust-build.log"
test -x "${rust_binary}"

wait_tcp() {
  local port="$1"
  for _ in $(seq 1 100); do
    if python3 - "${port}" <<'PY' >/dev/null 2>&1
import socket
import sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.5)
s.close()
PY
    then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

wait_proxy() {
  local container="$1"
  for _ in $(seq 1 100); do
    if podman exec "${container}" python3 - "${proxy_port}" <<'PY' >/dev/null 2>&1
import socket
import sys

s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.5)
s.close()
PY
    then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

wait_ready() {
  local address="$1"
  for _ in $(seq 1 160); do
    if curl -fsS --max-time 1 "http://${address}/api/v2/rpc/info" \
      -H 'content-type: application/json' --data '{}' >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "[go-live-flow-parity] service did not become ready: ${address}" >&2
  return 1
}

echo "[go-live-flow-parity] starting proxy, Go, and Rust services in Podman"
podman run -d \
  --name "${go_container}" \
  --network=pasta \
  -p "127.0.0.1:${go_api}:50051" \
  -p "127.0.0.1:${go_inbound}:18080" \
  --userns=keep-id \
  -v "${run_dir}:/data" \
  -v "${go_binary}:/usr/local/bin/yuhaiin:ro" \
  --entrypoint /usr/local/bin/yuhaiin \
  "${image}" \
  -host "${container_api}" -path /data/go \
  >"${run_dir}/go-container-id"
podman run -d \
  --name "${rust_container}" \
  --network=pasta \
  -p "127.0.0.1:${rust_api}:50051" \
  -p "127.0.0.1:${rust_inbound}:18080" \
  --userns=keep-id \
  -v "${run_dir}:/data" \
  -v "${rust_binary}:/usr/local/bin/yuhaiin:ro" \
  -e "YUHAIIN_DB=/data/rust/state.sqlite" \
  -e "YUHAIIN_HTTP=${container_api}" \
  --entrypoint /usr/local/bin/yuhaiin \
  "${image}" \
  >"${run_dir}/rust-container-id"
wait_ready "${go_address}"
wait_ready "${rust_address}"
go_proxy_host="$(podman exec "${go_container}" hostname -I | awk '{print $1}')"
rust_proxy_host="$(podman exec "${rust_container}" hostname -I | awk '{print $1}')"
test -n "${go_proxy_host}"
test -n "${rust_proxy_host}"

podman run -d \
  --name "${go_proxy_container}" \
  --network "container:${go_container}" \
  --userns=keep-id \
  -v "${repo_root}/scripts/integration/http-connect-echo.py:/usr/local/bin/http-connect-echo.py:ro" \
  --entrypoint python3 \
  "${proxy_image}" \
  -u /usr/local/bin/http-connect-echo.py "${proxy_port}" \
  >"${run_dir}/go-proxy-container-id"
podman run -d \
  --name "${rust_proxy_container}" \
  --network "container:${rust_container}" \
  --userns=keep-id \
  -v "${repo_root}/scripts/integration/http-connect-echo.py:/usr/local/bin/http-connect-echo.py:ro" \
  --entrypoint python3 \
  "${proxy_image}" \
  -u /usr/local/bin/http-connect-echo.py "${proxy_port}" \
  >"${run_dir}/rust-proxy-container-id"
wait_proxy "${go_proxy_container}"
wait_proxy "${rust_proxy_container}"
echo "[go-live-flow-parity] sidecar proxy addresses=${go_proxy_host}:${proxy_port},${rust_proxy_host}:${proxy_port}"

rpc() {
  local address="$1"
  local operation="$2"
  local body="${3-}"
  if [[ -z "${body}" ]]; then
    body='{}'
  fi
  curl -fsS --max-time 10 -X POST "http://${address}/api/v2/rpc/${operation}" \
    -H 'content-type: application/json' --data "${body}"
}

configure_service() {
  local address="$1"
  local _inbound_port="$2"
  local prefix="$3"
  local proxy_host="$4"
  local node_id="${prefix}-http-out"
  local inbound_id="${prefix}-http-in"
  local list_id="${prefix}-host-list"
  local rule_name="${prefix}-route"
  local node_body inbound_body list_body rule_body

  node_body="$(jq -cn --arg id "${node_id}" --arg host "${proxy_host}" --arg port "${proxy_port}" \
    '{id:$id,name:"live HTTP outbound",group:"live",enabled:true,chain:[{type:"fixed",fixed:{host:$host,port:($port|tonumber)}},{type:"http",http:{user:"",password:""}}]}')"
  inbound_body="$(jq -cn --arg id "${inbound_id}" --arg host "${container_inbound}" \
    '{id:$id,name:"live HTTP inbound",enabled:true,network:{type:"tcp_udp",tcp_udp:{host:$host,udp:"disabled"}},transports:[{type:"normal",normal:{}}],protocol:{type:"http",http:{username:"",password:""}}}')"
  list_body="$(jq -cn --arg name "${list_id}" \
    '{name:$name,type:"host",source:{type:"local",local:{lists:["example.test"]}}}')"
  rule_body="$(jq -cn --arg name "${rule_name}" --arg list "${list_id}" \
    '{name:$name,mode:"proxy",rules:[{type:"host",host:{list:$list}}],tag:"live"}')"

  rpc "${address}" nodes.post "${node_body}" >"${run_dir}/${prefix}-node.json"
  rpc "${address}" node.use "$(jq -cn --arg id "${node_id}" '{id:$id}')" >/dev/null
  rpc "${address}" inbounds.post "${inbound_body}" >"${run_dir}/${prefix}-inbound.json"
  rpc "${address}" route.lists.post "${list_body}" >"${run_dir}/${prefix}-list.json"
  rpc "${address}" route.rules.post "${rule_body}" >"${run_dir}/${prefix}-rule.json"
  rpc "${address}" route.apply '{}' >/dev/null
}

configure_service "${go_address}" "${go_inbound}" go "${go_proxy_host}"
configure_service "${rust_address}" "${rust_inbound}" rust "${rust_proxy_host}"
wait_tcp "${go_inbound}"
wait_tcp "${rust_inbound}"

send_flow() {
  local port="$1"
  python3 - "${port}" <<'PY'
import socket
import sys

payload = b"go-rust-live-flow-parity"
print("connecting", flush=True)
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
s.settimeout(5)
print("connected", flush=True)
s.sendall(b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
print("connect request sent", flush=True)
response = b""
while b"\r\n\r\n" not in response:
    response += s.recv(4096)
print(f"connect response={response!r}", flush=True)
if not response.startswith(b"HTTP/1.1 200"):
    raise SystemExit(f"inbound CONNECT failed: {response!r}")
s.sendall(payload)
print("payload sent", flush=True)
echo = b""
while len(echo) < len(payload):
    echo += s.recv(len(payload) - len(echo))
print(f"echo={echo!r}", flush=True)
if echo != payload:
    raise SystemExit(f"payload mismatch: {echo!r}")
import time
time.sleep(15)
s.close()
PY
}

send_flow "${go_inbound}" >"${run_dir}/go-flow.log" 2>&1 &
go_flow_pid=$!
send_flow "${rust_inbound}" >"${run_dir}/rust-flow.log" 2>&1 &
rust_flow_pid=$!

wait_connection() {
  local address="$1"
  local inbound_id="$2"
  local output="$3"
  for _ in $(seq 1 120); do
    rpc "${address}" connections '{}' >"${output}"
    if jq -e '.connections | length > 0' "${output}" >/dev/null; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

if ! wait_connection "${go_address}" go-http-in "${run_dir}/go-connections.json"; then
  echo "[go-live-flow-parity] Go live connection did not appear" >&2
  cat "${run_dir}/go-flow.log" >&2 || true
  podman logs "${go_container}" >&2 || true
  rpc "${go_address}" connections.failed_history '{}' >"${run_dir}/go-failed-history.json" || true
  podman logs "${go_proxy_container}" >&2 || true
  exit 1
fi
if ! wait_connection "${rust_address}" rust-http-in "${run_dir}/rust-connections.json"; then
  echo "[go-live-flow-parity] Rust live connection did not appear" >&2
  cat "${run_dir}/rust-flow.log" >&2 || true
  podman logs "${rust_container}" >&2 || true
  rpc "${rust_address}" connections.failed_history '{}' >"${run_dir}/rust-failed-history.json" || true
  podman logs "${rust_proxy_container}" >&2 || true
  exit 1
fi
wait "${go_flow_pid}"
wait "${rust_flow_pid}"

for service in go rust; do
  jq -S ' {
    connections: [.connections[] | select(.addr == "example.test:443") |
      {addr,destination,mode,outbound,nodeId:"http-out",nodeName,tag,
       inbound:(if (.inbound | test("^(\\[::\\]|0\\.0\\.0\\.0):")) then "http" else .inbound end),
       inboundName,protocol,resolver,domain,udpMigrateId,
       localAddrPresent:(.localAddr != ""),
       network:{connType:.network.connType,underlyingType:.network.underlyingType},
       matchHistory: [.matchHistory[]? |
         {ruleName:(if (.ruleName | endswith("-route")) then "live-route" else .ruleName end),
          history:[.history[]? |
            {listName:(.listName | sub("^List (go|rust)-"; "List ")),matched}]}]}]}
  ' "${run_dir}/${service}-connections.json" >"${run_dir}/${service}-connections-normalized.json"
done
if ! diff -u "${run_dir}/go-connections-normalized.json" \
  "${run_dir}/rust-connections-normalized.json" >"${run_dir}/connections.diff"; then
  echo "[go-live-flow-parity] live connection mismatch" >&2
  sed -n '1,200p' "${run_dir}/connections.diff" >&2
  exit 1
fi

for service in go rust; do
  address="${go_address}"
  [[ "${service}" == rust ]] && address="${rust_address}"
  echo "[go-live-flow-parity] validating ${service} statistics"
  rpc "${address}" connections.total '{}' >"${run_dir}/${service}-total.json"
  rpc "${address}" connections.traffic '{"interval":"hour","from":"2020-01-01T00:00:00Z","to":"2030-01-01T00:00:00Z"}' >"${run_dir}/${service}-traffic.json"
  rpc "${address}" connections.telemetry '{"from":"2020-01-01T00:00:00Z","to":"2030-01-01T00:00:00Z","limit":50}' >"${run_dir}/${service}-telemetry.json"
  latency="$(rpc "${address}" node.latency \
    "$(jq -cn --arg id "${service}-http-out" \
      '{id:$id,type:"tcp",url:"http://example.test:443/health"}')")"
  jq -e '.ok == true' <<<"${latency}" >/dev/null || {
    echo "[go-live-flow-parity] ${service} latency failed: ${latency}" >&2
    exit 1
  }
  jq -e '((.upload | tonumber) > 0 and (.download | tonumber) > 0)' \
    "${run_dir}/${service}-total.json" >/dev/null
  jq -e '.items | type == "array"' "${run_dir}/${service}-traffic.json" >/dev/null
  jq -e '.groups | type == "array"' "${run_dir}/${service}-telemetry.json" >/dev/null
done

for service in go rust; do
  address="${go_address}"
  [[ "${service}" == rust ]] && address="${rust_address}"
  for _ in $(seq 1 120); do
    rpc "${address}" connections.history '{}' >"${run_dir}/${service}-history.json"
    if jq -e '.items | any(.[]; .connection.addr == "example.test:443")' \
      "${run_dir}/${service}-history.json" >/dev/null; then
      break
    fi
    sleep 0.05
  done
  jq -e '.items | any(.[]; .connection.addr == "example.test:443")' \
    "${run_dir}/${service}-history.json" >/dev/null
done

echo "[go-live-flow-parity] passed; logs=${run_dir}"
