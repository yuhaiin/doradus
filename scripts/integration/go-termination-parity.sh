#!/usr/bin/env bash
set -euo pipefail

# Compare the same reverse_http -> http_termination -> tls_termination
# configuration in the Go and Rust services.  Both services,
# their HTTP targets, and the Rust build run in Podman; host-side Python only
# drives the exposed API/TLS sockets.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${repo_root}/scripts/lib/cache.sh"
go_root="${YUHAIIN_GO_DIR:-$(cd "${repo_root}/../yuhaiin" && pwd)}"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_root="${YUHAIIN_TERMINATION_PARITY_DIR:-${cache_root}/integration/go-termination-parity}"
keep_runs="${YUHAIIN_KEEP_RUNS:-3}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
proxy_image="${YUHAIIN_PROXY_IMAGE:-localhost/yuhaiin-nettools-python:testing}"

command -v curl >/dev/null
command -v jq >/dev/null
command -v podman >/dev/null
command -v python3 >/dev/null
command -v ip >/dev/null
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
go_address="127.0.0.1:${go_api}"
rust_address="127.0.0.1:${rust_api}"
container_api="0.0.0.0:50051"
container_inbound="0.0.0.0:18081"
target_port=18090
rust_target_port=18091
target_host="$(ip -4 route get 192.168.2.1 | awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i + 1); exit}}')"
rust_target_host=127.0.0.1
host_ip="${target_host}"
test -n "${host_ip}"

go_binary="${run_dir}/yuhaiin-go"
rust_binary="${target_dir}/debug/yuhaiin"
go_container="yuhaiin-go-termination-${run_id}"
rust_container="yuhaiin-rust-termination-${run_id}"
go_target_container="yuhaiin-go-termination-target-${run_id}"
rust_target_container="yuhaiin-rust-termination-target-${run_id}"
go_client_pid=""
rust_client_pid=""

cleanup() {
  for pid in "${go_client_pid}" "${rust_client_pid}"; do
    if [[ -n "${pid}" ]]; then
      kill -TERM "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  for container in \
    "${go_target_container}" "${rust_target_container}" \
    "${go_container}" "${rust_container}"; do
    podman logs "${container}" >"${run_dir}/${container}.log" 2>&1 || true
  done
  podman rm -f --ignore \
    "${go_target_container}" "${rust_target_container}" \
    "${go_container}" "${rust_container}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "[go-termination-parity] building Go and Rust services in Podman"
"${repo_root}/scripts/integration/podman-go.sh" \
  --state-dir "${run_dir}" -- \
  env GOEXPERIMENT=jsonv2,greenteagc go build -o /state/yuhaiin-go ./cmd/yuhaiin
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${run_dir}" -- \
  cargo build -p yuhaiin-runtime --all-features --bin yuhaiin \
  >"${run_dir}/rust-build.log" 2>&1
test -x "${rust_binary}"

wait_ready() {
  local address="$1"
  for _ in $(seq 1 160); do
    if curl -fsS --max-time 1 "http://${address}/api/v2/rpc/info" \
      -H 'content-type: application/json' --data '{}' >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "[go-termination-parity] service did not become ready: ${address}" >&2
  return 1
}

podman run -d \
  --name "${go_container}" \
  --network=pasta \
  -p "127.0.0.1:${go_api}:50051" \
  -p "127.0.0.1:${go_inbound}:18081" \
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
  -p "127.0.0.1:${rust_inbound}:18081" \
  --userns=keep-id \
  -v "${run_dir}:/data" \
  -v "${rust_binary}:/usr/local/bin/yuhaiin:ro" \
  -e YUHAIIN_DB=/data/rust/state.sqlite \
  -e YUHAIIN_HTTP="${container_api}" \
  --entrypoint /usr/local/bin/yuhaiin \
  "${image}" \
  >"${run_dir}/rust-container-id"
wait_ready "${go_address}"
wait_ready "${rust_address}"

target_script="${repo_root}/scripts/integration/http-termination-target.py"
podman run -d \
  --name "${go_target_container}" \
  --network "container:${go_container}" \
  --userns=keep-id \
  -v "${target_script}:/usr/local/bin/http-termination-target.py:ro" \
  --entrypoint python3 \
  "${proxy_image}" \
  /usr/local/bin/http-termination-target.py "${target_port}" /health "${target_host}:${target_port}" 2 \
  >"${run_dir}/go-target-id"
podman run -d \
  --name "${rust_target_container}" \
  --network "container:${rust_container}" \
  --userns=keep-id \
  -v "${target_script}:/usr/local/bin/http-termination-target.py:ro" \
  --entrypoint python3 \
  "${proxy_image}" \
  /usr/local/bin/http-termination-target.py "${rust_target_port}" /health "${rust_target_host}:${rust_target_port}" 2 \
  >"${run_dir}/rust-target-id"

wait_target() {
  local container="$1"
  local port="$2"
  for _ in $(seq 1 120); do
    if podman exec "${container}" python3 - "${port}" <<'PY' >/dev/null 2>&1
import socket
import sys

with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.5):
    pass
PY
    then
      return 0
    fi
    sleep 0.05
  done
  echo "[go-termination-parity] target did not become ready: ${container}:${port}" >&2
  return 1
}

wait_target "${go_target_container}" "${target_port}"
wait_target "${rust_target_container}" "${rust_target_port}"

rpc() {
  local address="$1"
  local operation="$2"
  local body="${3-}"
  [[ -n "${body}" ]] || body='{}'
  curl -fsS --max-time 10 -X POST "http://${address}/api/v2/rpc/${operation}" \
    -H 'content-type: application/json' --data "${body}"
}

# This is the same certificate fixture used by Rust process tests. Clients
# deliberately skip verification; both services must nevertheless parse the
# compatible certificate transport and complete the same TLS flow.
# Normalize the shared Rust test fixture to one-line base64 at runtime so the
# Go-shaped API receives exactly the same certificate/key bytes.
certificate_base64="$(python3 - "${repo_root}/crates/yuhaiin-runtime/tests/support/mod.rs" <<'PY'
import base64
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text()
start = source.index('const LEAF_CERTIFICATE_PEM: &[u8] = br#"')
start = source.index('br#"', start) + 4
end = source.index('"#;', start)
print(base64.b64encode(source[start:end].encode()).decode())
PY
)"
private_key_base64="$(python3 - "${repo_root}/crates/yuhaiin-runtime/tests/support/mod.rs" <<'PY'
import base64
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text()
start = source.index('const PRIVATE_KEY_PEM: &[u8] = br#"')
start = source.index('br#"', start) + 4
end = source.index('"#;', start)
print(base64.b64encode(source[start:end].encode()).decode())
PY
)"

configure_service() {
  local address="$1"
  local prefix="$2"
  local mode="${3:-combo}"
  local node_body inbound_body rule_body service_target_host service_target_ip service_target_port
  service_target_host="${target_host}"
  service_target_ip="${host_ip}"
  service_target_port="${target_port}"
  if [[ "${prefix}" == rust ]]; then
    service_target_host="${rust_target_host}"
    service_target_ip="${rust_target_host}"
    service_target_port="${rust_target_port}"
  fi
  if [[ "${prefix}" == go ]]; then
    # The Go node contract uses json []byte fields (`cert`/`key`), which are
    # themselves represented as base64 strings by encoding/json.  Rust also
    # accepts this shape, while its compatibility API additionally accepts
    # the inbound-style certBase64/keyBase64 names.
    if [[ "${mode}" == standalone ]]; then
      node_body="$(jq -cn \
        --arg cert "${certificate_base64}" --arg key "${private_key_base64}" --arg prefix "${prefix}" \
        '{id:($prefix+"-termination-out"),name:"termination parity outbound",group:"parity",enabled:true,chain:[
          {type:"direct",direct:{}},
          {type:"tls_termination",tls_termination:{tls:{certificates:[{cert:$cert,key:$key}],nextProtos:[]}}}
        ]}')"
    else
      node_body="$(jq -cn \
        --arg cert "${certificate_base64}" --arg key "${private_key_base64}" --arg prefix "${prefix}" \
        '{id:($prefix+"-termination-out"),name:"termination parity outbound",group:"parity",enabled:true,chain:[
          {type:"direct",direct:{}},
          {type:"http_termination",http_termination:{headers:{}}},
          {type:"tls_termination",tls_termination:{tls:{certificates:[{cert:$cert,key:$key}],nextProtos:[]}}}
        ]}')"
    fi
  else
    if [[ "${mode}" == standalone ]]; then
      node_body="$(jq -cn \
        --arg cert "${certificate_base64}" --arg key "${private_key_base64}" --arg prefix "${prefix}" \
        '{id:($prefix+"-termination-out"),name:"termination parity outbound",group:"parity",enabled:true,chain:[
          {type:"direct",direct:{}},
          {type:"tls_termination",tls_termination:{tls:{certificates:[{certBase64:$cert,keyBase64:$key}],nextProtos:[]}}}
        ]}')"
    else
      node_body="$(jq -cn \
        --arg cert "${certificate_base64}" --arg key "${private_key_base64}" --arg prefix "${prefix}" \
        '{id:($prefix+"-termination-out"),name:"termination parity outbound",group:"parity",enabled:true,chain:[
          {type:"direct",direct:{}},
          {type:"http_termination",http_termination:{headers:{}}},
          {type:"tls_termination",tls_termination:{tls:{certificates:[{certBase64:$cert,keyBase64:$key}],nextProtos:[]}}}
        ]}')"
    fi
  fi
  inbound_body="$(jq -cn --arg prefix "${prefix}" --arg host "${container_inbound}" --arg target_host "${service_target_host}" --arg target_port "${service_target_port}" \
    '{id:($prefix+"-termination-in"),name:"termination parity inbound",enabled:true,
      network:{type:"tcp_udp",tcp_udp:{host:$host,udp:"disabled"}},
      transports:[{type:"normal",normal:{}}],
      protocol:{type:"reverse_http",reverse_http:{url:("http://"+$target_host+":"+$target_port+"/base")}}}')"
  if [[ "${prefix}" == go ]]; then
    # Go's built-in LAN rule also covers the pasta-visible/private target
    # address. Match TCP explicitly, then move this rule before LAN below so
    # the parity flow reaches the configured outbound chain.
    rule_body='{"name":"termination-parity-route","mode":"proxy","rules":[{"type":"network","network":{"network":"tcp"}}]}'
  else
    rule_body="$(jq -cn --arg ip "${service_target_ip}" \
      '{name:"termination-parity-route",mode:"proxy",match:{cidr:($ip+"/32")}}')"
  fi
  if [[ "${mode}" == combo ]]; then
    rpc "${address}" nodes.post "${node_body}" >"${run_dir}/${prefix}-${mode}-node.json"
  else
    rpc "${address}" node.put "${node_body}" >"${run_dir}/${prefix}-${mode}-node.json"
  fi
  rpc "${address}" node.use "$(jq -cn --arg prefix "${prefix}" '{id:($prefix+"-termination-out")}')" >/dev/null
  if [[ "${mode}" == combo ]]; then
    if [[ "${prefix}" == go ]]; then
      rpc "${address}" nodes.selected '{}' >"${run_dir}/${prefix}-selected.json"
    fi
    rpc "${address}" inbounds.post "${inbound_body}" >"${run_dir}/${prefix}-inbound.json"
    rpc "${address}" route.rules.post "${rule_body}" >"${run_dir}/${prefix}-route.json"
    rpc "${address}" route.rules.priority \
      '{"source":{"name":"termination-parity-route"},"target":{"name":"LAN"},"operate":"insert_before"}' \
      >"${run_dir}/${prefix}-route-priority.json"
    rpc "${address}" route.apply '{}' >/dev/null
    rpc "${address}" route.rules.test "{\"host\":\"${service_target_host}:${service_target_port}\"}" >"${run_dir}/${prefix}-route-test.json"
  fi
}

configure_service "${go_address}" go combo
configure_service "${rust_address}" rust combo

wait_tcp() {
  local port="$1"
  for _ in $(seq 1 120); do
    if python3 - "${port}" <<'PY' >/dev/null 2>&1
import socket
import sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.5)
s.close()
PY
    then return 0; fi
    sleep 0.05
  done
  return 1
}
wait_tcp "${go_inbound}"
wait_tcp "${rust_inbound}"

send_tls_request() {
  local port="$1"
  local output="$2"
  local host="$3"
  python3 - "${port}" "${host}" >"${output}" 2>&1 <<'PY'
import socket
import ssl
import sys
import time

port = int(sys.argv[1])
host = sys.argv[2]
context = ssl._create_unverified_context()
for _ in range(120):
    try:
        raw = socket.create_connection(("127.0.0.1", port), timeout=1)
        break
    except OSError:
        time.sleep(0.05)
else:
    raise SystemExit("termination inbound did not accept TCP")
with context.wrap_socket(raw) as stream:
    stream.sendall(
        b"GET /health HTTP/1.1\r\n"
        + f"Host: {host}\r\n".encode()
        + b"Connection: keep-alive\r\n\r\n"
    )
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = stream.recv(4096)
        if not chunk:
            break
        response.extend(chunk)
    header_end = response.find(b"\r\n\r\n")
    headers = bytes(response[:header_end]).lower()
    content_length = int(
        next(
            line.split(b":", 1)[1].strip()
            for line in headers.split(b"\r\n")
            if line.startswith(b"content-length:")
        )
    )
    while len(response) - header_end - 4 < content_length:
        chunk = stream.recv(4096)
        if not chunk:
            break
        response.extend(chunk)
    expected = b"termination-parity-ok"
    if not response.startswith(b"HTTP/1.1 200") or not response.endswith(expected):
        raise SystemExit(f"unexpected termination response: {bytes(response)!r}")
    print(bytes(response).decode("latin1"), flush=True)
    time.sleep(2)
PY
}

run_case() {
  local case_name="$1"
  echo "[go-termination-parity] sending ${case_name} raw-TLS reverse requests"
  send_tls_request "${go_inbound}" "${run_dir}/go-${case_name}-client.log" "${target_host}:${target_port}" &
  go_client_pid=$!
  send_tls_request "${rust_inbound}" "${run_dir}/rust-${case_name}-client.log" "${rust_target_host}:${rust_target_port}" &
  rust_client_pid=$!

  for service in go rust; do
    address="${go_address}"
    [[ "${service}" == rust ]] && address="${rust_address}"
    for _ in $(seq 1 120); do
      rpc "${address}" connections '{}' >"${run_dir}/${service}-${case_name}-connections.json"
      if jq -e '.connections | any(.[]; .inboundName == "termination parity inbound" and .mode == "proxy")' \
        "${run_dir}/${service}-${case_name}-connections.json" >/dev/null; then
        break
      fi
      sleep 0.05
    done
    jq -e '.connections | any(.[]; .inboundName == "termination parity inbound" and .mode == "proxy")' \
      "${run_dir}/${service}-${case_name}-connections.json" >/dev/null
  done
  wait "${go_client_pid}"
  go_client_pid=""
  wait "${rust_client_pid}"
  rust_client_pid=""

  for service in go rust; do
    grep -q 'HTTP/1.1 200 OK' "${run_dir}/${service}-${case_name}-client.log"
    grep -q 'termination-parity-ok' "${run_dir}/${service}-${case_name}-client.log"
  done
}

run_case combo
configure_service "${go_address}" go standalone
configure_service "${rust_address}" rust standalone
sleep 0.2
run_case standalone

for target_container in "${go_target_container}" "${rust_target_container}"; do
  podman wait "${target_container}" >/dev/null
done

echo "[go-termination-parity] passed; Go/Rust cases=4; logs=${run_dir}"
