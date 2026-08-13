#!/usr/bin/env bash
set -euo pipefail

# Run Go and Rust against the same SQLite file from separate network
# namespaces. Each service owns its own mixed inbound and API listener, while
# the host drives both traffic paths and reads both management APIs.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${repo_root}/scripts/lib/cache.sh"
go_root="${YUHAIIN_GO_DIR:-$(cd "${repo_root}/../yuhaiin" && pwd)}"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/go-rust-stats}"
keep_runs="${YUHAIIN_KEEP_RUNS:-3}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"

command -v curl >/dev/null
command -v podman >/dev/null
test -d "${go_root}"
[[ "${keep_runs}" =~ ^[1-9][0-9]*$ ]]
mkdir -p "${scenario_dir}"
cache_prune_timestamped_runs "${scenario_dir}" "$((keep_runs - 1))"

run_id="$(date +%Y%m%d%H%M%S)-$$"
run_dir="${scenario_dir}/${run_id}"
mkdir -p "${run_dir}"

reserve_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

rust_api="$(reserve_port)"
rust_inbound="$(reserve_port)"
go_api="$(reserve_port)"
go_inbound="$(reserve_port)"
rust_name="yuhaiin-rust-stats-${run_id}"
go_name="yuhaiin-go-stats-${run_id}"
go_binary="${run_dir}/yuhaiin-go"
rust_binary="${target_dir}/debug/yuhaiin"

cleanup() {
  podman rm -f "${go_name}" "${rust_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "[go-rust-stats] building Go and Rust services in Podman"
"${repo_root}/scripts/integration/podman-go.sh" \
  --state-dir "${run_dir}" -- \
  env GOEXPERIMENT=jsonv2,greenteagc go build -o /state/yuhaiin-go ./cmd/yuhaiin
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${run_dir}" -- \
  cargo build --locked \
  -p yuhaiin-runtime \
  --all-features \
  --bin yuhaiin \
  >"${run_dir}/rust-build.log"
test -x "${rust_binary}"

echo "[go-rust-stats] starting Rust and Go with shared state ${run_dir}/state.db"
podman run -d \
  --name "${rust_name}" \
  -p "127.0.0.1:${rust_api}:50051" \
  -p "127.0.0.1:${rust_inbound}:1080" \
  -v "${run_dir}:/data" \
  -v "${rust_binary}:/usr/local/bin/yuhaiin:ro" \
  --entrypoint /usr/local/bin/yuhaiin \
  "${image}" \
  -host 0.0.0.0:50051 \
  -path /data \
  >"${run_dir}/rust-container-id"

wait_http() {
  local port="$1"
  local label="$2"
  local container="$3"
  for _ in $(seq 1 600); do
    if curl -fsS --max-time 1 "http://127.0.0.1:${port}/api/v2/rpc/info" \
      -H 'content-type: application/json' --data '{}' >/dev/null 2>&1; then
      echo "[go-rust-stats] ${label} API ready on ${port}"
      return 0
    fi
    sleep 0.1
  done
  echo "[go-rust-stats] ${label} API did not become ready" >&2
  podman logs "${container}" >"${run_dir}/${label}-failure.log" 2>&1 || true
  sed -n '1,160p' "${run_dir}/${label}-failure.log" >&2 || true
  return 1
}

wait_http "${rust_api}" rust "${rust_name}"

podman run -d \
  --name "${go_name}" \
  -p "127.0.0.1:${go_api}:50051" \
  -p "127.0.0.1:${go_inbound}:1080" \
  -v "${run_dir}:/data" \
  -v "${go_binary}:/usr/local/bin/yuhaiin:ro" \
  --entrypoint /usr/local/bin/yuhaiin \
  "${image}" \
  -host 0.0.0.0:50051 \
  -path /data \
  >"${run_dir}/go-container-id"

wait_http "${go_api}" go "${go_name}"

configure_mixed_listener() {
  local label="$1"
  local port="$2"
  local input="${run_dir}/${label}-mixed.json"
  local output="${run_dir}/${label}-mixed-updated.json"
  curl -fsS --max-time 2 -X POST \
    -H 'content-type: application/json' \
    --data '{"id":"mixed"}' \
    "http://127.0.0.1:${port}/api/v2/rpc/inbound.get" >"${input}"
  python3 - "${input}" "${output}" <<'PY'
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
value = json.loads(source.read_text())
value["network"]["tcp_udp"]["host"] = "0.0.0.0:1080"
target.write_text(json.dumps(value, separators=(",", ":")))
PY
  curl -fsS --max-time 5 -X POST \
    -H 'content-type: application/json' \
    --data "@${output}" \
    "http://127.0.0.1:${port}/api/v2/rpc/inbound.put" >/dev/null
  echo "[go-rust-stats] ${label} mixed inbound reloaded on 0.0.0.0:1080"
}

configure_mixed_listener rust "${rust_api}"
configure_mixed_listener go "${go_api}"

read_stats() {
  local label="$1"
  local port="$2"
  local output="${run_dir}/${label}-reader.log"
  for _ in $(seq 1 80); do
    for operation in \
      connections \
      connections.total \
      connections.history \
      connections.failed_history; do
      local response="${run_dir}/${label}-reader-response.json"
      if ! curl -fsS --max-time 2 -X POST \
        -H 'content-type: application/json' \
        --data '{}' \
        "http://127.0.0.1:${port}/api/v2/rpc/${operation}" \
        -o "${response}"; then
        echo "${label} read failed: ${operation}" >&2
        sed -n '1,80p' "${response}" >&2 || true
        return 1
      fi
    done
  done
  echo "${label} statistics reads ok" >"${output}"
}

write_traffic() {
  local label="$1"
  local proxy_port="$2"
  local api_port="$3"
  local output="${run_dir}/${label}-traffic.log"
  for _ in $(seq 1 60); do
    # The request target is the service's internal API address. The mapped
    # mixed inbound receives the request and its direct outbound connects to
    # 127.0.0.1:50051 inside the same container.
    local response="${run_dir}/${label}-traffic-response.json"
    if ! curl -fsS --max-time 2 --noproxy '' \
      --proxy "http://127.0.0.1:${proxy_port}" \
      -H 'content-type: application/json' \
      --data '{}' \
      "http://127.0.0.1:50051/api/v2/rpc/info" -o "${response}"; then
      echo "${label} traffic failed through inbound ${proxy_port}" >&2
      sed -n '1,80p' "${response}" >&2 || true
      return 1
    fi
    # Also read the service's own API so each process is both a writer and a
    # reader while the other implementation holds the same SQLite file.
    curl -fsS --max-time 2 -X POST \
      -H 'content-type: application/json' \
      --data '{}' \
      "http://127.0.0.1:${api_port}/api/v2/rpc/connections.total" >/dev/null
  done
  echo "${label} traffic writes ok" >"${output}"
}

read_stats rust "${rust_api}" &
rust_reader_pid=$!
read_stats go "${go_api}" &
go_reader_pid=$!
write_traffic rust "${rust_inbound}" "${rust_api}" &
rust_writer_pid=$!
write_traffic go "${go_inbound}" "${go_api}" &
go_writer_pid=$!

failed=0
for pid in "${rust_reader_pid}" "${go_reader_pid}" "${rust_writer_pid}" "${go_writer_pid}"; do
  if ! wait "${pid}"; then
    failed=1
  fi
done
if [[ "${failed}" == "1" ]]; then
  echo "[go-rust-stats] reader/writer loop failed" >&2
  podman logs "${rust_name}" >&2 || true
  podman logs "${go_name}" >&2 || true
  exit 1
fi

curl -fsS --max-time 2 -X POST \
  -H 'content-type: application/json' \
  --data '{}' \
  "http://127.0.0.1:${rust_api}/api/v2/rpc/connections.total" >"${run_dir}/rust-total.json"
curl -fsS --max-time 2 -X POST \
  -H 'content-type: application/json' \
  --data '{}' \
  "http://127.0.0.1:${go_api}/api/v2/rpc/connections.total" >"${run_dir}/go-total.json"
podman logs "${rust_name}" >"${run_dir}/rust.log" 2>&1 || true
podman logs "${go_name}" >"${run_dir}/go.log" 2>&1 || true

echo "[go-rust-stats] passed; logs=${run_dir}"
