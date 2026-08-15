#!/usr/bin/env bash
set -euo pipefail

# Compare public management responses from a stopped, consistent Go database
# snapshot. Go and Rust always receive separate copies; neither process may
# write the source fixture or share a live state.db. Compilation and runtime
# both happen in disposable Podman containers; the host only drives curl.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
go_root="${YUHAIIN_GO_DIR:-$(cd "${repo_root}/../yuhaiin" && pwd)}"
source_db="${YUHAIIN_SOURCE_DB:?set YUHAIIN_SOURCE_DB to a stopped, consistent Go state.db snapshot}"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
scenario_dir="${YUHAIIN_INTEGRATION_DIR:-${cache_root}/integration/go-api-parity}"
go_cache_root="${YUHAIIN_GO_CACHE_DIR:-${cache_root}/go-cache}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
cargo_home="${YUHAIIN_CARGO_HOME:-${cache_root}/cargo-home}"
go_http="${YUHAIIN_GO_HTTP:-127.0.0.1:55252}"
rust_http="${YUHAIIN_RUST_HTTP:-127.0.0.1:55251}"
prepare_http="${YUHAIIN_PREPARE_HTTP:-127.0.0.1:55250}"
prepare_enabled="${YUHAIIN_PREPARE:-1}"

command -v curl >/dev/null
command -v jq >/dev/null
command -v podman >/dev/null
test -f "${source_db}"
mkdir -p "${scenario_dir}/go" "${scenario_dir}/rust" "${scenario_dir}/prepared" "${cargo_home}"
mkdir -p "${go_cache_root}"

image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
rust_build_image="${YUHAIIN_BUILD_IMAGE:-docker.io/library/rust:latest}"
go_build_image="${YUHAIIN_GO_BUILD_IMAGE:-docker.io/library/golang:latest}"
sqlite_audit_image="${YUHAIIN_SQLITE_AUDIT_IMAGE:-docker.io/library/python:3.13-slim}"
run_id="${BASHPID}-$(date +%s)"
go_container="yuhaiin-go-api-parity-${run_id}"
rust_container="yuhaiin-rust-api-parity-${run_id}"
prepare_container="yuhaiin-rust-api-parity-prepare-${run_id}"

echo "[go-api-parity] building Go and Rust services"
go_binary="${scenario_dir}/yuhaiin-go"
podman run --rm --network=host \
  -v "${go_root}:/go-src:ro" \
  -v "${scenario_dir}:/state:Z" \
  -v "${go_cache_root}:/go-cache:Z" \
  --entrypoint /bin/sh \
  "${go_build_image}" \
  -ec '
    set -eu
    mkdir -p /go-cache/build /go-cache/mod /state/go-tmp
    export GOCACHE=/go-cache/build
    export GOMODCACHE=/go-cache/mod
    export GOTMPDIR=/state/go-tmp
    cd /go-src
    GOEXPERIMENT=jsonv2,greenteagc go build -o /state/yuhaiin-go ./cmd/yuhaiin
  ' >"${scenario_dir}/go-build.log" 2>&1
podman run --rm --network=host \
  -v "${repo_root}:/workspace:ro" \
  -v "${target_dir}:/target:Z" \
  -v "${scenario_dir}:/state:Z" \
  -v "${cargo_home}:/cargo-home:Z" \
  --entrypoint /bin/sh \
  "${rust_build_image}" \
  -ec '
    set -eu
    mkdir -p /state/home /state/cache/tmp
    export HOME=/state/home
    export CARGO_HOME=/cargo-home
    export CARGO_TARGET_DIR=/target
    export TMPDIR=/state/cache/tmp
    unset CARGO_NET_OFFLINE
    cd /workspace
    cargo build --locked \
      --manifest-path /workspace/Cargo.toml \
      -p yuhaiin-api \
      --all-features \
      --bin yuhaiin \
      >/state/rust-build.log 2>&1
  '
rust_binary="${target_dir}/debug/yuhaiin"
test -x "${go_binary}"
test -x "${rust_binary}"

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

cleanup() {
  podman logs "${prepare_container}" >"${scenario_dir}/prepare-container.log" 2>&1 || true
  podman logs "${go_container}" >"${scenario_dir}/go-container.log" 2>&1 || true
  podman logs "${rust_container}" >"${scenario_dir}/rust-container.log" 2>&1 || true
  podman rm -f --ignore "${prepare_container}" "${go_container}" "${rust_container}" \
    >"${scenario_dir}/container-cleanup.log" 2>&1 || true
}
trap cleanup EXIT

if [[ "${prepare_enabled}" == "1" ]]; then
  # Older Go production snapshots may not yet contain Go's telemetry tables.
  # Let the current Rust takeover path create/migrate them on a disposable
  # copy first, then give the prepared snapshot to two independent services.
  cp --reflink=auto "${source_db}" "${scenario_dir}/prepared/state.sqlite"
  echo "[go-api-parity] preparing a disposable Rust takeover snapshot in Podman"
  podman run -d \
    --name "${prepare_container}" \
    -p "${prepare_http}:50051" \
    -v "${scenario_dir}/prepared:/data:Z" \
    -v "${rust_binary}:/usr/local/bin/yuhaiin:ro" \
    -e YUHAIIN_DB=/data/state.sqlite \
    -e YUHAIIN_HTTP=0.0.0.0:50051 \
    --entrypoint /usr/local/bin/yuhaiin \
    "${image}" \
    >"${scenario_dir}/prepare-container-id"
  wait_ready "${prepare_http}"
  podman stop "${prepare_container}" >"${scenario_dir}/prepare-stop.log"
  podman rm -f "${prepare_container}" >"${scenario_dir}/prepare-rm.log"
  cp --reflink=auto "${scenario_dir}/prepared/state.sqlite" "${scenario_dir}/go/state.db"
  cp --reflink=auto "${scenario_dir}/prepared/state.sqlite" "${scenario_dir}/rust/state.sqlite"

  echo "[go-api-parity] auditing SQLite schema retained by the Rust takeover"
  podman run --rm --network=none \
    -v "${source_db}:/state/source.sqlite:ro" \
    -v "${scenario_dir}/prepared/state.sqlite:/state/prepared.sqlite:ro" \
    -v "${repo_root}/scripts/integration/audit-sqlite-snapshot.py:/state/audit.py:ro" \
    --entrypoint python3 \
    "${sqlite_audit_image}" \
    /state/audit.py \
      --source /state/source.sqlite \
      --prepared /state/prepared.sqlite \
    | tee "${scenario_dir}/sqlite-schema-audit.json"
else
  cp --reflink=auto "${source_db}" "${scenario_dir}/go/state.db"
  cp --reflink=auto "${source_db}" "${scenario_dir}/rust/state.sqlite"
fi

start_services() {
  echo "[go-api-parity] starting Go and Rust services in Podman"
  podman run -d \
    --name "${go_container}" \
    -p "${go_http}:50051" \
    -v "${scenario_dir}/go:/data:Z" \
    -v "${go_binary}:/usr/local/bin/yuhaiin:ro" \
    --entrypoint /usr/local/bin/yuhaiin \
    "${image}" \
    -host 0.0.0.0:50051 -path /data \
    >"${scenario_dir}/go-container-id"
  podman run -d \
    --name "${rust_container}" \
    -p "${rust_http}:50051" \
    -v "${scenario_dir}/rust:/data:Z" \
    -v "${rust_binary}:/usr/local/bin/yuhaiin:ro" \
    -e YUHAIIN_DB=/data/state.sqlite \
    -e YUHAIIN_HTTP=0.0.0.0:50051 \
    --entrypoint /usr/local/bin/yuhaiin \
    "${image}" \
    >"${scenario_dir}/rust-container-id"
}

start_services

wait_ready "${go_http}"
wait_ready "${rust_http}"

request() {
  local address="$1"
  local operation="$2"
  local body="$3"
  local service="rust"
  [[ "${address}" == "${go_http}" ]] && service="go"
  local safe_name="${operation//./-}"
  local raw_output="${scenario_dir}/request-${service}-${safe_name}.raw"
  local status
  if ! status="$(curl -sS --max-time 30 -o "${raw_output}" -w '%{http_code}' \
    "http://${address}/api/v2/rpc/${operation}" \
    -H 'content-type: application/json' \
    --data "${body}")"; then
    echo "[go-api-parity] curl failed: ${service} ${operation}" >&2
    return 1
  fi
  if [[ "${status}" != 2* ]]; then
    echo "[go-api-parity] unexpected HTTP ${status}: ${service} ${operation}" >&2
    if jq -e . "${raw_output}" >/dev/null 2>&1; then
      jq -S . "${raw_output}" >&2
    else
      sed -n '1,160p' "${raw_output}" >&2 || true
    fi
    return 1
  fi
  cat "${raw_output}"
}

normalize() {
  local operation="$1"
  local stage="${2:-initial}"
  case "${operation}" in
    info)
      # Version/compiler/build metadata are intentionally implementation
      # specific; compare the stable response shape without hiding missing
      # fields.
      jq -S 'with_entries(if (.key | IN("version", "commit", "buildTime", "goVersion", "arch", "platform", "os", "compiler", "build")) then .value = "<implementation>" else . end)'
      ;;
    backup.config.get)
      # Go lazily assigns a random v4 instance name on first read. When Go
      # and Rust each migrate an old snapshot independently, the values must
      # differ, but both must still be valid UUID-shaped persisted identities.
      # Keep non-UUID configured names strict so this does not hide a real
      # backup configuration mismatch.
      jq -S 'if (.instanceName | type) == "string" and (.instanceName | test("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")) then .instanceName = "<generated-uuid>" else . end'
      ;;
    nodes.get|resolvers.get|inbounds.get)
      jq -S 'if (.items | type) == "array" then .items |= sort_by(.id) else . end'
      ;;
    route.lists.get)
      # Go refreshes remote lists into its Pebble cache during startup. Rust
      # intentionally consumes only its persistent ~/.cache route-list cache,
      # so remote item counts/errors/previews are environment-dependent here;
      # compare the stable control-plane projection and keep local metrics
      # fully strict.
      jq -S '.items |= map(if .source == "remote" then del(.itemCount, .errorCount, .preview) else . end)'
      ;;
    connections.telemetry)
      # The management request is made against two independently running
      # services. Go may create failure-only telemetry while refreshing its
      # configured DNS/route clients during startup; Rust does not reproduce
      # those implementation-specific background attempts. Transfer totals
      # and dimensions remain strict here, while failure counters are covered
      # by the SQLite migration/store tests and live proxy-flow tests.
      if [[ "${stage}" == "force-stop-reopen" ]]; then
        # The mutation matrix deliberately tests route.rules.test against a
        # domain while the legacy fixture has no selected TCP node. Go's
        # resolver records that failed-only probe as zero-byte telemetry;
        # Rust's management route test does not open a proxy connection.
        # Drop only zero-byte entries in this replay stage. Any traffic-bearing
        # dimension remains strict, as do all other stages.
        jq -S '.groups |= map(.items |= map(select((.download != "0") or (.upload != "0"))) | .items |= map(del(.failures)))'
      else
        jq -S '.groups |= map(.items |= map(del(.failures)))'
      fi
      ;;
    connections.failed_history)
      if [[ "${stage}" == "force-stop-reopen" ]]; then
        # Match only environment/transport differences that are known from
        # this fixture:
        #   * Go's container trust store rejects doh.pub while Rust's bundled
        #     WebPKI roots accept it;
        #   * Go opens one failed DoH transport per A/AAAA request, while the
        #     Rust HTTP/2 client can reuse one failed connection for both;
        #   * the legacy v2 database has two rows tied at the SQLite LIMIT 1000
        #     cutoff, whose ORDER BY last_seen_at alone leaves row order free.
        # Keep every other host, error and count strict.
        jq -S '
          .items |= map(select(
            ((.host != "dns.google:443") or ((.error // "") | contains("selected tcp node not found") | not)) and
            ((.host != "doh.pub:443") or ((.error // "") | contains("x509: certificate signed by unknown authority") | not)) and
            ((.host != "83.31.199.157:6969") or
              (.process != "/usr/bin/transmission-daemon") or
              (.protocol != "1") or
              (.error != "i/o timeout") or
              (.time != "2026-07-10T08:24:57Z"))
          ))
          | .items |= map(if
              .host == "jc72n2xbdh.cloudflare-gateway.com:443" and
              (.error // "") == "selected tcp node not found"
            then .failedCount = "<transport-attempts>" else . end)'
      else
        jq -S .
      fi
      ;;
    connections.history)
      if [[ "${stage}" == "force-stop-reopen" ]]; then
        # Go exposes its bootstrap DNS socket in connection history. Rust's
        # resolver transport keeps bootstrap work outside the user flow
        # history, so compare all user-flow entries strictly and omit only
        # this implementation-specific component.
        jq -S '.items |= map(select((.connection.component // "") != "dns:bootstrap"))'
      else
        jq -S .
      fi
      ;;
    route.activation)
      if [[ "${stage}" == "force-stop-reopen" ]]; then
        # Rule/list activation timestamps describe the in-memory runtime
        # rebuild. Go resets them after a hard restart while Rust reports the
        # rebuild time; neither value is persisted user configuration.
        jq -S '.hostIndexRefreshAt = 0 | .ruleApplyAt = 0'
      else
        jq -S .
      fi
      ;;
    route.lists.activation)
      if [[ "${stage}" == "force-stop-reopen" ]]; then
        jq -S '.hostIndexRefreshAt = 0'
      else
        jq -S .
      fi
      ;;
    tools.interfaces)
      # Interface enumeration order is provided by the kernel, and IPv6
      # link-local addresses are derived from each container's veth/MAC. Keep
      # the stable interface/address projection strict while ignoring that
      # namespace-specific link-local value.
      jq -S '.interfaces |= (map((.addresses |= (map(select(test("^fe80::") | not)) | sort))) | sort_by(.name))'
      ;;
    tools.licenses|tools.logs)
      # Dependency manifests and startup logs are implementation-specific;
      # the request above still verifies that both management surfaces are
      # wired and return valid JSON.
      jq -S '{implementationSpecific: true}'
      ;;
    *)
      jq -S .
      ;;
  esac
}

declare -a operations=(
  'info|{}'
  'update.status|{}'
  'settings.get|{}'
  'backup.config.get|{}'
  'inbounds.config.get|{}'
  'nodes.get|{"page":1,"page_size":1000}'
  'resolvers.get|{"page":1,"page_size":1000}'
  'inbounds.get|{"page":1,"page_size":1000}'
  'connections|{}'
  'connections.total|{}'
  'connections.traffic|{"interval":"hour","from":"2020-01-01T00:00:00Z","to":"2030-01-01T00:00:00Z"}'
  'connections.telemetry|{"from":"2020-01-01T00:00:00Z","to":"2030-01-01T00:00:00Z","limit":50}'
  'connections.failed_history|{}'
  'connections.history|{}'
  'resolver.hosts.get|{}'
  'resolver.fakedns.get|{}'
  'resolver.server.get|{}'
  'publishes|{}'
  'route.activation|{}'
  'route.config.get|{}'
  'route.lists.get|{"page":1,"page_size":1000}'
  'route.lists.config.get|{}'
  'route.lists.activation|{}'
  'route.rules.get|{"page":1,"page_size":1000}'
  'route.rules.block_history|{}'
  'route.tags.get|{}'
  'tools.interfaces|{}'
  'tools.licenses|{}'
)

# Go treats an empty LinkNames request as "refresh all". Keep this exact
# contract in the matrix when the source has no links (the operation is then a
# deterministic no-op); snapshots containing links may perform real network
# refreshes, so subscription refresh remains an explicit deferred feature and
# is not allowed to make a stopped-snapshot parity run hang on remote URLs.
include_empty_subscription_update="${YUHAIIN_INCLUDE_EMPTY_SUBSCRIPTION_UPDATE:-0}"
if [[ "${include_empty_subscription_update}" != "1" ]] \
  && command -v sqlite3 >/dev/null 2>&1; then
  subscription_count="$(sqlite3 "${source_db}" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='subscriptions';")"
  if [[ "${subscription_count}" == "1" ]]; then
    subscription_rows="$(sqlite3 "${source_db}" "SELECT COUNT(*) FROM subscriptions;")"
    [[ "${subscription_rows}" == "0" ]] && include_empty_subscription_update=1
  fi
fi
if [[ "${include_empty_subscription_update}" == "1" ]]; then
  operations+=( 'subscriptions.update|{}' )
fi

compare_read_operations() {
  local stage="${1:-initial}"
  local file_prefix=""
  if [[ "${stage}" != "initial" ]]; then
    file_prefix="${stage}-"
  fi
  for request_spec in "${operations[@]}"; do
    local operation="${request_spec%%|*}"
    local body="${request_spec#*|}"
    local safe_name="${operation//./-}"
    request "${go_http}" "${operation}" "${body}" | normalize "${operation}" "${stage}" >"${scenario_dir}/${file_prefix}go-${safe_name}.json"
    request "${rust_http}" "${operation}" "${body}" | normalize "${operation}" "${stage}" >"${scenario_dir}/${file_prefix}rust-${safe_name}.json"
    if ! diff -u "${scenario_dir}/${file_prefix}go-${safe_name}.json" \
      "${scenario_dir}/${file_prefix}rust-${safe_name}.json" \
      >"${scenario_dir}/${file_prefix}${safe_name}.diff"; then
      echo "[go-api-parity] response mismatch: ${operation} (${stage})" >&2
      sed -n '1,160p' "${scenario_dir}/${file_prefix}${safe_name}.diff" >&2
      exit 1
    fi
    echo "[go-api-parity] identical: ${operation} (${stage})"
  done
}

compare_read_operations

compare_mutation() {
  local name="$1"
  local operation="$2"
  local body="${3:-}"
  if [[ -z "${body}" ]]; then
    body='{}'
  fi
  request_mutation() {
    local address="$1"
    local request_body="$2"
    local raw_output="$3"
    local normalized_output="$4"
    local status
    if ! status="$(curl -sS --max-time 30 -o "${raw_output}" -w '%{http_code}' \
      "http://${address}/api/v2/rpc/${operation}" \
      -H 'content-type: application/json' \
      --data "${request_body}")"; then
      echo "[go-api-parity] curl failed: ${operation} address=${address}" >&2
      return 1
    fi
    if [[ "${status}" != 2* ]]; then
      echo "[go-api-parity] mutation HTTP ${status}: ${operation} address=${address}" >&2
      sed -n '1,160p' "${raw_output}" >&2 || true
      return 1
    fi
    jq -S . "${raw_output}" >"${normalized_output}"
  }

  request_mutation "${go_http}" "${body}" \
    "${scenario_dir}/mutation-go-${name}.raw" \
    "${scenario_dir}/mutation-go-${name}.json"
  request_mutation "${rust_http}" "${body}" \
    "${scenario_dir}/mutation-rust-${name}.raw" \
    "${scenario_dir}/mutation-rust-${name}.json"
  if ! diff -u "${scenario_dir}/mutation-go-${name}.json" \
    "${scenario_dir}/mutation-rust-${name}.json" \
    >"${scenario_dir}/mutation-${name}.diff"; then
    echo "[go-api-parity] mutation response mismatch: ${operation}" >&2
    sed -n '1,160p' "${scenario_dir}/mutation-${name}.diff" >&2
    exit 1
  fi
  echo "[go-api-parity] mutation identical: ${operation}"
}

if [[ "${YUHAIIN_MUTATION_PARITY:-1}" == "1" ]]; then
  # These IDs are deliberately unique per invocation so the mutation matrix
  # can run against an unchanged production snapshot without deleting user
  # configuration. Both services receive the same body and path sequence.
  mutation_suffix="${YUHAIIN_MUTATION_SUFFIX:-${BASHPID}}"
  node_id="rust-api-parity-node-${mutation_suffix}"
  inbound_id="rust-api-parity-inbound-${mutation_suffix}"
  resolver_id="rust-api-parity-resolver-${mutation_suffix}"
  list_id="rust-api-parity-list-${mutation_suffix}"
  process_list_id="rust-api-parity-process-list-${mutation_suffix}"
  inbound_list_id="rust-api-parity-inbound-list-${mutation_suffix}"
  rule_id="rust-api-parity-rule-${mutation_suffix}"
  tag_id="rust-api-parity-tag-${mutation_suffix}"

  node_body="$(jq -cn --arg id "${node_id}" '{id:$id,name:"API parity node",group:"parity",enabled:true,chain:[{type:"direct",direct:{}}]}')"
  compare_mutation node-post nodes.post "${node_body}"
  compare_mutation node-get node.get "$(jq -cn --arg id "${node_id}" '{id:$id}')"
  node_put_body="$(jq -cn --arg id "${node_id}" '{id:$id,name:"API parity node updated",enabled:false,chain:[{type:"direct",direct:{}}]}')"
  compare_mutation node-put node.put "${node_put_body}"
  compare_mutation node-get-updated node.get "$(jq -cn --arg id "${node_id}" '{id:$id}')"
  compare_mutation node-use node.use "$(jq -cn --arg id "${node_id}" '{id:$id}')"
  compare_mutation nodes-selected nodes.selected '{}'
  compare_mutation node-close node.close "$(jq -cn --arg id "${node_id}" '{id:$id}')"
  compare_mutation node-delete node.delete "$(jq -cn --arg id "${node_id}" '{id:$id}')"

  inbound_body="$(jq -cn --arg id "${inbound_id}" '{id:$id,name:"API parity inbound",enabled:false,network:{type:"empty",empty:{}},transports:[],protocol:{type:"none",none:{}}}')"
  compare_mutation inbound-post inbounds.post "${inbound_body}"
  compare_mutation inbound-get inbound.get "$(jq -cn --arg id "${inbound_id}" '{id:$id}')"
  inbound_put_body="$(jq -cn --arg id "${inbound_id}" '{id:$id,name:"API parity inbound updated",enabled:false,network:{type:"empty",empty:{}},transports:[],protocol:{type:"none",none:{}}}')"
  compare_mutation inbound-put inbound.put "${inbound_put_body}"
  compare_mutation inbound-get-updated inbound.get "$(jq -cn --arg id "${inbound_id}" '{id:$id}')"
  compare_mutation inbound-delete inbound.delete "$(jq -cn --arg id "${inbound_id}" '{id:$id}')"

  resolver_body="$(jq -cn --arg id "${resolver_id}" '{id:$id,type:"udp",host:"127.0.0.1:53"}')"
  compare_mutation resolver-post resolvers.post "${resolver_body}"
  compare_mutation resolver-get resolver.get "$(jq -cn --arg id "${resolver_id}" '{id:$id}')"
  resolver_put_body="$(jq -cn --arg id "${resolver_id}" '{id:$id,type:"udp",host:"127.0.0.1:5353"}')"
  compare_mutation resolver-put resolver.put "${resolver_put_body}"
  compare_mutation resolver-get-updated resolver.get "$(jq -cn --arg id "${resolver_id}" '{id:$id}')"
  compare_mutation resolver-delete resolver.delete "$(jq -cn --arg id "${resolver_id}" '{id:$id}')"

  settings_body="$(jq '.pprof = false' "${scenario_dir}/go-settings-get.json")"
  compare_mutation settings-put settings.put "${settings_body}"
  compare_mutation settings-get-updated settings.get '{}'

  backup_body='{"instanceName":"api-parity","interval":0,"lastBackupHash":"","s3":{"enabled":false,"accessKey":"","secretKey":"","bucket":"","region":"","endpointUrl":"","usePathStyle":false,"storageClass":""}}'
  compare_mutation backup-put backup.config.put "${backup_body}"
  compare_mutation backup-get-updated backup.config.get '{}'

  inbound_config_body='{"hijackDns":true,"hijackDnsFakeIp":false,"sniff":true}'
  compare_mutation inbound-config-put inbounds.config.put "${inbound_config_body}"
  compare_mutation inbound-config-get-updated inbounds.config.get '{}'

  hosts_body='{"hosts":{"api-parity.example":"127.0.0.1"}}'
  compare_mutation hosts-put resolver.hosts.put "${hosts_body}"
  compare_mutation hosts-get-updated resolver.hosts.get '{}'

  fakedns_body='{"enabled":false,"ipv4Range":"198.18.0.0/15","ipv6Range":"fc00::/18","whitelist":["api-parity.example"],"skipCheckList":["skip.api-parity.example"]}'
  compare_mutation fakedns-put resolver.fakedns.put "${fakedns_body}"
  compare_mutation fakedns-get-updated resolver.fakedns.get '{}'

  server_body='{"server":"127.0.0.1:5353"}'
  compare_mutation resolver-server-put resolver.server.put "${server_body}"
  compare_mutation resolver-server-get-updated resolver.server.get '{}'

  route_config_body='{"directResolver":"bootstrap","proxyResolver":"proxy","resolveLocally":true,"udpProxyFqdnStrategy":"resolve"}'
  compare_mutation route-config-put route.config.put "${route_config_body}"
  compare_mutation route-config-get-updated route.config.get '{}'

  route_list_config_body='{"refreshInterval":"3600","lastRefreshTime":"0","error":"","hostIndexDisk":false,"maxMindDbGeoIp":{"downloadUrl":"","error":""}}'
  compare_mutation route-lists-config-put route.lists.config.put "${route_list_config_body}"
  compare_mutation route-lists-config-get-updated route.lists.config.get '{}'

  list_body="$(jq -cn --arg name "${list_id}" '{name:$name,type:"host",source:{type:"local",local:{lists:["parity.example"]}}}')"
  compare_mutation route-list-post route.lists.post "${list_body}"
  compare_mutation route-list-get route.list.get "$(jq -cn --arg id "${list_id}" '{id:$id}')"

  process_list_body="$(jq -cn --arg name "${process_list_id}" '{name:$name,type:"process",source:{type:"local",local:{lists:["parity-process"]}}}')"
  compare_mutation route-process-list-post route.lists.post "${process_list_body}"
  compare_mutation route-process-list-get route.list.get "$(jq -cn --arg id "${process_list_id}" '{id:$id}')"
  inbound_list_body="$(jq -cn --arg name "${inbound_list_id}" '{name:$name,type:"inbound",source:{type:"local",local:{lists:["parity-inbound"]}}}')"
  compare_mutation route-inbound-list-post route.lists.post "${inbound_list_body}"
  compare_mutation route-inbound-list-get route.list.get "$(jq -cn --arg id "${inbound_list_id}" '{id:$id}')"

  # Exercise a nested matcher rather than only a single host-list predicate:
  # parity.example is in the list but the requested port (443) is outside the
  # rule's 8443 range, so both services must expose the rejected rule history.
  rule_body="$(jq -cn --arg name "${rule_id}" --arg list "${list_id}" --arg process_list "${process_list_id}" '{name:$name,mode:"direct",tag:"parity",rules:[{type:"all",all:[{type:"host",host:{list:$list}},{type:"process",process:{list:$process_list}},{type:"inbound",inbound:{names:["parity-inbound"]}},{type:"port",port:{ports:"8443"}},{type:"not",not:{type:"port",port:{ports:"9443"}}}]}]}')"
  compare_mutation route-rule-post route.rules.post "${rule_body}"
  compare_mutation route-rule-get route.rule.get "$(jq -cn --arg name "${rule_id}" '{name:$name,index:0}')"
  compare_mutation route-apply route.apply '{}'
  compare_mutation route-rules-test route.rules.test '{"host":"parity.example:443"}'
  compare_mutation route-list-delete route.list.delete "$(jq -cn --arg id "${list_id}" '{id:$id}')"
  compare_mutation route-process-list-delete route.list.delete "$(jq -cn --arg id "${process_list_id}" '{id:$id}')"
  compare_mutation route-inbound-list-delete route.list.delete "$(jq -cn --arg id "${inbound_list_id}" '{id:$id}')"
  compare_mutation route-tag-put route.tag.put "$(jq -cn --arg tag "${tag_id}" '{tag:$tag,type:"node",hash:""}')"
  compare_mutation route-tag-get route.tags.get "$(jq -cn --arg query "${tag_id}" '{query:$query}')"
  compare_mutation route-tag-delete route.tag.delete "$(jq -cn --arg tag "${tag_id}" '{tag:$tag}')"
  compare_mutation route-rule-delete route.rule.delete "$(jq -cn --arg name "${rule_id}" '{name:$name,index:0}')"

  publish_name="rust-api-parity-publish-${mutation_suffix}"
  publish_body="$(jq -cn --arg name "${publish_name}" '{name:$name,points:[],path:"parity",password:"secret",address:"",insecure:false}')"
  compare_mutation publish-put publish.put "${publish_body}"
  compare_mutation publishes-after-put publishes '{}'
  compare_mutation publish-resolve publish.resolve "$(jq -cn --arg name "${publish_name}" '{name:$name,path:"parity",password:"secret"}')"
  compare_mutation publish-delete publish.delete "$(jq -cn --arg name "${publish_name}" '{name:$name}')"
  compare_mutation publishes-after-delete publishes '{}'
fi

# Go's typed CloseRequest decodes a missing/null ids field as an empty slice;
# closing no connections is a successful no-op. Keep this explicit because it
# is a request-shape edge case rather than a mutation of the fixture.
compare_mutation connections-close-empty connections.close '{}'

compare_error() {
  local name="$1"
  local operation="$2"
  local body="$3"
  local safe_name="${name//./-}"
  local address service status raw normalized
  for service in go rust; do
    if [[ "${service}" == "go" ]]; then
      address="${go_http}"
    else
      address="${rust_http}"
    fi
    raw="${scenario_dir}/error-${service}-${safe_name}.raw"
    normalized="${scenario_dir}/error-${service}-${safe_name}.json"
    status="$(curl -sS --max-time 30 -o "${raw}" -w '%{http_code}' \
      "http://${address}/api/v2/rpc/${operation}" \
      -H 'content-type: application/json' \
      --data "${body}")"
    if [[ "${status}" == 2* ]]; then
      echo "[go-api-parity] expected error but got HTTP ${status}: ${operation} ${body}" >&2
      return 1
    fi
    printf '%s\n' "${status}" >"${scenario_dir}/error-${service}-${safe_name}.status"
    if jq -e . "${raw}" >/dev/null 2>&1; then
      # Go's decoder includes its concrete request type in malformed JSON
      # messages (for example `emptyRequest`); that implementation detail is
      # not part of the frontend contract. Status and error code remain
      # strict, while raw bodies above retain the original diagnostic.
      jq -S 'if (.error.message? != null) then .error.message = "<validation-message>" else . end' \
        "${raw}" >"${normalized}"
    else
      # Go's net/http ServeMux can answer an unknown method/path with a
      # plain-text 404/405. Preserve that body instead of hiding it behind a
      # JSON-only harness; known RPC errors remain strictly normalized JSON.
      jq -Rs . "${raw}" >"${normalized}"
    fi
  done
  if ! diff -u "${scenario_dir}/error-go-${safe_name}.status" \
    "${scenario_dir}/error-rust-${safe_name}.status" \
    >"${scenario_dir}/error-${safe_name}.status.diff"; then
    echo "[go-api-parity] error status mismatch: ${operation}" >&2
    sed -n '1,160p' "${scenario_dir}/error-${safe_name}.status.diff" >&2
    return 1
  fi
  if ! diff -u "${scenario_dir}/error-go-${safe_name}.json" \
    "${scenario_dir}/error-rust-${safe_name}.json" \
    >"${scenario_dir}/error-${safe_name}.diff"; then
    echo "[go-api-parity] error body mismatch: ${operation}" >&2
    sed -n '1,160p' "${scenario_dir}/error-${safe_name}.diff" >&2
    return 1
  fi
  echo "[go-api-parity] error identical: ${operation} (${name})"
}

# These requests must not mutate either service. Keep them alongside the
# success/mutation matrix so a frontend replacement is checked for the same
# HTTP status, rpc error code, and validation message as Go.
declare -a error_operations=(
  'non-object-body|info|[]'
  'node-id-required|node.get|{}'
  'node-not-found|node.get|{"id":"missing-error-node"}'
  'inbound-id-required|inbound.get|{}'
  'inbound-not-found|inbound.get|{"id":"missing-error-inbound"}'
  'resolver-id-required|resolver.get|{}'
  'resolver-not-found|resolver.get|{"id":"missing-error-resolver"}'
  'route-list-id-required|route.list.get|{}'
  'route-list-not-found|route.list.get|{"id":"missing-error-list"}'
  'route-rule-name-required|route.rule.get|{"index":0}'
  'route-rule-not-found|route.rule.get|{"name":"missing-error-rule","index":0}'
  'connections-traffic-missing-from|connections.traffic|{"to":"2030-01-01T00:00:00Z"}'
  'connections-traffic-invalid-from|connections.traffic|{"from":"not-rfc3339","to":"2030-01-01T00:00:00Z"}'
  'connections-traffic-reversed|connections.traffic|{"from":"2030-01-02T00:00:00Z","to":"2030-01-01T00:00:00Z"}'
  'connections-telemetry-limit|connections.telemetry|{"from":"2020-01-01T00:00:00Z","to":"2030-01-01T00:00:00Z","limit":51}'
  'connections-close-id-invalid|connections.close|{"ids":["not-a-number"]}'
  'connections-close-ids-type|connections.close|{"ids":123}'
  'route-test-host-required|route.rules.test|{}'
  'route-test-port-invalid|route.rules.test|{"host":"example.com:not-a-port"}'
  'route-priority-source-required|route.rules.priority|{"target":{"name":"missing"}}'
  'route-priority-operate-invalid|route.rules.priority|{"source":{"name":"missing"},"target":{"name":"missing"},"operate":"invalid"}'
)

# An empty restore request is deterministic only when S3 backup is disabled.
# With an enabled remote backup, Go and Rust are expected to attempt the
# configured object through their own runtime/proxy stacks; a stopped-snapshot
# parity run must not turn that external operation (or a deliberately
# unsupported legacy proxy protocol) into a status-code comparison. The local
# backup/restore contract is covered by the Rust fake-S3 integration test.
if ! jq -e '.s3.enabled == true' "${scenario_dir}/go-backup-config-get.json" >/dev/null 2>&1; then
  error_operations+=( 'backup-restore-source-required|backup.restore|{}' )
else
  echo "[go-api-parity] skipped external backup.restore error probe: S3 backup is enabled"
fi

for request_spec in "${error_operations[@]}"; do
  error_name="${request_spec%%|*}"
  remainder="${request_spec#*|}"
  error_operation="${remainder%%|*}"
  error_body="${remainder#*|}"
  compare_error "${error_name}" "${error_operation}" "${error_body}"
done

if [[ "${YUHAIIN_FORCE_STOP_REOPEN:-0}" == "1" ]]; then
  echo "[go-api-parity] force-stopping both services before persistence replay"
  podman kill --signal KILL "${go_container}" "${rust_container}" \
    >"${scenario_dir}/force-stop-status.log" 2>&1 || true
  podman logs "${go_container}" >"${scenario_dir}/go-force-stop.log" 2>&1 || true
  podman logs "${rust_container}" >"${scenario_dir}/rust-force-stop.log" 2>&1 || true
  podman rm -f --ignore "${go_container}" "${rust_container}" \
    >"${scenario_dir}/force-stop-rm.log" 2>&1
  start_services
  wait_ready "${go_http}"
  wait_ready "${rust_http}"
  compare_read_operations force-stop-reopen
  echo "[go-api-parity] force-stop persistence replay passed"
fi

echo "[go-api-parity] passed; logs=${scenario_dir}"
