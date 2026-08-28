#!/usr/bin/env bash
set -euo pipefail

# Exercise the real S3-compatible request path against MinIO.  The runtime,
# MinIO, the bucket helper and the binary build all run in disposable Podman
# containers. State and logs stay below the repository-local cache directory.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${DORADUS_CACHE_DIR:-${repo_root}/.cache/doradus}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
scenario_dir="${DORADUS_INTEGRATION_DIR:-${cache_root}/integration/s3-minio}"
image="${DORADUS_MINIO_IMAGE:-quay.io/minio/minio:latest}"
mc_image="${DORADUS_MINIO_MC_IMAGE:-quay.io/minio/mc:latest}"
test_image="${DORADUS_TEST_IMAGE:-docker.io/library/debian:testing}"
http_address="${DORADUS_S3_MINIO_HTTP:-127.0.0.1:55253}"
access_key="${DORADUS_MINIO_ACCESS_KEY:-doradus-access}"
secret_key="${DORADUS_MINIO_SECRET_KEY:-doradus-secret-123}"
bucket="${DORADUS_MINIO_BUCKET:-doradus-smoke}"

command -v curl >/dev/null
command -v jq >/dev/null
command -v podman >/dev/null
mkdir -p "${scenario_dir}"

ensure_image() {
  local image_name="$1"
  if ! podman image exists "${image_name}"; then
    echo "[s3-minio] pulling ${image_name}"
    podman pull "${image_name}"
  fi
}

ensure_image "${image}"
ensure_image "${mc_image}"

echo "[s3-minio] building runtime in Podman"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" --state-dir "${scenario_dir}" -- \
  cargo build \
  --locked -p doradus-api --bin doradus --all-features \
  >"${scenario_dir}/runtime-build.log" 2>&1
runtime_binary="${target_dir}/debug/doradus"
test -x "${runtime_binary}"

network="doradus-s3-minio-${BASHPID}"
minio_container="${network}-server"
runtime_container="${network}-runtime"
state_dir="${scenario_dir}/state"
mkdir -p "${state_dir}/cache" "${state_dir}/home" "${state_dir}/minio"
podman network create "${network}" >"${scenario_dir}/network-id"

cleanup() {
  podman rm -f --ignore "${runtime_container}" "${minio_container}" \
    >"${scenario_dir}/container-cleanup.log" 2>&1 || true
  podman network rm "${network}" \
    >>"${scenario_dir}/container-cleanup.log" 2>&1 || true
}
trap cleanup EXIT

echo "[s3-minio] starting MinIO and bucket helper in Podman"
podman run -d \
  --name "${minio_container}" \
  --network "${network}" \
  --network-alias minio \
  -e "MINIO_ROOT_USER=${access_key}" \
  -e "MINIO_ROOT_PASSWORD=${secret_key}" \
  -v "${state_dir}/minio:/data:Z" \
  "${image}" server /data --address :9000 \
  >"${scenario_dir}/minio-container-id"

for _ in $(seq 1 120); do
  if podman run --rm --network "${network}" \
    -e "MC_HOST_local=http://${access_key}:${secret_key}@minio:9000" \
    "${mc_image}" ready local >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
podman run --rm --network "${network}" \
  -e "MC_HOST_local=http://${access_key}:${secret_key}@minio:9000" \
  "${mc_image}" mb --ignore-existing "local/${bucket}" \
  >"${scenario_dir}/bucket.log"

echo "[s3-minio] starting runtime in Podman"
podman run -d \
  --name "${runtime_container}" \
  --network "${network}" \
  -p "${http_address}:58080" \
  -v "${runtime_binary}:/usr/local/bin/doradus:ro" \
  -v "${state_dir}:/state:Z" \
  -e HOME=/state/home \
  -e DORADUS_CACHE_DIR=/state/cache \
  --entrypoint /usr/local/bin/doradus \
  "${test_image}" \
  -host 0.0.0.0:58080 -path /state \
  >"${scenario_dir}/runtime-container-id"

rpc() {
  local operation="$1"
  local body="$2"
  curl --fail --silent --show-error --max-time 30 \
    "http://${http_address}/api/v2/rpc/${operation}" \
    -H 'content-type: application/json' \
    --data "${body}"
}

echo "[s3-minio] waiting for runtime"
for _ in $(seq 1 120); do
  if rpc info '{}' >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
rpc info '{}' >/dev/null

config="$(jq -cn \
  --arg instance "s3-minio" \
  --arg access "${access_key}" \
  --arg secret "${secret_key}" \
  --arg bucket "${bucket}" \
  '{instanceName:$instance,interval:0,lastBackupHash:"",s3:{enabled:true,accessKey:$access,secretKey:$secret,bucket:$bucket,region:"us-east-1",endpointUrl:"http://minio:9000",usePathStyle:true,storageClass:"STANDARD"}}')"
rpc backup.config.put "${config}" >"${scenario_dir}/backup-config-put.json"
rpc backup.run '{}' >"${scenario_dir}/backup-run.json"
rpc backup.config.get '{}' >"${scenario_dir}/backup-config-after-run.json"

hash="$(jq -r '.lastBackupHash' "${scenario_dir}/backup-config-after-run.json")"
test "${#hash}" -eq 64
podman run --rm --network "${network}" \
  -e "MC_HOST_local=http://${access_key}:${secret_key}@minio:9000" \
  "${mc_image}" stat "local/${bucket}/s3-minio-state.db" \
  >"${scenario_dir}/object-stat.log"

# An empty restore must download the same object before asking the managed
# service to restart.  The downloaded file is on the cache-backed state mount.
rpc backup.restore '{}' >"${scenario_dir}/backup-restore.json"
jq -e '.accepted == true and .restart == true' "${scenario_dir}/backup-restore.json" >/dev/null
for _ in $(seq 1 100); do
  running="$(podman inspect -f '{{.State.Running}}' "${runtime_container}" 2>/dev/null || true)"
  [[ "${running}" == "false" ]] && break
  sleep 0.1
done
test -s "${state_dir}/cache/doradus/backups/remote-state.sqlite"

podman logs "${runtime_container}" >"${scenario_dir}/runtime.log" 2>&1 || true
echo "[s3-minio] passed; object=${bucket}/s3-minio-state.db logs=${scenario_dir}"
