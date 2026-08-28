#!/usr/bin/env bash
set -euo pipefail

# Opt-in external smoke for the Go-compatible HTTP inbound behavior:
# absolute-form HTTPS request -> selected outbound -> origin TLS -> response.
# The Rust test itself owns the service process and persists its fixture under
# the normal cache root; this wrapper only supplies a stable Podman entrypoint.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${DORADUS_CACHE_DIR:-${repo_root}/.cache/doradus}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
state_dir="${DORADUS_HTTP_INBOUND_HTTPS_DIR:-${cache_root}/integration/http-inbound-https}"

mkdir -p "${state_dir}"
"${repo_root}/scripts/integration/podman-cargo.sh" \
  --target-dir "${target_dir}" \
  --state-dir "${state_dir}" \
  -- cargo test --locked -p doradus-runtime --all-features --test service_chain \
    http_inbound_forwards_absolute_https_request -- --ignored --nocapture

echo "[http-inbound-https] passed; logs=${state_dir}"
