#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_dir="${DORADUS_TUN_CHAIN_DIR:-${repo_dir}/.cache/doradus/integration/tun-chain-service}"

DORADUS_TUN_CHAIN=tls-h2-yuubinsya \
DORADUS_INTEGRATION_DIR="${cache_dir}" \
  "${repo_dir}/scripts/integration/tun-service.sh"
