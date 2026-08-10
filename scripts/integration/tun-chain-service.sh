#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_dir="${YUHAIIN_TUN_CHAIN_DIR:-${HOME}/.cache/yuhaiin-rust/integration/tun-chain-service}"

YUHAIIN_TUN_CHAIN=tls-h2-yuubinsya \
YUHAIIN_INTEGRATION_DIR="${cache_dir}" \
  "${repo_dir}/scripts/integration/tun-service.sh"
