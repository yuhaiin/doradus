#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
YUHAIIN_TUN_ASSERT_CONNECTIONS=1 \
YUHAIIN_TUN_TRAFFIC_BYTES="${YUHAIIN_TUN_TRAFFIC_BYTES:-1048576}" \
  "${repo_dir}/scripts/integration/tun-chain-service.sh"
