#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DORADUS_TUN_ASSERT_CONNECTIONS=1 \
DORADUS_TUN_ASSERT_PROCESS=1 \
DORADUS_TUN_TRAFFIC_BYTES="${DORADUS_TUN_TRAFFIC_BYTES:-1048576}" \
  "${repo_dir}/scripts/integration/tun-chain-service.sh"
