#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_dir="${YUHAIIN_INTEGRATION_DIR:-${HOME}/.cache/yuhaiin-rust/integration-reusable}"
mkdir -p "${cache_dir}"

cd "${repo_dir}"
YUHAIIN_INTEGRATION_DIR="${cache_dir}" \
  cargo test -p yuhaiin-runtime --all-features --offline --test service_chain -- --nocapture
