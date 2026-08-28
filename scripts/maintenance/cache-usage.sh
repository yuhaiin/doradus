#!/usr/bin/env bash
set -euo pipefail

# Keep all build and integration state under the repository-local cache directory. This
# command is intentionally read-only: removal remains an explicit
# cache-prune operation with its own allowlists.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${DORADUS_CACHE_DIR:-${repo_root}/.cache/doradus}"
warn_gib="${DORADUS_CACHE_WARN_GIB:-20}"

if [[ ! "${warn_gib}" =~ ^[0-9]+$ ]] || [[ "${warn_gib}" -eq 0 ]]; then
  echo "DORADUS_CACHE_WARN_GIB must be a positive integer" >&2
  exit 2
fi

if [[ ! -d "${cache_root}" ]]; then
  echo "[cache-usage] cache directory does not exist: ${cache_root}"
  exit 0
fi

total_kib="$(du -sk -- "${cache_root}" | awk '{print $1}')"
warn_kib=$((warn_gib * 1024 * 1024))
total_gib="$(awk -v kib="${total_kib}" 'BEGIN { printf "%.2f", kib / 1024 / 1024 }')"
printf '[cache-usage] root=%s total=%s GiB warning-threshold=%s GiB\n' \
  "${cache_root}" "${total_gib}" "${warn_gib}"

if (( total_kib >= warn_kib )); then
  echo "[cache-usage] WARNING: cache exceeds the configured threshold; review cache-prune before another large build" >&2
fi

echo '[cache-usage] largest direct children:'
du -k --max-depth=1 -- "${cache_root}" 2>/dev/null \
  | sort -n -k1,1 \
  | tail -25 \
  | awk -v root="${cache_root}" '$2 != root { printf "  %8.2f GiB  %s\n", $1 / 1024 / 1024, $2 }'
