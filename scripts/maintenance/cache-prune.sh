#!/usr/bin/env bash
set -euo pipefail

# Remove only stale, reproducible integration outputs. Cargo artifacts and
# reusable fixtures are intentionally left alone because deleting them makes
# the next Podman run needlessly expensive.
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
retention_days="${YUHAIIN_CACHE_RETENTION_DAYS:-1}"
dry_run="${YUHAIIN_CACHE_DRY_RUN:-0}"

if [[ ! "${retention_days}" =~ ^[0-9]+$ ]]; then
  echo "YUHAIIN_CACHE_RETENTION_DAYS must be a non-negative integer" >&2
  exit 2
fi
if [[ "${dry_run}" != 0 && "${dry_run}" != 1 ]]; then
  echo "YUHAIIN_CACHE_DRY_RUN must be 0 or 1" >&2
  exit 2
fi

if [[ ! -d "${cache_root}" ]]; then
  echo "[cache-prune] cache directory does not exist: ${cache_root}"
  exit 0
fi

size_kib() {
  du -sk -- "${cache_root}" | awk '{print $1}'
}

before="$(size_kib)"
echo "[cache-prune] root=${cache_root} size=${before} KiB retention=${retention_days}d"

parents=(
  integration
  production-parity
  api-parity
  api-compare
  benchmarks
)
stale_count=0
for parent in "${parents[@]}"; do
  parent_path="${cache_root}/${parent}"
  [[ -d "${parent_path}" ]] || continue
  while IFS= read -r -d '' path; do
    [[ -d "${path}" && ! -L "${path}" ]] || continue
    stale_count=$((stale_count + 1))
    if [[ "${dry_run}" == 1 ]]; then
      echo "[cache-prune] stale (dry-run): ${path}"
    else
      echo "[cache-prune] remove stale: ${path}"
      rm -rf -- "${path}"
    fi
  done < <(find "${parent_path}" -mindepth 1 -maxdepth 1 -type d \
    -mmin "+$((retention_days * 1440))" -print0)
done

after="$(size_kib)"
echo "[cache-prune] stale-directories=${stale_count} size-after=${after} KiB"
if [[ "${dry_run}" == 1 ]]; then
  echo "[cache-prune] dry-run only; set YUHAIIN_CACHE_DRY_RUN=0 to remove them"
fi
echo "[cache-prune] cargo-target and fixtures were not modified"
