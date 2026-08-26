#!/usr/bin/env bash
set -euo pipefail

# Remove only stale, reproducible integration outputs. Cargo artifacts and
# reusable fixtures are intentionally left alone because deleting them makes
# the next Podman run needlessly expensive.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${repo_root}/.cache/yuhaiin-rust}"
retention_days="${YUHAIIN_CACHE_RETENTION_DAYS:-1}"
dry_run="${YUHAIIN_CACHE_DRY_RUN:-0}"
prune_debug="${YUHAIIN_CACHE_PRUNE_DEBUG:-0}"
prune_transient="${YUHAIIN_CACHE_PRUNE_TRANSIENT:-0}"

if [[ ! "${retention_days}" =~ ^[0-9]+$ ]]; then
  echo "YUHAIIN_CACHE_RETENTION_DAYS must be a non-negative integer" >&2
  exit 2
fi
if [[ "${dry_run}" != 0 && "${dry_run}" != 1 ]]; then
  echo "YUHAIIN_CACHE_DRY_RUN must be 0 or 1" >&2
  exit 2
fi
if [[ "${prune_debug}" != 0 && "${prune_debug}" != 1 ]]; then
  echo "YUHAIIN_CACHE_PRUNE_DEBUG must be 0 or 1" >&2
  exit 2
fi
if [[ "${prune_transient}" != 0 && "${prune_transient}" != 1 ]]; then
  echo "YUHAIIN_CACHE_PRUNE_TRANSIENT must be 0 or 1" >&2
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

if [[ "${prune_debug}" == 1 || "${prune_transient}" == 1 ]]; then
  active_build=""
  for proc_dir in /proc/[0-9]*; do
    proc_pid="${proc_dir##*/}"
    [[ "${proc_pid}" == "$$" ]] && continue
    [[ -r "${proc_dir}/cmdline" ]] || continue
    proc_cmdline="$(tr '\0' ' ' <"${proc_dir}/cmdline" 2>/dev/null || true)"
    if [[ " ${proc_cmdline} " =~ (^|[[:space:]])([^[:space:]]*/)?(cargo|rustc)([[:space:]]|$) ]] &&
      [[ "${proc_cmdline}" == *"${cache_root}"* ]]; then
      active_build="${proc_cmdline}"
      break
    fi
  done
  if [[ -n "${active_build}" ]]; then
    echo "[cache-prune] refusing build cleanup while cargo/rustc uses ${cache_root}: ${active_build}" >&2
    exit 3
  fi
fi

if [[ "${prune_debug}" == 1 ]]; then
  debug_root="${cache_root}/cargo-target/debug"
  for path in \
    "${debug_root}/deps" \
    "${debug_root}/build" \
    "${debug_root}/.fingerprint" \
    "${debug_root}/examples" \
    "${debug_root}/incremental"; do
    if [[ "${dry_run}" == 1 ]]; then
      [[ -e "${path}" ]] && echo "[cache-prune] debug artifact (dry-run): ${path}"
    elif [[ -e "${path}" ]]; then
      echo "[cache-prune] remove debug artifact: ${path}"
      rm -rf -- "${path}"
    fi
  done
fi

transient_count=0
if [[ "${prune_transient}" == 1 ]]; then
  # These roots are disposable outputs from one-off cross/CI experiments.
  # Keep the allowlist explicit: cargo-target, fixtures, rules, and integration
  # state are intentionally outside this branch.
  transient_roots=(
    "${cache_root}/cargo-target-ci"
    "${cache_root}/ci-udp-hardening-target"
    "${cache_root}/cross-target"
    "${cache_root}/cross-aarch64-apple-darwin"
    "${cache_root}/cross-x86_64-apple-darwin"
    "${cache_root}/cross-x86_64-pc-windows-gnu"
    "${cache_root}/final-musl-target"
    "${cache_root}/make-musl-target"
    "${cache_root}/static-cargo-target"
  )
  for path in "${transient_roots[@]}"; do
    [[ -d "${path}" && ! -L "${path}" ]] || continue
    if find "${path}" -maxdepth 0 -type d \
      -mmin "+$((retention_days * 1440))" -print -quit | grep -q .; then
      transient_count=$((transient_count + 1))
      if [[ "${dry_run}" == 1 ]]; then
        echo "[cache-prune] transient (dry-run): ${path}"
      else
        echo "[cache-prune] remove transient: ${path}"
        rm -rf -- "${path}"
      fi
    fi
  done
fi

after="$(size_kib)"
echo "[cache-prune] stale-directories=${stale_count} size-after=${after} KiB"
if [[ "${dry_run}" == 1 ]]; then
  echo "[cache-prune] dry-run only; set YUHAIIN_CACHE_DRY_RUN=0 to remove them"
fi
if [[ "${prune_debug}" == 1 ]]; then
  echo "[cache-prune] selected cargo-target/debug dependency artifacts were pruned; debug binaries remain"
else
  echo "[cache-prune] cargo-target and fixtures were not modified"
  echo "[cache-prune] set YUHAIIN_CACHE_PRUNE_DEBUG=1 for opt-in debug dependency cleanup"
fi
if [[ "${prune_transient}" == 1 ]]; then
  echo "[cache-prune] transient-roots=${transient_count} (allowlisted, retention=${retention_days}d)"
else
  echo "[cache-prune] one-off cross/CI target roots were not modified"
  echo "[cache-prune] set YUHAIIN_CACHE_PRUNE_TRANSIENT=1 for opt-in cleanup"
fi
