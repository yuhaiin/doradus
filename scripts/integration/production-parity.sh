#!/usr/bin/env bash
set -euo pipefail

# Run the existing Go/Rust management parity smoke against several stopped
# production-shaped databases. The source files are never modified; each
# invocation gets an isolated cache-backed copy under ~/.cache.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
go_root="${YUHAIIN_GO_DIR:-$(cd "${repo_root}/../yuhaiin" && pwd)}"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
scenario_root="${YUHAIIN_PRODUCTION_PARITY_DIR:-${cache_root}/production-parity}"

test -d "${go_root}"
mkdir -p "${scenario_root}"

declare -a candidates=()
if [[ -n "${YUHAIIN_SOURCE_DB:-}" ]]; then
  IFS=: read -r -a candidates <<<"${YUHAIIN_SOURCE_DB}"
else
  # The default path prepares each snapshot with Rust first, because these
  # stopped production snapshots can carry a migration ledger from a newer Go
  # checkout while still using the older dimension/value telemetry tables.
  # YUHAIIN_PREPARE=0 remains a useful raw-source diagnostic, but it is not a
  # valid Go/Rust parity fixture when the current Go checkout cannot migrate
  # that future ledger and its telemetry API returns HTTP 500.
  candidates=(
    "${go_root}/tmp/v2/state.db"
    "${go_root}/tmp/yuhaiin/state.db"
    "${go_root}/tmp/aws/yuhaiin/state.db"
  )
fi

declare -A seen=()
ran=0
for source_db in "${candidates[@]}"; do
  [[ -n "${source_db}" && -f "${source_db}" ]] || continue
  source_db="$(realpath "${source_db}")"
  [[ -n "${seen[${source_db}]:-}" ]] && continue
  seen["${source_db}"]=1
  relative_db="${source_db#${go_root}/}"
  label="${relative_db%.*}"
  label="${label//\//-}"
  label="${label//[^[:alnum:]_.-]/-}"
  scenario_dir="${scenario_root}/${label}"
  echo "[production-parity] checking ${source_db}"
  YUHAIIN_GO_DIR="${go_root}" \
  YUHAIIN_SOURCE_DB="${source_db}" \
  YUHAIIN_INTEGRATION_DIR="${scenario_dir}" \
  YUHAIIN_PREPARE="${YUHAIIN_PREPARE:-1}" \
    "${repo_root}/scripts/integration/go-api-parity.sh"
  ran=$((ran + 1))
done

if (( ran == 0 )); then
  echo "[production-parity] no fixture found; set YUHAIIN_SOURCE_DB to a stopped SQLite snapshot" >&2
  exit 0
fi
echo "[production-parity] passed ${ran} fixture(s); logs=${scenario_root}"
