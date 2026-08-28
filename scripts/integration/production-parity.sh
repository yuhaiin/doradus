#!/usr/bin/env bash
set -euo pipefail

# Run the existing Go/Rust management parity smoke against several stopped
# production-shaped databases. The source files are never modified; each
# invocation gets an isolated cache-backed copy under the repository-local cache.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
go_root="${DORADUS_GO_DIR:-$(cd "${repo_root}/../yuhaiin" && pwd)}"
cache_root="${DORADUS_CACHE_DIR:-${repo_root}/.cache/doradus}"
scenario_root="${DORADUS_PRODUCTION_PARITY_DIR:-${cache_root}/production-parity}"
port_base="${DORADUS_PRODUCTION_PORT_BASE:-55250}"

[[ "${port_base}" =~ ^[0-9]+$ ]] || {
  echo "DORADUS_PRODUCTION_PORT_BASE must be a numeric host port" >&2
  exit 1
}

test -d "${go_root}"
mkdir -p "${scenario_root}"

declare -a candidates=()
if [[ -n "${DORADUS_SOURCE_DB:-}" ]]; then
  IFS=: read -r -a candidates <<<"${DORADUS_SOURCE_DB}"
else
  # Newer stopped production snapshots are prepared with Rust first, because
  # they can carry a migration ledger from a newer Go checkout while still
  # using the older dimension/value telemetry tables. The legacy v1 fixture is
  # detected below and automatically uses independent copies instead.
  candidates=(
    "${go_root}/tmp/state.db"
    "${go_root}/tmp/v2/state.db"
    "${go_root}/tmp/doradus/state.db"
    "${go_root}/tmp/aws/doradus/state.db"
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
  # pasta may retain a just-released forwarding namespace briefly. Give each
  # snapshot its own three-port window so one slow cleanup cannot make the
  # next independent Go/Rust comparison fail before it starts.
  prepare_http="${DORADUS_PREPARE_HTTP:-127.0.0.1:$((port_base + ran * 3))}"
  rust_http="${DORADUS_RUST_HTTP:-127.0.0.1:$((port_base + ran * 3 + 1))}"
  go_http="${DORADUS_GO_HTTP:-127.0.0.1:$((port_base + ran * 3 + 2))}"
  prepare_mode="${DORADUS_PREPARE:-1}"
  if [[ -z "${DORADUS_PREPARE+x}" ]] && command -v sqlite3 >/dev/null 2>&1; then
    # Go v1 snapshots have only legacy `nodes`/`inbounds` tables. Preparing
    # them with Rust first creates v2 projections that the current Go v1
    # migration path tries to create again. Run both services from independent
    # read-only copies for this old schema; newer snapshots retain the Rust-
    # first compatibility path above.
    has_v2_tables="$(sqlite3 "${source_db}" \
      "SELECT CASE WHEN EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='nodes_v2') THEN 1 ELSE 0 END;")"
    if [[ "${has_v2_tables}" != "1" ]]; then
      prepare_mode=0
      echo "[production-parity] detected legacy v1 schema; using independent copies"
    fi
  fi
  echo "[production-parity] checking ${source_db}"
  DORADUS_GO_DIR="${go_root}" \
  DORADUS_SOURCE_DB="${source_db}" \
  DORADUS_INTEGRATION_DIR="${scenario_dir}" \
  DORADUS_PREPARE_HTTP="${prepare_http}" \
  DORADUS_RUST_HTTP="${rust_http}" \
  DORADUS_GO_HTTP="${go_http}" \
  DORADUS_PREPARE="${prepare_mode}" \
    "${repo_root}/scripts/integration/go-api-parity.sh"
  ran=$((ran + 1))
done

if (( ran == 0 )); then
  echo "[production-parity] no fixture found; set DORADUS_SOURCE_DB to a stopped SQLite snapshot" >&2
  exit 0
fi
echo "[production-parity] passed ${ran} fixture(s); logs=${scenario_root}"
