#!/usr/bin/env bash
set -euo pipefail

# Check the public Go v2 route inventory against the Rust API boundary. This
# is intentionally source-level: it catches a forgotten frontend operation
# before a fixture or a running service happens to exercise it.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
go_root="${DORADUS_GO_DIR:-$(cd "${repo_root}/../yuhaiin" 2>/dev/null && pwd || true)}"
go_routes="${go_root}/pkg/httpapi/v2_routes.go"
rust_api="${repo_root}/crates/doradus-api/src/api.rs"

if [[ ! -f "${go_routes}" ]]; then
  echo "[api-route-parity] Go route source is unavailable: ${go_routes}" >&2
  echo "[api-route-parity] set DORADUS_GO_DIR to the Go checkout; skipped (77)" >&2
  exit 77
fi
test -f "${rust_api}"

go_operations="$(sed -nE \
  's/^[[:space:]]*v2[A-Za-z0-9_]+[[:space:]]+v2Endpoint[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
  "${go_routes}" | sort -u)"
rpc_source="$(sed -n '/^async fn rpc(/,/^}$/p' "${rust_api}")"

test -n "${go_operations}"
test -n "${rpc_source}"

missing=0
go_count=0
while IFS= read -r operation; do
  [[ -n "${operation}" ]] || continue
  go_count=$((go_count + 1))
  case "${operation}" in
    tools.logs)
      path='/api/v2/tools/logs'
      ;;
    tools.logs.v2)
      path='/api/v2/tools/logs/v2'
      ;;
    connections.events)
      path='/api/v2/connections/events'
      ;;
    *)
      if ! grep -Fq '"'"${operation}"'"' <<<"${rpc_source}"; then
        echo "[api-route-parity] missing Rust RPC operation: ${operation}" >&2
        missing=$((missing + 1))
      fi
      continue
      ;;
  esac

  if ! grep -Fq '"'"${path}"'"' "${rust_api}"; then
    echo "[api-route-parity] missing Rust direct route: ${operation} -> ${path}" >&2
    missing=$((missing + 1))
  fi
done <<<"${go_operations}"

if (( missing != 0 )); then
  echo "[api-route-parity] failed: ${missing} missing route(s) across ${go_count} Go operations" >&2
  exit 1
fi

echo "[api-route-parity] passed: ${go_count} Go v2 operations are covered by Rust RPC or direct routes"
