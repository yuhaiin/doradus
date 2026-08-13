#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checklist="${repo_root}/IMPLEMENTATION_CHECKLIST.md"

read -r completed partial total < <(
  awk '
    /^## 模块状态/ { inside = 1; next }
    /^## Inbound \/ outbound/ { inside = 0 }
    inside && /\| `\[x\]` \|/ { completed++ }
    inside && /\| `\[~\]` \|/ { partial++ }
    END { printf "%d %d %d\n", completed, partial, completed + partial }
  ' "${checklist}"
)

declared_total="$(awk -F'|' '$2 ~ /纳入统计的模块验收项/ {gsub(/[[:space:]]/, "", $3); print $3; exit}' "${checklist}")"
declared_completed="$(awk -F'|' '$2 ~ /已完成/ {gsub(/[[:space:]]/, "", $3); print $3; exit}' "${checklist}")"
declared_partial="$(awk -F'|' '$2 ~ /主路径可用但仍有现场/ {gsub(/[[:space:]]/, "", $3); print $3; exit}' "${checklist}")"
declared_coverage="$(sed -n 's/^| 加权覆盖率 | \*\*\([0-9.]*\)%\*\*.*/\1/p' "${checklist}" | head -n 1)"
expected_coverage="$(awk -v completed="${completed}" -v partial="${partial}" -v total="${total}" 'BEGIN { printf "%.1f", (completed + partial * 0.5) * 100 / total }')"

if [[ "${declared_total}" != "${total}" ||
      "${declared_completed}" != "${completed}" ||
      "${declared_partial}" != "${partial}" ||
      "${declared_coverage}" != "${expected_coverage}" ]]; then
  printf 'checklist stats mismatch: table=%s/%s/%s %s%%, rows=%s/%s/%s %s%%\n' \
    "${declared_completed}" "${declared_partial}" "${declared_total}" "${declared_coverage}" \
    "${completed}" "${partial}" "${total}" "${expected_coverage}" >&2
  exit 1
fi

printf 'checklist stats: completed=%s partial=%s total=%s weighted=%s%%\n' \
  "${completed}" "${partial}" "${total}" "${expected_coverage}"
