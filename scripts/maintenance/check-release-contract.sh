#!/usr/bin/env bash
set -euo pipefail

# Validate the release workflow's public artifact contract without contacting
# GitHub. This is deliberately a structural check: the remote runner still
# owns the native macOS/Windows compile and permission boundary.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workflow="${repo_root}/.github/workflows/rust.yml"

test -f "${workflow}"

matrix_entry_exists() {
  local platform="$1"
  local arch="$2"
  local target="$3"
  local runner="$4"

  awk -v expected_platform="${platform}" \
      -v expected_arch="${arch}" \
      -v expected_target="${target}" \
      -v expected_runner="${runner}" '
    /^          - platform:/ {
      platform = $3
      arch = ""
      target = ""
      runner = ""
    }
    /^            arch:/ { arch = $2 }
    /^            target:/ { target = $2 }
    /^            runner:/ {
      runner = $2
      if (platform == expected_platform && arch == expected_arch &&
          target == expected_target && runner == expected_runner) {
        found = 1
      }
    }
    END { exit(found ? 0 : 1) }
  ' "${workflow}"
}

for entry in \
  "linux amd64 x86_64-unknown-linux-musl ubuntu-latest" \
  "linux arm64 aarch64-unknown-linux-musl ubuntu-latest" \
  "darwin amd64 x86_64-apple-darwin macos-14" \
  "darwin arm64 aarch64-apple-darwin macos-14" \
  "windows amd64 x86_64-pc-windows-msvc windows-latest" \
  "windows arm64 aarch64-pc-windows-msvc windows-latest"; do
  # shellcheck disable=SC2086
  matrix_entry_exists ${entry}
done

required_literals=(
  'fail-fast: false'
  'needs: checks'
  'cargo build --locked --release --target'
  'matrix.target'
  '-p yuhaiin-runtime --bin yuhaiin --all-features'
  'actions/upload-artifact@v7'
  'actions/download-artifact@v7'
  'sha256sum -- * | sort -k2'
  ') > release/checksums.txt'
  'github.ref_type == '\''tag'\'' || (github.ref_type == '\''branch'\'' && github.ref_name == '\''main'\'')'
  'git push origin refs/tags/main --force'
  'files: |'
  'release/*'
  'release_notes.txt'
)

for literal in "${required_literals[@]}"; do
  if ! grep -Fq -- "${literal}" "${workflow}"; then
    echo "[release-contract] missing workflow literal: ${literal}" >&2
    exit 1
  fi
done

if grep -Fq -- $'            checksums.txt' "${workflow}"; then
  echo "[release-contract] checksum must be published from release/checksums.txt" >&2
  exit 1
fi

for artifact in \
  yuhaiin-linux-amd64 \
  yuhaiin-linux-arm64 \
  yuhaiin-darwin-amd64 \
  yuhaiin-darwin-arm64 \
  yuhaiin-windows-amd64.exe \
  yuhaiin-windows-arm64.exe; do
  if ! grep -Fq -- "${artifact}" "${workflow}"; then
    echo "[release-contract] missing release artifact: ${artifact}" >&2
    exit 1
  fi
done

echo "[release-contract] passed: six native targets, checks gate, artifact assembly, checksums, and rolling-main publication are covered"
