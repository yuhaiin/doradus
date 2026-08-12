#!/usr/bin/env bash
set -euo pipefail

# Build a Rust target inside a disposable container.  Integration scripts may
# still discover the resulting binary from the shared cache, but no host cargo
# or rustc process is involved.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
state_dir="${YUHAIIN_PODMAN_BUILD_STATE:-${cache_root}/integration/podman-build}"
image="${YUHAIIN_BUILD_IMAGE:-docker.io/library/rust:latest}"

usage() {
  echo "usage: podman-cargo.sh [--target-dir DIR] [--state-dir DIR] [--image IMAGE] -- cargo ..." >&2
  exit 2
}

while (($#)); do
  case "$1" in
    --target-dir)
      (($# >= 2)) || usage
      target_dir="$2"
      shift 2
      ;;
    --state-dir)
      (($# >= 2)) || usage
      state_dir="$2"
      shift 2
      ;;
    --image)
      (($# >= 2)) || usage
      image="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    *)
      usage
      ;;
  esac
done

(($# > 0)) || usage
mkdir -p "${target_dir}" "${state_dir}"

podman run --rm --network=host \
  -v "${repo_root}:/workspace:ro" \
  -v "${target_dir}:/target:Z" \
  -v "${state_dir}:/state:Z" \
  -v "${HOME}/.cargo:/cargo-home:ro" \
  --entrypoint /bin/sh "${image}" \
  -ec '
    set -eu
    mkdir -p /state/home /state/cache/tmp
    export HOME=/state/home
    export CARGO_HOME=/cargo-home
    export CARGO_TARGET_DIR=/target
    export TMPDIR=/state/cache/tmp
    export CARGO_NET_OFFLINE=true
    cd /workspace
    exec "$@"
  ' -- "$@"
