#!/usr/bin/env bash
set -euo pipefail

# Build the Go compatibility binary in a disposable Go container.  The module
# and build caches are reusable, while scratch files remain under the project
# cache rather than the host /tmp.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${repo_root}/.cache/yuhaiin-rust}"
go_root="${YUHAIIN_GO_DIR:-$(cd "${repo_root}/../yuhaiin" && pwd)}"
cache_dir="${YUHAIIN_GO_CACHE_DIR:-${cache_root}/go-cache}"
state_dir="${YUHAIIN_PODMAN_GO_STATE:-${cache_root}/integration/podman-go-build}"
image="${YUHAIIN_GO_BUILD_IMAGE:-docker.io/library/golang:latest}"

usage() {
  echo "usage: podman-go.sh [--state-dir DIR] [--cache-dir DIR] [--image IMAGE] -- go build ..." >&2
  exit 2
}

while (($#)); do
  case "$1" in
    --state-dir)
      (($# >= 2)) || usage
      state_dir="$2"
      shift 2
      ;;
    --cache-dir)
      (($# >= 2)) || usage
      cache_dir="$2"
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
mkdir -p "${cache_dir}" "${state_dir}"

podman run --rm --network=host \
  -v "${go_root}:/go-src:ro" \
  -v "${state_dir}:/state:Z" \
  -v "${cache_dir}:/go-cache:Z" \
  --entrypoint /bin/sh "${image}" \
  -ec '
    set -eu
    mkdir -p /go-cache/build /go-cache/mod /state/go-tmp /state/cache/tmp
    export GOCACHE=/go-cache/build
    export GOMODCACHE=/go-cache/mod
    export GOTMPDIR=/state/go-tmp
    export TMPDIR=/state/cache/tmp
    cd /go-src
    exec "$@"
  ' -- "$@"
