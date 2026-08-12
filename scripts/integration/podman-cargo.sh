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
  echo "usage: podman-cargo.sh [--target-dir DIR] [--state-dir DIR] [--image IMAGE] [--env KEY=VALUE] [--install-target TARGET] [--install-component COMPONENT] [--install-musl-toolchain] -- cargo ..." >&2
  exit 2
}

podman_env_args=()
install_target=""
install_musl_toolchain=0
install_component=""

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
    --env)
      (($# >= 2)) || usage
      [[ "$2" == *=* ]] || usage
      podman_env_args+=(--env "$2")
      shift 2
      ;;
    --install-target)
      (($# >= 2)) || usage
      install_target="$2"
      shift 2
      ;;
    --install-musl-toolchain)
      install_musl_toolchain=1
      shift
      ;;
    --install-component)
      (($# >= 2)) || usage
      install_component="$2"
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
  "${podman_env_args[@]}" \
  -v "${repo_root}:/workspace:ro" \
  -v "${target_dir}:/target:Z" \
  -v "${state_dir}:/state:Z" \
  -v "${HOME}/.cargo:/cargo-home:ro" \
  --entrypoint /bin/sh "${image}" \
  -ec '
    set -eu
    install_musl_toolchain="$1"
    install_target="$2"
    install_component="$3"
    shift 3
    mkdir -p /state/home /state/cache/tmp
    export HOME=/state/home
    export CARGO_HOME=/cargo-home
    export CARGO_TARGET_DIR=/target
    export TMPDIR=/state/cache/tmp
    export CARGO_NET_OFFLINE=true
    cd /workspace
    if [ "$install_musl_toolchain" = 1 ] && ! command -v x86_64-linux-musl-gcc >/dev/null 2>&1; then
      command -v apt-get >/dev/null 2>&1 || {
        echo "musl toolchain requested but apt-get is unavailable" >&2
        exit 1
      }
      apt-get update
      apt-get install --yes --no-install-recommends musl-tools
    fi
    if [ -n "$install_target" ] && ! rustup target list --installed | grep -Fxq "$install_target"; then
      rustup target add "$install_target"
    fi
    if [ -n "$install_component" ] && ! rustup component list --installed | grep -Eq "^${install_component}(-| )"; then
      rustup component add "$install_component"
    fi
    exec "$@"
  ' -- "${install_musl_toolchain}" "${install_target}" "${install_component}" "$@"
