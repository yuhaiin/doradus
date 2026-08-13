#!/usr/bin/env bash
set -euo pipefail

# This is a source/cfg check for Windows from Linux.  The release workflow
# still builds MSVC artifacts on native Windows runners; GNU is used here
# because a Linux container can provide a reproducible MinGW linker.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
scenario_dir="${YUHAIIN_RELEASE_WINDOWS_DIR:-${cache_root}/integration/release-windows-cross}"
target_dir="${YUHAIIN_RELEASE_WINDOWS_TARGET_DIR:-${cache_root}/release-windows-target}"
target="${YUHAIIN_RELEASE_WINDOWS_TARGET:-x86_64-pc-windows-gnu}"

case "${target}" in
  x86_64-pc-windows-gnu)
    mingw_package=gcc-mingw-w64-x86-64
    linker=x86_64-w64-mingw32-gcc
    ;;
  *)
    echo "unsupported Windows container target: ${target}" >&2
    echo "use x86_64-pc-windows-gnu; MSVC release targets run on native Windows CI" >&2
    exit 2
    ;;
esac

mkdir -p "${scenario_dir}" "${target_dir}"

podman run --rm --network=host \
  -v "${repo_root}:/workspace:ro" \
  -v "${scenario_dir}:/state:Z" \
  -v "${target_dir}:/target:Z" \
  -v "${HOME}/.cargo:/cargo-home:ro" \
  docker.io/library/rust:latest sh -ec '
    set -eu
    target="$1"
    mingw_package="$2"
    linker="$3"
    mkdir -p /state/home /state/cache/tmp
    export HOME=/state/home
    export CARGO_HOME=/cargo-home
    export CARGO_TARGET_DIR=/target
    export TMPDIR=/state/cache/tmp

    apt-get update >/state/apt-update.log
    DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends "$mingw_package" \
      >/state/apt-install.log
    rustup target add "$target"
    export CARGO_NET_OFFLINE=true
    target_env=$(printf "%s" "$target" | tr "[:lower:]-" "[:upper:]_")
    eval "export CARGO_TARGET_${target_env}_LINKER=$linker"
    eval "export CC_${target_env}=$linker"
    cd /workspace
    cargo check --locked --target "$target" -p yuhaiin-runtime --bin yuhaiin --all-features
  ' -- "${target}" "${mingw_package}" "${linker}"

echo "[release-windows-cross] passed; target=${target} state=${scenario_dir}"
