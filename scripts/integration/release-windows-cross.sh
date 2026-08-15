#!/usr/bin/env bash
set -euo pipefail

# This is a source/cfg check for Windows from Linux.  The release workflow
# still builds MSVC artifacts on native Windows runners; GNU is used here
# because a Linux container can provide a reproducible MinGW linker.
#
# The cross check must be able to bootstrap a newly added locked dependency.
# GitHub's Rust cache is not guaranteed to contain the sparse-index entry and
# crate archive for every workspace feature, so this job deliberately uses a
# writable Cargo cache and lets `--locked` enforce dependency reproducibility.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
scenario_dir="${YUHAIIN_RELEASE_WINDOWS_DIR:-${cache_root}/integration/release-windows-cross}"
target_dir="${YUHAIIN_RELEASE_WINDOWS_TARGET_DIR:-${cache_root}/release-windows-target}"
cargo_home="${YUHAIIN_RELEASE_WINDOWS_CARGO_HOME:-${cache_root}/release-windows-cargo-home}"
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

mkdir -p "${scenario_dir}" "${target_dir}" "${cargo_home}"

podman run --rm --network=host \
  -v "${repo_root}:/workspace:ro" \
  -v "${scenario_dir}:/state:Z" \
  -v "${target_dir}:/target:Z" \
  -v "${cargo_home}:/cargo-home:Z" \
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
    # Do not let a runner-level Cargo setting or a persisted CARGO_HOME config
    # turn this online bootstrap into an unexplained sparse-index miss.
    # `--locked` still enforces the lockfile; the command-line config is the
    # highest-precedence Cargo setting and therefore also covers a reused cache
    # containing `net.offline = true`.
    unset CARGO_NET_OFFLINE

    apt-get update >/state/apt-update.log
    DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends "$mingw_package" \
      >/state/apt-install.log
    rustup target add "$target"
    target_env=$(printf "%s" "$target" | tr "[:lower:]-" "[:upper:]_")
    eval "export CARGO_TARGET_${target_env}_LINKER=$linker"
    eval "export CC_${target_env}=$linker"
    cd /workspace
    cargo check --config net.offline=false --locked --target "$target" \
      -p yuhaiin-api --bin yuhaiin --all-features \
      >/state/cargo-check.log 2>&1 || {
        echo "[release-windows-cross] cargo check failed; see /state/cargo-check.log" >&2
        cat /state/cargo-check.log >&2
        exit 1
      }
  ' -- "${target}" "${mingw_package}" "${linker}"

echo "[release-windows-cross] passed; target=${target} state=${scenario_dir}"
