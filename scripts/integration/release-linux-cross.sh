#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
scenario_dir="${YUHAIIN_RELEASE_LINUX_DIR:-${cache_root}/integration/release-linux-cross}"
target_dir="${YUHAIIN_RELEASE_LINUX_TARGET_DIR:-${cache_root}/release-linux-target}"
cargo_home="${YUHAIIN_RELEASE_LINUX_CARGO_HOME:-${cache_root}/release-linux-cargo-home}"
target="${YUHAIIN_RELEASE_LINUX_TARGET:-aarch64-unknown-linux-musl}"

case "${target}" in
  x86_64-unknown-linux-musl)
    sha256="5f20e367608d6e547c04534d37d00ecedbaa0c2e82730df12957b3332fa36a2d"
    ;;
  aarch64-unknown-linux-musl)
    sha256="90282c463498dcdab9b96a464a0925d53f30c884b2d7b25e3998999416ae34b8"
    ;;
  *)
    echo "unsupported Linux release target: ${target}" >&2
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
    sha256="$2"
    mkdir -p /state/home /state/cache/tmp /state/toolchain
    export HOME=/state/home
    export CARGO_HOME=/cargo-home
    export CARGO_TARGET_DIR=/target
    export TMPDIR=/state/cache/tmp
    unset CARGO_NET_OFFLINE

    archive="/state/${target}.tar.xz"
    url="https://github.com/cross-tools/musl-cross/releases/download/20260515/${target}.tar.xz"
    if test ! -f "${archive}"; then
      curl --fail --location --retry 3 --output "${archive}" "${url}"
    fi
    printf "%s  %s\\n" "${sha256}" "${archive}" | sha256sum --check

    toolchain_root="/state/toolchain/${target}"
    if test ! -x "${toolchain_root}/bin/${target}-gcc"; then
      rm -rf "${toolchain_root}"
      mkdir -p "${toolchain_root}"
      tar --extract --xz --file "${archive}" --strip-components=1 --directory "${toolchain_root}"
    fi
    test -x "${toolchain_root}/bin/${target}-gcc"
    rustup target add "${target}"

    export PATH="${toolchain_root}/bin:${PATH}"
    target_env=$(printf "%s" "${target}" | tr "[:lower:]-" "[:upper:]_")
    eval "export CARGO_TARGET_${target_env}_LINKER=${toolchain_root}/bin/${target}-gcc"
    eval "export CC_${target_env}=${toolchain_root}/bin/${target}-gcc"
    eval "export AR_${target_env}=${toolchain_root}/bin/${target}-ar"
    cd /workspace
    cargo check --config net.offline=false --locked --target "${target}" \
      -p yuhaiin-api --bin yuhaiin --all-features
  ' -- "${target}" "${sha256}"

echo "[release-linux-cross] passed; target=${target} state=${scenario_dir}"
