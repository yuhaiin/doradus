#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
scenario_dir="${YUHAIIN_TRANSPARENT_DIR:-${cache_root}/integration/transparent-service}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
binary="${target_dir}/debug/transparent-service-smoke"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
target_addr="${YUHAIIN_TARGET_ADDR:-127.0.0.2:18080}"
redir_addr="${YUHAIIN_REDIR_ADDR:-127.0.0.1:18081}"
state_dir="${scenario_dir}/state"
runtime_log="${state_dir}/runtime.log"
client_log="${state_dir}/client.log"

xtables_multi="${YUHAIIN_XTABLES_MULTI:-$(command -v xtables-nft-multi || true)}"
host_loader="${YUHAIIN_LD_LINUX:-/usr/lib64/ld-linux-x86-64.so.2}"
if [[ ! -x "${xtables_multi}" || ! -x "${host_loader}" ]]; then
  echo "transparent smoke requires host xtables-nft-multi and glibc loader" >&2
  echo "set YUHAIIN_XTABLES_MULTI and YUHAIIN_LD_LINUX to override their paths" >&2
  exit 1
fi

mkdir -p "${state_dir}"
rm -f "${runtime_log}" "${client_log}" "${state_dir}/client.done" "${state_dir}/iptables"

cd "${repo_dir}"
cargo build \
  --target-dir "${target_dir}" \
  -p yuhaiin-runtime \
  --bin transparent-service-smoke \
  --all-features \
  --offline \
  >"${scenario_dir}/build.log"
test -x "${binary}"
chmod 755 "${binary}"

target_ip="${target_addr%:*}"
target_port="${target_addr##*:}"
redir_port="${redir_addr##*:}"

echo "[transparent-service] running isolated REDIRECT TCP smoke in Podman"
podman run --rm --privileged --network=none \
  -v "${binary}:/usr/local/bin/transparent-service-smoke:ro" \
  -v "${state_dir}:/state:Z" \
  -v "${xtables_multi}:/host/xtables-nft-multi:ro" \
  -v /usr/lib:/host/usr/lib:ro \
  -v /usr/lib64:/host/usr/lib64:ro \
  -e YUHAIIN_DB=/state/state.sqlite \
  -e YUHAIIN_TARGET_ADDR="${target_addr}" \
  -e YUHAIIN_REDIR_ADDR="${redir_addr}" \
  -e YUHAIIN_CLIENT_DONE=/state/client.done \
  -e YUHAIIN_TARGET_IP="${target_ip}" \
  -e YUHAIIN_TARGET_PORT="${target_port}" \
  -e YUHAIIN_REDIR_PORT="${redir_port}" \
  -e YUHAIIN_HOST_LOADER="/host${host_loader}" \
  --entrypoint /bin/sh \
  "${image}" \
  -ceu '
    ln -sf /host/xtables-nft-multi /state/iptables
    run_iptables() {
      XTABLES_LIBDIR=/host/usr/lib/xtables \
        "$YUHAIIN_HOST_LOADER" \
        --library-path /host/usr/lib/x86_64-linux-gnu:/host/usr/lib:/host/usr/lib64 \
        /state/iptables "$@"
    }

    rule_installed=0
    cleanup() {
      if [ "$rule_installed" -eq 1 ]; then
        run_iptables -t nat -D OUTPUT -d "${YUHAIIN_TARGET_IP}/32" -p tcp \
          -m tcp --dport "${YUHAIIN_TARGET_PORT}" -m owner --uid-owner 65534 \
          -j REDIRECT --to-ports "${YUHAIIN_REDIR_PORT}" || true
      fi
    }
    trap cleanup EXIT INT TERM

    /usr/local/bin/transparent-service-smoke --tproxy-probe \
      >/state/tproxy.log 2>&1
    /usr/local/bin/transparent-service-smoke >/state/runtime.log 2>&1 &
    service_pid=$!
    run_iptables -t nat -A OUTPUT -d "${YUHAIIN_TARGET_IP}/32" -p tcp \
      -m tcp --dport "${YUHAIIN_TARGET_PORT}" -m owner --uid-owner 65534 \
      -j REDIRECT --to-ports "${YUHAIIN_REDIR_PORT}"
    rule_installed=1

    if ! runuser -u nobody -- /usr/local/bin/transparent-service-smoke --client \
      >/state/client.log 2>&1; then
      cat /state/runtime.log /state/client.log >&2
      exit 1
    fi
    touch /state/client.done
    wait "$service_pid"
    cat /state/tproxy.log /state/runtime.log /state/client.log
  '

grep -Fq "transparent-ready" "${runtime_log}"
grep -Fq "transparent-redir-tcp-ok" "${runtime_log}"
grep -Fq "transparent-closed" "${runtime_log}"
grep -Fq "transparent-client-ok" "${client_log}"
grep -Fq "transparent-tproxy-socket-ok" "${state_dir}/tproxy.log"
echo "[transparent-service] passed; logs=${scenario_dir}"
