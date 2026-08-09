#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
scenario_dir="${YUHAIIN_TRANSPARENT_DIR:-${cache_root}/integration/transparent-service}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
binary="${target_dir}/debug/transparent-service-smoke"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
service_ip="${YUHAIIN_TRANSPARENT_SERVICE_IP:-10.253.0.2}"
client_ip="${YUHAIIN_TRANSPARENT_CLIENT_IP:-10.253.0.3}"
target_addr="${YUHAIIN_TARGET_ADDR:-${service_ip}:18080}"
udp_target_addr="${YUHAIIN_UDP_TARGET_ADDR:-10.254.1.2:18082}"
redir_addr="${YUHAIIN_REDIR_ADDR:-0.0.0.0:18081}"
tproxy_addr="${YUHAIIN_TPROXY_ADDR:-${service_ip}:18083}"
main_container="${YUHAIIN_TRANSPARENT_CONTAINER:-yuhaiin-transparent-${BASHPID}}"
state_dir="${scenario_dir}/state"
runtime_log="${state_dir}/runtime.log"
client_log="${state_dir}/client.log"
udp_client_log="${state_dir}/udp-client.log"

xtables_multi="${YUHAIIN_XTABLES_MULTI:-$(command -v xtables-nft-multi || true)}"
host_loader="${YUHAIIN_LD_LINUX:-/usr/lib64/ld-linux-x86-64.so.2}"
host_ip="${YUHAIIN_IP:-$(command -v ip || true)}"
if [[ ! -x "${xtables_multi}" || ! -x "${host_loader}" || ! -x "${host_ip}" ]]; then
  echo "transparent smoke requires host xtables-nft-multi, ip and glibc loader" >&2
  echo "set YUHAIIN_XTABLES_MULTI, YUHAIIN_IP and YUHAIIN_LD_LINUX to override their paths" >&2
  exit 1
fi

mkdir -p "${state_dir}"
rm -f "${runtime_log}" "${client_log}" "${udp_client_log}" \
  "${state_dir}/udp-target.log" "${state_dir}/tproxy.log" \
  "${state_dir}/client.done" "${state_dir}/udp-client.done" \
  "${state_dir}/iptables" "${state_dir}/state.sqlite" \
  "${state_dir}/state.sqlite-wal" "${state_dir}/state.sqlite-shm"

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
udp_target_ip="${udp_target_addr%:*}"
udp_target_port="${udp_target_addr##*:}"
redir_port="${redir_addr##*:}"
tproxy_port="${tproxy_addr##*:}"

tproxy_mode="${YUHAIIN_TPROXY_ENABLED:-auto}"
if [[ "${tproxy_mode}" == "auto" ]]; then
  podman_rootless="$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || echo true)"
  if [[ "${podman_rootless}" == "true" ]]; then
    tproxy_enabled=0
  else
    tproxy_enabled=1
  fi
else
  tproxy_enabled="${tproxy_mode}"
fi
if [[ "${tproxy_enabled}" != 0 && "${tproxy_enabled}" != 1 ]]; then
  echo "YUHAIIN_TPROXY_ENABLED must be 0, 1, or auto" >&2
  exit 1
fi

echo "[transparent-service] running isolated REDIRECT TCP + TPROXY UDP smoke in Podman"
if [[ "${tproxy_enabled}" -eq 0 ]]; then
  echo "[transparent-service] TPROXY UDP skipped: rootless Podman; set YUHAIIN_TPROXY_ENABLED=1 to require it"
fi
cleanup_main() {
  podman rm -f "${main_container}" >/dev/null 2>&1 || true
}
trap cleanup_main EXIT INT TERM
podman run --rm --privileged --name "${main_container}" --network=none \
  -v "${binary}:/usr/local/bin/transparent-service-smoke:ro" \
  -v "${state_dir}:/state:Z" \
  -v "${xtables_multi}:/host/xtables-nft-multi:ro" \
  -v "${host_ip}:/host/ip:ro" \
  -v /usr/bin/nsenter:/host/nsenter:ro \
  -v /usr/bin/unshare:/host/unshare:ro \
  -v /usr/lib:/host/usr/lib:ro \
  -v /usr/lib64:/host/usr/lib64:ro \
  -e YUHAIIN_DB=/state/state.sqlite \
  -e YUHAIIN_TARGET_ADDR="${target_addr}" \
  -e YUHAIIN_UDP_TARGET_ADDR="${udp_target_addr}" \
  -e YUHAIIN_REDIR_ADDR="${redir_addr}" \
  -e YUHAIIN_TPROXY_ADDR="${tproxy_addr}" \
  -e YUHAIIN_CLIENT_DONE=/state/client.done \
  -e YUHAIIN_UDP_CLIENT_DONE=/state/udp-client.done \
  -e YUHAIIN_TARGET_IP="${target_ip}" \
  -e YUHAIIN_TARGET_PORT="${target_port}" \
  -e YUHAIIN_UDP_TARGET_IP="${udp_target_ip}" \
  -e YUHAIIN_UDP_TARGET_PORT="${udp_target_port}" \
  -e YUHAIIN_REDIR_PORT="${redir_port}" \
  -e YUHAIIN_TPROXY_PORT="${tproxy_port}" \
  -e YUHAIIN_CLIENT_IP="${client_ip}" \
  -e YUHAIIN_SERVICE_IP="${service_ip}" \
  -e YUHAIIN_TPROXY_ENABLED="${tproxy_enabled}" \
  -e YUHAIIN_HOST_NSENTER="/host/nsenter" \
  -e YUHAIIN_HOST_UNSHARE="/host/unshare" \
  -e YUHAIIN_HOST_LOADER="/host${host_loader}" \
  --entrypoint /bin/sh \
  "${image}" \
  -ceu '
    ln -sf /host/xtables-nft-multi /state/iptables
    ln -sf /host/ip /state/ip
    run_iptables() {
      XTABLES_LIBDIR=/host/usr/lib/xtables \
        "$YUHAIIN_HOST_LOADER" \
        --library-path /host/usr/lib/x86_64-linux-gnu:/host/usr/lib:/host/usr/lib64 \
        /state/iptables "$@"
    }
    run_ip() {
      "$YUHAIIN_HOST_LOADER" \
        --library-path /host/usr/lib/x86_64-linux-gnu:/host/usr/lib:/host/usr/lib64 \
        /state/ip "$@"
    }
    run_ns_ip() {
      ns_pid="$1"
      shift
      "$YUHAIIN_HOST_NSENTER" -t "$ns_pid" -n "$YUHAIIN_HOST_LOADER" \
        --library-path /host/usr/lib/x86_64-linux-gnu:/host/usr/lib:/host/usr/lib64 \
        /state/ip "$@"
    }
    run_ns() {
      ns_pid="$1"
      shift
      "$YUHAIIN_HOST_NSENTER" -t "$ns_pid" -n "$@"
    }

    client_ns_pid=0
    target_ns_pid=0
    target_pid=0
    run_ip link set lo up
    "$YUHAIIN_HOST_UNSHARE" -n --fork /bin/sh -c "exec sleep 300" &
    client_ns_pid=$!
    if [ "$YUHAIIN_TPROXY_ENABLED" -eq 1 ]; then
      "$YUHAIIN_HOST_UNSHARE" -n --fork /bin/sh -c "exec sleep 300" &
      target_ns_pid=$!
    fi

    run_ip link add service-client type veth peer name client0
    run_ip link set client0 netns "$client_ns_pid"
    run_ip addr add "${YUHAIIN_SERVICE_IP}/24" dev service-client
    run_ip link set service-client up
    run_ns_ip "$client_ns_pid" link set lo up
    run_ns_ip "$client_ns_pid" addr add "${YUHAIIN_CLIENT_IP}/24" dev client0
    run_ns_ip "$client_ns_pid" link set client0 up
    run_ns_ip "$client_ns_pid" route add "${YUHAIIN_UDP_TARGET_IP}/32" via "${YUHAIIN_SERVICE_IP}"

    if [ "$YUHAIIN_TPROXY_ENABLED" -eq 1 ]; then
      run_ip link add service-target type veth peer name target0
      run_ip link set target0 netns "$target_ns_pid"
      run_ip addr add 10.254.1.1/24 dev service-target
      run_ip link set service-target up
      run_ns_ip "$target_ns_pid" link set lo up
      run_ns_ip "$target_ns_pid" addr add "${YUHAIIN_UDP_TARGET_IP}/24" dev target0
      run_ns_ip "$target_ns_pid" link set target0 up
      run_ns_ip "$target_ns_pid" route add "${YUHAIIN_SERVICE_IP%.*}.0/24" via 10.254.1.1
    fi

    echo 0 >/proc/sys/net/ipv4/conf/all/rp_filter || true
    echo 0 >/proc/sys/net/ipv4/conf/service-client/rp_filter || true
    if [ "$YUHAIIN_TPROXY_ENABLED" -eq 1 ]; then
      echo 0 >/proc/sys/net/ipv4/conf/service-target/rp_filter || true
    fi
    echo 1 >/proc/sys/net/ipv4/conf/all/src_valid_mark || true
    echo 1 >/proc/sys/net/ipv4/conf/service-client/src_valid_mark || true

    if [ "$YUHAIIN_TPROXY_ENABLED" -eq 1 ]; then
      run_ns "$target_ns_pid" env \
        YUHAIIN_UDP_TARGET_ADDR="${YUHAIIN_UDP_TARGET_ADDR}" \
        /usr/local/bin/transparent-service-smoke --udp-target \
        >/state/udp-target.log 2>&1 &
      target_pid=$!
    fi

    rule_installed=0
    tproxy_rule_installed=0
    route_installed=0
    cleanup() {
      if [ "$target_pid" -ne 0 ]; then kill "$target_pid" 2>/dev/null || true; fi
      if [ "$rule_installed" -eq 1 ]; then
        run_iptables -t nat -D PREROUTING -s "${YUHAIIN_CLIENT_IP}/32" \
          -d "${YUHAIIN_SERVICE_IP}/32" -p tcp \
          -m tcp --dport "${YUHAIIN_TARGET_PORT}" \
          -j REDIRECT --to-ports "${YUHAIIN_REDIR_PORT}" || true
      fi
      if [ "$tproxy_rule_installed" -eq 1 ]; then
        run_iptables -t mangle -D PREROUTING -s "${YUHAIIN_CLIENT_IP}/32" \
          -d "${YUHAIIN_UDP_TARGET_IP}/32" -p udp \
          -m udp --dport "${YUHAIIN_UDP_TARGET_PORT}" \
          -j TPROXY --on-port "${YUHAIIN_TPROXY_PORT}" \
          --tproxy-mark 1/1 || true
      fi
      if [ "$route_installed" -eq 1 ]; then
        run_ip route del local 0.0.0.0/0 dev lo table 100 || true
        run_ip rule del fwmark 1 table 100 || true
      fi
      if [ "$client_ns_pid" -ne 0 ]; then kill "$client_ns_pid" 2>/dev/null || true; fi
      if [ "$target_ns_pid" -ne 0 ]; then kill "$target_ns_pid" 2>/dev/null || true; fi
    }
    trap cleanup EXIT INT TERM

    if [ "$YUHAIIN_TPROXY_ENABLED" -eq 1 ]; then
      /usr/local/bin/transparent-service-smoke --tproxy-probe \
        >/state/tproxy.log 2>&1
    else
      echo "transparent-tproxy-socket-skipped reason=rootless-podman" >/state/tproxy.log
    fi
    /usr/local/bin/transparent-service-smoke >/state/runtime.log 2>&1 &
    service_pid=$!
    run_iptables -t nat -A PREROUTING -s "${YUHAIIN_CLIENT_IP}/32" \
      -d "${YUHAIIN_SERVICE_IP}/32" -p tcp \
      -m tcp --dport "${YUHAIIN_TARGET_PORT}" \
      -j REDIRECT --to-ports "${YUHAIIN_REDIR_PORT}"
    rule_installed=1

    if [ "$YUHAIIN_TPROXY_ENABLED" -eq 1 ]; then
      run_ip rule add fwmark 1 table 100
      run_ip route add local 0.0.0.0/0 dev lo table 100
      route_installed=1
      run_iptables -t mangle -A PREROUTING -s "${YUHAIIN_CLIENT_IP}/32" \
        -d "${YUHAIIN_UDP_TARGET_IP}/32" -p udp \
        -m udp --dport "${YUHAIIN_UDP_TARGET_PORT}" \
        -j TPROXY --on-port "${YUHAIIN_TPROXY_PORT}" \
        --tproxy-mark 1/1
      tproxy_rule_installed=1
    fi

    for _ in $(seq 1 100); do
      if grep -Fq "transparent-ready" /state/runtime.log 2>/dev/null; then
        if [ "$YUHAIIN_TPROXY_ENABLED" -eq 0 ] \
          || grep -Fq "transparent-udp-target-ready" /state/udp-target.log 2>/dev/null; then
          break
        fi
      fi
      sleep 0.1
    done

    if [ "$YUHAIIN_TPROXY_ENABLED" -eq 1 ] \
      && ! grep -Fq "transparent-udp-target-ready" /state/udp-target.log 2>/dev/null; then
      echo "transparent UDP target did not start" >&2
      exit 1
    fi

    if ! run_ns "$client_ns_pid" env \
      YUHAIIN_TARGET_ADDR="${YUHAIIN_TARGET_ADDR}" \
      /usr/sbin/runuser -u nobody -- /usr/local/bin/transparent-service-smoke --client \
      >/state/client.log 2>&1; then
      cat /state/client.log >&2
      exit 1
    fi
    touch /state/client.done

    if [ "$YUHAIIN_TPROXY_ENABLED" -eq 1 ]; then
      if ! run_ns "$client_ns_pid" env \
        YUHAIIN_UDP_TARGET_ADDR="${YUHAIIN_UDP_TARGET_ADDR}" \
        /usr/sbin/runuser -u nobody -- /usr/local/bin/transparent-service-smoke --udp-client \
        >/state/udp-client.log 2>&1; then
        cat /state/udp-client.log >&2
        touch /state/udp-client.done
        wait "$service_pid" || true
        run_ip rule show >&2
        run_ip route show table 100 >&2
        run_iptables -t mangle -L PREROUTING -v -n >&2
        cat /state/tproxy.log /state/runtime.log >&2
        exit 1
      fi
      touch /state/udp-client.done
    fi

    service_status=0
    wait "$service_pid" || service_status=$?
    exit "$service_status"
  ' >"${scenario_dir}/container.log" 2>&1 &
main_pid=$!
if wait "${main_pid}"; then
  main_status=0
else
  main_status=$?
fi
for log_file in "${scenario_dir}/container.log" "${runtime_log}" "${client_log}" "${udp_client_log}"; do
  if [[ -f "${log_file}" ]]; then
    cat "${log_file}"
  fi
done

if [[ "${main_status}" -ne 0 ]]; then
  exit "${main_status}"
fi

grep -Fq "transparent-ready" "${runtime_log}"
grep -Fq "transparent-redir-tcp-ok" "${runtime_log}"
grep -Fq "transparent-closed" "${runtime_log}"
grep -Fq "transparent-client-ok" "${client_log}"
if [[ "${tproxy_enabled}" -eq 1 ]]; then
  grep -Fq "transparent-udp-client-ok" "${udp_client_log}"
  grep -Fq "transparent-tproxy-udp-ok" "${runtime_log}"
  grep -Fq "transparent-tproxy-socket-ok" "${state_dir}/tproxy.log"
else
  grep -Fq "transparent-tproxy-udp-skipped" "${runtime_log}"
  grep -Fq "transparent-tproxy-socket-skipped" "${state_dir}/tproxy.log"
fi
echo "[transparent-service] passed; logs=${scenario_dir}"
