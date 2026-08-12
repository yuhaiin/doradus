#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cache_root="${YUHAIIN_CACHE_DIR:-${HOME}/.cache/yuhaiin-rust}"
scenario_dir="${YUHAIIN_TRANSPARENT_DIR:-${cache_root}/integration/transparent-service}"
target_dir="${CARGO_TARGET_DIR:-${cache_root}/cargo-target}"
binary="${YUHAIIN_TRANSPARENT_BINARY:-${target_dir}/debug/transparent-service-smoke}"
image="${YUHAIIN_TEST_IMAGE:-docker.io/library/debian:testing}"
network_mode="${YUHAIIN_TRANSPARENT_NETWORK:-none}"
service_ip="${YUHAIIN_TRANSPARENT_SERVICE_IP:-10.253.0.2}"
client_ip="${YUHAIIN_TRANSPARENT_CLIENT_IP:-10.253.0.3}"
service_ipv6="${YUHAIIN_TRANSPARENT_SERVICE_IPV6:-fd00:253::2}"
client_ipv6="${YUHAIIN_TRANSPARENT_CLIENT_IPV6:-fd00:253::3}"
target_v6_addr="${YUHAIIN_TARGET_V6_ADDR:-[fd00:253::2]:18084}"
redir_v6_addr="${YUHAIIN_REDIR_V6_ADDR:-[::]:18085}"
target_addr="${YUHAIIN_TARGET_ADDR:-${service_ip}:18080}"
udp_target_addr="${YUHAIIN_UDP_TARGET_ADDR:-10.254.1.2:18082}"
redir_addr="${YUHAIIN_REDIR_ADDR:-0.0.0.0:18081}"
# A TPROXY UDP socket must be wildcard-bound: packets retain their original
# destination, so binding only to the service veth address would not match the
# kernel's transparent socket lookup for 10.254.1.2:18082.
tproxy_addr="${YUHAIIN_TPROXY_ADDR:-0.0.0.0:18083}"
tproxy_kernel_mode="${YUHAIIN_TPROXY_MODE:-tproxy}"
tproxy_backend="${YUHAIIN_TPROXY_BACKEND:-iptables}"
main_container="${YUHAIIN_TRANSPARENT_CONTAINER:-yuhaiin-transparent-${BASHPID}}"
state_dir="${scenario_dir}/state"
runtime_log="${state_dir}/runtime.log"
client_log="${state_dir}/client.log"
udp_client_log="${state_dir}/udp-client.log"
ipv6_client_log="${state_dir}/ipv6-client.log"

ipv6_mode="${YUHAIIN_TRANSPARENT_IPV6:-0}"
if [[ "${ipv6_mode}" != 0 && "${ipv6_mode}" != 1 ]]; then
  echo "YUHAIIN_TRANSPARENT_IPV6 must be 0 or 1" >&2
  exit 1
fi

xtables_multi="${YUHAIIN_XTABLES_MULTI:-$(command -v xtables-nft-multi || true)}"
xtables_libdir="${YUHAIIN_XTABLES_LIBDIR:-}"
if [[ -z "${xtables_libdir}" ]]; then
  for candidate in /usr/lib/xtables /usr/lib/*/xtables; do
    if [[ -f "${candidate}/libxt_tcp.so" && -f "${candidate}/libxt_TPROXY.so" ]]; then
      xtables_libdir="${candidate}"
      break
    fi
  done
fi
host_loader="${YUHAIIN_LD_LINUX:-/usr/lib64/ld-linux-x86-64.so.2}"
host_ip="${YUHAIIN_IP:-$(command -v ip || true)}"
host_nft="${YUHAIIN_NFT:-$(command -v nft || true)}"
if [[ ! -x "${xtables_multi}" || ! -d "${xtables_libdir}" || ! -x "${host_loader}" || ! -x "${host_ip}" ]]; then
  echo "transparent smoke requires host xtables-nft-multi, xtables modules, ip and glibc loader" >&2
  echo "set YUHAIIN_XTABLES_MULTI, YUHAIIN_XTABLES_LIBDIR, YUHAIIN_IP and YUHAIIN_LD_LINUX to override their paths" >&2
  exit 1
fi
if [[ "${tproxy_backend}" != "iptables" && "${tproxy_backend}" != "nft" ]]; then
  echo "YUHAIIN_TPROXY_BACKEND must be iptables or nft" >&2
  exit 1
fi
if [[ "${tproxy_backend}" == "nft" && ! -x "${host_nft}" ]]; then
  echo "native nft TPROXY smoke requires nft; set YUHAIIN_NFT to override its path" >&2
  exit 1
fi

mkdir -p "${state_dir}"
rm -f "${runtime_log}" "${client_log}" "${udp_client_log}" "${ipv6_client_log}" \
  "${state_dir}/udp-target.log" "${state_dir}/tproxy.log" \
  "${state_dir}/client.done" "${state_dir}/ipv6-client.done" "${state_dir}/udp-client.done" \
  "${state_dir}/runtime.pid" "${state_dir}/force-stop.ready" "${state_dir}/force-stop.request" \
  "${state_dir}/force-stop-observed" \
  "${state_dir}/iptables" "${state_dir}/ip6tables" "${state_dir}/state.sqlite" \
  "${state_dir}/state.sqlite-wal" "${state_dir}/state.sqlite-shm"

if [[ "${YUHAIIN_SKIP_BUILD:-0}" != "1" ]]; then
  "${repo_dir}/scripts/integration/podman-cargo.sh" \
    --target-dir "${target_dir}" --state-dir "${scenario_dir}" -- \
    cargo build \
    -p yuhaiin-runtime \
    --bin transparent-service-smoke \
    --all-features \
    >"${scenario_dir}/build.log"
fi
test -x "${binary}"
chmod 755 "${binary}"

target_ip="${target_addr%:*}"
target_port="${target_addr##*:}"
udp_target_ip="${udp_target_addr%:*}"
udp_target_port="${udp_target_addr##*:}"
target_v6_port="${target_v6_addr##*:}"
target_v6_port="${target_v6_port%]}"
redir_v6_port="${redir_v6_addr##*:}"
redir_v6_port="${redir_v6_port%]}"
redir_port="${redir_addr##*:}"
tproxy_port="${tproxy_addr##*:}"

tproxy_mode="${YUHAIIN_TPROXY_ENABLED:-auto}"
podman_rootless="$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || echo true)"
if [[ "${tproxy_mode}" == "auto" ]]; then
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
if [[ "${tproxy_kernel_mode}" != "tproxy" && "${tproxy_kernel_mode}" != "redirect" ]]; then
  echo "YUHAIIN_TPROXY_MODE must be tproxy or redirect" >&2
  exit 1
fi
if [[ "${tproxy_enabled}" -eq 1 && "${podman_rootless}" == "true" ]]; then
  cat >&2 <<EOF
[transparent-service] TPROXY UDP requires a rootful Podman namespace with
CAP_NET_ADMIN and a kernel mangle/route namespace. The current Podman
connection is rootless, so the explicit gate is not runnable here.
[transparent-service] run this smoke with rootful Podman, or omit
YUHAIIN_TPROXY_ENABLED=1 to record the deterministic capability skip.
EOF
  exit 77
fi

ipv6_env_args=()
if [[ "${ipv6_mode}" -eq 1 ]]; then
  ipv6_env_args+=(
    -e "YUHAIIN_TARGET_V6_ADDR=${target_v6_addr}"
    -e "YUHAIIN_REDIR_V6_ADDR=${redir_v6_addr}"
    -e "YUHAIIN_IPV6_CLIENT_DONE=/state/ipv6-client.done"
  )
  echo "[transparent-service] IPv6 REDIRECT enabled: ${target_v6_addr} -> ${redir_v6_addr}"
else
  echo "[transparent-service] IPv6 REDIRECT skipped: set YUHAIIN_TRANSPARENT_IPV6=1 to require it"
fi

echo "[transparent-service] running isolated REDIRECT TCP + TPROXY UDP smoke in Podman"
if [[ "${tproxy_enabled}" -eq 0 ]]; then
  echo "[transparent-service] TPROXY UDP skipped by auto capability policy; set YUHAIIN_TPROXY_ENABLED=1 to require it"
fi
cleanup_main() {
  podman rm -f "${main_container}" >/dev/null 2>&1 || true
}
trap cleanup_main EXIT INT TERM
podman run --rm --privileged --name "${main_container}" --network="${network_mode}" \
  -v "${binary}:/usr/local/bin/transparent-service-smoke:ro" \
  -v "${state_dir}:/state:Z" \
  -v "${xtables_multi}:/host/xtables-nft-multi:ro" \
  -v "${xtables_libdir}:/host${xtables_libdir}:ro" \
  -v "${host_ip}:/host/ip:ro" \
  -v "${host_nft}:/host/nft:ro" \
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
  -e YUHAIIN_SERVICE_IPV6="${service_ipv6}" \
  -e YUHAIIN_CLIENT_IPV6="${client_ipv6}" \
  -e YUHAIIN_TARGET_V6_PORT="${target_v6_port}" \
  -e YUHAIIN_REDIR_V6_PORT="${redir_v6_port}" \
  -e YUHAIIN_TRANSPARENT_IPV6="${ipv6_mode}" \
  -e YUHAIIN_TPROXY_ENABLED="${tproxy_enabled}" \
  -e YUHAIIN_TPROXY_MODE="${tproxy_kernel_mode}" \
  -e YUHAIIN_TPROXY_BACKEND="${tproxy_backend}" \
  -e YUHAIIN_TPROXY_ON_IP="${YUHAIIN_TPROXY_ON_IP:-}" \
  -e YUHAIIN_TPROXY_DEBUG_HOLD_SEC="${YUHAIIN_TPROXY_DEBUG_HOLD_SEC:-0}" \
  -e YUHAIIN_TPROXY_DEBUG_AFTER_TCP_HOLD_SEC="${YUHAIIN_TPROXY_DEBUG_AFTER_TCP_HOLD_SEC:-0}" \
  -e YUHAIIN_TPROXY_DEBUG_UDP_DURING_HOLD="${YUHAIIN_TPROXY_DEBUG_UDP_DURING_HOLD:-0}" \
  -e YUHAIIN_TPROXY_IDLE_WAIT_MS="${YUHAIIN_TPROXY_IDLE_WAIT_MS:-0}" \
  -e YUHAIIN_TEST_UDP_IDLE_TIMEOUT_MS="${YUHAIIN_TEST_UDP_IDLE_TIMEOUT_MS:-}" \
  -e YUHAIIN_TPROXY_FORCE_SERVICE_STOP="${YUHAIIN_TPROXY_FORCE_STOP:-0}" \
  -e YUHAIIN_TPROXY_FORCE_STOP_READY=/state/force-stop.ready \
  -e YUHAIIN_HOST_NSENTER="/host/nsenter" \
  -e YUHAIIN_HOST_UNSHARE="/host/unshare" \
  -e YUHAIIN_HOST_LOADER="/host${host_loader}" \
  -e YUHAIIN_HOST_XTABLES_LIBDIR="/host${xtables_libdir}" \
  "${ipv6_env_args[@]}" \
  --entrypoint /bin/sh \
  "${image}" \
  -ceu '
    ln -sf /host/xtables-nft-multi /state/iptables
    ln -sf /host/xtables-nft-multi /state/ip6tables
    ln -sf /host/ip /state/ip
    run_iptables() {
      XTABLES_LIBDIR="$YUHAIIN_HOST_XTABLES_LIBDIR" \
        "$YUHAIIN_HOST_LOADER" \
        --library-path /host/usr/lib/x86_64-linux-gnu:/host/usr/lib:/host/usr/lib64 \
        /state/iptables "$@"
    }
    run_ip6tables() {
      XTABLES_LIBDIR="$YUHAIIN_HOST_XTABLES_LIBDIR" \
        "$YUHAIIN_HOST_LOADER" \
        --library-path /host/usr/lib/x86_64-linux-gnu:/host/usr/lib:/host/usr/lib64 \
        /state/ip6tables "$@"
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
    run_nft() {
      "$YUHAIIN_HOST_LOADER" \
        --library-path /host/usr/lib/x86_64-linux-gnu:/host/usr/lib:/host/usr/lib64 \
        /host/nft "$@"
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
    if [ "$YUHAIIN_TRANSPARENT_IPV6" -eq 1 ]; then
      run_ip -6 addr add "${YUHAIIN_SERVICE_IPV6}/64" dev service-client nodad
      run_ns_ip "$client_ns_pid" -6 addr add "${YUHAIIN_CLIENT_IPV6}/64" dev client0 nodad
    fi

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
    # The transparent destination is reached through a different local
    # interface than the ingress address selected by TPROXY. Linux otherwise
    # rejects the locally-routed datagram as a martian on the ingress veth.
    echo 1 >/proc/sys/net/ipv4/conf/service-client/accept_local || true

    if [ "$YUHAIIN_TPROXY_ENABLED" -eq 1 ]; then
      run_ns "$target_ns_pid" env \
        YUHAIIN_UDP_TARGET_ADDR="${YUHAIIN_UDP_TARGET_ADDR}" \
        /usr/local/bin/transparent-service-smoke --udp-target \
        >/state/udp-target.log 2>&1 &
      target_pid=$!
    fi

    rule_installed=0
    ipv6_rule_installed=0
    tproxy_rule_installed=0
    route_installed=0
    tproxy_on_ip_args=""
    if [ -n "${YUHAIIN_TPROXY_ON_IP:-}" ]; then
      tproxy_on_ip_args="--on-ip ${YUHAIIN_TPROXY_ON_IP}"
    fi
    cleanup() {
      if [ "$target_pid" -ne 0 ]; then kill "$target_pid" 2>/dev/null || true; fi
      if [ "$rule_installed" -eq 1 ]; then
        run_iptables -t nat -D PREROUTING -s "${YUHAIIN_CLIENT_IP}/32" \
          -d "${YUHAIIN_SERVICE_IP}/32" -p tcp \
          -m tcp --dport "${YUHAIIN_TARGET_PORT}" \
          -j REDIRECT --to-ports "${YUHAIIN_REDIR_PORT}" || true
      fi
      if [ "$ipv6_rule_installed" -eq 1 ]; then
        run_ip6tables -t nat -D PREROUTING -s "${YUHAIIN_CLIENT_IPV6}/128" \
          -d "${YUHAIIN_SERVICE_IPV6}/128" -p tcp \
          -m tcp --dport "${YUHAIIN_TARGET_V6_PORT}" \
          -j REDIRECT --to-ports "${YUHAIIN_REDIR_V6_PORT}" || true
      fi
      if [ "$tproxy_rule_installed" -eq 1 ]; then
        if [ "$YUHAIIN_TPROXY_BACKEND" = nft ]; then
          run_nft delete table ip yuhaiin_tproxy || true
        elif [ "$YUHAIIN_TPROXY_MODE" = redirect ]; then
          run_iptables -t nat -D PREROUTING -s "${YUHAIIN_CLIENT_IP}/32" \
            -d "${YUHAIIN_UDP_TARGET_IP}/32" -p udp \
            -m udp --dport "${YUHAIIN_UDP_TARGET_PORT}" \
            -j REDIRECT --to-ports "${YUHAIIN_TPROXY_PORT}" || true
        else
          run_iptables -t mangle -D PREROUTING -s "${YUHAIIN_CLIENT_IP}/32" \
            -d "${YUHAIIN_UDP_TARGET_IP}/32" -p udp \
            -m udp --dport "${YUHAIIN_UDP_TARGET_PORT}" \
            -j TPROXY --on-port "${YUHAIIN_TPROXY_PORT}" \
            --tproxy-mark 1/1 ${tproxy_on_ip_args} || true
        fi
      fi
      if [ "$route_installed" -eq 1 ]; then
        run_ip route del local 0.0.0.0/0 dev lo table 100 || true
        run_ip rule del fwmark 1 table 100 || true
      fi
      if [ "$client_ns_pid" -ne 0 ]; then kill "$client_ns_pid" 2>/dev/null || true; fi
      if [ "$target_ns_pid" -ne 0 ]; then kill "$target_ns_pid" 2>/dev/null || true; fi
      run_ip link del service-client 2>/dev/null || true
      run_ip link del service-target 2>/dev/null || true
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
    echo "$service_pid" >/state/runtime.pid
    run_iptables -t nat -A PREROUTING -s "${YUHAIIN_CLIENT_IP}/32" \
      -d "${YUHAIIN_SERVICE_IP}/32" -p tcp \
      -m tcp --dport "${YUHAIIN_TARGET_PORT}" \
      -j REDIRECT --to-ports "${YUHAIIN_REDIR_PORT}"
    rule_installed=1
    if [ "$YUHAIIN_TRANSPARENT_IPV6" -eq 1 ]; then
      run_ip6tables -t nat -A PREROUTING -s "${YUHAIIN_CLIENT_IPV6}/128" \
        -d "${YUHAIIN_SERVICE_IPV6}/128" -p tcp \
        -m tcp --dport "${YUHAIIN_TARGET_V6_PORT}" \
        -j REDIRECT --to-ports "${YUHAIIN_REDIR_V6_PORT}"
      ipv6_rule_installed=1
    fi

    if [ "$YUHAIIN_TPROXY_ENABLED" -eq 1 ]; then
      run_ip rule add fwmark 1 table 100
      run_ip route add local 0.0.0.0/0 dev lo table 100
      route_installed=1
      if [ "$YUHAIIN_TPROXY_BACKEND" = nft ]; then
        run_nft add table ip yuhaiin_tproxy
        run_nft add chain ip yuhaiin_tproxy prerouting \
          "{ type filter hook prerouting priority mangle; policy accept; }"
        run_nft add rule ip yuhaiin_tproxy prerouting \
          ip saddr "${YUHAIIN_CLIENT_IP}" ip daddr "${YUHAIIN_UDP_TARGET_IP}" \
          udp dport "${YUHAIIN_UDP_TARGET_PORT}" \
          tproxy to :"${YUHAIIN_TPROXY_PORT}" meta mark set 1 accept
      elif [ "$YUHAIIN_TPROXY_MODE" = redirect ]; then
        run_iptables -t nat -A PREROUTING -s "${YUHAIIN_CLIENT_IP}/32" \
          -d "${YUHAIIN_UDP_TARGET_IP}/32" -p udp \
          -m udp --dport "${YUHAIIN_UDP_TARGET_PORT}" \
          -j REDIRECT --to-ports "${YUHAIIN_TPROXY_PORT}"
      else
        run_iptables -t mangle -A PREROUTING -s "${YUHAIIN_CLIENT_IP}/32" \
          -d "${YUHAIIN_UDP_TARGET_IP}/32" -p udp \
          -m udp --dport "${YUHAIIN_UDP_TARGET_PORT}" \
          -j TPROXY --on-port "${YUHAIIN_TPROXY_PORT}" \
          --tproxy-mark 1/1 ${tproxy_on_ip_args}
      fi
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

    if [ "${YUHAIIN_TPROXY_DEBUG_HOLD_SEC:-0}" -gt 0 ]; then
      sleep "${YUHAIIN_TPROXY_DEBUG_HOLD_SEC}"
    fi

    if ! run_ns "$client_ns_pid" env \
      YUHAIIN_TARGET_ADDR="${YUHAIIN_TARGET_ADDR}" \
      /usr/sbin/runuser -u nobody -- /usr/local/bin/transparent-service-smoke --client \
      >/state/client.log 2>&1; then
      cat /state/client.log >&2
      exit 1
    fi
    touch /state/client.done

    if [ "${YUHAIIN_TPROXY_DEBUG_AFTER_TCP_HOLD_SEC:-0}" -gt 0 ]; then
      echo "[transparent-service] holding after TCP client for ${YUHAIIN_TPROXY_DEBUG_AFTER_TCP_HOLD_SEC}s" >&2
      debug_udp_pid=0
      if [ "${YUHAIIN_TPROXY_DEBUG_UDP_DURING_HOLD:-0}" -eq 1 ]; then
        run_ns "$client_ns_pid" env \
          YUHAIIN_UDP_TARGET_ADDR="${YUHAIIN_UDP_TARGET_ADDR}" \
          /usr/sbin/runuser -u nobody -- /usr/local/bin/transparent-service-smoke --udp-client \
          >/state/debug-udp-client.log 2>&1 &
        debug_udp_pid=$!
        sleep 1
      fi
      run_ip rule show >&2 || true
      run_ip route show table 100 >&2 || true
      run_ip route get "${YUHAIIN_UDP_TARGET_IP}" mark 1 >&2 || true
      run_iptables -t mangle -L PREROUTING -v -n >&2 || true
      cat /proc/net/udp >&2 || true
      sleep "${YUHAIIN_TPROXY_DEBUG_AFTER_TCP_HOLD_SEC}"
      if [ "$debug_udp_pid" -ne 0 ]; then
        kill "$debug_udp_pid" 2>/dev/null || true
        wait "$debug_udp_pid" 2>/dev/null || true
      fi
    fi

    if [ "$YUHAIIN_TRANSPARENT_IPV6" -eq 1 ]; then
      if ! run_ns "$client_ns_pid" env \
        YUHAIIN_TARGET_ADDR="${YUHAIIN_TARGET_V6_ADDR}" \
        /usr/sbin/runuser -u nobody -- /usr/local/bin/transparent-service-smoke --client \
        >/state/ipv6-client.log 2>&1; then
        cat /state/ipv6-client.log >&2
        exit 1
      fi
      touch /state/ipv6-client.done
    fi

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
    if [ -f /state/force-stop.request ] && [ "$service_status" -ne 0 ]; then
      echo "transparent-force-stop-observed status=$service_status" | tee /state/force-stop-observed
      exit 0
    fi
    exit "$service_status"
  ' >"${scenario_dir}/container.log" 2>&1 &
main_pid=$!
if [[ "${YUHAIIN_TPROXY_FORCE_STOP:-0}" == "1" ]]; then
  ready=0
  for _ in $(seq 1 200); do
    if [[ -f "${state_dir}/client.done" && -f "${state_dir}/udp-client.done" \
      && -f "${state_dir}/force-stop.ready" && -s "${state_dir}/runtime.pid" ]]; then
      ready=1
      break
    fi
    sleep 0.1
  done
  if (( ready == 0 )); then
    cat "${scenario_dir}/container.log" >&2 || true
    echo "TPROXY force-stop fixture did not reach two established UDP flows" >&2
    podman rm -f "${main_container}" >/dev/null 2>&1 || true
    exit 1
  fi
  service_pid="$(<"${state_dir}/runtime.pid")"
  # Tell the inner shell that the non-zero runtime exit is intentional.  The
  # marker must be visible before SIGKILL, otherwise --rm can reap the
  # container while the outer podman exec is still returning.
  touch "${state_dir}/force-stop.request"
  if ! podman exec "${main_container}" /bin/sh -ceu "kill -KILL ${service_pid}"; then
    # The target exits immediately after SIGKILL and --rm may remove the
    # container before podman exec has received its success response.  Keep
    # the failure strict unless the inner shell recorded the expected status.
    for _ in $(seq 1 20); do
      [[ -f "${state_dir}/force-stop-observed" ]] && break
      sleep 0.05
    done
    test -f "${state_dir}/force-stop-observed"
  fi
fi
if wait "${main_pid}"; then
  main_status=0
else
  main_status=$?
fi
for log_file in "${scenario_dir}/container.log" "${runtime_log}" "${client_log}" "${ipv6_client_log}" "${udp_client_log}"; do
  if [[ -f "${log_file}" ]]; then
    cat "${log_file}"
  fi
done

if [[ "${main_status}" -ne 0 ]]; then
  if [[ "${YUHAIIN_TPROXY_FORCE_STOP:-0}" == "1" \
    && -f "${state_dir}/force-stop-observed" ]]; then
    # Podman may report the container's SIGKILL status even though the inner
    # shell converted that intentional runtime death into a successful smoke.
    main_status=0
  else
    exit "${main_status}"
  fi
fi

grep -Fq "transparent-ready" "${runtime_log}"
grep -Fq "transparent-client-ok" "${client_log}"
if [[ "${YUHAIIN_TPROXY_FORCE_STOP:-0}" == "1" ]]; then
  grep -Fq "transparent-force-stop-ready" "${runtime_log}"
else
  grep -Fq "transparent-redir-tcp-ok" "${runtime_log}"
  grep -Fq "transparent-closed" "${runtime_log}"
fi
if [[ "${ipv6_mode}" -eq 1 ]]; then
  grep -Fq "transparent-client-ok" "${ipv6_client_log}"
  if [[ "${YUHAIIN_TPROXY_FORCE_STOP:-0}" != "1" ]]; then
    grep -Fq "transparent-redir-ipv6-ok" "${runtime_log}"
  fi
fi
if [[ "${tproxy_enabled}" -eq 1 ]]; then
  grep -Fq "transparent-udp-client-ok" "${udp_client_log}"
  if [[ "${YUHAIIN_TPROXY_FORCE_STOP:-0}" != "1" ]]; then
    grep -Fq "transparent-tproxy-udp-ok" "${runtime_log}"
  fi
  grep -Fq "transparent-tproxy-socket-ok" "${state_dir}/tproxy.log"
else
  grep -Fq "transparent-tproxy-udp-skipped" "${runtime_log}"
  grep -Fq "transparent-tproxy-socket-skipped" "${state_dir}/tproxy.log"
fi
if [[ "${YUHAIIN_TPROXY_FORCE_STOP:-0}" == "1" ]]; then
  grep -Fq "transparent-force-stop-observed" "${state_dir}/force-stop-observed"
fi
echo "[transparent-service] passed; logs=${scenario_dir}"
