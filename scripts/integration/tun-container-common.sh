#!/usr/bin/env bash

# Shared by TUN integration and benchmark scripts.  The file is sourced, not
# executed directly.  It selects a disposable user/network namespace when the
# caller lacks CAP_NET_ADMIN, so rootless Podman can still exercise the real
# kernel TUN path without changing the host namespace.

configure_tun_container_namespace() {
  local label="${1:-tun}"
  local command_path="${2:-/usr/local/bin/tun-service-smoke}"
  local mode="${YUHAIIN_TUN_USER_NAMESPACE:-auto}"
  local cap_eff
  local use_user_namespace=0

  case "${mode}" in
    1|true|yes)
      use_user_namespace=1
      ;;
    0|false|no)
      ;;
    auto)
      cap_eff="$(awk '/^CapEff:/ {print $2; exit}' /proc/self/status 2>/dev/null || true)"
      if [[ ! "${cap_eff}" =~ ^[0-9a-fA-F]+$ ]] || (( (16#${cap_eff} & (1 << 12)) == 0 )); then
        use_user_namespace=1
      fi
      ;;
    *)
      echo "YUHAIIN_TUN_USER_NAMESPACE must be auto, 0, or 1" >&2
      return 2
      ;;
  esac

  if (( use_user_namespace )); then
    TUN_CONTAINER_ENTRYPOINT=/usr/bin/unshare
    TUN_CONTAINER_COMMAND_ARGS=(-Urn "${command_path}")
    echo "[${label}] using disposable user/network namespace"
  else
    TUN_CONTAINER_ENTRYPOINT=/usr/local/bin/tun-service-smoke
    TUN_CONTAINER_COMMAND_ARGS=()
  fi
}
