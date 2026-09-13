#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -uo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo tools/check-t2-linux-readiness.sh" >&2; exit 2; }

config_file=/etc/t2-touchid.conf
port_file=/var/lib/t2-touchid/biometric-port
failures=0
warnings=0

pass() { printf 'PASS  %s\n' "$*"; }
warn() { printf 'WARN  %s\n' "$*"; warnings=$((warnings + 1)); }
fail() { printf 'FAIL  %s\n' "$*"; failures=$((failures + 1)); }

config_value() {
  local key=$1 line value=
  while IFS= read -r line; do
    case $line in
      "$key="*) value=${line#*=} ;;
    esac
  done < "$config_file"
  printf '%s' "$value"
}

enabled_state() {
  systemctl is-enabled "$1" 2>/dev/null || true
}

echo "T2 Touch ID Linux readiness check (read-only)"
echo

if [[ -r $config_file ]]; then
  pass "configuration is readable"
  interface=$(config_value T2_TOUCHID_INTERFACE)
  host=$(config_value T2_TOUCHID_HOST)
  apple_uid=$(config_value T2_TOUCHID_MACOS_USER_ID)
  [[ -n $interface ]] || fail "T2_TOUCHID_INTERFACE is not configured"
  [[ -n $host ]] || fail "T2_TOUCHID_HOST is not configured"
  [[ $apple_uid =~ ^[0-9]+$ ]] || fail "T2_TOUCHID_MACOS_USER_ID is invalid"
else
  fail "configuration is missing or unreadable: $config_file"
  interface=
  host=
  apple_uid=
fi

for unit in t2-sep-transport.service t2-keybag-load.service \
  t2-credential-unlock.service t2-biometric-ready.service fprintd.service; do
  state=$(enabled_state "$unit")
  if [[ $state == disabled ]]; then
    pass "$unit is disabled for manual bring-up"
  else
    fail "$unit must be disabled for manual bring-up (currently ${state:-unknown})"
  fi
done

refresh_state=$(enabled_state t2-biometric-port-refresh.service)
if [[ $refresh_state == enabled ]]; then
  pass "t2-biometric-port-refresh.service is enabled for one boot-time run"
else
  warn "t2-biometric-port-refresh.service is ${refresh_state:-unknown}"
fi

if [[ -n $interface && -d /sys/class/net/$interface ]]; then
  pass "network interface $interface exists"
  driver=$(basename "$(readlink -f "/sys/class/net/$interface/device/driver" 2>/dev/null)" 2>/dev/null || true)
  if [[ $driver == cdc_ncm ]]; then
    pass "$interface uses cdc_ncm"
  else
    warn "$interface driver is ${driver:-unknown}, expected cdc_ncm"
  fi

  if ip -6 addr show dev "$interface" scope link | grep -q 'inet6 .* scope link' &&
    ! ip -6 addr show dev "$interface" scope link | grep -q tentative; then
    pass "$interface has a usable IPv6 link-local address"
  else
    fail "$interface has no usable IPv6 link-local address"
  fi

  if [[ -n $host ]] && ping -6 -c 1 -W 2 -I "$interface" "${host%%%*}%$interface" >/dev/null 2>&1; then
    pass "configured BridgeOS peer responds"
  else
    fail "configured BridgeOS peer does not respond"
  fi
else
  [[ -n $interface ]] && fail "network interface $interface does not exist"
fi

refresh_active=$(systemctl is-active t2-biometric-port-refresh.service 2>/dev/null || true)
refresh_result=$(systemctl show t2-biometric-port-refresh.service -p Result --value 2>/dev/null || true)
if [[ $refresh_active == active && $refresh_result == success ]]; then
  pass "boot-time biometric-port discovery succeeded"
else
  warn "biometric-port discovery is active=$refresh_active result=${refresh_result:-unknown}"
fi

if [[ -r $port_file ]]; then
  read -r port < "$port_file" || port=
  if [[ $port =~ ^[0-9]+$ ]] && (( port >= 49152 && port <= 65535 )); then
    pass "cached BiometricKit port is valid"
  else
    fail "cached BiometricKit port is invalid"
  fi
else
  fail "cached BiometricKit port is missing or unreadable"
fi

if [[ -f /var/lib/t2-touchid/user.kb ]]; then
  keybag_mode=$(stat -c '%a:%U:%G' /var/lib/t2-touchid/user.kb 2>/dev/null || true)
  if [[ $keybag_mode == 600:root:root ]]; then
    pass "user keybag is root-only"
  else
    fail "user keybag permissions are $keybag_mode, expected 600:root:root"
  fi
else
  fail "user keybag is missing"
fi

# fprintd deliberately fails closed without the private host baseline used to
# reconcile labels with the live SEP inventory.
catacomb_root=/var/lib/t2-touchid/catacomb
if [[ -d $catacomb_root && $(stat -c '%a:%U:%G' "$catacomb_root" 2>/dev/null) == 700:root:root ]] &&
  [[ $apple_uid =~ ^[0-9]+$ ]]; then
  printf -v user_component 'user_%08x.cat' "$apple_uid"
  catacomb_ok=yes
  for component in master.cat biolockout.cat "$user_component"; do
    mode=$(stat -c '%a:%U:%G' "$catacomb_root/$component" 2>/dev/null || true)
    [[ $mode == 600:root:root ]] || catacomb_ok=no
  done
  if [[ $catacomb_ok == yes ]]; then
    pass "local Catacomb baseline is root-only and complete"
  else
    fail "local Catacomb baseline is incomplete or has unsafe permissions"
  fi
else
  fail "local Catacomb baseline is missing or unsafe"
fi

module_loaded=no
[[ -d /sys/module/t2_sep_transport ]] && module_loaded=yes
aks_present=no
[[ -c /dev/t2-aks ]] && aks_present=yes
transport_log=$(journalctl -b -k --no-pager 2>/dev/null | grep -E \
  'AppleKeyStore capability (reply passed|negotiation failed)|root-only /dev/t2-aks' || true)

echo
if [[ $module_loaded == no && $aks_present == no && -z $transport_log ]]; then
  pass "transport has not been attempted during this boot"
  outcome=READY
elif [[ $module_loaded == yes && $aks_present == yes ]] &&
  grep -q 'capability reply passed' <<< "$transport_log"; then
  pass "transport capability negotiation succeeded and /dev/t2-aks exists"
  outcome=INITIALIZED
else
  fail "transport is loaded or was attempted without a healthy /dev/t2-aks"
  warn "do not restart, unload, or retry transport during this boot"
  outcome=BLOCKED
fi

echo
if (( failures > 0 )); then
  result=NOT_READY
  [[ $outcome == BLOCKED ]] && result=BLOCKED
  printf 'RESULT: %s (%d failure(s), %d warning(s))\n' "$result" "$failures" "$warnings"
  exit 1
fi

printf 'RESULT: %s (%d warning(s))\n' "$outcome" "$warnings"
if [[ $outcome == READY ]]; then
  echo "One controlled t2-sep-transport.service start may now be attempted."
fi
