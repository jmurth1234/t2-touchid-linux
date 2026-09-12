#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

PATH=/usr/bin:/bin
export PATH
export LC_ALL=C

config_file=/etc/t2-touchid.conf
state_dir=/run/t2-touchid
nm_marker=$state_dir/network-manager-detached

restore_network_manager() {
  [[ -f $nm_marker ]] || return 0
  [[ $(stat -c '%a:%U:%G' "$nm_marker" 2>/dev/null) == 600:root:root ]] || return 1
  mapfile -t detached_interfaces <"$nm_marker"
  (( ${#detached_interfaces[@]} == 1 )) || return 1
  interface=${detached_interfaces[0]}
  [[ $interface =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || return 1
  if systemctl is-active --quiet NetworkManager.service; then
    nmcli device set "$interface" managed yes || return 1
  fi
  rm -f -- "$nm_marker"
}

case ${1:-prepare} in
  prepare) ;;
  restore)
    restore_network_manager
    exit
    ;;
  *) exit 2 ;;
esac

[[ -r $config_file ]] || { echo "T2 Touch ID configuration is unavailable" >&2; exit 1; }
mapfile -t interfaces < <(sed -n 's/^T2_TOUCHID_INTERFACE=//p' "$config_file")
mapfile -t hosts < <(sed -n 's/^T2_TOUCHID_HOST=//p' "$config_file")
(( ${#interfaces[@]} == 1 && ${#hosts[@]} == 1 )) || {
  echo "T2 Bridge network configuration is invalid" >&2
  exit 1
}
interface=${interfaces[0]}
host=${hosts[0]}
[[ $interface =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || {
  echo "T2 Bridge network configuration is invalid" >&2
  exit 1
}
peer=$(printf '%s\n' "$host" | python -c '
import ipaddress, sys
raw = sys.stdin.read()
if not raw.endswith("\n") or raw[:-1] != raw[:-1].strip():
    raise SystemExit(1)
try:
    value = ipaddress.IPv6Address(raw[:-1])
except ValueError:
    raise SystemExit(1)
if not value.is_link_local or value.is_multicast or value.scope_id is not None:
    raise SystemExit(1)
print(value.compressed)
') || { echo "Configured BridgeOS peer is not an unscoped IPv6 link-local address" >&2; exit 1; }

bind_unbound_ibridge() {
  local device function
  local -a candidates=()

  [[ -w /sys/bus/usb/drivers/cdc_ncm/bind ]] || return 1
  for device in /sys/bus/usb/devices/*; do
    [[ -f $device/idVendor && -f $device/idProduct ]] || continue
    [[ $(<"$device/idVendor") == 05ac && $(<"$device/idProduct") == 8233 ]] || continue
    function=$device:1.0
    [[ -d $function && ! -e $function/driver ]] || continue
    candidates+=("$(basename "$function")")
  done
  (( ${#candidates[@]} == 1 )) || return 1

  printf '%s' "${candidates[0]}" >/sys/bus/usb/drivers/cdc_ncm/bind || return 1
  logger --priority authpriv.info --tag t2-bridge-network \
    'recovered delayed Apple T2 cdc_ncm bind'
}

deadline=$((SECONDS + 30))
while [[ ! -d /sys/class/net/$interface && $SECONDS -lt $deadline ]]; do
  sleep 1
done
if [[ ! -d /sys/class/net/$interface ]] && bind_unbound_ibridge; then
  deadline=$((SECONDS + 5))
  while [[ ! -d /sys/class/net/$interface && $SECONDS -lt $deadline ]]; do
    sleep 1
  done
fi
[[ -d /sys/class/net/$interface ]] || { echo "T2 network interface is unavailable" >&2; exit 1; }

driver=$(basename "$(readlink -f "/sys/class/net/$interface/device/driver" 2>/dev/null)" 2>/dev/null || true)
[[ $driver == cdc_ncm ]] || { echo "Configured T2 interface does not use cdc_ncm" >&2; exit 1; }

changed_nm=0
network_ready=0
cleanup() {
  if [[ $network_ready == 0 && $changed_nm == 1 ]]; then
    restore_network_manager || true
  fi
}
trap cleanup EXIT
if systemctl is-active --quiet NetworkManager.service &&
    [[ $(nmcli -g GENERAL.NM-MANAGED device show "$interface") == yes ]]; then
  install -d -o root -g root -m 0700 "$state_dir"
  umask 077
  printf '%s\n' "$interface" >"$nm_marker"
  changed_nm=1
  nmcli device set "$interface" managed no
fi
ip link set dev "$interface" up

usable_link_local() {
  ip -o -6 address show dev "$interface" scope link |
    grep -Ev ' tentative( |$)| dadfailed( |$)' |
    grep -q ' scope link '
}

for _ in {1..5}; do
  usable_link_local && break
  sleep 1
done

if ! usable_link_local; then
  mac=$(<"/sys/class/net/$interface/address")
  [[ $mac =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]] || {
    echo "T2 interface hardware address is invalid" >&2
    exit 1
  }
  IFS=: read -r b1 b2 b3 b4 b5 b6 <<<"$mac"
  first=$((16#$b1 ^ 2))
  printf -v local_address 'fe80::%02x%s:%sff:fe%s:%s%s' \
    "$first" "${b2,,}" "${b3,,}" "${b4,,}" "${b5,,}" "${b6,,}"
  ip -6 address replace "$local_address/64" dev "$interface" scope link
  for _ in {1..5}; do
    usable_link_local && break
    sleep 1
  done
fi
usable_link_local || { echo "T2 interface has no usable IPv6 link-local address" >&2; exit 1; }

deadline=$((SECONDS + 15))
while ! ping -6 -c 1 -W 2 -I "$interface" "$peer%$interface" >/dev/null 2>&1; do
  (( SECONDS < deadline )) || { echo "Configured BridgeOS peer is unreachable" >&2; exit 1; }
  sleep 1
done

network_ready=1
trap - EXIT
logger --priority authpriv.info --tag t2-bridge-network \
  'T2 Bridge network is ready'
