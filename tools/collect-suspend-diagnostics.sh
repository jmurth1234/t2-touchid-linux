#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

output=${1:-t2-suspend-diagnostics.txt}
umask 077
{
  echo "T2 Touch ID suspend diagnostics"
  echo "kernel=$(uname -r)"
  echo "module_loaded=$([[ -d /sys/module/t2_sep_transport ]] && echo yes || echo no)"
  echo "aks_device=$([[ -e /dev/t2-aks ]] && echo present || echo absent)"
  echo "sleep_modes=$(tr -d '[]' </sys/power/mem_sleep 2>/dev/null || echo unavailable)"
  echo
  echo "Service state (no configuration values):"
  for unit in t2-sep-transport t2-keybag-load t2-credential-unlock t2-biometric-ready fprintd; do
    printf '%s=' "$unit"
    systemctl is-active "$unit.service" 2>/dev/null || true
  done
  echo
  echo "Relevant kernel messages (addresses removed):"
  journalctl -k -b --no-pager 2>/dev/null | \
    grep -Ei 't2|apple-bce|cdc_ncm|NETDEV WATCHDOG|suspend|resume' | \
    sed -E 's/([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}/[REDACTED-MAC]/g; s/fe80::[[:xdigit:]:%]+/[REDACTED-IPV6]/g' || true
} >"$output"
chmod 0600 "$output"
echo "Wrote privacy-filtered diagnostics to $output"
