#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

module=t2_sep_transport
parameter=/sys/module/$module/parameters/register_ool

if [[ -e /dev/t2-aks ]]; then
  exit 0
fi

# One capability probe per boot. A failed 0x4d pins DMA; a second start
# cannot recover (-110 / -71 / -74). Do not unload.
if journalctl -b -k --no-pager 2>/dev/null |
    grep -q 'AppleKeyStore capability negotiation failed'; then
  echo "$module already failed AppleKeyStore capability this boot; reboot required" >&2
  exit 1
fi

if [[ -d /sys/module/$module ]]; then
  # A PCI modalias may load the module before this service.  It is safe to
  # replace only the observation-only instance: it has registered no SEP DMA.
  if [[ ! -r $parameter ]] || [[ $(<"$parameter") != Y ]]; then
    # Unbind first: the bound PCI driver holds a module reference that makes
    # a bare modprobe --remove fail with "Module is in use" (observed 15,2).
    for dev in /sys/bus/pci/drivers/$module/0000:*; do
      [[ -e $dev ]] && echo "${dev##*/}" > /sys/bus/pci/drivers/$module/unbind
    done
    /usr/bin/modprobe --remove "$module"
  else
    echo "$module is active with register_ool=1 but /dev/t2-aks is absent; reboot required" >&2
    exit 1
  fi
fi

# Pass probe_capabilities explicitly: modprobe.d must stay observation-only by
# default (early auto-load safety), so the service load cannot inherit it.
# The v1 negotiation is a SEP-side prerequisite, not just a check — without it
# SEP ignores all endpoint-7 exchanges (keybag-load and even the read-only
# capabilities query time out). Observed MacBookPro15,2 2026-09-06.
/usr/bin/modprobe "$module" register_ool=1 probe_capabilities=1
[[ -e /dev/t2-aks ]] || {
  echo "$module loaded without creating /dev/t2-aks" >&2
  exit 1
}
