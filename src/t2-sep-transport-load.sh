#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

module=t2_sep_transport
parameter=/sys/module/$module/parameters/register_ool

if [[ -e /dev/t2-aks ]]; then
  exit 0
fi

if [[ -d /sys/module/$module ]]; then
  # A PCI modalias may load the module before this service.  It is safe to
  # replace only the observation-only instance: it has registered no SEP DMA.
  if [[ ! -r $parameter ]] || [[ $(<"$parameter") != Y ]]; then
    /usr/bin/modprobe --remove "$module"
  else
    echo "$module is active with register_ool=1 but /dev/t2-aks is absent; reboot required" >&2
    exit 1
  fi
fi

/usr/bin/modprobe "$module" register_ool=1
[[ -e /dev/t2-aks ]] || {
  echo "$module loaded without creating /dev/t2-aks" >&2
  exit 1
}
