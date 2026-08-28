#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
if [[ ${1:-} == --help ]]; then
  echo "Usage: sudo ./uninstall.sh [--purge-private-data]"
  exit 0
fi
[[ $# -le 1 && ( $# -eq 0 || $1 == --purge-private-data ) ]] || exit 2

systemctl disable --now fprintd.service t2-biometric-ready.service \
  t2-credential-unlock.service t2-keybag-load.service \
  t2-sep-transport.service 2>/dev/null || true
for file in /etc/systemd/system/{fprintd,t2-biometric-ready,t2-credential-unlock,t2-keybag-load,t2-sep-transport}.service \
  /usr/local/sbin/{t2-aks-tool,t2-keybag-load,t2-pam-unlock,t2-credential-unlock,t2-biometric-ready,t2-touchid-doctor} \
  /etc/dbus-1/system.d/99-t2-touchid-fprint.conf; do
  [[ ! -e $file ]] || rm -- "$file"
done
rm -rf -- /opt/t2-touchid /usr/local/lib/t2-touchid
systemctl daemon-reload
systemctl reload dbus.service 2>/dev/null || true

if [[ ${1:-} == --purge-private-data ]]; then
  rm -rf -- /var/lib/t2-touchid
  rm -f -- /etc/t2-touchid.conf /etc/credstore.encrypted/t2-touchid-password
  echo "Removed installed files and private data. PAM files were not changed."
else
  echo "Removed installed files. Preserved config, credentials, keybags, and PAM backups."
fi
echo "The pinned kernel module remains loaded until reboot."
