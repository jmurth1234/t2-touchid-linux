#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
if [[ ${1:-} == --help ]]; then
  echo "Usage: sudo ./uninstall.sh [--purge-private-data]"
  exit 0
fi
[[ $# -le 1 && ( $# -eq 0 || $1 == --purge-private-data ) ]] || exit 2

target_user=
target_home=
if [[ -r /etc/t2-touchid.conf ]]; then
  target_user=$(sed -n 's/^T2_TOUCHID_USER=//p' /etc/t2-touchid.conf | tail -n 1)
  if [[ $target_user =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    target_home=$(getent passwd "$target_user" | cut -d: -f6)
  fi
fi

systemctl disable --now fprintd.service t2-touchid-post-reboot.service t2-biometric-ready.service \
  t2-credential-unlock.service t2-keybag-load.service \
  t2-sep-transport.service 2>/dev/null || true
for file in /etc/systemd/system/{fprintd,t2-touchid-post-reboot,t2-biometric-ready,t2-credential-unlock,t2-keybag-load,t2-sep-transport}.service \
  /usr/local/sbin/{t2-aks-tool,t2-keybag-load,t2-pam-unlock,t2-credential-unlock,t2-biometric-ready,t2-sep-transport-load,t2-touchid-doctor,t2-touchid-inventory,t2-touchid-identities,t2-touchid-identify-finger,t2-touchid-manage,t2-touchid-baseline,t2-catacomb-fixture-check,t2-acm-preflight,t2-aks-observe-test,t2-acm-lifecycle-test,t2-acm-policy-preflight,t2-acm-authorize-test,t2-touchid-enroll-test,t2-touchid-enroll,t2-touchid-user-map,t2-touchid-user-broker-gate,t2-touchid-fprint-status,t2-touchid-fprint-enrollment-gate,t2-touchid-post-reboot,t2-fprint-enrollment-worker,t2-fprint-delete-worker} \
  /etc/systemd/system/fprintd.service.d/10-native-enrollment.conf \
  /etc/systemd/system/fprintd.service.d/20-native-identity-management.conf \
  /etc/modprobe.d/t2-sep-transport.conf \
  /usr/share/polkit-1/actions/org.t2linux.touchid.policy \
  /etc/dbus-1/system.d/99-t2-touchid-fprint.conf; do
  [[ ! -e $file ]] || rm -- "$file"
done
rmdir /etc/systemd/system/fprintd.service.d 2>/dev/null || true
rm -rf -- /opt/t2-touchid /usr/local/lib/t2-touchid
if [[ -n $target_home && -d $target_home/.config/systemd/user ]]; then
  for unit in t2-touchid-alert.service t2-touchid-failure.service t2-touchid-success.service; do
    file=$target_home/.config/systemd/user/$unit
    [[ ! -e $file ]] || rm -- "$file"
  done
  runuser -u "$target_user" -- systemctl --user daemon-reload 2>/dev/null || true
fi
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
