#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
backup_dir=/var/lib/t2-touchid/pam-backups
restored=0
for name in sudo omarchy-lock-password; do
  backup=$backup_dir/$name.original
  if [[ -f $backup ]]; then
    install -o root -g root -m 0644 "$backup" "/etc/pam.d/$name"
    restored=1
  fi
done
[[ $restored == 1 ]] || { echo "No PAM backups found." >&2; exit 1; }
rm -f -- /etc/security/t2-touchid-sudo-prompt
echo "Original PAM files restored."
