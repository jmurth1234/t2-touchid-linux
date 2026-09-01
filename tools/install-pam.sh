#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
source_dir=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
backup_dir=/var/lib/t2-touchid/pam-backups
install -d -o root -g root -m 0700 "$backup_dir"

install_one() {
  local source=$2 target=/etc/pam.d/$1 backup=$backup_dir/$1.original
  [[ -f $source ]] || { echo "Missing template: $source" >&2; exit 1; }
  if [[ -e $target && ! -e $backup ]]; then
    install -o root -g root -m 0600 "$target" "$backup"
  fi
  install -o root -g root -m 0644 "$source" "$target"
}

install_one sudo "$source_dir/pam/sudo"
if [[ -e /etc/pam.d/omarchy-lock-password ]]; then
  install_one omarchy-lock-password "$source_dir/pam/omarchy-lock-password"
fi
rm -f -- /etc/security/t2-touchid-sudo-prompt

echo "PAM templates installed; originals are in $backup_dir."
echo "Keep this terminal open and validate password fallback before closing it."
