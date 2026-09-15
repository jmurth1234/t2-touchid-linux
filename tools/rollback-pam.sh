#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
exec 9>/run/lock/t2-touchid-pam.lock
flock -x 9
backup_dir=/var/lib/t2-touchid/pam-backups
restored=0
for name in sudo polkit-1 omarchy-lock-password omarchy-lock-fingerprint; do
  backup=$backup_dir/$name.original
  absent=$backup_dir/$name.absent
  installed=$backup_dir/$name.installed
  target=/etc/pam.d/$name
  if [[ -e $installed && -e $target ]] && ! cmp -s -- "$target" "$installed"; then
    echo "Refusing to overwrite changed PAM stack: $target" >&2
    exit 1
  fi
  if [[ -f $backup ]]; then
    tmp=$(mktemp /etc/pam.d/.$name.t2.XXXXXX)
    install -o root -g root -m 0644 "$backup" "$tmp"
    mv -f -- "$tmp" "$target"
    rm -f -- "$backup" "$absent" "$installed"
    restored=1
  elif [[ -f $absent ]]; then
    rm -f -- "$target"
    rm -f -- "$absent" "$installed"
    restored=1
  fi
done

target=/etc/pam.d/system-auth
backup=$backup_dir/system-auth.original
gate='auth [success=ignore default=1] pam_succeed_if.so quiet service = sudo'
hook='auth optional pam_exec.so quiet seteuid /usr/local/sbin/t2-pam-unlock'
if [[ -f $backup ]]; then
  tmp=$(mktemp /etc/pam.d/.system-auth.t2.XXXXXX)
  trap 'rm -f -- "$tmp"' EXIT
  removed=0
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line == "$gate" || $line == "$hook" ]]; then
      ((removed += 1))
    else
      printf '%s\n' "$line" >>"$tmp"
    fi
  done <"$target"
  [[ $removed == 2 ]] || {
    echo "Refusing to alter a system-auth stack without the exact managed hook." >&2
    exit 1
  }
  chown root:root "$tmp"
  chmod 0644 "$tmp"
  mv -f -- "$tmp" "$target"
  rm -f -- "$backup"
  trap - EXIT
  restored=1
fi
[[ $restored == 1 ]] || { echo "No PAM backups found." >&2; exit 1; }
rm -f -- /etc/security/t2-touchid-sudo-prompt
echo "Original PAM files restored."
