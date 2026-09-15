#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
exec 9>/run/lock/t2-touchid-pam.lock
flock -x 9
source_dir=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
backup_dir=/var/lib/t2-touchid/pam-backups
install -d -o root -g root -m 0700 "$backup_dir"

install_one() {
  local source=$2 target=/etc/pam.d/$1 backup=$backup_dir/$1.original
  local absent=$backup_dir/$1.absent installed=$backup_dir/$1.installed tmp
  local mode=${3:-apply} managed_before=0
  [[ -f $source ]] || { echo "Missing template: $source" >&2; exit 1; }
  [[ -e $backup || -e $absent ]] && managed_before=1
  if [[ $managed_before == 1 && -e $target && ! -e $installed ]]; then
    cmp -s -- "$target" "$source" || {
      echo "Refusing to overwrite changed PAM stack: $target" >&2
      exit 1
    }
    install -o root -g root -m 0600 "$target" "$installed"
  fi
  if [[ -e $installed && -e $target ]] && ! cmp -s -- "$target" "$installed"; then
    echo "Refusing to overwrite changed PAM stack: $target" >&2
    exit 1
  fi
  [[ $mode == check ]] && return
  if [[ ! -e $backup && ! -e $absent ]]; then
    if [[ -e $target ]]; then
      install -o root -g root -m 0600 "$target" "$backup"
    else
      install -o root -g root -m 0600 /dev/null "$absent"
    fi
  fi
  tmp=$(mktemp "$(dirname -- "$target")/.$1.t2.XXXXXXXXXX")
  install -o root -g root -m 0644 "$source" "$tmp"
  mv -f -- "$tmp" "$target"
  install -o root -g root -m 0600 "$source" "$installed"
}

install_system_auth_hook() {
  local target=/etc/pam.d/system-auth backup=$backup_dir/system-auth.original
  local gate='auth [success=ignore default=1] pam_succeed_if.so quiet service = sudo'
  local hook='auth optional pam_exec.so quiet seteuid /usr/local/sbin/t2-pam-unlock'
  local legacy_hook='auth optional pam_exec.so quiet expose_authtok seteuid /usr/local/sbin/t2-pam-unlock'
  local tmp line line_number=0 unix_line=0 authfail_line=0 authsucc_line=0
  local unix_count=0 authfail_count=0 authsucc_count=0 gate_line=0 hook_line=0
  local gate_count hook_count legacy_count inserted=0 auth_index=0 auth_invalid=0
  local mode=${1:-apply}

  [[ -f $target ]] || { echo "Missing PAM stack: $target" >&2; exit 1; }
  gate_count=$(grep -Fxc "$gate" "$target" || true)
  hook_count=$(grep -Fxc "$hook" "$target" || true)
  legacy_count=$(grep -Fxc "$legacy_hook" "$target" || true)
  [[ $gate_count == 0 && $hook_count == 0 && $legacy_count == 0 ]] || {
    [[ $gate_count == 1 && $((hook_count + legacy_count)) == 1 ]] || {
      echo "Refusing to repair a partial system-auth hook automatically." >&2
      exit 1
    }
  }
  while IFS= read -r line || [[ -n $line ]]; do
    ((line_number += 1))
    if [[ $line =~ ^auth[[:space:]]+\[success=1[[:space:]]+default=bad\][[:space:]]+pam_unix\.so([[:space:]]|$) ]]; then
      unix_line=$line_number
      ((unix_count += 1))
    elif [[ $line =~ ^auth[[:space:]]+\[default=die\][[:space:]]+pam_faillock\.so[[:space:]]+authfail([[:space:]]|$) ]]; then
      authfail_line=$line_number
      ((authfail_count += 1))
    elif [[ $line =~ ^auth[[:space:]]+required[[:space:]]+pam_faillock\.so[[:space:]]+authsucc([[:space:]]|$) ]]; then
      authsucc_line=$line_number
      ((authsucc_count += 1))
    fi
    [[ $line == "$gate" ]] && gate_line=$line_number
    [[ $line == "$hook" || $line == "$legacy_hook" ]] && hook_line=$line_number
    if [[ $line =~ ^-?auth[[:space:]] ]] && \
       [[ $line != "$gate" && $line != "$hook" && $line != "$legacy_hook" ]]; then
      ((auth_index += 1))
      case $auth_index in
        1) [[ $line =~ ^auth[[:space:]]+required[[:space:]]+pam_faillock\.so[[:space:]]+preauth([[:space:]]|$) ]] || auth_invalid=1 ;;
        2) [[ $line =~ ^-auth[[:space:]]+\[success=2[[:space:]]+default=ignore\][[:space:]]+pam_systemd_home\.so([[:space:]]|$) ]] || auth_invalid=1 ;;
        3) [[ $line =~ ^auth[[:space:]]+\[success=1[[:space:]]+default=bad\][[:space:]]+pam_unix\.so([[:space:]]|$) ]] || auth_invalid=1 ;;
        4) [[ $line =~ ^auth[[:space:]]+\[default=die\][[:space:]]+pam_faillock\.so[[:space:]]+authfail([[:space:]]|$) ]] || auth_invalid=1 ;;
        5) [[ $line =~ ^auth[[:space:]]+optional[[:space:]]+pam_permit\.so([[:space:]]|$) ]] || auth_invalid=1 ;;
        6) [[ $line =~ ^auth[[:space:]]+required[[:space:]]+pam_env\.so([[:space:]]|$) ]] || auth_invalid=1 ;;
        7) [[ $line =~ ^auth[[:space:]]+required[[:space:]]+pam_faillock\.so[[:space:]]+authsucc([[:space:]]|$) ]] || auth_invalid=1 ;;
        *) auth_invalid=1 ;;
      esac
    fi
  done <"$target"
  if (( auth_index != 7 || auth_invalid || unix_count != 1 ||
        authfail_count != 1 || authsucc_count != 1 ||
        authfail_line != unix_line + 1 || authfail_line >= authsucc_line )); then
    echo "Refusing to patch unfamiliar system-auth authentication controls." >&2
    exit 1
  fi
  if [[ $gate_count == 1 ]]; then
    if (( gate_line == authsucc_line + 1 && hook_line == gate_line + 1 )); then
      [[ $hook_count == 1 || $mode == check ]] && return
    else
      echo "Refusing to repair a misplaced system-auth hook automatically." >&2
      exit 1
    fi
  fi
  [[ $mode == check ]] && return
  [[ ! -e $backup ]] && install -o root -g root -m 0600 "$target" "$backup"
  tmp=$(mktemp /etc/pam.d/.system-auth.t2.XXXXXX)
  trap 'rm -f -- "$tmp"' RETURN
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line == "$gate" || $line == "$hook" || $line == "$legacy_hook" ]] && continue
    printf '%s\n' "$line" >>"$tmp"
    if [[ $line =~ ^auth[[:space:]]+required[[:space:]]+pam_faillock\.so[[:space:]]+authsucc([[:space:]]|$) ]]; then
      printf '%s\n' "$gate" >>"$tmp"
      printf '%s\n' "$hook" >>"$tmp"
      ((inserted += 1))
    fi
  done <"$target"
  [[ $inserted == 1 ]] || { echo "Missing system-auth success control." >&2; exit 1; }
  chown root:root "$tmp"
  chmod 0644 "$tmp"
  mv -f -- "$tmp" "$target"
  trap - RETURN
}

install_system_auth_hook check
install_one sudo "$source_dir/pam/sudo" check
install_one polkit-1 "$source_dir/pam/polkit-1" check
if [[ -e /etc/pam.d/omarchy-lock-password ]]; then
  install_one omarchy-lock-password "$source_dir/pam/omarchy-lock-password" check
  install_one omarchy-lock-fingerprint "$source_dir/pam/omarchy-lock-fingerprint" check
fi

install_system_auth_hook
install_one sudo "$source_dir/pam/sudo"
install_one polkit-1 "$source_dir/pam/polkit-1"
if [[ -e /etc/pam.d/omarchy-lock-password ]]; then
  install_one omarchy-lock-password "$source_dir/pam/omarchy-lock-password"
  install_one omarchy-lock-fingerprint "$source_dir/pam/omarchy-lock-fingerprint"
fi
rm -f -- /etc/security/t2-touchid-sudo-prompt

echo "PAM templates installed; originals are in $backup_dir."
echo "Keep this terminal open and validate password fallback before closing it."
