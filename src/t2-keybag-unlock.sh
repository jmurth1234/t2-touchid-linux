#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail
ulimit -c 0

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }

tool=/usr/local/sbin/t2-aks-tool
state_file=/run/t2-touchid/keybag.env
ready_file=/run/t2-touchid/keybags-unlocked
rejected_file=/run/t2-touchid/keybag-password-rejected
[[ -x $tool && -r $state_file ]] || { echo "Keybag runtime state is unavailable." >&2; exit 1; }

if /usr/local/sbin/t2-pam-fingerprint-ready; then
  systemctl try-restart --no-block fprintd.service || true
  echo "Both keybags are already unlocked for this boot."
  exit 0
fi

rm -f -- "$ready_file" "$rejected_file"
snapshot=$(mktemp "${ready_file}.XXXXXX")
trap 'rm -f -- "$snapshot"' EXIT
install -o root -g root -m 0600 "$state_file" "$snapshot"

session=$(sed -n 's/^T2_KEYBAG_SESSION=\([0-9][0-9]*\)$/\1/p' "$snapshot")
handle=$(sed -n 's/^T2_KEYBAG_HANDLE=\(-\{0,1\}[0-9][0-9]*\)$/\1/p' "$snapshot")
special=$(sed -n 's/^T2_KEYBAG_SPECIAL=\(-\{0,1\}[0-9][0-9]*\)$/\1/p' "$snapshot")
[[ -n $session && -n $handle && -n $special ]] || { echo "Keybag runtime state is invalid." >&2; exit 1; }

ask_options=(--timeout=120)
[[ -t 0 && -t 1 ]] || ask_options+=(--no-tty)
if ! systemd-ask-password "${ask_options[@]}" \
    'macOS login password for T2 Touch ID:' |
    "$tool" unlock-keybags-stdin "$session" "$handle" "$special"; then
  status=${PIPESTATUS[1]}
  [[ $status == 3 ]] && install -o root -g root -m 0600 /dev/null "$rejected_file"
  exit "$status"
fi
cmp -s -- "$snapshot" "$state_file" || { echo "Keybag runtime state changed during unlock." >&2; exit 1; }
mv -f -- "$snapshot" "$ready_file"
trap - EXIT
if ! systemctl try-restart --no-block fprintd.service; then
  echo "Warning: keybags unlocked but fprintd could not be restarted." >&2
fi
echo "Both keybags are unlocked for this boot."
