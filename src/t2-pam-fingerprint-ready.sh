#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# PAM gate: success permits the following fingerprint modules; any failure
# skips directly to password authentication.
[[ $EUID -eq 0 ]] || exit 1
state_file=/run/t2-touchid/keybag.env
ready_file=/run/t2-touchid/keybags-unlocked
[[ -f $state_file && -f $ready_file ]] || exit 1
[[ $(stat -c '%a:%U:%G' "$state_file" 2>/dev/null) == 600:root:root ]] || exit 1
[[ $(stat -c '%a:%U:%G' "$ready_file" 2>/dev/null) == 600:root:root ]] || exit 1
cmp -s -- "$state_file" "$ready_file" || exit 1

# pam_fprintd cannot wait inside Claim (D-Bus method timeout ~25 s). Another
# sudo/pkexec holding the sensor would be AlreadyInUse → password. Wait here,
# before the touch prompt, only for those short-lived PAM clients. The lock
# screen writes "other" and must not delay TTY sudo. Match
# PAM_CLAIM_WAIT_SECONDS in t2-fprintd.py (finger window 30 s + claim expiry).
claim_file=/run/t2-touchid/workers/fprint-claim
deadline=$((SECONDS + 32))
while ((SECONDS < deadline)) && [[ -r $claim_file ]]; do
  comm=$(tr -d '\n' <"$claim_file" 2>/dev/null) || break
  case $comm in
    sudo | sudoedit | pkexec | polkit-agent-he | polkit-agent-helper-1 | fprintd-verify)
      sleep 0.1
      ;;
    *)
      break
      ;;
  esac
done
exit 0
