#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -u
PATH=/usr/bin:/bin
export PATH
ulimit -c 0

TOOL=/usr/local/sbin/t2-aks-tool
STATE_FILE=/run/t2-touchid/keybag.env
READY_FILE=/run/t2-touchid/keybags-unlocked
REJECTED_FILE=/run/t2-touchid/keybag-password-rejected
CREDENTIAL_NAME=t2-touchid-password

[[ -n ${CREDENTIALS_DIRECTORY:-} ]] || exit 1
credential=$CREDENTIALS_DIRECTORY/$CREDENTIAL_NAME
[[ -r $credential && -r $STATE_FILE && -x $TOOL ]] || exit 1

rm -f -- "$READY_FILE" "$REJECTED_FILE"
snapshot=$(mktemp "${READY_FILE}.XXXXXX") || exit 1
trap 'rm -f -- "$snapshot"' EXIT
install -o root -g root -m 0600 "$STATE_FILE" "$snapshot" || exit 1
session=$(sed -n 's/^T2_KEYBAG_SESSION=\([0-9][0-9]*\)$/\1/p' "$snapshot")
handle=$(sed -n 's/^T2_KEYBAG_HANDLE=\(-\{0,1\}[0-9][0-9]*\)$/\1/p' "$snapshot")
special=$(sed -n 's/^T2_KEYBAG_SPECIAL=\(-\{0,1\}[0-9][0-9]*\)$/\1/p' "$snapshot")
[[ -n $session && -n $handle && -n $special ]] || exit 1

normal_ok=0
special_ok=0
normal_status=0
special_status=0
"$TOOL" unlock-keybag-stdin "$session" "$handle" <"$credential" >/dev/null 2>&1 \
  && normal_ok=1 || normal_status=$?
"$TOOL" unlock-keybag-stdin "$session" "$special" <"$credential" >/dev/null 2>&1 \
  && special_ok=1 || special_status=$?

if [[ $normal_ok == 1 && $special_ok == 1 ]] && cmp -s -- "$snapshot" "$STATE_FILE"; then
  mv -f -- "$snapshot" "$READY_FILE"
  trap - EXIT
  logger --priority authpriv.info --tag t2-credential-unlock 'keybags unlocked from encrypted system credential'
  exit 0
fi
if [[ $normal_status == 3 || $special_status == 3 ]]; then
  install -o root -g root -m 0600 /dev/null "$REJECTED_FILE" || true
fi
logger --priority authpriv.warning --tag t2-credential-unlock 'encrypted-credential keybag unlock failed closed'
exit 1
