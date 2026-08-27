#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -u
PATH=/usr/bin:/bin
export PATH
ulimit -c 0

TOOL=/usr/local/sbin/t2-aks-tool
STATE_FILE=/run/t2-touchid/keybag.env
CREDENTIAL_NAME=t2-touchid-password

[[ -n ${CREDENTIALS_DIRECTORY:-} ]] || exit 1
credential=$CREDENTIALS_DIRECTORY/$CREDENTIAL_NAME
[[ -r $credential && -r $STATE_FILE && -x $TOOL ]] || exit 1

session=$(sed -n 's/^T2_KEYBAG_SESSION=\([0-9][0-9]*\)$/\1/p' "$STATE_FILE")
handle=$(sed -n 's/^T2_KEYBAG_HANDLE=\(-\{0,1\}[0-9][0-9]*\)$/\1/p' "$STATE_FILE")
special=$(sed -n 's/^T2_KEYBAG_SPECIAL=\(-\{0,1\}[0-9][0-9]*\)$/\1/p' "$STATE_FILE")
[[ -n $session && -n $handle && -n $special ]] || exit 1

normal_ok=0
special_ok=0
"$TOOL" unlock-keybag-stdin "$session" "$handle" <"$credential" >/dev/null 2>&1 && normal_ok=1
"$TOOL" unlock-keybag-stdin "$session" "$special" <"$credential" >/dev/null 2>&1 && special_ok=1

if [[ $normal_ok == 1 && $special_ok == 1 ]]; then
  logger --priority authpriv.info --tag t2-credential-unlock 'keybags unlocked from encrypted system credential'
  exit 0
fi
logger --priority authpriv.warning --tag t2-credential-unlock 'encrypted-credential keybag unlock failed closed'
exit 1
