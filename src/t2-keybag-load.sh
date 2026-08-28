#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu

TOOL=/usr/local/sbin/t2-aks-tool
BAG=/var/lib/t2-touchid/user.kb
SESSION=1
CONFIG_FILE=/etc/t2-touchid.conf
SPECIAL_BAG=$(sed -n 's/^T2_TOUCHID_SPECIAL_BAG=//p' "$CONFIG_FILE" | tail -n 1)
printf '%s\n' "$SPECIAL_BAG" | grep -Eq '^-[0-9]+$' || {
	echo "invalid T2_TOUCHID_SPECIAL_BAG" >&2
	exit 1
}
STATE_DIR=/run/t2-touchid
STATE_FILE=$STATE_DIR/keybag.env

output="$($TOOL load-keybag "$BAG" "$SESSION")"
case "$output" in
	status=0\ handle=*\ response_length=*) ;;
	*)
		echo "unexpected load-keybag result: $output" >&2
		exit 1
		;;
esac
handle=${output#*handle=}
handle=${handle%% *}
$TOOL set-system-keybag "$SESSION" "$handle" "$SPECIAL_BAG"
install -d -o root -g root -m 0700 "$STATE_DIR"
umask 077
printf 'T2_KEYBAG_SESSION=%s\nT2_KEYBAG_HANDLE=%s\nT2_KEYBAG_SPECIAL=%s\n' \
	"$SESSION" "$handle" "$SPECIAL_BAG" >"$STATE_FILE"
printf 'loaded keybag handle=%s session=%s special=%s\n' \
	"$handle" "$SESSION" "$SPECIAL_BAG"
