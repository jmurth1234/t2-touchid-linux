#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu

TOOL=/usr/local/sbin/t2-aks-tool
BAG=/var/lib/t2-touchid/user.kb
SESSION=1
SPECIAL_BAG=-501

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
printf 'loaded keybag handle=%s session=%s special=%s\n' \
	"$handle" "$SESSION" "$SPECIAL_BAG"
