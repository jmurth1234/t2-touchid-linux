#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
OUTPUT="$SCRIPT_DIR/t2-touchid-catacomb.tar.gz"
DIAGNOSTIC="$SCRIPT_DIR/t2-touchid-catacomb-diagnostic.tar.gz"
WORK_DIR="$(mktemp -d /tmp/t2-touchid-catacomb.XXXXXX)"
PATH_LIST="$WORK_DIR/template-paths.txt"
FREEZE_AND_REBOOT=1
FROZEN_PID=""

case "${1:-}" in
  "") ;;
  --freeze-and-reboot) FREEZE_AND_REBOOT=1 ;;
  --no-reboot) FREEZE_AND_REBOOT=0 ;;
  *)
    echo "Usage: $0 [--freeze-and-reboot|--no-reboot]" >&2
    exit 2
    ;;
esac

cleanup() {
  if [[ -n "$FROZEN_PID" ]]; then
    sudo kill -CONT "$FROZEN_PID" >/dev/null 2>&1 || true
  fi
  sudo rm -rf -- "$WORK_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

echo "Locating the macOS Touch ID template store."
echo "macOS may ask for your administrator password."

DAEMON_PID="$(pgrep -x biometrickitd | head -n 1 || true)"
DAEMON_USER=""
DAEMON_HOME=""
if [[ -n "$DAEMON_PID" ]]; then
  DAEMON_USER="$(ps -o user= -p "$DAEMON_PID" | awk '{$1=$1; print}')"
  if [[ -n "$DAEMON_USER" ]]; then
    DAEMON_HOME="$(dscl . -read "/Users/$DAEMON_USER" NFSHomeDirectory 2>/dev/null | sed 's/^NFSHomeDirectory:[[:space:]]*//' || true)"
  fi
fi

{
  echo "biometrickitd_pid=$DAEMON_PID"
  echo "biometrickitd_user=$DAEMON_USER"
  echo "biometrickitd_home=$DAEMON_HOME"
  sw_vers 2>/dev/null || true
} > "$WORK_DIR/environment.txt"

(sudo find /private/var /Library \
  -type f -name 'TemplateList.cat' -print 2>/dev/null || true) \
  | sort -u > "$PATH_LIST"

if [[ -s "$PATH_LIST" ]]; then
  echo "Found Touch ID template store:"
  sed 's/^/  /' "$PATH_LIST"
  sudo tar -czf "$OUTPUT.tmp.$$" -T "$PATH_LIST"
  sudo mv -f -- "$OUTPUT.tmp.$$" "$OUTPUT"
  sudo chmod 600 "$OUTPUT" 2>/dev/null || true
  echo "Created: $OUTPUT"
elif [[ -d /Library/Catacomb ]]; then
  CATACOMB_KIB="$(sudo du -sk /Library/Catacomb 2>/dev/null | awk '{print $1}')"
  CATACOMB_KIB="${CATACOMB_KIB:-0}"
  USER_CATACOMB="$(sudo find /Library/Catacomb -type f -name 'user_*.cat' -size +0c -print -quit 2>/dev/null || true)"
  EFI_FREE_KIB="$(df -k "$SCRIPT_DIR" | awk 'NR == 2 {print $4}')"
  EFI_FREE_KIB="${EFI_FREE_KIB:-0}"
  echo "Found the macOS system Catacomb backing store (${CATACOMB_KIB} KiB)."
  if (( CATACOMB_KIB <= 0 )); then
    echo "Could not read the Catacomb backing store." >&2
    exit 1
  fi
  if (( FREEZE_AND_REBOOT )) && [[ -z "$USER_CATACOMB" ]]; then
    echo "No enrolled-user Catacomb exists yet." >&2
    echo "Enroll a fingerprint in Touch ID settings, confirm it is listed, then rerun this helper." >&2
    exit 1
  fi
  if (( CATACOMB_KIB + 16384 >= EFI_FREE_KIB )); then
    echo "Not enough free EFI space to export it safely." >&2
    exit 1
  fi
  if (( FREEZE_AND_REBOOT )); then
    if [[ -z "$DAEMON_PID" ]]; then
      echo "biometrickitd is not running; refusing a controlled frozen export." >&2
      exit 1
    fi
    echo "Freezing biometrickitd to prevent the exported state being superseded."
    sudo kill -STOP "$DAEMON_PID"
    FROZEN_PID="$DAEMON_PID"
  fi
  sudo tar -C / -czf "$OUTPUT.tmp.$$" Library/Catacomb
  sudo mv -f -- "$OUTPUT.tmp.$$" "$OUTPUT"
  sudo chmod 600 "$OUTPUT" 2>/dev/null || true
  sync "$OUTPUT" 2>/dev/null || sync
  echo "Created: $OUTPUT"
else
  echo "No TemplateList.cat file was found. Creating a diagnostic archive."
  sudo launchctl print system/com.apple.biometrickitd \
    > "$WORK_DIR/launchctl-biometrickitd.txt" 2>&1 || true
  (sudo find /private/var /Library \
    -type d -name Catacomb -print 2>/dev/null || true) \
    | sort -u > "$WORK_DIR/catacomb-directories.txt"
  tar -C "$WORK_DIR" -czf "$DIAGNOSTIC.tmp.$$" \
    environment.txt template-paths.txt catacomb-directories.txt \
    launchctl-biometrickitd.txt
  mv -f -- "$DIAGNOSTIC.tmp.$$" "$DIAGNOSTIC"
  chmod 600 "$DIAGNOSTIC" 2>/dev/null || true
  echo "Created: $DIAGNOSTIC"
fi

if (( FREEZE_AND_REBOOT )); then
  if [[ -z "$FROZEN_PID" ]]; then
    echo "A Catacomb archive was not produced; refusing to reboot." >&2
    exit 1
  fi
  echo "Archive flushed. Rebooting immediately; choose Linux at startup."
  if sudo shutdown -r now; then
    FROZEN_PID=""
    trap - EXIT HUP INT TERM
    exit 0
  fi
  echo "Could not schedule reboot; resuming biometrickitd." >&2
  exit 1
fi

echo "Keep the resulting archive private, then reboot into Linux and resume."
