#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
OUTPUT="$SCRIPT_DIR/t2-keybags.tar.gz"
WORK_DIR="$(mktemp -d /tmp/t2-keybags.XXXXXX)"
CANDIDATES="$WORK_DIR/state/candidates.txt"

cleanup() {
  sudo rm -rf -- "$WORK_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

echo "Exporting AppleKeyStore keybag state for the Linux Touch ID driver."
echo "macOS may ask for your administrator password."

sudo mkdir -p "$WORK_DIR/state"
sudo chmod 700 "$WORK_DIR/state"

{
  sw_vers 2>/dev/null || true
  printf 'console_user=%s\n' "$(stat -f '%Su' /dev/console 2>/dev/null || true)"
} | sudo tee "$WORK_DIR/state/environment.txt" >/dev/null

sudo touch "$CANDIDATES"
for root in \
  /System/Volumes/Preboot \
  /System/Volumes/Data/Users \
  /System/Volumes/Data/private/var \
  /Users \
  /private/var \
  /Library; do
  if sudo test -d "$root"; then
    sudo find "$root" -xdev \
      \( -type d \( -iname keybags -o -iname 'user.kb' -o -iname 'stash.kb' \) -o \
         -type f \( -iname 'user.kb' -o -iname 'stash.kb' -o \
                       -iname '*.kb' -o -iname '*keybag*' \) -size -16M \) \
      -print 2>/dev/null || true
  fi
done | sort -u | sudo tee "$CANDIDATES" >/dev/null

# candidates.txt is root-owned after sudo tee. Reading it in this shell fails
# with "Permission denied" and still produces an empty-looking archive. Copy
# under sudo and refuse to publish zero-candidate output.
copied="$(
  sudo bash -c '
    set -euo pipefail
    candidates="$1"
    state="$2"
    : > "$state/keybags-listing.txt"
    : > "$state/path-map.txt"
    index=0
    while IFS= read -r candidate; do
      test -n "$candidate" || continue
      index=$((index + 1))
      destination="$state/candidate-$(printf "%04d" "$index")"
      stat -f "%Sp %Su:%Sg %z %N" "$candidate" \
        >> "$state/keybags-listing.txt" || true
      ditto --noqtn "$candidate" "$destination"
      printf "%s\t%s\n" "$(basename "$destination")" "$candidate" \
        >> "$state/path-map.txt"
    done < "$candidates"
    printf "%s\n" "$index"
  ' bash "$CANDIDATES" "$WORK_DIR/state"
)"

if [[ "${copied:-0}" -lt 1 ]]; then
  echo "error: no keybag candidates were copied; refusing to write $OUTPUT" >&2
  exit 1
fi

sudo tar -czf "$OUTPUT.tmp.$$" -C "$WORK_DIR" state
sudo mv -f -- "$OUTPUT.tmp.$$" "$OUTPUT"
sudo chmod 600 "$OUTPUT"
sync

echo "Created: $OUTPUT"
echo "Keep this archive private. Reboot into Linux and resume the Touch ID goal."
