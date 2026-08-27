#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
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

sudo sh -c ': > "$1"' sh "$WORK_DIR/state/keybags-listing.txt"
index=0
while IFS= read -r candidate; do
  test -n "$candidate" || continue
  index=$((index + 1))
  destination="$WORK_DIR/state/candidate-$(printf '%04d' "$index")"
  sudo stat -f '%Sp %Su:%Sg %z %N' "$candidate" \
    | sudo tee -a "$WORK_DIR/state/keybags-listing.txt" >/dev/null || true
  sudo ditto --noqtn "$candidate" "$destination"
  printf '%s\t%s\n' "$(basename "$destination")" "$candidate" \
    | sudo tee -a "$WORK_DIR/state/path-map.txt" >/dev/null
done < "$CANDIDATES"

sudo tar -czf "$OUTPUT.tmp.$$" -C "$WORK_DIR" state
sudo mv -f -- "$OUTPUT.tmp.$$" "$OUTPUT"
sudo chmod 600 "$OUTPUT"
sync

echo "Created: $OUTPUT"
echo "Keep this archive private. Reboot into Linux and resume the Touch ID goal."
