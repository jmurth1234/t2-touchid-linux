#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

usage() {
  cat >&2 <<EOF
Usage: $0 [OUTPUT_ARCHIVE]

Creates one private .tar.gz containing a consistent Catacomb copy and the
read-only macOS account/persona metadata needed by the enrollment research.
EOF
  exit 2
}

[[ $(uname -s) == Darwin ]] || { echo "This collector must run on macOS." >&2; exit 1; }
[[ $# -le 1 ]] || usage
[[ $EUID -ne 0 ]] || {
  echo "Run this as your normal macOS user; it invokes sudo only when needed." >&2
  exit 1
}

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
output=${1:-"$PWD/t2-enrollment-evidence-$timestamp.tar.gz"}
case $output in
  /*) ;;
  *) output="$PWD/$output" ;;
esac
[[ ! -e $output ]] || { echo "Refusing to overwrite: $output" >&2; exit 1; }

console_user=$(stat -f '%Su' /dev/console 2>/dev/null || true)
[[ -n $console_user && $console_user != root ]] || {
  echo "Could not determine the logged-in macOS user." >&2
  exit 1
}
caller_uid=$(id -u)
caller_gid=$(id -g)
work=$(mktemp -d /tmp/t2-enrollment-evidence.XXXXXX)
evidence=$work/evidence
daemon_pid=""

cleanup() {
  if [[ -n $daemon_pid ]]; then
    sudo kill -CONT "$daemon_pid" >/dev/null 2>&1 || true
  fi
  sudo rm -rf -- "$work" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

umask 077
mkdir -p "$evidence/catacomb" "$evidence/persona" "$evidence/account"
chmod 700 "$work" "$evidence" "$evidence"/*

echo "This collects private biometric/account metadata."
echo "It performs no enrollment, deletion, keybag, or SEP command."
echo "macOS will request administrator authentication for protected reads."
sudo -v

{
  printf 'captured_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'console_user=%s\n' "$console_user"
  sw_vers 2>/dev/null || true
  uname -a
  sysctl -n kern.boottime 2>/dev/null || true
} > "$evidence/environment.txt"

dscl . -read "/Users/$console_user" \
  RecordName UniqueID PrimaryGroupID GeneratedUID NFSHomeDirectory UserShell \
  > "$evidence/account/console-user.txt" 2>&1

{
  hostinfo 2>/dev/null | sed -n '/host UUID/p' || true
  ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null \
    | sed -n '/IOPlatformUUID/p' || true
} > "$evidence/account/host-uuid.txt"

persona=/private/var/db/keybags/persona.kb
if sudo test -f "$persona"; then
  sudo cp -p "$persona" "$evidence/persona/persona.kb"
  sudo plutil -p "$persona" > "$evidence/persona/persona.txt" 2>&1 || true
else
  echo "persona.kb not present" > "$evidence/persona/NOT_PRESENT.txt"
fi

catacomb_root=/Library/Catacomb
if ! sudo test -d "$catacomb_root"; then
  echo "$catacomb_root not present" > "$evidence/catacomb/NOT_PRESENT.txt"
else
  daemon_pid=$(pgrep -x biometrickitd | head -n 1 || true)
  [[ -n $daemon_pid ]] || {
    echo "biometrickitd is not running; refusing an inconsistent Catacomb copy." >&2
    exit 1
  }

  echo "Briefly freezing biometrickitd for a point-in-time Catacomb copy."
  sudo kill -STOP "$daemon_pid"

  sudo find "$catacomb_root" -exec stat -f '%Sp %Su:%Sg %z %m %N' {} \; \
    > "$evidence/catacomb/source-stat.txt" 2>&1 || true
  sudo find "$catacomb_root" -exec ls -ldeO@ {} \; \
    > "$evidence/catacomb/source-flags-acls-xattrs.txt" 2>&1 || true
  sudo xattr -lr "$catacomb_root" \
    > "$evidence/catacomb/source-xattrs.txt" 2>&1 || true
  sudo ditto --noqtn "$catacomb_root" "$evidence/catacomb/files"

  sudo kill -CONT "$daemon_pid"
  daemon_pid=""
  echo "biometrickitd resumed."
fi

cat > "$evidence/UNRESOLVED.txt" <<'EOF'
Not collected by this script:
- AKSIdentityList top-level identity UUIDs
- live keybag handle/UUID state
- selector-0x61 keybag-persona UUID list
- final T2 mode-0 enrollment acceptance/replay behavior

The first three require a separately reviewed read-only AppleKeyStore helper.
The last requires the separately approved, journaled disposable-finger test.
Do not infer any missing value from another UUID namespace.
EOF

sudo chown -R "$caller_uid:$caller_gid" "$evidence"
chmod -R go-rwx "$evidence"
find "$evidence" -type f ! -name MANIFEST.sha256 -print0 \
  | LC_ALL=C sort -z \
  | xargs -0 shasum -a 256 > "$evidence/MANIFEST.sha256"

archive_tmp=$work/t2-enrollment-evidence.tar.gz
tar -C "$work" -czf "$archive_tmp" evidence
chmod 600 "$archive_tmp"
tar -tzf "$archive_tmp" >/dev/null
if [[ -w $(dirname "$output") ]]; then
  mv "$archive_tmp" "$output"
else
  sudo cp "$archive_tmp" "$output"
  sudo chmod 600 "$output" 2>/dev/null || true
fi

echo
echo "Created private archive: $output"
echo "Keep it private. Do not upload it to GitHub or any public service."
echo "Reboot into Linux, copy it into your home directory, and tell Codex the path."
