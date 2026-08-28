#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

[[ $(uname -s) == Darwin ]] || { echo "This collector must run on macOS." >&2; exit 1; }
[[ $# == 2 ]] || { echo "Usage: sudo $0 USERNAME OUTPUT_DIRECTORY" >&2; exit 2; }

username=$1
output=$2
[[ $username =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid account name." >&2; exit 2; }
[[ ! -e $output ]] || { echo "Refusing to overwrite: $output" >&2; exit 1; }

umask 077
mkdir -p "$output/private"
chmod 700 "$output" "$output/private"

{
  sw_vers 2>/dev/null || true
  printf 'captured_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'account=%s\n' "$username"
  dscl . -read "/Users/$username" UniqueID GeneratedUID NFSHomeDirectory 2>&1
  hostinfo 2>/dev/null | sed -n '/host UUID/p' || true
} > "$output/account.txt"

persona=/private/var/db/keybags/persona.kb
if [[ -f $persona ]]; then
  cp -p "$persona" "$output/private/persona.kb"
  shasum -a 256 "$output/private/persona.kb" > "$output/persona.sha256"
  plutil -p "$output/private/persona.kb" > "$output/private/persona.txt" 2>&1 || true
else
  echo "persona.kb not present" > "$output/persona.sha256"
fi

cat > "$output/UNRESOLVED.txt" <<'EOF'
Not collected by this script:
- AKSIdentityList top-level identity UUIDs
- loaded keybag UUID for the selected identity
- selector-0x61 keybag-persona UUID list

These need a separately reviewed read-only AppleKeyStore helper. Do not infer
their values from similarly shaped UUIDs in this capture.
EOF

chmod -R go-rwx "$output"
echo "Private inventory written to: $output"
echo "Do not commit or publish this directory."
