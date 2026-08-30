#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

usage() {
  cat >&2 <<EOF
Usage: $0 [OUTPUT_DIRECTORY]

Collects current macOS code-signing identities for likely AppleKeyStore
selector-42 callers. The default destination is
/Volumes/OMARCHY_EFI/t2-aks-caller-identities.
EOF
  exit 2
}

[[ $(uname -s) == Darwin ]] || {
  echo "This collector must run on macOS." >&2
  exit 1
}
[[ $# -le 1 ]] || usage

output=${1:-/Volumes/OMARCHY_EFI/t2-aks-caller-identities}
case $output in
  /*) ;;
  *) output="$PWD/$output" ;;
esac
[[ ! -e $output ]] || {
  echo "Refusing to overwrite existing output: $output" >&2
  exit 1
}
parent=$(dirname "$output")
[[ -d $parent && -w $parent ]] || {
  echo "Output parent is not writable: $parent" >&2
  echo "Mount OMARCHY_EFI in Finder, or pass another destination." >&2
  exit 1
}

work=$(mktemp -d /tmp/t2-aks-callers.XXXXXX)
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM
umask 077
mkdir -p "$work/candidates"

echo "This reads only Apple system executables and public signing metadata."
echo "It does not access passwords, keybags, Catacomb data, or fingerprints."

{
  printf 'captured_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  sw_vers
  uname -a
  printf 'hardware_model='; sysctl -n hw.model
} >"$work/environment.txt"

{
  for root in \
    /System/Library/Frameworks \
    /System/Library/PrivateFrameworks \
    /System/Library/CoreServices \
    /System/Library/Services \
    /System/Cryptexes \
    /usr/libexec; do
    [[ -d $root ]] || continue
    find "$root" -type f \( \
      -name LocalAuthenticationRemoteService -o \
      -name coreauthd -o \
      -name applekeystored -o \
      -name authd -o \
      -name securityd -o \
      -name biometrickitd \
    \) -print 2>/dev/null || true
  done
} | LC_ALL=C sort -u >"$work/candidate-paths.txt"

count=0
while IFS= read -r executable; do
  [[ -f $executable ]] || continue
  count=$((count + 1))
  slot=$(printf 'candidate-%03d' "$count")
  destination="$work/candidates/$slot"
  mkdir "$destination"
  printf '%s\n' "$executable" >"$destination/source-path.txt"
  /bin/cp -X "$executable" "$destination/executable"
  codesign -d --verbose=6 "$executable" \
    >"$destination/codesign.txt" 2>&1 || true
  codesign -d --entitlements :- "$executable" \
    >"$destination/entitlements.plist" 2>&1 || true
  file "$executable" >"$destination/file.txt"
  shasum -a 256 "$destination/executable" >"$destination/SHA256.txt"
  {
    printf 'slot=%s\npath=%s\n' "$slot" "$executable"
    sed -n 's/^Identifier=/identifier=/p; s/^CDHash=/cdhash=/p; s/^TeamIdentifier=/team_identifier=/p' \
      "$destination/codesign.txt"
  } >>"$work/CDHASHES.txt"
  printf '\n' >>"$work/CDHASHES.txt"
done <"$work/candidate-paths.txt"

if [[ $count -eq 0 ]]; then
  echo "No candidate AppleKeyStore caller executable was found." >&2
  exit 1
fi

ps axww -o pid=,user=,comm= | \
  grep -Ei 'LocalAuthentication|coreauth|keystore|authd|securityd|biometric' \
  >"$work/relevant-processes.txt" || true

(
  cd "$work"
  find . -type f ! -name MANIFEST.sha256 -print | LC_ALL=C sort | \
    while IFS= read -r file; do
      shasum -a 256 "$file"
    done
) >"$work/MANIFEST.sha256"

mkdir "$output"
/bin/cp -RX "$work"/. "$output"/
find "$output" -type f -exec chmod 600 {} +
find "$output" -type d -exec chmod 700 {} +

echo
echo "Collected $count candidate caller identities."
echo "Created: $output"
echo "Reboot into Linux and tell Codex it is ready."
