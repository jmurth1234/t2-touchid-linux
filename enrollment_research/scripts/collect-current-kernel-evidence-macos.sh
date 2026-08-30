#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

usage() {
  cat >&2 <<EOF
Usage: $0 [OUTPUT_DIRECTORY]

Copies the running macOS kernel collections and non-secret version metadata.
The default destination is /Volumes/OMARCHY_EFI/t2-current-kernel-evidence.
EOF
  exit 2
}

[[ $(uname -s) == Darwin ]] || {
  echo "This collector must run on macOS." >&2
  exit 1
}
[[ $# -le 1 ]] || usage

output=${1:-/Volumes/OMARCHY_EFI/t2-current-kernel-evidence}
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

work=$(mktemp -d /tmp/t2-kernel-evidence.XXXXXX)
cleanup() {
  sudo rm -rf -- "$work" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
umask 077
mkdir -p "$work/kernel-collections" "$work/kext-metadata" \
  "$work/caller-identities"

echo "This performs read-only collection of Apple-supplied system binaries."
echo "It does not access passwords, keybags, Catacomb data, or fingerprints."
sudo -v

{
  printf 'captured_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  sw_vers
  uname -a
  printf 'hardware_model='; sysctl -n hw.model
  printf 'boot_uuid='; sysctl -n kern.bootsessionuuid 2>/dev/null || true
} > "$work/environment.txt"

sudo kmutil showloaded --list-only > "$work/kmutil-showloaded.txt" 2>&1
grep -E 'AppleKeyStore|AppleCredentialManager|AppleSEP|Biometric' \
  "$work/kmutil-showloaded.txt" > "$work/relevant-loaded-kexts.txt" || true

# Selector 42 is invoked by LocalAuthentication/AKS host processes. Preserve
# their public code-signing identity and executable, where present, so Linux
# can test the exact 20-byte caller CDHash instead of guessing one. These are
# Apple system binaries and metadata only; no user credential data is read.
caller_candidates=(
  /System/Library/Frameworks/LocalAuthentication.framework/Support/LocalAuthenticationRemoteService
  /System/Library/PrivateFrameworks/LocalAuthentication.framework/Support/LocalAuthenticationRemoteService
  /usr/libexec/coreauthd
  /usr/libexec/applekeystored
  /usr/libexec/authd
  /usr/libexec/securityd
  /usr/libexec/biometrickitd
)
for executable in "${caller_candidates[@]}"; do
  [[ -f $executable ]] || continue
  name=$(basename "$executable")
  destination="$work/caller-identities/$name"
  if [[ -e $destination ]]; then
    destination="$work/caller-identities/${name}-$(printf '%s' "$executable" | shasum -a 256 | cut -c1-12)"
  fi
  sudo /bin/cp -X "$executable" "$destination"
  codesign -d --verbose=4 "$executable" >"$destination.codesign.txt" 2>&1 || true
  codesign -d --entitlements :- "$executable" >"$destination.entitlements.plist" 2>&1 || true
done

find /System/Library /usr/libexec -type f -name LocalAuthenticationRemoteService \
  -print >"$work/caller-identities/locations.txt" 2>/dev/null || true

for bundle in \
  /System/Library/Extensions/AppleKeyStore.kext \
  /System/Library/Extensions/AppleCredentialManager.kext \
  /System/Library/Extensions/AppleSEPManager.kext; do
  [[ -d $bundle ]] || continue
  name=$(basename "$bundle" .kext)
  for plist in "$bundle/Contents/Info.plist" "$bundle/Contents/version.plist"; do
    [[ -f $plist ]] || continue
    sudo plutil -convert xml1 -o "$work/kext-metadata/$name-$(basename "$plist")" \
      "$plist"
  done
done

found=0
for collection in \
  /System/Library/KernelCollections/BootKernelExtensions.kc \
  /System/Library/KernelCollections/SystemKernelExtensions.kc \
  /System/Library/KernelCollections/AuxiliaryKernelExtensions.kc; do
  [[ -f $collection ]] || continue
  size=$(stat -f %z "$collection")
  if [[ $size -gt 1073741824 ]]; then
    echo "Refusing unexpectedly large kernel collection: $collection ($size bytes)" >&2
    exit 1
  fi
  echo "Copying $collection ($size bytes)"
  sudo /bin/cp -X "$collection" "$work/kernel-collections/$(basename "$collection")"
  found=$((found + 1))
done

if [[ $found -eq 0 ]]; then
  echo "No kernel collection was found under /System/Library/KernelCollections." >&2
  echo "Available candidates:" >&2
  sudo find /System/Volumes/Preboot /System/Library -type f -name '*.kc' -print \
    2>/dev/null | head -n 100 >&2 || true
  exit 1
fi

sudo chown -R "$(id -u):$(id -g)" "$work"
(
  cd "$work"
  find . -type f ! -name MANIFEST.sha256 -print \
    | LC_ALL=C sort \
    | while IFS= read -r file; do
        shasum -a 256 "$file"
      done
) > "$work/MANIFEST.sha256"

mkdir "$output"
/bin/cp -RX "$work"/. "$output"/
find "$output" -type f -exec chmod 600 {} +
find "$output" -type d -exec chmod 700 {} +

echo
echo "Created: $output"
echo "Reboot into Linux and tell Codex it is ready."
