#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

[[ $# == 2 ]] || { echo "Usage: $0 BRIDGEOS_IPSW OUTPUT_DIRECTORY" >&2; exit 2; }
source_ipsw=$1
output=$2
[[ -f $source_ipsw ]] || { echo "Not a file: $source_ipsw" >&2; exit 1; }
[[ ! -e $output ]] || { echo "Refusing to overwrite: $output" >&2; exit 1; }

umask 077
mkdir -p "$output"
member=Firmware/all_flash/sep-firmware.j132.RELEASE.im4p
unzip -p "$source_ipsw" "$member" > "$output/sep-firmware.j132.RELEASE.im4p"
[[ -s $output/sep-firmware.j132.RELEASE.im4p ]] || { echo "SEP member not found." >&2; exit 1; }

sha256sum "$source_ipsw" "$output/sep-firmware.j132.RELEASE.im4p" > "$output/SHA256SUMS"
if command -v ipsw >/dev/null 2>&1; then
  ipsw img4 im4p info "$output/sep-firmware.j132.RELEASE.im4p" > "$output/im4p-info.txt" 2>&1 || true
  ipsw img4 im4p extract --kbag "$output/sep-firmware.j132.RELEASE.im4p" > "$output/kbag-wrapped.txt" 2>&1 || true
fi

cat > "$output/README.txt" <<'EOF'
This is an encrypted Apple SEP firmware artifact. KBAG values printed by tools
are wrapped material and are not directly usable AES keys. No decryption was
attempted. Do not commit Apple firmware to the public repository.
EOF
chmod -R go-rwx "$output"
echo "Encrypted SEP evidence written to: $output"
