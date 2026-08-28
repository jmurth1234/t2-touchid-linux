#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

[[ $# -ge 2 ]] || { echo "Usage: $0 BINARY... OUTPUT_DIRECTORY" >&2; exit 2; }
output=${!#}
[[ ! -e $output ]] || { echo "Refusing to overwrite: $output" >&2; exit 1; }
mkdir -p "$output"
chmod 700 "$output"

for binary in "${@:1:$#-1}"; do
  [[ -f $binary ]] || { echo "Skipping non-file: $binary" >&2; continue; }
  name=$(basename "$binary")
  {
    echo "source=$binary"
    shasum -a 256 "$binary" 2>/dev/null || sha256sum "$binary"
    echo "[strings]"
    strings -a "$binary" | rg -i 'remove.?user|user.?data|identity|catacomb|exist|present|valid|database' || true
    echo "[symbols]"
    nm -a "$binary" 2>/dev/null | rg -i 'remove.?user|user.?data|identity|catacomb|exist|present|valid|database' || true
  } > "$output/$name.txt"
done

cat > "$output/README.txt" <<'EOF'
These are search leads, not a recovered command contract. Any candidate must be
confirmed by exact disassembly and request/reply tracing. Never probe guessed
commands against a live SEP identity store.
EOF
chmod -R go-rwx "$output"
echo "Offline search results written to: $output"
