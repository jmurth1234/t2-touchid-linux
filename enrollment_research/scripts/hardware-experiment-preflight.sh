#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

[[ $# == 1 ]] || { echo "Usage: $0 OUTPUT_DIRECTORY" >&2; exit 2; }
output=$1
[[ ! -e $output ]] || { echo "Refusing to overwrite: $output" >&2; exit 1; }
umask 077
mkdir -p "$output"

cat > "$output/CHECKLIST.md" <<'EOF'
# Controlled enrollment experiment prerequisites

- [ ] A disposable enrolled identity/finger is selected; it is not the only working login path.
- [ ] Password login and macOS recovery were tested immediately before the experiment.
- [ ] Stable read-only inventory works and records exact UID + identity UUIDs.
- [ ] Raw Catacomb fixtures were backed up, hashed, and independently decoded.
- [ ] Strict Catacomb writer output passes independent read-back tests.
- [ ] Endpoint-10 ACM broker passes non-mutating create/export/policy/destroy tests.
- [ ] Per-component intent/result journal survives process and power loss.
- [ ] Suspend and reconnect invalidate the operation and authorization context.
- [ ] The exact proposed mutating command and immutable target were reviewed.
- [ ] The operator explicitly approved this single experiment.

This preflight performs no enrollment, deletion, keybag, Catacomb, or SEP
operation. A separate reviewed experiment must refuse to run until every item
has independently verifiable evidence.
EOF

{
  printf 'generated_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  uname -a
  git -C "$(dirname "$0")/../.." rev-parse HEAD 2>/dev/null || true
} > "$output/environment.txt"
chmod -R go-rwx "$output"

echo "Preflight checklist written to: $output"
echo "No hardware operation was performed."
exit 3
