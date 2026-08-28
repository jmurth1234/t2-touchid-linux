#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
cd "$root"

if git ls-files --others --cached --exclude-standard enrollment_research \
  | rg -i '\.(cat|kb|im4p|ipsw|pcap|tar|zip)$|(^|/)(evidence|private|captures?)(/|$)'; then
  echo "Private or redistributable artifact detected in enrollment_research." >&2
  exit 1
fi

if rg -n -i '/home/|/Users/[^<][^/ ]*|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|fe80::[0-9a-f]' \
  enrollment_research/FINDINGS.md enrollment_research/README.md \
  enrollment_research/EVIDENCE_COLLECTION.md; then
  echo "Possible local identifier, address, or secret detected." >&2
  exit 1
fi

echo "Enrollment research public-tree scan passed."
