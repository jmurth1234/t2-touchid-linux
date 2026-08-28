#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$root"

if git ls-files | grep -E '\.(kb|cat|pcap|pcapng)$|(^|/)(credential|catacomb)(/|$)' >/dev/null; then
  echo "Tracked private-artifact filename detected." >&2
  exit 1
fi
if git grep -IEn '(T2_TOUCHID_HOST=fe80::[0-9a-f]|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|identity_uuid.{0,8}[0-9a-f]{8}-)' -- \
  ':!tools/privacy-check.sh' ':!README.md' ':!SECURITY.md'; then
  echo "Possible identifier or secret detected." >&2
  exit 1
fi
echo "Privacy scan passed."
