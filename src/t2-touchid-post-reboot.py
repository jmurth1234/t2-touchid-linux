#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Automatically prove a completed biometric mutation survived a fresh boot."""

from __future__ import annotations

import json
import sys

import t2_post_reboot_reconciler


def main() -> int:
    try:
        result = t2_post_reboot_reconciler.run()
    except t2_post_reboot_reconciler.PostRebootReconcilerError:
        print(
            "t2-touchid-post-reboot: reconciliation stopped; "
            "inspect the private service journal",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result.redacted(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
