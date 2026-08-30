#!/usr/bin/env python3
"""Observe policy 1007 without binding a password or enrolling a finger."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
if INSTALLED_SOURCE.is_dir():
    sys.path.insert(0, str(INSTALLED_SOURCE))

from t2_acm_device import ACMDevice, ACMDeviceError, policy_preflight_test

CONFIG = Path("/etc/t2-touchid.conf")


def configured_user_id() -> int:
    info = CONFIG.stat()
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise ACMDeviceError("configuration ownership or mode is unsafe")
    matches = []
    for line in CONFIG.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"T2_TOUCHID_MACOS_USER_ID=([0-9]+)", line)
        if match:
            matches.append(int(match.group(1)))
    if len(matches) != 1 or not 0 <= matches[0] <= 0xFFFFFFFF:
        raise ACMDeviceError("configuration has no unique valid macOS user ID")
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--acknowledge-transient-context-mutation", action="store_true", required=True
    )
    args = parser.parse_args()
    if not args.acknowledge_transient_context_mutation:
        return 2
    if os.geteuid() != 0:
        print("t2-acm-policy-preflight must run as root", file=sys.stderr)
        return 2
    try:
        user_id = configured_user_id()
        with ACMDevice() as device:
            result = policy_preflight_test(device, user_id)
    except (OSError, ValueError, ACMDeviceError) as error:
        print(f"t2-acm-policy-preflight: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
