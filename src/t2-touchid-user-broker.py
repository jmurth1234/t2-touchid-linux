#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Disabled-by-default entry point for one read-only broker connection."""

from __future__ import annotations

import sys
from pathlib import Path


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
if (LOCAL_SOURCE / "t2_user_broker_socket_activation.py").is_file():
    sys.path.insert(0, str(LOCAL_SOURCE))
elif INSTALLED_SOURCE.is_dir():
    sys.path.insert(0, str(INSTALLED_SOURCE))

import t2_user_broker_socket_activation


def main() -> int:
    try:
        t2_user_broker_socket_activation.run_once(
            modification_allowed=False,
            allow_user_interaction=True,
        )
    except t2_user_broker_socket_activation.UserBrokerSocketActivationError:
        print("t2-touchid-user-broker: request failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
