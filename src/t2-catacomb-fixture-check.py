#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Validate a private macOS Catacomb capture without printing identifiers."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
if (LOCAL_SOURCE / "t2_catacomb_fixture.py").is_file():
    sys.path.insert(0, str(LOCAL_SOURCE))
elif INSTALLED_SOURCE.is_dir():
    sys.path.insert(0, str(INSTALLED_SOURCE))

from t2_catacomb_fixture import FixtureCheckError, check_archive


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path, help="private macOS evidence archive")
    parser.add_argument(
        "--apple-user-id",
        type=int,
        required=True,
        help="expected numeric Apple user ID",
    )
    args = parser.parse_args()
    try:
        result = check_archive(args.archive, args.apple_user_id)
    except (FixtureCheckError, OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
