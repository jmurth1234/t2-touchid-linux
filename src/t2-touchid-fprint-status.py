#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Report whether reconciled T2 labels form a truthful fprint identity list."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
SOURCE = (
    LOCAL_SOURCE
    if (LOCAL_SOURCE / "t2_fprint_projection.py").is_file()
    else INSTALLED_SOURCE
)
sys.path.insert(0, str(SOURCE))

import t2_fprint_projection


class FprintStatusError(RuntimeError):
    pass


def _load_identities():
    path = SOURCE / "t2-touchid-identities.py"
    specification = importlib.util.spec_from_file_location(
        "t2_touchid_fprint_status_identities", path
    )
    if specification is None or specification.loader is None:
        raise FprintStatusError("identity collector is unavailable")
    module = importlib.util.module_from_spec(specification)
    previous = sys.modules.get(specification.name)
    sys.modules[specification.name] = module
    try:
        specification.loader.exec_module(module)
    except Exception as error:
        if previous is None:
            sys.modules.pop(specification.name, None)
        else:
            sys.modules[specification.name] = previous
        raise FprintStatusError("identity collector cannot load") from error
    return module


def collect() -> t2_fprint_projection.FprintProjection:
    identities = _load_identities()
    try:
        inventory = identities.collect()
    except Exception as error:
        raise FprintStatusError(
            "reconciled identity inventory is unavailable"
        ) from error
    try:
        return t2_fprint_projection.project(inventory)
    except t2_fprint_projection.FprintProjectionError as error:
        raise FprintStatusError("fprint projection is unavailable") from error


def main() -> int:
    if len(sys.argv) != 1:
        print("t2-touchid-fprint-status: no arguments permitted", file=sys.stderr)
        return 2
    try:
        result = collect()
    except FprintStatusError:
        print("t2-touchid-fprint-status: unavailable", file=sys.stderr)
        return 1
    print(json.dumps(result.public(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
