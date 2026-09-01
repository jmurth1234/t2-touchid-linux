#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Report redacted prerequisites for a staged read-only user-broker test."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
SOURCE = (
    LOCAL_SOURCE
    if (LOCAL_SOURCE / "t2_user_broker_exposure_gate.py").is_file()
    else INSTALLED_SOURCE
)
sys.path.insert(0, str(SOURCE))

import t2_user_broker_exposure_gate
import t2_user_mapping_admin


class UserBrokerGateCommandError(RuntimeError):
    pass


def _load(name: str, filename: str):
    path = SOURCE / filename
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise UserBrokerGateCommandError("gate collector is unavailable")
    module = importlib.util.module_from_spec(specification)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        specification.loader.exec_module(module)
    except Exception as error:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise UserBrokerGateCommandError("gate collector cannot load") from error
    return module


def collect(acknowledged: bool) -> t2_user_broker_exposure_gate.ExposureGateResult:
    if os.geteuid() != 0:
        raise UserBrokerGateCommandError("run through sudo")
    doctor = _load("t2_user_broker_gate_doctor", "t2-touchid-doctor.py")
    observer = _load("t2_user_broker_gate_observer", "t2-aks-observe-test.py")
    identities = _load(
        "t2_user_broker_gate_identities", "t2-touchid-identities.py"
    )
    module_check = doctor.module_build_check()
    try:
        alias_observation = observer.collect()
    except Exception:
        alias_observation = None
    try:
        identity_inventory = identities.collect()
    except Exception:
        identity_inventory = None
    try:
        mapping_status = t2_user_mapping_admin.status()
    except t2_user_mapping_admin.UserMappingAdminError:
        mapping_status = None
    return t2_user_broker_exposure_gate.evaluate(
        module_build_current=(
            getattr(module_check, "status", None) == "pass"
            and getattr(module_check, "name", None) == "module-build"
        ),
        alias_observation=alias_observation,
        identity_inventory=identity_inventory,
        mapping_status=mapping_status,
        fingerprint_survivors_acknowledged_this_boot=acknowledged,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--acknowledge-two-distinct-fingers-verified-this-boot",
        action="store_true",
        help="confirm two distinct enrolled fingers matched after this boot",
    )
    arguments = parser.parse_args()
    try:
        result = collect(
            arguments.acknowledge_two_distinct_fingers_verified_this_boot
        )
    except (
        OSError,
        UserBrokerGateCommandError,
        t2_user_broker_exposure_gate.UserBrokerExposureGateError,
    ):
        print("t2-touchid-user-broker-gate: collection failed", file=sys.stderr)
        return 2
    print(json.dumps(result.public(), sort_keys=True, indent=2))
    return 0 if result.ready_for_staged_negative_test else 1


if __name__ == "__main__":
    raise SystemExit(main())
