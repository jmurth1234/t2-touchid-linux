#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Report whether the uninstalled native fprint enrollment switch may be staged."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
SOURCE = (
    LOCAL_SOURCE
    if (LOCAL_SOURCE / "t2_fprint_activation_gate.py").is_file()
    else INSTALLED_SOURCE
)
sys.path.insert(0, str(SOURCE))

import t2_fprint_activation_gate
import t2_fprint_projection
import t2_user_broker_exposure_gate
import t2_user_mapping_admin


class FprintEnrollmentGateCommandError(RuntimeError):
    pass


def _load(name: str, filename: str):
    path = SOURCE / filename
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise FprintEnrollmentGateCommandError("gate collector is unavailable")
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
        raise FprintEnrollmentGateCommandError(
            "gate collector cannot load"
        ) from error
    return module


def _effective_daemon_is_default_off() -> bool:
    try:
        result = subprocess.run(
            (
                "/usr/bin/systemctl",
                "show",
                "fprintd.service",
                "--property=ExecStart",
                "--value",
            ),
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return (
        result.returncode == 0
        and bool(result.stdout.strip())
        and "--enable-native-enrollment" not in result.stdout
    )


def collect(
    *,
    two_fingers_acknowledged: bool,
    password_fallback_acknowledged: bool,
    worker_negative_controls_acknowledged: bool,
) -> t2_fprint_activation_gate.FprintActivationGateResult:
    if os.geteuid() != 0:
        raise FprintEnrollmentGateCommandError("run through sudo")
    doctor = _load("t2_fprint_enrollment_gate_doctor", "t2-touchid-doctor.py")
    observer = _load(
        "t2_fprint_enrollment_gate_observer", "t2-aks-observe-test.py"
    )
    identities = _load(
        "t2_fprint_enrollment_gate_identities", "t2-touchid-identities.py"
    )
    enrollment = _load(
        "t2_fprint_enrollment_gate_enrollment",
        "t2-touchid-enroll-test.py",
    )
    management = _load(
        "t2_fprint_enrollment_gate_management", "t2-touchid-manage.py"
    )
    checks = doctor.collect()
    statuses: dict[str, str] = {}
    for check in checks:
        name = getattr(check, "name", None)
        status = getattr(check, "status", None)
        if name in t2_fprint_activation_gate.REQUIRED_HEALTH_CHECKS:
            if name in statuses or status not in {"pass", "warn", "fail"}:
                raise FprintEnrollmentGateCommandError(
                    "health report is ambiguous"
                )
            statuses[name] = status
    inventory = identities.collect()
    projection = t2_fprint_projection.project(inventory)
    mapping_status = t2_user_mapping_admin.status()
    exposure = t2_user_broker_exposure_gate.evaluate(
        module_build_current=(statuses.get("module-build") == "pass"),
        alias_observation=observer.collect(),
        identity_inventory=inventory,
        mapping_status=mapping_status,
        fingerprint_survivors_acknowledged_this_boot=(
            two_fingers_acknowledged
        ),
    )
    return t2_fprint_activation_gate.evaluate(
        health_checks=statuses,
        projection=projection,
        enrollment_status=enrollment.enrollment_status(),
        management_status=management.status(),
        exposure=exposure,
        password_fallback_acknowledged=password_fallback_acknowledged,
        worker_negative_controls_acknowledged=(
            worker_negative_controls_acknowledged
        ),
        installed_daemon_default_off=_effective_daemon_is_default_off(),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--acknowledge-two-distinct-fingers-verified-this-boot",
        action="store_true",
    )
    parser.add_argument(
        "--acknowledge-password-fallback-tested",
        action="store_true",
    )
    parser.add_argument(
        "--acknowledge-worker-negative-controls-passed",
        action="store_true",
    )
    arguments = parser.parse_args()
    try:
        result = collect(
            two_fingers_acknowledged=(
                arguments.acknowledge_two_distinct_fingers_verified_this_boot
            ),
            password_fallback_acknowledged=(
                arguments.acknowledge_password_fallback_tested
            ),
            worker_negative_controls_acknowledged=(
                arguments.acknowledge_worker_negative_controls_passed
            ),
        )
    except Exception:
        print(
            "t2-touchid-fprint-enrollment-gate: collection failed",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result.public(), sort_keys=True, indent=2))
    return 0 if result.ready_to_stage_research_activation else 1


if __name__ == "__main__":
    raise SystemExit(main())
