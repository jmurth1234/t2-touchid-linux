# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "src"
sys.path.insert(0, str(SOURCE))

import t2_user_mapping_admin as mapping_admin
from tests import test_fprint_activation_gate as fixtures


SPEC = importlib.util.spec_from_file_location(
    "t2_touchid_fprint_enrollment_gate_command",
    SOURCE / "t2-touchid-fprint-enrollment-gate.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def inventory():
    return {
        "schema_version": 1,
        "identity_count": 2,
        "identities": [
            {"slot": 1, "name": "left-thumb", "live": True},
            {"slot": 2, "name": "right-index-finger", "live": True},
        ],
        "local_live_reconciled": True,
        "selection_scope": "current-reconciled-list",
        "fprintd_listing_is_compatibility_alias": True,
        "identifiers_redacted": True,
    }


def observer():
    return {
        "schema_version": 1,
        "operation_0x06_validated": True,
        "operation_0x19_validated": True,
        "stable_double_read": True,
        "queried_alias_matched": True,
        "bag_uuid_valid_and_redacted": True,
        "account_uuid_valid_and_redacted": True,
        "lock_state": 0,
        "mutation_performed": False,
        "identifiers_redacted": True,
    }


class FprintActivationGateCommandTests(unittest.TestCase):
    def collectors(self):
        modules = {
            "t2-touchid-doctor.py": SimpleNamespace(
                collect=lambda: [
                    SimpleNamespace(name=name, status="pass")
                    for name in MODULE.t2_fprint_activation_gate.REQUIRED_HEALTH_CHECKS
                ]
            ),
            "t2-aks-observe-test.py": SimpleNamespace(collect=observer),
            "t2-touchid-identities.py": SimpleNamespace(collect=inventory),
            "t2-touchid-enroll-test.py": SimpleNamespace(
                enrollment_status=fixtures.enrollment_status
            ),
            "t2-touchid-manage.py": SimpleNamespace(
                status=fixtures.management_status
            ),
        }
        return lambda _name, filename: modules[filename]

    def mapping(self):
        return mapping_admin.AdminResult(
            "status", "mapping-valid", 1, 1, None, None
        )

    def test_collect_combines_live_read_only_collectors(self):
        with (
            mock.patch.object(MODULE.os, "geteuid", return_value=0),
            mock.patch.object(MODULE, "_load", side_effect=self.collectors()),
            mock.patch.object(
                MODULE.t2_user_mapping_admin,
                "status",
                return_value=self.mapping(),
            ),
            mock.patch.object(
                MODULE, "_effective_daemon_is_default_off", return_value=True
            ),
        ):
            result = MODULE.collect(
                two_fingers_acknowledged=True,
                password_fallback_acknowledged=True,
                worker_negative_controls_acknowledged=True,
            )
        self.assertTrue(result.ready_to_stage_research_activation)

    def test_main_requires_all_acknowledgements(self):
        ready = fixtures.evaluate()
        for arguments, expected in (
            (["gate"], 1),
            (
                [
                    "gate",
                    "--acknowledge-two-distinct-fingers-verified-this-boot",
                    "--acknowledge-password-fallback-tested",
                    "--acknowledge-worker-negative-controls-passed",
                ],
                0,
            ),
        ):
            output = io.StringIO()
            with (
                mock.patch.object(MODULE.sys, "argv", arguments),
                mock.patch.object(
                    MODULE,
                    "collect",
                    return_value=(
                        ready
                        if expected == 0
                        else fixtures.evaluate(
                            password_fallback_acknowledged=False
                        )
                    ),
                ),
                redirect_stdout(output),
            ):
                self.assertEqual(MODULE.main(), expected)
            value = json.loads(output.getvalue())
            self.assertEqual(
                value["ready_to_stage_research_activation"], expected == 0
            )
            self.assertFalse(value["t2_mutation_performed"])

    def test_collection_failure_is_generic(self):
        error = io.StringIO()
        with (
            mock.patch.object(MODULE.os, "geteuid", return_value=1000),
            mock.patch.object(MODULE.sys, "argv", ["gate"]),
            redirect_stderr(error),
        ):
            self.assertEqual(MODULE.main(), 2)
        self.assertEqual(
            error.getvalue(),
            "t2-touchid-fprint-enrollment-gate: collection failed\n",
        )

    def test_effective_command_must_be_loaded_and_default_off(self):
        for completed, expected in (
            (
                subprocess.CompletedProcess(
                    (), 0, "python t2-fprintd.py\n", ""
                ),
                True,
            ),
            (
                subprocess.CompletedProcess(
                    (),
                    0,
                    "python t2-fprintd.py --enable-native-enrollment\n",
                    "",
                ),
                False,
            ),
            (subprocess.CompletedProcess((), 1, "", "failure"), False),
        ):
            with (
                self.subTest(completed=completed),
                mock.patch.object(
                    MODULE.subprocess, "run", return_value=completed
                ),
            ):
                self.assertEqual(
                    MODULE._effective_daemon_is_default_off(), expected
                )

    def test_installer_owns_gate_and_uninstaller_owns_candidate_rollback(self):
        install = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn("src/t2-touchid-fprint-enrollment-gate.py", install)
        self.assertIn("t2-touchid-fprint-enrollment-gate", uninstall)
        self.assertIn("10-native-enrollment.conf", uninstall)
        self.assertNotIn("10-native-enrollment.conf", install)


if __name__ == "__main__":
    unittest.main()
