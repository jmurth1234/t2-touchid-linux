# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_mapping_admin as mapping_admin


SPEC = importlib.util.spec_from_file_location(
    "t2_touchid_user_broker_gate_command",
    SOURCE / "t2-touchid-user-broker-gate.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


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


def inventory():
    return {
        "schema_version": 1,
        "identity_count": 2,
        "identities": [
            {"slot": 1, "name": "Finger 1", "live": True},
            {"slot": 2, "name": "Linux enrolled finger", "live": True},
        ],
        "local_live_reconciled": True,
        "selection_scope": "current-reconciled-list",
        "fprintd_listing_is_compatibility_alias": True,
        "identifiers_redacted": True,
    }


class UserBrokerGateCommandTests(unittest.TestCase):
    def collectors(self):
        modules = {
            "t2-touchid-doctor.py": SimpleNamespace(
                module_build_check=lambda: SimpleNamespace(
                    status="pass", name="module-build"
                )
            ),
            "t2-aks-observe-test.py": SimpleNamespace(collect=observer),
            "t2-touchid-identities.py": SimpleNamespace(collect=inventory),
        }
        return lambda name, filename: modules[filename]

    def test_collect_is_ready_only_with_explicit_attestation(self):
        status = mapping_admin.AdminResult(
            "status", "mapping-valid", 1, 1, None, None
        )
        with (
            mock.patch.object(MODULE.os, "geteuid", return_value=0),
            mock.patch.object(MODULE, "_load", side_effect=self.collectors()),
            mock.patch.object(
                MODULE.t2_user_mapping_admin, "status", return_value=status
            ),
        ):
            self.assertTrue(MODULE.collect(True).ready_for_staged_negative_test)
            self.assertFalse(MODULE.collect(False).ready_for_staged_negative_test)

    def test_real_collectors_load_with_import_metadata_registered(self):
        for index, filename in enumerate(
            (
                "t2-touchid-doctor.py",
                "t2-aks-observe-test.py",
                "t2-touchid-identities.py",
            )
        ):
            name = f"t2_user_broker_gate_real_{index}"
            try:
                loaded = MODULE._load(name, filename)
                self.assertIs(sys.modules[name], loaded)
            finally:
                sys.modules.pop(name, None)

    def test_main_prints_only_redacted_gate_and_uses_readiness_exit_status(self):
        status = mapping_admin.AdminResult(
            "status", "mapping-valid", 1, 1, None, None
        )
        output = io.StringIO()
        with (
            mock.patch.object(MODULE.os, "geteuid", return_value=0),
            mock.patch.object(MODULE, "_load", side_effect=self.collectors()),
            mock.patch.object(
                MODULE.t2_user_mapping_admin, "status", return_value=status
            ),
            mock.patch.object(
                MODULE.sys,
                "argv",
                [
                    "t2-touchid-user-broker-gate",
                    "--acknowledge-two-distinct-fingers-verified-this-boot",
                ],
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(MODULE.main(), 0)
        result = json.loads(output.getvalue())
        self.assertTrue(result["ready_for_staged_negative_test"])
        self.assertFalse(result["broker_socket_installed"])
        self.assertFalse(result["t2_mutation_performed"])

    def test_missing_mapping_is_an_incomplete_gate_not_collection_failure(self):
        output = io.StringIO()
        with (
            mock.patch.object(MODULE.os, "geteuid", return_value=0),
            mock.patch.object(MODULE, "_load", side_effect=self.collectors()),
            mock.patch.object(
                MODULE.t2_user_mapping_admin,
                "status",
                side_effect=mapping_admin.UserMappingAdminError("private"),
            ),
            mock.patch.object(
                MODULE.sys, "argv", ["t2-touchid-user-broker-gate"]
            ),
            redirect_stdout(output),
        ):
            self.assertEqual(MODULE.main(), 1)
        result = json.loads(output.getvalue())
        self.assertFalse(result["protected_mapping_present"])
        self.assertFalse(result["ready_for_staged_negative_test"])
        self.assertNotIn("private", output.getvalue())

    def test_nonroot_and_collector_load_failure_are_generic(self):
        for patches in (
            (mock.patch.object(MODULE.os, "geteuid", return_value=1000),),
            (
                mock.patch.object(MODULE.os, "geteuid", return_value=0),
                mock.patch.object(
                    MODULE,
                    "_load",
                    side_effect=MODULE.UserBrokerGateCommandError("private"),
                ),
            ),
        ):
            error = io.StringIO()
            with ExitStack() as stack:
                for patch in patches:
                    stack.enter_context(patch)
                stack.enter_context(mock.patch.object(
                    MODULE.sys, "argv", ["t2-touchid-user-broker-gate"]
                ))
                stack.enter_context(redirect_stderr(error))
                self.assertEqual(MODULE.main(), 2)
            self.assertEqual(
                error.getvalue(),
                "t2-touchid-user-broker-gate: collection failed\n",
            )

    def test_installer_owns_gate_but_not_candidate_service(self):
        install = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn("src/t2-touchid-user-broker-gate.py", install)
        self.assertIn("t2-touchid-user-broker-gate", uninstall)
        self.assertNotIn("t2-touchid-user-broker.socket", install)


if __name__ == "__main__":
    unittest.main()
