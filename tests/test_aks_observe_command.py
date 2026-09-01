# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
import uuid
from contextlib import nullcontext, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_readiness as readiness


SPEC = importlib.util.spec_from_file_location(
    "t2_aks_observe_test_command", SOURCE / "t2-aks-observe-test.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


class Observer:
    def __init__(self, evidence):
        self.evidence = evidence
        self.alias = None

    def observe_alias(self, alias):
        self.alias = alias
        return self.evidence


class AKSObserveCommandTests(unittest.TestCase):
    def collect(self, evidence):
        observer = Observer(evidence)
        with (
            mock.patch.object(MODULE.os, "geteuid", return_value=0),
            mock.patch.object(MODULE, "_configured_user_id", return_value=501),
            mock.patch.object(MODULE, "_operation_lock", return_value=nullcontext()),
            mock.patch.object(
                MODULE.t2_aks_observer,
                "AKSAliasObserver",
                return_value=observer,
            ),
        ):
            result = MODULE.collect()
        self.assertEqual(observer.alias, -501)
        return result

    def test_collect_is_redacted_read_only_and_validates_both_operations(self):
        result = self.collect(
            readiness.AliasEvidence(
                True, -501, identifier(2), 0, identifier(1)
            )
        )
        self.assertTrue(result["operation_0x06_validated"])
        self.assertTrue(result["operation_0x19_validated"])
        self.assertTrue(result["stable_double_read"])
        self.assertFalse(result["mutation_performed"])
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn(identifier(1), rendered)
        self.assertNotIn(identifier(2), rendered)
        self.assertNotIn("501", rendered)

    def test_absent_mismatched_or_unknown_state_is_not_validated(self):
        cases = (
            readiness.AliasEvidence(False, None, None, None, None),
            readiness.AliasEvidence(
                True, -502, identifier(2), 0, identifier(1)
            ),
            readiness.AliasEvidence(
                True, -501, identifier(2), 1 << 8, identifier(1)
            ),
        )
        for evidence in cases:
            with self.subTest(present=evidence.present):
                with self.assertRaises(MODULE.AKSObserveTestError):
                    self.collect(evidence)

    def test_configured_user_is_exact_single_canonical_signed_alias(self):
        cases = {
            b"T2_TOUCHID_MACOS_USER_ID=501\n": 501,
            b"T2_TOUCHID_MACOS_USER_ID=0501\n": None,
            b"T2_TOUCHID_MACOS_USER_ID=9\n": None,
            b"T2_TOUCHID_MACOS_USER_ID=2147483648\n": None,
            b"T2_TOUCHID_MACOS_USER_ID=501\nT2_TOUCHID_MACOS_USER_ID=502\n": None,
            b"T2_TOUCHID_HOST=example\n": None,
        }
        for content, expected in cases.items():
            with self.subTest(content=content):
                with mock.patch.object(
                    MODULE, "_read_private_root_file", return_value=content
                ):
                    if expected is None:
                        with self.assertRaises(MODULE.AKSObserveTestError):
                            MODULE._configured_user_id()
                    else:
                        self.assertEqual(MODULE._configured_user_id(), expected)

    def test_main_reports_clean_failure_and_redacted_success(self):
        error = io.StringIO()
        with (
            mock.patch.object(
                MODULE,
                "collect",
                side_effect=MODULE.AKSObserveTestError("not ready"),
            ),
            redirect_stderr(error),
        ):
            self.assertEqual(MODULE.main(), 1)
        self.assertEqual(error.getvalue(), "t2-aks-observe-test: not ready\n")

        expected = {"schema_version": 1, "identifiers_redacted": True}
        output = io.StringIO()
        with (
            mock.patch.object(MODULE, "collect", return_value=expected),
            redirect_stdout(output),
        ):
            self.assertEqual(MODULE.main(), 0)
        self.assertEqual(json.loads(output.getvalue()), expected)

    def test_installer_and_uninstaller_own_the_validation_command(self):
        install = (SOURCE.parent / "install.sh").read_text(encoding="utf-8")
        uninstall = (SOURCE.parent / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn("src/t2-aks-observe-test.py", install)
        self.assertIn("t2-aks-observe-test", uninstall)


if __name__ == "__main__":
    unittest.main()
