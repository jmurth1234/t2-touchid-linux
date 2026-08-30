# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
SPEC = importlib.util.spec_from_file_location(
    "t2_acm_authorize_command", SOURCE / "t2-acm-authorize-test.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class ACMAuthorizeCommandTests(unittest.TestCase):
    def test_verify_password_uses_canonical_v1_command(self) -> None:
        plain = MODULE.verify_password_command(1, -501)
        self.assertEqual(
            plain,
            [str(MODULE.AKS_TOOL), "verify-password-acm", "1", "-501"],
        )

    def test_runtime_state_returns_positive_loaded_handle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "keybag.env"
            state.write_text(
                "T2_KEYBAG_SESSION=1\n"
                "T2_KEYBAG_HANDLE=5\n"
                "T2_KEYBAG_SPECIAL=-501\n",
                encoding="utf-8",
            )
            os.chmod(state, 0o600)
            with (
                mock.patch.object(MODULE, "KEYBAG_STATE", state),
                mock.patch.object(
                    Path,
                    "stat",
                    return_value=SimpleNamespace(st_uid=0, st_mode=0o100600),
                ),
            ):
                self.assertEqual(MODULE.keybag_runtime(-501), (1, 5))

    def test_matrix_uses_both_validated_runtime_handles(self) -> None:
        self.assertEqual(
            MODULE.verify_password_matrix_command(1, -501, 6),
            [
                str(MODULE.AKS_TOOL),
                "verify-password-acm-matrix",
                "1",
                "-501",
                "6",
            ],
        )

    def test_password_only_uses_positive_runtime_handle(self) -> None:
        self.assertEqual(
            MODULE.verify_password_only_command(1, 6),
            [str(MODULE.AKS_TOOL), "verify-password-only", "1", "6"],
        )

    def test_password_only_rejects_special_handle(self) -> None:
        with self.assertRaisesRegex(
            MODULE.ACMDeviceError, "unsafe password-only verification target"
        ):
            MODULE.verify_password_only_command(1, -501)

    def test_password_only_requires_its_narrow_acknowledgement(self) -> None:
        self.assertFalse(MODULE.acknowledgement_valid(True, True, False))
        self.assertTrue(MODULE.acknowledgement_valid(True, False, True))

    def test_acm_path_requires_policy_mutation_acknowledgement(self) -> None:
        self.assertFalse(MODULE.acknowledgement_valid(False, False, True))
        self.assertTrue(MODULE.acknowledgement_valid(False, True, False))

    def test_runtime_state_rejects_nonpositive_loaded_handle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "keybag.env"
            state.write_text(
                "T2_KEYBAG_SESSION=1\n"
                "T2_KEYBAG_HANDLE=0\n"
                "T2_KEYBAG_SPECIAL=-501\n",
                encoding="utf-8",
            )
            os.chmod(state, 0o600)
            with (
                mock.patch.object(MODULE, "KEYBAG_STATE", state),
                mock.patch.object(
                    Path,
                    "stat",
                    return_value=SimpleNamespace(st_uid=0, st_mode=0o100600),
                ),
            ):
                with self.assertRaisesRegex(
                    MODULE.ACMDeviceError, "runtime keybag session"
                ):
                    MODULE.keybag_runtime(-501)


if __name__ == "__main__":
    unittest.main()
