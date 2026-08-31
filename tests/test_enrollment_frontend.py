# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
SPEC = importlib.util.spec_from_file_location(
    "t2_touchid_enroll_frontend", SOURCE / "t2-touchid-enroll.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class EnrollmentFrontendTests(unittest.TestCase):
    def translate(self, arguments: list[str]) -> list[str]:
        return MODULE.broker_arguments(MODULE.parser().parse_args(arguments))

    def test_status_and_recovery_commands_have_exact_mappings(self):
        cases = {
            ("status",): ["--status-only"],
            ("verify-post-reboot",): ["--verify-post-reboot"],
            ("recover-outcome",): ["--reconcile-outcome-unknown"],
            ("recover-local",): ["--recover-local-transaction"],
        }
        for arguments, expected in cases.items():
            with self.subTest(arguments=arguments):
                self.assertEqual(self.translate(list(arguments)), expected)

    def test_preflight_maps_only_an_explicit_acknowledgement(self):
        self.assertEqual(self.translate(["preflight"]), ["--preflight-only"])
        self.assertEqual(
            self.translate(
                ["preflight", "--acknowledge-password-fallback-tested"]
            ),
            ["--preflight-only", "--acknowledge-password-fallback-tested"],
        )

    def test_start_preserves_name_and_explicit_acknowledgements(self):
        self.assertEqual(
            self.translate(
                [
                    "start",
                    "--name",
                    "Research finger",
                    "--acknowledge-password-fallback-tested",
                    "--acknowledge-live-fingerprint-enrollment",
                    "--acknowledge-local-catacomb-mutation",
                ]
            ),
            [
                "--identity-name",
                "Research finger",
                "--acknowledge-password-fallback-tested",
                "--acknowledge-live-fingerprint-enrollment",
                "--acknowledge-local-catacomb-mutation",
            ],
        )

    def test_recover_observed_preserves_name_and_explicit_acknowledgements(self):
        self.assertEqual(
            self.translate(
                [
                    "recover-observed",
                    "--name",
                    "Recovered finger",
                    "--acknowledge-observed-identity-recovery",
                    "--acknowledge-local-catacomb-mutation",
                ]
            ),
            [
                "--recover-observed-identity",
                "--identity-name",
                "Recovered finger",
                "--acknowledge-observed-identity-recovery",
                "--acknowledge-local-catacomb-mutation",
            ],
        )

    def test_main_execs_broker_directly_without_a_shell(self):
        broker = Path("/safe/t2-touchid-enroll-test")
        with (
            mock.patch.object(sys, "argv", ["t2-touchid-enroll", "status"]),
            mock.patch.object(MODULE, "broker_path", return_value=broker),
            mock.patch.object(MODULE.os, "execv", side_effect=RuntimeError("exec"))
            as execute,
        ):
            with self.assertRaisesRegex(RuntimeError, "exec"):
                MODULE.main()
        execute.assert_called_once_with(
            sys.executable,
            [sys.executable, str(broker), "--status-only"],
        )


if __name__ == "__main__":
    unittest.main()
