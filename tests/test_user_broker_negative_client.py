# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_broker_negative as negative


SPEC = importlib.util.spec_from_file_location(
    "t2_user_broker_negative_client_command",
    ROOT
    / "systemd/research/t2-touchid-user-broker-negative-client.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class UserBrokerNegativeClientTests(unittest.TestCase):
    def test_fixed_candidate_path_and_no_arguments(self):
        self.assertEqual(
            MODULE.SOCKET_PATH, "/run/t2-touchid/user-broker.sock"
        )
        output = io.StringIO()
        with (
            mock.patch.object(
                MODULE,
                "run",
                return_value=negative.classify(
                    peer_closed_without_response=True
                ),
            ),
            mock.patch.object(MODULE.sys, "argv", ["negative-client"]),
            redirect_stdout(output),
        ):
            self.assertEqual(MODULE.main(), 0)
        self.assertTrue(json.loads(output.getvalue())["negative_boundary_held"])

        error = io.StringIO()
        with (
            mock.patch.object(MODULE.sys, "argv", ["negative-client", "x"]),
            redirect_stderr(error),
        ):
            self.assertEqual(MODULE.main(), 2)
        self.assertIn("no arguments permitted", error.getvalue())

    def test_failure_is_generic(self):
        error = io.StringIO()
        with (
            mock.patch.object(
                MODULE,
                "run",
                side_effect=MODULE.NegativeClientError("private"),
            ),
            mock.patch.object(MODULE.sys, "argv", ["negative-client"]),
            redirect_stderr(error),
        ):
            self.assertEqual(MODULE.main(), 1)
        self.assertNotIn("private", error.getvalue())

    def test_research_client_is_not_installed(self):
        install = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        name = "t2-touchid-user-broker-negative-client"
        self.assertNotIn(name, install)
        self.assertNotIn(name, uninstall)


if __name__ == "__main__":
    unittest.main()
