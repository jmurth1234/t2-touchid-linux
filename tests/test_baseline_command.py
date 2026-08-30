# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
SPEC = importlib.util.spec_from_file_location(
    "t2_touchid_baseline_command", SOURCE / "t2-touchid-baseline.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class BaselineCommandTests(unittest.TestCase):
    @patch.object(MODULE, "run_private_inventory", return_value={"stable": True})
    @patch.object(MODULE.subprocess, "run")
    def test_active_fprintd_is_warmed_before_locked_inventory(self, run, inventory):
        run.side_effect = [
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 0),
        ]
        result = MODULE.warmed_private_inventory({}, Path("private.json"))
        self.assertEqual(result, {"stable": True})
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["/usr/bin/systemctl", "restart", "t2-biometric-ready.service"],
        )
        inventory.assert_called_once()

    @patch.object(MODULE, "run_private_inventory")
    @patch.object(MODULE.subprocess, "run")
    def test_failed_warmup_prevents_inventory(self, run, inventory):
        run.side_effect = [
            subprocess.CompletedProcess([], 0),
            subprocess.CompletedProcess([], 1),
        ]
        with self.assertRaisesRegex(MODULE.BaselineCommandError, "could not warm"):
            MODULE.warmed_private_inventory({}, Path("private.json"))
        inventory.assert_not_called()

    @patch.object(MODULE, "run_private_inventory")
    @patch.object(MODULE.subprocess, "run")
    def test_inactive_fprintd_is_rejected_without_inventory(self, run, inventory):
        run.return_value = subprocess.CompletedProcess([], 3)
        with self.assertRaisesRegex(MODULE.BaselineCommandError, "must be active"):
            MODULE.warmed_private_inventory({}, Path("private.json"))
        self.assertEqual(run.call_count, 1)
        inventory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
