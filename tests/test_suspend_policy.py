# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "t2_touchid_doctor_suspend", ROOT / "src/t2-touchid-doctor.py"
)
DOCTOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = DOCTOR
SPEC.loader.exec_module(DOCTOR)


class SuspendPolicyTests(unittest.TestCase):
    def test_installed_policy_selects_only_s2idle(self):
        policy = (
            ROOT / "systemd/sleep.conf.d/90-t2-touchid-s2idle.conf"
        ).read_text(encoding="utf-8")
        self.assertIn("[Sleep]", policy)
        self.assertIn("MemorySleepMode=s2idle", policy)
        self.assertNotIn("MemorySleepMode=deep", policy)

        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        uninstaller = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
        target = "/etc/systemd/sleep.conf.d/90-t2-touchid-s2idle.conf"
        self.assertIn(target, installer)
        self.assertIn(target, uninstaller)

    def test_doctor_accepts_s2idle_and_warns_for_deep(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mem_sleep"
            with mock.patch.object(DOCTOR, "MEM_SLEEP", path):
                path.write_text("[s2idle] deep\n", encoding="ascii")
                check = DOCTOR.sleep_mode_check()
                self.assertEqual(check.status, "pass")
                self.assertIn("s2idle selected", check.detail)

                path.write_text("s2idle [deep]\n", encoding="ascii")
                check = DOCTOR.sleep_mode_check()
                self.assertEqual(check.status, "warn")
                self.assertIn("use s2idle", check.detail)

    def test_doctor_fails_closed_for_ambiguous_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mem_sleep"
            path.write_text("s2idle deep\n", encoding="ascii")
            with mock.patch.object(DOCTOR, "MEM_SLEEP", path):
                self.assertEqual(DOCTOR.sleep_mode_check().status, "warn")

    def test_installer_negotiates_applekeystore_before_keybag_loading(self):
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn(
            "register_ool=1 probe_capabilities=1",
            installer,
        )


if __name__ == "__main__":
    unittest.main()
