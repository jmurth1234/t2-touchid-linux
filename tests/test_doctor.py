# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
import json
import stat
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src" / "t2-touchid-doctor.py"
SPEC = importlib.util.spec_from_file_location("t2_touchid_doctor", MODULE_PATH)
assert SPEC and SPEC.loader
doctor = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = doctor
SPEC.loader.exec_module(doctor)


class DoctorTests(unittest.TestCase):
    def test_assignment_parser_ignores_comments_and_invalid_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config"
            path.write_text("# private\nGOOD=value\nbad-key=no\nWITH_EQUALS=a=b\n")
            self.assertEqual(
                doctor.read_assignments(path),
                {"GOOD": "value", "WITH_EQUALS": "a=b"},
            )

    def test_private_file_rejects_group_access(self):
        info = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_uid=0)
        with mock.patch.object(Path, "stat", return_value=info):
            self.assertFalse(doctor.private_regular_file(Path("ignored")))

    def test_service_check_accepts_active_success(self):
        completed = mock.Mock(
            returncode=0,
            stdout="loaded\nactive\nrunning\nsuccess\n0\n",
        )
        with mock.patch.object(doctor, "run", return_value=completed):
            check = doctor.service_check("example.service")
        self.assertEqual(check.status, "pass")
        self.assertNotIn("example.service", check.detail)

    def test_json_shape_contains_no_implicit_identifiers(self):
        check = doctor.Check("pass", "bridge-network", "endpoint reachable")
        encoded = json.dumps({"checks": [doctor.asdict(check)]})
        self.assertIn('"status": "pass"', encoded)
        self.assertNotIn("fe80", encoded)

    def test_dkms_check_requires_running_kernel_installed(self):
        completed = mock.Mock(
            returncode=0,
            stdout="t2-sep-transport/0.1.0, test-kernel, x86_64: installed\n",
        )
        with (
            mock.patch.object(doctor, "run", return_value=completed),
            mock.patch.object(doctor.platform, "release", return_value="test-kernel"),
        ):
            self.assertEqual(doctor.dkms_check().status, "pass")

    def test_journal_no_entries_banner_is_suppressed(self):
        completed = mock.Mock(returncode=0, stdout="-- No entries --\n")
        with mock.patch.object(doctor, "run", return_value=completed):
            check = doctor.watchdog_check()
        self.assertEqual(check.status, "pass")


if __name__ == "__main__":
    unittest.main()
