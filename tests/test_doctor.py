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

    def test_keybag_readiness_reports_locked_and_unlocked_state(self):
        with (
            mock.patch.object(doctor.os, "geteuid", return_value=0),
            mock.patch.object(doctor, "private_regular_file", return_value=True),
            mock.patch.object(Path, "read_bytes", side_effect=(b"same", b"same")),
        ):
            self.assertEqual(doctor.keybag_readiness_check().status, "pass")

        with (
            mock.patch.object(doctor.os, "geteuid", return_value=0),
            mock.patch.object(doctor, "private_regular_file", return_value=True),
            mock.patch.object(Path, "read_bytes", side_effect=(b"old", b"new")),
        ):
            check = doctor.keybag_readiness_check()
        self.assertEqual(check.status, "warn")
        self.assertIn("t2-keybag-unlock", check.detail)

    def test_keybag_readiness_reports_recorded_password_rejection(self):
        states = {
            doctor.STATE: True,
            doctor.READY: False,
            doctor.REJECTED: True,
        }
        rejected_info = types.SimpleNamespace(st_size=0)
        with (
            mock.patch.object(doctor.os, "geteuid", return_value=0),
            mock.patch.object(
                doctor, "private_regular_file", side_effect=lambda path: states[path]
            ),
            mock.patch.object(Path, "stat", return_value=rejected_info),
        ):
            check = doctor.keybag_readiness_check()
        self.assertEqual(check.status, "warn")
        self.assertIn("macOS password was rejected", check.detail)

    def test_service_check_accepts_active_success(self):
        completed = mock.Mock(
            returncode=0,
            stdout="loaded\nactive\nrunning\nsuccess\n0\n",
        )
        with mock.patch.object(doctor, "run", return_value=completed):
            check = doctor.service_check("example.service")
        self.assertEqual(check.status, "pass")
        self.assertNotIn("example.service", check.detail)

    def test_manual_unlock_mode_does_not_require_conditional_services(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                mock.patch.object(doctor, "CREDENTIAL", Path(directory) / "missing"),
                mock.patch.object(doctor, "service_check") as service_check,
                mock.patch.object(
                    doctor,
                    "dkms_check",
                    return_value=doctor.Check("pass", "dkms", "ok"),
                ),
                mock.patch.object(
                    doctor,
                    "module_build_check",
                    return_value=doctor.Check("pass", "build", "ok"),
                ),
                mock.patch.object(doctor, "read_assignments", side_effect=OSError),
                mock.patch.object(
                    doctor,
                    "acm_transport_check",
                    return_value=doctor.Check("pass", "acm", "ok"),
                ),
                mock.patch.object(
                    doctor,
                    "sleep_mode_check",
                    return_value=doctor.Check("pass", "sleep", "ok"),
                ),
                mock.patch.object(doctor.os, "geteuid", return_value=1),
            ):
                service_check.return_value = doctor.Check("pass", "service", "ok")
                checks = doctor.collect()
        manual = {
            check.name: check
            for check in checks
            if check.name in (
                "t2-credential-unlock.service",
                "t2-biometric-ready.service",
            )
        }
        self.assertTrue(all(check.status == "pass" for check in manual.values()))
        self.assertTrue(
            all("manual keybag-unlock" in check.detail for check in manual.values())
        )

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

    def test_gnu_build_id_reads_sysfs_note(self):
        descriptor = bytes(range(20))
        note = (
            (4).to_bytes(4, "little")
            + len(descriptor).to_bytes(4, "little")
            + (3).to_bytes(4, "little")
            + b"GNU\0"
            + descriptor
        )
        self.assertEqual(doctor.gnu_build_id(note), descriptor)

    def test_module_build_check_warns_when_reboot_is_required(self):
        live_descriptor = bytes(range(20))
        installed_descriptor = bytes(reversed(range(20)))

        def note(descriptor):
            return (
                (4).to_bytes(4, "little")
                + len(descriptor).to_bytes(4, "little")
                + (3).to_bytes(4, "little")
                + b"GNU\0"
                + descriptor
            )

        completed = mock.Mock(returncode=0, stdout="/module.ko\n")
        with (
            mock.patch.object(doctor, "run", return_value=completed),
            mock.patch.object(
                Path,
                "read_bytes",
                side_effect=(note(live_descriptor), note(installed_descriptor)),
            ),
            mock.patch.object(Path, "is_file", return_value=True),
        ):
            check = doctor.module_build_check()
        self.assertEqual(check.status, "warn")
        self.assertIn("reboot required", check.detail)

    def test_journal_no_entries_banner_is_suppressed(self):
        completed = mock.Mock(returncode=0, stdout="-- No entries --\n")
        with mock.patch.object(doctor, "run", return_value=completed):
            check = doctor.watchdog_check()
        self.assertEqual(check.status, "pass")

    def test_acm_transport_reports_poisoned_generation(self):
        completed = mock.Mock(returncode=1, stderr="reboot required\n")
        with (
            mock.patch.object(doctor.os, "geteuid", return_value=0),
            mock.patch.object(doctor, "run", return_value=completed),
        ):
            check = doctor.acm_transport_check(True)
        self.assertEqual(check.status, "warn")
        self.assertIn("reboot required", check.detail)

    def test_acm_transport_is_explicit_when_disabled(self):
        check = doctor.acm_transport_check(False)
        self.assertEqual(check.status, "pass")
        self.assertIn("disabled", check.detail)


if __name__ == "__main__":
    unittest.main()
