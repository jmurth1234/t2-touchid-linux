# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
SPEC = importlib.util.spec_from_file_location(
    "t2_touchid_enroll_command", SOURCE / "t2-touchid-enroll-test.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


CONFIGURATION = {
    "linux_user": "mapped",
    "linux_uid": 1000,
    "apple_uid": 501,
    "special_bag": -501,
    "host": "fd00::1",
    "interface": "enp0s1f1",
    "mapping_generation": "d" * 64,
}


class EnrollmentCommandTests(unittest.TestCase):
    def invoke(
        self,
        arguments,
        *,
        live=False,
        recovery=False,
        status_only=False,
        enrollment_error=None,
    ):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "operation.lock"
            backup = Path(directory) / ("a" * 64 + ".tar.gz")
            output = io.StringIO()
            lifecycle = []
            result = {
                "schema_version": 1,
                "identifiers_redacted": True,
                "mutation_performed": False,
            }
            with (
                mock.patch.object(sys, "argv", ["enroll", *arguments]),
                mock.patch.object(MODULE.os, "geteuid", return_value=0),
                mock.patch.object(
                    MODULE, "runtime_configuration", return_value=CONFIGURATION
                ),
                mock.patch.object(MODULE, "_private_root_owned"),
                mock.patch.object(
                    MODULE.os,
                    "fstat",
                    return_value=SimpleNamespace(st_mode=0o100600, st_uid=0),
                ),
                mock.patch.object(
                    MODULE, "select_backup", return_value=backup
                ) as select_backup,
                mock.patch.object(
                    MODULE.t2_catacomb_local,
                    "provision_from_backup",
                    return_value=({}, object()),
                ) as provision,
                mock.patch.object(
                    MODULE,
                    "warm_sensor",
                    side_effect=lambda: lifecycle.append("warm"),
                ) as warm_sensor,
                mock.patch.object(
                    MODULE.fcntl,
                    "flock",
                    side_effect=lambda *_args: lifecycle.append("lock"),
                ),
                mock.patch.object(MODULE, "require_no_unfinished_enrollment"),
                mock.patch.object(MODULE, "OPERATION_LOCK", lock),
                mock.patch.object(
                    MODULE,
                    "run_preflight",
                    return_value=result,
                ) as preflight,
                mock.patch.object(
                    MODULE,
                    "run_enrollment",
                    return_value={
                        **result,
                        "mutation_performed": True,
                        "enrollment_succeeded": True,
                    },
                    side_effect=enrollment_error,
                ) as enrollment,
                mock.patch.object(
                    MODULE,
                    "run_outcome_unknown_reconciliation",
                    return_value={
                        **result,
                        "outcome_unknown_reconciled": True,
                        "fingerprint_mutation_performed": False,
                    },
                ) as reconcile,
                mock.patch.object(
                    MODULE,
                    "enrollment_status",
                    return_value={
                        **result,
                        "status_only": True,
                        "unfinished_count": 0,
                    },
                ) as status_report,
                mock.patch.object(MODULE, "notify_user") as notify,
                redirect_stdout(output),
                redirect_stderr(io.StringIO()),
            ):
                status = MODULE.main()
            self.assertEqual(status, 1 if enrollment_error is not None else 0)
            self.assertEqual(
                preflight.called, not live and not recovery and not status_only
            )
            self.assertEqual(enrollment.called, live)
            self.assertEqual(reconcile.called, recovery)
            self.assertEqual(status_report.called, status_only)
            if status_only:
                select_backup.assert_not_called()
                warm_sensor.assert_not_called()
                provision.assert_not_called()
                self.assertEqual(lifecycle, ["lock"])
            else:
                self.assertEqual(lifecycle[:2], ["warm", "lock"])
            if enrollment_error is not None:
                notify.assert_called_once_with(
                    CONFIGURATION["linux_user"], "t2-touchid-failure.service"
                )
            return output.getvalue()

    def test_preflight_requires_no_live_mutation_acknowledgement(self):
        output = self.invoke(
            ["--preflight-only", "--acknowledge-password-fallback-tested"]
        )
        self.assertIn('"mutation_performed": false', output)

    def test_live_path_requires_both_specific_acknowledgements(self):
        for arguments in (
            ["--acknowledge-password-fallback-tested"],
            [
                "--acknowledge-password-fallback-tested",
                "--acknowledge-live-fingerprint-enrollment",
            ],
            [
                "--acknowledge-password-fallback-tested",
                "--acknowledge-local-catacomb-mutation",
            ],
        ):
            with (
                self.subTest(arguments=arguments),
                mock.patch.object(sys, "argv", ["enroll", *arguments]),
                mock.patch.object(MODULE.os, "geteuid", return_value=0),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                MODULE.main()

    def test_live_path_dispatches_only_with_all_acknowledgements(self):
        output = self.invoke(
            [
                "--acknowledge-password-fallback-tested",
                "--acknowledge-live-fingerprint-enrollment",
                "--acknowledge-local-catacomb-mutation",
                "--identity-name",
                "Left index finger",
            ],
            live=True,
        )
        self.assertIn('"mutation_performed": true', output)

    def test_live_exception_emits_best_effort_failure_feedback(self):
        self.invoke(
            [
                "--acknowledge-password-fallback-tested",
                "--acknowledge-live-fingerprint-enrollment",
                "--acknowledge-local-catacomb-mutation",
            ],
            live=True,
            enrollment_error=MODULE.EnrollmentCommandError("synthetic failure"),
        )

    def test_recovery_needs_no_password_or_live_mutation_acknowledgement(self):
        output = self.invoke(
            ["--reconcile-outcome-unknown"],
            recovery=True,
        )
        self.assertIn('"outcome_unknown_reconciled": true', output)
        self.assertIn('"fingerprint_mutation_performed": false', output)

    def test_status_needs_no_acknowledgement_or_hardware_setup(self):
        output = self.invoke(["--status-only"], status_only=True)
        self.assertIn('"status_only": true', output)
        self.assertIn('"unfinished_count": 0', output)

    def test_status_redacts_journal_identity_and_reports_recovery_eligibility(self):
        histories = [
            (
                Path("/private/identifier-one.jsonl"),
                SimpleNamespace(
                    phase=MODULE.t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN
                ),
            )
        ]
        with mock.patch.object(
            MODULE, "unfinished_enrollment_journals", return_value=histories
        ):
            result = MODULE.enrollment_status()
        self.assertEqual(result["unfinished_count"], 1)
        self.assertEqual(result["unfinished_phases"], {"outcome-unknown": 1})
        self.assertTrue(result["automatic_no_change_recovery_candidate"])
        self.assertNotIn("identifier-one", repr(result))

    def test_recovery_rejects_mixed_unfinished_journals(self):
        histories = [
            (
                Path("/private/one.jsonl"),
                SimpleNamespace(
                    phase=MODULE.t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN
                ),
            ),
            (
                Path("/private/two.jsonl"),
                SimpleNamespace(
                    phase=MODULE.t2_enrollment_journal.EnrollmentPhase.PERSISTING
                ),
            ),
        ]
        with (
            mock.patch.object(
                MODULE, "unfinished_enrollment_journals", return_value=histories
            ),
            self.assertRaisesRegex(MODULE.EnrollmentCommandError, "exactly one"),
        ):
            MODULE.run_outcome_unknown_reconciliation(CONFIGURATION, object())

    def test_unfinished_journal_blocks_a_new_live_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = root / "00000000-0000-0000-0000-000000000001.jsonl"
            journal.touch()
            history = SimpleNamespace(
                phase=MODULE.t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN
            )
            with (
                mock.patch.object(MODULE, "MUTATION_ROOT", root),
                mock.patch.object(MODULE, "_private_root_owned"),
                mock.patch.object(
                    MODULE.t2_enrollment_journal, "read", return_value=history
                ),
                self.assertRaisesRegex(MODULE.EnrollmentCommandError, "unfinished"),
            ):
                MODULE.require_no_unfinished_enrollment()

    def test_invalid_identity_name_is_rejected_before_runtime_setup(self):
        arguments = [
            "--acknowledge-password-fallback-tested",
            "--acknowledge-live-fingerprint-enrollment",
            "--acknowledge-local-catacomb-mutation",
            "--identity-name",
            "x" * 1025,
        ]
        with (
            mock.patch.object(sys, "argv", ["enroll", *arguments]),
            mock.patch.object(MODULE.os, "geteuid", return_value=0),
            mock.patch.object(MODULE, "runtime_configuration") as runtime,
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            MODULE.main()
        runtime.assert_not_called()

    def test_live_composition_uses_only_protected_runtime_subjects(self):
        class Context:
            def __init__(self, value):
                self.value = value

            def __enter__(self):
                return self.value

            def __exit__(self, *_args):
                return None

        lease = SimpleNamespace(connection_generation="00000000-0000-0000-0000-000000000004")
        result = SimpleNamespace(
            outcome="identity-observed",
            policy_satisfied=True,
            persistence_ready=True,
            reconciliation_complete=True,
        )
        seen = {}

        def coordinator(**kwargs):
            seen.update(kwargs)
            kwargs["password_binder"](bytes(16))
            return result

        completed = SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as directory:
            boot = Path(directory) / "boot_id"
            boot.write_text("00000000-0000-0000-0000-000000000003\n")
            with (
                mock.patch.object(MODULE, "keybag_runtime", return_value=(1, 9)),
                mock.patch.object(MODULE, "_port", return_value=55555),
                mock.patch.object(MODULE, "BOOT_ID", boot),
                mock.patch.object(
                    MODULE.t2_bridge_connection.BridgeConnectionLease,
                    "connect",
                    return_value=Context(lease),
                ),
                mock.patch.object(MODULE, "ACMDevice", return_value=Context(object())),
                mock.patch.object(
                    MODULE.t2_enrollment_finalizer,
                    "BuiltinEnrollmentFinalizer",
                    return_value=object(),
                ) as finalizer,
                mock.patch.object(
                    MODULE.t2_enrollment_coordinator, "run", side_effect=coordinator
                ),
                mock.patch.object(MODULE.subprocess, "run", return_value=completed) as run,
                mock.patch.object(MODULE, "notify_user"),
            ):
                output = MODULE.run_enrollment(
                    CONFIGURATION,
                    {"private": "host"},
                    Path("/var/lib/t2-touchid/backups/" + "a" * 64 + ".tar.gz"),
                    "Left index finger",
                    MODULE.Event(),
                )
        binder_call = run.call_args_list[0]
        self.assertEqual(
            binder_call.args[0],
            [str(MODULE.AKS_TOOL), "verify-password-acm", "1", "-501"],
        )
        self.assertEqual(seen["apple_user_id"], 501)
        self.assertEqual(seen["caller_linux_uid"], 1000)
        self.assertEqual(seen["target_linux_uid"], 1000)
        self.assertEqual(seen["mapping_generation"], "d" * 64)
        self.assertEqual(finalizer.call_args.kwargs["catacomb_root"], MODULE.STORE_ROOT)
        self.assertTrue(output["persistence_ready"])

    def test_desktop_feedback_failure_cannot_abort_enrollment(self):
        with mock.patch.object(
            MODULE.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired("systemctl", 5),
        ):
            MODULE.notify_user("mapped", "t2-touchid-alert.service")

    def test_scan_feedback_is_actionable_and_advisory(self):
        transition = SimpleNamespace(
            action=MODULE.t2_enrollment_protocol.EnrollmentAction.RETRY_SMALL_COVERAGE,
            progress_percent=None,
        )
        output = io.StringIO()
        with (
            mock.patch.object(MODULE, "notify_user") as notify,
            redirect_stdout(output),
        ):
            MODULE.report_enrollment_feedback("mapped", transition)
        self.assertIn("Cover more", output.getvalue())
        notify.assert_called_once_with("mapped", "t2-touchid-alert.service")

        progress = SimpleNamespace(
            action=MODULE.t2_enrollment_protocol.EnrollmentAction.PROGRESS,
            progress_percent=42,
        )
        with (
            mock.patch.object(MODULE, "notify_user") as notify,
            mock.patch("builtins.print", side_effect=BrokenPipeError),
        ):
            MODULE.report_enrollment_feedback("mapped", progress)
        notify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
