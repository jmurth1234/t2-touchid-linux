# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
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
        post_reboot=False,
        local_recovery=False,
        enrollment_error=None,
        cancel_before_dispatch=False,
    ):
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "operation.lock"
            backup = Path(directory) / ("a" * 64 + ".tar.gz")
            store_root = Path(directory) / "catacomb"
            store_root.mkdir(mode=0o700)
            output = io.StringIO()
            lifecycle = []
            result = {
                "schema_version": 1,
                "identifiers_redacted": True,
                "mutation_performed": False,
            }

            inhibitor = SimpleNamespace(poll=mock.Mock(return_value=None))

            @contextmanager
            def inhibit_sleep():
                lifecycle.append("inhibit")
                try:
                    yield inhibitor
                finally:
                    lifecycle.append("uninhibit")

            def warm():
                lifecycle.append("warm")
                if cancel_before_dispatch:
                    signal.raise_signal(signal.SIGTERM)

            with (
                mock.patch.object(sys, "argv", ["enroll", *arguments]),
                mock.patch.object(MODULE.os, "geteuid", return_value=0),
                mock.patch.object(
                    MODULE, "runtime_configuration", return_value=CONFIGURATION
                ),
                mock.patch.multiple(
                    MODULE,
                    _private_root_owned=mock.DEFAULT,
                    STORE_ROOT=store_root,
                ),
                mock.patch.object(
                    MODULE.os,
                    "fstat",
                    return_value=SimpleNamespace(st_mode=0o100600, st_uid=0),
                ),
                mock.patch.object(
                    MODULE, "select_backup", return_value=backup
                ) as select_backup,
                mock.patch.object(
                    MODULE,
                    "open_current_or_provision",
                    return_value=({}, object(), False),
                ) as current_store,
                mock.patch.object(
                    MODULE.t2_catacomb_store,
                    "CatacombStore",
                    return_value=object(),
                ) as open_store,
                mock.patch.object(
                    MODULE,
                    "warm_sensor",
                    side_effect=warm,
                ) as warm_sensor,
                mock.patch.object(
                    MODULE.fcntl,
                    "flock",
                    side_effect=lambda *_args: lifecycle.append("lock"),
                ),
                mock.patch.multiple(
                    MODULE,
                    require_no_unfinished_enrollment=mock.DEFAULT,
                    sleep_inhibitor=mock.DEFAULT,
                ) as guards,
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
                mock.patch.multiple(
                    MODULE,
                    run_post_reboot_verification=mock.DEFAULT,
                    run_local_transaction_recovery=mock.DEFAULT,
                ) as recovery_modes,
                mock.patch.object(MODULE, "notify_user") as notify,
                redirect_stdout(output),
                redirect_stderr(io.StringIO()),
            ):
                guards["sleep_inhibitor"].side_effect = inhibit_sleep
                post_reboot_verification = recovery_modes[
                    "run_post_reboot_verification"
                ]
                post_reboot_verification.return_value = {
                    **result,
                    "post_reboot_verified": True,
                    "fingerprint_mutation_performed": False,
                }
                recover_local = recovery_modes["run_local_transaction_recovery"]
                recover_local.return_value = {
                    **result,
                    "local_transaction_recovered": True,
                    "outcome_unknown": True,
                }
                status = MODULE.main()
            self.assertEqual(
                status,
                1 if enrollment_error is not None or cancel_before_dispatch else 0,
            )
            self.assertEqual(
                preflight.called,
                not live
                and not recovery
                and not status_only
                and not post_reboot
                and not local_recovery,
            )
            self.assertEqual(enrollment.called, live and not cancel_before_dispatch)
            self.assertEqual(reconcile.called, recovery)
            self.assertEqual(status_report.called, status_only)
            self.assertEqual(post_reboot_verification.called, post_reboot)
            self.assertEqual(recover_local.called, local_recovery)
            if status_only:
                select_backup.assert_not_called()
                warm_sensor.assert_not_called()
                current_store.assert_not_called()
                self.assertEqual(lifecycle, ["lock"])
            elif post_reboot:
                select_backup.assert_not_called()
                current_store.assert_not_called()
                open_store.assert_called_once_with(
                    store_root, CONFIGURATION["apple_uid"]
                )
                self.assertEqual(lifecycle[:2], ["warm", "lock"])
            elif local_recovery:
                select_backup.assert_not_called()
                warm_sensor.assert_not_called()
                current_store.assert_not_called()
                open_store.assert_called_once_with(
                    store_root, CONFIGURATION["apple_uid"]
                )
                self.assertEqual(lifecycle, ["lock"])
            else:
                current_store.assert_called_once_with(backup, CONFIGURATION)
                self.assertEqual(lifecycle[:2], ["warm", "lock"])
            if live:
                self.assertEqual(lifecycle[2:], ["inhibit", "uninhibit"])
            if enrollment_error is not None or cancel_before_dispatch:
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

    def test_signal_before_dispatch_cancels_without_entering_enrollment(self):
        self.invoke(
            [
                "--acknowledge-password-fallback-tested",
                "--acknowledge-live-fingerprint-enrollment",
                "--acknowledge-local-catacomb-mutation",
            ],
            live=True,
            cancel_before_dispatch=True,
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

    def test_post_reboot_verification_needs_no_mutation_acknowledgement(self):
        output = self.invoke(["--verify-post-reboot"], post_reboot=True)
        self.assertIn('"post_reboot_verified": true', output)
        self.assertIn('"fingerprint_mutation_performed": false', output)

    def test_local_transaction_recovery_needs_no_live_acknowledgement(self):
        output = self.invoke(
            ["--recover-local-transaction"], local_recovery=True
        )
        self.assertIn('"local_transaction_recovered": true', output)
        self.assertIn('"outcome_unknown": true', output)

    def test_status_redacts_journal_identity_and_reports_recovery_eligibility(self):
        histories = [
            (
                Path("/private/identifier-one.jsonl"),
                SimpleNamespace(
                    phase=MODULE.t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN
                ),
            )
        ]
        with mock.patch.object(MODULE, "enrollment_journals", return_value=histories):
            result = MODULE.enrollment_status()
        self.assertEqual(result["unfinished_count"], 1)
        self.assertEqual(result["unfinished_phases"], {"outcome-unknown": 1})
        self.assertTrue(result["automatic_no_change_recovery_candidate"])
        self.assertNotIn("identifier-one", repr(result))

    def test_status_reports_only_redacted_local_transaction_eligibility(self):
        persistence = SimpleNamespace(
            batch_index=0,
            batches=((('user_000001f5.cat', "1" * 64),),),
            staged_files=(("user_000001f5.cat", "7" * 64),),
            phase=(
                MODULE.t2_enrollment_persistence_journal.PersistencePhase.HOST_STAGED
            ),
        )
        history = SimpleNamespace(
            phase=MODULE.t2_enrollment_journal.EnrollmentPhase.PERSISTING,
            terminal_identity_uuid=None,
            persistence=persistence,
        )
        with tempfile.TemporaryDirectory() as directory:
            store_root = Path(directory)
            (store_root / "prepare").mkdir()
            with (
                mock.patch.object(MODULE, "STORE_ROOT", store_root),
                mock.patch.object(
                    MODULE,
                    "enrollment_journals",
                    return_value=[
                        (Path("/private/private-journal-name.jsonl"), history)
                    ],
                ),
            ):
                result = MODULE.enrollment_status()
        self.assertTrue(result["local_transaction_pending"])
        self.assertTrue(result["local_transaction_recovery_candidate"])
        self.assertTrue(result["live_enrollment_blocked"])
        self.assertFalse(result["automatic_no_change_recovery_candidate"])
        self.assertNotIn("private-journal-name", repr(result))

    def test_status_rejects_a_local_transaction_with_the_wrong_replay_direction(self):
        persistence = SimpleNamespace(
            batch_index=0,
            batches=((('user_000001f5.cat', "1" * 64),),),
            staged_files=(("user_000001f5.cat", "7" * 64),),
            phase=(
                MODULE.t2_enrollment_persistence_journal.PersistencePhase.HOST_STAGED
            ),
        )
        history = SimpleNamespace(
            phase=MODULE.t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN,
            outcome_unknown_stage="local-commit-rolled-forward",
            terminal_identity_uuid=None,
            persistence=persistence,
        )
        with tempfile.TemporaryDirectory() as directory:
            store_root = Path(directory)
            (store_root / "prepare").mkdir()
            with (
                mock.patch.object(MODULE, "STORE_ROOT", store_root),
                mock.patch.object(
                    MODULE,
                    "enrollment_journals",
                    return_value=[(Path("/private/journal.jsonl"), history)],
                ),
            ):
                result = MODULE.enrollment_status()
        self.assertTrue(result["local_transaction_pending"])
        self.assertFalse(result["local_transaction_recovery_candidate"])

    def test_pending_e4_blocks_another_live_enrollment(self):
        pending = SimpleNamespace(
            phase=MODULE.t2_enrollment_journal.EnrollmentPhase.RECONCILED,
            terminal_identity_uuid="private-identity",
        )
        with mock.patch.object(
            MODULE, "enrollment_journals", return_value=[(Path("private"), pending)]
        ):
            result = MODULE.enrollment_status()
            self.assertEqual(result["post_reboot_pending_count"], 1)
            self.assertTrue(result["post_reboot_verification_candidate"])
            self.assertTrue(result["live_enrollment_blocked"])
            with self.assertRaisesRegex(
                MODULE.EnrollmentCommandError, "post-reboot verification"
            ):
                MODULE.require_no_unfinished_enrollment()

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

    def test_post_reboot_verifier_composes_fresh_readback_without_identity_output(self):
        class Context:
            def __init__(self, value):
                self.value = value

            def __enter__(self):
                return self.value

            def __exit__(self, *_args):
                return None

        history = SimpleNamespace(
            phase=MODULE.t2_enrollment_journal.EnrollmentPhase.RECONCILED,
            terminal_identity_uuid="private-identity",
            baseline={"apple_uid": 501, "mapping_generation": "d" * 64},
            operation_id="private-operation",
        )
        live = {"per_user_identity_records": [{"private": True}]}
        verified = SimpleNamespace(
            phase=MODULE.t2_enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED
        )
        lease = object()
        boot_uuid = "00000000-0000-0000-0000-000000000003"
        with tempfile.TemporaryDirectory() as directory:
            boot = Path(directory) / "boot_id"
            boot.write_text(f"{boot_uuid}\n")
            with (
                mock.patch.object(
                    MODULE,
                    "enrollment_journals",
                    return_value=[(Path("/private/journal"), history)],
                ),
                mock.patch.object(MODULE, "keybag_runtime", return_value=(1, 9)),
                mock.patch.object(MODULE, "_port", return_value=55555),
                mock.patch.object(MODULE, "BOOT_ID", boot),
                mock.patch.object(
                    MODULE.t2_bridge_connection.BridgeConnectionLease,
                    "connect",
                    return_value=Context(lease),
                ),
                mock.patch.object(
                    MODULE.t2_bridge_inventory,
                    "collect_stable_private_inventory",
                    return_value=live,
                ),
                mock.patch.object(
                    MODULE.t2_enrollment_finalizer,
                    "read_local_host_snapshot",
                    return_value={"private": "host"},
                ),
                mock.patch.object(
                    MODULE.t2_enrollment_reconciliation,
                    "append_post_reboot_verified",
                    return_value=verified,
                ) as append,
            ):
                result = MODULE.run_post_reboot_verification(
                    CONFIGURATION, object()
                )
        self.assertTrue(result["post_reboot_verified"])
        self.assertNotIn("private-identity", repr(result))
        self.assertNotIn("private-operation", repr(result))
        self.assertEqual(append.call_args.kwargs["linux_boot_uuid"], boot_uuid)

    def test_existing_advanced_local_store_becomes_current_baseline(self):
        backup_host = {
            "account_uuid": "account",
            "bag_uuid": "bag",
            "host_components": [{"name": "private-metadata"}],
            "archive_sha256": "a" * 64,
        }
        current = {
            "account_uuid": "account",
            "bag_uuid": "bag",
            "identity_records": [{"new": "identity"}],
        }
        store = object()
        with (
            mock.patch.object(MODULE.os.path, "lexists", return_value=True),
            mock.patch.object(
                MODULE.t2_catacomb_local,
                "read_backup_components",
                return_value=(backup_host, {"private": b"backup"}),
            ),
            mock.patch.object(
                MODULE.t2_catacomb_store, "CatacombStore", return_value=store
            ),
            mock.patch.object(
                MODULE.t2_enrollment_finalizer,
                "read_local_host_snapshot",
                return_value=current,
            ) as read_current,
        ):
            host, opened, provisioned = MODULE.open_current_or_provision(
                Path("/private/backup.tar.gz"), CONFIGURATION
            )
        self.assertIs(opened, store)
        self.assertFalse(provisioned)
        self.assertEqual(host["identity_records"], [{"new": "identity"}])
        self.assertEqual(host["archive_sha256"], "a" * 64)
        read_current.assert_called_once_with(
            store,
            {
                "apple_uid": 501,
                "host_components": [{"name": "private-metadata"}],
            },
        )

    def test_existing_local_store_rejects_account_or_keybag_binding_drift(self):
        backup_host = {
            "account_uuid": "account",
            "bag_uuid": "bag",
            "host_components": [],
            "archive_sha256": "a" * 64,
        }
        with (
            mock.patch.object(MODULE.os.path, "lexists", return_value=True),
            mock.patch.object(
                MODULE.t2_catacomb_local,
                "read_backup_components",
                return_value=(backup_host, {}),
            ),
            mock.patch.object(MODULE.t2_catacomb_store, "CatacombStore"),
            mock.patch.object(
                MODULE.t2_enrollment_finalizer,
                "read_local_host_snapshot",
                return_value={"account_uuid": "changed", "bag_uuid": "bag"},
            ),
            self.assertRaisesRegex(MODULE.EnrollmentCommandError, "binding"),
        ):
            MODULE.open_current_or_provision(
                Path("/private/backup.tar.gz"), CONFIGURATION
            )

    def test_missing_local_store_is_provisioned_from_recovery_backup(self):
        store = object()
        host = {"private": "baseline"}
        with (
            mock.patch.object(MODULE.os.path, "lexists", return_value=False),
            mock.patch.object(
                MODULE.t2_catacomb_local,
                "provision_from_backup",
                return_value=(host, store),
            ) as provision,
        ):
            opened_host, opened_store, provisioned = (
                MODULE.open_current_or_provision(
                    Path("/private/backup.tar.gz"), CONFIGURATION
                )
            )
        self.assertIs(opened_host, host)
        self.assertIs(opened_store, store)
        self.assertTrue(provisioned)
        provision.assert_called_once_with(
            Path("/private/backup.tar.gz"), MODULE.STORE_ROOT, 501
        )

    def test_prepare_recovery_discards_only_the_journal_bound_batch(self):
        lifecycle = []
        persistence = SimpleNamespace(
            batch_index=0,
            batches=((('user_000001f5.cat', "1" * 64), ('master.cat', "2" * 64)),),
            staged_files=(("user_000001f5.cat", "7" * 64),),
            phase=MODULE.t2_enrollment_persistence_journal.PersistencePhase.HOST_STAGED,
        )
        history = SimpleNamespace(
            phase=MODULE.t2_enrollment_journal.EnrollmentPhase.PERSISTING,
            baseline={
                "apple_uid": 501,
                "mapping_generation": "d" * 64,
                "connection_generation": "00000000-0000-0000-0000-000000000004",
            },
            persistence=persistence,
            operation_id="private-operation",
        )
        store = SimpleNamespace(
            discard_prepare=mock.Mock(
                side_effect=lambda *_args: lifecycle.append("store")
            ),
            recover=mock.Mock(),
        )
        terminal = SimpleNamespace(
            phase=MODULE.t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN
        )

        def exists(path):
            return path.name == "prepare"

        with (
            mock.patch.object(
                MODULE,
                "unfinished_enrollment_journals",
                return_value=[(Path("/private/journal"), history)],
            ),
            mock.patch.object(MODULE.os.path, "lexists", side_effect=exists),
            mock.patch.object(
                MODULE.t2_enrollment_journal,
                "append_checked",
                side_effect=lambda *_args: (
                    lifecycle.append("journal") or terminal
                ),
            ) as append,
        ):
            result = MODULE.run_local_transaction_recovery(CONFIGURATION, store)
        store.discard_prepare.assert_called_once_with(
            {"user_000001f5.cat", "master.cat"},
            {"user_000001f5.cat": "7" * 64},
        )
        store.recover.assert_not_called()
        self.assertEqual(result["recovery_action"], "prepare-discarded")
        self.assertNotIn("private-operation", repr(result))
        self.assertEqual(
            append.call_args.args[2], "ENROLL_OUTCOME_UNKNOWN"
        )
        self.assertEqual(lifecycle, ["journal", "store"])

    def test_commit_recovery_requires_and_rolls_forward_a_complete_batch(self):
        lifecycle = []
        phases = MODULE.t2_enrollment_persistence_journal.PersistencePhase
        commit_intent = phases.BATCH_COMMIT_INTENT
        persistence = SimpleNamespace(
            batch_index=0,
            batches=((('user_000001f5.cat', "1" * 64), ('master.cat', "2" * 64)),),
            staged_files=(
                ("master.cat", "8" * 64),
                ("user_000001f5.cat", "7" * 64),
            ),
            phase=commit_intent,
        )
        history = SimpleNamespace(
            phase=MODULE.t2_enrollment_journal.EnrollmentPhase.PERSISTING,
            baseline={
                "apple_uid": 501,
                "mapping_generation": "d" * 64,
                "connection_generation": "00000000-0000-0000-0000-000000000004",
            },
            persistence=persistence,
            operation_id="private-operation",
        )
        store = SimpleNamespace(
            discard_prepare=mock.Mock(),
            recover=mock.Mock(
                side_effect=lambda *_args: (
                    lifecycle.append("store") or "commit-rolled-forward"
                )
            ),
        )
        terminal = SimpleNamespace(
            phase=MODULE.t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN
        )

        def exists(path):
            return path.name == "commit"

        with (
            mock.patch.object(
                MODULE,
                "unfinished_enrollment_journals",
                return_value=[(Path("/private/journal"), history)],
            ),
            mock.patch.object(MODULE.os.path, "lexists", side_effect=exists),
            mock.patch.object(
                MODULE.t2_enrollment_journal,
                "append_checked",
                side_effect=lambda *_args: (
                    lifecycle.append("journal") or terminal
                ),
            ),
        ):
            result = MODULE.run_local_transaction_recovery(CONFIGURATION, store)
        store.recover.assert_called_once_with(
            {"master.cat": "8" * 64, "user_000001f5.cat": "7" * 64}
        )
        self.assertEqual(result["recovery_action"], "commit-rolled-forward")
        self.assertEqual(lifecycle, ["journal", "store"])

    def test_local_recovery_replays_after_the_outcome_marker_is_durable(self):
        persistence = SimpleNamespace(
            batch_index=0,
            batches=((('user_000001f5.cat', "1" * 64),),),
            staged_files=(("user_000001f5.cat", "7" * 64),),
            phase=(
                MODULE.t2_enrollment_persistence_journal.PersistencePhase.HOST_STAGED
            ),
        )
        history = SimpleNamespace(
            phase=MODULE.t2_enrollment_journal.EnrollmentPhase.OUTCOME_UNKNOWN,
            outcome_unknown_stage="local-prepare-discarded",
            baseline={
                "apple_uid": 501,
                "mapping_generation": "d" * 64,
                "connection_generation": "00000000-0000-0000-0000-000000000004",
            },
            persistence=persistence,
            operation_id="private-operation",
        )
        store = SimpleNamespace(discard_prepare=mock.Mock(), recover=mock.Mock())

        with (
            mock.patch.object(
                MODULE,
                "unfinished_enrollment_journals",
                return_value=[(Path("/private/journal"), history)],
            ),
            mock.patch.object(
                MODULE.os.path,
                "lexists",
                side_effect=lambda path: path.name == "prepare",
            ),
            mock.patch.object(
                MODULE.t2_enrollment_journal, "append_checked"
            ) as append,
        ):
            result = MODULE.run_local_transaction_recovery(CONFIGURATION, store)
        append.assert_not_called()
        store.discard_prepare.assert_called_once()
        self.assertEqual(result["recovery_action"], "prepare-discarded")

    def test_incomplete_commit_recovery_refuses_before_journal_or_store_mutation(self):
        persistence = SimpleNamespace(
            batch_index=0,
            batches=(
                (
                    ('user_000001f5.cat', "1" * 64),
                    ('master.cat', "2" * 64),
                ),
            ),
            staged_files=(("user_000001f5.cat", "7" * 64),),
            phase=(
                MODULE.t2_enrollment_persistence_journal.PersistencePhase.HOST_STAGED
            ),
        )
        history = SimpleNamespace(
            phase=MODULE.t2_enrollment_journal.EnrollmentPhase.PERSISTING,
            baseline={
                "apple_uid": 501,
                "mapping_generation": "d" * 64,
                "connection_generation": "00000000-0000-0000-0000-000000000004",
            },
            persistence=persistence,
            operation_id="private-operation",
        )
        store = SimpleNamespace(discard_prepare=mock.Mock(), recover=mock.Mock())
        with (
            mock.patch.object(
                MODULE,
                "unfinished_enrollment_journals",
                return_value=[(Path("/private/journal"), history)],
            ),
            mock.patch.object(
                MODULE.os.path,
                "lexists",
                side_effect=lambda path: path.name == "commit",
            ),
            mock.patch.object(
                MODULE.t2_enrollment_journal, "append_checked"
            ) as append,
            self.assertRaisesRegex(
                MODULE.EnrollmentCommandError, "complete journaled host batch"
            ),
        ):
            MODULE.run_local_transaction_recovery(CONFIGURATION, store)
        append.assert_not_called()
        store.discard_prepare.assert_not_called()
        store.recover.assert_not_called()

    def test_orphaned_local_transaction_blocks_live_enrollment(self):
        with tempfile.TemporaryDirectory() as directory:
            store_root = Path(directory)
            (store_root / "prepare").mkdir()
            with (
                mock.patch.object(MODULE, "STORE_ROOT", store_root),
                mock.patch.object(MODULE, "enrollment_journals", return_value=[]),
                self.assertRaisesRegex(
                    MODULE.EnrollmentCommandError, "pending local transaction"
                ),
            ):
                MODULE.require_no_unfinished_enrollment()

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
                    MODULE.Event().is_set,
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
        self.assertNotIn("operation_id", output)

    def test_sleep_inhibitor_is_verified_and_dropped_by_closing_parent_pipe(self):
        class Input:
            closed = False

            def close(self):
                self.closed = True

        process = SimpleNamespace(
            pid=4242,
            stdin=Input(),
            poll=mock.Mock(return_value=None),
            wait=mock.Mock(return_value=0),
            terminate=mock.Mock(),
            kill=mock.Mock(),
        )
        listing = subprocess.CompletedProcess(
            [],
            0,
            stdout=json.dumps(
                [
                    {
                        "pid": 4242,
                        "who": "t2-touchid-enrollment",
                        "what": "sleep",
                        "mode": "block",
                    }
                ]
            ).encode(),
        )
        with (
            mock.patch.object(MODULE.subprocess, "Popen", return_value=process) as popen,
            mock.patch.object(MODULE.subprocess, "run", return_value=listing),
            MODULE.sleep_inhibitor() as active,
        ):
            self.assertIs(active, process)
        self.assertTrue(process.stdin.closed)
        process.wait.assert_called_once_with(timeout=2)
        process.terminate.assert_not_called()
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.PIPE)

    def test_sleep_inhibitor_failure_is_fail_closed_and_cleaned_up(self):
        class Input:
            def close(self):
                return None

        process = SimpleNamespace(
            pid=4242,
            stdin=Input(),
            poll=mock.Mock(return_value=1),
            wait=mock.Mock(return_value=1),
            terminate=mock.Mock(),
            kill=mock.Mock(),
        )
        with (
            mock.patch.object(MODULE.subprocess, "Popen", return_value=process),
            mock.patch.object(
                MODULE, "_sleep_inhibitor_is_registered", return_value=False
            ),
            self.assertRaisesRegex(
                MODULE.EnrollmentCommandError, "exited during setup"
            ),
        ):
            with MODULE.sleep_inhibitor():
                self.fail("unverified inhibitor must not enter the live scope")
        process.wait.assert_called_once_with(timeout=2)

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
