# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_enrollment_journal as enrollment_journal
import t2_catacomb_codec as catacomb_codec
import t2_identity_delete_journal as delete_journal
import t2_identity_rename_journal as rename_journal
import t2_linux_account as linux_account
import t2_post_reboot_reconciler as reconciler
import t2_user_mapping as mapping
import t2_user_readiness as readiness
import t2_user_reconciliation_live as live_reconciliation
from tests.test_catacomb_codec import fixture


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


class Live:
    def __init__(self, selected, material):
        self.selected = selected
        self.material = material
        self.runtime_generation = material.connection_generation
        self.entered = False
        self.exited = False
        self.collect_count = 0

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, _kind, _value, _traceback):
        self.exited = True
        return False

    def collect(self, selected, generation, keybag_sha256):
        self.collect_count += 1
        if (
            selected != self.selected
            or generation != self.selected.linux_account_generation
            or keybag_sha256 != self.selected.keybag_sha256
        ):
            raise AssertionError("wrong live binding")
        return (
            readiness.PersistentEvidence(
                generation,
                keybag_sha256,
                selected.apple_uid,
                selected.account_uuid,
                selected.bag_uuid,
                True,
            ),
            readiness.AliasEvidence(
                True,
                selected.special_bag_alias,
                selected.bag_uuid,
                0,
                selected.account_uuid,
            ),
        )

    def revalidate_runtime_keybag(self, selected, positive_handle):
        return selected == self.selected and positive_handle == 42

    def prepare_post_reboot_material(self, selected, _baseline):
        if selected != self.selected:
            raise AssertionError("wrong material mapping")
        return self.material


class PostRebootReconcilerTests(unittest.TestCase):
    def setUp(self):
        self.mapping = mapping.UserMapping(
            1000,
            "a" * 64,
            501,
            identifier(1),
            identifier(2),
            "/var/lib/t2-touchid/users/1000/user.kb",
            "b" * 64,
            "host-encrypted-credential",
            frozenset({"enroll", "identity-management", "verify"}),
            True,
        )
        self.mapping_set = mapping.UserMappingSet(
            "d" * 64, (self.mapping,)
        )
        self.baseline = {
            "caller_linux_uid": 1000,
            "target_linux_uid": 1000,
            "apple_uid": 501,
            "account_uuid": identifier(1),
            "bag_uuid": identifier(2),
            "mapping_generation": "d" * 64,
        }
        self.history = SimpleNamespace(
            operation_id=identifier(20),
            phase=enrollment_journal.EnrollmentPhase.RECONCILED,
            record_count=10,
            head_hash="e" * 64,
            baseline=self.baseline,
            terminal_identity_uuid=identifier(21),
        )
        self.path = Path("/var/lib/t2-touchid/mutations") / (
            f"{self.history.operation_id}.jsonl"
        )
        self.local = catacomb_codec.decode_user_catacomb(fixture(), 501)
        self.material = live_reconciliation.PostRebootMaterial(
            {"host": True},
            {"live": True},
            self.local,
            501,
            identifier(30),
        )
        self.live = Live(self.mapping, self.material)
        self.account = linux_account.AccountEvidence(1000, "a" * 64)

        self.candidate = reconciler.PendingMutation(
            "enroll", "enroll", self.path, self.history
        )

    def common_patches(self, candidate=None):
        return (
            mock.patch.object(reconciler, "ROOT_UID", os.geteuid()),
            mock.patch.object(
                reconciler,
                "_pending_candidate",
                return_value=candidate or self.candidate,
            ),
            mock.patch.object(
                reconciler.t2_user_mapping_admin,
                "_open_parent",
                return_value=(10, "users.json"),
            ),
            mock.patch.object(
                reconciler.t2_user_mapping_admin,
                "_open_lock",
                return_value=11,
            ),
            mock.patch.object(
                reconciler.t2_user_mapping_admin,
                "_load_optional",
                return_value=self.mapping_set,
            ),
            mock.patch.object(reconciler, "_unchanged_history"),
            mock.patch.object(reconciler.os, "close"),
        )

    def test_no_pending_enrollment_is_a_read_only_noop(self):
        with mock.patch.object(reconciler, "ROOT_UID", os.geteuid()), mock.patch.object(
            reconciler, "_pending_candidate", return_value=None
        ), mock.patch.object(
            reconciler.t2_user_mapping_admin, "_open_parent"
        ) as open_parent:
            result = reconciler.run()
        self.assertEqual(result.state, "no-pending-mutation")
        self.assertFalse(result.journal_updated)
        open_parent.assert_not_called()

    def test_stable_fresh_boot_appends_only_e4(self):
        verified = SimpleNamespace(
            phase=enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED
        )
        append = mock.Mock(return_value=verified)
        patches = self.common_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], mock.patch.object(
            reconciler.t2_enrollment_reconciliation,
            "append_post_reboot_verified",
            append,
        ):
            result = reconciler.run(
                live_factory=lambda: self.live,
                account_collector=lambda _uid: self.account,
                keybag_reader=lambda _path: "b" * 64,
                runtime_state=lambda _alias: (1, 42),
                boot_reader=lambda: identifier(40),
            )
        self.assertEqual(result.state, "enroll-post-reboot-verified")
        self.assertTrue(result.journal_updated)
        self.assertEqual(self.live.collect_count, 2)
        self.assertTrue(self.live.exited)
        arguments = append.call_args.kwargs
        self.assertIs(arguments["host"], self.material.host)
        self.assertIs(arguments["live"], self.material.live)
        self.assertTrue(arguments["keybag_runtime_revalidated"])

    def test_mapping_drift_fails_before_live_collection_or_append(self):
        self.history.baseline["mapping_generation"] = "f" * 64
        append = mock.Mock()
        patches = self.common_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], mock.patch.object(
            reconciler.t2_enrollment_reconciliation,
            "append_post_reboot_verified",
            append,
        ):
            with self.assertRaisesRegex(
                reconciler.PostRebootReconcilerError,
                "another protected mapping",
            ):
                reconciler.run(
                    live_factory=lambda: self.live,
                    account_collector=lambda _uid: self.account,
                    keybag_reader=lambda _path: "b" * 64,
                    runtime_state=lambda _alias: (1, 42),
                    boot_reader=lambda: identifier(40),
                )
        self.assertEqual(self.live.collect_count, 0)
        append.assert_not_called()

    def test_invalid_runtime_handle_fails_before_live_collection(self):
        patches = self.common_patches()
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
        ):
            with self.assertRaisesRegex(
                reconciler.PostRebootReconcilerError,
                "runtime keybag state",
            ):
                reconciler.run(
                    live_factory=lambda: self.live,
                    account_collector=lambda _uid: self.account,
                    keybag_reader=lambda _path: "b" * 64,
                    runtime_state=lambda _alias: (2, 42),
                    boot_reader=lambda: identifier(40),
                )
        self.assertEqual(self.live.collect_count, 0)

    def test_candidate_scan_requires_one_blocking_reconciled_enrollment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / f"{self.history.operation_id}.jsonl"
            path.touch()
            entry = SimpleNamespace(blocks_new_mutation=True)
            with mock.patch.object(reconciler, "MUTATION_ROOT", root), mock.patch.object(
                reconciler.t2_mutation_registry,
                "scan",
                return_value=(entry,),
            ), mock.patch.object(
                reconciler.t2_mutation_journal,
                "read",
                return_value=[{"evidence": {"operation_kind": "enroll"}}],
            ), mock.patch.object(
                reconciler.t2_enrollment_journal,
                "validate_history",
                return_value=self.history,
            ):
                candidate = reconciler._pending_candidate()
                self.assertEqual(candidate.kind, "enroll")
                self.assertEqual(candidate.capability, "enroll")
                self.assertEqual(candidate.path, path)
                self.assertIs(candidate.history, self.history)

                with mock.patch.object(
                    reconciler.t2_mutation_registry,
                    "scan",
                    return_value=(entry, entry),
                ):
                    with self.assertRaisesRegex(
                        reconciler.PostRebootReconcilerError,
                        "another biometric mutation",
                    ):
                        reconciler._pending_candidate()

    def test_stable_rename_appends_only_rename_post_reboot_proof(self):
        history = SimpleNamespace(
            operation_id=identifier(50),
            phase=rename_journal.IdentityRenamePhase.RECONCILED,
            record_count=12,
            head_hash="f" * 64,
            baseline=dict(self.baseline),
        )
        path = Path("/var/lib/t2-touchid/mutations") / (
            f"{history.operation_id}.jsonl"
        )
        candidate = reconciler.PendingMutation(
            "rename", "identity-management", path, history
        )
        verified = SimpleNamespace(
            phase=rename_journal.IdentityRenamePhase.POST_REBOOT_VERIFIED
        )
        rename_append = mock.Mock(return_value=verified)
        enrollment_append = mock.Mock()
        patches = self.common_patches(candidate)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            mock.patch.object(
                reconciler.t2_identity_rename_reconciliation,
                "append_post_reboot_verified",
                rename_append,
            ),
            mock.patch.object(
                reconciler.t2_enrollment_reconciliation,
                "append_post_reboot_verified",
                enrollment_append,
            ),
        ):
            result = reconciler.run(
                live_factory=lambda: self.live,
                account_collector=lambda _uid: self.account,
                keybag_reader=lambda _path: "b" * 64,
                runtime_state=lambda _alias: (1, 42),
                boot_reader=lambda: identifier(40),
            )
        self.assertEqual(result.state, "rename-post-reboot-verified")
        self.assertTrue(result.journal_updated)
        enrollment_append.assert_not_called()
        self.assertIs(rename_append.call_args.kwargs["local"], self.local)
        self.assertIs(rename_append.call_args.kwargs["host"], self.material.host)
        self.assertIs(rename_append.call_args.kwargs["live"], self.material.live)

    def test_candidate_scan_selects_one_reconciled_rename(self):
        history = SimpleNamespace(
            operation_id=identifier(60),
            phase=rename_journal.IdentityRenamePhase.RECONCILED,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / f"{history.operation_id}.jsonl"
            path.touch()
            entry = SimpleNamespace(blocks_new_mutation=True)
            with (
                mock.patch.object(reconciler, "MUTATION_ROOT", root),
                mock.patch.object(
                    reconciler.t2_mutation_registry,
                    "scan",
                    return_value=(entry,),
                ),
                mock.patch.object(
                    reconciler.t2_mutation_journal,
                    "read",
                    return_value=[{"evidence": {"operation_kind": "rename"}}],
                ),
                mock.patch.object(
                    reconciler.t2_identity_rename_journal,
                    "validate_history",
                    return_value=history,
                ),
            ):
                candidate = reconciler._pending_candidate()
        self.assertEqual(candidate.kind, "rename")
        self.assertEqual(candidate.capability, "identity-management")
        self.assertEqual(candidate.path, path)
        self.assertIs(candidate.history, history)

    def test_stable_delete_appends_only_delete_post_reboot_proof(self):
        history = SimpleNamespace(
            operation_id=identifier(70),
            phase=delete_journal.IdentityDeletePhase.RECONCILED,
            record_count=14,
            head_hash="9" * 64,
            baseline=dict(self.baseline),
        )
        path = Path("/var/lib/t2-touchid/mutations") / (
            f"{history.operation_id}.jsonl"
        )
        candidate = reconciler.PendingMutation(
            "delete-one", "identity-management", path, history
        )
        verified = SimpleNamespace(
            phase=delete_journal.IdentityDeletePhase.POST_REBOOT_VERIFIED
        )
        delete_append = mock.Mock(return_value=verified)
        enrollment_append = mock.Mock()
        rename_append = mock.Mock()
        patches = self.common_patches(candidate)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            mock.patch.object(
                reconciler.t2_identity_delete_reconciliation,
                "append_post_reboot_verified",
                delete_append,
            ),
            mock.patch.object(
                reconciler.t2_enrollment_reconciliation,
                "append_post_reboot_verified",
                enrollment_append,
            ),
            mock.patch.object(
                reconciler.t2_identity_rename_reconciliation,
                "append_post_reboot_verified",
                rename_append,
            ),
        ):
            result = reconciler.run(
                live_factory=lambda: self.live,
                account_collector=lambda _uid: self.account,
                keybag_reader=lambda _path: "b" * 64,
                runtime_state=lambda _alias: (1, 42),
                boot_reader=lambda: identifier(40),
            )
        self.assertEqual(result.state, "delete-one-post-reboot-verified")
        self.assertTrue(result.journal_updated)
        enrollment_append.assert_not_called()
        rename_append.assert_not_called()
        self.assertIs(delete_append.call_args.kwargs["local"], self.local)
        self.assertIs(delete_append.call_args.kwargs["host"], self.material.host)
        self.assertIs(delete_append.call_args.kwargs["live"], self.material.live)

    def test_candidate_scan_selects_one_reconciled_delete(self):
        history = SimpleNamespace(
            operation_id=identifier(80),
            phase=delete_journal.IdentityDeletePhase.RECONCILED,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / f"{history.operation_id}.jsonl"
            path.touch()
            entry = SimpleNamespace(blocks_new_mutation=True)
            with (
                mock.patch.object(reconciler, "MUTATION_ROOT", root),
                mock.patch.object(
                    reconciler.t2_mutation_registry,
                    "scan",
                    return_value=(entry,),
                ),
                mock.patch.object(
                    reconciler.t2_mutation_journal,
                    "read",
                    return_value=[
                        {"evidence": {"operation_kind": "delete-one"}}
                    ],
                ),
                mock.patch.object(
                    reconciler.t2_identity_delete_journal,
                    "validate_history",
                    return_value=history,
                ),
            ):
                candidate = reconciler._pending_candidate()
        self.assertEqual(candidate.kind, "delete-one")
        self.assertEqual(candidate.capability, "identity-management")
        self.assertEqual(candidate.path, path)
        self.assertIs(candidate.history, history)

    def test_service_is_read_only_ordered_and_installed(self):
        root = Path(__file__).parents[1]
        unit = (
            root / "systemd/system/t2-touchid-post-reboot.service"
        ).read_text(encoding="utf-8")
        fprintd = (root / "systemd/system/fprintd.service").read_text(
            encoding="utf-8"
        )
        install = (root / "install.sh").read_text(encoding="utf-8")
        uninstall = (root / "uninstall.sh").read_text(encoding="utf-8")
        for required in (
            "Before=fprintd.service",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "DevicePolicy=closed",
            "DeviceAllow=/dev/t2-aks rw",
            "ReadWritePaths=/run/t2-touchid /var/lib/t2-touchid",
        ):
            self.assertIn(required, unit)
        self.assertNotIn("LoadCredential", unit)
        self.assertNotIn("t2-fprint-enrollment-worker", unit)
        self.assertIn("Wants=t2-touchid-post-reboot.service", fprintd)
        self.assertIn("t2-touchid-post-reboot.py", install)
        self.assertIn("t2-touchid-post-reboot", uninstall)


if __name__ == "__main__":
    unittest.main()
