# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import sys
import tempfile
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_codec as codec
import t2_catacomb_store as store_module
import t2_external_delete_reconcile as reconcile
import t2_mutation_journal as mutation
from tests.test_catacomb_codec import biolockout_fixture, fixture, master_fixture
from tests.test_identity_inventory import live_for


class ExternalDeletePlanTests(unittest.TestCase):
    def setUp(self):
        first = codec.decode_user_catacomb(fixture(), 501)
        self.local = codec.decode_user_catacomb(
            first.add(
                identity_uuid=str(uuid.UUID(int=4)),
                entity=1,
                name="right-thumb",
            ),
            501,
        )
        self.live = live_for(self.local)
        self.live["per_user_identity_records"] = self.live[
            "per_user_identity_records"
        ][:-1]
        self.live["global_identity_records"] = self.live[
            "global_identity_records"
        ][:-1]
        self.live["catacomb"]["user_states"] = [
            {"kind": "user", "user_id": 501, "needs_save": False},
            {"kind": "master", "needs_save": False},
        ]

    def test_plans_exact_local_only_identity_without_changing_survivor(self):
        result = reconcile.plan(self.local, self.live)
        survivor = codec.decode_user_catacomb(result.archive, 501)

        self.assertEqual(result.local_identity_count, 2)
        self.assertEqual(result.live_identity_count, 1)
        self.assertEqual(survivor.identities, (self.local.identities[0],))
        self.assertEqual(survivor.account_uuid, self.local.account_uuid)
        self.assertEqual(survivor.keybag_uuid, self.local.keybag_uuid)
        self.assertEqual(survivor.secure_data, self.local.secure_data)
        self.assertNotIn(result.stale_identity_uuid, repr(result))
        reconcile.verify(result, survivor, self.live)

    def test_rejects_any_shape_other_than_one_local_only_identity(self):
        cases = []
        no_difference = live_for(self.local)
        no_difference["catacomb"]["user_states"] = self.live["catacomb"][
            "user_states"
        ]
        cases.append(no_difference)

        no_live = dict(self.live)
        no_live["per_user_identity_records"] = []
        no_live["global_identity_records"] = []
        cases.append(no_live)

        live_only = dict(self.live)
        live_only["per_user_identity_records"] = [
            {"user_id": 501, "identity_uuid": str(uuid.UUID(int=99))}
        ]
        live_only["global_identity_records"] = [
            {
                "user_id": 501,
                "identity_uuid": str(uuid.UUID(int=99)),
                "group_type": 1,
                "group_uuid": str(uuid.UUID(int=0)),
            }
        ]
        cases.append(live_only)

        dirty = dict(self.live)
        dirty["catacomb"] = {
            **self.live["catacomb"],
            "user_states": [
                {"kind": "user", "user_id": 501, "needs_save": True},
                {"kind": "master", "needs_save": False},
            ],
        }
        cases.append(dirty)

        for value in cases:
            with self.subTest(value=value), self.assertRaises(
                reconcile.ExternalDeleteReconcileError
            ):
                reconcile.plan(self.local, value)

    def test_verification_rejects_reappearance_or_changed_survivor(self):
        result = reconcile.plan(self.local, self.live)
        with self.assertRaises(reconcile.ExternalDeleteReconcileError):
            reconcile.verify(result, self.local, self.live)


class ExternalDeleteBackupTests(unittest.TestCase):
    def test_creates_exclusive_private_full_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            operation_id = "00000000-0000-0000-0000-000000000091"
            components = {
                "master.cat": b"master",
                "user_000001f5.cat": b"user",
            }
            result = reconcile.create_backup(root, operation_id, components)
            target = root / operation_id

            self.assertEqual(result.reference, operation_id)
            self.assertEqual(
                {name for name, _digest in result.component_hashes},
                set(components),
            )
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)
            for name, value in components.items():
                self.assertEqual((target / name).read_bytes(), value)
                self.assertEqual((target / name).stat().st_mode & 0o777, 0o600)
            with self.assertRaises(reconcile.ExternalDeleteReconcileError):
                reconcile.create_backup(root, operation_id, components)

    def test_plan_commits_only_the_user_component_and_reconciles(self):
        first = codec.decode_user_catacomb(fixture(), 501)
        local_archive = first.add(
            identity_uuid=str(uuid.UUID(int=4)),
            entity=1,
            name="right-thumb",
        )
        local = codec.decode_user_catacomb(local_archive, 501)
        live = live_for(local)
        live["per_user_identity_records"] = live["per_user_identity_records"][:-1]
        live["global_identity_records"] = live["global_identity_records"][:-1]
        live["catacomb"]["user_states"] = [
            {"kind": "user", "user_id": 501, "needs_save": False},
            {"kind": "master", "needs_save": False},
        ]
        plan = reconcile.plan(local, live)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "catacomb"
            root.mkdir(mode=0o700)
            components = {
                "master.cat": master_fixture(),
                "biolockout.cat": biolockout_fixture(),
                "user_000001f5.cat": local_archive,
            }
            for name, data in components.items():
                target = root / name
                target.write_bytes(data)
                target.chmod(0o600)
            store = store_module.CatacombStore(root, 501)
            user_name = "user_000001f5.cat"
            store.begin_stage({user_name})
            digest = store.stage_component(user_name, plan.archive, {user_name})
            store.cross_commit_boundary({user_name: digest})
            committed = store.read_committed_components()

        self.assertEqual(committed["master.cat"], components["master.cat"])
        self.assertEqual(
            committed["biolockout.cat"], components["biolockout.cat"]
        )
        survivor = codec.decode_user_catacomb(committed[user_name], 501)
        reconcile.verify(plan, survivor, live)


def baseline_evidence():
    return {
        "operation_kind": "reconcile-external-delete",
        "apple_uid": 501,
        "linux_boot_uuid": "00000000-0000-0000-0000-000000000081",
        "connection_generation": "00000000-0000-0000-0000-000000000082",
        "mapping_generation": "1" * 64,
        "local_identity_count": 2,
        "live_identity_count": 1,
        "stale_identity_uuid": "00000000-0000-0000-0000-000000000083",
        "stale_entity": 1,
        "stale_name_sha256": "2" * 64,
        "local_snapshot_sha256": "3" * 64,
        "live_snapshot_sha256": "4" * 64,
        "survivor_snapshot_sha256": "5" * 64,
        "before_user_sha256": "6" * 64,
        "other_components_snapshot_sha256": "7" * 64,
        "backup_reference": "00000000-0000-0000-0000-000000000084",
        "backup_snapshot_sha256": "8" * 64,
        "sep_mutation_performed": False,
    }


class ExternalDeleteJournalTests(unittest.TestCase):
    def test_validates_complete_host_only_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "00000000-0000-0000-0000-000000000090.jsonl"
            operation_id = "00000000-0000-0000-0000-000000000090"
            history = reconcile.create_journal(
                path, operation_id, baseline_evidence()
            )
            self.assertEqual(history.phase, reconcile.ExternalDeletePhase.BASELINE)
            history = reconcile.append_checked(
                path,
                operation_id,
                "EXTERNAL_DELETE_INTENT",
                {
                    "connection_generation": baseline_evidence()[
                        "connection_generation"
                    ],
                    "staged_user_sha256": "9" * 64,
                    "survivor_snapshot_sha256": "5" * 64,
                    "identity_count": 1,
                    "sep_mutation_performed": False,
                },
            )
            self.assertEqual(history.phase, reconcile.ExternalDeletePhase.INTENT)
            history = reconcile.append_checked(
                path,
                operation_id,
                "EXTERNAL_DELETE_HOST_COMMITTED",
                {
                    "staged_user_sha256": "9" * 64,
                    "recovery_action": "direct",
                    "sep_mutation_performed": False,
                },
            )
            history = reconcile.append_checked(
                path,
                operation_id,
                "EXTERNAL_DELETE_RECONCILED",
                {
                    "connection_generation": "00000000-0000-0000-0000-000000000082",
                    "staged_user_sha256": "9" * 64,
                    "identity_count": 1,
                    "local_live_equal": True,
                    "target_absent": True,
                    "other_components_unchanged": True,
                    "sep_mutation_performed": False,
                },
            )
            self.assertEqual(
                history.phase, reconcile.ExternalDeletePhase.RECONCILED
            )
            self.assertNotIn(baseline_evidence()["stale_identity_uuid"], repr(history))
            self.assertEqual(
                reconcile.validate_history(mutation.read(path)), history
            )

    def test_rejects_any_claim_of_sep_mutation(self):
        evidence = baseline_evidence()
        evidence["sep_mutation_performed"] = True
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "00000000-0000-0000-0000-000000000092.jsonl"
            with self.assertRaises(reconcile.ExternalDeleteReconcileError):
                reconcile.create_journal(
                    path,
                    "00000000-0000-0000-0000-000000000092",
                    evidence,
                )


if __name__ == "__main__":
    unittest.main()
