# SPDX-License-Identifier: GPL-2.0-only
import hashlib
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_protocol as catacomb_protocol
import t2_identity_rename_journal as rename_journal
import t2_mutation_journal as mutation
from tests.test_mutation_journal import baseline


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class IdentityRenameJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "rename.jsonl"
        self.value = baseline()
        self.operation_id, _record = mutation.create(
            self.path, "rename", self.value
        )
        self.target = self.value["identity_records"][0]
        self.intent = {
            "connection_generation": self.value["connection_generation"],
            "user_id": self.value["apple_uid"],
            "identity_uuid": self.target["uuid"],
            "entity": self.target["entity"],
            "previous_name_sha256": digest("Old"),
            "new_name_sha256": digest("New"),
            "mapping_generation": self.value["mapping_generation"],
        }

    def tearDown(self):
        self.temp.cleanup()

    def append(self, milestone, evidence):
        return rename_journal.append_checked(
            self.path, self.operation_id, milestone, evidence
        )

    def append_complete_user_persistence(self):
        name = f'user_{self.value["apple_uid"]:08x}.cat'
        descriptor = catacomb_protocol.CatacombComponent.user(
            self.value["apple_uid"]
        ).descriptor
        descriptor_hash = hashlib.sha256(descriptor).hexdigest()
        reference = {
            "connection_generation": self.value["connection_generation"],
            "batch_index": 0,
            "component_index": 0,
            "name": name,
            "descriptor_sha256": descriptor_hash,
        }
        blob_hash = "6" * 64
        file_hash = "7" * 64
        self.append(
            "CATACOMB_PERSISTENCE_PLAN",
            {
                "connection_generation": self.value["connection_generation"],
                "batches": [[{"name": name, "descriptor_sha256": descriptor_hash}]],
            },
        )
        self.append("CATACOMB_PREPARE_INTENT", reference)
        self.append(
            "CATACOMB_PREPARED",
            {**reference, "status": 0, "expected_blob_length": 32},
        )
        self.append("CATACOMB_COMPLETE_INTENT", reference)
        self.append(
            "CATACOMB_SECURE_BLOB_CAPTURED",
            {
                **reference,
                "status": 0,
                "blob_length": 32,
                "secure_blob_sha256": blob_hash,
            },
        )
        self.append(
            "CATACOMB_HOST_STAGED",
            {
                **reference,
                "secure_blob_sha256": blob_hash,
                "final_file_sha256": file_hash,
            },
        )
        snapshot = hashlib.sha256(
            mutation.canonical([{"name": name, "final_file_sha256": file_hash}])
        ).hexdigest()
        batch = {
            "connection_generation": self.value["connection_generation"],
            "batch_index": 0,
            "staged_snapshot_sha256": snapshot,
        }
        self.append("CATACOMB_HOST_BATCH_COMMIT_INTENT", batch)
        self.append("CATACOMB_HOST_BATCH_COMMITTED", batch)
        self.append("CATACOMB_FINAL_CONFIRM_INTENT", reference)
        self.append("CATACOMB_FINAL_CONFIRMED", {**reference, "status": 0})
        return self.append(
            "CATACOMB_PERSISTENCE_ATTESTED",
            {
                "connection_generation": self.value["connection_generation"],
                "batch_count": 1,
                "reconciliation_snapshot_sha256": "8" * 64,
                "sep_host_generation_equal": True,
                "independent_archive_readback": True,
            },
        )

    def test_one_user_component_reaches_reconciled_and_post_reboot(self):
        history = self.append("RENAME_INTENT", self.intent)
        self.assertEqual(history.phase, rename_journal.IdentityRenamePhase.INTENT)
        history = self.append_complete_user_persistence()
        self.assertEqual(
            history.phase, rename_journal.IdentityRenamePhase.PERSISTENCE_READY
        )
        reconciliation = {
            "connection_generation": self.value["connection_generation"],
            "identity_uuid": self.target["uuid"],
            "new_name_sha256": self.intent["new_name_sha256"],
            "snapshot_sha256": "8" * 64,
            "mapping_generation": self.value["mapping_generation"],
            "identity_count": len(self.value["identity_records"]),
            "identity_set_unchanged": True,
            "label_updated": True,
            "local_live_equal": True,
        }
        history = self.append("RENAME_RECONCILED", reconciliation)
        self.assertEqual(history.phase, rename_journal.IdentityRenamePhase.RECONCILED)
        history = self.append(
            "RENAME_POST_REBOOT_VERIFIED",
            {
                "linux_boot_uuid": str(uuid.UUID(int=91)),
                "connection_generation": str(uuid.UUID(int=92)),
                "identity_uuid": self.target["uuid"],
                "new_name_sha256": self.intent["new_name_sha256"],
                "snapshot_sha256": "8" * 64,
                "mapping_generation": self.value["mapping_generation"],
                "identity_set_unchanged": True,
                "label_preserved": True,
                "local_live_equal": True,
            },
        )
        self.assertEqual(
            history.phase, rename_journal.IdentityRenamePhase.POST_REBOOT_VERIFIED
        )

    def test_rejects_wrong_target_and_enrollment_component_plan(self):
        invalid = dict(self.intent)
        invalid["identity_uuid"] = str(uuid.UUID(int=99))
        with self.assertRaises(rename_journal.IdentityRenameJournalError):
            self.append("RENAME_INTENT", invalid)

        self.append("RENAME_INTENT", self.intent)
        with self.assertRaisesRegex(
            rename_journal.IdentityRenameJournalError, "only its user"
        ):
            self.append(
                "CATACOMB_PERSISTENCE_PLAN",
                {
                    "connection_generation": self.value["connection_generation"],
                    "batches": [
                        [
                            {
                                "name": "master.cat",
                                "descriptor_sha256": "1" * 64,
                            }
                        ]
                    ],
                },
            )

    def test_recovery_intent_can_close_as_committed_or_no_change(self):
        for committed, action in (
            (False, "prepare-discarded"),
            (True, "no-local-transaction"),
        ):
            with self.subTest(committed=committed), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "rename.jsonl"
                operation_id, _record = mutation.create(path, "rename", self.value)
                rename_journal.append_checked(
                    path, operation_id, "RENAME_INTENT", self.intent
                )
                history = rename_journal.append_checked(
                    path,
                    operation_id,
                    "RENAME_RECOVERY_INTENT",
                    {
                        "action": action,
                        "mapping_generation": self.value["mapping_generation"],
                        "host_commit_possible": action != "prepare-discarded",
                        "mutation_possible": True,
                    },
                )
                self.assertEqual(
                    history.phase, rename_journal.IdentityRenamePhase.OUTCOME_UNKNOWN
                )
                milestone = (
                    "RENAME_RECOVERY_RECONCILED_COMMITTED"
                    if committed
                    else "RENAME_RECOVERY_RECONCILED_NO_CHANGE"
                )
                history = rename_journal.append_checked(
                    path,
                    operation_id,
                    milestone,
                    {
                        "connection_generation": str(uuid.UUID(int=7001)),
                        "identity_uuid": self.target["uuid"],
                        "name_sha256": (
                            self.intent["new_name_sha256"]
                            if committed
                            else self.intent["previous_name_sha256"]
                        ),
                        "snapshot_sha256": "8" * 64,
                        "mapping_generation": self.value["mapping_generation"],
                        "identity_count": len(self.value["identity_records"]),
                        "identity_set_unchanged": True,
                        "local_live_equal": True,
                        "sep_clean": True,
                        "host_reconciled": True,
                        "recovery_action": action,
                    },
                )
                self.assertEqual(
                    history.phase,
                    rename_journal.IdentityRenamePhase.RECONCILED
                    if committed
                    else rename_journal.IdentityRenamePhase.ABORTED,
                )

    def test_roll_forward_cannot_be_claimed_as_no_change(self):
        self.append("RENAME_INTENT", self.intent)
        self.append(
            "RENAME_RECOVERY_INTENT",
            {
                "action": "commit-rolled-forward",
                "mapping_generation": self.value["mapping_generation"],
                "host_commit_possible": True,
                "mutation_possible": True,
            },
        )
        with self.assertRaisesRegex(
            rename_journal.IdentityRenameJournalError, "cannot reconcile"
        ):
            self.append(
                "RENAME_RECOVERY_RECONCILED_NO_CHANGE",
                {
                    "connection_generation": str(uuid.UUID(int=7002)),
                    "identity_uuid": self.target["uuid"],
                    "name_sha256": self.intent["previous_name_sha256"],
                    "snapshot_sha256": "8" * 64,
                    "mapping_generation": self.value["mapping_generation"],
                    "identity_count": len(self.value["identity_records"]),
                    "identity_set_unchanged": True,
                    "local_live_equal": True,
                    "sep_clean": True,
                    "host_reconciled": True,
                    "recovery_action": "commit-rolled-forward",
                },
            )


if __name__ == "__main__":
    unittest.main()
