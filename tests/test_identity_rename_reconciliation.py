# SPDX-License-Identifier: GPL-2.0-only
import copy
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_codec as codec
import t2_catacomb_protocol
import t2_identity_rename as rename
import t2_identity_rename_journal as journal
import t2_identity_rename_reconciliation as reconciliation
import t2_mutation_journal as mutation
from tests.test_catacomb_codec import fixture
from tests.test_identity_inventory import live_for
from tests.test_mutation_journal import baseline


class IdentityRenameReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "rename.jsonl"
        self.before = codec.decode_user_catacomb(fixture(), 501)
        self.plan = rename.plan(
            self.before,
            live_for(self.before),
            slot=1,
            new_name="Renamed finger",
        )
        self.after = codec.decode_user_catacomb(
            bytes(rename.bind_secure_blob(self.plan, b"LTFC" + b"z" * 28)), 501
        )
        self.value = baseline()
        self.value["account_uuid"] = self.before.account_uuid
        self.value["bag_uuid"] = self.before.keybag_uuid
        self.value["identity_records"] = [
            {
                "user_id": identity.user_id,
                "uuid": identity.uuid,
                "entity": identity.entity,
            }
            for identity in self.before.identities
        ]
        self.value["capacity"]["used"] = len(self.before.identities)
        self.operation_id, _record = mutation.create(
            self.path, "rename", self.value
        )
        journal.append_checked(
            self.path,
            self.operation_id,
            "RENAME_INTENT",
            {
                "connection_generation": self.value["connection_generation"],
                "user_id": 501,
                "identity_uuid": self.plan.identity_uuid,
                "entity": self.plan.entity,
                "previous_name_sha256": hashlib.sha256(
                    self.plan.previous_name.encode()
                ).hexdigest(),
                "new_name_sha256": hashlib.sha256(
                    self.plan.new_name.encode()
                ).hexdigest(),
                "mapping_generation": self.value["mapping_generation"],
            },
        )
        self._append_to_attestation_ready()
        self.history = journal.read(self.path)
        self.host = {
            "account_uuid": self.before.account_uuid,
            "bag_uuid": self.before.keybag_uuid,
            "identity_records": copy.deepcopy(self.value["identity_records"]),
            "master_enrollment_count": self.value["master_enrollment_count"],
            "host_components": copy.deepcopy(self.value["host_components"]),
        }
        for component in self.host["host_components"]:
            if component["name"] == "user_000001f5.cat":
                component["sha256"] = "9" * 64
        self.live = live_for(self.after)
        self.live.update(
            {
                "connection_generation": self.value["connection_generation"],
                "catacomb": {
                    "present": True,
                    "uuid": self.value["sep_catacomb"]["uuid"],
                    "hash": "3" * 64,
                    "user_states": [
                        {"kind": "master", "user_id": None, "needs_save": False},
                        {"kind": "user", "user_id": 501, "needs_save": False},
                    ],
                },
            }
        )

    def tearDown(self):
        self.temp.cleanup()

    def append(self, milestone, evidence):
        journal.append_checked(self.path, self.operation_id, milestone, evidence)

    def _append_to_attestation_ready(self):
        name = "user_000001f5.cat"
        descriptor = t2_catacomb_protocol.CatacombComponent.user(501).descriptor
        descriptor_hash = hashlib.sha256(descriptor).hexdigest()
        reference = {
            "connection_generation": self.value["connection_generation"],
            "batch_index": 0,
            "component_index": 0,
            "name": name,
            "descriptor_sha256": descriptor_hash,
        }
        self.append(
            "CATACOMB_PERSISTENCE_PLAN",
            {
                "connection_generation": self.value["connection_generation"],
                "batches": [[{"name": name, "descriptor_sha256": descriptor_hash}]],
            },
        )
        self.append("CATACOMB_PREPARE_INTENT", reference)
        self.append("CATACOMB_PREPARED", {**reference, "status": 0, "expected_blob_length": 32})
        self.append("CATACOMB_COMPLETE_INTENT", reference)
        self.append(
            "CATACOMB_SECURE_BLOB_CAPTURED",
            {**reference, "status": 0, "blob_length": 32, "secure_blob_sha256": "6" * 64},
        )
        self.append(
            "CATACOMB_HOST_STAGED",
            {**reference, "secure_blob_sha256": "6" * 64, "final_file_sha256": "7" * 64},
        )
        snapshot = hashlib.sha256(
            mutation.canonical([{"name": name, "final_file_sha256": "7" * 64}])
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

    def classify(self, *, local=None, host=None, live=None):
        return reconciliation.classify(
            self.history,
            self.plan,
            local=self.after if local is None else local,
            host=self.host if host is None else host,
            live=self.live if live is None else live,
            mapping_generation=self.value["mapping_generation"],
        )

    def test_proves_label_only_update_and_clean_sep_state(self):
        result = self.classify()
        self.assertEqual(result.identity_count, 1)
        self.assertTrue(result.label_updated)
        self.assertEqual(len(result.snapshot_sha256), 64)

    def test_rejects_wrong_label_unrelated_component_or_dirty_state(self):
        with self.assertRaisesRegex(
            reconciliation.IdentityRenameReconciliationError, "rename plan"
        ):
            self.classify(local=self.before)

        host = copy.deepcopy(self.host)
        next(
            item for item in host["host_components"] if item["name"] == "master.cat"
        )["sha256"] = "4" * 64
        with self.assertRaisesRegex(
            reconciliation.IdentityRenameReconciliationError, "unrelated"
        ):
            self.classify(host=host)

        live = copy.deepcopy(self.live)
        live["catacomb"]["user_states"][1]["needs_save"] = True
        with self.assertRaisesRegex(
            reconciliation.IdentityRenameReconciliationError, "not clean"
        ):
            self.classify(live=live)


if __name__ == "__main__":
    unittest.main()
