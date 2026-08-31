# SPDX-License-Identifier: GPL-2.0-only
import hashlib
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_codec as codec
import t2_identity_delete as delete
import t2_identity_delete_bridge as delete_bridge
import t2_identity_delete_journal as journal
import t2_identity_delete_operation as operation
import t2_mutation_journal as mutation
from tests.test_catacomb_codec import fixture
from tests.test_identity_delete_journal import delete_baseline
from tests.test_identity_inventory import live_for


class FakeBridge:
    def __init__(self, generation, *, status=0, error=None):
        self.connection_generation = generation
        self.status = status
        self.error = error

    def delete(self, request):
        if self.error:
            raise self.error
        return delete_bridge.IdentityDeleteCommandResult(self.status)


class IdentityDeleteOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "delete.jsonl"
        one = codec.decode_user_catacomb(fixture(), 501)
        self.local = codec.decode_user_catacomb(
            one.add(identity_uuid=str(uuid.UUID(int=2)), entity=1, name="Finger 2"),
            501,
        )
        self.plan = delete.plan(self.local, live_for(self.local), slot=2)
        self.value = delete_baseline()
        self.value["identity_records"] = [
            {"user_id": item.user_id, "uuid": item.uuid, "entity": item.entity}
            for item in self.local.identities
        ]
        self.operation_id, _record = mutation.create(
            self.path, "delete-one", self.value
        )
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_INTENT",
            {
                "connection_generation": self.value["connection_generation"],
                "user_id": 501,
                "identity_uuid": self.plan.identity_uuid,
                "entity": self.plan.entity,
                "target_name_sha256": hashlib.sha256(
                    self.plan.name.encode()
                ).hexdigest(),
                "request_sha256": hashlib.sha256(self.plan.request).hexdigest(),
                "request_length": 20,
                "survivor_snapshot_sha256": self.plan.survivor_snapshot_sha256,
                "survivor_count": 1,
                "mapping_generation": self.value["mapping_generation"],
            },
        )

    def tearDown(self):
        self.temp.cleanup()

    def live(self, local):
        value = live_for(local)
        value.update(
            {
                "connection_generation": self.value["connection_generation"],
                "catacomb": {
                    "present": True,
                    "uuid": self.value["sep_catacomb"]["uuid"],
                    "hash": self.value["sep_catacomb"]["hash"],
                },
            }
        )
        return value

    def execute(self, bridge, live):
        return operation.run(
            self.path,
            self.operation_id,
            plan=self.plan,
            local=self.local,
            bridge=bridge,
            collect_inventory=lambda: live,
        )

    def test_stable_survivors_override_nonzero_command_status(self):
        survivors = codec.decode_user_catacomb(self.plan.archive, 501)
        result = self.execute(
            FakeBridge(self.value["connection_generation"], status=-9),
            self.live(survivors),
        )
        self.assertEqual(result.outcome, "sep-deleted")
        self.assertEqual(
            journal.read(self.path).phase, journal.IdentityDeletePhase.SEP_DELETED
        )

    def test_failed_command_and_exact_original_state_closes_not_deleted(self):
        result = self.execute(
            FakeBridge(self.value["connection_generation"], status=-1),
            self.live(self.local),
        )
        self.assertEqual(result.outcome, "not-deleted")
        self.assertEqual(
            journal.read(self.path).phase, journal.IdentityDeletePhase.ABORTED
        )

    def test_success_with_target_still_present_freezes(self):
        with self.assertRaisesRegex(operation.IdentityDeleteOperationError, "readback"):
            self.execute(
                FakeBridge(self.value["connection_generation"], status=0),
                self.live(self.local),
            )
        self.assertEqual(
            journal.read(self.path).phase,
            journal.IdentityDeletePhase.OUTCOME_UNKNOWN,
        )

    def test_transport_failure_is_durable_outcome_unknown(self):
        with self.assertRaisesRegex(operation.IdentityDeleteOperationError, "dispatch"):
            self.execute(
                FakeBridge(
                    self.value["connection_generation"],
                    error=OSError("synthetic private failure"),
                ),
                self.live(self.local),
            )
        self.assertEqual(
            journal.read(self.path).phase,
            journal.IdentityDeletePhase.OUTCOME_UNKNOWN,
        )


if __name__ == "__main__":
    unittest.main()
