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
import t2_identity_delete_journal as journal
import t2_identity_delete_persistence as persistence
import t2_mutation_journal as mutation
from tests.test_catacomb_codec import fixture
from tests.test_identity_delete_journal import delete_baseline
from tests.test_identity_inventory import live_for


class FakeTransport:
    def __init__(self, fail_at=None):
        self.fail_at = fail_at
        self.blob = bytearray(b"LTFC" + b"z" * 28)
        self.calls = []

    def prepare(self, descriptor):
        self.calls.append("prepare")
        if self.fail_at == "prepare":
            raise OSError("synthetic private error")
        return 0, len(self.blob)

    def complete(self, descriptor):
        self.calls.append("complete")
        if self.fail_at == "complete":
            raise OSError("synthetic private error")
        return 0, self.blob

    def confirm(self, descriptor):
        self.calls.append("confirm")
        if self.fail_at == "confirm":
            raise OSError("synthetic private error")
        return 0


class FakeStore:
    def __init__(self, fail_at=None):
        self.fail_at = fail_at
        self.staged = None
        self.committed = None

    def begin_stage(self, expected_names):
        if self.fail_at == "begin":
            raise OSError("synthetic private error")
        self.expected_names = expected_names

    def stage_component(self, name, data, expected_names):
        if self.fail_at == "stage":
            raise OSError("synthetic private error")
        self.staged = bytes(data)
        return hashlib.sha256(data).hexdigest()

    def cross_commit_boundary(self, expected):
        if self.fail_at == "commit":
            raise OSError("synthetic private error")
        self.committed = self.staged


class IdentityDeletePersistenceTests(unittest.TestCase):
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
        target_name_hash = hashlib.sha256(self.plan.name.encode()).hexdigest()
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_INTENT",
            {
                "connection_generation": self.value["connection_generation"],
                "user_id": 501,
                "identity_uuid": self.plan.identity_uuid,
                "entity": self.plan.entity,
                "target_name_sha256": target_name_hash,
                "request_sha256": hashlib.sha256(self.plan.request).hexdigest(),
                "request_length": 20,
                "survivor_snapshot_sha256": self.plan.survivor_snapshot_sha256,
                "survivor_count": 1,
                "mapping_generation": self.value["mapping_generation"],
            },
        )
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_DISPATCH_INTENT",
            {
                "connection_generation": self.value["connection_generation"],
                "identity_uuid": self.plan.identity_uuid,
                "request_sha256": hashlib.sha256(self.plan.request).hexdigest(),
                "command": 0x0D,
                "protocol_version": 0,
            },
        )
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_COMMAND_OBSERVED",
            {
                "connection_generation": self.value["connection_generation"],
                "identity_uuid": self.plan.identity_uuid,
                "status": 0,
                "output_length": 0,
                "service_event_count": 0,
            },
        )
        journal.append_checked(
            self.path,
            self.operation_id,
            "DELETE_SEP_ABSENCE_OBSERVED",
            {
                "connection_generation": self.value["connection_generation"],
                "identity_uuid": self.plan.identity_uuid,
                "survivor_snapshot_sha256": self.plan.survivor_snapshot_sha256,
                "survivor_count": 1,
                "stable_double_read": True,
                "per_user_global_equal": True,
                "target_absent": True,
            },
        )

    def tearDown(self):
        self.temp.cleanup()

    def execute(self, transport=None, store=None, readback=None):
        return persistence.run(
            self.path,
            self.operation_id,
            plan=self.plan,
            transport=transport or FakeTransport(),
            store=store or FakeStore(),
            mapping_generation=self.value["mapping_generation"],
            readback=readback
            or (lambda: persistence.DeleteReadbackAttestation(
                connection_generation=self.value["connection_generation"],
                snapshot_sha256="8" * 64,
                identity_count=1,
            )),
        )

    def test_forward_transaction_persists_survivors_and_wipes_blob(self):
        transport = FakeTransport()
        store = FakeStore()
        result = self.execute(transport=transport, store=store)
        self.assertEqual(result.phase, journal.IdentityDeletePhase.RECONCILED)
        self.assertEqual(transport.calls, ["prepare", "complete", "confirm"])
        self.assertEqual(bytes(transport.blob), bytes(len(transport.blob)))
        decoded = codec.decode_user_catacomb(store.committed, 501)
        self.assertEqual(decoded.identities, (self.local.identities[0],))
        self.assertEqual(decoded.secure_data, b"LTFC" + b"z" * 28)

    def test_every_post_sep_failure_freezes_without_claiming_rollback(self):
        cases = (
            (None, "begin", None),
            ("prepare", None, None),
            ("complete", None, None),
            (None, "stage", None),
            (None, "commit", None),
            ("confirm", None, None),
            (None, None, lambda: None),
        )
        for index, (transport_failure, store_failure, readback) in enumerate(cases):
            with self.subTest(index=index):
                if index:
                    self.tearDown()
                    self.setUp()
                with self.assertRaises(persistence.IdentityDeletePersistenceError):
                    self.execute(
                        transport=FakeTransport(transport_failure),
                        store=FakeStore(store_failure),
                        readback=readback,
                    )
                self.assertEqual(
                    journal.read(self.path).phase,
                    journal.IdentityDeletePhase.OUTCOME_UNKNOWN,
                )


if __name__ == "__main__":
    unittest.main()
