# SPDX-License-Identifier: GPL-2.0-only
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_codec as codec
import t2_identity_rename as rename
import t2_identity_rename_journal as rename_journal
import t2_identity_rename_operation as operation
import t2_mutation_journal as mutation
from tests.test_catacomb_codec import fixture
from tests.test_identity_inventory import live_for
from tests.test_mutation_journal import baseline


class FakeTransport:
    def __init__(self, *, fail_at=None):
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
    def __init__(self, *, fail_at=None):
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


class IdentityRenameOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "rename.jsonl"
        self.local = codec.decode_user_catacomb(fixture(), 501)
        self.value = baseline()
        self.value["identity_records"][0]["uuid"] = self.local.identities[0].uuid
        self.operation_id, _record = mutation.create(
            self.path, "rename", self.value
        )
        self.plan = rename.plan(
            self.local, live_for(self.local), slot=1, new_name="Renamed finger"
        )
        rename_journal.append_checked(
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

    def tearDown(self):
        self.temp.cleanup()

    def test_transaction_persists_confirms_reconciles_and_wipes_blob(self):
        transport = FakeTransport()
        store = FakeStore()
        result = operation.run(
            self.path,
            self.operation_id,
            plan=self.plan,
            transport=transport,
            store=store,
            mapping_generation=self.value["mapping_generation"],
            readback=lambda: operation.RenameReadbackAttestation(
                self.value["connection_generation"],
                "8" * 64,
                1,
                True,
                True,
                True,
            ),
        )
        self.assertEqual(result.phase, rename_journal.IdentityRenamePhase.RECONCILED)
        self.assertEqual(transport.calls, ["prepare", "complete", "confirm"])
        self.assertEqual(bytes(transport.blob), bytes(len(transport.blob)))
        decoded = codec.decode_user_catacomb(store.committed, 501)
        self.assertEqual(decoded.identities[0].name, "Renamed finger")
        self.assertEqual(decoded.secure_data, b"LTFC" + b"z" * 28)

    def test_prepare_failure_is_durable_outcome_unknown(self):
        with self.assertRaisesRegex(
            operation.IdentityRenameOperationError, "reconciliation"
        ):
            operation.run(
                self.path,
                self.operation_id,
                plan=self.plan,
                transport=FakeTransport(fail_at="prepare"),
                store=FakeStore(),
                mapping_generation=self.value["mapping_generation"],
                readback=lambda: None,
            )
        self.assertEqual(
            rename_journal.read(self.path).phase,
            rename_journal.IdentityRenamePhase.OUTCOME_UNKNOWN,
        )

    def test_host_unavailable_aborts_before_transport_dispatch(self):
        transport = FakeTransport()
        with self.assertRaisesRegex(
            operation.IdentityRenameOperationError, "local transaction"
        ):
            operation.run(
                self.path,
                self.operation_id,
                plan=self.plan,
                transport=transport,
                store=FakeStore(fail_at="begin"),
                mapping_generation=self.value["mapping_generation"],
                readback=lambda: None,
            )
        self.assertEqual(transport.calls, [])
        self.assertEqual(
            rename_journal.read(self.path).phase,
            rename_journal.IdentityRenamePhase.ABORTED,
        )

    def test_each_post_dispatch_failure_freezes_without_replay(self):
        cases = (
            ("complete", None, lambda: None),
            (None, "stage", lambda: None),
            (None, "commit", lambda: None),
            ("confirm", None, lambda: None),
            (
                None,
                None,
                lambda: operation.RenameReadbackAttestation(
                    self.value["connection_generation"],
                    "8" * 64,
                    1,
                    True,
                    False,
                    True,
                ),
            ),
        )
        for index, (transport_failure, store_failure, readback) in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "rename.jsonl"
                operation_id, _record = mutation.create(path, "rename", self.value)
                rename_journal.append_checked(
                    path,
                    operation_id,
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
                with self.assertRaises(operation.IdentityRenameOperationError):
                    operation.run(
                        path,
                        operation_id,
                        plan=self.plan,
                        transport=FakeTransport(fail_at=transport_failure),
                        store=FakeStore(fail_at=store_failure),
                        mapping_generation=self.value["mapping_generation"],
                        readback=readback,
                    )
                self.assertEqual(
                    rename_journal.read(path).phase,
                    rename_journal.IdentityRenamePhase.OUTCOME_UNKNOWN,
                )


if __name__ == "__main__":
    unittest.main()
