# SPDX-License-Identifier: GPL-2.0-only
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_codec as codec
import t2_catacomb_store as store_module
import t2_enrollment_journal as enrollment
import t2_enrollment_persistence_operation as operation
import t2_mutation_journal as mutation
from tests.test_catacomb_codec import biolockout_fixture, fixture, master_fixture
from tests.test_mutation_journal import baseline


class FakeTransport:
    def __init__(self, *, fail_confirm=False):
        self.calls = []
        self.buffers = []
        self.fail_confirm = fail_confirm

    def prepare(self, descriptor):
        self.calls.append(("prepare", descriptor))
        return 0, 32

    def complete(self, descriptor):
        self.calls.append(("complete", descriptor))
        value = bytearray(b"LTFC" + bytes([descriptor[0]]) * 28)
        self.buffers.append(value)
        return 0, value

    def confirm(self, descriptor):
        self.calls.append(("confirm", descriptor))
        return 5 if self.fail_confirm else 0


class CrashAfterCommitStore:
    def __init__(self, inner):
        self.inner = inner

    def begin_stage(self, expected_names):
        self.inner.begin_stage(expected_names)

    def stage_component(self, name, data, expected_names):
        return self.inner.stage_component(name, data, expected_names)

    def cross_commit_boundary(self, expected):
        self.inner.cross_commit_boundary(expected)
        raise RuntimeError("injected crash after host commit")


class PersistenceOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.journal = base / "journal" / "operation.jsonl"
        self.root = base / "catacomb"
        self.root.mkdir(mode=0o700)
        self.old = {
            "master.cat": master_fixture(),
            "biolockout.cat": biolockout_fixture(),
            "user_000001f5.cat": fixture(),
        }
        for name, data in self.old.items():
            path = self.root / name
            path.write_bytes(data)
            path.chmod(0o600)
        value = baseline()
        self.operation_id, _record = mutation.create(
            self.journal, "enroll", value
        )
        enrollment.append_checked(
            self.journal,
            self.operation_id,
            "ENROLL_START_INTENT",
            {
                "apple_uid": 501,
                "protocol_version": 2,
                "connection_generation": value["connection_generation"],
                "request_length": 68,
                "request_sha256": "a" * 64,
            },
        )
        enrollment.append_checked(
            self.journal, self.operation_id, "ENROLL_START_OBSERVED", {"status": 0}
        )
        enrollment.append_checked(
            self.journal,
            self.operation_id,
            "E2_TERMINAL_IDENTITY_OBSERVED",
            {
                "connection_generation": value["connection_generation"],
                "event_sequence": 1,
                "envelope_type": enrollment.SERVICE_ENROLLMENT_RESULT,
                "event_version": 2,
                "user_id": 501,
                "identity_uuid": str(uuid.UUID(int=8)),
            },
        )
        self.specs = (
            (
                operation.ComponentSpec("user_000001f5.cat", b"u" * 24),
                operation.ComponentSpec("master.cat", b"m" * 24),
            ),
        )
        self.encoded_buffers = []

    def tearDown(self):
        self.temp.cleanup()

    def encode(self, name, secure_blob):
        if name == "user_000001f5.cat":
            archive = codec.decode_user_catacomb(
                self.old[name], 501
            ).replace_secure_data(bytes(secure_blob))
        elif name == "master.cat":
            archive = codec.decode_master_catacomb(self.old[name]).encode(
                secure_data=bytes(secure_blob),
                enrollment_count=3,
                current_time=710000000.0,
            )
        else:
            archive = codec.decode_biolockout_catacomb(self.old[name]).encode(
                secure_data=bytes(secure_blob)
            )
        value = bytearray(archive)
        self.encoded_buffers.append(value)
        return value

    def readback(self):
        return operation.ReadbackAttestation("9" * 64, True, True)

    def test_operation_orders_components_commits_and_wipes_buffers(self):
        transport = FakeTransport()
        result = operation.run(
            self.journal,
            self.operation_id,
            batches=self.specs,
            transport=transport,
            encoder=self.encode,
            store=store_module.CatacombStore(self.root, 501),
            readback=self.readback,
        )
        self.assertEqual(result.phase, enrollment.EnrollmentPhase.PERSISTENCE_READY)
        self.assertEqual(
            [name for name, _descriptor in transport.calls],
            ["prepare", "complete", "confirm", "prepare", "complete", "confirm"],
        )
        self.assertTrue(all(not any(value) for value in transport.buffers))
        self.assertTrue(all(not any(value) for value in self.encoded_buffers))
        self.assertFalse((self.root / "prepare").exists())
        self.assertFalse((self.root / "commit").exists())

    def test_failed_early_confirm_freezes_and_preserves_staged_evidence(self):
        transport = FakeTransport(fail_confirm=True)
        with self.assertRaisesRegex(
            operation.PersistenceOperationError, "reconciliation"
        ):
            operation.run(
                self.journal,
                self.operation_id,
                batches=self.specs,
                transport=transport,
                encoder=self.encode,
                store=store_module.CatacombStore(self.root, 501),
                readback=self.readback,
            )
        history = enrollment.read(self.journal)
        self.assertEqual(history.phase, enrollment.EnrollmentPhase.OUTCOME_UNKNOWN)
        self.assertTrue((self.root / "prepare" / "user_000001f5.cat").exists())
        self.assertTrue(all(not any(value) for value in transport.buffers))
        self.assertTrue(all(not any(value) for value in self.encoded_buffers))

    def test_bad_component_order_is_rejected_before_transport_dispatch(self):
        transport = FakeTransport()
        reversed_specs = ((self.specs[0][1], self.specs[0][0]),)
        with self.assertRaises(enrollment.EnrollmentJournalError):
            operation.run(
                self.journal,
                self.operation_id,
                batches=reversed_specs,
                transport=transport,
                encoder=self.encode,
                store=store_module.CatacombStore(self.root, 501),
                readback=self.readback,
            )
        self.assertEqual(transport.calls, [])

    def test_ambiguous_host_commit_is_durable_outcome_unknown(self):
        transport = FakeTransport()
        store = CrashAfterCommitStore(
            store_module.CatacombStore(self.root, 501)
        )
        with self.assertRaisesRegex(
            operation.PersistenceOperationError, "reconciliation"
        ):
            operation.run(
                self.journal,
                self.operation_id,
                batches=self.specs,
                transport=transport,
                encoder=self.encode,
                store=store,
                readback=self.readback,
            )
        history = enrollment.read(self.journal)
        self.assertEqual(history.phase, enrollment.EnrollmentPhase.OUTCOME_UNKNOWN)
        self.assertFalse((self.root / "prepare").exists())
        self.assertFalse((self.root / "commit").exists())


if __name__ == "__main__":
    unittest.main()
