# SPDX-License-Identifier: GPL-2.0-only
import datetime as dt
import hashlib
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_codec as codec
import t2_catacomb_protocol as catacomb_protocol
import t2_enrollment_finalizer as finalizer
import t2_enrollment_journal as enrollment
import t2_enrollment_operation as enrollment_operation
import t2_enrollment_persistence_operation as persistence_operation
import t2_mutation_journal as mutation
from tests.test_catacomb_codec import biolockout_fixture, fixture, master_fixture


GENERATION = str(uuid.UUID(int=4))
IDENTITY = str(uuid.UUID(int=8))


class FakeLease:
    def __init__(self):
        self.connection_generation = GENERATION
        self.peer_boot_uuid = None
        self.invalidated = False
        self.calls = []
        self.replies = iter(
            [
                ([0, (32).to_bytes(4, "little")], []),
                ([0, b"LTFC" + b"u" * 28], []),
                ([0, b""], []),
                ([0, (32).to_bytes(4, "little")], []),
                ([0, b"LTFC" + b"m" * 28], []),
                ([0, b""], []),
            ]
        )

    def biometric_command(
        self, command, *, version, value, data, output_capacity
    ):
        self.calls.append((command, version, value, bytes(data), output_capacity))
        return next(self.replies)

    def invalidate(self):
        self.invalidated = True


def make_baseline(components):
    return {
        "baseline_version": 1,
        "caller_linux_uid": 1000,
        "target_linux_uid": 1000,
        "apple_uid": 501,
        "account_uuid": str(uuid.UUID(int=2)),
        "bag_uuid": str(uuid.UUID(int=3)),
        "linux_boot_uuid": str(uuid.UUID(int=3)),
        "connection_generation": GENERATION,
        "bridge_boot_uuid": None,
        "protocol_version": 2,
        "policy_decision": "authorized",
        "identity_records": [
            {"user_id": 501, "uuid": str(uuid.UUID(int=1)), "entity": 0}
        ],
        "capacity": {"used": 1, "maximum": 5},
        "sep_catacomb": {
            "present": True,
            "uuid": str(uuid.UUID(int=6)),
            "hash": "a" * 64,
        },
        "host_components": [
            {
                "name": name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "mode": 0o644,
                "uid": 0,
                "gid": 0,
            }
            for name, data in sorted(components.items())
        ],
        "master_enrollment_count": 2,
        "mapping_generation": "d" * 64,
        "backup_references": [{"reference": "backup-1", "sha256": "e" * 64}],
        "double_collection_equal": True,
        "password_fallback_verified": True,
    }


def live_after():
    identities = [str(uuid.UUID(int=1)), IDENTITY]
    return {
        "schema_version": 1,
        "connection_generation": GENERATION,
        "bridge_boot_uuid": None,
        "biometric_protocol_version": 2,
        "apple_uid": 501,
        "per_user_identity_records": [
            {"user_id": 501, "identity_uuid": value} for value in identities
        ],
        "global_identity_records": [
            {
                "user_id": 501,
                "identity_uuid": value,
                "group_type": 1,
                "group_uuid": str(uuid.UUID(int=0)),
            }
            for value in identities
        ],
        "maximum_capacity": 5,
        "configured_user_free_capacity": 3,
        "catacomb": {
            "uuid": str(uuid.UUID(int=6)),
            "present": True,
            "hash": "f" * 64,
        },
        "sks_lock_state_raw": 552,
        "double_collection_equal": True,
    }


class EnrollmentFinalizerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "catacomb"
        self.root.mkdir(mode=0o700)
        self.components = {
            "master.cat": master_fixture(),
            "biolockout.cat": biolockout_fixture(),
            "user_000001f5.cat": fixture(),
        }
        for name, data in self.components.items():
            path = self.root / name
            path.write_bytes(data)
            path.chmod(0o600)
        self.baseline = make_baseline(self.components)
        self.journal = Path(self.temp.name) / "journal" / "operation.jsonl"
        self.operation_id, _record = mutation.create(
            self.journal, "enroll", self.baseline
        )
        enrollment.append_checked(
            self.journal,
            self.operation_id,
            "ENROLL_START_INTENT",
            {
                "apple_uid": 501,
                "protocol_version": 2,
                "connection_generation": GENERATION,
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
                "connection_generation": GENERATION,
                "event_sequence": 1,
                "envelope_type": enrollment.SERVICE_ENROLLMENT_RESULT,
                "event_version": 2,
                "user_id": 501,
                "identity_uuid": IDENTITY,
            },
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_concrete_finalizer_persists_and_reconciles_real_codecs(self):
        lease = FakeLease()
        instance = finalizer.BuiltinEnrollmentFinalizer(
            lease=lease,
            apple_user_id=501,
            connection_generation=GENERATION,
            journal_path=self.journal,
            operation_id=self.operation_id,
            catacomb_root=self.root,
            mapping_generation="d" * 64,
            identity_name="Linux enrolled finger",
            clock=lambda: codec.APPLE_EPOCH + dt.timedelta(seconds=710000000),
        )
        components = (
            catacomb_protocol.CatacombComponent.user(501),
            catacomb_protocol.CatacombComponent.master(),
        )
        outcome = enrollment_operation.EnrollmentOperationResult(
            "identity-observed", None, True
        )
        with (
            patch(
                "t2_enrollment_finalizer.t2_catacomb_bridge.collect_builtin_save_components",
                return_value=components,
            ),
            patch(
                "t2_enrollment_finalizer.t2_bridge_inventory.collect_stable_private_inventory",
                return_value=live_after(),
            ),
        ):
            attestation = instance(outcome)

        self.assertTrue(attestation.persistence_ready)
        self.assertTrue(attestation.reconciliation_complete)
        self.assertEqual(enrollment.read(self.journal).phase, enrollment.EnrollmentPhase.RECONCILED)
        user = codec.decode_user_catacomb(
            (self.root / "user_000001f5.cat").read_bytes(), 501
        )
        self.assertEqual([identity.uuid for identity in user.identities], [str(uuid.UUID(int=1)), IDENTITY])
        self.assertEqual(user.identities[-1].name, "Linux enrolled finger")
        self.assertEqual(user.secure_data, b"LTFC" + b"u" * 28)
        master = codec.decode_master_catacomb((self.root / "master.cat").read_bytes())
        self.assertEqual(master.enrollment_count, 3)
        self.assertEqual(master.secure_data, b"LTFC" + b"m" * 28)
        self.assertEqual([call[0] for call in lease.calls], [0x3D, 0x3E, 0x3F, 0x3D, 0x3E, 0x3F])
        self.assertFalse(lease.invalidated)

    def test_concrete_readback_failure_is_durable_outcome_unknown(self):
        lease = FakeLease()
        instance = finalizer.BuiltinEnrollmentFinalizer(
            lease=lease,
            apple_user_id=501,
            connection_generation=GENERATION,
            journal_path=self.journal,
            operation_id=self.operation_id,
            catacomb_root=self.root,
            mapping_generation="d" * 64,
            identity_name="Linux enrolled finger",
            clock=lambda: codec.APPLE_EPOCH + dt.timedelta(seconds=710000000),
        )
        components = (
            catacomb_protocol.CatacombComponent.user(501),
            catacomb_protocol.CatacombComponent.master(),
        )
        outcome = enrollment_operation.EnrollmentOperationResult(
            "identity-observed", None, True
        )
        with (
            patch(
                "t2_enrollment_finalizer.t2_catacomb_bridge.collect_builtin_save_components",
                return_value=components,
            ),
            patch(
                "t2_enrollment_finalizer.t2_bridge_inventory.collect_stable_private_inventory",
                side_effect=ConnectionError("synthetic readback disconnect"),
            ),
            self.assertRaisesRegex(persistence_operation.PersistenceOperationError, "reconciliation"),
        ):
            instance(outcome)
        history = enrollment.read(self.journal)
        self.assertEqual(history.phase, enrollment.EnrollmentPhase.OUTCOME_UNKNOWN)
        # Host commit and SEP confirms already crossed; the failure must not be
        # simplified to a rollback or reported as a successful enrollment.
        user = codec.decode_user_catacomb(
            (self.root / "user_000001f5.cat").read_bytes(), 501
        )
        self.assertIn(IDENTITY, {identity.uuid for identity in user.identities})


if __name__ == "__main__":
    unittest.main()
