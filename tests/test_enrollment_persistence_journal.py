# SPDX-License-Identifier: GPL-2.0-only
import hashlib
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_enrollment_journal as enrollment
import t2_mutation_journal as mutation
from tests.test_mutation_journal import baseline


def component_ref(batch_index, component_index, name, descriptor_sha256):
    return {
        "connection_generation": baseline()["connection_generation"],
        "batch_index": batch_index,
        "component_index": component_index,
        "name": name,
        "descriptor_sha256": descriptor_sha256,
    }


def append_persistence(
    path, operation_id, reconciliation_snapshot_sha256, *, include_biolockout=False
):
    descriptors = {
        "user_000001f5.cat": "1" * 64,
        "master.cat": "2" * 64,
        "biolockout.cat": "3" * 64,
    }
    batch_names = [("user_000001f5.cat", "master.cat")]
    if include_biolockout:
        batch_names.append(("biolockout.cat",))
    enrollment.append_checked(
        path,
        operation_id,
        "CATACOMB_PERSISTENCE_PLAN",
        {
            "connection_generation": baseline()["connection_generation"],
            "batches": [
                [
                    {"name": name, "descriptor_sha256": descriptors[name]}
                    for name in names
                ]
                for names in batch_names
            ],
        },
    )
    for batch_index, names in enumerate(batch_names):
        staged = []
        final_reference = None
        for component_index, name in enumerate(names):
            reference = component_ref(
                batch_index, component_index, name, descriptors[name]
            )
            blob_sha256 = str(4 + batch_index * 2 + component_index) * 64
            final_file_sha256 = str(7 + batch_index + component_index) * 64
            enrollment.append_checked(
                path, operation_id, "CATACOMB_PREPARE_INTENT", reference
            )
            enrollment.append_checked(
                path,
                operation_id,
                "CATACOMB_PREPARED",
                {**reference, "status": 0, "expected_blob_length": 32},
            )
            enrollment.append_checked(
                path, operation_id, "CATACOMB_COMPLETE_INTENT", reference
            )
            enrollment.append_checked(
                path,
                operation_id,
                "CATACOMB_SECURE_BLOB_CAPTURED",
                {
                    **reference,
                    "status": 0,
                    "blob_length": 32,
                    "secure_blob_sha256": blob_sha256,
                },
            )
            enrollment.append_checked(
                path,
                operation_id,
                "CATACOMB_HOST_STAGED",
                {
                    **reference,
                    "secure_blob_sha256": blob_sha256,
                    "final_file_sha256": final_file_sha256,
                },
            )
            staged.append({"name": name, "final_file_sha256": final_file_sha256})
            final_reference = reference
            if component_index + 1 < len(names):
                enrollment.append_checked(
                    path, operation_id, "CATACOMB_CONFIRM_INTENT", reference
                )
                enrollment.append_checked(
                    path,
                    operation_id,
                    "CATACOMB_CONFIRMED",
                    {**reference, "status": 0},
                )
        staged_snapshot_sha256 = hashlib.sha256(
            mutation.canonical(staged)
        ).hexdigest()
        batch = {
            "connection_generation": baseline()["connection_generation"],
            "batch_index": batch_index,
            "staged_snapshot_sha256": staged_snapshot_sha256,
        }
        enrollment.append_checked(
            path, operation_id, "CATACOMB_HOST_BATCH_COMMIT_INTENT", batch
        )
        enrollment.append_checked(
            path, operation_id, "CATACOMB_HOST_BATCH_COMMITTED", batch
        )
        enrollment.append_checked(
            path, operation_id, "CATACOMB_FINAL_CONFIRM_INTENT", final_reference
        )
        enrollment.append_checked(
            path,
            operation_id,
            "CATACOMB_FINAL_CONFIRMED",
            {**final_reference, "status": 0},
        )
    return enrollment.append_checked(
        path,
        operation_id,
        "CATACOMB_PERSISTENCE_ATTESTED",
        {
            "connection_generation": baseline()["connection_generation"],
            "batch_count": len(batch_names),
            "reconciliation_snapshot_sha256": reconciliation_snapshot_sha256,
            "sep_host_generation_equal": True,
            "independent_archive_readback": True,
        },
    )


class EnrollmentPersistenceJournalTests(unittest.TestCase):
    def create_identity(self, directory):
        value = baseline()
        path = Path(directory) / "operation.jsonl"
        operation_id, _record = mutation.create(path, "enroll", value)
        enrollment.append_checked(
            path,
            operation_id,
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
            path, operation_id, "ENROLL_START_OBSERVED", {"status": 0}
        )
        enrollment.append_checked(
            path,
            operation_id,
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
        return path, operation_id

    def test_complete_sequence_reaches_persistence_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create_identity(directory)
            result = append_persistence(path, operation_id, "9" * 64)
        self.assertEqual(result.phase, enrollment.EnrollmentPhase.PERSISTENCE_READY)
        self.assertTrue(result.persistence.sep_host_generation_equal)
        self.assertTrue(result.persistence.independent_archive_readback)

    def test_separate_biolockout_batch_reaches_persistence_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create_identity(directory)
            result = append_persistence(
                path, operation_id, "9" * 64, include_biolockout=True
            )
        self.assertEqual(result.phase, enrollment.EnrollmentPhase.PERSISTENCE_READY)
        self.assertEqual(len(result.persistence.batches), 2)

    def test_persistence_requires_identity_and_immutable_complete_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            value = baseline()
            path = Path(directory) / "operation.jsonl"
            operation_id, _record = mutation.create(path, "enroll", value)
            with self.assertRaisesRegex(enrollment.EnrollmentJournalError, "identity"):
                enrollment.append_checked(
                    path,
                    operation_id,
                    "CATACOMB_PERSISTENCE_PLAN",
                    {
                        "connection_generation": value["connection_generation"],
                        "batches": [],
                    },
                )

            path, operation_id = self.create_identity(Path(directory) / "second")
            with self.assertRaisesRegex(enrollment.EnrollmentJournalError, "omits"):
                enrollment.append_checked(
                    path,
                    operation_id,
                    "CATACOMB_PERSISTENCE_PLAN",
                    {
                        "connection_generation": value["connection_generation"],
                        "batches": [
                            [{"name": "master.cat", "descriptor_sha256": "1" * 64}]
                        ],
                    },
                )

            path, operation_id = self.create_identity(Path(directory) / "third")
            with self.assertRaisesRegex(
                enrollment.EnrollmentJournalError, "master|primary"
            ):
                enrollment.append_checked(
                    path,
                    operation_id,
                    "CATACOMB_PERSISTENCE_PLAN",
                    {
                        "connection_generation": value["connection_generation"],
                        "batches": [
                            [
                                {"name": "master.cat", "descriptor_sha256": "1" * 64},
                                {
                                    "name": "user_000001f5.cat",
                                    "descriptor_sha256": "2" * 64,
                                },
                            ]
                        ],
                    },
                )

    def test_final_component_cannot_use_early_confirm_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create_identity(directory)
            generation = baseline()["connection_generation"]
            enrollment.append_checked(
                path,
                operation_id,
                "CATACOMB_PERSISTENCE_PLAN",
                {
                    "connection_generation": generation,
                    "batches": [
                        [
                            {
                                "name": "user_000001f5.cat",
                                "descriptor_sha256": "1" * 64,
                            },
                            {"name": "master.cat", "descriptor_sha256": "2" * 64},
                        ]
                    ],
                },
            )
            reference = component_ref(0, 0, "user_000001f5.cat", "1" * 64)
            enrollment.append_checked(
                path, operation_id, "CATACOMB_PREPARE_INTENT", reference
            )
            with self.assertRaisesRegex(enrollment.EnrollmentJournalError, "out of order"):
                enrollment.append_checked(
                    path, operation_id, "CATACOMB_CONFIRM_INTENT", reference
                )


if __name__ == "__main__":
    unittest.main()
