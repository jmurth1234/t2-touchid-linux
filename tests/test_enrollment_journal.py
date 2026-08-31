import tempfile
import unittest
import uuid
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_enrollment_journal as enrollment
import t2_mutation_journal as journal
from tests.test_mutation_journal import baseline


class EnrollmentJournalTests(unittest.TestCase):
    def create(self, directory: str) -> tuple[Path, str]:
        path = Path(directory) / "operation.jsonl"
        operation_id, _record = journal.create(path, "enroll", baseline())
        return path, operation_id

    def start(self, path: Path, operation_id: str) -> None:
        value = baseline()
        enrollment.append_checked(
            path,
            operation_id,
            "ENROLL_START_INTENT",
            {
                "apple_uid": value["apple_uid"],
                "protocol_version": value["protocol_version"],
                "connection_generation": value["connection_generation"],
                "request_length": 68,
                "request_sha256": "a" * 64,
            },
        )
        enrollment.append_checked(
            path, operation_id, "ENROLL_START_OBSERVED", {"status": 0}
        )

    def test_pre_dispatch_abort_is_terminal_and_records_no_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create(directory)
            result = enrollment.append_checked(
                path,
                operation_id,
                "ENROLL_ABORTED_BEFORE_START",
                {
                    "connection_generation": baseline()["connection_generation"],
                    "reason": "safety-guard-unavailable",
                    "mutation_possible": False,
                },
            )
            self.assertEqual(
                result.phase, enrollment.EnrollmentPhase.ABORTED_BEFORE_START
            )
            with self.assertRaisesRegex(
                enrollment.EnrollmentJournalError, "out of order"
            ):
                enrollment.append_checked(
                    path,
                    operation_id,
                    "ENROLL_START_INTENT",
                    {
                        "apple_uid": 501,
                        "protocol_version": 2,
                        "connection_generation": baseline()[
                            "connection_generation"
                        ],
                        "request_length": 68,
                        "request_sha256": "a" * 64,
                    },
                )

    def test_start_continue_and_terminal_identity_are_strictly_ordered(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create(directory)
            self.start(path, operation_id)
            value = baseline()
            enrollment.append_checked(
                path,
                operation_id,
                "ENROLL_CONTINUE_INTENT",
                {
                    "connection_generation": value["connection_generation"],
                    "event_sequence": 10,
                    "event_ordinal": 263,
                    "event_sha256": "b" * 64,
                },
            )
            enrollment.append_checked(
                path,
                operation_id,
                "ENROLL_CONTINUE_OBSERVED",
                {
                    "event_sequence": 10,
                    "status": -1,
                    "return_status_authoritative": False,
                },
            )
            result = enrollment.append_checked(
                path,
                operation_id,
                "E2_TERMINAL_IDENTITY_OBSERVED",
                {
                    "connection_generation": value["connection_generation"],
                    "event_sequence": 11,
                    "envelope_type": enrollment.SERVICE_ENROLLMENT_RESULT,
                    "event_version": 2,
                    "user_id": 501,
                    "identity_uuid": str(uuid.UUID(int=7)),
                },
            )
            self.assertEqual(result.phase, enrollment.EnrollmentPhase.TERMINAL_IDENTITY)
            self.assertEqual(result.last_event_sequence, 11)

    def test_legacy_zero_continue_observation_remains_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create(directory)
            self.start(path, operation_id)
            value = baseline()
            enrollment.append_checked(
                path,
                operation_id,
                "ENROLL_CONTINUE_INTENT",
                {
                    "connection_generation": value["connection_generation"],
                    "event_sequence": 10,
                    "event_ordinal": 100,
                    "event_sha256": "b" * 64,
                },
            )
            history = enrollment.append_checked(
                path,
                operation_id,
                "ENROLL_CONTINUE_OBSERVED",
                {"event_sequence": 10, "status": 0},
            )
            self.assertEqual(history.phase, enrollment.EnrollmentPhase.ACTIVE)

    def test_continue_return_cannot_be_marked_authoritative(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create(directory)
            self.start(path, operation_id)
            value = baseline()
            enrollment.append_checked(
                path,
                operation_id,
                "ENROLL_CONTINUE_INTENT",
                {
                    "connection_generation": value["connection_generation"],
                    "event_sequence": 10,
                    "event_ordinal": 100,
                    "event_sha256": "b" * 64,
                },
            )
            with self.assertRaisesRegex(
                enrollment.EnrollmentJournalError, "authoritative"
            ):
                enrollment.append_checked(
                    path,
                    operation_id,
                    "ENROLL_CONTINUE_OBSERVED",
                    {
                        "event_sequence": 10,
                        "status": -1,
                        "return_status_authoritative": True,
                    },
                )

    def test_cancel_is_intent_dispatch_then_terminal_handshake(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create(directory)
            self.start(path, operation_id)
            generation = baseline()["connection_generation"]
            enrollment.append_checked(
                path,
                operation_id,
                "ENROLL_CANCEL_INTENT",
                {"connection_generation": generation, "reason": "caller-requested"},
            )
            enrollment.append_checked(
                path,
                operation_id,
                "ENROLL_CANCEL_DISPATCH_OBSERVED",
                {"status": 0},
            )
            result = enrollment.append_checked(
                path,
                operation_id,
                "ENROLL_TERMINAL_FAILURE_OBSERVED",
                {
                    "connection_generation": generation,
                    "event_sequence": 20,
                    "envelope_type": enrollment.SERVICE_STATUS,
                    "status": 66,
                },
            )
            self.assertEqual(result.phase, enrollment.EnrollmentPhase.TERMINAL_FAILURE)

    def test_unknown_outcome_is_terminal_and_requires_mutation_possible(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create(directory)
            enrollment.append_checked(
                path,
                operation_id,
                "ENROLL_START_INTENT",
                {
                    "apple_uid": 501,
                    "protocol_version": 2,
                    "connection_generation": baseline()["connection_generation"],
                    "request_length": 68,
                    "request_sha256": "a" * 64,
                },
            )
            result = enrollment.append_checked(
                path,
                operation_id,
                "ENROLL_OUTCOME_UNKNOWN",
                {
                    "connection_generation": baseline()["connection_generation"],
                    "stage": "start",
                    "reason": "transport-error",
                    "mutation_possible": True,
                },
            )
            self.assertEqual(result.phase, enrollment.EnrollmentPhase.OUTCOME_UNKNOWN)
            with self.assertRaises(enrollment.EnrollmentJournalError):
                enrollment.append_checked(
                    path,
                    operation_id,
                    "ENROLL_START_OBSERVED",
                    {"status": 0},
                )

    def test_unknown_outcome_accepts_only_fresh_no_change_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create(directory)
            value = baseline()
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
                path,
                operation_id,
                "ENROLL_OUTCOME_UNKNOWN",
                {
                    "connection_generation": value["connection_generation"],
                    "stage": "start",
                    "reason": "transport-error",
                    "mutation_possible": True,
                },
            )
            evidence = {
                "connection_generation": str(uuid.UUID(int=99)),
                "snapshot_sha256": "f" * 64,
                "identity_uuid": None,
                "identity_present": False,
                "host_sep_identity_equal": True,
                "catacomb_reconciled": True,
                "bindings_preserved": True,
                "mapping_generation": value["mapping_generation"],
                "capacity_used": value["capacity"]["used"],
                "capacity_maximum": value["capacity"]["maximum"],
                "master_enrollment_count": value["master_enrollment_count"],
            }
            with self.assertRaisesRegex(enrollment.EnrollmentJournalError, "fresh"):
                enrollment.append_checked(
                    path,
                    operation_id,
                    "E3_RECOVERY_NO_CHANGE_RECONCILED",
                    {**evidence, "connection_generation": value["connection_generation"]},
                )
            result = enrollment.append_checked(
                path,
                operation_id,
                "E3_RECOVERY_NO_CHANGE_RECONCILED",
                evidence,
            )
        self.assertEqual(result.phase, enrollment.EnrollmentPhase.RECONCILED)

    def test_wrong_generation_uid_digest_and_continue_order_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create(directory)
            base_intent = {
                "apple_uid": 501,
                "protocol_version": 2,
                "connection_generation": baseline()["connection_generation"],
                "request_length": 68,
                "request_sha256": "a" * 64,
            }
            for field, value in (
                ("apple_uid", 502),
                ("connection_generation", "00000000-0000-0000-0000-000000000099"),
                ("request_sha256", "short"),
                ("request_length", 48),
            ):
                with self.subTest(field=field):
                    invalid = {**base_intent, field: value}
                    with self.assertRaises(enrollment.EnrollmentJournalError):
                        enrollment.append_checked(
                            path, operation_id, "ENROLL_START_INTENT", invalid
                        )
            self.start(path, operation_id)
            with self.assertRaises(enrollment.EnrollmentJournalError):
                enrollment.append_checked(
                    path,
                    operation_id,
                    "ENROLL_CONTINUE_OBSERVED",
                    {"event_sequence": 1, "status": 0},
                )

    def test_generic_untyped_milestone_poisoning_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create(directory)
            journal.append(path, operation_id, "UNSAFE_GENERIC_STEP", {})
            with self.assertRaises(enrollment.EnrollmentJournalError):
                enrollment.read(path)

    def test_start_readiness_binds_boot_connection_mapping_and_callers(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _operation_id = self.create(directory)
            history = enrollment.read(path)
            value = baseline()
            arguments = {
                "linux_boot_uuid": value["linux_boot_uuid"],
                "connection_generation": value["connection_generation"],
                "mapping_generation": value["mapping_generation"],
                "caller_linux_uid": value["caller_linux_uid"],
                "target_linux_uid": value["target_linux_uid"],
                "protocol_version": value["protocol_version"],
            }
            enrollment.require_start_ready(history, **arguments)
            invalid_values = {
                "linux_boot_uuid": "00000000-0000-0000-0000-000000000099",
                "connection_generation": "00000000-0000-0000-0000-000000000099",
                "mapping_generation": "f" * 64,
                "caller_linux_uid": 1001,
                "target_linux_uid": 1001,
                "protocol_version": 1,
            }
            for field, invalid in invalid_values.items():
                with self.subTest(field=field):
                    with self.assertRaises(enrollment.EnrollmentJournalError):
                        enrollment.require_start_ready(
                            history, **{**arguments, field: invalid}
                        )

    def test_start_readiness_rejects_full_capacity(self):
        with tempfile.TemporaryDirectory() as directory:
            value = baseline()
            value["capacity"] = {"used": 1, "maximum": 1}
            path = Path(directory) / "operation.jsonl"
            journal.create(path, "enroll", value)
            with self.assertRaisesRegex(
                enrollment.EnrollmentJournalError, "capacity"
            ):
                enrollment.require_start_ready(
                    enrollment.read(path),
                    linux_boot_uuid=value["linux_boot_uuid"],
                    connection_generation=value["connection_generation"],
                    mapping_generation=value["mapping_generation"],
                    caller_linux_uid=1000,
                    target_linux_uid=1000,
                    protocol_version=2,
                )

    def test_failure_with_new_identity_is_promoted_by_stable_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            path, operation_id = self.create(directory)
            self.start(path, operation_id)
            generation = baseline()["connection_generation"]
            enrollment.append_checked(
                path,
                operation_id,
                "ENROLL_TERMINAL_FAILURE_OBSERVED",
                {
                    "connection_generation": generation,
                    "event_sequence": 1,
                    "envelope_type": enrollment.SERVICE_STATUS,
                    "status": 67,
                },
            )
            result = enrollment.append_checked(
                path,
                operation_id,
                "E2_IDENTITY_READBACK_OBSERVED",
                {
                    "connection_generation": generation,
                    "user_id": 501,
                    "identity_uuid": str(uuid.UUID(int=8)),
                    "source": "stable-readback",
                },
            )
        self.assertEqual(result.phase, enrollment.EnrollmentPhase.TERMINAL_IDENTITY)
        self.assertEqual(result.terminal_identity_uuid, str(uuid.UUID(int=8)))


if __name__ == "__main__":
    unittest.main()
