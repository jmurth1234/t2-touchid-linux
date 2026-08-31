import hashlib
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_enrollment_journal as typed_journal
import t2_enrollment_operation as operation
import t2_enrollment_protocol as protocol
import t2_mutation_journal as journal
from tests.test_mutation_journal import baseline


def raw_event(sequence: int, envelope: int, version: int, ordinal: int, payload: bytes = b"") -> bytes:
    if envelope == protocol.SERVICE_STATUS and not payload:
        payload = protocol.STATUS_PAYLOAD_HEADER.pack(ordinal, 0)
    return protocol.SERVICE_HEADER.pack(0, envelope, version, sequence) + payload


class FakeTransport:
    def __init__(self, events: list[bytes], *, start_status: int = 0) -> None:
        self.connection_generation = baseline()["connection_generation"]
        self.protocol_version = 2
        self.events = iter(events)
        self.start_status = start_status
        self.start_view: memoryview | None = None
        self.start_calls = 0
        self.continue_calls = 0
        self.cancel_calls = 0

    def start(self, payload: memoryview) -> int:
        self.start_calls += 1
        self.start_view = payload
        return self.start_status

    def continue_enrollment(self) -> int:
        self.continue_calls += 1
        return 0

    def cancel(self) -> int:
        self.cancel_calls += 1
        return 0

    def next_event(self) -> bytes:
        return next(self.events)


class FailingStartTransport(FakeTransport):
    def start(self, payload: memoryview) -> int:
        self.start_calls += 1
        self.start_view = payload
        raise ConnectionError("synthetic disconnect")


class EnrollmentOperationTests(unittest.TestCase):
    def create(
        self, directory: str, transport: FakeTransport
    ) -> tuple[operation.EnrollmentOperation, Path, str]:
        value = baseline()
        path = Path(directory) / "operation.jsonl"
        operation_id, _record = journal.create(path, "enroll", value)
        instance = operation.EnrollmentOperation(
            journal_path=path,
            operation_id=operation_id,
            transport=transport,
            linux_boot_uuid=value["linux_boot_uuid"],
            mapping_generation=value["mapping_generation"],
            caller_linux_uid=value["caller_linux_uid"],
            target_linux_uid=value["target_linux_uid"],
        )
        return instance, path, operation_id

    def test_progress_continue_and_identity_are_journaled_and_secret_wiped(self):
        identity_uuid = uuid.UUID(int=7).bytes
        result_payload = (501).to_bytes(4, "little") + identity_uuid + bytes(20)
        transport = FakeTransport(
            [
                raw_event(
                    8,
                    protocol.SERVICE_SKS_LOCK_STATE,
                    1,
                    0,
                    protocol.SKS_LOCK_STATE_PAYLOAD.pack(501, 0x228),
                ),
                raw_event(9, protocol.SERVICE_STATISTICS, 1, 0, bytes(28)),
                raw_event(10, protocol.SERVICE_STATUS, 1, 90),
                raw_event(11, protocol.SERVICE_STATUS, 1, 263),
                raw_event(
                    12,
                    protocol.SERVICE_ENROLLMENT_RESULT,
                    2,
                    0,
                    result_payload,
                ),
            ]
        )
        feedback = []
        with tempfile.TemporaryDirectory() as directory:
            instance, path, _operation_id = self.create(directory, transport)
            result = instance.run(bytes(range(16)), on_feedback=feedback.append)
            history = typed_journal.read(path)
        self.assertEqual(result.outcome, "identity-observed")
        self.assertTrue(result.reconciliation_required)
        self.assertEqual(history.phase, typed_journal.EnrollmentPhase.TERMINAL_IDENTITY)
        self.assertEqual(transport.continue_calls, 1)
        self.assertEqual(len(feedback), 1)
        self.assertEqual(feedback[0].progress_percent, 63)
        self.assertIsNotNone(transport.start_view)
        self.assertEqual(bytes(transport.start_view), bytes(68))

    def test_request_digest_is_journaled_without_request_bytes(self):
        transport = FakeTransport([], start_status=-5)
        secret = bytes(range(16))
        expected = protocol.SensitiveEnrollmentRequest(2, 501, secret)
        digest = hashlib.sha256(expected.buffer).hexdigest()
        expected.wipe()
        with tempfile.TemporaryDirectory() as directory:
            instance, path, _operation_id = self.create(directory, transport)
            result = instance.run(secret)
            records = journal.read(path)
            journal_text = path.read_text()
        self.assertEqual(result.outcome, "start-rejected")
        self.assertEqual(records[1]["evidence"]["request_sha256"], digest)
        self.assertNotIn(secret.hex(), journal_text)

    def test_failed_dispatch_guard_aborts_durably_before_transport_use(self):
        transport = FakeTransport([])
        with tempfile.TemporaryDirectory() as directory:
            instance, path, _operation_id = self.create(directory, transport)
            with self.assertRaisesRegex(
                operation.EnrollmentPreDispatchCancelled,
                "before start dispatch",
            ):
                instance.run(
                    bytes(range(16)), dispatch_allowed=lambda: False
                )
            history = typed_journal.read(path)
        self.assertEqual(transport.start_calls, 0)
        self.assertEqual(
            history.phase, typed_journal.EnrollmentPhase.ABORTED_BEFORE_START
        )

    def test_dispatch_guard_exception_fails_closed_before_transport_use(self):
        transport = FakeTransport([])

        def fail() -> bool:
            raise RuntimeError("private guard detail")

        with tempfile.TemporaryDirectory() as directory:
            instance, path, _operation_id = self.create(directory, transport)
            with self.assertRaisesRegex(
                operation.EnrollmentPreDispatchCancelled,
                "before start dispatch",
            ):
                instance.run(bytes(range(16)), dispatch_allowed=fail)
            history = typed_journal.read(path)
        self.assertEqual(transport.start_calls, 0)
        self.assertEqual(
            history.phase, typed_journal.EnrollmentPhase.ABORTED_BEFORE_START
        )

    def test_start_disconnect_becomes_durable_outcome_unknown(self):
        transport = FailingStartTransport([])
        with tempfile.TemporaryDirectory() as directory:
            instance, path, _operation_id = self.create(directory, transport)
            with self.assertRaisesRegex(operation.EnrollmentOperationError, "unknown"):
                instance.run(bytes(range(16)))
            history = typed_journal.read(path)
        self.assertEqual(history.phase, typed_journal.EnrollmentPhase.OUTCOME_UNKNOWN)
        self.assertEqual(bytes(transport.start_view), bytes(68))

    def test_cancel_waits_for_terminal_status(self):
        transport = FakeTransport(
            [raw_event(1, protocol.SERVICE_STATUS, 1, 66)]
        )
        with tempfile.TemporaryDirectory() as directory:
            instance, path, _operation_id = self.create(directory, transport)
            result = instance.run(bytes(range(16)), cancel_requested=lambda: True)
            history = typed_journal.read(path)
        self.assertEqual(result.outcome, "cancelled")
        self.assertEqual(transport.cancel_calls, 1)
        self.assertEqual(history.phase, typed_journal.EnrollmentPhase.TERMINAL_FAILURE)

    def test_duplicate_event_freezes_and_journals_protocol_unknown(self):
        duplicate = raw_event(1, protocol.SERVICE_STATUS, 1, 100)
        transport = FakeTransport([duplicate, duplicate])
        with tempfile.TemporaryDirectory() as directory:
            instance, path, _operation_id = self.create(directory, transport)
            with self.assertRaisesRegex(operation.EnrollmentOperationError, "unknown"):
                instance.run(bytes(range(16)))
            history = typed_journal.read(path)
        self.assertEqual(transport.continue_calls, 1)
        self.assertEqual(history.phase, typed_journal.EnrollmentPhase.OUTCOME_UNKNOWN)

    def test_stale_connection_baseline_is_rejected_before_transport_use(self):
        transport = FakeTransport([])
        transport.connection_generation = str(uuid.UUID(int=99))
        with tempfile.TemporaryDirectory() as directory:
            value = baseline()
            path = Path(directory) / "operation.jsonl"
            operation_id, _record = journal.create(path, "enroll", value)
            with self.assertRaises(typed_journal.EnrollmentJournalError):
                operation.EnrollmentOperation(
                    journal_path=path,
                    operation_id=operation_id,
                    transport=transport,
                    linux_boot_uuid=value["linux_boot_uuid"],
                    mapping_generation=value["mapping_generation"],
                    caller_linux_uid=1000,
                    target_linux_uid=1000,
                )

    def test_cancel_callback_failure_is_journaled_as_unknown(self):
        transport = FakeTransport([])

        def fail() -> bool:
            raise RuntimeError("synthetic callback failure")

        with tempfile.TemporaryDirectory() as directory:
            instance, path, _operation_id = self.create(directory, transport)
            with self.assertRaisesRegex(operation.EnrollmentOperationError, "unknown"):
                instance.run(bytes(range(16)), cancel_requested=fail)
            history = typed_journal.read(path)
        self.assertEqual(history.phase, typed_journal.EnrollmentPhase.OUTCOME_UNKNOWN)

    def test_post_dispatch_journal_failure_is_reclassified_as_unknown(self):
        transport = FakeTransport([])
        real_append = typed_journal.append_checked
        failed = False

        def fail_once(path, operation_id, milestone, evidence):
            nonlocal failed
            if milestone == "ENROLL_START_OBSERVED" and not failed:
                failed = True
                raise typed_journal.EnrollmentJournalError("synthetic journal failure")
            return real_append(path, operation_id, milestone, evidence)

        with tempfile.TemporaryDirectory() as directory:
            instance, path, _operation_id = self.create(directory, transport)
            with patch.object(
                operation.enrollment_journal,
                "append_checked",
                side_effect=fail_once,
            ):
                with self.assertRaisesRegex(operation.EnrollmentOperationError, "unknown"):
                    instance.run(bytes(range(16)))
            history = typed_journal.read(path)
        self.assertTrue(failed)
        self.assertEqual(history.phase, typed_journal.EnrollmentPhase.OUTCOME_UNKNOWN)

    def test_feedback_callback_failure_is_journaled_as_unknown(self):
        transport = FakeTransport(
            [raw_event(1, protocol.SERVICE_STATUS, 1, 100)]
        )

        def fail(_transition) -> None:
            raise RuntimeError("synthetic feedback failure")

        with tempfile.TemporaryDirectory() as directory:
            instance, path, _operation_id = self.create(directory, transport)
            with self.assertRaisesRegex(operation.EnrollmentOperationError, "unknown"):
                instance.run(bytes(range(16)), on_feedback=fail)
            history = typed_journal.read(path)
        self.assertEqual(history.phase, typed_journal.EnrollmentPhase.OUTCOME_UNKNOWN)
        self.assertEqual(transport.continue_calls, 0)


if __name__ == "__main__":
    unittest.main()
