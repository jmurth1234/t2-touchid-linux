import sys
import tempfile
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_enrollment_bridge as bridge
import t2_enrollment_operation as operation
import t2_enrollment_protocol as protocol
import t2_mutation_journal as journal
from tests.test_mutation_journal import baseline


GENERATION = str(uuid.UUID(int=10))


def event(sequence: int = 1, ordinal: int = 100) -> list[object]:
    raw = protocol.SERVICE_HEADER.pack(
        sequence, protocol.SERVICE_STATUS, 1, ordinal
    )
    return [9, 0, raw, None, None]


class FakeLease:
    def __init__(self) -> None:
        self.connection_generation = GENERATION
        self.results: list[object] = []
        self.events: list[object] = []
        self.calls: list[tuple[int, int, int, bytes, int]] = []

    def biometric_command(
        self,
        command: int,
        *,
        version: int,
        value: int,
        data: bytes | memoryview,
        output_capacity: int,
    ) -> tuple[object, list[object]]:
        self.calls.append((command, version, value, bytes(data), output_capacity))
        result = self.results.pop(0) if self.results else ([0, None], [])
        if isinstance(result, BaseException):
            raise result
        return result  # type: ignore[return-value]

    def next_service_event(self) -> object:
        value = self.events.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


def start_payload(version: int = 2) -> memoryview:
    request = protocol.SensitiveEnrollmentRequest(version, 501, bytes(range(16)))
    # The adapter does not retain this view; the caller owns request wiping.
    return request.buffer


class EnrollmentBridgeTests(unittest.TestCase):
    def make(self, lease: FakeLease, version: int = 2) -> bridge.EnrollmentBridgeTransport:
        return bridge.EnrollmentBridgeTransport(
            lease,
            protocol_version=version,
            connection_generation=GENERATION,
        )

    def test_exact_start_continue_and_cancel_commands(self):
        lease = FakeLease()
        transport = self.make(lease)
        self.assertEqual(transport.start(start_payload()), 0)
        self.assertEqual(transport.continue_enrollment(), 0)
        self.assertEqual(transport.cancel(), 0)
        self.assertEqual(
            lease.calls,
            [
                (protocol.COMMAND_ENROLL_START, 2, 0, bytes(68), 0),
                (protocol.COMMAND_ENROLL_CONTINUE, 2, 0, b"", 0),
                (bridge.COMMAND_CANCEL, 2, 0, b"", 0),
            ],
        )
        self.assertEqual(transport.state, bridge.EnrollmentBridgeState.CANCEL_REQUESTED)

    def test_command_events_are_queued_before_async_receive(self):
        lease = FakeLease()
        first = event(1)
        second = event(2)
        lease.results = [([0, b""], [first])]
        lease.events = [second]
        transport = self.make(lease)
        transport.start(start_payload())
        self.assertEqual(transport.next_event(), first[2])
        self.assertEqual(transport.next_event(), second[2])
        self.assertEqual(lease.events, [])

    def test_start_rejection_is_terminal_and_has_no_mutation_retry(self):
        lease = FakeLease()
        lease.results = [([-5, None], [])]
        transport = self.make(lease)
        self.assertEqual(transport.start(start_payload()), -5)
        self.assertEqual(transport.state, bridge.EnrollmentBridgeState.START_REJECTED)
        with self.assertRaisesRegex(bridge.EnrollmentBridgeError, "out of order"):
            transport.start(start_payload())

    def test_nonzero_continue_poisons_active_operation(self):
        lease = FakeLease()
        lease.results = [([0, None], []), ([-1, None], [])]
        transport = self.make(lease)
        transport.start(start_payload())
        self.assertEqual(transport.continue_enrollment(), -1)
        self.assertEqual(transport.state, bridge.EnrollmentBridgeState.POISONED)

    def test_constructor_rejects_stale_or_noncanonical_generation(self):
        lease = FakeLease()
        for generation in (str(uuid.UUID(int=11)), GENERATION.upper(), "bad"):
            with self.subTest(generation=generation):
                with self.assertRaises(bridge.EnrollmentBridgeError):
                    bridge.EnrollmentBridgeTransport(
                        lease,
                        protocol_version=2,
                        connection_generation=generation,
                    )

    def test_invalid_start_payload_never_dispatches(self):
        lease = FakeLease()
        transport = self.make(lease)
        for payload in (memoryview(bytes(67)), memoryview(bytearray(68))):
            with self.subTest(readonly=payload.readonly, size=payload.nbytes):
                with self.assertRaises(bridge.EnrollmentBridgeError):
                    transport.start(payload)
        self.assertEqual(lease.calls, [])
        self.assertEqual(transport.state, bridge.EnrollmentBridgeState.IDLE)

    def test_malformed_reply_output_or_event_poisons(self):
        bad_results = [
            [0, None],
            ([], []),
            ([True, None], []),
            ([0, b"unexpected"], []),
            ([0, None], [event()[2]]),
            ([-5, None], [event()]),
        ]
        for result in bad_results:
            with self.subTest(result=result):
                lease = FakeLease()
                lease.results = [result]
                transport = self.make(lease)
                with self.assertRaises(bridge.EnrollmentBridgeError):
                    transport.start(start_payload())
                self.assertEqual(transport.state, bridge.EnrollmentBridgeState.POISONED)

    def test_zero_output_reply_encodings_are_equivalent(self):
        for reply in ([0], [0, None], [0, b""]):
            with self.subTest(reply=reply):
                lease = FakeLease()
                lease.results = [(reply, [])]
                transport = self.make(lease)
                self.assertEqual(transport.start(start_payload()), 0)
                self.assertEqual(transport.state, bridge.EnrollmentBridgeState.ACTIVE)

    def test_generation_change_during_dispatch_poisons(self):
        lease = FakeLease()

        def change_generation(*_args: object, **_kwargs: object) -> tuple[object, list[object]]:
            lease.connection_generation = str(uuid.UUID(int=12))
            return [0, None], []

        lease.biometric_command = change_generation  # type: ignore[method-assign]
        transport = self.make(lease)
        with self.assertRaisesRegex(bridge.EnrollmentBridgeError, "generation changed"):
            transport.start(start_payload())
        self.assertEqual(transport.state, bridge.EnrollmentBridgeState.POISONED)

    def test_async_receive_failure_or_bad_event_poisons(self):
        for value in (ConnectionError("lost"), [9, 0, b"short", None, None]):
            with self.subTest(value=value):
                lease = FakeLease()
                lease.events = [value]
                transport = self.make(lease)
                transport.start(start_payload())
                with self.assertRaises(bridge.EnrollmentBridgeError):
                    transport.next_event()
                self.assertEqual(transport.state, bridge.EnrollmentBridgeState.POISONED)

    def test_repr_does_not_include_event_or_enrollment_payload(self):
        lease = FakeLease()
        raw = event()
        lease.results = [([0, None], [raw])]
        transport = self.make(lease)
        transport.start(start_payload())
        rendered = repr(transport)
        self.assertIn("queued_events=1", rendered)
        self.assertNotIn(bytes(raw[2]).hex(), rendered)

    def test_adapter_composes_with_journaled_enrollment_operation(self):
        lease = FakeLease()
        identity_uuid = uuid.UUID(int=7).bytes
        progress = event(1, 263)
        result_data = protocol.SERVICE_HEADER.pack(
            2, protocol.SERVICE_ENROLLMENT_RESULT, 2, 0
        ) + (501).to_bytes(4, "little") + identity_uuid + bytes(20)
        result = [9, 0, result_data, None, None]
        lease.results = [([0, None], [progress]), ([0, None], [result])]
        transport = self.make(lease)
        value = baseline()
        value["connection_generation"] = GENERATION
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "operation.jsonl"
            operation_id, _record = journal.create(path, "enroll", value)
            enrollment = operation.EnrollmentOperation(
                journal_path=path,
                operation_id=operation_id,
                transport=transport,
                linux_boot_uuid=value["linux_boot_uuid"],
                mapping_generation=value["mapping_generation"],
                caller_linux_uid=value["caller_linux_uid"],
                target_linux_uid=value["target_linux_uid"],
            )
            outcome = enrollment.run(bytes(range(16)))
        self.assertEqual(outcome.outcome, "identity-observed")
        self.assertEqual(
            [call[0] for call in lease.calls],
            [protocol.COMMAND_ENROLL_START, protocol.COMMAND_ENROLL_CONTINUE],
        )
        self.assertEqual(lease.connection_generation, GENERATION)


if __name__ == "__main__":
    unittest.main()
