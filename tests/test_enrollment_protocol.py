import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_enrollment_protocol as enrollment


def event(sequence: int, envelope: int, version: int, ordinal: int, payload: bytes = b""):
    return enrollment.ServiceEvent(sequence, envelope, version, ordinal, payload)


class EnrollmentProtocolTests(unittest.TestCase):
    def machine(self) -> enrollment.EnrollmentStateMachine:
        return enrollment.EnrollmentStateMachine(
            expected_user_id=501,
            connection_generation="generation-a",
            operation_id="operation-a",
        )

    def accept(
        self,
        machine: enrollment.EnrollmentStateMachine,
        value: enrollment.ServiceEvent,
    ) -> enrollment.EnrollmentTransition:
        return machine.accept(
            value,
            connection_generation="generation-a",
            operation_id="operation-a",
        )

    def test_start_request_is_exact_mode_zero_acm_layout_and_wipes(self):
        secret = bytes(range(16))
        request = enrollment.SensitiveEnrollmentRequest(2, 501, secret)
        self.assertEqual(request.command, 3)
        raw = bytes(request.buffer)
        retained_view = request.buffer
        self.assertEqual(len(raw), 68)
        self.assertEqual(raw[:16].hex(), "00000000f50100000000000010000000")
        self.assertEqual(raw[16:32], secret)
        self.assertEqual(raw[32:], bytes(36))
        self.assertNotIn(secret.hex(), repr(request))
        request.wipe()
        self.assertEqual(bytes(retained_view), bytes(68))
        with self.assertRaisesRegex(enrollment.EnrollmentProtocolError, "wiped"):
            request.buffer

    def test_start_request_rejects_unknown_version_or_non_acm_secret(self):
        for version, secret in ((0, bytes(16)), (3, bytes(16)), (2, bytes(15)), (2, bytearray(16))):
            with self.subTest(version=version, secret_type=type(secret).__name__):
                with self.assertRaises(enrollment.EnrollmentProtocolError):
                    enrollment.SensitiveEnrollmentRequest(version, 501, secret)

    def test_protocol_one_start_request_is_exactly_48_bytes(self):
        with enrollment.SensitiveEnrollmentRequest(1, 501, bytes(range(16))) as request:
            raw = bytes(request.buffer)
            self.assertEqual(len(raw), 48)
            self.assertEqual(raw[32:], bytes(16))

    def test_continue_has_no_payload(self):
        self.assertEqual(enrollment.COMMAND_ENROLL_CONTINUE, 0x0E)
        self.assertEqual(enrollment.build_continue_payload(), b"")

    def test_service_event_parser_preserves_two_level_header(self):
        raw = enrollment.SERVICE_HEADER.pack(
            0, enrollment.SERVICE_STATUS, 1, 7
        ) + enrollment.STATUS_PAYLOAD_HEADER.pack(263, 0)
        parsed = enrollment.parse_service_event(raw)
        self.assertEqual(parsed.sequence, 7)
        self.assertEqual(parsed.envelope_type, enrollment.SERVICE_STATUS)
        self.assertEqual(parsed.ordinal, 263)
        self.assertEqual(parsed.payload, enrollment.STATUS_PAYLOAD_HEADER.pack(263, 0))

    def test_live_status_shape_uses_timestamp_not_status_as_sequence(self):
        timestamp = 0x6B158284DB5
        raw = enrollment.SERVICE_HEADER.pack(
            0, enrollment.SERVICE_STATUS, 1, timestamp
        ) + enrollment.STATUS_PAYLOAD_HEADER.pack(90, 0)
        parsed = enrollment.parse_service_event(raw)
        self.assertEqual(parsed.sequence, timestamp)
        self.assertEqual(parsed.ordinal, 90)
        self.assertEqual(parsed.version, 1)

    def test_wire_parser_rejects_nonzero_reserved_or_missing_status_record(self):
        for raw in (
            enrollment.SERVICE_HEADER.pack(1, enrollment.SERVICE_STATUS, 1, 7)
            + enrollment.STATUS_PAYLOAD_HEADER.pack(100, 0),
            enrollment.SERVICE_HEADER.pack(0, enrollment.SERVICE_STATUS, 1, 0)
            + enrollment.STATUS_PAYLOAD_HEADER.pack(100, 0),
            enrollment.SERVICE_HEADER.pack(0, enrollment.SERVICE_STATUS, 1, 7),
        ):
            with self.subTest(length=len(raw)):
                with self.assertRaises(enrollment.EnrollmentProtocolError):
                    enrollment.parse_service_event(raw)

    def test_progress_requires_exactly_one_continue_and_never_completes(self):
        machine = self.machine()
        for sequence, status, percent in ((1, 100, 0), (2, 263, 63), (3, 355, 100)):
            transition = self.accept(
                machine, event(sequence, enrollment.SERVICE_STATUS, 1, status)
            )
            self.assertEqual(transition.action, enrollment.EnrollmentAction.PROGRESS)
            self.assertEqual(transition.progress_percent, percent)
            self.assertTrue(transition.continue_required)
            self.assertEqual(machine.state, enrollment.EnrollmentState.ACTIVE)

    def test_status_70_continues_without_progress(self):
        transition = self.accept(
            self.machine(), event(1, enrollment.SERVICE_STATUS, 1, 70)
        )
        self.assertEqual(transition.action, enrollment.EnrollmentAction.CONTINUE)
        self.assertIsNone(transition.progress_percent)
        self.assertTrue(transition.continue_required)

    def test_structured_status_payload_is_validated_but_not_exposed(self):
        detail = b"private-node-data"
        payload = (
            (263).to_bytes(4, "little")
            + bytes(4)
            + len(detail).to_bytes(8, "little")
            + detail
        )
        transition = self.accept(
            self.machine(),
            event(1, enrollment.SERVICE_STATUS, 1, 263, payload),
        )
        self.assertEqual(transition.progress_percent, 63)
        self.assertNotIn(detail.hex(), repr(transition))

    def test_capture_feedback_is_nonterminal_and_does_not_continue(self):
        cases = {
            74: enrollment.EnrollmentAction.REMOVE_AND_RETRY,
            78: enrollment.EnrollmentAction.RETRY_SCAN,
            85: enrollment.EnrollmentAction.RETRY_SCAN,
            86: enrollment.EnrollmentAction.RETRY_SMALL_COVERAGE,
            87: enrollment.EnrollmentAction.RETRY_SCAN,
            88: enrollment.EnrollmentAction.RETRY_SCAN,
            93: enrollment.EnrollmentAction.DIRTY_SENSOR,
            98: enrollment.EnrollmentAction.RETRY_SCAN,
        }
        for status, action in cases.items():
            with self.subTest(status=status):
                machine = self.machine()
                transition = self.accept(
                    machine, event(1, enrollment.SERVICE_STATUS, 1, status)
                )
                self.assertEqual(transition.action, action)
                self.assertFalse(transition.continue_required)
                self.assertEqual(machine.state, enrollment.EnrollmentState.ACTIVE)

    def test_statistics_telemetry_is_ignored_without_advancing_enrollment(self):
        machine = self.machine()
        transition = self.accept(
            machine,
            event(1, enrollment.SERVICE_STATISTICS, 1, 0, bytes(28)),
        )
        self.assertEqual(
            transition.action, enrollment.EnrollmentAction.IGNORE_TELEMETRY
        )
        self.assertFalse(transition.continue_required)
        self.assertEqual(machine.state, enrollment.EnrollmentState.ACTIVE)

        for version in (0, 2):
            with self.subTest(version=version):
                rejected = self.machine()
                with self.assertRaisesRegex(
                    enrollment.EnrollmentProtocolError,
                    r"envelope 0xe3ff8004 version",
                ):
                    self.accept(
                        rejected,
                        event(1, enrollment.SERVICE_STATISTICS, version, 0),
                    )

        truncated = self.machine()
        with self.assertRaisesRegex(
            enrollment.EnrollmentProtocolError,
            "statistics telemetry payload is truncated",
        ):
            self.accept(
                truncated,
                event(
                    1,
                    enrollment.SERVICE_STATISTICS,
                    1,
                    0,
                    bytes(enrollment.STATISTICS_MIN_PAYLOAD_SIZE - 1),
                ),
            )
        self.assertEqual(truncated.state, enrollment.EnrollmentState.FROZEN)

    def test_sks_lock_state_auxiliary_event_is_validated_and_ignored(self):
        machine = self.machine()
        payload = enrollment.SKS_LOCK_STATE_PAYLOAD.pack(501, 0x228)
        transition = self.accept(
            machine,
            event(1, enrollment.SERVICE_SKS_LOCK_STATE, 1, 0, payload),
        )
        self.assertEqual(
            transition.action, enrollment.EnrollmentAction.IGNORE_AUXILIARY
        )
        self.assertFalse(transition.continue_required)
        self.assertEqual(machine.state, enrollment.EnrollmentState.ACTIVE)

        # The matching daemon requires at least six bytes and ignores trailing
        # fields, so the reducer mirrors that recovered boundary.
        trailing = self.machine()
        accepted = self.accept(
            trailing,
            event(
                1,
                enrollment.SERVICE_SKS_LOCK_STATE,
                1,
                0,
                payload + b"future",
            ),
        )
        self.assertEqual(
            accepted.action, enrollment.EnrollmentAction.IGNORE_AUXILIARY
        )

    def test_sks_lock_state_auxiliary_event_rejects_wrong_shape_or_user(self):
        cases = (
            event(1, enrollment.SERVICE_SKS_LOCK_STATE, 0, 0, bytes(6)),
            event(1, enrollment.SERVICE_SKS_LOCK_STATE, 2, 0, bytes(6)),
            event(1, enrollment.SERVICE_SKS_LOCK_STATE, 1, 0, bytes(5)),
            event(
                1,
                enrollment.SERVICE_SKS_LOCK_STATE,
                1,
                0,
                enrollment.SKS_LOCK_STATE_PAYLOAD.pack(502, 0),
            ),
        )
        for value in cases:
            with self.subTest(version=value.version, length=len(value.payload)):
                machine = self.machine()
                with self.assertRaisesRegex(
                    enrollment.EnrollmentProtocolError,
                    "invalid SKS lock-state auxiliary event",
                ):
                    self.accept(machine, value)
                self.assertEqual(machine.state, enrollment.EnrollmentState.FROZEN)

    def test_terminal_failures_remain_distinct_and_67_is_generic(self):
        cases = {
            66: (enrollment.EnrollmentAction.CANCELLED, enrollment.EnrollmentState.CANCELLED),
            67: (enrollment.EnrollmentAction.FAILED, enrollment.EnrollmentState.FAILED),
            68: (enrollment.EnrollmentAction.TIMED_OUT, enrollment.EnrollmentState.TIMED_OUT),
        }
        for status, (action, state) in cases.items():
            with self.subTest(status=status):
                machine = self.machine()
                transition = self.accept(
                    machine, event(1, enrollment.SERVICE_STATUS, 1, status)
                )
                self.assertEqual(transition.action, action)
                self.assertEqual(machine.state, state)

    def test_v1_result_normalizes_builtin_group_but_is_only_provisional(self):
        identity_uuid = bytes(range(1, 17))
        payload = (501).to_bytes(4, "little") + identity_uuid
        machine = self.machine()
        transition = self.accept(
            machine,
            event(1, enrollment.SERVICE_ENROLLMENT_RESULT, 1, 0, payload),
        )
        self.assertEqual(transition.action, enrollment.EnrollmentAction.IDENTITY_OBSERVED)
        self.assertEqual(machine.state, enrollment.EnrollmentState.SEP_IDENTITY_OBSERVED)
        self.assertEqual(transition.identity.group_type, 1)
        self.assertNotIn(identity_uuid.hex(), repr(transition.identity))

    def test_v2_result_accepts_only_expected_user_and_builtin_group(self):
        identity_uuid = bytes(range(1, 17))
        base = (501).to_bytes(4, "little") + identity_uuid
        for group in (bytes(20), (1).to_bytes(4, "little") + bytes(16)):
            parsed = enrollment.parse_enrollment_identity(
                event(1, enrollment.SERVICE_ENROLLMENT_RESULT, 2, 0, base + group),
                expected_user_id=501,
            )
            self.assertEqual(parsed.identity_uuid, identity_uuid)
        for payload in (
            (502).to_bytes(4, "little") + identity_uuid + bytes(20),
            (501).to_bytes(4, "little") + bytes(16) + bytes(20),
            base + (2).to_bytes(4, "little") + bytes(range(16)),
        ):
            with self.assertRaises(enrollment.EnrollmentProtocolError):
                enrollment.parse_enrollment_identity(
                    event(1, enrollment.SERVICE_ENROLLMENT_RESULT, 2, 0, payload),
                    expected_user_id=501,
                )

    def test_result_versions_enforce_recovered_lengths(self):
        identity = (501).to_bytes(4, "little") + bytes(range(1, 17))
        v2 = identity + bytes(20)
        parsed = enrollment.parse_enrollment_identity(
            event(1, enrollment.SERVICE_ENROLLMENT_RESULT, 2, 0, v2 + b"trailing"),
            expected_user_id=501,
        )
        self.assertEqual(parsed.user_id, 501)
        for version, payload in (
            (1, identity[:-1]),
            (1, identity + b"x"),
            (2, v2[:-1]),
            (3, v2),
        ):
            with self.subTest(version=version, length=len(payload)):
                with self.assertRaises(enrollment.EnrollmentProtocolError):
                    enrollment.parse_enrollment_identity(
                        event(
                            1,
                            enrollment.SERVICE_ENROLLMENT_RESULT,
                            version,
                            0,
                            payload,
                        ),
                        expected_user_id=501,
                    )

    def test_duplicate_regressive_wrong_generation_or_unknown_event_freezes(self):
        cases = []
        duplicate = self.machine()
        accepted = event(1, enrollment.SERVICE_STATUS, 1, 100)
        self.accept(duplicate, accepted)
        cases.append((duplicate, accepted, "generation-a", "operation-a"))
        regressive = self.machine()
        self.accept(regressive, event(2, enrollment.SERVICE_STATUS, 1, 100))
        cases.append((regressive, event(1, enrollment.SERVICE_STATUS, 1, 101), "generation-a", "operation-a"))
        cases.append((self.machine(), event(1, enrollment.SERVICE_STATUS, 1, 100), "generation-b", "operation-a"))
        cases.append((self.machine(), event(1, enrollment.SERVICE_STATUS, 1, 100), "generation-a", "operation-b"))
        cases.append((self.machine(), event(1, 0xDEADBEEF, 1, 0), "generation-a", "operation-a"))
        for machine, value, generation, operation in cases:
            with self.subTest(generation=generation, operation=operation):
                with self.assertRaises(enrollment.EnrollmentProtocolError):
                    machine.accept(
                        value,
                        connection_generation=generation,
                        operation_id=operation,
                    )
                self.assertEqual(machine.state, enrollment.EnrollmentState.FROZEN)

    def test_cancel_is_a_handshake_and_rejects_nonterminal_progress(self):
        machine = self.machine()
        machine.request_cancel()
        self.assertEqual(machine.state, enrollment.EnrollmentState.CANCEL_REQUESTED)
        transition = self.accept(
            machine, event(1, enrollment.SERVICE_STATUS, 1, 66)
        )
        self.assertEqual(transition.action, enrollment.EnrollmentAction.CANCELLED)

        machine = self.machine()
        machine.request_cancel()
        with self.assertRaises(enrollment.EnrollmentProtocolError):
            self.accept(machine, event(1, enrollment.SERVICE_STATUS, 1, 100))
        self.assertEqual(machine.state, enrollment.EnrollmentState.FROZEN)

    def test_unknown_status_version_payload_and_accessory_freeze(self):
        mismatched_status = (101).to_bytes(4, "little") + bytes(12)
        mismatched_length = (100).to_bytes(4, "little") + bytes(4) + (1).to_bytes(8, "little")
        cases = (
            event(1, enrollment.SERVICE_STATUS, 2, 100),
            event(1, enrollment.SERVICE_STATUS, 1, 100, b"truncated"),
            event(1, enrollment.SERVICE_STATUS, 1, 100, mismatched_status),
            event(1, enrollment.SERVICE_STATUS, 1, 100, mismatched_length),
            event(1, enrollment.SERVICE_STATUS, 1, 501),
            event(1, enrollment.SERVICE_ACCESSORY_AUTHORIZATION, 1, 501),
        )
        for value in cases:
            machine = self.machine()
            with self.subTest(value=value.ordinal):
                with self.assertRaises(enrollment.EnrollmentProtocolError):
                    self.accept(machine, value)
                self.assertEqual(machine.state, enrollment.EnrollmentState.FROZEN)

    def test_invalid_result_freezes_the_operation(self):
        machine = self.machine()
        wrong_user = (502).to_bytes(4, "little") + bytes(range(1, 17))
        with self.assertRaisesRegex(
            enrollment.EnrollmentProtocolError, "invalid enrollment-result"
        ):
            self.accept(
                machine,
                event(1, enrollment.SERVICE_ENROLLMENT_RESULT, 1, 0, wrong_user),
            )
        self.assertEqual(machine.state, enrollment.EnrollmentState.FROZEN)


if __name__ == "__main__":
    unittest.main()
