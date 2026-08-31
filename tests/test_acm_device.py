import struct
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_acm_device as device
import t2_acm_protocol as protocol


class FakeDevice:
    def __init__(
        self,
        response: bytes,
        *,
        policy_response: bytes | list[bytes] = b"",
        fail_delete: bool = False,
    ):
        self.response = response
        self.policy_response = policy_response
        self.fail_delete = fail_delete
        self.commands = []

    def exchange(self, command: bytes, response_capacity: int) -> bytes:
        opcode = protocol.validate_command(command)
        self.commands.append((opcode, response_capacity))
        if opcode == protocol.OP_CONTEXT_DELETE:
            if self.fail_delete:
                raise device.ACMDeviceError("synthetic cleanup failure")
            return b""
        if opcode == protocol.OP_VERIFY_POLICY:
            if isinstance(self.policy_response, list):
                return self.policy_response.pop(0)
            return self.policy_response
        return self.response


class ACMDeviceTests(unittest.TestCase):
    def test_uapi_layout_and_ioctl_numbers(self):
        self.assertEqual(device.INFO_SIZE, 16)
        self.assertEqual(device.EXCHANGE_SIZE, 48)
        self.assertEqual(device.T2_ACM_IOC_GET_INFO, 0x8010AC01)
        self.assertEqual(device.T2_ACM_IOC_EXCHANGE, 0xC030AC00)

    def test_registration_metadata_accepts_clean_generation(self):
        info = struct.pack(device.INFO_FORMAT, 7, 16384, 0)
        self.assertEqual(device._registration_generation(info), 7)

    def test_registration_metadata_reports_poisoned_endpoint(self):
        info = struct.pack(
            device.INFO_FORMAT, 8, 16384, device.T2_ACM_INFO_F_POISONED
        )
        with self.assertRaisesRegex(device.ACMDeviceError, "reboot required"):
            device._registration_generation(info)

    def test_registration_metadata_rejects_unknown_flags(self):
        info = struct.pack(device.INFO_FORMAT, 8, 16384, 2)
        with self.assertRaisesRegex(device.ACMDeviceError, "invalid"):
            device._registration_generation(info)

    def test_lifecycle_creates_and_deletes_without_disclosing_context(self):
        context = bytes(range(16))
        fake = FakeDevice(context + b"\x78\x56\x34\x12" + b"\x01")
        result = device.lifecycle_test(fake, 501)
        self.assertEqual(
            fake.commands,
            [
                (protocol.OP_CONTEXT_CREATE_TRACKING, 21),
                (protocol.OP_CONTEXT_DELETE, 0),
            ],
        )
        self.assertTrue(result["mutation_reconciled"])
        self.assertNotIn(context.hex(), str(result))

    def test_invalid_response_is_cleaned_up_before_error(self):
        context = bytes(range(16))
        fake = FakeDevice(context + b"\x00" * 4 + b"\x02")
        with self.assertRaisesRegex(device.ACMDeviceError, "context was cleaned up"):
            device.lifecycle_test(fake, 501)
        self.assertEqual(fake.commands[-1][0], protocol.OP_CONTEXT_DELETE)

    def test_cleanup_failure_is_never_reported_as_reconciled(self):
        context = bytes(range(16))
        fake = FakeDevice(
            context + b"\x00" * 4 + b"\x01", fail_delete=True
        )
        with self.assertRaisesRegex(device.ACMDeviceError, "mandatory context cleanup failed"):
            device.lifecycle_test(fake, 501)

    def test_policy_preflight_is_bounded_and_cleanup_safe(self):
        context = bytes(range(16))
        fake = FakeDevice(
            context + b"\x00" * 4 + b"\x01",
            policy_response=(
                b"\x00\x00\x00\x00"
                + b"\x01\x00\x00\x00"
                + b"\x00\x00\x00\x00"
                + b"\x01\x00\x00\x00"
                + b"\x04\x00\x00\x00"
                + b"data"
            ),
        )
        result = device.policy_preflight_test(fake, 501)
        self.assertEqual(
            fake.commands,
            [
                (protocol.OP_CONTEXT_CREATE_TRACKING, 21),
                (protocol.OP_VERIFY_POLICY, protocol.POLICY_RESPONSE_CAPACITY),
                (protocol.OP_CONTEXT_DELETE, 0),
            ],
        )
        self.assertFalse(result["policy_satisfied"])
        self.assertEqual(result["requirement_length"], 20)
        self.assertEqual(result["requirement_type"], 1)
        self.assertEqual(result["requirement_payload_length"], 4)
        self.assertTrue(result["mutation_reconciled"])
        self.assertNotIn(context.hex(), str(result))

    def test_invalid_policy_response_still_deletes_context(self):
        context = bytes(range(16))
        fake = FakeDevice(
            context + b"\x00" * 4 + b"\x01",
            policy_response=b"\x02\x00\x00\x00",
        )
        with self.assertRaisesRegex(device.ACMDeviceError, "context was cleaned up"):
            device.policy_preflight_test(fake, 501)
        self.assertEqual(fake.commands[-1][0], protocol.OP_CONTEXT_DELETE)

    def test_authorization_binds_password_retries_policy_and_cleans_up(self):
        context = bytes(range(16))
        requirement = (
            b"\x00\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x04\x00\x00\x00"
            + b"data"
        )
        fake = FakeDevice(
            context + b"\x00" * 4 + b"\x01",
            policy_response=[requirement, b"\x01\x00\x00\x00"],
        )
        bound = []
        result = device.authorization_test(fake, 501, bound.append)
        self.assertEqual(bound, [context])
        self.assertTrue(result["policy_satisfied"])
        self.assertFalse(result["fingerprint_mutation_performed"])
        self.assertEqual(fake.commands[-1][0], protocol.OP_CONTEXT_DELETE)

    def test_authorized_consumer_is_scoped_before_context_delete(self):
        context = bytes(range(16))
        requirement = (
            b"\x00\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x00\x00\x00\x00"
        )
        fake = FakeDevice(
            context + b"\x00" * 4 + b"\x01",
            policy_response=[requirement, b"\x01\x00\x00\x00"],
        )

        def consume(value: bytes) -> str:
            self.assertEqual(value, context)
            self.assertEqual(
                [command for command, _capacity in fake.commands],
                [
                    protocol.OP_CONTEXT_CREATE_TRACKING,
                    protocol.OP_VERIFY_POLICY,
                    protocol.OP_VERIFY_POLICY,
                ],
            )
            return "consumed"

        initial, final, result = device.with_authorized_context(
            fake, 501, lambda _context: None, consume
        )
        self.assertFalse(initial.satisfied)
        self.assertTrue(final.satisfied)
        self.assertEqual(result, "consumed")
        self.assertEqual(fake.commands[-1][0], protocol.OP_CONTEXT_DELETE)

    def test_authorized_consumer_failure_still_deletes_context(self):
        context = bytes(range(16))
        requirement = (
            b"\x00\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x00\x00\x00\x00"
        )
        fake = FakeDevice(
            context + b"\x00" * 4 + b"\x01",
            policy_response=[requirement, b"\x01\x00\x00\x00"],
        )

        def fail(_context: bytes) -> None:
            raise RuntimeError("synthetic consumer failure")

        with self.assertRaisesRegex(
            device.ACMDeviceError,
            "failed at authorized-consumer; context was cleaned up",
        ):
            device.with_authorized_context(fake, 501, lambda _: None, fail)
        self.assertEqual(fake.commands[-1][0], protocol.OP_CONTEXT_DELETE)

    def test_authorized_consumer_rejects_async_result_and_deletes_context(self):
        context = bytes(range(16))
        requirement = (
            b"\x00\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x00\x00\x00\x00"
        )
        fake = FakeDevice(
            context + b"\x00" * 4 + b"\x01",
            policy_response=[requirement, b"\x01\x00\x00\x00"],
        )

        async def consume(_context: bytes) -> None:
            return None

        with self.assertRaisesRegex(
            device.ACMDeviceError, "context was cleaned up"
        ) as raised:
            device.with_authorized_context(fake, 501, lambda _: None, consume)
        self.assertIsInstance(raised.exception.__cause__, device.ACMDeviceError)
        self.assertRegex(str(raised.exception.__cause__), "complete synchronously")
        self.assertEqual(fake.commands[-1][0], protocol.OP_CONTEXT_DELETE)

    def test_authorization_can_use_legacy_context_create(self):
        context = bytes(range(16))
        requirement = (
            b"\x00\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x00\x00\x00\x00"
        )
        fake = FakeDevice(
            context + b"\x01",
            policy_response=[requirement, b"\x01\x00\x00\x00"],
        )
        result = device.authorization_test(
            fake, 501, lambda _: None, tracking=False
        )
        self.assertEqual(
            fake.commands,
            [
                (protocol.OP_CONTEXT_CREATE, 17),
                (protocol.OP_VERIFY_POLICY, protocol.POLICY_RESPONSE_CAPACITY),
                (protocol.OP_VERIFY_POLICY, protocol.POLICY_RESPONSE_CAPACITY),
                (protocol.OP_CONTEXT_DELETE, 0),
            ],
        )
        self.assertFalse(result["context_create_tracking"])

    def test_authorization_binder_failure_still_deletes_context(self):
        context = bytes(range(16))
        requirement = (
            b"\x00\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x04\x00\x00\x00"
            + b"data"
        )
        fake = FakeDevice(
            context + b"\x00" * 4 + b"\x01", policy_response=requirement
        )

        def fail(_: bytes) -> None:
            raise device.ACMDeviceError("synthetic password failure")

        with self.assertRaisesRegex(
            device.ACMDeviceError,
            "failed at password-binding; context was cleaned up",
        ):
            device.authorization_test(fake, 501, fail)
        self.assertEqual(fake.commands[-1][0], protocol.OP_CONTEXT_DELETE)

    def test_authorization_preflight_failure_reports_safe_stage(self):
        context = bytes(range(16))
        fake = FakeDevice(
            context + b"\x00" * 4 + b"\x01",
            policy_response=b"\x02\x00\x00\x00",
        )

        with self.assertRaisesRegex(
            device.ACMDeviceError,
            "failed at policy-preflight; context was cleaned up",
        ):
            device.authorization_test(fake, 501, lambda _: None)
        self.assertEqual(fake.commands[-1][0], protocol.OP_CONTEXT_DELETE)


if __name__ == "__main__":
    unittest.main()
