# SPDX-License-Identifier: GPL-2.0-only
import sys
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_bridge as bridge


GENERATION = str(uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))


class FakeLease:
    def __init__(self, replies):
        self.connection_generation = GENERATION
        self.replies = iter(replies)
        self.calls = []

    def biometric_command(
        self, command, *, version, value, data, output_capacity
    ):
        self.calls.append(
            (command, version, value, data, output_capacity)
        )
        result = next(self.replies)
        if isinstance(result, BaseException):
            raise result
        return result


def success_replies(length=32):
    return [
        ([0, length.to_bytes(4, "little")], []),
        ([0, b"L" * length], []),
        ([0, b""], []),
    ]


class CatacombBridgeTests(unittest.TestCase):
    def transport(self, lease, *, version=2):
        return bridge.CatacombBridgeTransport(
            lease,
            protocol_version=version,
            connection_generation=GENERATION,
        )

    def test_complete_transaction_uses_exact_commands_and_capacities(self):
        descriptor = bytes(range(24))
        lease = FakeLease(success_replies())
        transport = self.transport(lease)
        self.assertEqual(transport.prepare(descriptor), (0, 32))
        status, output = transport.complete(descriptor)
        self.assertEqual(status, 0)
        self.assertIs(type(output), bytearray)
        self.assertEqual(output, b"L" * 32)
        self.assertEqual(transport.confirm(descriptor), 0)
        self.assertEqual(transport.state, bridge.TransactionState.IDLE)
        self.assertEqual(
            lease.calls,
            [
                (0x3D, 2, 0, descriptor, 4),
                (0x3E, 2, 0, descriptor, 32),
                (0x3F, 2, 0, descriptor, 0),
            ],
        )
        self.assertNotIn(descriptor.hex(), repr(transport))
        output[:] = bytes(len(output))
        self.assertFalse(any(output))

    def test_protocol_one_preserves_exact_four_byte_descriptor(self):
        descriptor = b"v1!!"
        lease = FakeLease(success_replies(8))
        transport = self.transport(lease, version=1)
        transport.prepare(descriptor)
        transport.complete(descriptor)
        transport.confirm(descriptor)
        self.assertTrue(all(call[3] == descriptor for call in lease.calls))

    def test_out_of_order_or_changed_component_never_dispatches(self):
        descriptor = bytes(24)
        lease = FakeLease(success_replies())
        transport = self.transport(lease)
        with self.assertRaisesRegex(bridge.CatacombBridgeError, "out of order"):
            transport.complete(descriptor)
        self.assertEqual(lease.calls, [])
        transport.prepare(descriptor)
        with self.assertRaisesRegex(bridge.CatacombBridgeError, "changed"):
            transport.complete(b"x" * 24)
        self.assertEqual(len(lease.calls), 1)
        self.assertEqual(transport.state, bridge.TransactionState.PREPARED)

    def test_invalid_descriptor_is_rejected_before_dispatch(self):
        lease = FakeLease(success_replies())
        transport = self.transport(lease)
        with self.assertRaisesRegex(bridge.CatacombBridgeError, "descriptor"):
            transport.prepare(bytes(4))
        self.assertEqual(lease.calls, [])
        self.assertEqual(transport.state, bridge.TransactionState.IDLE)

    def test_disconnect_poisons_generation_and_prevents_retry(self):
        lease = FakeLease([ConnectionError("synthetic disconnect")])
        transport = self.transport(lease)
        with self.assertRaisesRegex(bridge.CatacombBridgeError, "reconciliation"):
            transport.prepare(bytes(24))
        self.assertEqual(transport.state, bridge.TransactionState.POISONED)
        with self.assertRaisesRegex(bridge.CatacombBridgeError, "poisoned"):
            transport.prepare(bytes(24))
        self.assertEqual(len(lease.calls), 1)

    def test_generation_change_during_dispatch_poisons_adapter(self):
        class ChangingLease(FakeLease):
            def biometric_command(self, *args, **kwargs):
                result = super().biometric_command(*args, **kwargs)
                self.connection_generation = str(uuid.UUID(int=17))
                return result

        lease = ChangingLease(success_replies())
        transport = self.transport(lease)
        with self.assertRaisesRegex(bridge.CatacombBridgeError, "generation"):
            transport.prepare(bytes(24))
        self.assertEqual(transport.state, bridge.TransactionState.POISONED)

    def test_malformed_reply_status_output_or_events_poison_adapter(self):
        malformed = (
            [0, b"only-reply"],
            ([0], []),
            ([False, bytes(4)], []),
            ([0, bytearray(4)], []),
            ([0, bytes(5)], []),
            ([0, bytes(4)], [b"unexpected"]),
        )
        for result in malformed:
            with self.subTest(result_type=type(result).__name__):
                lease = FakeLease([result])
                transport = self.transport(lease)
                with self.assertRaises(bridge.CatacombBridgeError):
                    transport.prepare(bytes(24))
                self.assertEqual(
                    transport.state, bridge.TransactionState.POISONED
                )

    def test_nonzero_status_and_complete_length_mismatch_are_terminal(self):
        cases = (
            [([-5, (32).to_bytes(4, "little")], [])],
            [
                ([0, (32).to_bytes(4, "little")], []),
                ([0, bytes(31)], []),
            ],
        )
        for replies in cases:
            with self.subTest(reply_count=len(replies)):
                lease = FakeLease(replies)
                transport = self.transport(lease)
                if len(replies) == 1:
                    with self.assertRaises(bridge.CatacombBridgeError):
                        transport.prepare(bytes(24))
                else:
                    transport.prepare(bytes(24))
                    with self.assertRaises(bridge.CatacombBridgeError):
                        transport.complete(bytes(24))
                self.assertEqual(
                    transport.state, bridge.TransactionState.POISONED
                )

    def test_confirm_requires_empty_output_and_cannot_be_retried(self):
        lease = FakeLease(
            [
                ([0, (8).to_bytes(4, "little")], []),
                ([0, bytes(8)], []),
                ([0, b"unexpected"], []),
            ]
        )
        transport = self.transport(lease)
        transport.prepare(bytes(24))
        transport.complete(bytes(24))
        with self.assertRaises(bridge.CatacombBridgeError):
            transport.confirm(bytes(24))
        self.assertEqual(transport.state, bridge.TransactionState.POISONED)
        with self.assertRaisesRegex(bridge.CatacombBridgeError, "poisoned"):
            transport.confirm(bytes(24))
        self.assertEqual(len(lease.calls), 3)

    def test_constructor_rejects_stale_or_noncanonical_generation(self):
        lease = FakeLease([])
        for generation in ("not-a-uuid", GENERATION.upper()):
            with self.subTest(generation=generation):
                with self.assertRaises(bridge.CatacombBridgeError):
                    bridge.CatacombBridgeTransport(
                        lease,
                        protocol_version=2,
                        connection_generation=generation,
                    )
        with self.assertRaises(bridge.CatacombBridgeError):
            bridge.CatacombBridgeTransport(
                lease,
                protocol_version=True,
                connection_generation=GENERATION,
            )


if __name__ == "__main__":
    unittest.main()
