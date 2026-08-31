# SPDX-License-Identifier: GPL-2.0-only
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_biolockout_bridge as bridge


GENERATION = str(uuid.UUID(int=4))


class FakeLease:
    def __init__(self, reply=([0, b"HRLB" + b"x" * 101], [])):
        self.connection_generation = GENERATION
        self.reply = reply
        self.calls = []
        self.invalidated = False

    def biometric_command(self, command, *, version, value, data, output_capacity):
        self.calls.append((command, version, value, data, output_capacity))
        return self.reply

    def invalidate(self):
        self.invalidated = True


class BioLockoutBridgeTests(unittest.TestCase):
    def test_capture_is_exact_generation_pinned_and_one_shot(self):
        lease = FakeLease()
        transport = bridge.BioLockoutBridgeTransport(
            lease, connection_generation=GENERATION
        )
        output = transport.capture()
        self.assertEqual(output, b"HRLB" + b"x" * 101)
        self.assertEqual(lease.calls, [(0x4A, 1, 0, b"", 0x1000)])
        self.assertEqual(transport.state, bridge.BioLockoutBridgeState.CAPTURED)
        self.assertFalse(lease.invalidated)
        with self.assertRaisesRegex(bridge.BioLockoutBridgeError, "already"):
            transport.capture()

    def test_malformed_reply_poisoned_and_invalidates_lease(self):
        lease = FakeLease(([0, b"NOPE" + b"x" * 101], []))
        transport = bridge.BioLockoutBridgeTransport(
            lease, connection_generation=GENERATION
        )
        with self.assertRaisesRegex(bridge.BioLockoutBridgeError, "invalid"):
            transport.capture()
        self.assertEqual(transport.state, bridge.BioLockoutBridgeState.POISONED)
        self.assertTrue(lease.invalidated)

    def test_unexpected_event_is_ambiguous_and_poisoned(self):
        lease = FakeLease(([0, b"HRLB" + b"x" * 101], [[2, 1, b"event"]]))
        transport = bridge.BioLockoutBridgeTransport(
            lease, connection_generation=GENERATION
        )
        with self.assertRaisesRegex(bridge.BioLockoutBridgeError, "event"):
            transport.capture()
        self.assertTrue(lease.invalidated)

    def test_pre_dispatch_generation_mismatch_does_not_invalidate(self):
        lease = FakeLease()
        transport = bridge.BioLockoutBridgeTransport(
            lease, connection_generation=GENERATION
        )
        lease.connection_generation = str(uuid.UUID(int=5))
        with self.assertRaisesRegex(bridge.BioLockoutBridgeError, "generation"):
            transport.capture()
        self.assertFalse(lease.calls)
        self.assertFalse(lease.invalidated)


if __name__ == "__main__":
    unittest.main()
