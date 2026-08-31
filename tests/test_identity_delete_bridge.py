# SPDX-License-Identifier: GPL-2.0-only
import sys
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_bridge_wire
import t2_identity_delete_bridge as bridge


class Lease:
    def __init__(self, reply=None, events=None, error=None):
        self.connection_generation = str(uuid.UUID(int=90))
        self.reply = [0, b""] if reply is None else reply
        self.events = [] if events is None else events
        self.error = error
        self.calls = []
        self.invalidated = False

    def biometric_command(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if self.error:
            raise self.error
        return self.reply, self.events

    def invalidate(self):
        self.invalidated = True


class IdentityDeleteBridgeTests(unittest.TestCase):
    def test_exact_command_version_and_target_are_dispatched_once(self):
        lease = Lease(reply=[-7, t2_bridge_wire.BIOMETRIC_NIL_OUTPUT_SENTINEL])
        adapter = bridge.IdentityDeleteBridge(
            lease, connection_generation=lease.connection_generation
        )
        request = b"x" * 20
        result = adapter.delete(request)
        self.assertEqual(result.status, -7)
        self.assertEqual(
            lease.calls,
            [
                (
                    0x0D,
                    {
                        "version": 0,
                        "value": 0,
                        "data": request,
                        "output_capacity": 0,
                    },
                )
            ],
        )
        with self.assertRaises(bridge.IdentityDeleteBridgeError):
            adapter.delete(request)

    def test_malformed_reply_or_event_poison_generation(self):
        for reply, events in (([0, b"unexpected"], []), ([0, b""], ["event"])):
            with self.subTest(reply=reply, events=events):
                lease = Lease(reply=reply, events=events)
                adapter = bridge.IdentityDeleteBridge(
                    lease, connection_generation=lease.connection_generation
                )
                with self.assertRaises(bridge.IdentityDeleteBridgeError):
                    adapter.delete(b"x" * 20)
                self.assertTrue(lease.invalidated)

    def test_local_length_error_does_not_dispatch_or_poison(self):
        lease = Lease()
        adapter = bridge.IdentityDeleteBridge(
            lease, connection_generation=lease.connection_generation
        )
        with self.assertRaises(bridge.IdentityDeleteBridgeError):
            adapter.delete(b"short")
        self.assertEqual(lease.calls, [])
        self.assertEqual(adapter.state, bridge.DeleteBridgeState.READY)


if __name__ == "__main__":
    unittest.main()
