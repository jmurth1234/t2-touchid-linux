# SPDX-License-Identifier: GPL-2.0-only
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_biolockout_protocol as biolockout_protocol
import t2_catacomb_protocol as catacomb_protocol
import t2_enrollment_persistence_bridge as bridge


GENERATION = str(uuid.UUID(int=4))


class FakeLease:
    def __init__(self):
        self.connection_generation = GENERATION
        self.calls = []
        self.invalidated = False
        self.replies = iter(
            [
                ([0, (32).to_bytes(4, "little")], []),
                ([0, b"LTFC" + b"u" * 28], []),
                ([0, b""], []),
                ([0, b"HRLB" + b"b" * 101], []),
            ]
        )

    def biometric_command(self, command, *, version, value, data, output_capacity):
        self.calls.append((command, version, value, bytes(data), output_capacity))
        return next(self.replies)

    def invalidate(self):
        self.invalidated = True


class EnrollmentPersistenceBridgeTests(unittest.TestCase):
    def test_routes_catacomb_then_variable_length_biolockout(self):
        lease = FakeLease()
        transport = bridge.EnrollmentPersistenceBridgeTransport(
            lease, protocol_version=2, connection_generation=GENERATION
        )
        descriptor = catacomb_protocol.CatacombComponent.user(501).descriptor
        self.assertEqual(transport.prepare(descriptor), (0, 32))
        status, user_blob = transport.complete(descriptor)
        self.assertEqual((status, len(user_blob)), (0, 32))
        self.assertEqual(transport.confirm(descriptor), 0)

        bio = biolockout_protocol.PERSISTENCE_DESCRIPTOR
        self.assertEqual(transport.prepare(bio), (0, 0x1000))
        status, bio_blob = transport.complete(bio)
        self.assertEqual((status, len(bio_blob)), (0, 105))
        self.assertEqual(transport.confirm(bio), 0)
        self.assertEqual(transport.state, bridge.RouteState.IDLE)
        self.assertEqual(
            [call[0] for call in lease.calls], [0x3D, 0x3E, 0x3F, 0x4A]
        )
        self.assertFalse(lease.invalidated)

    def test_route_change_is_rejected_before_second_dispatch(self):
        lease = FakeLease()
        transport = bridge.EnrollmentPersistenceBridgeTransport(
            lease, protocol_version=2, connection_generation=GENERATION
        )
        descriptor = catacomb_protocol.CatacombComponent.user(501).descriptor
        transport.prepare(descriptor)
        with self.assertRaisesRegex(
            bridge.EnrollmentPersistenceBridgeError, "bio-lockout"
        ):
            transport.complete(biolockout_protocol.PERSISTENCE_DESCRIPTOR)
        self.assertEqual([call[0] for call in lease.calls], [0x3D])


if __name__ == "__main__":
    unittest.main()
