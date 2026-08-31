# SPDX-License-Identifier: GPL-2.0-only
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_protocol as protocol


class CatacombProtocolTests(unittest.TestCase):
    def test_requests_preserve_exact_v1_and_v2_descriptors(self):
        for version, descriptor in ((1, b"v1!!"), (2, bytes(range(24)))):
            with self.subTest(version=version):
                prepare = protocol.build_prepare_request(version, descriptor)
                complete = protocol.build_complete_request(version, descriptor, 64)
                confirm = protocol.build_confirm_request(version, descriptor)
                self.assertEqual(
                    (prepare.command, complete.command, confirm.command),
                    (0x3D, 0x3E, 0x3F),
                )
                self.assertEqual(prepare.descriptor, descriptor)
                self.assertEqual(complete.descriptor, descriptor)
                self.assertEqual(confirm.descriptor, descriptor)
                self.assertEqual(
                    (prepare.output_capacity, complete.output_capacity, confirm.output_capacity),
                    (4, 64, 0),
                )
                self.assertNotIn(descriptor.hex(), repr(prepare))

    def test_descriptor_versions_and_lengths_are_exact(self):
        for version, descriptor in (
            (0, bytes(4)),
            (3, bytes(24)),
            (1, bytes(3)),
            (1, bytes(24)),
            (2, bytes(4)),
            (2, bytearray(24)),
            (True, bytes(4)),
        ):
            with self.subTest(version=version, length=len(descriptor)):
                with self.assertRaises(protocol.CatacombProtocolError):
                    protocol.build_prepare_request(version, descriptor)

    def test_prepare_returns_only_a_bounded_exact_length(self):
        self.assertEqual(protocol.parse_prepare_reply(0, (64).to_bytes(4, "little")), 64)
        for status, output in (
            (True, (64).to_bytes(4, "little")),
            (-1, (64).to_bytes(4, "little")),
            (0, bytes(3)),
            (0, bytes(5)),
            (0, bytearray((64).to_bytes(4, "little"))),
            (0, bytes(4)),
            (0, (protocol.MAX_SECURE_BLOB_SIZE + 1).to_bytes(4, "little")),
        ):
            with self.subTest(status=status, output_type=type(output).__name__):
                with self.assertRaises(protocol.CatacombProtocolError):
                    protocol.parse_prepare_reply(status, output)

    def test_complete_requires_the_prepared_length_and_returns_wipeable_storage(self):
        output = bytearray(range(32))
        parsed = protocol.parse_complete_reply(0, output, 32)
        self.assertIs(parsed, output)
        parsed[:] = bytes(len(parsed))
        self.assertFalse(any(output))
        for status, value, expected in (
            (1, bytearray(32), 32),
            (False, bytearray(32), 32),
            (0, bytes(32), 32),
            (0, bytearray(31), 32),
            (0, bytearray(32), 0),
            (0, bytearray(32), protocol.MAX_SECURE_BLOB_SIZE + 1),
        ):
            with self.subTest(status=status, value_type=type(value).__name__):
                with self.assertRaises(protocol.CatacombProtocolError):
                    protocol.parse_complete_reply(status, value, expected)

    def test_confirm_accepts_success_with_no_payload_only(self):
        self.assertIsNone(protocol.parse_confirm_reply(0, b""))
        for status, output in ((1, b""), (False, b""), (0, b"x"), (0, bytearray())):
            with self.subTest(status=status, output_type=type(output).__name__):
                with self.assertRaises(protocol.CatacombProtocolError):
                    protocol.parse_confirm_reply(status, output)

    def test_output_capacities_reject_bool_zero_and_unbounded_values(self):
        descriptor = bytes(24)
        for value in (True, 0, -1, protocol.MAX_SECURE_BLOB_SIZE + 1):
            with self.subTest(value=value):
                with self.assertRaises(protocol.CatacombProtocolError):
                    protocol.build_complete_request(2, descriptor, value)

    def test_request_object_cannot_bypass_per_command_output_contract(self):
        descriptor = bytes(24)
        for command, capacity in ((0x3D, 0), (0x3E, 0), (0x3F, 4)):
            with self.subTest(command=command, capacity=capacity):
                with self.assertRaises(protocol.CatacombProtocolError):
                    protocol.CatacombRequest(command, 2, descriptor, capacity)


if __name__ == "__main__":
    unittest.main()
