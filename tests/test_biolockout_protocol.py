# SPDX-License-Identifier: GPL-2.0-only
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_biolockout_protocol as protocol


class BioLockoutProtocolTests(unittest.TestCase):
    def test_exact_save_request(self):
        request = protocol.build_save_request()
        self.assertEqual(
            (
                request.command,
                request.version,
                request.value,
                request.data,
                request.output_capacity,
            ),
            (0x4A, 1, 0, b"", 0x1000),
        )

    def test_valid_variable_length_record_is_copied_to_wipeable_storage(self):
        source = b"HRLB" + b"x" * 101
        output = protocol.parse_save_reply(0, source)
        self.assertIsInstance(output, bytearray)
        self.assertEqual(output, source)

    def test_rejects_status_shape_length_and_envelope_ambiguity(self):
        invalid = (
            (True, b"HRLB" + b"x" * 12),
            (1, b"HRLB" + b"x" * 12),
            (0, bytearray(b"HRLB" + b"x" * 12)),
            (0, b"HRLB" + b"x" * 11),
            (0, b"NOPE" + b"x" * 12),
            (0, b"HRLB" + b"x" * protocol.OUTPUT_CAPACITY),
        )
        for status, output in invalid:
            with self.subTest(status=status, length=len(output)):
                with self.assertRaises(protocol.BioLockoutProtocolError):
                    protocol.parse_save_reply(status, output)


if __name__ == "__main__":
    unittest.main()
