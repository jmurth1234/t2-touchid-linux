import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_acm_protocol as acm


class ACMProtocolTests(unittest.TestCase):
    def test_tracking_create_matches_recovered_apple_framing(self):
        self.assertEqual(
            acm.build_create(user_id=501, tracking=True).hex(),
            "4452435324000001f5010000",
        )
        self.assertEqual(
            acm.validate_command(acm.build_create(user_id=501, tracking=True)),
            acm.OP_CONTEXT_CREATE_TRACKING,
        )

    def test_legacy_create_matches_recovered_apple_framing(self):
        self.assertEqual(
            acm.build_create(user_id=501, tracking=False).hex(),
            "4452435301000001f5010000",
        )

    def test_tracking_create_response_is_exact_and_typed(self):
        context = bytes(range(16))
        parsed = acm.parse_create_response(
            context + b"\x01" + bytes.fromhex("78563412"), tracking=True
        )
        self.assertEqual(parsed, acm.ContextHandle(context, 0x12345678, True, True))

    def test_legacy_create_response_is_exact_and_typed(self):
        context = bytes(range(16))
        parsed = acm.parse_create_response(context + b"\x00", tracking=False)
        self.assertEqual(parsed, acm.ContextHandle(context, 0, False, False))

    def test_delete_contains_only_header_and_context(self):
        handle = acm.ContextHandle(bytes(range(16)), 0xDEADBEEF, True, True)
        command = acm.build_delete(handle)
        self.assertEqual(command.hex(), "4452435302000001" + bytes(range(16)).hex())
        self.assertEqual(acm.validate_command(command), acm.OP_CONTEXT_DELETE)

    def test_response_rejects_wrong_size_or_tracking_mode(self):
        with self.assertRaises(acm.ACMProtocolError):
            acm.parse_create_response(b"\x00" * 20, tracking=True)
        with self.assertRaises(acm.ACMProtocolError):
            acm.parse_create_response(b"\x00" * 16 + b"\x02" + b"\x00" * 4, tracking=True)
        with self.assertRaises(acm.ACMProtocolError):
            acm.parse_create_response(b"\x00" * 16 + b"\x02", tracking=False)

    def test_validator_rejects_raw_or_extended_commands(self):
        for command in (
            b"",
            b"DRCS\x03\x00\x00\x01",
            b"DRCS\x01\x00\x00\x01",
            b"DRCS\x01\x01\x00\x01" + b"\x00" * 4,
            acm.build_create(user_id=501) + b"\x00",
        ):
            with self.subTest(command=command):
                with self.assertRaises(acm.ACMProtocolError):
                    acm.validate_command(command)


if __name__ == "__main__":
    unittest.main()
