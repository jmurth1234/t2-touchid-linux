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
            context + bytes.fromhex("78563412") + b"\x01", tracking=True
        )
        self.assertEqual(parsed, acm.ContextHandle(context, 0x12345678, True, 1))

    def test_legacy_create_response_is_exact_and_typed(self):
        context = bytes(range(16))
        parsed = acm.parse_create_response(context + b"\x00", tracking=False)
        self.assertEqual(parsed, acm.ContextHandle(context, 0, False, 0))

    def test_legacy_create_preserves_opaque_response_byte(self):
        context = bytes(range(16))
        parsed = acm.parse_create_response(context + b"\x28", tracking=False)
        self.assertEqual(parsed, acm.ContextHandle(context, 0, False, 0x28))
        self.assertIsNone(parsed.response_flag)

    def test_delete_contains_only_header_and_context(self):
        handle = acm.ContextHandle(bytes(range(16)), 0xDEADBEEF, True, 1)
        command = acm.build_delete(handle)
        self.assertEqual(command.hex(), "4452435302000001" + bytes(range(16)).hex())
        self.assertEqual(acm.validate_command(command), acm.OP_CONTEXT_DELETE)

    def test_enrollment_preflight_matches_recovered_fixed_framing(self):
        handle = acm.ContextHandle(bytes(range(16)), 0, True, 1)
        command = acm.build_enrollment_policy_preflight(handle)
        self.assertEqual(len(command), 51)
        self.assertEqual(command[:8], b"DRCS\x03\x00\x00\x01")
        self.assertEqual(command[8:24], bytes(range(16)))
        self.assertEqual(
            command[24:], b"TouchIdEnrollment\x00\x01" + b"\x00" * 8
        )
        self.assertEqual(acm.validate_command(command), acm.OP_VERIFY_POLICY)
        committed = acm.build_enrollment_policy(handle, preflight=False)
        self.assertEqual(committed[42], 0)
        self.assertEqual(acm.validate_command(committed), acm.OP_VERIFY_POLICY)

    def test_policy_response_is_typed_without_exposing_requirement(self):
        requirement = (
            b"\x01\x00\x00\x00"
            + b"\x00\x00\x00\x00"
            + b"\x01\x00\x00\x00"
            + b"\x04\x00\x00\x00"
            + b"private!"[:4]
        )
        parsed = acm.parse_policy_response(b"\x00\x00\x00\x00" + requirement)
        self.assertEqual(
            parsed, acm.PolicyResult(False, True, 20, 1, 0, 1, 4)
        )
        for response in (
            b"",
            b"\x02\x00\x00\x00",
            b"\x00" * 4097,
            b"\x00" * 4 + b"\x01" * 15,
            b"\x00" * 4 + b"\x04" + b"\x00" * 15,
        ):
            with self.subTest(response_length=len(response)):
                with self.assertRaises(acm.ACMProtocolError):
                    acm.parse_policy_response(response)

    def test_response_rejects_wrong_size_or_tracking_mode(self):
        with self.assertRaises(acm.ACMProtocolError):
            acm.parse_create_response(b"\x00" * 20, tracking=True)
        with self.assertRaises(acm.ACMProtocolError):
            acm.parse_create_response(b"\x00" * 20 + b"\x02", tracking=True)
        with self.assertRaises(acm.ACMProtocolError):
            acm.parse_create_response(b"\x00" * 16, tracking=False)

    def test_validator_rejects_raw_or_extended_commands(self):
        for command in (
            b"",
            b"DRCS\x03\x00\x00\x01",
            b"DRCS\x01\x00\x00\x01",
            b"DRCS\x01\x01\x00\x01" + b"\x00" * 4,
            acm.build_create(user_id=501) + b"\x00",
            acm.build_enrollment_policy_preflight(
                acm.ContextHandle(bytes(16), 0, True, 1)
            )[:-1] + b"\x01",
        ):
            with self.subTest(command=command):
                with self.assertRaises(acm.ACMProtocolError):
                    acm.validate_command(command)


if __name__ == "__main__":
    unittest.main()
