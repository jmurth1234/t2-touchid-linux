#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free fail-closed parser tests for BridgeXPC replies."""

import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
import uuid


MODULE_PATH = Path(__file__).resolve().parents[1] / "src/bridge-xpc-probe.py"
SPEC = importlib.util.spec_from_file_location("bridge_xpc_probe", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

import t2_bridge_wire as wire


class ReplyTests(unittest.TestCase):
    def test_full_inventory_retries_missing_initial_protocol_payload(self):
        successful = [0, struct.pack("<I", 2)]
        remaining = [
            [0, b""],
            successful,
            [0, b""],
            [0, struct.pack("<I", 5)],
            [0, b""],
            [0, struct.pack("<I", 5)],
            [0, uuid.UUID(int=3).bytes],
            [0, b"\x00" + b"h" * 32],
            [0, b"\0" * 16],
            [0, struct.pack("<I", 552)],
        ]
        with patch.object(
            MODULE,
            "biometric_command",
            side_effect=[(reply, []) for reply in remaining],
        ) as command:
            inventory = MODULE.collect_full_inventory(object(), 501)
        self.assertEqual(inventory["replies"]["protocol"], successful)
        self.assertEqual(command.call_count, 10)

    def test_malformed_command_replies_are_invalid(self):
        for value in (None, {}, [], ["zero"], b"bytes"):
            with self.subTest(value=value):
                self.assertFalse(MODULE.summarize_command_reply(value)["valid"])

    def test_status_and_output_are_summarized_without_payload(self):
        summary = MODULE.summarize_command_reply([0, b"secret payload"])
        self.assertTrue(summary["valid"])
        self.assertEqual(summary["output_length"], 14)
        self.assertNotIn("output", summary)

    def test_nil_placeholder_is_classified_without_disclosure(self):
        sentinel = wire.BIOMETRIC_NIL_OUTPUT_SENTINEL
        summary = MODULE.summarize_command_reply([0, sentinel])
        self.assertTrue(summary["valid"])
        self.assertEqual(summary["output_kind"], "nil-placeholder")
        self.assertIsNone(summary["output_length"])
        self.assertNotIn(sentinel, str(summary))

    def full_inventory(self):
        identity = struct.pack("<I", 501) + uuid.UUID(int=1).bytes
        group = struct.pack("<I", 1) + uuid.UUID(int=2).bytes
        replies = {
            "protocol": [0, struct.pack("<I", 2)],
            "global_identities": [0, identity + group],
            "maximum_capacity": [0, struct.pack("<I", 5)],
            "per_user_identities": [0, identity],
            "free_capacity": [0, struct.pack("<I", 2)],
            "catacomb_uuid": [0, uuid.UUID(int=3).bytes],
            "catacomb_hash": [0, b"\x01" + b"h" * 32],
            "catacomb_state": [0, b"\0" * 16],
            "sks_lock_state": [0, struct.pack("<I", 552)],
        }
        return {"replies": replies, "events": {}}

    def test_full_inventory_compares_whole_private_snapshots(self):
        first = self.full_inventory()
        second = self.full_inventory()
        public, private = MODULE.summarize_full_inventory(
            first,
            second,
            501,
            "00000000-0000-0000-0000-000000000010",
            {},
        )
        self.assertTrue(public["full_snapshot_repeat_equal"])
        self.assertTrue(public["private_inventory_complete"])
        self.assertEqual(public["private_inventory_gate_failures"], [])
        self.assertTrue(public["configured_identity_records_reconciled"])
        self.assertEqual(private["per_user_identity_records"][0]["user_id"], 501)
        self.assertNotIn(str(uuid.UUID(int=1)), str(public))

    def test_full_inventory_with_changed_second_snapshot_is_not_private(self):
        first = self.full_inventory()
        second = self.full_inventory()
        second["replies"]["catacomb_hash"] = [0, b"\x01" + b"x" * 32]
        public, private = MODULE.summarize_full_inventory(
            first,
            second,
            501,
            "00000000-0000-0000-0000-000000000010",
            {},
        )
        self.assertFalse(public["full_snapshot_repeat_equal"])
        self.assertFalse(public["private_inventory_complete"])
        self.assertEqual(public["private_inventory_gate_failures"], ["snapshot_stable"])
        self.assertEqual(private, {})

    def test_v2_global_identity_reply_attests_rejected_protocol_query(self):
        first = self.full_inventory()
        second = self.full_inventory()
        rejected = [-536870206, b"\0" * 4]
        first["replies"]["protocol"] = rejected
        second["replies"]["protocol"] = rejected
        public, private = MODULE.summarize_full_inventory(
            first,
            second,
            501,
            "00000000-0000-0000-0000-000000000010",
            {},
        )
        self.assertTrue(public["biometric_protocol_v2_attested"])
        self.assertEqual(
            public["biometric_protocol_attestation"],
            "v2-global-identity-command",
        )
        self.assertTrue(public["private_inventory_complete"])
        self.assertEqual(private["biometric_protocol_version"], 2)


if __name__ == "__main__":
    unittest.main()
