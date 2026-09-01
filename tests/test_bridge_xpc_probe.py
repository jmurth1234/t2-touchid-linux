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
import t2_catacomb_codec as codec
import t2_fprint_match_gate as match_gate
from tests.test_catacomb_codec import fixture


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

    def test_service_status_summary_uses_payload_ordinal_not_timestamp(self):
        timestamp = 0x6B158284DB5
        raw = struct.pack("<QIIQ", 0, 0xE3FF8001, 1, timestamp)
        raw += struct.pack("<I4xQ", 90, 0)
        summary = MODULE.summarize_event([9, 0xE3FF8000, raw, None, None])
        self.assertTrue(summary["common_record_valid"])
        self.assertTrue(summary["reserved_zero"])
        self.assertTrue(summary["event_timestamp_present"])
        self.assertEqual(summary["ordinal"], 90)
        self.assertTrue(summary["parsed_ordinal_matches"])
        self.assertNotIn(str(timestamp), str(summary))

    def test_sks_event_summary_exposes_only_shape_and_user_match(self):
        timestamp = 0x6B158284DB5
        raw = struct.pack("<QIIQ", 0, 0xE3FF800A, 1, timestamp)
        raw += struct.pack("<IH", 501, 0x228) + b"opaque"
        summary = MODULE.summarize_event(
            [9, 0xE3FF8000, raw, None, None], expected_user_id=501
        )
        self.assertEqual(summary["event_kind"], "sks_lock_state")
        self.assertEqual(summary["event_data_length"], 12)
        self.assertTrue(summary["user_id_matches_configured"])
        self.assertNotIn("501", str(summary))
        self.assertNotIn("552", str(summary))
        self.assertNotIn("opaque", str(summary))

    def test_match_summary_distinguishes_selected_from_other_enrolled_identity(self):
        selected = struct.pack("<I", 501) + uuid.UUID(int=11).bytes
        other = struct.pack("<I", 501) + uuid.UUID(int=12).bytes
        raw = struct.pack("<QIIQ", 0, 0xE3FF8002, 2, 1)
        raw += other[4:20] + b"\0" * (0xC70 - 16)
        summary = MODULE.summarize_event(
            [9, 0xE3FF8000, raw, None, None],
            (selected, other),
            expected_user_id=501,
            selected_identity_record=selected,
        )
        self.assertTrue(summary["matched"])
        self.assertTrue(summary["matches_enrolled_identity"])
        self.assertFalse(summary["matches_selected_identity"])
        self.assertNotIn(selected.hex(), str(summary))
        self.assertNotIn(other.hex(), str(summary))

    def test_match_summary_accepts_only_selected_identity_boolean(self):
        selected = struct.pack("<I", 501) + uuid.UUID(int=11).bytes
        other = struct.pack("<I", 501) + uuid.UUID(int=12).bytes
        raw = struct.pack("<QIIQ", 0, 0xE3FF8002, 2, 1)
        raw += selected[4:20] + b"\0" * (0xC70 - 16)
        summary = MODULE.summarize_event(
            [9, 0xE3FF8000, raw, None, None],
            (selected, other),
            selected_identity_record=selected,
        )
        self.assertTrue(summary["matches_selected_identity"])

    def test_any_match_summary_resolves_only_one_canonical_name(self):
        original = codec.decode_user_catacomb(fixture(), 501)
        renamed = codec.decode_user_catacomb(
            original.rename(
                original.identities[0].uuid,
                "right-index-finger",
            ),
            501,
        )
        local = codec.decode_user_catacomb(
            renamed.add(
                identity_uuid=str(uuid.UUID(int=4)),
                entity=1,
                name="left-thumb",
            ),
            501,
        )
        records = tuple(
            struct.pack("<I", identity.user_id) + uuid.UUID(identity.uuid).bytes
            for identity in local.identities
        )
        global_records = tuple(
            record + struct.pack("<I", 1) + uuid.UUID(int=0).bytes
            for record in records
        )
        gate = match_gate.prepare_all(
            local,
            {"master.cat": b"m", "user_000001f5.cat": b"u"},
            records,
            global_records,
            records,
            global_records,
        )
        raw = struct.pack("<QIIQ", 0, 0xE3FF8002, 2, 1)
        raw += records[1][4:20] + b"\0" * (0xC70 - 16)
        summary = MODULE.summarize_event(
            [9, 0xE3FF8000, raw, None, None],
            records,
            all_match_gate=gate,
        )
        self.assertTrue(summary["matched_finger_name_present"])
        self.assertEqual(summary["matched_finger_name"], local.identities[1].name)
        self.assertNotIn(records[1].hex(), str(summary))

    def test_slot_match_summary_resolves_only_ephemeral_slot(self):
        original = codec.decode_user_catacomb(fixture(), 501)
        local = codec.decode_user_catacomb(
            original.add(
                identity_uuid=str(uuid.UUID(int=4)),
                entity=1,
                name="Linux enrolled finger",
            ),
            501,
        )
        records = tuple(
            struct.pack("<I", identity.user_id)
            + uuid.UUID(identity.uuid).bytes
            for identity in reversed(local.identities)
        )
        global_records = tuple(
            record + struct.pack("<I", 1) + uuid.UUID(int=0).bytes
            for record in records
        )
        gate = match_gate.prepare_slots(
            local,
            {"master.cat": b"m", "user_000001f5.cat": b"u"},
            records,
            global_records,
            records,
            global_records,
        )
        raw = struct.pack("<QIIQ", 0, 0xE3FF8002, 2, 1)
        raw += records[0][4:20] + b"\0" * (0xC70 - 16)
        summary = MODULE.summarize_event(
            [9, 0xE3FF8000, raw, None, None],
            records,
            slot_match_gate=gate,
        )
        self.assertTrue(summary["matched_identity_slot_present"])
        self.assertIn(summary["matched_identity_slot"], (1, 2))
        self.assertNotIn(records[0].hex(), str(summary))
        self.assertNotIn("finger_name", str(summary))

    def test_strict_identity_records_rejects_status_shape_and_events(self):
        record = struct.pack("<I", 501) + uuid.UUID(int=11).bytes
        self.assertEqual(
            MODULE.strict_identity_records([0, record], [], 20, "test"),
            (record,),
        )
        for reply, events, size in (
            ([-1, record], [], 20),
            ([0, record + b"x"], [], 20),
            ([0, record], [object()], 20),
            ([0, record], [], 21),
        ):
            with self.subTest(), self.assertRaises(ValueError):
                MODULE.strict_identity_records(reply, events, size, "test")

    def test_post_match_inventory_retains_separate_late_callbacks(self):
        record = struct.pack("<I", 501) + uuid.UUID(int=11).bytes
        callback = [9, 0xE3FF8000, b"opaque", None, None]
        self.assertEqual(
            MODULE.post_match_identity_records(
                [0, record], [callback], 20, "post-match"
            ),
            (record,),
        )
        with self.assertRaisesRegex(ValueError, "callback stream"):
            MODULE.post_match_identity_records(
                [0, record], None, 20, "post-match"
            )

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
