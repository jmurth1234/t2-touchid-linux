# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import struct
import sys
import unittest
import uuid
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_catacomb_codec as codec
import t2_fprint_match_gate as gate
from tests.test_catacomb_codec import fixture


def user_record(user_id: int, identity_uuid: str) -> bytes:
    return struct.pack("<I", user_id) + uuid.UUID(identity_uuid).bytes


def global_record(record: bytes, group_type: int = 1) -> bytes:
    return record + struct.pack("<I", group_type) + uuid.UUID(int=0).bytes


class FprintMatchGateTests(unittest.TestCase):
    def setUp(self):
        original = codec.decode_user_catacomb(fixture(), 501)
        renamed = codec.decode_user_catacomb(
            original.rename(
                original.identities[0].uuid,
                "right-index-finger",
            ),
            501,
        )
        self.local = codec.decode_user_catacomb(
            renamed.add(
                identity_uuid=str(uuid.UUID(int=4)),
                entity=1,
                name="left-thumb",
            ),
            501,
        )
        self.components = {
            "master.cat": b"master-private",
            "user_000001f5.cat": b"user-private",
        }
        self.user = tuple(
            user_record(identity.user_id, identity.uuid)
            for identity in reversed(self.local.identities)
        )
        other = user_record(502, str(uuid.UUID(int=99)))
        self.global_records = tuple(
            global_record(record) for record in self.user
        ) + (global_record(other),)

    def test_prepares_one_private_named_identity(self):
        result = gate.prepare(
            self.local,
            self.components,
            self.user,
            self.global_records,
            self.user,
            self.global_records,
            "left-thumb",
        )
        self.assertEqual(
            result.identity_record,
            user_record(501, str(uuid.UUID(int=4))),
        )
        rendered = json.dumps(result.public(), sort_keys=True)
        self.assertNotIn(str(uuid.UUID(int=4)), rendered)
        self.assertNotIn(result.identity_record.hex(), rendered)
        self.assertNotIn("501", rendered)

    def test_post_match_attests_exact_unchanged_state(self):
        result = gate.prepare(
            self.local,
            self.components,
            self.user,
            self.global_records,
            self.user,
            self.global_records,
            "right-index-finger",
        )
        report = gate.attest_unchanged(
            result,
            dict(reversed(tuple(self.components.items()))),
            self.user,
            self.global_records,
        )
        self.assertTrue(report["identity_state_unchanged"])

    def test_unstable_or_divergent_live_views_fail(self):
        cases = (
            (self.user, self.global_records, self.user[::-1], self.global_records),
            (self.user, self.global_records, self.user, self.global_records[::-1]),
            (self.user[:-1], self.global_records, self.user[:-1], self.global_records),
            (
                self.user,
                self.global_records[:-2] + self.global_records[-1:],
                self.user,
                self.global_records[:-2] + self.global_records[-1:],
            ),
        )
        for first_user, first_global, second_user, second_global in cases:
            with self.subTest(), self.assertRaises(gate.FprintMatchGateError):
                gate.prepare(
                    self.local,
                    self.components,
                    first_user,
                    first_global,
                    second_user,
                    second_global,
                    "left-thumb",
                )

    def test_bad_global_binding_fails(self):
        rebound = list(self.global_records)
        rebound[0] = global_record(self.user[0], group_type=2)
        with self.assertRaises(gate.FprintMatchGateError):
            gate.prepare(
                self.local,
                self.components,
                self.user,
                tuple(rebound),
                self.user,
                tuple(rebound),
                "left-thumb",
            )

    def test_post_match_change_fails_closed(self):
        result = gate.prepare(
            self.local,
            self.components,
            self.user,
            self.global_records,
            self.user,
            self.global_records,
            "left-thumb",
        )
        cases = (
            ({**self.components, "master.cat": b"changed"}, self.user, self.global_records),
            (self.components, self.user[::-1], self.global_records),
            (self.components, self.user, self.global_records[::-1]),
        )
        for components, user, all_records in cases:
            with self.subTest(), self.assertRaises(gate.FprintMatchGateError):
                gate.attest_unchanged(result, components, user, all_records)

    def test_all_match_resolves_one_canonical_name_without_identifier(self):
        result = gate.prepare_all(
            self.local,
            self.components,
            self.user,
            self.global_records,
            self.user,
            self.global_records,
        )
        event_data = self.user[0][4:20] + b"\0" * (0xC70 - 16)
        matched = gate.resolve_all_match_event(result, event_data)
        expected = next(
            identity.name
            for identity in self.local.identities
            if uuid.UUID(identity.uuid).bytes == self.user[0][4:20]
        )
        self.assertEqual(matched, expected)
        rendered = json.dumps(result.public(), sort_keys=True)
        self.assertNotIn(self.user[0].hex(), rendered)
        self.assertNotIn(str(uuid.UUID(bytes=self.user[0][4:20])), rendered)

    def test_all_match_negative_is_none_and_ambiguous_fails(self):
        result = gate.prepare_all(
            self.local,
            self.components,
            self.user,
            self.global_records,
            self.user,
            self.global_records,
        )
        self.assertIsNone(
            gate.resolve_all_match_event(result, b"\0" * 0xC70)
        )
        ambiguous = (
            self.user[0][4:20]
            + self.user[1][4:20]
            + b"\0" * (0xC70 - 32)
        )
        with self.assertRaises(gate.FprintMatchGateError):
            gate.resolve_all_match_event(result, ambiguous)

    def test_all_match_requires_complete_names_and_post_attests(self):
        original = codec.decode_user_catacomb(fixture(), 501)
        original_records = tuple(
            user_record(identity.user_id, identity.uuid)
            for identity in original.identities
        )
        original_global = tuple(global_record(record) for record in original_records)
        with self.assertRaises(gate.FprintMatchGateError):
            gate.prepare_all(
                original,
                self.components,
                original_records,
                original_global,
                original_records,
                original_global,
            )
        prepared = gate.prepare_all(
            self.local,
            self.components,
            self.user,
            self.global_records,
            self.user,
            self.global_records,
        )
        self.assertTrue(
            gate.attest_unchanged(
                prepared,
                self.components,
                self.user,
                self.global_records,
            )["identity_state_unchanged"]
        )


if __name__ == "__main__":
    unittest.main()
