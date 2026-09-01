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
import t2_fprint_match_selection as selection
from tests.test_catacomb_codec import fixture


def record(user_id, identity_uuid):
    return struct.pack("<I", user_id) + uuid.UUID(identity_uuid).bytes


class FprintMatchSelectionTests(unittest.TestCase):
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
        self.records = tuple(
            record(identity.user_id, identity.uuid)
            for identity in reversed(self.local.identities)
        )

    def test_selects_one_private_record_by_canonical_name(self):
        result = selection.select(
            self.local,
            self.records,
            "left-thumb",
        )
        self.assertEqual(result.finger_name, "left-thumb")
        self.assertEqual(
            result.identity_record,
            record(501, str(uuid.UUID(int=4))),
        )
        rendered = json.dumps(result.public(), sort_keys=True)
        self.assertNotIn(str(uuid.UUID(int=4)), rendered)
        self.assertNotIn("501", rendered)
        self.assertNotIn("identity_record", rendered)
        self.assertNotIn(result.identity_record.hex(), rendered)

    def test_name_is_metadata_but_inventory_is_authority(self):
        reordered = tuple(reversed(self.records))
        result = selection.select(
            self.local,
            reordered,
            "right-index-finger",
        )
        self.assertEqual(
            result.identity_record,
            record(501, self.local.identities[0].uuid),
        )
        self.assertTrue(
            result.public()["finger_name_is_presentation_metadata"]
        )

    def test_incomplete_duplicate_or_missing_name_fails(self):
        original = codec.decode_user_catacomb(fixture(), 501)
        duplicate = codec.decode_user_catacomb(
            original.rename(
                original.identities[0].uuid,
                "right-index-finger",
            ),
            501,
        )
        duplicate = codec.decode_user_catacomb(
            duplicate.add(
                identity_uuid=str(uuid.UUID(int=4)),
                entity=1,
                name="right-index-finger",
            ),
            501,
        )
        for local, name in (
            (original, "right-index-finger"),
            (duplicate, "right-index-finger"),
            (self.local, "right-thumb"),
        ):
            records = tuple(
                record(identity.user_id, identity.uuid)
                for identity in local.identities
            )
            with self.subTest(name=name), self.assertRaises(
                selection.FprintMatchSelectionError
            ):
                selection.select(local, records, name)

    def test_malformed_rebound_duplicate_or_divergent_records_fail(self):
        cases = (
            list(self.records),
            self.records[:-1],
            (b"short", self.records[1]),
            (record(502, self.local.identities[0].uuid), self.records[1]),
            (record(501, str(uuid.UUID(int=99))), self.records[1]),
            (self.records[0], self.records[0]),
        )
        for records in cases:
            with self.subTest(records=type(records).__name__), self.assertRaises(
                selection.FprintMatchSelectionError
            ):
                selection.select(self.local, records, "left-thumb")

    def test_invalid_finger_or_local_type_fails_before_record_use(self):
        for local, name in (
            (object(), "left-thumb"),
            (self.local, "any"),
            (self.local, "Finger 1"),
        ):
            with self.subTest(name=name), self.assertRaises(
                selection.FprintMatchSelectionError
            ):
                selection.select(local, self.records, name)


if __name__ == "__main__":
    unittest.main()
