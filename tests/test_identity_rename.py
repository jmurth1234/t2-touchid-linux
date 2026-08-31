# SPDX-License-Identifier: GPL-2.0-only
import sys
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_codec as codec
import t2_identity_rename as rename
from tests.test_catacomb_codec import fixture
from tests.test_identity_inventory import live_for


class IdentityRenameTests(unittest.TestCase):
    def setUp(self):
        first = codec.decode_user_catacomb(fixture(), 501)
        self.local = codec.decode_user_catacomb(
            first.add(
                identity_uuid=str(uuid.UUID(int=4)),
                entity=1,
                name="Linux enrolled finger",
            ),
            501,
        )
        self.live = live_for(self.local)

    def test_plan_changes_only_selected_label_and_redacts_repr(self):
        value = rename.plan(
            self.local, self.live, slot=2, new_name="Left index finger"
        )
        decoded = codec.decode_user_catacomb(value.archive, 501)
        self.assertEqual(
            [identity.name for identity in decoded.identities],
            ["Right index finger", "Left index finger"],
        )
        self.assertNotIn(value.identity_uuid, repr(value))
        self.assertNotIn(value.archive.hex(), repr(value))

    def test_plan_rejects_stale_slot_invalid_or_unchanged_name(self):
        for slot, name in (
            (0, "New"),
            (3, "New"),
            (2, ""),
            (2, "Linux enrolled finger"),
            (2, "x\x00y"),
        ):
            with self.subTest(slot=slot, name=name), self.assertRaises(
                rename.IdentityRenameError
            ):
                rename.plan(self.local, self.live, slot=slot, new_name=name)

        stale = live_for(self.local)
        stale["per_user_identity_records"] = stale["per_user_identity_records"][:-1]
        with self.assertRaises(rename.IdentityRenameError):
            rename.plan(self.local, stale, slot=2, new_name="New")

    def test_fresh_secure_blob_preserves_renamed_semantics(self):
        value = rename.plan(self.local, self.live, slot=2, new_name="New")
        output = rename.bind_secure_blob(value, b"LTFC" + b"z" * 28)
        decoded = codec.decode_user_catacomb(bytes(output), 501)
        self.assertEqual(decoded.secure_data, b"LTFC" + b"z" * 28)
        self.assertEqual(decoded.identities[1].name, "New")

        with self.assertRaises(rename.IdentityRenameError):
            rename.bind_secure_blob(value, b"bad")


if __name__ == "__main__":
    unittest.main()
