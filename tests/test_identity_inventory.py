# SPDX-License-Identifier: GPL-2.0-only
import sys
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_codec as codec
import t2_identity_inventory as inventory
from tests.test_catacomb_codec import fixture


def live_for(local):
    records = [
        {"user_id": identity.user_id, "identity_uuid": identity.uuid}
        for identity in local.identities
    ]
    return {
        "double_collection_equal": True,
        "apple_uid": 501,
        "biometric_protocol_version": 2,
        "catacomb": {"present": True},
        "per_user_identity_records": records,
        "global_identity_records": [
            {
                **record,
                "group_type": 1,
                "group_uuid": str(uuid.UUID(int=0)),
            }
            for record in records
        ],
    }


class IdentityInventoryTests(unittest.TestCase):
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

    def test_lists_numbered_labels_without_identifiers(self):
        result = inventory.summarize(self.local, live_for(self.local))
        self.assertEqual(result["identity_count"], 2)
        self.assertEqual(
            result["identities"],
            [
                {"slot": 1, "name": "Right index finger", "live": True},
                {"slot": 2, "name": "Linux enrolled finger", "live": True},
            ],
        )
        rendered = repr(result)
        for identity in self.local.identities:
            self.assertNotIn(identity.uuid, rendered)

    def test_rejects_local_live_or_global_divergence(self):
        live = live_for(self.local)
        live["per_user_identity_records"] = live["per_user_identity_records"][:-1]
        with self.assertRaisesRegex(
            inventory.IdentityInventoryError, "disagree"
        ):
            inventory.summarize(self.local, live)

        live = live_for(self.local)
        live["global_identity_records"][0]["group_type"] = 2
        with self.assertRaisesRegex(
            inventory.IdentityInventoryError, "built-in"
        ):
            inventory.summarize(self.local, live)

    def test_rejects_unstable_or_rebound_inventory(self):
        for field, value in (
            ("double_collection_equal", False),
            ("apple_uid", 502),
            ("biometric_protocol_version", 1),
            ("catacomb", {"present": False}),
        ):
            live = live_for(self.local)
            live[field] = value
            with self.subTest(field=field), self.assertRaises(
                inventory.IdentityInventoryError
            ):
                inventory.summarize(self.local, live)


if __name__ == "__main__":
    unittest.main()
