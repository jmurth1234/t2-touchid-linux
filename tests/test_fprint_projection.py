# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_fprint_projection as projection


def inventory(names):
    return {
        "schema_version": 1,
        "identity_count": len(names),
        "identities": [
            {"slot": slot, "name": name, "live": True}
            for slot, name in enumerate(names, 1)
        ],
        "local_live_reconciled": True,
        "selection_scope": "current-reconciled-list",
        "fprintd_listing_is_compatibility_alias": True,
        "identifiers_redacted": True,
    }


class FprintProjectionTests(unittest.TestCase):
    def test_complete_projection_uses_upstream_finger_order(self):
        result = projection.project(
            inventory(["right-index-finger", "left-thumb"])
        )
        self.assertTrue(result.complete)
        self.assertEqual(
            result.finger_names,
            ("left-thumb", "right-index-finger"),
        )
        self.assertEqual(result.reconciled_identity_count, 2)
        self.assertEqual(result.unassigned_identity_count, 0)
        self.assertEqual(result.duplicate_finger_name_count, 0)
        self.assertFalse(result.public()["compatibility_alias_required"])

    def test_unknown_or_duplicate_label_never_produces_partial_listing(self):
        cases = (
            (["Finger 1", "right-index-finger"], 1, 0),
            (["right-index-finger", "right-index-finger"], 0, 1),
            (["Finger 1", "Linux enrolled finger"], 2, 0),
        )
        for names, unassigned, duplicates in cases:
            with self.subTest(names=names):
                result = projection.project(inventory(names))
                self.assertFalse(result.complete)
                self.assertEqual(result.finger_names, ())
                self.assertEqual(result.unassigned_identity_count, unassigned)
                self.assertEqual(
                    result.duplicate_finger_name_count, duplicates
                )
                self.assertTrue(
                    result.public()["compatibility_alias_required"]
                )

    def test_projection_is_identifier_free_and_labels_are_not_authority(self):
        result = projection.project(inventory(["left-thumb"]))
        rendered = json.dumps(result.public(), sort_keys=True)
        self.assertIn("finger_names_are_presentation_metadata", rendered)
        for forbidden in (
            "apple_uid",
            "linux_uid",
            "identity_uuid",
            "bag_uuid",
            "keybag",
            '"entity":',
        ):
            self.assertNotIn(forbidden, rendered)

    def test_malformed_or_nonreconciled_inventory_is_rejected(self):
        values = (None, inventory([]), inventory(["left-thumb"]))
        values[1]["identity_count"] = 1
        values[2]["local_live_reconciled"] = False
        for value in values:
            with self.subTest(value=value), self.assertRaises(
                projection.FprintProjectionError
            ):
                projection.project(value)

    def test_upstream_vocabulary_is_exact_and_excludes_any(self):
        self.assertEqual(len(projection.FINGER_NAMES), 10)
        self.assertEqual(len(set(projection.FINGER_NAMES)), 10)
        self.assertNotIn("any", projection.FINGER_NAME_SET)


if __name__ == "__main__":
    unittest.main()
