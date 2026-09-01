# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_fprint_runtime as runtime


def projection(names=(), *, count=2, complete=False):
    return {
        "schema_version": 1,
        "finger_names": list(names),
        "reconciled_identity_count": count,
        "unassigned_identity_count": 0 if complete else count,
        "duplicate_finger_name_count": 0,
        "complete": complete,
        "compatibility_alias_required": not complete,
        "finger_names_are_presentation_metadata": True,
        "identifiers_redacted": True,
    }


class FprintRuntimeTests(unittest.TestCase):
    def test_incomplete_projection_lists_only_compatibility_alias(self):
        view = runtime.parse_projection(projection(), "right-index-finger")
        self.assertEqual(view.listed_fingers, ("right-index-finger",))
        request = runtime.resolve_match(view, "right-index-finger")
        self.assertTrue(request.match_all)
        self.assertIsNone(request.target_finger)
        self.assertTrue(request.compatibility_alias_used)

    def test_complete_projection_lists_and_targets_exact_names(self):
        view = runtime.parse_projection(
            projection(
                ("left-thumb", "right-index-finger"),
                count=2,
                complete=True,
            ),
            "right-index-finger",
        )
        self.assertEqual(
            view.listed_fingers,
            ("left-thumb", "right-index-finger"),
        )
        request = runtime.resolve_match(view, "left-thumb")
        self.assertFalse(request.match_all)
        self.assertEqual(request.target_finger, "left-thumb")

    def test_any_matches_all_but_is_never_a_private_target(self):
        for view in (
            runtime.parse_projection(projection(), "right-index-finger"),
            runtime.parse_projection(
                projection(("left-thumb",), count=1, complete=True),
                "right-index-finger",
            ),
        ):
            request = runtime.resolve_match(view, "any")
            self.assertTrue(request.match_all)
            self.assertIsNone(request.target_finger)

    def test_duplicate_labels_are_validly_incomplete_and_never_listed(self):
        value = projection()
        value["unassigned_identity_count"] = 0
        value["duplicate_finger_name_count"] = 1
        view = runtime.parse_projection(value, "right-index-finger")
        self.assertFalse(view.complete)
        self.assertEqual(view.listed_fingers, ("right-index-finger",))

    def test_unenrolled_name_and_empty_inventory_fail(self):
        complete = runtime.parse_projection(
            projection(("left-thumb",), count=1, complete=True),
            "right-index-finger",
        )
        empty = runtime.parse_projection(
            projection((), count=0, complete=True),
            "right-index-finger",
        )
        for view, requested in (
            (complete, "right-thumb"),
            (empty, "any"),
            (empty, "right-index-finger"),
        ):
            with self.subTest(), self.assertRaises(runtime.FprintRuntimeError):
                runtime.resolve_match(view, requested)

    def test_malformed_or_incoherent_projection_fails(self):
        cases = []
        for key, value in (
            ("schema_version", 2),
            ("finger_names", ["any"]),
            ("reconciled_identity_count", True),
            ("identifiers_redacted", False),
            ("compatibility_alias_required", False),
        ):
            candidate = projection()
            candidate[key] = value
            cases.append(candidate)
        partial = projection(("left-thumb",))
        partial["unassigned_identity_count"] = 1
        cases.append(partial)
        wrong_order = projection(
            ("right-index-finger", "left-thumb"),
            count=2,
            complete=True,
        )
        cases.append(wrong_order)
        extra = projection()
        extra["private_uuid"] = "forbidden"
        cases.append(extra)
        for candidate in cases:
            with self.subTest(), self.assertRaises(runtime.FprintRuntimeError):
                runtime.parse_projection(candidate, "right-index-finger")


if __name__ == "__main__":
    unittest.main()
