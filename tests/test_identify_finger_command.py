# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "src/t2-touchid-identify-finger.py"
)
SPEC = importlib.util.spec_from_file_location(
    "t2_touchid_identify_finger_test", MODULE_PATH
)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def report(*, matched: bool, slot: int | None = None) -> dict[str, object]:
    event = {
        "event_kind": "match_result",
        "matched": matched,
        "matches_enrolled_identity": matched,
        "matched_identity_slot_present": slot is not None,
    }
    if slot is not None:
        event["matched_identity_slot"] = slot
    return {
        "resolved_slot_match_gate": {
            "schema_version": 1,
            "identity_count": 2,
            "all_identities_selected": True,
            "same_connection_inventory_stable": True,
            "local_live_reconciled": True,
            "slot_scope": "current-reconciled-list",
            "identifiers_redacted": True,
        },
        "resolved_slot_match_post_attestation": {
            "schema_version": 1,
            "identity_state_unchanged": True,
            "local_components_unchanged": True,
            "per_user_inventory_unchanged": True,
            "global_inventory_unchanged": True,
            "identifiers_redacted": True,
        },
        "match_events": [event],
    }


class IdentifyFingerCommandTests(unittest.TestCase):
    def test_positive_returns_only_ephemeral_slot(self):
        result = MODULE.parse_probe_result(report(matched=True, slot=2))
        self.assertEqual(result["slot"], 2)
        self.assertTrue(result["matched"])
        self.assertFalse(result["mutation_performed"])
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn("uuid", rendered.lower())
        self.assertNotIn("finger_name", rendered)

    def test_negative_is_explicit_and_has_no_slot(self):
        result = MODULE.parse_probe_result(report(matched=False))
        self.assertFalse(result["matched"])
        self.assertNotIn("slot", result)
        self.assertFalse(result["mutation_performed"])

    def test_incomplete_ambiguous_or_out_of_range_results_fail(self):
        cases = []
        missing_post = report(matched=True, slot=1)
        del missing_post["resolved_slot_match_post_attestation"]
        cases.append(missing_post)
        duplicate = report(matched=True, slot=1)
        duplicate["match_events"].append(dict(duplicate["match_events"][0]))
        cases.append(duplicate)
        cases.append(report(matched=True, slot=3))
        ambiguous_negative = report(matched=False)
        ambiguous_negative["match_events"][0]["matched_identity_slot"] = 1
        cases.append(ambiguous_negative)
        for value in cases:
            with self.subTest(), self.assertRaises(MODULE.IdentifyFingerError):
                MODULE.parse_probe_result(value)

    def test_installer_exposes_read_only_bootstrap_helper(self):
        root = MODULE_PATH.parents[1]
        installer = root.joinpath("install.sh").read_text()
        self.assertIn(
            'src/t2-touchid-identify-finger.py" '
            "/usr/local/sbin/t2-touchid-identify-finger",
            installer,
        )
        self.assertIn(
            "t2-touchid-identify-finger", root.joinpath("uninstall.sh").read_text()
        )


if __name__ == "__main__":
    unittest.main()
