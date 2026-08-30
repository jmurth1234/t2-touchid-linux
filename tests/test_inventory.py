# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "src/t2-touchid-inventory.py"
SPEC = importlib.util.spec_from_file_location("t2_touchid_inventory", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def reply(status=0):
    return {"valid": True, "status": status}


def stable_probe(identity_count=2):
    return {
        "biometric_protocol_reply": reply(),
        "biometric_protocol_version": 2,
        "identity_list_reply": reply(),
        "identity_record_count": identity_count,
        "identity_record_bytes_valid": True,
        "identity_user_field": "prefix" if identity_count else None,
        "identity_inventory_repeat_equal": True,
        "global_identity_list_reply": reply(),
        "global_identity_record_bytes_valid": True,
        "global_identity_record_count": identity_count,
        "configured_identity_records_reconciled": True,
        "global_identity_inventory_repeat_equal": True,
        "identity_capacity_reply": reply(),
        "identity_free_count_reply": reply(),
        "identity_maximum_capacity": 5,
        "identity_free_count": 5 - identity_count,
        "identity_capacity_repeat_equal": True,
        "catacomb_uuid_reply": reply(),
        "catacomb_hash_reply": reply(),
        "catacomb_uuid_length_valid": True,
        "catacomb_hash_length_valid": True,
        "catacomb_component_present": bool(identity_count),
        "catacomb_component_repeat_equal": True,
        "catacomb_state_repeat_equal": True,
        "sks_lock_state_repeat_equal": True,
    }


class InventoryTests(unittest.TestCase):
    def test_summarizes_without_biometric_identifiers(self):
        probe = stable_probe()
        probe.update(
            {
                "catacomb_state_reply": reply(),
                "catacomb_state_words": [1, 2, 3, 4],
                "sks_lock_state_reply": reply(),
                "sks_lock_state": 0,
                "private_uuid_that_must_not_escape": "secret",
            }
        )
        result = MODULE.summarize_probe(probe, 501)
        self.assertEqual(result["sep_identity_count"], 2)
        self.assertTrue(result["identifiers_redacted"])
        self.assertNotIn("private_uuid_that_must_not_escape", result)

    def test_rejects_malformed_identity_records(self):
        with self.assertRaises(MODULE.InventoryError):
            probe = stable_probe(1)
            probe["identity_record_bytes_valid"] = False
            MODULE.summarize_probe(probe, 501)

    def test_empty_inventory_does_not_require_layout_discriminator(self):
        result = MODULE.summarize_probe(stable_probe(0), 501)
        self.assertEqual(result["sep_identity_count"], 0)

    def test_rejects_inventory_that_changes_between_collections(self):
        with self.assertRaises(MODULE.InventoryError):
            probe = stable_probe(1)
            probe["identity_inventory_repeat_equal"] = False
            MODULE.summarize_probe(probe, 501)


if __name__ == "__main__":
    unittest.main()
