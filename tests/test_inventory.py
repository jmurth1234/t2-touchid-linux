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


class InventoryTests(unittest.TestCase):
    def test_summarizes_without_biometric_identifiers(self):
        result = MODULE.summarize_probe(
            {
                "identity_list_reply": reply(),
                "identity_record_count": 2,
                "identity_record_bytes_valid": True,
                "identity_user_field": "prefix",
                "identity_inventory_repeat_equal": True,
                "catacomb_state_repeat_equal": True,
                "sks_lock_state_repeat_equal": True,
                "catacomb_state_reply": reply(),
                "catacomb_state_words": [1, 2, 3, 4],
                "sks_lock_state_reply": reply(),
                "sks_lock_state": 0,
                "private_uuid_that_must_not_escape": "secret",
            },
            501,
        )
        self.assertEqual(result["sep_identity_count"], 2)
        self.assertTrue(result["identifiers_redacted"])
        self.assertNotIn("private_uuid_that_must_not_escape", result)

    def test_rejects_malformed_identity_records(self):
        with self.assertRaises(MODULE.InventoryError):
            MODULE.summarize_probe(
                {
                    "identity_list_reply": reply(),
                    "identity_record_count": 1,
                    "identity_record_bytes_valid": False,
                    "identity_inventory_repeat_equal": True,
                    "catacomb_state_repeat_equal": True,
                    "sks_lock_state_repeat_equal": True,
                },
                501,
            )

    def test_empty_inventory_does_not_require_layout_discriminator(self):
        result = MODULE.summarize_probe(
            {
                "identity_list_reply": reply(),
                "identity_record_count": 0,
                "identity_record_bytes_valid": True,
                "identity_inventory_repeat_equal": True,
                "catacomb_state_repeat_equal": True,
                "sks_lock_state_repeat_equal": True,
            },
            501,
        )
        self.assertEqual(result["sep_identity_count"], 0)

    def test_rejects_inventory_that_changes_between_collections(self):
        with self.assertRaises(MODULE.InventoryError):
            MODULE.summarize_probe(
                {
                    "identity_list_reply": reply(),
                    "identity_record_count": 1,
                    "identity_record_bytes_valid": True,
                    "identity_user_field": "prefix",
                    "identity_inventory_repeat_equal": False,
                    "catacomb_state_repeat_equal": True,
                    "sks_lock_state_repeat_equal": True,
                },
                501,
            )


if __name__ == "__main__":
    unittest.main()
