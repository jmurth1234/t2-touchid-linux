# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_broker_exposure_gate as gate
import t2_user_mapping_admin as mapping_admin


def observer():
    return {
        "schema_version": 1,
        "operation_0x06_validated": True,
        "operation_0x19_validated": True,
        "stable_double_read": True,
        "queried_alias_matched": True,
        "bag_uuid_valid_and_redacted": True,
        "account_uuid_valid_and_redacted": True,
        "lock_state": 0,
        "mutation_performed": False,
        "identifiers_redacted": True,
    }


def inventory(count=2):
    identities = [
        {"slot": slot, "name": f"Finger {slot}", "live": True}
        for slot in range(1, count + 1)
    ]
    return {
        "schema_version": 1,
        "identity_count": count,
        "identities": identities,
        "local_live_reconciled": True,
        "selection_scope": "current-reconciled-list",
        "fprintd_listing_is_compatibility_alias": True,
        "identifiers_redacted": True,
    }


def mapping(enabled=1):
    return mapping_admin.AdminResult(
        "status", "mapping-valid", 1, enabled, None, None
    )


class UserBrokerExposureGateTests(unittest.TestCase):
    def evaluate(self, **overrides):
        arguments = {
            "module_build_current": True,
            "alias_observation": observer(),
            "identity_inventory": inventory(),
            "mapping_status": mapping(),
            "fingerprint_survivors_acknowledged_this_boot": True,
        }
        arguments.update(overrides)
        return gate.evaluate(**arguments)

    def test_ready_requires_all_redacted_live_evidence(self):
        result = self.evaluate()
        self.assertTrue(result.ready_for_staged_negative_test)
        self.assertEqual(result.reconciled_identity_count, 2)
        self.assertTrue(result.two_identity_minimum)
        public = result.public()
        self.assertFalse(public["broker_socket_installed"])
        self.assertFalse(public["t2_mutation_performed"])
        self.assertTrue(public["identifiers_redacted"])
        rendered = json.dumps(public, sort_keys=True)
        for forbidden in (
            "apple_uid",
            "linux_uid",
            "00000000-0000-0000-0000-000000000001",
            "keybag_path",
        ):
            self.assertNotIn(forbidden, rendered.lower())

    def test_every_gate_fails_closed(self):
        malformed_observer = observer()
        malformed_observer["unexpected"] = True
        unknown_lock_state = observer()
        unknown_lock_state["lock_state"] = 1 << 8
        malformed_inventory = inventory()
        malformed_inventory["identity_count"] = 3
        cases = (
            {"module_build_current": False},
            {"alias_observation": None},
            {"alias_observation": malformed_observer},
            {"alias_observation": unknown_lock_state},
            {"identity_inventory": inventory(1)},
            {"identity_inventory": malformed_inventory},
            {"mapping_status": None},
            {"mapping_status": mapping(0)},
            {"fingerprint_survivors_acknowledged_this_boot": False},
        )
        for overrides in cases:
            with self.subTest(overrides=tuple(overrides)):
                self.assertFalse(
                    self.evaluate(**overrides).ready_for_staged_negative_test
                )

    def test_malformed_inventory_does_not_leak_partial_count(self):
        value = inventory()
        value["identities"][0]["apple_uid"] = 501
        result = self.evaluate(identity_inventory=value)
        self.assertIsNone(result.reconciled_identity_count)
        self.assertFalse(result.two_identity_minimum)

    def test_boolean_inputs_are_exact(self):
        for field in (
            "module_build_current",
            "fingerprint_survivors_acknowledged_this_boot",
        ):
            with self.subTest(field=field), self.assertRaises(
                gate.UserBrokerExposureGateError
            ):
                self.evaluate(**{field: 1})


if __name__ == "__main__":
    unittest.main()
