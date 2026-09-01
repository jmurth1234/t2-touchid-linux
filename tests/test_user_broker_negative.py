# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_broker_negative as negative
import t2_user_broker_protocol as protocol
import t2_user_policy as policy


def denied(state="mapping-or-capability-denied"):
    return protocol.InventoryResponse(
        state,
        policy.OPERATION_POLICIES["inventory"].action,
        False,
        False,
        False,
        None,
        False,
        False,
        None,
    )


class UserBrokerNegativeTests(unittest.TestCase):
    def test_exact_explicit_denials_prove_no_inventory_or_authority(self):
        for state in negative.DENIED_STATES:
            with self.subTest(state=state):
                result = negative.classify(denied(state))
                self.assertTrue(result.explicit_denial)
                self.assertEqual(result.outcome, state)
                public = result.public()
                self.assertFalse(public["inventory_received"])
                self.assertFalse(public["activation_authority_received"])
                self.assertFalse(public["broker_consumer_invoked"])
                self.assertTrue(public["negative_boundary_held"])

    def test_clean_close_without_response_is_a_narrow_negative_outcome(self):
        result = negative.classify(peer_closed_without_response=True)
        self.assertFalse(result.explicit_denial)
        self.assertEqual(result.outcome, "connection-closed-without-response")
        self.assertTrue(result.public()["negative_boundary_held"])

    def test_any_data_authority_or_other_state_fails(self):
        cases = (
            None,
            object(),
            denied("operation-policy-denied"),
            protocol.InventoryResponse(
                "mapping-or-capability-denied",
                policy.OPERATION_POLICIES["inventory"].action,
                False,
                True,
                False,
                "alias-absent",
                False,
                False,
                None,
            ),
        )
        for value in cases:
            with self.subTest(value=value), self.assertRaises(
                negative.UserBrokerNegativeError
            ):
                negative.classify(value)
        with self.assertRaises(negative.UserBrokerNegativeError):
            negative.classify(
                denied(), peer_closed_without_response=True
            )

    def test_public_result_is_identifier_free_and_nonmutating(self):
        rendered = json.dumps(negative.classify(denied()).public())
        for forbidden in (
            "apple_uid",
            "linux_uid",
            "uuid",
            "keybag",
            "identity",
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertIn('"t2_mutation_performed": false', rendered)


if __name__ == "__main__":
    unittest.main()
