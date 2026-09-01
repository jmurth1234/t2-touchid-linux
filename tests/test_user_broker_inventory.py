# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import sys
import unittest
import uuid
from dataclasses import replace
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_broker as broker
import t2_user_broker_inventory as inventory
import t2_user_mapping as mapping
import t2_user_policy as policy
import t2_user_readiness as readiness


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


def mapped():
    document = {
        "schema_version": 1,
        "mappings": [
            {
                "linux_uid": 1000,
                "linux_account_generation": "a" * 64,
                "apple_uid": 501,
                "account_uuid": identifier(1),
                "bag_uuid": identifier(2),
                "keybag_path": "/var/lib/t2-touchid/users/1000/user.kb",
                "keybag_sha256": "b" * 64,
                "unlock_mode": "password-on-demand",
                "capabilities": ["verify"],
                "enabled": True,
            }
        ],
    }
    result = mapping.parse(json.dumps(document, sort_keys=True).encode())
    return result, result.mappings[0]


def decision(state="authorized"):
    operation = policy.OPERATION_POLICIES["inventory"]
    authorized = state == "authorized"
    return policy.UserPolicyDecision(
        state,
        "inventory",
        operation.action,
        authorized,
        state == "activation-authorization-required",
        False,
        "ready" if authorized else "alias-absent",
        False,
        None,
        None,
    )


def summary():
    return {
        "schema_version": 1,
        "identity_count": 2,
        "identities": [
            {"slot": 1, "name": "Right index finger", "live": True},
            {"slot": 2, "name": "Linux enrolled finger", "live": True},
        ],
        "local_live_reconciled": True,
        "selection_scope": "current-reconciled-list",
        "fprintd_listing_is_compatibility_alias": True,
        "identifiers_redacted": True,
    }


class Live:
    runtime_generation = identifier(20)

    def __init__(self, value=None):
        self.value = summary() if value is None else value
        self.selected = None

    def public_identity_inventory(self, selected):
        self.selected = selected
        return self.value


def authority(current_decision=None):
    current, selected = mapped()
    return broker.BrokerAuthority(
        current,
        selected,
        readiness.PersistentEvidence(
            "a" * 64,
            "b" * 64,
            501,
            identifier(1),
            identifier(2),
            True,
        ),
        readiness.AliasEvidence(
            True, -501, identifier(2), 0, identifier(1)
        ),
        current_decision or decision(),
        identifier(30),
        identifier(21),
        identifier(20),
        "operate",
    )


class UserBrokerInventoryTests(unittest.TestCase):
    def test_parser_accepts_only_exact_redacted_current_list(self):
        parsed = inventory.parse_public_inventory(summary())
        self.assertEqual(parsed.identity_count, 2)
        self.assertEqual(parsed.public(), summary())
        self.assertEqual(parsed.identities[1].name, "Linux enrolled finger")

        variants = []
        extra = summary()
        extra["apple_uid"] = 501
        variants.append(extra)
        wrong_count = summary()
        wrong_count["identity_count"] = 1
        variants.append(wrong_count)
        wrong_slot = summary()
        wrong_slot["identities"][1]["slot"] = 3
        variants.append(wrong_slot)
        not_live = summary()
        not_live["identities"][0]["live"] = False
        variants.append(not_live)
        too_long = summary()
        too_long["identities"][0]["name"] = (
            "x" * (inventory.MAX_PUBLIC_NAME_BYTES + 1)
        )
        variants.append(too_long)
        for value in variants:
            with self.subTest(keys=tuple(value)), self.assertRaises(
                inventory.UserBrokerInventoryError
            ):
                inventory.parse_public_inventory(value)

    def test_consumer_reads_only_cached_inventory_for_exact_authority(self):
        current_authority = authority()
        live = Live()
        result = inventory._consumer(current_authority, live)
        self.assertEqual(result.public(), summary())
        self.assertEqual(live.selected, current_authority.selected)

        for invalid_authority, invalid_live in (
            (replace(current_authority, stage="activate"), Live()),
            (current_authority, replace_live_generation(Live())),
            (replace(current_authority, decision=decision("operation-policy-denied")), Live()),
        ):
            with self.subTest(stage=invalid_authority.stage), self.assertRaises(
                inventory.UserBrokerInventoryError
            ):
                inventory._consumer(invalid_authority, invalid_live)

    def test_run_joins_inventory_policy_without_activation_or_mutation(self):
        calls = []
        current_authority = authority()
        live = Live()

        def runner(connection, **arguments):
            calls.append((connection, arguments))
            value = arguments["consumer"](current_authority, live)
            return broker.BrokerResult(decision(), True, value)

        result = inventory.run(
            object(), allow_user_interaction=False, broker_runner=runner
        )
        self.assertTrue(result.consumer_invoked)
        self.assertEqual(result.inventory.identity_count, 2)
        self.assertEqual(len(calls), 1)
        arguments = calls[0][1]
        self.assertEqual(arguments["operation"], "inventory")
        self.assertFalse(arguments["modification_allowed"])
        self.assertFalse(arguments["collect_activation_authority"])
        self.assertFalse(arguments["allow_user_interaction"])
        rendered = json.dumps(result.redacted(), sort_keys=True)
        self.assertIn("Linux enrolled finger", rendered)
        for forbidden in (identifier(1), identifier(2), "apple_uid", "keybag"):
            self.assertNotIn(forbidden, rendered)

    def test_denied_or_malformed_broker_result_never_returns_inventory(self):
        denied = inventory.run(
            object(),
            allow_user_interaction=False,
            broker_runner=lambda connection, **arguments: broker.BrokerResult(
                decision("operation-policy-denied"), False, None
            ),
        )
        self.assertFalse(denied.consumer_invoked)
        self.assertIsNone(denied.inventory)
        self.assertFalse(denied.redacted()["identity_inventory_available"])

        bad_results = (
            object(),
            broker.BrokerResult(decision(), False, None),
            broker.BrokerResult(
                decision("operation-policy-denied"), False, {"private": True}
            ),
            broker.BrokerResult(decision(), True, {"untyped": True}),
        )
        for value in bad_results:
            with self.subTest(value=type(value).__name__), self.assertRaises(
                inventory.UserBrokerInventoryError
            ):
                inventory.run(
                    object(),
                    allow_user_interaction=False,
                    broker_runner=lambda connection, value=value, **arguments: value,
                )


def replace_live_generation(value):
    value.runtime_generation = identifier(99)
    return value


if __name__ == "__main__":
    unittest.main()
