# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import sys
import unittest
import uuid
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_mapping as mapping
import t2_user_readiness as readiness


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


def selected(*, enabled: bool = True) -> mapping.UserMapping:
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
                "capabilities": ["enroll", "verify"],
                "enabled": enabled,
            }
        ],
    }
    return mapping.parse(json.dumps(document, sort_keys=True).encode()).mappings[0]


def persistent(**changes) -> readiness.PersistentEvidence:
    values = {
        "linux_account_generation": "a" * 64,
        "keybag_sha256": "b" * 64,
        "catacomb_user_id": 501,
        "account_uuid": identifier(1),
        "bag_uuid": identifier(2),
        "catacomb_reconciled": True,
    }
    values.update(changes)
    return readiness.PersistentEvidence(**values)


def alias(lock_state: int = 0, **changes) -> readiness.AliasEvidence:
    values = {
        "present": True,
        "special_alias": -501,
        "bag_uuid": identifier(2),
        "lock_state": lock_state,
    }
    values.update(changes)
    return readiness.AliasEvidence(**values)


class UserReadinessTests(unittest.TestCase):
    def test_known_safe_informational_bits_are_match_ready(self):
        state = (
            readiness.UNLOCK_TOKEN_PRESENT
            | readiness.PASSCODE_VALIDATED
            | readiness.APPLE_PAY_TOKEN_PRESENT
        )
        result = readiness.assess(selected(), "verify", persistent(), alias(state))
        self.assertEqual(result.state, "ready")
        self.assertTrue(result.operation_permitted)
        self.assertTrue(result.match_ready)
        self.assertFalse(result.quarantine)

    def test_capability_must_be_explicit_and_enabled(self):
        denied = readiness.assess(
            selected(enabled=False), "verify", persistent(), alias()
        )
        self.assertEqual(denied.state, "capability-denied")
        denied = readiness.assess(
            selected(), "identity-management", persistent(), alias()
        )
        self.assertEqual(denied.state, "capability-denied")

    def test_any_persistent_binding_drift_quarantines(self):
        cases = {
            "linux_account_generation": "c" * 64,
            "keybag_sha256": "d" * 64,
            "catacomb_user_id": 502,
            "account_uuid": identifier(3),
            "bag_uuid": identifier(4),
            "catacomb_reconciled": False,
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                result = readiness.assess(
                    selected(), "verify", persistent(**{field: value}), alias()
                )
                self.assertEqual(result.state, "persistent-binding-mismatch")
                self.assertTrue(result.quarantine)

    def test_absent_alias_requires_activation_without_claiming_ready(self):
        result = readiness.assess(
            selected(),
            "verify",
            persistent(),
            readiness.AliasEvidence(False, None, None, None),
        )
        self.assertEqual(result.state, "alias-absent")
        self.assertEqual(result.next_step, "activate-and-reconcile-alias")
        self.assertFalse(result.match_ready)

    def test_alias_or_bag_collision_quarantines(self):
        for evidence in (
            alias(special_alias=-502),
            alias(bag_uuid=identifier(9)),
        ):
            with self.subTest(evidence=evidence):
                result = readiness.assess(
                    selected(), "verify", persistent(), evidence
                )
                self.assertEqual(result.state, "alias-binding-mismatch")
                self.assertTrue(result.quarantine)

    def test_locked_and_before_first_unlock_require_password(self):
        cases = {
            readiness.DEVICE_LOCKED: "device-locked",
            readiness.BEFORE_FIRST_UNLOCK: "before-first-unlock",
        }
        for state, expected in cases.items():
            with self.subTest(state=state):
                result = readiness.assess(
                    selected(), "verify", persistent(), alias(state)
                )
                self.assertEqual(result.state, expected)
                self.assertEqual(result.next_step, "password-unlock-required")

    def test_lockout_is_not_treated_as_an_unlock_retry(self):
        for bit in (
            readiness.PASSCODE_LOCKOUT,
            readiness.BIO_LOCKOUT,
            readiness.IDENTIFICATION_LOCKOUT,
        ):
            with self.subTest(bit=bit):
                result = readiness.assess(
                    selected(), "verify", persistent(), alias(bit)
                )
                self.assertEqual(result.state, "keybag-lockout")
                self.assertEqual(result.next_step, "password-recovery-required")

    def test_corruption_or_unknown_bits_quarantine(self):
        for state, expected in (
            (readiness.CATACOMB_CORRUPTED, "catacomb-corrupted"),
            (1 << 8, "unknown-lock-state"),
            (1 << 15, "unknown-lock-state"),
        ):
            with self.subTest(state=state):
                result = readiness.assess(
                    selected(), "verify", persistent(), alias(state)
                )
                self.assertEqual(result.state, expected)
                self.assertTrue(result.quarantine)

    def test_absent_alias_cannot_carry_stale_runtime_values(self):
        with self.assertRaisesRegex(readiness.UserReadinessError, "contradictory"):
            readiness.assess(
                selected(),
                "verify",
                persistent(),
                readiness.AliasEvidence(False, -501, None, None),
            )

    def test_redacted_result_contains_no_user_or_bag_identifier(self):
        result = readiness.assess(selected(), "verify", persistent(), alias())
        self.assertEqual(
            result.redacted(),
            {
                "schema_version": 1,
                "state": "ready",
                "next_step": "none",
                "operation_permitted": True,
                "match_ready": True,
                "quarantine": False,
                "identifiers_redacted": True,
            },
        )


if __name__ == "__main__":
    unittest.main()
