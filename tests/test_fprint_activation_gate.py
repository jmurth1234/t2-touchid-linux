# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

from dataclasses import replace
import json
import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_fprint_activation_gate as gate
import t2_fprint_projection as projection
import t2_user_broker_exposure_gate as exposure_gate


def health():
    return {name: "pass" for name in gate.REQUIRED_HEALTH_CHECKS}


def projected():
    return projection.FprintProjection(
        ("left-thumb", "right-index-finger"), 2, 0, 0, True
    )


def enrollment_status():
    return {
        "schema_version": 1,
        "status_only": True,
        "unfinished_count": 0,
        "unfinished_phases": {},
        "post_reboot_pending_count": 0,
        "post_reboot_verification_candidate": False,
        "live_enrollment_blocked": False,
        "automatic_no_change_recovery_candidate": False,
        "local_transaction_pending": False,
        "local_transaction_recovery_candidate": False,
        "identifiers_redacted": True,
        "mutation_performed": False,
    }


def management_status():
    return {
        "schema_version": 1,
        "status_only": True,
        "rename_pending_count": 0,
        "rename_pending_phases": {},
        "delete_pending_count": 0,
        "delete_pending_phases": {},
        "external_reconciliation_pending_count": 0,
        "external_reconciliation_pending_phases": {},
        "post_reboot_pending_count": 0,
        "rename_recovery_candidate": False,
        "delete_recovery_candidate": False,
        "new_mutation_blocked": False,
        "identifiers_redacted": True,
    }


def exposure():
    return exposure_gate.ExposureGateResult(
        True, True, 2, True, True, True, True, True
    )


def evaluate(**overrides):
    values = {
        "health_checks": health(),
        "projection": projected(),
        "enrollment_status": enrollment_status(),
        "management_status": management_status(),
        "exposure": exposure(),
        "password_fallback_acknowledged": True,
        "worker_negative_controls_acknowledged": True,
        "installed_daemon_default_off": True,
    }
    values.update(overrides)
    return gate.evaluate(**values)


class FprintActivationGateTests(unittest.TestCase):
    def test_all_independent_controls_are_required(self):
        self.assertTrue(evaluate().ready_to_stage_research_activation)
        cases = (
            {"health_checks": {**health(), "aks-device": "fail"}},
            {
                "projection": projection.FprintProjection(
                    (), 2, 2, 0, False
                )
            },
            {
                "enrollment_status": {
                    **enrollment_status(),
                    "live_enrollment_blocked": True,
                }
            },
            {
                "management_status": {
                    **management_status(),
                    "new_mutation_blocked": True,
                }
            },
            {
                "exposure": replace(
                    exposure(), protected_mapping_enabled=False
                )
            },
            {"exposure": replace(exposure(), aks_alias_observer_valid=False)},
            {
                "exposure": replace(
                    exposure(),
                    fingerprint_survivors_acknowledged_this_boot=False,
                )
            },
            {"password_fallback_acknowledged": False},
            {"worker_negative_controls_acknowledged": False},
            {"installed_daemon_default_off": False},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                self.assertFalse(
                    evaluate(**changes).ready_to_stage_research_activation
                )

    def test_malformed_evidence_fails_closed(self):
        for changes in (
            {"health_checks": {}},
            {"projection": object()},
            {"enrollment_status": {}},
            {"management_status": {}},
            {"exposure": object()},
        ):
            with self.subTest(changes=changes):
                self.assertFalse(
                    evaluate(**changes).ready_to_stage_research_activation
                )
        with self.assertRaises(gate.FprintActivationGateError):
            evaluate(password_fallback_acknowledged=1)

    def test_public_result_is_redacted_and_cannot_claim_staging(self):
        value = evaluate().public()
        self.assertTrue(value["ready_to_stage_research_activation"])
        self.assertFalse(value["service_mutation_performed"])
        self.assertFalse(value["t2_mutation_performed"])
        rendered = json.dumps(value, sort_keys=True)
        for forbidden in (
            "apple_uid",
            "linux_uid",
            "identity_uuid",
            "account_uuid",
            "bag_uuid",
            "keybag",
        ):
            self.assertNotIn(forbidden, rendered)


if __name__ == "__main__":
    unittest.main()
