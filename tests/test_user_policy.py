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
import t2_user_policy as policy
import t2_user_readiness as readiness


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


def mappings(capabilities=None):
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
                "capabilities": capabilities
                or ["enroll", "identity-management", "verify"],
                "enabled": True,
            }
        ],
    }
    return mapping.parse(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    )


def caller(**changes):
    values = {
        "linux_uid": 1000,
        "linux_account_generation": "a" * 64,
        "authenticated": True,
        "active_local_session": True,
    }
    values.update(changes)
    return policy.CallerEvidence(**values)


def request(operation="enroll", **changes):
    values = {
        "operation": operation,
        "target_linux_uid": 1000,
        "operation_id": identifier(20),
        "linux_boot_uuid": identifier(21),
        "observed_monotonic_ns": 2_000,
        "modification_allowed": True,
    }
    values.update(changes)
    return policy.OperationRequest(**values)


def grant(values, action=None, **changes):
    operation_policy = policy.OPERATION_POLICIES[values.operation]
    fields = {
        "authorization_id": identifier(30),
        "action": action or operation_policy.action,
        "caller_linux_uid": 1000,
        "linux_account_generation": "a" * 64,
        "target_linux_uid": values.target_linux_uid,
        "mapping_generation": mappings().generation,
        "operation_id": values.operation_id,
        "linux_boot_uuid": values.linux_boot_uuid,
        "issued_monotonic_ns": 1_000,
        "expires_monotonic_ns": 3_000,
        "authorized": True,
    }
    fields.update(changes)
    return policy.PolicyGrant(**fields)


def persistent(**changes):
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


def alias(lock_state=0, **changes):
    values = {
        "present": True,
        "special_alias": -501,
        "bag_uuid": identifier(2),
        "lock_state": lock_state,
        "account_uuid": identifier(1),
    }
    values.update(changes)
    return readiness.AliasEvidence(**values)


class UserPolicyTests(unittest.TestCase):
    def authorize(self, operation="enroll", **changes):
        current_request = changes.pop("request", request(operation))
        current_mappings = changes.pop("mapping_set", mappings())
        operation_grant = changes.pop(
            "operation_grant",
            grant(
                current_request,
                mapping_generation=current_mappings.generation,
            ),
        )
        return policy.authorize(
            current_mappings,
            current_request,
            changes.pop("caller", caller()),
            changes.pop("persistent", persistent()),
            changes.pop("alias", alias()),
            operation_grant,
            changes.pop("activation_grant", None),
        )

    def test_each_operation_requires_its_exact_nontransitive_action(self):
        for operation, expected in policy.OPERATION_POLICIES.items():
            with self.subTest(operation=operation):
                result = self.authorize(operation)
                self.assertEqual(result.state, "authorized")
                self.assertTrue(result.operation_permitted)
                self.assertEqual(result.policy_action, expected.action)
                self.assertEqual(result.selected_mapping.apple_uid, 501)
        enrollment = request("enroll")
        wrong = grant(
            enrollment,
            action="org.t2linux.touchid.identity-management",
        )
        result = self.authorize(request=enrollment, operation_grant=wrong)
        self.assertEqual(
            result.state, "operation-authorization-binding-mismatch"
        )
        self.assertFalse(result.operation_permitted)

    def test_cross_user_and_root_do_not_bypass_self_service(self):
        current = request(target_linux_uid=1001)
        result = self.authorize(
            request=current,
            caller=caller(linux_uid=1000),
            operation_grant=None,
        )
        self.assertEqual(result.state, "delegation-disabled")
        with self.assertRaises(policy.UserPolicyError):
            self.authorize(caller=caller(linux_uid=0))

    def test_session_mapping_capability_and_account_generation_fail_closed(self):
        cases = (
            (
                {"caller": caller(authenticated=False)},
                "caller-session-denied",
            ),
            (
                {"caller": caller(active_local_session=False)},
                "caller-session-denied",
            ),
            (
                {"mapping_set": mappings(["verify"])},
                "mapping-or-capability-denied",
            ),
            (
                {"caller": caller(linux_account_generation="c" * 64)},
                "caller-account-generation-mismatch",
            ),
        )
        for arguments, expected in cases:
            with self.subTest(expected=expected):
                result = self.authorize(**arguments)
                self.assertEqual(result.state, expected)
                self.assertFalse(result.operation_permitted)

    def test_mutations_honor_independent_modification_policy(self):
        for operation in ("enroll", "rename", "delete-one"):
            with self.subTest(operation=operation):
                current = request(operation, modification_allowed=False)
                result = self.authorize(operation, request=current)
                self.assertEqual(
                    result.state, "fingerprint-modification-disabled"
                )
                self.assertFalse(result.operation_permitted)
        current = request("verify", modification_allowed=False)
        self.assertTrue(
            self.authorize("verify", request=current).operation_permitted
        )

    def test_not_ready_target_requires_a_separate_bound_activation_grant(self):
        current = request("enroll")
        absent = readiness.AliasEvidence(False, None, None, None, None)
        missing = self.authorize(request=current, alias=absent)
        self.assertEqual(missing.state, "activation-authorization-required")
        self.assertTrue(missing.activation_required)
        self.assertFalse(missing.activation_permitted)

        activation = grant(current, action=policy.ACTIVATE_ACTION)
        allowed = self.authorize(
            request=current, alias=absent, activation_grant=activation
        )
        self.assertEqual(allowed.state, "activation-authorized")
        self.assertTrue(allowed.activation_permitted)
        self.assertFalse(allowed.operation_permitted)

        reused_operation_grant = grant(current)
        denied = self.authorize(
            request=current,
            alias=absent,
            activation_grant=reused_operation_grant,
        )
        self.assertEqual(
            denied.state, "activation-authorization-binding-mismatch"
        )

    def test_lockout_and_quarantine_never_authorize_activation(self):
        activation = grant(request(), action=policy.ACTIVATE_ACTION)
        locked_out = self.authorize(
            alias=alias(readiness.BIO_LOCKOUT),
            activation_grant=activation,
        )
        self.assertEqual(locked_out.state, "target-not-ready")
        self.assertFalse(locked_out.activation_permitted)
        quarantined = self.authorize(
            persistent=persistent(bag_uuid=identifier(9)),
            activation_grant=activation,
        )
        self.assertEqual(quarantined.state, "target-quarantined")
        self.assertTrue(quarantined.quarantine)

    def test_policy_grant_is_bound_to_operation_boot_mapping_target_and_time(self):
        current = request()
        base = grant(current)
        cases = {
            "operation": {"operation_id": identifier(99)},
            "boot": {"linux_boot_uuid": identifier(98)},
            "mapping": {"mapping_generation": "f" * 64},
            "account": {"linux_account_generation": "f" * 64},
            "target": {"target_linux_uid": 1001},
            "caller": {"caller_linux_uid": 1001},
        }
        for label, changes in cases.items():
            with self.subTest(label=label):
                wrong = policy.PolicyGrant(
                    **{**base.__dict__, **changes}
                )
                result = self.authorize(
                    request=current, operation_grant=wrong
                )
                self.assertEqual(
                    result.state, "operation-authorization-binding-mismatch"
                )
        for wrong in (
            grant(current, issued_monotonic_ns=2_001),
            grant(current, expires_monotonic_ns=1_999),
            grant(
                current,
                issued_monotonic_ns=2_000,
                expires_monotonic_ns=2_000,
            ),
            grant(
                current,
                expires_monotonic_ns=policy.MAX_POLICY_LIFETIME_NS + 1_001,
            ),
        ):
            with self.assertRaises(policy.UserPolicyError):
                self.authorize(request=current, operation_grant=wrong)

    def test_explicit_policy_denial_and_missing_grant_are_not_authority(self):
        current = request()
        missing = self.authorize(request=current, operation_grant=None)
        self.assertEqual(missing.state, "operation-authorization-required")
        denied = self.authorize(
            request=current,
            operation_grant=grant(current, authorized=False),
        )
        self.assertEqual(denied.state, "operation-policy-denied")
        self.assertFalse(denied.operation_permitted)

    def test_redacted_decision_contains_no_mapping_or_operation_identifiers(self):
        result = self.authorize()
        rendered = json.dumps(result.redacted(), sort_keys=True)
        self.assertNotIn(identifier(1), rendered)
        self.assertNotIn(identifier(2), rendered)
        self.assertNotIn(identifier(20), rendered)
        self.assertNotIn("501", rendered)
        self.assertEqual(
            result.redacted(),
            {
                "schema_version": 1,
                "state": "authorized",
                "operation": "enroll",
                "policy_action": "org.t2linux.touchid.enroll",
                "operation_permitted": True,
                "activation_required": False,
                "activation_permitted": False,
                "readiness_state": "ready",
                "quarantine": False,
                "identifiers_redacted": True,
            },
        )

    def test_downstream_binding_rejects_wrong_boot_capability_or_mode(self):
        current_mappings = mappings()
        current = request("enroll")
        operation_grant = grant(
            current, mapping_generation=current_mappings.generation
        )
        ready = policy.authorize(
            current_mappings,
            current,
            caller(),
            persistent(),
            alias(),
            operation_grant,
        )
        selected = current_mappings.resolve(1000, "enroll")
        self.assertEqual(
            policy.require_bound_authority(
                ready,
                current_mappings,
                selected,
                "enroll",
                linux_boot_uuid=current.linux_boot_uuid,
                activation=False,
            ),
            current.operation_id,
        )
        for capability, boot, activation in (
            ("verify", current.linux_boot_uuid, False),
            ("enroll", identifier(99), False),
            ("enroll", current.linux_boot_uuid, True),
        ):
            with self.subTest(capability=capability, activation=activation):
                with self.assertRaises(policy.UserPolicyError):
                    policy.require_bound_authority(
                        ready,
                        current_mappings,
                        selected,
                        capability,
                        linux_boot_uuid=boot,
                        activation=activation,
                    )

    def test_malformed_request_caller_and_grant_are_rejected(self):
        current = request()
        malformed_requests = (
            request(operation="raw-sep"),
            request(target_linux_uid=True),
            request(operation_id="not-a-uuid"),
            request(observed_monotonic_ns=True),
            request(modification_allowed=1),
        )
        for malformed in malformed_requests:
            with self.subTest(request=malformed):
                with self.assertRaises(policy.UserPolicyError):
                    policy.authorize(
                        mappings(),
                        malformed,
                        caller(),
                        persistent(),
                        alias(),
                        None,
                    )
        malformed_callers = (
            caller(linux_uid=True),
            caller(linux_account_generation="x"),
            caller(authenticated=1),
        )
        for malformed in malformed_callers:
            with self.subTest(caller=malformed):
                with self.assertRaises(policy.UserPolicyError):
                    policy.authorize(
                        mappings(),
                        current,
                        malformed,
                        persistent(),
                        alias(),
                        None,
                    )
        malformed_grant = grant(current, authorized=1)
        with self.assertRaises(policy.UserPolicyError):
            self.authorize(request=current, operation_grant=malformed_grant)


if __name__ == "__main__":
    unittest.main()
