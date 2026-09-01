# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import sys
import tempfile
import unittest
import uuid
from dataclasses import replace
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_enrollment_coordinator as coordinator
import t2_fprint_enrollment_consumer as consumer
import t2_recovery_anchor as recovery_anchor
import t2_user_broker as broker
import t2_user_mapping as mapping
import t2_user_policy as policy
import t2_user_readiness as readiness
import t2_user_reconciliation_live as live_reconciliation


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


def authority(*, stage: str = "operate") -> broker.BrokerAuthority:
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
                "unlock_mode": "host-encrypted-credential",
                "capabilities": ["enroll", "verify"],
                "enabled": True,
            }
        ],
    }
    mapping_set = mapping.parse(json.dumps(document, sort_keys=True).encode())
    selected = mapping_set.mappings[0]
    operation_id = identifier(30)
    linux_boot_uuid = identifier(31)
    runtime_generation = identifier(32)
    operation_policy = policy.OPERATION_POLICIES["enroll"]
    binding = policy.PolicyBinding(
        mapping_set.generation,
        selected.linux_account_generation,
        operation_id,
        linux_boot_uuid,
        runtime_generation,
        10_000,
        selected.linux_uid,
        selected.linux_uid,
        "enroll",
        identifier(33),
        None,
    )
    decision = policy.UserPolicyDecision(
        "authorized",
        "enroll",
        operation_policy.action,
        True,
        False,
        False,
        "ready",
        False,
        selected,
        binding,
    )
    return broker.BrokerAuthority(
        mapping_set,
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
        decision,
        operation_id,
        linux_boot_uuid,
        runtime_generation,
        stage,
        lambda: True,
    )


class Lease:
    connection_generation = identifier(32)


class Live:
    runtime_generation = identifier(32)

    def __init__(self, material, names=("right-index-finger",)):
        self.material = material
        self.names = names
        self.calls = []
        self.inventory_calls = []

    def public_identity_inventory(self, selected):
        self.inventory_calls.append(selected)
        return {
            "schema_version": 1,
            "identity_count": len(self.names),
            "identities": [
                {"slot": slot, "name": name, "live": True}
                for slot, name in enumerate(self.names, 1)
            ],
            "local_live_reconciled": True,
            "selection_scope": "current-reconciled-list",
            "fprintd_listing_is_compatibility_alias": True,
            "identifiers_redacted": True,
        }

    def prepare_enrollment_material(self, selected, operation_id):
        self.calls.append((selected, operation_id))
        return self.material


class ACM:
    def __init__(self):
        self.entered = False
        self.exited = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, exception_type, exception, traceback):
        self.exited = True
        return False


class FprintEnrollmentConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "mutations"
        self.root.mkdir(mode=0o700)
        self.current = authority()
        anchor = recovery_anchor.RecoveryAnchor(
            live_reconciliation.RECOVERY_ANCHOR_ROOT
            / f"{self.current.operation_id}.tar",
            f"recovery-anchors/{self.current.operation_id}.tar",
            "d" * 64,
            {"archive_sha256": "d" * 64},
        )
        self.material = live_reconciliation.EnrollmentMaterial(
            Lease(),
            anchor,
            501,
            identifier(32),
            Path("/var/lib/t2-touchid/catacomb"),
        )
        self.live = Live(self.material)
        self.acm = ACM()
        self.finalizer = object()
        self.coordinator_calls = []

    def tearDown(self):
        self.temporary.cleanup()

    def run_coordinator(self, **arguments):
        self.coordinator_calls.append(arguments)
        self.assertTrue(arguments["dispatch_allowed"]())
        return coordinator.EnrollmentCoordinatorResult(
            "identity-observed", True, True, True
        )

    def make_consumer(self, finger_name="left-thumb"):
        return consumer.EnrollmentConsumer(
            finger_name,
            lambda _context: None,
            lambda: False,
            lambda _transition: None,
            True,
            acm_device_factory=lambda: self.acm,
            finalizer_factory=lambda **_arguments: self.finalizer,
            coordinator=self.run_coordinator,
        )

    def test_runs_on_exact_broker_lease_anchor_and_authority(self):
        original = consumer.MUTATION_ROOT
        consumer.MUTATION_ROOT = self.root
        try:
            result = self.make_consumer()(self.current, self.live)
        finally:
            consumer.MUTATION_ROOT = original
        self.assertEqual(result.outcome, "identity-observed")
        self.assertTrue(self.acm.entered)
        self.assertTrue(self.acm.exited)
        self.assertEqual(
            self.live.calls,
            [(self.current.selected, self.current.operation_id)],
        )
        self.assertEqual(self.live.inventory_calls, [self.current.selected])
        arguments = self.coordinator_calls[0]
        self.assertIs(arguments["lease"], self.material.lease)
        self.assertIs(arguments["host_inventory"], self.material.anchor.host_inventory)
        self.assertEqual(
            arguments["journal_path"],
            self.root / f"{self.current.operation_id}.jsonl",
        )
        self.assertEqual(
            arguments["backup_reference"], self.material.anchor.reference
        )
        self.assertIs(arguments["finalizer"], self.finalizer)

    def test_rejects_noncanonical_name_or_unverified_fallback(self):
        with self.assertRaises(consumer.FprintEnrollmentConsumerError):
            self.make_consumer("Finger 1")
        with self.assertRaises(consumer.FprintEnrollmentConsumerError):
            consumer.EnrollmentConsumer(
                "left-thumb",
                lambda _context: None,
                lambda: False,
                lambda _transition: None,
                False,
            )

    def test_rejects_activation_wrong_operation_or_generation(self):
        for current, live in (
            (authority(stage="activate"), self.live),
            (
                replace(
                    self.current,
                    decision=replace(
                        self.current.decision,
                        operation="rename",
                    ),
                ),
                self.live,
            ),
            (self.current, replace_live_generation(self.live, identifier(99))),
        ):
            with self.subTest(stage=current.stage), self.assertRaises(
                consumer.FprintEnrollmentConsumerError
            ):
                self.make_consumer()(current, live)
        self.assertEqual(self.live.calls, [])

    def test_rejects_material_from_another_generation(self):
        material = replace(
            self.material, connection_generation=identifier(99)
        )
        with self.assertRaises(consumer.FprintEnrollmentConsumerError):
            self.make_consumer()(self.current, Live(material))
        self.assertEqual(self.coordinator_calls, [])

    def test_rejects_incomplete_or_duplicate_lock_held_projection(self):
        cases = (
            (("Finger 1",), "require migration"),
            (("left-thumb",), "already enrolled"),
        )
        for names, message in cases:
            current_live = Live(self.material, names)
            with self.subTest(names=names), self.assertRaisesRegex(
                consumer.FprintEnrollmentConsumerError, message
            ):
                self.make_consumer()(self.current, current_live)
            self.assertEqual(current_live.calls, [])
        self.assertEqual(self.coordinator_calls, [])

    def test_rejects_missing_or_malformed_lock_held_projection(self):
        malformed = Live(self.material)
        malformed.public_identity_inventory = lambda _selected: {}
        for current_live in (object(), malformed):
            with self.subTest(live=current_live), self.assertRaises(
                consumer.FprintEnrollmentConsumerError
            ):
                self.make_consumer()(self.current, current_live)
        self.assertEqual(self.coordinator_calls, [])

    def test_preexisting_cancel_vetoes_dispatch(self):
        observed = []

        def coordinator_run(**arguments):
            observed.append(arguments["dispatch_allowed"]())
            return coordinator.EnrollmentCoordinatorResult(
                "cancelled", True, False, True
            )

        current = consumer.EnrollmentConsumer(
            "left-thumb",
            lambda _context: None,
            lambda: True,
            lambda _transition: None,
            True,
            acm_device_factory=lambda: self.acm,
            finalizer_factory=lambda **_arguments: self.finalizer,
            coordinator=coordinator_run,
        )
        result = current(self.current, self.live)
        self.assertEqual(result.outcome, "cancelled")
        self.assertEqual(observed, [False])


def replace_live_generation(value: Live, generation: str) -> Live:
    replacement = Live(value.material)
    replacement.runtime_generation = generation
    return replacement


if __name__ == "__main__":
    unittest.main()
