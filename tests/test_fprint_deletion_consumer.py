# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import sys
import tempfile
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_catacomb_codec as codec
import t2_fprint_deletion_consumer as consumer
import t2_identity_delete_journal as delete_journal
import t2_identity_delete_operation as delete_operation
import t2_recovery_anchor as recovery_anchor
import t2_user_broker as broker
import t2_user_mapping as mapping
import t2_user_policy as policy
import t2_user_readiness as readiness
import t2_user_reconciliation_live as live_reconciliation
from tests.test_catacomb_codec import fixture
from tests.test_identity_inventory import live_for


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


def local_inventory():
    original = codec.decode_user_catacomb(fixture(), 501)
    renamed = codec.decode_user_catacomb(
        original.rename(
            original.identities[0].uuid,
            "right-index-finger",
        ),
        501,
    )
    return codec.decode_user_catacomb(
        renamed.add(
            identity_uuid=identifier(4),
            entity=1,
            name="left-thumb",
        ),
        501,
    )


def authority(local, *, stage="operate", dispatch=True):
    document = {
        "schema_version": 1,
        "mappings": [
            {
                "linux_uid": 1000,
                "linux_account_generation": "a" * 64,
                "apple_uid": 501,
                "account_uuid": local.account_uuid,
                "bag_uuid": local.keybag_uuid,
                "keybag_path": "/var/lib/t2-touchid/users/1000/user.kb",
                "keybag_sha256": "b" * 64,
                "unlock_mode": "host-encrypted-credential",
                "capabilities": ["identity-management", "verify"],
                "enabled": True,
            }
        ],
    }
    mapping_set = mapping.parse(json.dumps(document, sort_keys=True).encode())
    selected = mapping_set.mappings[0]
    operation_id = identifier(30)
    linux_boot_uuid = identifier(31)
    runtime_generation = identifier(32)
    operation_policy = policy.OPERATION_POLICIES["delete-one"]
    binding = policy.PolicyBinding(
        mapping_set.generation,
        selected.linux_account_generation,
        operation_id,
        linux_boot_uuid,
        runtime_generation,
        10_000,
        selected.linux_uid,
        selected.linux_uid,
        "identity-management",
        identifier(33),
        None,
    )
    decision = policy.UserPolicyDecision(
        "authorized",
        "delete-one",
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
            local.account_uuid,
            local.keybag_uuid,
            True,
        ),
        readiness.AliasEvidence(
            True, -501, local.keybag_uuid, 0, local.account_uuid
        ),
        decision,
        operation_id,
        linux_boot_uuid,
        runtime_generation,
        stage,
        lambda: dispatch,
    )


class Lease:
    connection_generation = identifier(32)


class Live:
    runtime_generation = identifier(32)

    def __init__(self, material, names=("right-index-finger", "left-thumb")):
        self.material = material
        self.names = names
        self.inventory_calls = []
        self.prepare_calls = []

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

    def prepare_deletion_material(self, selected, operation_id):
        self.prepare_calls.append((selected, operation_id))
        return self.material


class FprintDeletionConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "mutations"
        self.root.mkdir(mode=0o700)
        self.local = local_inventory()
        self.current = authority(self.local)
        self.live_private = live_for(self.local)
        self.live_private.update(
            {
                "connection_generation": identifier(32),
                "bridge_boot_uuid": identifier(40),
                "maximum_capacity": 5,
            }
        )
        self.live_private["catacomb"].update(
            {"uuid": identifier(41), "hash": "c" * 64}
        )
        host = {
            "account_uuid": self.local.account_uuid,
            "bag_uuid": self.local.keybag_uuid,
            "identity_records": [
                {
                    "user_id": item.user_id,
                    "uuid": item.uuid,
                    "entity": item.entity,
                }
                for item in self.local.identities
            ],
            "master_enrollment_count": 2,
            "host_components": [
                {
                    "name": name,
                    "sha256": character * 64,
                    "mode": 0o600,
                    "uid": 0,
                    "gid": 0,
                }
                for name, character in (
                    ("master.cat", "d"),
                    ("biolockout.cat", "e"),
                    ("user_000001f5.cat", "f"),
                )
            ],
            "archive_sha256": "9" * 64,
        }
        anchor = recovery_anchor.RecoveryAnchor(
            live_reconciliation.RECOVERY_ANCHOR_ROOT
            / f"{self.current.operation_id}.tar",
            f"recovery-anchors/{self.current.operation_id}.tar",
            "9" * 64,
            host,
        )
        self.material = live_reconciliation.DeletionMaterial(
            Lease(),
            anchor,
            self.local,
            self.live_private,
            501,
            identifier(32),
            live_reconciliation.STORE_ROOT,
        )
        self.live = Live(self.material)
        self.store = object()
        self.bridge = object()
        self.operation_calls = []
        self.persistence_calls = []
        self.final = mock.create_autospec(
            delete_journal.IdentityDeleteHistory, instance=True
        )
        self.final.phase = delete_journal.IdentityDeletePhase.RECONCILED

    def tearDown(self):
        self.temporary.cleanup()

    def operation_run(self, *arguments, **keywords):
        self.operation_calls.append((arguments, keywords))
        return delete_operation.IdentityDeleteOperationResult("sep-deleted", 0)

    def persistence_run(self, **keywords):
        self.persistence_calls.append(keywords)
        return self.final

    def make_consumer(self, **overrides):
        arguments = {
            "finger_name": "left-thumb",
            "password_fallback_verified": True,
            "mutation_root": self.root,
            "mutation_blocked": lambda _root: False,
            "store_factory": lambda _root, _uid: self.store,
            "bridge_factory": lambda *_args, **_kwargs: self.bridge,
            "operation_runner": self.operation_run,
            "persistence_runner": self.persistence_run,
            "inventory_collector": lambda *_args: self.live_private,
        }
        arguments.update(overrides)
        return consumer.DeletionConsumer(**arguments)

    def test_runs_exact_named_delete_to_reconciled_completion(self):
        value = self.make_consumer()(self.current, self.live)
        self.assertEqual(value.finger_name, "left-thumb")
        self.assertTrue(value.deleted)
        self.assertEqual(
            self.live.prepare_calls,
            [(self.current.selected, self.current.operation_id)],
        )
        operation = self.operation_calls[0][1]
        self.assertEqual(operation["plan"].name, "left-thumb")
        self.assertIs(operation["local"], self.local)
        self.assertIs(operation["bridge"], self.bridge)
        self.assertEqual(
            self.persistence_calls[0]["mapping_generation"],
            self.current.mapping_set.generation,
        )
        history = delete_journal.read(
            self.root / f"{self.current.operation_id}.jsonl"
        )
        self.assertIs(history.phase, delete_journal.IdentityDeletePhase.INTENT)
        self.assertEqual(history.target_name_sha256, mock.ANY)

    def test_rejects_blocked_incomplete_absent_or_final_inventory(self):
        blocked = self.make_consumer(mutation_blocked=lambda _root: True)
        with self.assertRaisesRegex(
            consumer.FprintDeletionConsumerError, "requires reconciliation"
        ):
            blocked(self.current, self.live)
        for names, message in (
            (("Finger 1", "left-thumb"), "require migration"),
            (("right-index-finger", "right-thumb"), "not currently enrolled"),
            (("left-thumb",), "final fingerprint"),
        ):
            current_live = Live(self.material, names)
            with self.subTest(names=names), self.assertRaisesRegex(
                consumer.FprintDeletionConsumerError, message
            ):
                self.make_consumer()(self.current, current_live)
            self.assertEqual(current_live.prepare_calls, [])

    def test_rejects_wrong_authority_generation_or_expired_dispatch(self):
        wrong = replace(
            self.current,
            decision=replace(self.current.decision, operation="rename"),
        )
        changed_live = Live(self.material)
        changed_live.runtime_generation = identifier(99)
        for current, current_live in (
            (replace(self.current, stage="activate"), self.live),
            (wrong, self.live),
            (self.current, changed_live),
        ):
            with self.subTest(stage=current.stage), self.assertRaises(
                consumer.FprintDeletionConsumerError
            ):
                self.make_consumer()(current, current_live)
        expired = authority(self.local, dispatch=False)
        with self.assertRaisesRegex(
            consumer.FprintDeletionConsumerError, "authority expired"
        ):
            self.make_consumer()(expired, self.live)
        self.assertFalse(
            (self.root / f"{expired.operation_id}.jsonl").exists()
        )

    def test_never_reports_success_for_nondelete_or_unreconciled_result(self):
        def not_deleted(*_arguments, **_keywords):
            return delete_operation.IdentityDeleteOperationResult(
                "not-deleted", -1
            )

        with self.assertRaisesRegex(
            consumer.FprintDeletionConsumerError, "did not perform"
        ):
            self.make_consumer(operation_runner=not_deleted)(
                self.current, self.live
            )
        self.assertEqual(self.persistence_calls, [])

        other = authority(self.local)
        second_root = Path(self.temporary.name) / "second-mutations"
        second_root.mkdir(mode=0o700)
        self.final.phase = delete_journal.IdentityDeletePhase.ABORTED
        with self.assertRaisesRegex(
            consumer.FprintDeletionConsumerError, "reconciled state"
        ):
            self.make_consumer(mutation_root=second_root)(other, self.live)

    def test_constructor_rejects_unsafe_or_unattested_inputs(self):
        for name, fallback in (("any", True), ("left-thumb", False)):
            with self.subTest(name=name), self.assertRaises(
                consumer.FprintDeletionConsumerError
            ):
                consumer.DeletionConsumer(name, fallback)


if __name__ == "__main__":
    unittest.main()
