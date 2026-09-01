# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import os
import sys
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_mapping as mapping
import t2_user_readiness as readiness
import t2_user_reconciliation_live as live_reconciliation
import t2_recovery_anchor as recovery_anchor
from tests.test_mutation_journal import baseline


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


def selected() -> mapping.UserMapping:
    return mapping.UserMapping(
        1000,
        "a" * 64,
        501,
        identifier(1),
        identifier(2),
        "/var/lib/t2-touchid/users/1000/user.kb",
        "b" * 64,
        "password-on-demand",
        frozenset({"verify"}),
        False,
    )


def catacomb() -> dict[str, object]:
    return {
        "present": True,
        "uuid": identifier(3),
        "hash": "c" * 64,
        "user_states": [
            {"kind": "master", "user_id": None, "state": 0, "needs_save": False},
            {"kind": "user", "user_id": 501, "state": 0, "needs_save": False},
        ],
    }


class Lease:
    def __init__(self):
        self.connection_generation = identifier(10)
        self.peer_boot_uuid = identifier(11)
        self.entered = False
        self.exited = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, exception_type, exception, traceback):
        self.exited = True
        return False


class Store:
    def __init__(self, reads):
        self.reads = iter(reads)

    def read_committed_components(self):
        return next(self.reads)


class LiveUserReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.lease = Lease()
        self.alias = readiness.AliasEvidence(
            True, -501, identifier(2), 0, identifier(1)
        )
        self.observer = mock.Mock()
        self.observer.observe_alias.return_value = self.alias
        self.components = {
            "master.cat": b"master",
            "biolockout.cat": b"bio",
            "user_000001f5.cat": b"user",
        }
        self.store = Store((self.components, self.components))
        self.live = {"catacomb": catacomb()}
        self.local = SimpleNamespace(
            account_uuid=identifier(1),
            keybag_uuid=identifier(2),
        )
        self.patches = (
            mock.patch.object(
                live_reconciliation, "ROOT_UID", os.geteuid()
            ),
            mock.patch.object(
                live_reconciliation,
                "_connection_configuration",
                return_value=("host", "interface", 55000),
            ),
            mock.patch.object(
                live_reconciliation, "_open_operation_lock", return_value=7
            ),
            mock.patch.object(
                live_reconciliation.os, "close", return_value=None
            ),
            mock.patch.object(
                live_reconciliation.t2_bridge_connection.BridgeConnectionLease,
                "connect",
                return_value=self.lease,
            ),
            mock.patch.object(
                live_reconciliation.t2_aks_observer,
                "AKSAliasObserver",
                return_value=self.observer,
            ),
            mock.patch.object(
                live_reconciliation.t2_catacomb_store,
                "CatacombStore",
                return_value=self.store,
            ),
            mock.patch.object(
                live_reconciliation.t2_catacomb_codec,
                "decode_user_catacomb",
                return_value=self.local,
            ),
            mock.patch.object(
                live_reconciliation.t2_bridge_inventory,
                "collect_stable_private_inventory",
                return_value=self.live,
            ),
            mock.patch.object(
                live_reconciliation.t2_identity_inventory,
                "summarize",
                return_value={
                    "local_live_reconciled": True,
                    "identifiers_redacted": True,
                },
            ),
        )
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()

    def test_session_holds_one_generation_and_collects_private_bindings(self):
        session = live_reconciliation.LiveUserReconciliationSession()
        with session:
            persistent, alias = session.collect(
                selected(), "a" * 64, "b" * 64
            )
            public = session.public_identity_inventory(selected())
            self.assertTrue(self.lease.entered)
            self.assertFalse(self.lease.exited)
        self.assertTrue(self.lease.exited)
        self.assertEqual(persistent.linux_account_generation, "a" * 64)
        self.assertEqual(persistent.keybag_sha256, "b" * 64)
        self.assertEqual(persistent.catacomb_user_id, 501)
        self.assertEqual(persistent.account_uuid, identifier(1))
        self.assertEqual(persistent.bag_uuid, identifier(2))
        self.assertTrue(persistent.catacomb_reconciled)
        self.assertEqual(alias, self.alias)
        self.assertEqual(
            public,
            {
                "local_live_reconciled": True,
                "identifiers_redacted": True,
            },
        )
        self.observer.observe_alias.assert_called_once_with(-501)
        live_reconciliation.t2_identity_inventory.summarize.assert_called_once()

    def test_public_inventory_requires_current_exact_selected_mapping(self):
        session = live_reconciliation.LiveUserReconciliationSession()
        with session:
            with self.assertRaisesRegex(
                live_reconciliation.LiveUserReconciliationError,
                "no current",
            ):
                session.public_identity_inventory(selected())
            session.collect(selected(), "a" * 64, "b" * 64)
            changed = replace(selected(), apple_uid=502)
            with self.assertRaisesRegex(
                live_reconciliation.LiveUserReconciliationError,
                "no current",
            ):
                session.public_identity_inventory(changed)
            first = session.public_identity_inventory(selected())
            first["identifiers_redacted"] = False
            self.assertTrue(
                session.public_identity_inventory(selected())[
                    "identifiers_redacted"
                ]
            )
        with self.assertRaisesRegex(
            live_reconciliation.LiveUserReconciliationError,
            "no current",
        ):
            session.public_identity_inventory(selected())

    def test_enrollment_material_retains_exact_lease_and_private_anchor(self):
        enrollment = replace(
            selected(), capabilities=frozenset({"verify", "enroll"}), enabled=True
        )
        anchor = recovery_anchor.RecoveryAnchor(
            Path("/private/anchor.tar"),
            "recovery-anchors/anchor.tar",
            "d" * 64,
            {
                "archive_sha256": "d" * 64,
                "account_uuid": identifier(1),
                "bag_uuid": identifier(2),
            },
        )
        session = live_reconciliation.LiveUserReconciliationSession()
        with mock.patch.object(
            live_reconciliation.t2_recovery_anchor,
            "materialize",
            return_value=anchor,
        ) as materialize, session:
            with self.assertRaisesRegex(
                live_reconciliation.LiveUserReconciliationError,
                "current reconciled",
            ):
                session.prepare_enrollment_material(enrollment, identifier(30))
            session.collect(enrollment, "a" * 64, "b" * 64)
            material = session.prepare_enrollment_material(
                enrollment, identifier(30)
            )
            self.assertIs(material.lease, self.lease)
            self.assertIs(material.anchor, anchor)
            self.assertEqual(material.connection_generation, identifier(10))
            self.assertNotIn(identifier(1), repr(material))
            with self.assertRaisesRegex(
                live_reconciliation.LiveUserReconciliationError,
                "already prepared",
            ):
                session.prepare_enrollment_material(enrollment, identifier(30))
        materialize.assert_called_once()

    def test_enrollment_material_rejects_wrong_or_disabled_mapping(self):
        enrollment = replace(
            selected(), capabilities=frozenset({"verify", "enroll"}), enabled=True
        )
        session = live_reconciliation.LiveUserReconciliationSession()
        with session:
            session.collect(enrollment, "a" * 64, "b" * 64)
            wrong = replace(enrollment, apple_uid=502)
            with self.assertRaisesRegex(
                live_reconciliation.LiveUserReconciliationError,
                "current reconciled",
            ):
                session.prepare_enrollment_material(wrong, identifier(30))
            disabled = replace(enrollment, enabled=False)
            session._inventory_selected = disabled
            with self.assertRaisesRegex(
                live_reconciliation.LiveUserReconciliationError,
                "does not permit",
            ):
                session.prepare_enrollment_material(disabled, identifier(30))

    def test_post_reboot_material_is_stable_private_and_read_only(self):
        enrollment = replace(
            selected(), capabilities=frozenset({"verify", "enroll"}), enabled=True
        )
        live_reconciliation.t2_catacomb_store.CatacombStore.return_value = Store(
            (self.components,) * 4
        )
        host = {"stable": True}
        session = live_reconciliation.LiveUserReconciliationSession()
        with mock.patch.object(
            live_reconciliation.t2_enrollment_finalizer,
            "read_local_host_snapshot",
            return_value=host,
        ) as read_host, session:
            session.collect(enrollment, "a" * 64, "b" * 64)
            material = session.prepare_post_reboot_material(
                enrollment, baseline()
            )
        self.assertIs(material.host, host)
        self.assertEqual(material.live, self.live)
        self.assertEqual(material.apple_uid, 501)
        self.assertEqual(material.connection_generation, identifier(10))
        self.assertNotIn(identifier(1), repr(material))
        read_host.assert_called_once()

    def test_runtime_keybag_revalidation_binds_both_handles(self):
        enrollment = replace(
            selected(), capabilities=frozenset({"verify", "enroll"}), enabled=True
        )
        self.observer.observe_handle_uuid.return_value = enrollment.bag_uuid
        session = live_reconciliation.LiveUserReconciliationSession()
        with session:
            session.collect(enrollment, "a" * 64, "b" * 64)
            self.assertTrue(
                session.revalidate_runtime_keybag(enrollment, 42)
            )
        self.observer.observe_handle_uuid.assert_called_once_with(42)
        self.assertEqual(self.observer.observe_alias.call_count, 2)

    def test_inactive_reentered_or_generation_changed_session_fails(self):
        session = live_reconciliation.LiveUserReconciliationSession()
        with self.assertRaises(live_reconciliation.LiveUserReconciliationError):
            _generation = session.runtime_generation
        with self.assertRaises(live_reconciliation.LiveUserReconciliationError):
            session.collect(selected(), "a" * 64, "b" * 64)
        with session:
            self.assertEqual(session.runtime_generation, identifier(10))
            with self.assertRaises(live_reconciliation.LiveUserReconciliationError):
                session.__enter__()
            self.lease.connection_generation = identifier(12)
            with self.assertRaisesRegex(
                live_reconciliation.LiveUserReconciliationError,
                "generation changed",
            ):
                session.collect(selected(), "a" * 64, "b" * 64)
        with self.assertRaises(live_reconciliation.LiveUserReconciliationError):
            _generation = session.runtime_generation

    def test_local_catacomb_change_or_malformed_host_binding_fails(self):
        changed = dict(self.components)
        changed["user_000001f5.cat"] = b"changed"
        live_reconciliation.t2_catacomb_store.CatacombStore.return_value = Store(
            (self.components, changed)
        )
        session = live_reconciliation.LiveUserReconciliationSession()
        with session:
            with self.assertRaisesRegex(
                live_reconciliation.LiveUserReconciliationError,
                "local Catacomb changed",
            ):
                session.collect(selected(), "a" * 64, "b" * 64)
            with self.assertRaisesRegex(
                live_reconciliation.LiveUserReconciliationError,
                "no current",
            ):
                session.public_identity_inventory(selected())

        for account, keybag in (("x", "b" * 64), ("a" * 64, "x")):
            with self.subTest(account=account == "x"):
                fresh = live_reconciliation.LiveUserReconciliationSession()
                with fresh:
                    with self.assertRaisesRegex(
                        live_reconciliation.LiveUserReconciliationError,
                        "host binding evidence",
                    ):
                        fresh.collect(selected(), account, keybag)

    def test_second_collection_binds_the_complete_private_snapshot(self):
        live_reconciliation.t2_catacomb_store.CatacombStore.return_value = Store(
            (
                self.components,
                self.components,
                self.components,
                self.components,
            )
        )
        changed_live = {"catacomb": dict(catacomb(), hash="d" * 64)}
        collector = (
            live_reconciliation.t2_bridge_inventory.collect_stable_private_inventory
        )
        collector.side_effect = (self.live, changed_live)
        session = live_reconciliation.LiveUserReconciliationSession()
        with session:
            session.collect(selected(), "a" * 64, "b" * 64)
            with self.assertRaisesRegex(
                live_reconciliation.LiveUserReconciliationError,
                "complete live snapshot changed",
            ):
                session.collect(selected(), "a" * 64, "b" * 64)

    def test_clean_catacomb_requires_exact_unique_clean_records(self):
        base = {"catacomb": catacomb()}
        live_reconciliation._require_clean_catacomb(base, 501)
        variants = []
        missing = {"catacomb": dict(base["catacomb"])}
        missing["catacomb"]["user_states"] = []
        variants.append(missing)
        dirty = {"catacomb": dict(base["catacomb"])}
        dirty["catacomb"]["user_states"] = [
            dict(item) for item in base["catacomb"]["user_states"]
        ]
        dirty["catacomb"]["user_states"][1]["needs_save"] = True
        variants.append(dirty)
        invalid_hash = {"catacomb": dict(base["catacomb"], hash="not-a-hash")}
        variants.append(invalid_hash)
        for value in variants:
            with self.subTest(value=len(variants)):
                with self.assertRaises(
                    live_reconciliation.LiveUserReconciliationError
                ):
                    live_reconciliation._require_clean_catacomb(value, 501)

    def test_connection_configuration_is_private_unique_and_canonical(self):
        self.patches[1].stop()
        valid = (
            b"T2_TOUCHID_HOST=host\nT2_TOUCHID_INTERFACE=iface\n",
            b"55000\n",
        )
        try:
            with mock.patch.object(
                live_reconciliation, "_read_private", side_effect=valid
            ):
                self.assertEqual(
                    live_reconciliation._connection_configuration(),
                    ("host", "iface", 55000),
                )
            invalid = (
                (b"T2_TOUCHID_HOST=host\n", b"55000\n"),
                (
                    b"T2_TOUCHID_HOST=host\nT2_TOUCHID_HOST=other\n"
                    b"T2_TOUCHID_INTERFACE=iface\n",
                    b"55000\n",
                ),
                (
                    b"T2_TOUCHID_HOST=host\nT2_TOUCHID_INTERFACE=iface\n",
                    b"055000\n",
                ),
            )
            for values in invalid:
                with self.subTest(config=values[0]):
                    with mock.patch.object(
                        live_reconciliation, "_read_private", side_effect=values
                    ):
                        with self.assertRaises(
                            live_reconciliation.LiveUserReconciliationError
                        ):
                            live_reconciliation._connection_configuration()
        finally:
            self.patches[1].start()

    def test_paths_and_root_identity_are_not_caller_selectable(self):
        with self.assertRaises(live_reconciliation.LiveUserReconciliationError):
            live_reconciliation.LiveUserReconciliationSession(
                store_root=Path("/tmp/catacomb")
            )
        with mock.patch.object(
            live_reconciliation, "ROOT_UID", os.geteuid() + 1
        ):
            with self.assertRaises(live_reconciliation.LiveUserReconciliationError):
                live_reconciliation.LiveUserReconciliationSession().__enter__()


if __name__ == "__main__":
    unittest.main()
