# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import uuid
from dataclasses import replace
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_linux_account as linux_account
import t2_user_mapping as mapping
import t2_user_mapping_admin as admin
import t2_user_readiness as readiness
import t2_user_reconciliation as reconciliation


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


class Session:
    def __init__(self, evidence, *, exit_error: bool = False):
        self.evidence = list(evidence)
        self.exit_error = exit_error
        self.calls = []
        self.entered = False
        self.exited = False

    def __enter__(self):
        self.entered = True
        return self

    def __exit__(self, exception_type, exception, traceback):
        self.exited = True
        if self.exit_error:
            raise RuntimeError("operation-lock release failed")
        return False

    def collect(self, selected, account_generation, keybag_sha256):
        self.calls.append((selected, account_generation, keybag_sha256))
        if not self.evidence:
            raise AssertionError("unexpected extra live collection")
        value = self.evidence.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


class UserReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "users.json"
        self.uid = os.getuid() if os.getuid() != 0 else 1000
        self.owner_patches = (
            mock.patch.object(admin, "ROOT_UID", os.geteuid()),
            mock.patch.object(mapping, "ROOT_UID", os.geteuid()),
        )
        for patcher in self.owner_patches:
            patcher.start()
        admin.bind_disabled(
            linux_uid=self.uid,
            apple_uid=501,
            account_uuid=identifier(1),
            bag_uuid=identifier(2),
            unlock_mode="password-on-demand",
            capabilities=("enroll", "verify"),
            acknowledge_apple_authority_is_already_provisioned=True,
            path=self.path,
            account_collector=self.account(),
            keybag_reader=self.keybag,
        )

    def tearDown(self):
        for patcher in reversed(self.owner_patches):
            patcher.stop()
        self.temporary.cleanup()

    @staticmethod
    def account(generation="a" * 64):
        return lambda uid: linux_account.AccountEvidence(uid, generation)

    @staticmethod
    def keybag(_path):
        return "b" * 64

    @staticmethod
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

    @staticmethod
    def alias(**changes):
        values = {
            "present": True,
            "special_alias": -501,
            "bag_uuid": identifier(2),
            "lock_state": 0,
            "account_uuid": identifier(1),
        }
        values.update(changes)
        return readiness.AliasEvidence(**values)

    def evidence(self, *, persistent=None, alias=None):
        return (
            persistent or self.persistent(),
            alias or self.alias(),
        )

    def enable(self, session, **changes):
        values = {
            "linux_uid": self.uid,
            "acknowledge_live_apple_authority_and_enable": True,
            "live_session_factory": lambda: session,
            "path": self.path,
            "account_collector": self.account(),
            "keybag_reader": self.keybag,
        }
        values.update(changes)
        return reconciliation.enable_reconciled(**values)

    def test_two_stable_live_reads_atomically_enable_and_redact(self):
        evidence = self.evidence()
        session = Session((evidence, evidence))
        result = self.enable(session)
        selected = mapping.load(self.path).mappings[0]
        self.assertTrue(selected.enabled)
        self.assertTrue(session.entered)
        self.assertTrue(session.exited)
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(session.calls[0][0].linux_uid, self.uid)
        self.assertEqual(session.calls[0][1], "a" * 64)
        self.assertEqual(session.calls[0][2], "b" * 64)
        self.assertEqual(
            result.redacted(),
            {
                "schema_version": 1,
                "state": "mapping-enabled-after-live-reconciliation",
                "mapping_count": 1,
                "enabled_mapping_count": 1,
                "enabled_capability_count": 2,
                "host_mapping_mutated": True,
                "t2_mutation_performed": False,
                "identifiers_redacted": True,
            },
        )
        rendered = json.dumps(result.redacted(), sort_keys=True)
        for private in (identifier(1), identifier(2), str(self.uid)):
            self.assertNotIn(private, rendered)

    def test_acknowledgement_disabled_state_and_root_are_required(self):
        evidence = self.evidence()
        with self.assertRaises(reconciliation.UserReconciliationError):
            self.enable(
                Session((evidence, evidence)),
                acknowledge_live_apple_authority_and_enable=False,
            )
        with mock.patch.object(admin, "ROOT_UID", os.geteuid() + 1):
            with self.assertRaisesRegex(
                reconciliation.UserReconciliationError, "requires root"
            ):
                self.enable(Session((evidence, evidence)))
        current = mapping.load(self.path)
        self.path.write_bytes(
            mapping.serialize((replace(current.mappings[0], enabled=True),))
        )
        self.path.chmod(0o600)
        with self.assertRaisesRegex(
            reconciliation.UserReconciliationError, "already enabled"
        ):
            self.enable(Session((evidence, evidence)))

    def test_any_persistent_or_alias_binding_mismatch_preserves_disabled(self):
        cases = (
            self.evidence(
                persistent=self.persistent(
                    linux_account_generation="c" * 64
                )
            ),
            self.evidence(
                persistent=self.persistent(keybag_sha256="c" * 64)
            ),
            self.evidence(persistent=self.persistent(catacomb_user_id=502)),
            self.evidence(persistent=self.persistent(account_uuid=identifier(9))),
            self.evidence(persistent=self.persistent(bag_uuid=identifier(9))),
            self.evidence(
                persistent=self.persistent(catacomb_reconciled=False)
            ),
            self.evidence(alias=self.alias(special_alias=-502)),
            self.evidence(alias=self.alias(account_uuid=identifier(9))),
            self.evidence(alias=self.alias(bag_uuid=identifier(9))),
            self.evidence(alias=self.alias(lock_state=readiness.DEVICE_LOCKED)),
            self.evidence(alias=self.alias(lock_state=1 << 8)),
            self.evidence(
                alias=readiness.AliasEvidence(False, None, None, None, None)
            ),
        )
        before = self.path.read_bytes()
        for evidence in cases:
            with self.subTest(evidence=evidence[0].catacomb_reconciled):
                with self.assertRaises(reconciliation.UserReconciliationError):
                    self.enable(Session((evidence, evidence)))
                self.assertEqual(self.path.read_bytes(), before)

    def test_host_or_live_drift_before_publish_preserves_disabled(self):
        first = self.evidence()
        live_changed = self.evidence(alias=self.alias(lock_state=1))
        account_values = iter(
            (
                linux_account.AccountEvidence(self.uid, "a" * 64),
                linux_account.AccountEvidence(self.uid, "c" * 64),
            )
        )
        keybag_values = iter(("b" * 64, "c" * 64))
        cases = (
            {
                "session": Session((first, live_changed)),
            },
            {
                "session": Session((first, first)),
                "account_collector": lambda uid: next(account_values),
            },
            {
                "session": Session((first, first)),
                "keybag_reader": lambda path: next(keybag_values),
            },
        )
        before = self.path.read_bytes()
        for values in cases:
            session = values.pop("session")
            with self.subTest(values=tuple(values)):
                with self.assertRaises(reconciliation.UserReconciliationError):
                    self.enable(session, **values)
                self.assertEqual(self.path.read_bytes(), before)

    def test_invalid_session_evidence_or_collection_failure_is_clean(self):
        before = self.path.read_bytes()
        sessions = (
            object(),
            Session(((self.persistent(),),)),
            Session((RuntimeError("offline"),)),
        )
        for session in sessions:
            with self.subTest(session=type(session).__name__):
                with self.assertRaises(reconciliation.UserReconciliationError):
                    self.enable(session)
                self.assertEqual(self.path.read_bytes(), before)

    def test_post_publish_session_failure_reports_outcome_unknown(self):
        evidence = self.evidence()
        session = Session((evidence, evidence), exit_error=True)
        with self.assertRaisesRegex(
            reconciliation.UserReconciliationError, "outcome is unknown"
        ):
            self.enable(session)
        self.assertTrue(mapping.load(self.path).mappings[0].enabled)

    def test_publish_failure_is_never_reported_as_safe_to_retry(self):
        evidence = self.evidence()
        with mock.patch.object(
            admin,
            "_publish",
            side_effect=admin.UserMappingAdminError("storage fault"),
        ):
            with self.assertRaisesRegex(
                reconciliation.UserReconciliationError, "outcome is unknown"
            ):
                self.enable(Session((evidence, evidence)))
        self.assertFalse(mapping.load(self.path).mappings[0].enabled)


if __name__ == "__main__":
    unittest.main()
