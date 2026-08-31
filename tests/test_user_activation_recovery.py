# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_activation_journal as journal
import t2_user_activation_recovery as recovery
import t2_user_mapping as mapping
import t2_user_readiness as readiness


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


def mapped() -> tuple[mapping.UserMappingSet, mapping.UserMapping]:
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
                "enabled": True,
            }
        ],
    }
    result = mapping.parse(json.dumps(document, sort_keys=True).encode())
    return result, result.mappings[0]


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


class Observer:
    def __init__(self, value, generation=identifier(30)):
        self.value = value
        self.runtime_generation = generation
        self.calls = 0

    def observe_alias(self, special_alias):
        self.calls += 1
        if isinstance(self.value, BaseException):
            raise self.value
        return self.value


class UserActivationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.mapping_set, self.selected = mapped()
        self.counter = 0

    def tearDown(self):
        self.temp.cleanup()

    def unknown(self, stage: str) -> Path:
        self.counter += 1
        path = Path(self.temp.name) / f"activation-{self.counter}.jsonl"
        runtime = identifier(20)
        if stage == "unlock":
            before = readiness.AliasEvidence(True, -501, identifier(2), 1)
        else:
            before = readiness.AliasEvidence(False, None, None, None)
        history = journal.create(
            path,
            self.mapping_set,
            self.selected,
            "verify",
            persistent(),
            before,
            linux_boot_uuid=identifier(21),
            runtime_generation=runtime,
        )

        def append(milestone, evidence):
            nonlocal history
            history = journal.append_checked(
                path, history.operation_id, milestone, evidence
            )

        if stage in {"load", "bind"}:
            append(
                "USER_KEYBAG_LOAD_INTENT",
                {
                    "runtime_generation": runtime,
                    "keybag_sha256": "b" * 64,
                    "mutation_possible": True,
                },
            )
        if stage == "bind":
            append(
                "USER_KEYBAG_HANDLE_OBSERVED",
                {
                    "runtime_generation": runtime,
                    "handle": 7,
                    "bag_uuid_matches": True,
                },
            )
            append(
                "USER_ALIAS_BIND_INTENT",
                {
                    "runtime_generation": runtime,
                    "handle": 7,
                    "special_alias": -501,
                    "mutation_possible": True,
                },
            )
        if stage == "unlock":
            append(
                "USER_ALIAS_UNLOCK_INTENT",
                {
                    "runtime_generation": runtime,
                    "special_alias": -501,
                    "mutation_possible": True,
                },
            )
        append(
            "USER_ACTIVATION_OUTCOME_UNKNOWN",
            {
                "runtime_generation": runtime,
                "stage": stage,
                "reason": "synthetic-ambiguity",
                "mutation_possible": True,
            },
        )
        return path

    def test_load_stage_absence_remains_blocked_by_unknown_handle(self):
        path = self.unknown("load")
        result = recovery.recover(
            path,
            self.mapping_set,
            self.selected,
            persistent(),
            Observer(readiness.AliasEvidence(False, None, None, None)),
        )
        self.assertEqual(result.resolution, "blocked")
        self.assertFalse(result.mutation_performed)
        self.assertEqual(journal.read(path).phase, journal.UserActivationPhase.RECOVERY_BLOCKED)

    def test_load_stage_cannot_claim_an_unattributable_ready_alias(self):
        path = self.unknown("load")
        result = recovery.recover(
            path,
            self.mapping_set,
            self.selected,
            persistent(),
            Observer(readiness.AliasEvidence(True, -501, identifier(2), 0)),
        )
        self.assertEqual(result.resolution, "quarantine")
        self.assertEqual(journal.read(path).phase, journal.UserActivationPhase.QUARANTINED)

    def test_bind_stage_ready_alias_closes_as_observed_ready(self):
        path = self.unknown("bind")
        result = recovery.recover(
            path,
            self.mapping_set,
            self.selected,
            persistent(),
            Observer(readiness.AliasEvidence(True, -501, identifier(2), 0)),
        )
        self.assertEqual(result.resolution, "ready")
        self.assertEqual(journal.read(path).phase, journal.UserActivationPhase.RECOVERED_READY)

    def test_unlock_stage_locked_alias_closes_not_ready_without_retry(self):
        path = self.unknown("unlock")
        observer = Observer(readiness.AliasEvidence(True, -501, identifier(2), 1))
        result = recovery.recover(
            path, self.mapping_set, self.selected, persistent(), observer
        )
        self.assertEqual(result.resolution, "not-ready")
        self.assertEqual(observer.calls, 1)
        self.assertEqual(
            journal.read(path).phase,
            journal.UserActivationPhase.RECOVERED_NOT_READY,
        )

    def test_binding_collision_or_persistent_drift_quarantines(self):
        cases = (
            (
                persistent(),
                readiness.AliasEvidence(True, -501, identifier(9), 0),
            ),
            (
                persistent(account_uuid=identifier(9)),
                readiness.AliasEvidence(True, -501, identifier(2), 0),
            ),
        )
        for persistent_state, alias in cases:
            with self.subTest(alias=alias):
                path = self.unknown("unlock")
                result = recovery.recover(
                    path,
                    self.mapping_set,
                    self.selected,
                    persistent_state,
                    Observer(alias),
                )
                self.assertEqual(result.resolution, "quarantine")
                self.assertEqual(
                    journal.read(path).phase,
                    journal.UserActivationPhase.QUARANTINED,
                )

    def test_same_runtime_generation_and_mapping_drift_are_rejected(self):
        path = self.unknown("unlock")
        with self.assertRaisesRegex(recovery.UserActivationRecoveryError, "fresh"):
            recovery.recover(
                path,
                self.mapping_set,
                self.selected,
                persistent(),
                Observer(
                    readiness.AliasEvidence(True, -501, identifier(2), 0),
                    generation=identifier(20),
                ),
            )
        # Whitespace alone changes the protected exact-file generation while
        # leaving the parsed authority semantically identical.
        changed_set = mapping.parse(
            json.dumps(
                {
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
                            "enabled": True,
                        }
                    ],
                },
                indent=2,
            ).encode()
        )
        self.assertEqual(changed_set.mappings, self.mapping_set.mappings)
        self.assertNotEqual(changed_set.generation, self.mapping_set.generation)
        with self.assertRaisesRegex(
            recovery.UserActivationRecoveryError, "protected mapping changed"
        ):
            recovery.recover(
                path,
                changed_set,
                changed_set.mappings[0],
                persistent(),
                Observer(readiness.AliasEvidence(True, -501, identifier(2), 0)),
            )

    def test_untrustworthy_observation_leaves_journal_outcome_unknown(self):
        path = self.unknown("bind")
        with self.assertRaisesRegex(
            recovery.UserActivationRecoveryError, "trustworthy read-back"
        ):
            recovery.recover(
                path,
                self.mapping_set,
                self.selected,
                persistent(),
                Observer(OSError("offline")),
            )
        self.assertEqual(
            journal.read(path).phase,
            journal.UserActivationPhase.OUTCOME_UNKNOWN,
        )

    def test_recovery_cannot_be_replayed_after_terminal_observation(self):
        path = self.unknown("bind")
        observer = Observer(readiness.AliasEvidence(True, -501, identifier(2), 0))
        recovery.recover(
            path, self.mapping_set, self.selected, persistent(), observer
        )
        with self.assertRaisesRegex(
            recovery.UserActivationRecoveryError, "not an outcome-unknown"
        ):
            recovery.recover(
                path, self.mapping_set, self.selected, persistent(), observer
            )


if __name__ == "__main__":
    unittest.main()
