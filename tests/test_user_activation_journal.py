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
import t2_user_activation_journal as activation
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


def persistent() -> readiness.PersistentEvidence:
    return readiness.PersistentEvidence(
        "a" * 64,
        "b" * 64,
        501,
        identifier(1),
        identifier(2),
        True,
    )


class UserActivationJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "activation.jsonl"
        self.mapping_set, self.selected = mapped()
        self.boot = identifier(10)
        self.runtime = identifier(11)

    def tearDown(self):
        self.temp.cleanup()

    def create(self, alias: readiness.AliasEvidence) -> activation.UserActivationHistory:
        return activation.create(
            self.path,
            self.mapping_set,
            self.selected,
            "verify",
            persistent(),
            alias,
            linux_boot_uuid=self.boot,
            runtime_generation=self.runtime,
        )

    def append(self, milestone: str, evidence: dict[str, object]):
        history = activation.read(self.path)
        return activation.append_checked(
            self.path, history.operation_id, milestone, evidence
        )

    def test_absent_alias_reaches_ready_only_through_all_observations(self):
        history = self.create(readiness.AliasEvidence(False, None, None, None))
        self.assertEqual(history.phase, activation.UserActivationPhase.BASELINE)
        self.append(
            "USER_KEYBAG_LOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "keybag_sha256": "b" * 64,
                "mutation_possible": True,
            },
        )
        self.append(
            "USER_KEYBAG_HANDLE_OBSERVED",
            {
                "runtime_generation": self.runtime,
                "handle": 7,
                "bag_uuid_matches": True,
            },
        )
        self.append(
            "USER_ALIAS_BIND_INTENT",
            {
                "runtime_generation": self.runtime,
                "handle": 7,
                "special_alias": -501,
                "mutation_possible": True,
            },
        )
        self.append(
            "USER_ALIAS_OBSERVED",
            {
                "runtime_generation": self.runtime,
                "special_alias": -501,
                "bag_uuid_matches": True,
                "command_status": 0,
                "command_raised": False,
            },
        )
        self.append(
            "USER_ALIAS_UNLOCK_INTENT",
            {
                "runtime_generation": self.runtime,
                "special_alias": -501,
                "mutation_possible": True,
            },
        )
        history = self.append(
            "USER_ACTIVATION_READY",
            {
                "runtime_generation": self.runtime,
                "special_alias": -501,
                "bag_uuid_matches": True,
                "readiness_state": "ready",
                "source": "unlock-readback",
                "command_status": 0,
                "command_raised": False,
            },
        )
        self.assertEqual(history.phase, activation.UserActivationPhase.READY)
        self.assertEqual(history.temporary_handle, 7)

    def test_preexisting_locked_alias_skips_load_and_bind(self):
        self.create(readiness.AliasEvidence(True, -501, identifier(2), 1))
        self.append(
            "USER_ALIAS_UNLOCK_INTENT",
            {
                "runtime_generation": self.runtime,
                "special_alias": -501,
                "mutation_possible": True,
            },
        )
        history = self.append(
            "USER_ACTIVATION_READY",
            {
                "runtime_generation": self.runtime,
                "special_alias": -501,
                "bag_uuid_matches": True,
                "readiness_state": "ready",
                "source": "unlock-readback",
                "command_status": None,
                "command_raised": True,
            },
        )
        self.assertEqual(history.phase, activation.UserActivationPhase.READY)
        self.assertIsNone(history.temporary_handle)

    def test_outcome_unknown_is_terminal_and_records_no_secret(self):
        history = self.create(readiness.AliasEvidence(False, None, None, None))
        self.append(
            "USER_KEYBAG_LOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "keybag_sha256": "b" * 64,
                "mutation_possible": True,
            },
        )
        history = self.append(
            "USER_ACTIVATION_OUTCOME_UNKNOWN",
            {
                "runtime_generation": self.runtime,
                "stage": "load",
                "reason": "transport-error",
                "mutation_possible": True,
            },
        )
        self.assertEqual(history.phase, activation.UserActivationPhase.OUTCOME_UNKNOWN)
        with self.assertRaises(activation.UserActivationJournalError):
            activation.append_checked(
                self.path,
                history.operation_id,
                "USER_KEYBAG_HANDLE_OBSERVED",
                {
                    "runtime_generation": self.runtime,
                    "handle": 7,
                    "bag_uuid_matches": True,
                },
            )
        self.assertNotIn("password", self.path.read_text())

    def test_create_rejects_ready_denied_or_quarantined_mapping(self):
        aliases = (
            readiness.AliasEvidence(True, -501, identifier(2), 0),
            readiness.AliasEvidence(True, -502, identifier(2), 0),
        )
        for alias in aliases:
            with self.subTest(alias=alias):
                with self.assertRaisesRegex(
                    activation.UserActivationJournalError, "not safely actionable"
                ):
                    activation.create(
                        self.path,
                        self.mapping_set,
                        self.selected,
                        "verify",
                        persistent(),
                        alias,
                        linux_boot_uuid=self.boot,
                        runtime_generation=self.runtime,
                    )

    def test_wrong_handle_or_generation_cannot_advance(self):
        history = self.create(readiness.AliasEvidence(False, None, None, None))
        self.append(
            "USER_KEYBAG_LOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "keybag_sha256": "b" * 64,
                "mutation_possible": True,
            },
        )
        with self.assertRaises(activation.UserActivationJournalError):
            activation.append_checked(
                self.path,
                history.operation_id,
                "USER_KEYBAG_HANDLE_OBSERVED",
                {
                    "runtime_generation": identifier(99),
                    "handle": 7,
                    "bag_uuid_matches": True,
                },
            )

    def test_terminal_stage_must_match_current_phase(self):
        history = self.create(readiness.AliasEvidence(False, None, None, None))
        self.append(
            "USER_KEYBAG_LOAD_INTENT",
            {
                "runtime_generation": self.runtime,
                "keybag_sha256": "b" * 64,
                "mutation_possible": True,
            },
        )
        with self.assertRaisesRegex(
            activation.UserActivationJournalError, "stop evidence"
        ):
            activation.append_checked(
                self.path,
                history.operation_id,
                "USER_ACTIVATION_OUTCOME_UNKNOWN",
                {
                    "runtime_generation": self.runtime,
                    "stage": "unlock",
                    "reason": "impossible-stage",
                    "mutation_possible": True,
                },
            )


if __name__ == "__main__":
    unittest.main()
