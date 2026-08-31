# SPDX-License-Identifier: GPL-2.0-only
import hashlib
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_identity_delete_journal as delete_journal
import t2_mutation_journal as mutation
from tests.test_mutation_journal import baseline


def delete_baseline():
    value = baseline()
    value["identity_records"].append(
        {"user_id": value["apple_uid"], "uuid": str(uuid.UUID(int=2)), "entity": 1}
    )
    value["capacity"]["used"] = 2
    return value


class IdentityDeleteJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "delete.jsonl"
        self.value = delete_baseline()
        self.operation_id, _record = mutation.create(
            self.path, "delete-one", self.value
        )
        self.target = self.value["identity_records"][1]
        self.intent = {
            "connection_generation": self.value["connection_generation"],
            "user_id": self.value["apple_uid"],
            "identity_uuid": self.target["uuid"],
            "entity": self.target["entity"],
            "target_name_sha256": "1" * 64,
            "request_sha256": "2" * 64,
            "request_length": 20,
            "survivor_snapshot_sha256": "3" * 64,
            "survivor_count": 1,
            "mapping_generation": self.value["mapping_generation"],
        }

    def tearDown(self):
        self.temp.cleanup()

    def append(self, milestone, evidence):
        return delete_journal.append_checked(
            self.path, self.operation_id, milestone, evidence
        )

    def dispatch_and_result(self, status=0):
        self.append("DELETE_INTENT", self.intent)
        self.append(
            "DELETE_DISPATCH_INTENT",
            {
                "connection_generation": self.value["connection_generation"],
                "identity_uuid": self.target["uuid"],
                "request_sha256": self.intent["request_sha256"],
                "command": 0x0D,
                "protocol_version": 0,
            },
        )
        return self.append(
            "DELETE_COMMAND_OBSERVED",
            {
                "connection_generation": self.value["connection_generation"],
                "identity_uuid": self.target["uuid"],
                "status": status,
                "output_length": 0,
                "service_event_count": 0,
            },
        )

    def test_intent_binds_target_wire_and_survivor_set(self):
        history = self.append("DELETE_INTENT", self.intent)
        self.assertEqual(history.phase, delete_journal.IdentityDeletePhase.INTENT)
        self.assertEqual(history.target_identity_uuid, self.target["uuid"])
        invalid = dict(self.intent)
        invalid["request_length"] = 16
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.jsonl"
            operation_id, _record = mutation.create(path, "delete-one", self.value)
            with self.assertRaises(delete_journal.IdentityDeleteJournalError):
                delete_journal.append_checked(path, operation_id, "DELETE_INTENT", invalid)

    def test_command_success_requires_stable_target_absence(self):
        self.dispatch_and_result()
        history = self.append(
            "DELETE_SEP_ABSENCE_OBSERVED",
            {
                "connection_generation": self.value["connection_generation"],
                "identity_uuid": self.target["uuid"],
                "survivor_snapshot_sha256": self.intent["survivor_snapshot_sha256"],
                "survivor_count": 1,
                "stable_double_read": True,
                "per_user_global_equal": True,
                "target_absent": True,
            },
        )
        self.assertEqual(history.phase, delete_journal.IdentityDeletePhase.SEP_DELETED)

    def test_failed_command_can_close_only_with_exact_no_change_proof(self):
        self.dispatch_and_result(status=-1)
        history = self.append(
            "DELETE_NOT_PERFORMED",
            {
                "connection_generation": self.value["connection_generation"],
                "identity_uuid": self.target["uuid"],
                "command_failed": True,
                "target_present": True,
                "baseline_identity_set_equal": True,
                "sep_catacomb_unchanged": True,
                "stable_double_read": True,
            },
        )
        self.assertEqual(history.phase, delete_journal.IdentityDeletePhase.ABORTED)

    def test_success_with_present_target_cannot_claim_abort(self):
        self.dispatch_and_result(status=0)
        with self.assertRaises(delete_journal.IdentityDeleteJournalError):
            self.append(
                "DELETE_NOT_PERFORMED",
                {
                    "connection_generation": self.value["connection_generation"],
                    "identity_uuid": self.target["uuid"],
                    "command_failed": True,
                    "target_present": True,
                    "baseline_identity_set_equal": True,
                    "sep_catacomb_unchanged": True,
                    "stable_double_read": True,
                },
            )

    def test_ambiguous_dispatch_freezes(self):
        self.append("DELETE_INTENT", self.intent)
        self.append(
            "DELETE_DISPATCH_INTENT",
            {
                "connection_generation": self.value["connection_generation"],
                "identity_uuid": self.target["uuid"],
                "request_sha256": self.intent["request_sha256"],
                "command": 0x0D,
                "protocol_version": 0,
            },
        )
        history = self.append(
            "DELETE_OUTCOME_UNKNOWN",
            {
                "connection_generation": self.value["connection_generation"],
                "stage": "dispatch",
                "reason": "transport-error",
                "mutation_possible": True,
            },
        )
        self.assertEqual(history.phase, delete_journal.IdentityDeletePhase.OUTCOME_UNKNOWN)


if __name__ == "__main__":
    unittest.main()
