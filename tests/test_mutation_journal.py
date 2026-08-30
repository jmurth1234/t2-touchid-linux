# SPDX-License-Identifier: GPL-2.0-only
import json
import tempfile
import unittest
from pathlib import Path

from src import t2_mutation_journal as journal


def baseline():
    return {
        "baseline_version": 1,
        "caller_linux_uid": 1000,
        "target_linux_uid": 1000,
        "apple_uid": 501,
        "account_uuid": "00000000-0000-0000-0000-000000000001",
        "bag_uuid": "00000000-0000-0000-0000-000000000002",
        "transport_generation": 1,
        "bridge_boot_uuid": "00000000-0000-0000-0000-000000000003",
        "protocol_version": 2,
        "policy_decision": "authorized",
        "identity_records": [
            {
                "user_id": 501,
                "uuid": "00000000-0000-0000-0000-000000000004",
                "entity": 0,
            }
        ],
        "capacity": {"used": 1, "maximum": 5},
        "sep_catacomb": {
            "present": True,
            "uuid": "00000000-0000-0000-0000-000000000005",
            "hash": "a" * 64,
        },
        "host_components": [
            {"name": "master.cat", "sha256": "b" * 64, "mode": 0o644, "uid": 0, "gid": 0},
            {"name": "user_000001f5.cat", "sha256": "c" * 64, "mode": 0o644, "uid": 0, "gid": 0},
        ],
        "master_enrollment_count": 2,
        "mapping_generation": "d" * 64,
        "backup_references": [{"reference": "backup-1", "sha256": "e" * 64}],
        "double_collection_equal": True,
        "password_fallback_verified": True,
    }


class MutationJournalTests(unittest.TestCase):
    def test_create_and_append_form_a_valid_durable_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.jsonl"
            operation_id, first = journal.create(
                path,
                "enroll",
                baseline(),
            )
            second = journal.append(
                path,
                operation_id,
                "ENROLL_START_INTENT",
                {"authorization_digest": "b" * 64},
            )
            records = journal.validate_records(path.read_bytes().splitlines(keepends=True))
            self.assertEqual(len(records), 2)
            self.assertEqual(second["previous_hash"], first["record_hash"])
            self.assertTrue(journal.secure_regular_file(path))

    def test_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.jsonl"
            operation_id, _ = journal.create(path, "delete-one", baseline())
            records = [json.loads(line) for line in path.read_text().splitlines()]
            records[0]["evidence"]["baseline"]["apple_uid"] = 502
            path.write_text("\n".join(json.dumps(record) for record in records) + "\n")
            with self.assertRaises(journal.JournalError):
                journal.append(path, operation_id, "DELETE_INTENT", {"target": "opaque"})

    def test_rejects_secret_shaped_fields_and_raw_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.jsonl"
            with self.assertRaises(journal.JournalError):
                value = baseline()
                value["password"] = "never"
                journal.create(path, "enroll", value)
            with self.assertRaises(journal.JournalError):
                value = baseline()
                value["backup_references"][0]["opaque"] = b"never"
                journal.create(path, "enroll", value)

    def test_refuses_to_replace_existing_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.jsonl"
            journal.create(path, "recovery", baseline())
            with self.assertRaises(journal.JournalError):
                journal.create(path, "recovery", baseline())

    def test_rejects_insecure_parent_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "public"
            parent.mkdir(mode=0o755)
            with self.assertRaises(journal.JournalError):
                journal.create(parent / "journal.jsonl", "enroll", baseline())

    def test_rejects_baseline_without_double_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            value = baseline()
            value["double_collection_equal"] = False
            with self.assertRaises(journal.JournalError):
                journal.create(Path(directory) / "journal.jsonl", "enroll", value)

    def test_rejects_identity_from_another_apple_user(self):
        with tempfile.TemporaryDirectory() as directory:
            value = baseline()
            value["identity_records"][0]["user_id"] = 502
            with self.assertRaises(journal.JournalError):
                journal.create(Path(directory) / "journal.jsonl", "enroll", value)


if __name__ == "__main__":
    unittest.main()
