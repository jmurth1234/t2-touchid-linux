# SPDX-License-Identifier: GPL-2.0-only
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_identity_rename_journal as rename_journal
import t2_identity_delete_journal as delete_journal
import t2_mutation_journal as mutation
import t2_mutation_registry as registry
from tests.test_mutation_journal import baseline


class MutationRegistryTests(unittest.TestCase):
    def test_baseline_only_enrollment_has_no_mutating_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "00000000-0000-0000-0000-000000000070.jsonl"
            mutation.create(
                path,
                "enroll",
                baseline(),
                operation_id="00000000-0000-0000-0000-000000000070",
            )
            entry = registry.scan(root)[0]
            self.assertEqual(entry.phase, "baseline-reconciled")
            self.assertFalse(entry.blocks_new_mutation)

    def test_routes_completed_enrollment_and_pending_rename_without_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            rename_path = root / "00000000-0000-0000-0000-000000000071.jsonl"
            operation_id, _record = mutation.create(
                rename_path,
                "rename",
                baseline(),
                operation_id="00000000-0000-0000-0000-000000000071",
            )
            target = baseline()["identity_records"][0]
            rename_journal.append_checked(
                rename_path,
                operation_id,
                "RENAME_INTENT",
                {
                    "connection_generation": baseline()["connection_generation"],
                    "user_id": 501,
                    "identity_uuid": target["uuid"],
                    "entity": target["entity"],
                    "previous_name_sha256": "1" * 64,
                    "new_name_sha256": "2" * 64,
                    "mapping_generation": baseline()["mapping_generation"],
                },
            )
            entries = registry.scan(root)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].kind, "rename")
            self.assertTrue(entries[0].blocks_new_mutation)
            self.assertNotIn("00000000-0000", repr(entries))

    def test_pending_single_delete_is_typed_and_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "00000000-0000-0000-0000-000000000072.jsonl"
            mutation.create(
                path,
                "delete-one",
                baseline(),
                operation_id="00000000-0000-0000-0000-000000000072",
            )
            entry = registry.scan(root)[0]
            self.assertEqual(entry.phase, "baseline-reconciled")
            self.assertFalse(entry.blocks_new_mutation)

            value = baseline()
            value["identity_records"].append(
                {"user_id": 501, "uuid": "00000000-0000-0000-0000-000000000002", "entity": 1}
            )
            value["capacity"]["used"] = 2
            second = root / "00000000-0000-0000-0000-000000000073.jsonl"
            operation_id, _record = mutation.create(
                second,
                "delete-one",
                value,
                operation_id="00000000-0000-0000-0000-000000000073",
            )
            target = value["identity_records"][1]
            delete_journal.append_checked(
                second,
                operation_id,
                "DELETE_INTENT",
                {
                    "connection_generation": value["connection_generation"],
                    "user_id": 501,
                    "identity_uuid": target["uuid"],
                    "entity": target["entity"],
                    "target_name_sha256": "1" * 64,
                    "request_sha256": "2" * 64,
                    "request_length": 20,
                    "survivor_snapshot_sha256": "3" * 64,
                    "survivor_count": 1,
                    "mapping_generation": value["mapping_generation"],
                },
            )
            entries = registry.scan(root)
            pending = next(item for item in entries if item.blocks_new_mutation)
            self.assertEqual(pending.phase, "delete-intent")
            self.assertTrue(pending.blocks_new_mutation)

    def test_unrouted_batch_kind_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "00000000-0000-0000-0000-000000000074.jsonl"
            mutation.create(
                path,
                "delete-batch",
                baseline(),
                operation_id="00000000-0000-0000-0000-000000000074",
            )
            entry = registry.scan(root)[0]
            self.assertEqual(entry.phase, "unrouted")
            self.assertTrue(entry.blocks_new_mutation)

    def test_rejects_unexpected_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            (root / "unexpected").write_text("bad")
            with self.assertRaises(registry.MutationRegistryError):
                registry.scan(root)


if __name__ == "__main__":
    unittest.main()
