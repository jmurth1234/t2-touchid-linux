# SPDX-License-Identifier: GPL-2.0-only
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_catacomb_sync_journal as sync
import t2_mutation_journal as mutation
import t2_mutation_registry as registry
from tests.test_mutation_journal import baseline


class CatacombSyncJournalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.operation_id = "00000000-0000-0000-0000-000000000090"
        self.path = self.root / f"{self.operation_id}.jsonl"
        mutation.create(
            self.path,
            "sync-user-catacomb",
            baseline(),
            operation_id=self.operation_id,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def intent(self):
        return sync.append_checked(
            self.path,
            self.operation_id,
            "CATACOMB_SYNC_INTENT",
            {
                "connection_generation": baseline()["connection_generation"],
                "mapping_generation": baseline()["mapping_generation"],
                "descriptor_snapshot_sha256": "1" * 64,
                "initial_component_snapshot_sha256": "2" * 64,
                "initial_sep_catacomb_hash": "3" * 64,
                "identity_snapshot_sha256": "4" * 64,
            },
        )

    def test_reconciled_sync_is_terminal_and_does_not_block(self):
        self.intent()
        sync.append_checked(
            self.path,
            self.operation_id,
            "CATACOMB_SYNC_HOST_COMMITTED",
            {
                "connection_generation": baseline()["connection_generation"],
                "final_component_snapshot_sha256": "5" * 64,
                "secure_blob_snapshot_sha256": "6" * 64,
            },
        )
        final = sync.append_checked(
            self.path,
            self.operation_id,
            "CATACOMB_SYNC_RECONCILED",
            {
                "connection_generation": baseline()["connection_generation"],
                "final_component_snapshot_sha256": "5" * 64,
                "final_sep_catacomb_hash": "7" * 64,
                "identity_snapshot_sha256": "4" * 64,
                "sep_clean": True,
                "local_live_equal": True,
            },
        )
        self.assertIs(final.phase, sync.CatacombSyncPhase.RECONCILED)
        entry = registry.scan(self.root)[0]
        self.assertEqual(entry.kind, "sync-user-catacomb")
        self.assertFalse(entry.blocks_new_mutation)

    def test_ambiguity_blocks_and_malformed_proof_is_rejected(self):
        self.intent()
        final = sync.append_checked(
            self.path,
            self.operation_id,
            "CATACOMB_SYNC_OUTCOME_UNKNOWN",
            {
                "stage": "complete",
                "reason": "sync-error",
                "mutation_possible": True,
                "host_commit_possible": False,
            },
        )
        self.assertIs(final.phase, sync.CatacombSyncPhase.OUTCOME_UNKNOWN)
        self.assertTrue(registry.scan(self.root)[0].blocks_new_mutation)
        with self.assertRaises(sync.CatacombSyncJournalError):
            sync.append_checked(
                self.path,
                self.operation_id,
                "CATACOMB_SYNC_RECONCILED",
                {},
            )

    def test_pre_dispatch_abort_is_terminal(self):
        self.intent()
        final = sync.append_checked(
            self.path,
            self.operation_id,
            "CATACOMB_SYNC_ABORTED_BEFORE_DISPATCH",
            {"reason": "host-store-unavailable", "mutation_possible": False},
        )
        self.assertIs(final.phase, sync.CatacombSyncPhase.ABORTED)
        self.assertFalse(registry.scan(self.root)[0].blocks_new_mutation)

    def _ambiguous_after_host_commit(self):
        self.intent()
        sync.append_checked(
            self.path,
            self.operation_id,
            "CATACOMB_SYNC_HOST_COMMITTED",
            {
                "connection_generation": baseline()["connection_generation"],
                "final_component_snapshot_sha256": "5" * 64,
                "secure_blob_snapshot_sha256": "6" * 64,
            },
        )
        return sync.append_checked(
            self.path,
            self.operation_id,
            "CATACOMB_SYNC_OUTCOME_UNKNOWN",
            {
                "stage": "final-confirm",
                "reason": "sync-error",
                "mutation_possible": True,
                "host_commit_possible": True,
            },
        )

    def test_fresh_recovery_can_reconcile_an_already_clean_sep(self):
        ambiguous = self._ambiguous_after_host_commit()
        final = sync.append_checked(
            self.path,
            self.operation_id,
            "CATACOMB_SYNC_RECOVERED_CLEAN",
            {
                "connection_generation": "00000000-0000-0000-0000-000000000099",
                "final_component_snapshot_sha256": "5" * 64,
                "identity_snapshot_sha256": "4" * 64,
                "final_sep_catacomb_hash": "7" * 64,
                "sep_clean": True,
                "local_live_equal": True,
            },
        )
        self.assertIsNotNone(ambiguous.host_commit)
        self.assertIs(final.phase, sync.CatacombSyncPhase.RECONCILED)
        self.assertTrue(final.recovery_attempted)
        self.assertFalse(registry.scan(self.root)[0].blocks_new_mutation)

    def test_one_fresh_dirty_recovery_can_complete_the_same_journal(self):
        self._ambiguous_after_host_commit()
        recovery_generation = "00000000-0000-0000-0000-000000000099"
        sync.append_checked(
            self.path,
            self.operation_id,
            "CATACOMB_SYNC_RECOVERY_INTENT",
            {
                "connection_generation": recovery_generation,
                "mapping_generation": baseline()["mapping_generation"],
                "descriptor_snapshot_sha256": "1" * 64,
                "initial_component_snapshot_sha256": "5" * 64,
                "initial_sep_catacomb_hash": "8" * 64,
                "identity_snapshot_sha256": "4" * 64,
                "prior_final_component_snapshot_sha256": "5" * 64,
            },
        )
        sync.append_checked(
            self.path,
            self.operation_id,
            "CATACOMB_SYNC_HOST_COMMITTED",
            {
                "connection_generation": recovery_generation,
                "final_component_snapshot_sha256": "9" * 64,
                "secure_blob_snapshot_sha256": "a" * 64,
            },
        )
        final = sync.append_checked(
            self.path,
            self.operation_id,
            "CATACOMB_SYNC_RECONCILED",
            {
                "connection_generation": recovery_generation,
                "final_component_snapshot_sha256": "9" * 64,
                "final_sep_catacomb_hash": "b" * 64,
                "identity_snapshot_sha256": "4" * 64,
                "sep_clean": True,
                "local_live_equal": True,
            },
        )
        self.assertIs(final.phase, sync.CatacombSyncPhase.RECONCILED)
        self.assertTrue(final.recovery_attempted)


if __name__ == "__main__":
    unittest.main()
