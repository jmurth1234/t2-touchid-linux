# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_catacomb_store
import t2_recovery_anchor
from tests.test_catacomb_codec import biolockout_fixture, fixture, master_fixture


class RecoveryAnchorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.parent = Path(self.temporary.name) / "private"
        self.parent.mkdir(mode=0o700)
        self.store_root = self.parent / "catacomb"
        self.store_root.mkdir(mode=0o700)
        self.components = {
            "master.cat": master_fixture(),
            "biolockout.cat": biolockout_fixture(),
            "user_000001f5.cat": fixture(),
        }
        for name, data in self.components.items():
            path = self.store_root / name
            path.write_bytes(data)
            path.chmod(0o600)
        self.anchor_root = self.parent / "recovery-anchors"
        self.anchor_root.mkdir(mode=0o700)
        self.store = t2_catacomb_store.CatacombStore(self.store_root, 501)
        self.operation_id = str(uuid.UUID(int=100))

    def tearDown(self):
        self.temporary.cleanup()

    def test_materializes_private_exact_idempotent_backup(self):
        first = t2_recovery_anchor.materialize(
            self.store, self.anchor_root, self.operation_id
        )
        second = t2_recovery_anchor.materialize(
            self.store, self.anchor_root, self.operation_id
        )
        self.assertEqual(first, second)
        self.assertEqual(first.reference, f"recovery-anchors/{self.operation_id}.tar")
        self.assertEqual(first.sha256, first.host_inventory["archive_sha256"])
        self.assertEqual(first.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(first.path.stat().st_nlink, 1)
        self.assertEqual(
            {item["name"]: item["mode"] for item in first.host_inventory["host_components"]},
            {name: 0o600 for name in self.components},
        )
        self.assertNotIn(str(self.store_root), repr(first))

    def test_refuses_existing_anchor_for_different_store(self):
        t2_recovery_anchor.materialize(
            self.store, self.anchor_root, self.operation_id
        )
        changed = bytearray(self.components["master.cat"])
        changed[-1] ^= 1
        (self.store_root / "master.cat").write_bytes(changed)
        (self.store_root / "master.cat").chmod(0o600)
        with self.assertRaises(
            (t2_catacomb_store.CatacombStoreError, t2_recovery_anchor.RecoveryAnchorError)
        ):
            t2_recovery_anchor.materialize(
                self.store, self.anchor_root, self.operation_id
            )

    def test_rejects_public_anchor_directory(self):
        self.anchor_root.chmod(0o755)
        with self.assertRaisesRegex(
            t2_recovery_anchor.RecoveryAnchorError, "not private"
        ):
            t2_recovery_anchor.materialize(
                self.store, self.anchor_root, self.operation_id
            )

    def test_rejects_symlink_destination_without_overwriting_target(self):
        target = self.parent / "target"
        target.write_bytes(b"untouched")
        destination = self.anchor_root / f"{self.operation_id}.tar"
        os.symlink(target, destination)
        with self.assertRaises(t2_recovery_anchor.RecoveryAnchorError):
            t2_recovery_anchor.materialize(
                self.store, self.anchor_root, self.operation_id
            )
        self.assertEqual(target.read_bytes(), b"untouched")


if __name__ == "__main__":
    unittest.main()

