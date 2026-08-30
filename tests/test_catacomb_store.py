# SPDX-License-Identifier: GPL-2.0-only
import os
import sys
import tempfile
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_catacomb_codec as codec
import t2_catacomb_store as store_module
from tests.test_catacomb_codec import biolockout_fixture, fixture, master_fixture


class InjectedCrash(RuntimeError):
    pass


class CatacombStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "catacomb"
        self.root.mkdir(mode=0o700)
        self.old = {
            "master.cat": master_fixture(),
            "biolockout.cat": biolockout_fixture(),
            "user_000001f5.cat": fixture(),
        }
        for name, data in self.old.items():
            (self.root / name).write_bytes(data)
            (self.root / name).chmod(0o600)
        master = codec.decode_master_catacomb(self.old["master.cat"])
        bio = codec.decode_biolockout_catacomb(self.old["biolockout.cat"])
        user = codec.decode_user_catacomb(self.old["user_000001f5.cat"], 501)
        self.new = {
            "master.cat": master.encode(
                secure_data=b"LTFC" + b"n" * 28,
                enrollment_count=3,
                current_time=710000000.0,
            ),
            "biolockout.cat": bio.encode(secure_data=b"HRLB" + b"n" * 28),
            "user_000001f5.cat": user.replace_secure_data(b"LTFC" + b"n" * 28),
        }
        self.store = store_module.CatacombStore(self.root, 501)

    def tearDown(self):
        self.temp.cleanup()

    def assert_root_is(self, expected):
        for name, data in expected.items():
            self.assertEqual((self.root / name).read_bytes(), data)

    def test_prepare_is_discarded_without_changing_root(self):
        hashes = self.store.stage(self.new)
        self.assertEqual(self.store.recover(hashes), "prepare-discarded")
        self.assert_root_is(self.old)
        self.assertFalse((self.root / "prepare").exists())

    def test_commit_promotes_all_components(self):
        hashes = self.store.stage(self.new)
        self.store.cross_commit_boundary(hashes)
        self.assert_root_is(self.new)
        self.assertFalse((self.root / "commit").exists())

    def test_crash_after_commit_rename_rolls_forward(self):
        hashes = self.store.stage(self.new)

        def crash(event):
            if event == "prepare_renamed_to_commit":
                raise InjectedCrash(event)

        with self.assertRaises(InjectedCrash):
            self.store.cross_commit_boundary(hashes, crash)
        self.assertEqual(self.store.recover(hashes), "commit-rolled-forward")
        self.assert_root_is(self.new)

    def test_crash_after_root_unlink_rolls_forward(self):
        hashes = self.store.stage(self.new)

        def crash(event):
            if event == "root_unlinked:biolockout.cat":
                raise InjectedCrash(event)

        with self.assertRaises(InjectedCrash):
            self.store.cross_commit_boundary(hashes, crash)
        self.assertFalse((self.root / "biolockout.cat").exists())
        self.assertEqual(self.store.recover(hashes), "commit-rolled-forward")
        self.assert_root_is(self.new)

    def test_crash_after_one_promotion_rolls_forward_mixed_generation(self):
        hashes = self.store.stage(self.new)

        def crash(event):
            if event == "component_promoted:biolockout.cat":
                raise InjectedCrash(event)

        with self.assertRaises(InjectedCrash):
            self.store.cross_commit_boundary(hashes, crash)
        self.assertEqual((self.root / "biolockout.cat").read_bytes(), self.new["biolockout.cat"])
        self.assertEqual(self.store.recover(hashes), "commit-rolled-forward")
        self.assert_root_is(self.new)

    def test_partial_prepare_is_preserved_when_it_cannot_match_journal(self):
        def crash(event):
            if event.startswith("component_written:"):
                raise InjectedCrash(event)

        with self.assertRaises(InjectedCrash):
            self.store.stage(self.new, crash)
        expected = {name: store_module.sha256(data) for name, data in self.new.items()}
        with self.assertRaisesRegex(store_module.CatacombStoreError, "does not match"):
            self.store.recover(expected)
        self.assertTrue((self.root / "prepare").exists())
        self.assert_root_is(self.old)

    def test_unexpected_prepare_entry_stops_recovery_without_changes(self):
        hashes = self.store.stage(self.new)
        unexpected = self.root / "prepare" / "notes.txt"
        unexpected.write_text("evidence")
        unexpected.chmod(0o600)
        with self.assertRaisesRegex(store_module.CatacombStoreError, "unexpected"):
            self.store.recover(hashes)
        self.assertTrue(unexpected.exists())
        self.assert_root_is(self.old)

    def test_symlinked_component_stops_recovery(self):
        hashes = self.store.stage(self.new)
        target = self.root / "prepare" / "master.cat"
        target.unlink()
        target.symlink_to(self.root / "master.cat")
        with self.assertRaisesRegex(store_module.CatacombStoreError, "unsafe"):
            self.store.recover(hashes)
        self.assert_root_is(self.old)


if __name__ == "__main__":
    unittest.main()
