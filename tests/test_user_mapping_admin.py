# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import hashlib
import json
import os
import stat
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


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


class MappingAdminTests(unittest.TestCase):
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

    def bind(self, **changes):
        values = {
            "linux_uid": self.uid,
            "apple_uid": 501,
            "account_uuid": identifier(1),
            "bag_uuid": identifier(2),
            "unlock_mode": "password-on-demand",
            "capabilities": ("enroll", "identity-management", "verify"),
            "acknowledge_apple_authority_is_already_provisioned": True,
            "path": self.path,
            "account_collector": self.account(),
            "keybag_reader": self.keybag,
        }
        values.update(changes)
        return admin.bind_disabled(**values)

    def rebind(self, **changes):
        values = {
            "linux_uid": self.uid,
            "acknowledge_account_generation_replacement": True,
            "path": self.path,
            "account_collector": self.account("c" * 64),
            "keybag_reader": self.keybag,
        }
        values.update(changes)
        return admin.rebind_disabled(**values)

    def test_initial_binding_is_atomic_private_disabled_and_redacted(self):
        result = self.bind()
        info = self.path.stat(follow_symlinks=False)
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(info.st_mode & 0o777, 0o600)
        current = mapping.load(self.path)
        selected = current.mappings[0]
        self.assertEqual(selected.linux_uid, self.uid)
        self.assertEqual(selected.linux_account_generation, "a" * 64)
        self.assertFalse(selected.enabled)
        self.assertEqual(selected.capabilities, mapping.CAPABILITIES)
        self.assertEqual(
            result.redacted(),
            {
                "schema_version": 1,
                "operation": "bind",
                "state": "mapping-bound-disabled",
                "mapping_count": 1,
                "enabled_mapping_count": 0,
                "account_generation_current": True,
                "mapping_disabled": True,
                "identifiers_redacted": True,
            },
        )
        rendered = json.dumps(result.redacted(), sort_keys=True)
        for private in (identifier(1), identifier(2), str(self.uid), "a" * 64):
            self.assertNotIn(private, rendered)

    def test_binding_requires_explicit_ack_and_capabilities(self):
        for changes in (
            {"acknowledge_apple_authority_is_already_provisioned": False},
            {"acknowledge_apple_authority_is_already_provisioned": 1},
            {"capabilities": ()},
            {"capabilities": ["verify"]},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(admin.UserMappingAdminError):
                    self.bind(**changes)
                self.assertFalse(self.path.exists())

    def test_cross_mapping_authority_collision_preserves_original(self):
        self.bind()
        before = self.path.read_bytes()
        with self.assertRaises(admin.UserMappingAdminError):
            self.bind(
                linux_uid=self.uid + 1,
                apple_uid=501,
                account_uuid=identifier(3),
                bag_uuid=identifier(4),
                account_collector=self.account("d" * 64),
            )
        self.assertEqual(self.path.read_bytes(), before)

    def test_account_change_during_binding_publishes_nothing(self):
        generations = iter(("a" * 64, "c" * 64))

        def changing(uid):
            return linux_account.AccountEvidence(uid, next(generations))

        with self.assertRaisesRegex(admin.UserMappingAdminError, "changed"):
            self.bind(account_collector=changing)
        self.assertFalse(self.path.exists())
        self.assertEqual(
            sorted(item.name for item in self.root.iterdir()),
            [".users.json.lock"],
        )

    def test_keybag_change_during_binding_publishes_nothing(self):
        digests = iter(("b" * 64, "c" * 64))
        with self.assertRaisesRegex(admin.UserMappingAdminError, "keybag changed"):
            self.bind(keybag_reader=lambda path: next(digests))
        self.assertFalse(self.path.exists())

    def test_rebind_changes_only_generation_and_forces_disabled(self):
        self.bind()
        initial = mapping.load(self.path)
        original = initial.mappings[0]
        # Exercise the important case where a previous trusted reconciliation
        # had enabled the record.
        self.path.write_bytes(mapping.serialize((replace(original, enabled=True),)))
        self.path.chmod(0o600)
        result = self.rebind()
        selected = mapping.load(self.path).mappings[0]
        self.assertEqual(selected.linux_account_generation, "c" * 64)
        self.assertFalse(selected.enabled)
        self.assertEqual(
            replace(selected, linux_account_generation="a" * 64, enabled=False),
            original,
        )
        self.assertEqual(result.state, "account-rebound-disabled")
        self.assertTrue(result.mapping_disabled)

    def test_rebind_requires_ack_drift_and_exact_keybag(self):
        self.bind()
        before = self.path.read_bytes()
        cases = (
            {"acknowledge_account_generation_replacement": False},
            {"acknowledge_account_generation_replacement": 1},
            {"account_collector": self.account("a" * 64)},
            {"keybag_reader": lambda path: "f" * 64},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(admin.UserMappingAdminError):
                    self.rebind(**changes)
                self.assertEqual(self.path.read_bytes(), before)

    def test_status_distinguishes_current_changed_and_aggregate(self):
        self.bind()
        aggregate = admin.status(path=self.path)
        self.assertEqual(aggregate.state, "mapping-valid")
        self.assertIsNone(aggregate.account_generation_current)
        current = admin.status(
            linux_uid=self.uid,
            path=self.path,
            account_collector=self.account(),
        )
        changed = admin.status(
            linux_uid=self.uid,
            path=self.path,
            account_collector=self.account("c" * 64),
        )
        self.assertEqual(current.state, "account-generation-current")
        self.assertTrue(current.account_generation_current)
        self.assertEqual(changed.state, "account-generation-changed")
        self.assertFalse(changed.account_generation_current)

    def test_missing_status_is_read_only_and_creates_no_lock(self):
        with self.assertRaisesRegex(admin.UserMappingAdminError, "does not exist"):
            admin.status(path=self.path)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_status_rejects_mapping_change_during_account_collection(self):
        self.bind()
        current = mapping.load(self.path)

        def changing(uid):
            selected = replace(current.mappings[0], enabled=True)
            self.path.write_bytes(mapping.serialize((selected,)))
            self.path.chmod(0o600)
            return linux_account.AccountEvidence(uid, "a" * 64)

        with self.assertRaisesRegex(admin.UserMappingAdminError, "changed"):
            admin.status(
                linux_uid=self.uid,
                path=self.path,
                account_collector=changing,
            )

    def test_keybag_reader_hashes_stably_and_rejects_public_or_symlinked_files(self):
        path = self.root / "keybag"
        path.write_bytes(b"private keybag bytes")
        path.chmod(0o600)
        self.assertEqual(
            admin._keybag_digest(path),
            hashlib.sha256(b"private keybag bytes").hexdigest(),
        )
        path.chmod(0o644)
        with self.assertRaisesRegex(admin.UserMappingAdminError, "private"):
            admin._keybag_digest(path)
        path.chmod(0o600)
        link = self.root / "keybag-link"
        link.symlink_to(path)
        with self.assertRaises(admin.UserMappingAdminError):
            admin._keybag_digest(link)

    def test_wrong_expected_generation_cannot_replace_mapping(self):
        self.bind()
        current = mapping.load(self.path)
        directory, name = admin._open_parent(self.path)
        try:
            with self.assertRaisesRegex(admin.UserMappingAdminError, "changed"):
                admin._publish(
                    directory,
                    name,
                    current.mappings,
                    "f" * 64,
                )
        finally:
            os.close(directory)
        self.assertEqual(mapping.load(self.path), current)
        self.assertFalse(any(item.name.endswith(".tmp") for item in self.root.iterdir()))

    def test_pre_publish_failure_cleans_temporary_file(self):
        with mock.patch.object(
            admin, "_write_all", side_effect=admin.UserMappingAdminError("fault")
        ):
            with self.assertRaisesRegex(admin.UserMappingAdminError, "fault"):
                self.bind()
        self.assertFalse(self.path.exists())
        self.assertFalse(any(item.name.endswith(".tmp") for item in self.root.iterdir()))

    def test_unsafe_parent_and_non_root_fail_before_writing(self):
        with mock.patch.object(admin, "ROOT_UID", os.geteuid() + 1):
            with self.assertRaisesRegex(admin.UserMappingAdminError, "root"):
                self.bind()
        self.root.chmod(0o777)
        try:
            with self.assertRaisesRegex(admin.UserMappingAdminError, "unsafe"):
                self.bind()
        finally:
            self.root.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
