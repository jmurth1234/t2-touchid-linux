# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
SPEC = importlib.util.spec_from_file_location(
    "t2_touchid_manage_command", SOURCE / "t2-touchid-manage.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class IdentityManagementCommandTests(unittest.TestCase):
    def test_status_is_redacted_and_counts_only_rename_operations(self):
        entries = (
            SimpleNamespace(
                kind="enroll",
                phase="post-reboot-verified",
                blocks_new_mutation=False,
                post_reboot_pending=False,
            ),
            SimpleNamespace(
                kind="rename",
                phase="reconciled",
                blocks_new_mutation=True,
                post_reboot_pending=True,
            ),
        )
        with mock.patch.object(
            MODULE.t2_mutation_registry, "scan", return_value=entries
        ):
            result = MODULE.status()
        self.assertEqual(result["rename_pending_count"], 1)
        self.assertEqual(result["post_reboot_pending_count"], 1)
        self.assertEqual(result["rename_pending_phases"], {"reconciled": 1})
        self.assertTrue(result["identifiers_redacted"])
        self.assertNotIn("operation", result)

    def test_current_host_uses_immutable_backup_only_as_metadata_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            backup = Path(directory) / ("a" * 64 + ".tar.gz")
            store = mock.Mock()
            store.read_committed_components.return_value = {
                "user_000001f5.cat": b"private"
            }
            backup_host = {
                "account_uuid": "account",
                "bag_uuid": "bag",
                "archive_sha256": "a" * 64,
                "host_components": [{"private": "metadata"}],
            }
            current = {
                "account_uuid": "account",
                "bag_uuid": "bag",
            }
            with (
                mock.patch.object(MODULE, "select_backup", return_value=backup),
                mock.patch.object(
                    MODULE.t2_catacomb_local,
                    "read_backup_components",
                    return_value=(backup_host, {}),
                ),
                mock.patch.object(
                    MODULE.t2_catacomb_store,
                    "CatacombStore",
                    return_value=store,
                ),
                mock.patch.object(
                    MODULE.t2_enrollment_finalizer,
                    "read_local_host_snapshot",
                    return_value=current,
                ) as snapshot,
                mock.patch.object(
                    MODULE.t2_catacomb_codec,
                    "decode_user_catacomb",
                    return_value="decoded-local",
                ),
            ):
                _store, host, local, selected = MODULE.current_host_and_local(
                    {"apple_uid": 501}
                )
        snapshot.assert_called_once_with(
            store,
            {
                "apple_uid": 501,
                "host_components": backup_host["host_components"],
            },
        )
        self.assertEqual(host["archive_sha256"], "a" * 64)
        self.assertEqual(local, "decoded-local")
        self.assertEqual(selected, backup)

    def test_rename_refuses_dispatch_while_any_mutation_blocks(self):
        with mock.patch.object(
            MODULE.t2_mutation_registry, "blocks_new_mutation", return_value=True
        ):
            with self.assertRaisesRegex(
                MODULE.IdentityManagementError, "earlier biometric mutation"
            ):
                MODULE.run_rename({}, slot=1, new_name="New")

    def test_post_reboot_requires_exactly_one_candidate(self):
        with mock.patch.object(MODULE, "rename_journals", return_value=[]):
            with self.assertRaisesRegex(
                MODULE.IdentityManagementError, "exactly one"
            ):
                MODULE.run_post_reboot_verification({})


if __name__ == "__main__":
    unittest.main()
