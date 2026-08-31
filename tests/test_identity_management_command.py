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

    def test_status_counts_delete_and_rename_post_reboot_work(self):
        entries = (
            SimpleNamespace(
                kind="rename",
                phase="reconciled",
                blocks_new_mutation=True,
                post_reboot_pending=True,
            ),
            SimpleNamespace(
                kind="delete-one",
                phase="outcome-unknown",
                blocks_new_mutation=True,
                post_reboot_pending=False,
            ),
        )
        with mock.patch.object(
            MODULE.t2_mutation_registry, "scan", return_value=entries
        ):
            result = MODULE.status()
        self.assertEqual(result["delete_pending_count"], 1)
        self.assertEqual(
            result["delete_pending_phases"], {"outcome-unknown": 1}
        )
        self.assertEqual(result["post_reboot_pending_count"], 1)
        self.assertFalse(result["rename_recovery_candidate"])
        self.assertFalse(result["delete_recovery_candidate"])

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

    def test_delete_refuses_dispatch_while_any_mutation_blocks(self):
        with mock.patch.object(
            MODULE.t2_mutation_registry, "blocks_new_mutation", return_value=True
        ):
            with self.assertRaisesRegex(
                MODULE.IdentityManagementError, "earlier biometric mutation"
            ):
                MODULE.run_delete({}, slot=1)

    def test_delete_broker_dispatches_once_then_persists_survivors(self):
        generation = "00000000-0000-0000-0000-000000000111"
        configuration = {
            "apple_uid": 501,
            "linux_uid": 1000,
            "special_bag": -501,
            "host": "host",
            "interface": "interface",
            "mapping_generation": "a" * 64,
        }
        local = SimpleNamespace(identities=(object(), object()))
        plan = SimpleNamespace(
            identity_uuid="redacted-target",
            entity=1,
            name="Finger 2",
            request=b"x" * 20,
            survivor_snapshot_sha256="b" * 64,
        )
        baseline = {
            "identity_records": [object(), object()],
            "connection_generation": generation,
        }
        lease = SimpleNamespace(connection_generation=generation)
        lease_context = mock.MagicMock()
        lease_context.__enter__.return_value = lease
        lease_context.__exit__.return_value = False
        bridge = object()
        final = SimpleNamespace(
            phase=MODULE.t2_identity_delete_journal.IdentityDeletePhase.RECONCILED
        )
        with (
            mock.patch.object(
                MODULE.t2_mutation_registry,
                "blocks_new_mutation",
                return_value=False,
            ),
            mock.patch.object(MODULE.os.path, "lexists", return_value=False),
            mock.patch.object(MODULE, "keybag_runtime"),
            mock.patch.object(
                MODULE,
                "current_host_and_local",
                return_value=(object(), {}, local, Path("backup")),
            ),
            mock.patch.object(MODULE, "_port", return_value=55555),
            mock.patch.object(
                MODULE.t2_bridge_connection.BridgeConnectionLease,
                "connect",
                return_value=lease_context,
            ),
            mock.patch.object(
                MODULE.t2_bridge_inventory,
                "collect_stable_private_inventory",
                return_value={},
            ),
            mock.patch.object(
                MODULE.t2_identity_delete, "plan", return_value=plan
            ),
            mock.patch.object(
                MODULE.t2_baseline, "build_baseline", return_value=baseline
            ),
            mock.patch.object(MODULE.t2_mutation_journal, "create"),
            mock.patch.object(MODULE.t2_identity_delete_journal, "append_checked"),
            mock.patch.object(
                MODULE.t2_identity_delete_bridge,
                "IdentityDeleteBridge",
                return_value=bridge,
            ) as bridge_factory,
            mock.patch.object(
                MODULE.t2_identity_delete_operation,
                "run",
                return_value=SimpleNamespace(outcome="sep-deleted"),
            ) as dispatch,
            mock.patch.object(MODULE, "_persist_delete", return_value=final) as persist,
        ):
            result = MODULE.run_delete(configuration, slot=2)
        bridge_factory.assert_called_once_with(
            lease, connection_generation=generation
        )
        self.assertIs(dispatch.call_args.kwargs["bridge"], bridge)
        persist.assert_called_once()
        self.assertTrue(result["delete_succeeded"])
        self.assertEqual(result["identity_count"], 1)

    def test_delete_preflight_resolves_target_without_creating_mutation(self):
        generation = "00000000-0000-0000-0000-000000000333"
        configuration = {
            "apple_uid": 501,
            "special_bag": -501,
            "host": "host",
            "interface": "interface",
        }
        local = SimpleNamespace(identities=(object(), object()))
        plan = SimpleNamespace(name="Linux enrolled finger")
        lease = SimpleNamespace(connection_generation=generation)
        lease_context = mock.MagicMock()
        lease_context.__enter__.return_value = lease
        lease_context.__exit__.return_value = False
        with (
            mock.patch.object(
                MODULE.t2_mutation_registry,
                "blocks_new_mutation",
                return_value=False,
            ),
            mock.patch.object(MODULE.os.path, "lexists", return_value=False),
            mock.patch.object(MODULE, "keybag_runtime"),
            mock.patch.object(
                MODULE,
                "current_host_and_local",
                return_value=(object(), {}, local, Path("backup")),
            ),
            mock.patch.object(MODULE, "_port", return_value=55555),
            mock.patch.object(
                MODULE.t2_bridge_connection.BridgeConnectionLease,
                "connect",
                return_value=lease_context,
            ),
            mock.patch.object(
                MODULE.t2_bridge_inventory,
                "collect_stable_private_inventory",
                return_value={},
            ),
            mock.patch.object(
                MODULE.t2_identity_delete, "plan", return_value=plan
            ) as planner,
            mock.patch.object(MODULE.t2_mutation_journal, "create") as create,
        ):
            result = MODULE.run_delete_preflight(configuration, slot=2)
        planner.assert_called_once_with(local, {}, slot=2)
        create.assert_not_called()
        self.assertTrue(result["delete_preflight_succeeded"])
        self.assertFalse(result["mutation_performed"])
        self.assertEqual(result["name"], "Linux enrolled finger")
        self.assertEqual(result["identity_count_after"], 1)

    def test_post_reboot_requires_exactly_one_candidate(self):
        with mock.patch.object(MODULE, "rename_journals", return_value=[]):
            with self.assertRaisesRegex(
                MODULE.IdentityManagementError, "exactly one"
            ):
                MODULE.run_post_reboot_verification({})

    def test_delete_post_reboot_requires_exactly_one_candidate(self):
        with mock.patch.object(MODULE, "delete_journals", return_value=[]):
            with self.assertRaisesRegex(
                MODULE.IdentityManagementError, "exactly one"
            ):
                MODULE.run_delete_post_reboot_verification({})

    def test_recovery_requires_exactly_one_candidate(self):
        with mock.patch.object(MODULE, "rename_journals", return_value=[]):
            with self.assertRaisesRegex(
                MODULE.IdentityManagementError, "exactly one"
            ):
                MODULE.run_recovery({})

    def test_delete_recovery_requires_exactly_one_candidate(self):
        with mock.patch.object(MODULE, "delete_journals", return_value=[]):
            with self.assertRaisesRegex(
                MODULE.IdentityManagementError, "exactly one"
            ):
                MODULE.run_delete_recovery({})

    def test_recovery_component_expectations_are_journal_bound(self):
        history = SimpleNamespace(
            persistence=SimpleNamespace(
                batch_index=0,
                batches=((('user_000001f5.cat', 'd' * 64),),),
                staged_files=(("user_000001f5.cat", "e" * 64),),
            )
        )
        names, hashes = MODULE._recovery_component_expectations(history)
        self.assertEqual(names, {"user_000001f5.cat"})
        self.assertEqual(hashes, {"user_000001f5.cat": "e" * 64})


if __name__ == "__main__":
    unittest.main()
