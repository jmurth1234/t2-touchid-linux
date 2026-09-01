# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_mapping_admin as admin
import t2_current_user_authority as current_authority


SPEC = importlib.util.spec_from_file_location(
    "t2_touchid_user_map_command", SOURCE / "t2-touchid-user-map.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def result(operation="status"):
    return admin.AdminResult(
        operation,
        "mapping-valid",
        1,
        0,
        None,
        None,
    )


class MappingAdminCommandTests(unittest.TestCase):
    def test_bind_derives_private_authority_and_prints_only_redacted_result(self):
        account_uuid = "00000000-0000-0000-0000-000000000001"
        bag_uuid = "00000000-0000-0000-0000-000000000002"
        authority = current_authority.CurrentAppleAuthority(
            501, account_uuid, bag_uuid, 0
        )
        expected = result("bind")
        output = io.StringIO()
        with (
            mock.patch.object(
                MODULE.t2_current_user_authority,
                "collect",
                return_value=authority,
            ) as collect,
            mock.patch.object(
                MODULE.t2_user_mapping_admin,
                "bind_disabled",
                return_value=expected,
            ) as bind,
            redirect_stdout(output),
        ):
            status = MODULE.main(
                [
                    "bind-current-disabled",
                    "--linux-uid",
                    "1000",
                    "--unlock-mode",
                    "password-on-demand",
                    "--capability",
                    "verify",
                    "--capability",
                    "enroll",
                    "--acknowledge-current-apple-authority-is-already-provisioned",
                ]
            )
        self.assertEqual(status, 0)
        collect.assert_called_once_with()
        bind.assert_called_once_with(
            linux_uid=1000,
            apple_uid=501,
            account_uuid=account_uuid,
            bag_uuid=bag_uuid,
            unlock_mode="password-on-demand",
            capabilities=("verify", "enroll"),
            acknowledge_apple_authority_is_already_provisioned=True,
        )
        rendered = output.getvalue()
        self.assertEqual(json.loads(rendered), expected.redacted())
        self.assertNotIn(account_uuid, rendered)
        self.assertNotIn(bag_uuid, rendered)
        self.assertNotIn("1000", rendered)

    def test_bind_cli_has_no_private_apple_identifier_arguments(self):
        bind = MODULE.parser()._subparsers._group_actions[0].choices[
            "bind-current-disabled"
        ]
        destinations = {action.dest for action in bind._actions}
        self.assertNotIn("apple_uid", destinations)
        self.assertNotIn("account_uuid", destinations)
        self.assertNotIn("bag_uuid", destinations)

    def test_rebind_and_status_route_without_mapping_path_override(self):
        with mock.patch.object(
            MODULE.t2_user_mapping_admin,
            "rebind_disabled",
            return_value=result("rebind"),
        ) as rebind:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    MODULE.main(
                        [
                            "rebind-disabled",
                            "--linux-uid",
                            "1000",
                            "--acknowledge-account-generation-replacement",
                        ]
                    ),
                    0,
                )
        rebind.assert_called_once_with(
            linux_uid=1000,
            acknowledge_account_generation_replacement=True,
        )

        with mock.patch.object(
            MODULE.t2_user_mapping_admin,
            "status",
            return_value=result(),
        ) as status:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(MODULE.main(["status"]), 0)
        status.assert_called_once_with(linux_uid=None)

    def test_enable_routes_only_to_the_fixed_live_reconciliation_session(self):
        expected = MODULE.t2_user_reconciliation.ReconciliationResult(
            "mapping-enabled-after-live-reconciliation",
            1,
            1,
            2,
        )
        with mock.patch.object(
            MODULE.t2_user_reconciliation,
            "enable_reconciled",
            return_value=expected,
        ) as enable:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    MODULE.main(
                        [
                            "enable-reconciled",
                            "--linux-uid",
                            "1000",
                            "--acknowledge-live-apple-aks-catacomb-"
                            "reconciliation-and-enable",
                        ]
                    ),
                    0,
                )
        enable.assert_called_once_with(
            linux_uid=1000,
            acknowledge_live_apple_authority_and_enable=True,
            live_session_factory=(
                MODULE.t2_user_reconciliation_live.LiveUserReconciliationSession
            ),
        )

    def test_disable_routes_to_immediate_admin_revocation(self):
        expected = result("disable")
        with mock.patch.object(
            MODULE.t2_user_mapping_admin,
            "disable",
            return_value=expected,
        ) as disable:
            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    MODULE.main(
                        [
                            "disable",
                            "--linux-uid",
                            "1000",
                            "--acknowledge-immediate-mapping-revocation",
                        ]
                    ),
                    0,
                )
        disable.assert_called_once_with(
            linux_uid=1000,
            acknowledge_immediate_mapping_revocation=True,
        )

    def test_admin_failure_is_clean_and_nonzero(self):
        error = io.StringIO()
        with (
            mock.patch.object(
                MODULE.t2_user_mapping_admin,
                "status",
                side_effect=admin.UserMappingAdminError("mapping unavailable"),
            ),
            redirect_stderr(error),
        ):
            self.assertEqual(MODULE.main(["status"]), 1)
        self.assertEqual(
            error.getvalue(),
            "t2-touchid-user-map: mapping unavailable\n",
        )

        with (
            mock.patch.object(
                MODULE.t2_current_user_authority,
                "collect",
                side_effect=current_authority.CurrentUserAuthorityError(
                    "authority unavailable"
                ),
            ),
            redirect_stderr(error := io.StringIO()),
        ):
            self.assertEqual(
                MODULE.main(
                    [
                        "bind-current-disabled",
                        "--linux-uid",
                        "1000",
                        "--unlock-mode",
                        "password-on-demand",
                        "--capability",
                        "verify",
                        "--acknowledge-current-apple-authority-is-already-provisioned",
                    ]
                ),
                1,
            )
        self.assertEqual(
            error.getvalue(),
            "t2-touchid-user-map: authority unavailable\n",
        )

    def test_install_and_uninstall_own_command_without_purging_by_default(self):
        command = (SOURCE / "t2-touchid-user-map.py").read_text(encoding="utf-8")
        install = (SOURCE.parent / "install.sh").read_text(encoding="utf-8")
        uninstall = (SOURCE.parent / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn('INSTALLED_SOURCE = Path("/opt/t2-touchid/src")', command)
        self.assertIn("sys.path.insert(0, str(INSTALLED_SOURCE))", command)
        self.assertIn("src/t2-touchid-user-map.py", install)
        self.assertIn("t2-touchid-user-map", uninstall)
        self.assertIn("--purge-private-data", uninstall)
        self.assertIn("Preserved config, credentials, keybags", uninstall)


if __name__ == "__main__":
    unittest.main()
