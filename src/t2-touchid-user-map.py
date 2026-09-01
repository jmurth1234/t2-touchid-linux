#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Root-only administration for disabled multi-user mapping records."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
if (LOCAL_SOURCE / "t2_user_mapping.py").is_file():
    sys.path.insert(0, str(LOCAL_SOURCE))
elif INSTALLED_SOURCE.is_dir():
    sys.path.insert(0, str(INSTALLED_SOURCE))

import t2_user_mapping
import t2_user_mapping_admin
import t2_user_reconciliation
import t2_user_reconciliation_live
import t2_current_user_authority


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        prog="t2-touchid-user-map",
        description=(
            "Create or rebind disabled T2 account mappings, or enable one only "
            "after stable live reconciliation. This command never mutates the T2."
        ),
    )
    commands = value.add_subparsers(dest="command", required=True)

    bind = commands.add_parser(
        "bind-current-disabled",
        help=(
            "derive the configured Apple authority privately and add one "
            "disabled mapping"
        ),
    )
    bind.add_argument("--linux-uid", required=True, type=int)
    bind.add_argument(
        "--unlock-mode",
        required=True,
        choices=sorted(t2_user_mapping.UNLOCK_MODES),
    )
    bind.add_argument(
        "--capability",
        action="append",
        required=True,
        choices=sorted(t2_user_mapping.CAPABILITIES),
        help="repeat for every explicitly permitted future capability",
    )
    bind.add_argument(
        "--acknowledge-current-apple-authority-is-already-provisioned",
        action="store_true",
        required=True,
        help=(
            "confirm the root-derived configured Apple authority is already "
            "provisioned; the resulting mapping remains disabled"
        ),
    )

    rebind = commands.add_parser(
        "rebind-disabled",
        help="replace one changed Linux account generation and force disabled",
    )
    rebind.add_argument("--linux-uid", required=True, type=int)
    rebind.add_argument(
        "--acknowledge-account-generation-replacement",
        action="store_true",
        required=True,
        help=(
            "confirm that this may bind a recreated UID to the stored Apple "
            "authority; the resulting mapping remains disabled"
        ),
    )

    enable = commands.add_parser(
        "enable-reconciled",
        help=(
            "enable one disabled mapping after stable account, keybag, "
            "Catacomb, identity, and AKS reconciliation"
        ),
    )
    enable.add_argument("--linux-uid", required=True, type=int)
    enable.add_argument(
        "--acknowledge-live-apple-aks-catacomb-reconciliation-and-enable",
        action="store_true",
        required=True,
        help=(
            "confirm that the exact disabled mapping may be enabled only if "
            "two read-only live collections remain fully reconciled"
        ),
    )

    disable = commands.add_parser(
        "disable",
        help="immediately revoke one enabled mapping without live hardware",
    )
    disable.add_argument("--linux-uid", required=True, type=int)
    disable.add_argument(
        "--acknowledge-immediate-mapping-revocation",
        action="store_true",
        required=True,
        help="confirm that the selected mapping will stop authorizing operations",
    )

    status = commands.add_parser("status", help="show a redacted mapping status")
    status.add_argument(
        "--linux-uid",
        type=int,
        help="also compare this mapped UID with its live account generation",
    )
    return value


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "bind-current-disabled":
            authority = t2_current_user_authority.collect()
            result = t2_user_mapping_admin.bind_disabled(
                linux_uid=arguments.linux_uid,
                apple_uid=authority.apple_uid,
                account_uuid=authority.account_uuid,
                bag_uuid=authority.bag_uuid,
                unlock_mode=arguments.unlock_mode,
                capabilities=tuple(arguments.capability),
                acknowledge_apple_authority_is_already_provisioned=(
                    arguments.acknowledge_current_apple_authority_is_already_provisioned
                ),
            )
        elif arguments.command == "rebind-disabled":
            result = t2_user_mapping_admin.rebind_disabled(
                linux_uid=arguments.linux_uid,
                acknowledge_account_generation_replacement=(
                    arguments.acknowledge_account_generation_replacement
                ),
            )
        elif arguments.command == "enable-reconciled":
            result = t2_user_reconciliation.enable_reconciled(
                linux_uid=arguments.linux_uid,
                acknowledge_live_apple_authority_and_enable=(
                    arguments.acknowledge_live_apple_aks_catacomb_reconciliation_and_enable
                ),
                live_session_factory=(
                    t2_user_reconciliation_live.LiveUserReconciliationSession
                ),
            )
        elif arguments.command == "disable":
            result = t2_user_mapping_admin.disable(
                linux_uid=arguments.linux_uid,
                acknowledge_immediate_mapping_revocation=(
                    arguments.acknowledge_immediate_mapping_revocation
                ),
            )
        else:
            result = t2_user_mapping_admin.status(
                linux_uid=arguments.linux_uid,
            )
    except (
        t2_user_mapping_admin.UserMappingAdminError,
        t2_current_user_authority.CurrentUserAuthorityError,
        t2_user_reconciliation.UserReconciliationError,
        t2_user_reconciliation_live.LiveUserReconciliationError,
    ) as error:
        print(f"t2-touchid-user-map: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result.redacted(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
