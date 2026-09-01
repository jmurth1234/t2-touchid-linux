#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Root-only administration for disabled multi-user mapping records."""

from __future__ import annotations

import argparse
import json
import sys

import t2_user_mapping
import t2_user_mapping_admin


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        prog="t2-touchid-user-map",
        description=(
            "Create or rebind disabled T2 account mappings. This command never "
            "enables a mapping and never mutates the T2."
        ),
    )
    commands = value.add_subparsers(dest="command", required=True)

    bind = commands.add_parser(
        "bind-disabled",
        help="add one disabled mapping for an already-provisioned Apple user",
    )
    bind.add_argument("--linux-uid", required=True, type=int)
    bind.add_argument("--apple-uid", required=True, type=int)
    bind.add_argument("--account-uuid", required=True)
    bind.add_argument("--bag-uuid", required=True)
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
        "--acknowledge-apple-authority-is-already-provisioned",
        action="store_true",
        required=True,
        help=(
            "confirm these Apple identifiers refer to an already-provisioned "
            "user; the resulting mapping remains disabled"
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
        if arguments.command == "bind-disabled":
            result = t2_user_mapping_admin.bind_disabled(
                linux_uid=arguments.linux_uid,
                apple_uid=arguments.apple_uid,
                account_uuid=arguments.account_uuid,
                bag_uuid=arguments.bag_uuid,
                unlock_mode=arguments.unlock_mode,
                capabilities=tuple(arguments.capability),
                acknowledge_apple_authority_is_already_provisioned=(
                    arguments.acknowledge_apple_authority_is_already_provisioned
                ),
            )
        elif arguments.command == "rebind-disabled":
            result = t2_user_mapping_admin.rebind_disabled(
                linux_uid=arguments.linux_uid,
                acknowledge_account_generation_replacement=(
                    arguments.acknowledge_account_generation_replacement
                ),
            )
        else:
            result = t2_user_mapping_admin.status(
                linux_uid=arguments.linux_uid,
            )
    except t2_user_mapping_admin.UserMappingAdminError as error:
        print(f"t2-touchid-user-map: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result.redacted(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
