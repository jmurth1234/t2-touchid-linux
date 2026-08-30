#!/usr/bin/env python3
"""Password-bind a transient ACM context and evaluate policy 1007."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
if (LOCAL_SOURCE / "t2_acm_device.py").is_file():
    sys.path.insert(0, str(LOCAL_SOURCE))
elif INSTALLED_SOURCE.is_dir():
    sys.path.insert(0, str(INSTALLED_SOURCE))

from t2_acm_device import ACMDevice, ACMDeviceError, authorization_test


CONFIG = Path("/etc/t2-touchid.conf")
KEYBAG_STATE = Path("/run/t2-touchid/keybag.env")
AKS_TOOL = Path("/usr/local/sbin/t2-aks-tool")


def configuration() -> tuple[int, int]:
    info = CONFIG.stat()
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise ACMDeviceError("configuration ownership or mode is unsafe")
    values: dict[str, list[int]] = {
        "T2_TOUCHID_MACOS_USER_ID": [],
        "T2_TOUCHID_SPECIAL_BAG": [],
    }
    for line in CONFIG.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([A-Z0-9_]+)=(-?[0-9]+)", line)
        if match and match.group(1) in values:
            values[match.group(1)].append(int(match.group(2)))
    user_ids = values["T2_TOUCHID_MACOS_USER_ID"]
    handles = values["T2_TOUCHID_SPECIAL_BAG"]
    if len(user_ids) != 1 or not 0 <= user_ids[0] <= 0xFFFFFFFF:
        raise ACMDeviceError("configuration has no unique valid macOS user ID")
    if len(handles) != 1 or handles[0] != -user_ids[0]:
        raise ACMDeviceError("special bag does not match the configured macOS user ID")
    return user_ids[0], handles[0]


def keybag_runtime(expected_special: int) -> tuple[int, int]:
    info = KEYBAG_STATE.stat()
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise ACMDeviceError("runtime keybag state ownership or mode is unsafe")
    values: dict[str, list[int]] = {
        "T2_KEYBAG_SESSION": [],
        "T2_KEYBAG_HANDLE": [],
        "T2_KEYBAG_SPECIAL": [],
    }
    for line in KEYBAG_STATE.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([A-Z0-9_]+)=(-?[0-9]+)", line)
        if match and match.group(1) in values:
            values[match.group(1)].append(int(match.group(2)))
    sessions = values["T2_KEYBAG_SESSION"]
    handles = values["T2_KEYBAG_HANDLE"]
    specials = values["T2_KEYBAG_SPECIAL"]
    if (
        sessions != [1]
        or len(handles) != 1
        or handles[0] <= 0
        or specials != [expected_special]
    ):
        raise ACMDeviceError("runtime keybag session does not match configuration")
    return sessions[0], handles[0]


def verify_password_command(
    session: int,
    keybag_handle: int,
) -> list[str]:
    if session != 1 or keybag_handle == 0:
        raise ACMDeviceError("unsafe password-verification target")
    return [
        str(AKS_TOOL),
        "verify-password-acm",
        str(session),
        str(keybag_handle),
    ]


def verify_password_matrix_command(
    session: int, special_handle: int, positive_handle: int
) -> list[str]:
    if session != 1 or special_handle >= 0 or positive_handle <= 0:
        raise ACMDeviceError("unsafe password-verification matrix target")
    return [
        str(AKS_TOOL),
        "verify-password-acm-matrix",
        str(session),
        str(special_handle),
        str(positive_handle),
    ]


def verify_password_only_command(session: int, positive_handle: int) -> list[str]:
    """Build the no-ACM diagnostic against the known live positive bag."""
    if session != 1 or positive_handle <= 0:
        raise ACMDeviceError("unsafe password-only verification target")
    return [
        str(AKS_TOOL),
        "verify-password-only",
        str(session),
        str(positive_handle),
    ]


def acknowledgement_valid(
    password_only: bool, binding_and_policy: bool, password_verification: bool
) -> bool:
    if password_only:
        return password_verification
    return binding_and_policy


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--acknowledge-password-binding-and-policy-mutation",
        action="store_true",
        help="acknowledge the ACM context binding and policy evaluation path",
    )
    parser.add_argument(
        "--acknowledge-password-verification",
        action="store_true",
        help="acknowledge the password-only keybag verification diagnostic",
    )
    handle_group = parser.add_mutually_exclusive_group()
    handle_group.add_argument(
        "--research-keybag-handle",
        type=int,
        choices=(-3,),
        help="override the configured -UID alias with Apple's current-user alias",
    )
    handle_group.add_argument(
        "--runtime-positive-keybag-handle",
        action="store_true",
        help="use the positive handle returned when this boot loaded the private keybag",
    )
    parser.add_argument(
        "--diagnostic-matrix",
        action="store_true",
        help="test -3, special, and positive handles with the canonical codec-v1 request, stopping at the first success",
    )
    parser.add_argument(
        "--diagnostic-password-only",
        action="store_true",
        help="verify the password against the positive runtime keybag without creating or attaching an ACM context",
    )
    parser.add_argument(
        "--legacy-context-create",
        action="store_true",
        help="use ACM context-create command 0x01 instead of tracking command 0x24",
    )
    args = parser.parse_args()
    if not acknowledgement_valid(
        args.diagnostic_password_only,
        args.acknowledge_password_binding_and_policy_mutation,
        args.acknowledge_password_verification,
    ):
        parser.error(
            "select the acknowledgement matching the requested diagnostic path"
        )
    if os.geteuid() != 0:
        print("t2-acm-authorize-test must run as root", file=sys.stderr)
        return 2
    try:
        user_id, keybag_handle = configuration()
        session, positive_handle = keybag_runtime(keybag_handle)
        if args.research_keybag_handle is not None:
            keybag_handle = args.research_keybag_handle
        elif args.runtime_positive_keybag_handle:
            keybag_handle = positive_handle

        if args.diagnostic_password_only:
            if args.diagnostic_matrix or args.legacy_context_create:
                raise ACMDeviceError(
                    "password-only diagnostic cannot be combined with ACM diagnostics"
                )
            completed = subprocess.run(
                verify_password_only_command(session, positive_handle),
                check=False,
            )
            return completed.returncode

        def bind_password(context: bytes) -> None:
            command = (
                verify_password_matrix_command(
                    session, -user_id, positive_handle
                )
                if args.diagnostic_matrix
                else verify_password_command(
                    session,
                    keybag_handle,
                )
            )
            completed = subprocess.run(
                command,
                input=context,
                check=False,
            )
            if completed.returncode:
                raise ACMDeviceError("AKS password binding failed")
            if args.diagnostic_matrix:
                raise ACMDeviceError(
                    "diagnostic completed without ACM credential binding"
                )

        with ACMDevice() as device:
            result = authorization_test(
                device,
                user_id,
                bind_password,
                tracking=not args.legacy_context_create,
            )
    except (OSError, ValueError, ACMDeviceError) as error:
        print(f"t2-acm-authorize-test: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
