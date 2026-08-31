#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""List reconciled T2 Touch ID identities without exposing their UUIDs."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


INSTALLED_SOURCE = Path("/opt/t2-touchid/src")
LOCAL_SOURCE = Path(__file__).resolve().parent
if (LOCAL_SOURCE / "t2_identity_inventory.py").is_file():
    sys.path.insert(0, str(LOCAL_SOURCE))
elif INSTALLED_SOURCE.is_dir():
    sys.path.insert(0, str(INSTALLED_SOURCE))

import t2_bridge_connection
import t2_bridge_inventory
import t2_catacomb_codec
import t2_catacomb_store
import t2_identity_inventory


CONFIG = Path("/etc/t2-touchid.conf")
PORT_CACHE = Path("/var/lib/t2-touchid/biometric-port")
STORE_ROOT = Path("/var/lib/t2-touchid/catacomb")
OPERATION_LOCK = Path("/run/t2-touchid/operation.lock")


class IdentityCommandError(RuntimeError):
    pass


def _private_root_file(path: Path) -> str:
    info = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o077
        or info.st_size > 1024 * 1024
    ):
        raise IdentityCommandError(f"{path.name} is not private and root-owned")
    return path.read_text(encoding="utf-8")


def _configuration() -> tuple[str, str, int, int]:
    values: dict[str, list[str]] = {
        "T2_TOUCHID_HOST": [],
        "T2_TOUCHID_INTERFACE": [],
        "T2_TOUCHID_MACOS_USER_ID": [],
    }
    for line in _private_root_file(CONFIG).splitlines():
        match = re.fullmatch(r"([A-Z0-9_]+)=(.*)", line)
        if match and match.group(1) in values:
            values[match.group(1)].append(match.group(2))
    if any(len(found) != 1 for found in values.values()):
        raise IdentityCommandError("runtime configuration is missing or duplicated")
    host = values["T2_TOUCHID_HOST"][0]
    interface = values["T2_TOUCHID_INTERFACE"][0]
    user_text = values["T2_TOUCHID_MACOS_USER_ID"][0]
    port_text = _private_root_file(PORT_CACHE).strip()
    if (
        not host
        or not interface
        or not user_text.isdecimal()
        or not 0 <= int(user_text) <= 0xFFFFFFFF
        or not port_text.isdecimal()
        or not 49152 <= int(port_text) <= 65535
    ):
        raise IdentityCommandError("runtime configuration is invalid")
    return host, interface, int(user_text), int(port_text)


@contextmanager
def _operation_lock() -> Iterator[None]:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(OPERATION_LOCK, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise IdentityCommandError("operation lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise IdentityCommandError("another Touch ID operation is active") from error
        yield
    finally:
        os.close(descriptor)


def collect() -> dict[str, object]:
    if os.geteuid() != 0:
        raise IdentityCommandError("run through sudo")
    host, interface, apple_user_id, port = _configuration()
    with _operation_lock():
        store = t2_catacomb_store.CatacombStore(STORE_ROOT, apple_user_id)
        components = store.read_committed_components()
        local = t2_catacomb_codec.decode_user_catacomb(
            components[f"user_{apple_user_id:08x}.cat"], apple_user_id
        )
        with t2_bridge_connection.BridgeConnectionLease.connect(
            host, interface, port, timeout=10
        ) as lease:
            live = t2_bridge_inventory.collect_stable_private_inventory(
                lease, apple_user_id
            )
        return t2_identity_inventory.summarize(local, live)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit compact JSON")
    args = parser.parse_args()
    try:
        result = collect()
    except (
        OSError,
        UnicodeError,
        IdentityCommandError,
        t2_bridge_connection.BridgeConnectionError,
        t2_bridge_inventory.BridgeInventoryError,
        t2_catacomb_codec.CatacombCodecError,
        t2_catacomb_store.CatacombStoreError,
        t2_identity_inventory.IdentityInventoryError,
    ) as error:
        parser.error(str(error))
    print(
        json.dumps(
            result,
            sort_keys=True,
            indent=None if args.json else 2,
            separators=(",", ":") if args.json else None,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

