#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run one redacted, read-only live AKS alias-observer validation."""

from __future__ import annotations

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
if (LOCAL_SOURCE / "t2_aks_observer.py").is_file():
    sys.path.insert(0, str(LOCAL_SOURCE))
elif INSTALLED_SOURCE.is_dir():
    sys.path.insert(0, str(INSTALLED_SOURCE))

import t2_aks_observer
import t2_user_mapping
import t2_user_readiness


CONFIG = Path("/etc/t2-touchid.conf")
OPERATION_LOCK = Path("/run/t2-touchid/operation.lock")
MAX_CONFIG_SIZE = 1024 * 1024


class AKSObserveTestError(RuntimeError):
    pass


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    return all(getattr(before, field) == getattr(after, field) for field in fields)


def _read_private_root_file(path: Path) -> bytes:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink != 1
            or before.st_mode & 0o077
            or not 0 < before.st_size <= MAX_CONFIG_SIZE
        ):
            raise AKSObserveTestError("runtime configuration is not private")
        data = bytearray()
        while len(data) <= MAX_CONFIG_SIZE:
            block = os.read(
                descriptor, min(65536, MAX_CONFIG_SIZE + 1 - len(data))
            )
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        if len(data) != before.st_size or not _same_file(before, after):
            raise AKSObserveTestError("runtime configuration changed during read")
        return bytes(data)
    except OSError as error:
        raise AKSObserveTestError("runtime configuration is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _configured_user_id() -> int:
    try:
        text = _read_private_root_file(CONFIG).decode("utf-8")
    except UnicodeError as error:
        raise AKSObserveTestError("runtime configuration is not UTF-8") from error
    matches = []
    for line in text.splitlines():
        match = re.fullmatch(r"T2_TOUCHID_MACOS_USER_ID=([0-9]+)", line)
        if match:
            matches.append(match.group(1))
    if len(matches) != 1:
        raise AKSObserveTestError(
            "configured Apple user is missing or duplicated"
        )
    value = matches[0]
    if (
        not value.isascii()
        or not value.isdecimal()
        or value != str(int(value, 10))
        or not 10 <= int(value, 10) <= t2_user_mapping.INT32_MAX
    ):
        raise AKSObserveTestError("configured Apple user cannot form an AKS alias")
    return int(value, 10)


@contextmanager
def _operation_lock() -> Iterator[None]:
    descriptor = -1
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(OPERATION_LOCK, flags, 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise AKSObserveTestError("operation lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AKSObserveTestError(
                "another Touch ID operation is active"
            ) from error
        yield
    except OSError as error:
        raise AKSObserveTestError("operation lock is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def collect() -> dict[str, object]:
    if os.geteuid() != 0:
        raise AKSObserveTestError("run through sudo")
    apple_user_id = _configured_user_id()
    with _operation_lock():
        evidence = t2_aks_observer.AKSAliasObserver().observe_alias(
            -apple_user_id
        )
    if (
        not evidence.present
        or evidence.special_alias != -apple_user_id
        or evidence.bag_uuid is None
        or evidence.account_uuid is None
        or evidence.lock_state is None
    ):
        raise AKSObserveTestError("configured AKS alias is absent or incomplete")
    if evidence.lock_state & ~t2_user_readiness.KNOWN_LOCK_STATE_BITS:
        raise AKSObserveTestError("configured AKS alias has unknown lock-state bits")
    return {
        "schema_version": 1,
        "operation_0x06_validated": True,
        "operation_0x19_validated": True,
        "stable_double_read": True,
        "queried_alias_matched": True,
        "bag_uuid_valid_and_redacted": True,
        "account_uuid_valid_and_redacted": True,
        "lock_state": evidence.lock_state,
        "mutation_performed": False,
        "identifiers_redacted": True,
    }


def main() -> int:
    try:
        result = collect()
    except (
        AKSObserveTestError,
        t2_aks_observer.AKSAliasObservationError,
        ValueError,
    ) as error:
        print(f"t2-aks-observe-test: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
