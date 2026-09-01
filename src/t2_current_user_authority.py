# SPDX-License-Identifier: GPL-2.0-only
"""Derive the configured Apple-user mapping authority without disclosing it."""

from __future__ import annotations

import fcntl
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

import t2_aks_observer
import t2_user_mapping
import t2_user_readiness


CONFIG = Path("/etc/t2-touchid.conf")
OPERATION_LOCK = Path("/run/t2-touchid/operation.lock")
MAX_CONFIG_SIZE = 1024 * 1024
ROOT_UID = 0


class CurrentUserAuthorityError(RuntimeError):
    pass


@dataclass(frozen=True, repr=False)
class CurrentAppleAuthority:
    apple_uid: int
    account_uuid: str
    bag_uuid: str
    lock_state: int

    def redacted(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "configured_apple_authority_present": True,
            "known_lock_state": True,
            "t2_mutation_performed": False,
            "identifiers_redacted": True,
        }


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    return all(
        getattr(before, field) == getattr(after, field)
        for field in (
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
    )


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
            or before.st_uid != ROOT_UID
            or before.st_nlink != 1
            or before.st_mode & 0o077
            or not 0 < before.st_size <= MAX_CONFIG_SIZE
        ):
            raise CurrentUserAuthorityError(
                "runtime configuration is not private"
            )
        data = bytearray()
        while len(data) <= MAX_CONFIG_SIZE:
            block = os.read(
                descriptor,
                min(65536, MAX_CONFIG_SIZE + 1 - len(data)),
            )
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        if len(data) != before.st_size or not _same_file(before, after):
            raise CurrentUserAuthorityError(
                "runtime configuration changed during read"
            )
        return bytes(data)
    except OSError as error:
        raise CurrentUserAuthorityError(
            "runtime configuration is unavailable"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _configured_user_id() -> int:
    try:
        text = _read_private_root_file(CONFIG).decode("utf-8")
    except UnicodeError as error:
        raise CurrentUserAuthorityError(
            "runtime configuration is not UTF-8"
        ) from error
    values: dict[str, list[str]] = {
        "T2_TOUCHID_MACOS_USER_ID": [],
        "T2_TOUCHID_SPECIAL_BAG": [],
    }
    for line in text.splitlines():
        match = re.fullmatch(r"([A-Z0-9_]+)=(.*)", line)
        if match and match.group(1) in values:
            values[match.group(1)].append(match.group(2))
    if any(len(items) != 1 for items in values.values()):
        raise CurrentUserAuthorityError(
            "configured Apple authority is missing or duplicated"
        )
    uid_text = values["T2_TOUCHID_MACOS_USER_ID"][0]
    if (
        not uid_text.isascii()
        or not uid_text.isdecimal()
        or uid_text != str(int(uid_text, 10))
        or not 10 <= int(uid_text, 10) <= t2_user_mapping.INT32_MAX
    ):
        raise CurrentUserAuthorityError(
            "configured Apple user cannot form an AKS alias"
        )
    apple_uid = int(uid_text, 10)
    if values["T2_TOUCHID_SPECIAL_BAG"][0] != str(-apple_uid):
        raise CurrentUserAuthorityError(
            "configured Apple alias does not match the user"
        )
    return apple_uid


def _open_operation_lock() -> int:
    descriptor = -1
    try:
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(OPERATION_LOCK, flags, 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != ROOT_UID
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise CurrentUserAuthorityError("operation lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise CurrentUserAuthorityError(
                "another Touch ID operation is active"
            ) from error
        return descriptor
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise CurrentUserAuthorityError(
            "operation lock is unavailable"
        ) from error
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def _validate(
    apple_uid: int,
    evidence: object,
) -> CurrentAppleAuthority:
    if (
        not isinstance(evidence, t2_user_readiness.AliasEvidence)
        or evidence.present is not True
        or evidence.special_alias != -apple_uid
        or evidence.bag_uuid is None
        or evidence.account_uuid is None
        or type(evidence.lock_state) is not int
        or not 0 <= evidence.lock_state <= 0xFFFFFFFF
        or evidence.lock_state & ~t2_user_readiness.KNOWN_LOCK_STATE_BITS
    ):
        raise CurrentUserAuthorityError(
            "configured Apple authority is absent or invalid"
        )
    try:
        account_uuid = t2_user_mapping._canonical_uuid(
            evidence.account_uuid, "account UUID"
        )
        bag_uuid = t2_user_mapping._canonical_uuid(
            evidence.bag_uuid, "bag UUID"
        )
    except t2_user_mapping.UserMappingError as error:
        raise CurrentUserAuthorityError(
            "configured Apple authority is absent or invalid"
        ) from error
    return CurrentAppleAuthority(
        apple_uid,
        account_uuid,
        bag_uuid,
        evidence.lock_state,
    )


def collect() -> CurrentAppleAuthority:
    """Collect exact private authority under the biometric operation lock."""

    if os.geteuid() != ROOT_UID:
        raise CurrentUserAuthorityError("current authority requires root")
    apple_uid = _configured_user_id()
    lock = _open_operation_lock()
    try:
        evidence = t2_aks_observer.AKSAliasObserver(
            expected_owner_uid=ROOT_UID
        ).observe_alias(-apple_uid)
        return _validate(apple_uid, evidence)
    except t2_aks_observer.AKSAliasObservationError as error:
        raise CurrentUserAuthorityError(
            "configured Apple authority observation failed"
        ) from error
    finally:
        os.close(lock)
