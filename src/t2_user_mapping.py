# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed persistent mapping model for already-provisioned Apple users.

This module deliberately performs no keybag, SEP, Catacomb, or account action.
It validates the private administrator-owned authority that future multi-user
brokers must reconcile against live state before selecting a target.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA_VERSION = 1
MAX_FILE_SIZE = 1024 * 1024
MAX_MAPPINGS = 64
UINT32_MAX = (1 << 32) - 1
KEYBAG_ROOT = PurePosixPath("/var/lib/t2-touchid/users")
CAPABILITIES = frozenset({"verify", "enroll", "identity-management"})
UNLOCK_MODES = frozenset({"password-on-demand", "host-encrypted-credential"})


class UserMappingError(ValueError):
    """Raised when persistent mapping authority is unsafe or ambiguous."""


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise UserMappingError("mapping JSON contains a duplicate key")
        result[key] = value
    return result


def _unsigned(value: Any, label: str, *, minimum: int) -> int:
    if type(value) is not int or not minimum <= value < UINT32_MAX:
        raise UserMappingError(f"{label} is outside the permitted numeric range")
    return value


def _sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise UserMappingError(f"{label} is not a lowercase SHA-256 digest")
    return value


def _canonical_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise UserMappingError(f"{label} is not a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise UserMappingError(f"{label} is not a canonical UUID") from error
    if parsed.int == 0 or str(parsed) != value:
        raise UserMappingError(f"{label} is not a canonical nonzero UUID")
    return value


def _keybag_path(value: Any, linux_uid: int) -> str:
    expected = KEYBAG_ROOT / str(linux_uid) / "user.kb"
    if not isinstance(value, str) or PurePosixPath(value) != expected:
        raise UserMappingError(
            "keybag path must use the target UID's private canonical location"
        )
    return value


@dataclass(frozen=True)
class UserMapping:
    linux_uid: int
    linux_account_generation: str
    apple_uid: int
    account_uuid: str
    bag_uuid: str
    keybag_path: str
    keybag_sha256: str
    unlock_mode: str
    capabilities: frozenset[str]
    enabled: bool

    @property
    def special_bag_alias(self) -> int:
        """Return the derived Apple alias; it is never caller-controlled."""

        return -self.apple_uid

    def permits(self, capability: str) -> bool:
        if capability not in CAPABILITIES:
            raise UserMappingError("requested capability is unknown")
        return self.enabled and capability in self.capabilities


@dataclass(frozen=True)
class UserMappingSet:
    generation: str
    mappings: tuple[UserMapping, ...]

    def resolve(self, linux_uid: int, capability: str) -> UserMapping:
        _unsigned(linux_uid, "target Linux UID", minimum=1)
        if capability not in CAPABILITIES:
            raise UserMappingError("requested capability is unknown")
        selected = [item for item in self.mappings if item.linux_uid == linux_uid]
        if len(selected) != 1:
            raise UserMappingError("target Linux UID has no unique protected mapping")
        if not selected[0].permits(capability):
            raise UserMappingError("target mapping does not permit this capability")
        return selected[0]

    def redacted_summary(self) -> dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "mapping_count": len(self.mappings),
            "enabled_mapping_count": sum(item.enabled for item in self.mappings),
            "password_on_demand_count": sum(
                item.unlock_mode == "password-on-demand" for item in self.mappings
            ),
            "host_encrypted_credential_count": sum(
                item.unlock_mode == "host-encrypted-credential"
                for item in self.mappings
            ),
            "identifiers_redacted": True,
        }


def _parse_mapping(value: Any) -> UserMapping:
    fields = {
        "linux_uid",
        "linux_account_generation",
        "apple_uid",
        "account_uuid",
        "bag_uuid",
        "keybag_path",
        "keybag_sha256",
        "unlock_mode",
        "capabilities",
        "enabled",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise UserMappingError("mapping entry fields are incomplete or unsupported")
    linux_uid = _unsigned(value["linux_uid"], "Linux UID", minimum=1)
    apple_uid = _unsigned(value["apple_uid"], "Apple UID", minimum=10)
    unlock_mode = value["unlock_mode"]
    if not isinstance(unlock_mode, str) or unlock_mode not in UNLOCK_MODES:
        raise UserMappingError("unlock mode is unsupported")
    capabilities = value["capabilities"]
    if (
        not isinstance(capabilities, list)
        or any(not isinstance(item, str) for item in capabilities)
        or len(capabilities) != len(set(capabilities))
        or capabilities != sorted(capabilities)
        or any(item not in CAPABILITIES for item in capabilities)
    ):
        raise UserMappingError("capabilities must be a sorted unique supported list")
    if type(value["enabled"]) is not bool:
        raise UserMappingError("mapping enabled state must be Boolean")
    return UserMapping(
        linux_uid=linux_uid,
        linux_account_generation=_sha256(
            value["linux_account_generation"], "Linux account generation"
        ),
        apple_uid=apple_uid,
        account_uuid=_canonical_uuid(value["account_uuid"], "Apple account UUID"),
        bag_uuid=_canonical_uuid(value["bag_uuid"], "AKS bag UUID"),
        keybag_path=_keybag_path(value["keybag_path"], linux_uid),
        keybag_sha256=_sha256(value["keybag_sha256"], "keybag digest"),
        unlock_mode=unlock_mode,
        capabilities=frozenset(capabilities),
        enabled=value["enabled"],
    )


def parse(data: bytes) -> UserMappingSet:
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_FILE_SIZE:
        raise UserMappingError("mapping file size is invalid")
    try:
        document = json.loads(
            data.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise UserMappingError("mapping file is not strict UTF-8 JSON") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "mappings"}
        or document["schema_version"] != SCHEMA_VERSION
        or type(document["schema_version"]) is not int
        or not isinstance(document["mappings"], list)
        or len(document["mappings"]) > MAX_MAPPINGS
    ):
        raise UserMappingError("mapping document schema is unsupported")
    mappings = tuple(_parse_mapping(item) for item in document["mappings"])
    for attribute, label in (
        ("linux_uid", "Linux UID"),
        ("apple_uid", "Apple UID"),
        ("account_uuid", "Apple account UUID"),
        ("bag_uuid", "AKS bag UUID"),
        ("keybag_path", "keybag path"),
    ):
        values = [getattr(item, attribute) for item in mappings]
        if len(values) != len(set(values)):
            raise UserMappingError(f"{label} is mapped more than once")
    return UserMappingSet(hashlib.sha256(data).hexdigest(), mappings)


def load(path: Path) -> UserMappingSet:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o077
            or not 0 < info.st_size <= MAX_FILE_SIZE
        ):
            raise UserMappingError("mapping file is not private and root-owned")
        data = bytearray()
        while len(data) <= MAX_FILE_SIZE:
            block = os.read(descriptor, min(65536, MAX_FILE_SIZE + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        if len(data) != info.st_size:
            raise UserMappingError("mapping file changed while it was being read")
        return parse(bytes(data))
    except OSError as error:
        raise UserMappingError("mapping file cannot be read safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
