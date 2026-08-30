#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Durable, append-only journal primitives for future biometric mutations.

This module performs no T2 operation.  It exists so every future mutating call
can durably record intent before dispatch and independently observed state
after read-back.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import uuid
from pathlib import Path
from typing import Any


FORMAT_VERSION = 1
ALLOWED_KINDS = {"enroll", "delete-one", "delete-batch", "recovery"}
FORBIDDEN_KEY_PARTS = ("password", "passcode", "credential", "secret", "auth_token")
SAFE_SECURITY_METADATA_SUFFIXES = ("_verified", "_digest", "_hash", "_present")
BASELINE_KEYS = {
    "baseline_version",
    "caller_linux_uid",
    "target_linux_uid",
    "apple_uid",
    "account_uuid",
    "bag_uuid",
    "linux_boot_uuid",
    "connection_generation",
    "bridge_boot_uuid",
    "protocol_version",
    "policy_decision",
    "identity_records",
    "capacity",
    "sep_catacomb",
    "host_components",
    "master_enrollment_count",
    "mapping_generation",
    "backup_references",
    "double_collection_equal",
    "password_fallback_verified",
}


class JournalError(RuntimeError):
    pass


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise JournalError(f"journal value is not canonical JSON: {error}") from error


def reject_secrets(value: Any, path: str = "entry") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise JournalError(f"{path} contains a non-string key")
            normalized = key.lower().replace("-", "_")
            if any(part in normalized for part in FORBIDDEN_KEY_PARTS) and not normalized.endswith(
                SAFE_SECURITY_METADATA_SUFFIXES
            ):
                raise JournalError(f"{path}.{key} may contain secret material")
            reject_secrets(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secrets(child, f"{path}[{index}]")
    elif isinstance(value, (bytes, bytearray)):
        raise JournalError(f"{path} contains raw bytes")


def record_hash(record_without_hash: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(record_without_hash)).hexdigest()


def require_uuid(value: Any, field: str) -> None:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise JournalError(f"{field} is not a UUID") from error
    if str(parsed).lower() != value.lower():
        raise JournalError(f"{field} is not a canonical UUID")


def require_sha256(value: Any, field: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise JournalError(f"{field} is not a SHA-256 digest")
    try:
        bytes.fromhex(value)
    except ValueError as error:
        raise JournalError(f"{field} is not a SHA-256 digest") from error


def require_nonnegative_int(value: Any, field: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise JournalError(f"{field} is not a non-negative integer")


def validate_baseline(baseline: Any) -> None:
    if not isinstance(baseline, dict) or set(baseline) != BASELINE_KEYS:
        missing = sorted(BASELINE_KEYS - set(baseline) if isinstance(baseline, dict) else BASELINE_KEYS)
        extra = sorted(set(baseline) - BASELINE_KEYS) if isinstance(baseline, dict) else []
        raise JournalError(f"baseline fields do not match schema; missing={missing}, extra={extra}")
    if baseline["baseline_version"] != 1:
        raise JournalError("unsupported baseline version")
    for field in (
        "caller_linux_uid",
        "target_linux_uid",
        "apple_uid",
        "protocol_version",
        "master_enrollment_count",
    ):
        require_nonnegative_int(baseline[field], field)
    for field in (
        "account_uuid",
        "bag_uuid",
        "linux_boot_uuid",
        "connection_generation",
    ):
        require_uuid(baseline[field], field)
    if baseline["bridge_boot_uuid"] is not None:
        require_uuid(baseline["bridge_boot_uuid"], "bridge_boot_uuid")
    if baseline["policy_decision"] != "authorized":
        raise JournalError("baseline policy decision is not authorized")
    if baseline["double_collection_equal"] is not True:
        raise JournalError("baseline was not reproduced by a second collection")
    if baseline["password_fallback_verified"] is not True:
        raise JournalError("password fallback is not verified")
    require_sha256(baseline["mapping_generation"], "mapping_generation")

    identities = baseline["identity_records"]
    if not isinstance(identities, list):
        raise JournalError("identity_records is not a list")
    seen_identities = set()
    for index, identity in enumerate(identities):
        if not isinstance(identity, dict) or set(identity) != {"user_id", "uuid", "entity"}:
            raise JournalError(f"identity_records[{index}] has an invalid schema")
        require_nonnegative_int(identity["user_id"], f"identity_records[{index}].user_id")
        require_nonnegative_int(identity["entity"], f"identity_records[{index}].entity")
        require_uuid(identity["uuid"], f"identity_records[{index}].uuid")
        key = (identity["user_id"], identity["uuid"].lower())
        if key in seen_identities:
            raise JournalError("identity_records contains a duplicate")
        seen_identities.add(key)
        if identity["user_id"] != baseline["apple_uid"]:
            raise JournalError("identity record belongs to another Apple UID")

    capacity = baseline["capacity"]
    if not isinstance(capacity, dict) or set(capacity) != {"used", "maximum"}:
        raise JournalError("capacity has an invalid schema")
    require_nonnegative_int(capacity["used"], "capacity.used")
    require_nonnegative_int(capacity["maximum"], "capacity.maximum")
    if capacity["used"] != len(identities) or capacity["used"] > capacity["maximum"]:
        raise JournalError("capacity does not agree with identity inventory")

    sep = baseline["sep_catacomb"]
    if not isinstance(sep, dict) or set(sep) != {"present", "uuid", "hash"}:
        raise JournalError("sep_catacomb has an invalid schema")
    if sep["present"] is True:
        require_uuid(sep["uuid"], "sep_catacomb.uuid")
        require_sha256(sep["hash"], "sep_catacomb.hash")
    elif sep["present"] is False:
        if sep["uuid"] is not None or sep["hash"] is not None:
            raise JournalError("absent SEP Catacomb has UUID/hash data")
    else:
        raise JournalError("sep_catacomb.present is not boolean")

    components = baseline["host_components"]
    if not isinstance(components, list):
        raise JournalError("host_components is not a list")
    component_names = set()
    for index, component in enumerate(components):
        expected = {"name", "sha256", "mode", "uid", "gid"}
        if not isinstance(component, dict) or set(component) != expected:
            raise JournalError(f"host_components[{index}] has an invalid schema")
        name = component["name"]
        if name not in {"master.cat", "biolockout.cat", f'user_{baseline["apple_uid"]:08x}.cat'}:
            raise JournalError(f"host_components[{index}] has an unexpected name")
        if name in component_names:
            raise JournalError("host_components contains a duplicate")
        component_names.add(name)
        require_sha256(component["sha256"], f"host_components[{index}].sha256")
        for field in ("mode", "uid", "gid"):
            require_nonnegative_int(component[field], f"host_components[{index}].{field}")

    backups = baseline["backup_references"]
    if not isinstance(backups, list) or not backups:
        raise JournalError("baseline has no verified backup references")
    for index, backup in enumerate(backups):
        if not isinstance(backup, dict) or set(backup) != {"reference", "sha256"}:
            raise JournalError(f"backup_references[{index}] has an invalid schema")
        if not isinstance(backup["reference"], str) or not backup["reference"]:
            raise JournalError(f"backup_references[{index}].reference is invalid")
        require_sha256(backup["sha256"], f"backup_references[{index}].sha256")


def validate_records(lines: list[bytes]) -> list[dict[str, Any]]:
    records = []
    previous_hash = None
    operation_id = None
    for sequence, line in enumerate(lines):
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise JournalError(f"invalid journal JSON at sequence {sequence}") from error
        if not isinstance(record, dict):
            raise JournalError(f"journal record {sequence} is not an object")
        supplied_hash = record.pop("record_hash", None)
        if record.get("format_version") != FORMAT_VERSION:
            raise JournalError(f"unsupported journal format at sequence {sequence}")
        if record.get("sequence") != sequence:
            raise JournalError(f"non-contiguous journal sequence at {sequence}")
        if record.get("previous_hash") != previous_hash:
            raise JournalError(f"broken journal hash chain at sequence {sequence}")
        if not isinstance(supplied_hash, str) or supplied_hash != record_hash(record):
            raise JournalError(f"invalid journal hash at sequence {sequence}")
        if operation_id is None:
            operation_id = record.get("operation_id")
        if record.get("operation_id") != operation_id:
            raise JournalError(f"operation ID changed at sequence {sequence}")
        record["record_hash"] = supplied_hash
        records.append(record)
        previous_hash = supplied_hash
    return records


def append(
    path: Path,
    operation_id: str,
    milestone: str,
    evidence: dict[str, Any],
    *,
    exclusive: bool = False,
) -> dict[str, Any]:
    try:
        uuid.UUID(operation_id)
    except ValueError as error:
        raise JournalError("invalid operation UUID") from error
    if not milestone or not milestone.isascii() or not milestone.replace("_", "").isalnum():
        raise JournalError("invalid milestone name")
    reject_secrets(evidence)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_info = path.parent.stat()
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.geteuid()
        or parent_info.st_mode & 0o077
    ):
        raise JournalError("journal directory is not private and caller-owned")
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NONBLOCK
    if exclusive:
        flags |= os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise JournalError("journal is not a private caller-owned regular file")
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        with os.fdopen(os.dup(fd), "rb") as stream:
            records = validate_records(stream.readlines())
        if records and records[0]["operation_id"] != operation_id:
            raise JournalError("journal belongs to another operation")
        previous_hash = records[-1]["record_hash"] if records else None
        unsigned = {
            "format_version": FORMAT_VERSION,
            "operation_id": operation_id,
            "sequence": len(records),
            "previous_hash": previous_hash,
            "milestone": milestone,
            "evidence": evidence,
        }
        record = {**unsigned, "record_hash": record_hash(unsigned)}
        os.write(fd, canonical(record) + b"\n")
        os.fsync(fd)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return record
    finally:
        os.close(fd)


def create(path: Path, kind: str, baseline: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if kind not in ALLOWED_KINDS:
        raise JournalError("unsupported mutation kind")
    if path.exists():
        raise JournalError("refusing to replace an existing journal")
    validate_baseline(baseline)
    operation_id = str(uuid.uuid4())
    record = append(
        path,
        operation_id,
        "BASELINE_RECONCILED",
        {"operation_kind": kind, "baseline": baseline},
        exclusive=True,
    )
    return operation_id, record


def secure_regular_file(path: Path) -> bool:
    info = path.stat()
    return stat.S_ISREG(info.st_mode) and not (info.st_mode & 0o077)
