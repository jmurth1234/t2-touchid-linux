#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Reconcile private live SEP inventory with a copied macOS Catacomb archive."""

from __future__ import annotations

import hashlib
import plistlib
import tarfile
import uuid
from pathlib import Path
from typing import Any


class BaselineError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_symbolic_mode(value: str) -> int:
    if len(value) != 10 or value[0] != "-":
        raise BaselineError("Catacomb component is not a regular file")
    mode = 0
    for character, bit in zip(value[1:], (0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001)):
        if character != "-":
            expected = "r" if bit & 0o444 else "w" if bit & 0o222 else "x"
            if character != expected:
                raise BaselineError("Catacomb component has special permission bits")
            mode |= bit
    return mode


def parse_source_metadata(data: bytes, expected_names: set[str]) -> dict[str, dict[str, int]]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise BaselineError("source-stat.txt is not UTF-8") from error
    result = {}
    for line in lines:
        fields = line.split(maxsplit=4)
        if len(fields) != 5:
            continue
        mode_text, owner, _size, _mtime, source_path = fields
        name = source_path.rsplit("/", 1)[-1]
        if name not in expected_names:
            continue
        if name in result:
            raise BaselineError(f"duplicate source metadata for {name}")
        if owner != "root:wheel":
            raise BaselineError(f"unexpected source owner for {name}")
        result[name] = {
            "mode": parse_symbolic_mode(mode_text),
            "uid": 0,
            "gid": 0,
        }
    if set(result) != expected_names:
        raise BaselineError("source-stat.txt is missing Catacomb component metadata")
    return result


class KeyedArchive:
    def __init__(self, data: bytes, name: str) -> None:
        try:
            value = plistlib.loads(data)
        except plistlib.InvalidFileException as error:
            raise BaselineError(f"{name} is not a plist") from error
        if not isinstance(value, dict) or value.get("$archiver") != "NSKeyedArchiver":
            raise BaselineError(f"{name} is not a keyed archive")
        self.top = value.get("$top")
        self.objects = value.get("$objects")
        if not isinstance(self.top, dict) or not isinstance(self.objects, list):
            raise BaselineError(f"{name} has a malformed keyed archive")

    def dereference(self, value: Any) -> Any:
        if not isinstance(value, plistlib.UID):
            return value
        if value.data >= len(self.objects):
            raise BaselineError("keyed-archive reference is out of range")
        return self.objects[value.data]

    def uuid(self, value: Any) -> str:
        value = self.dereference(value)
        if isinstance(value, bytes):
            raw = value
        elif isinstance(value, dict):
            raw = value.get("NS.uuidbytes")
        else:
            raw = None
        if not isinstance(raw, bytes) or len(raw) != 16:
            raise BaselineError("keyed archive contains an invalid UUID")
        return str(uuid.UUID(bytes=raw))


def read_host_archive(path: Path, apple_uid: int) -> dict[str, Any]:
    expected_names = {
        "master.cat",
        "biolockout.cat",
        f"user_{apple_uid:08x}.cat",
    }
    members: dict[str, tuple[tarfile.TarInfo, bytes]] = {}
    source_stat = None
    try:
        archive = tarfile.open(path, "r:*")
    except (OSError, tarfile.TarError) as error:
        raise BaselineError(f"cannot open Catacomb archive: {error}") from error
    with archive:
        for member in archive.getmembers():
            name = member.name.rsplit("/", 1)[-1]
            if name == "source-stat.txt":
                if source_stat is not None or not member.isfile() or member.size > 65536:
                    raise BaselineError("invalid or duplicate source-stat.txt")
                stream = archive.extractfile(member)
                if stream is None:
                    raise BaselineError("cannot read source-stat.txt")
                source_stat = stream.read()
                continue
            if name not in expected_names:
                continue
            if name in members:
                raise BaselineError(f"duplicate Catacomb component {name}")
            if not member.isfile() or member.size > 1024 * 1024:
                raise BaselineError(f"unsafe Catacomb component {name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise BaselineError(f"cannot read Catacomb component {name}")
            members[name] = (member, stream.read())
    if set(members) != expected_names:
        raise BaselineError(
            "archive does not contain exactly master, user, and biolockout components"
        )
    if source_stat is None:
        raise BaselineError("archive has no live source-stat.txt metadata")
    source_metadata = parse_source_metadata(source_stat, expected_names)

    user_name = f"user_{apple_uid:08x}.cat"
    user = KeyedArchive(members[user_name][1], user_name)
    if user.top.get("CatacombVersion") != 0x30000:
        raise BaselineError("unsupported user Catacomb version")
    if user.top.get("CatacombUserID") != apple_uid:
        raise BaselineError("user Catacomb belongs to another Apple UID")
    identity_array = user.dereference(user.top.get("CatacombIdentityList"))
    if not isinstance(identity_array, dict) or not isinstance(
        identity_array.get("NS.objects"), list
    ):
        raise BaselineError("user Catacomb has no valid identity list")
    identities = []
    for reference in identity_array["NS.objects"]:
        identity = user.dereference(reference)
        if not isinstance(identity, dict):
            raise BaselineError("user Catacomb identity is malformed")
        identity_uid = identity.get("BKIdentityUserID")
        entity = identity.get("BKIdentityEntityNumber")
        if identity_uid != apple_uid or not isinstance(entity, int) or entity < 0:
            raise BaselineError("user Catacomb identity owner/entity is invalid")
        identities.append(
            {
                "user_id": identity_uid,
                "uuid": user.uuid(identity.get("BKIdentityUUID")),
                "entity": entity,
            }
        )
    identities.sort(key=lambda item: (item["user_id"], item["uuid"]))
    if len({item["uuid"] for item in identities}) != len(identities):
        raise BaselineError("user Catacomb contains duplicate identity UUIDs")

    master = KeyedArchive(members["master.cat"][1], "master.cat")
    if master.top.get("CatacombVersion") != 0x30000:
        raise BaselineError("unsupported master Catacomb version")
    generation = master.top.get("CatacombEnrollmentCount")
    if not isinstance(generation, int) or generation < 0:
        raise BaselineError("master Catacomb has an invalid generation hint")

    components = []
    for name in sorted(expected_names):
        _member, data = members[name]
        components.append(
            {
                "name": name,
                "sha256": sha256(data),
                **source_metadata[name],
            }
        )
    return {
        "account_uuid": user.uuid(user.top.get("CatacombUserUUID")),
        "bag_uuid": user.uuid(user.top.get("CatacombUserKeybagUUID")),
        "identity_records": identities,
        "master_enrollment_count": generation,
        "host_components": components,
        "archive_sha256": sha256(path.read_bytes()),
    }


def build_baseline(
    *,
    host: dict[str, Any],
    live: dict[str, Any],
    caller_linux_uid: int,
    target_linux_uid: int,
    linux_boot_uuid: str,
    mapping_generation: str,
    backup_reference: str,
    password_fallback_verified: bool,
) -> dict[str, Any]:
    apple_uid = live.get("apple_uid")
    if not isinstance(apple_uid, int) or apple_uid < 0:
        raise BaselineError("live inventory has an invalid Apple UID")
    if live.get("double_collection_equal") is not True:
        raise BaselineError("live inventory is not stable")
    live_identities = {
        (item.get("user_id"), item.get("identity_uuid"))
        for item in live.get("per_user_identity_records", [])
        if isinstance(item, dict)
    }
    host_identities = {
        (item["user_id"], item["uuid"]) for item in host["identity_records"]
    }
    if live_identities != host_identities:
        raise BaselineError("live SEP and host Catacomb identities disagree")
    catacomb = live.get("catacomb")
    if not isinstance(catacomb, dict) or catacomb.get("present") is not True:
        raise BaselineError("live SEP Catacomb component is absent")
    maximum = live.get("maximum_capacity")
    if not isinstance(maximum, int) or maximum < len(host_identities):
        raise BaselineError("live identity capacity is invalid")
    if live.get("biometric_protocol_version") != 2:
        raise BaselineError("baseline requires biometric protocol version 2")
    if not password_fallback_verified:
        raise BaselineError("password fallback has not been verified")
    return {
        "baseline_version": 1,
        "caller_linux_uid": caller_linux_uid,
        "target_linux_uid": target_linux_uid,
        "apple_uid": apple_uid,
        "account_uuid": host["account_uuid"],
        "bag_uuid": host["bag_uuid"],
        "linux_boot_uuid": linux_boot_uuid,
        "connection_generation": live["connection_generation"],
        "bridge_boot_uuid": live.get("bridge_boot_uuid"),
        "protocol_version": 2,
        "policy_decision": "authorized",
        "identity_records": host["identity_records"],
        "capacity": {"used": len(host_identities), "maximum": maximum},
        "sep_catacomb": {
            "present": True,
            "uuid": catacomb["uuid"],
            "hash": catacomb["hash"],
        },
        "host_components": host["host_components"],
        "master_enrollment_count": host["master_enrollment_count"],
        "mapping_generation": mapping_generation,
        "backup_references": [
            {"reference": backup_reference, "sha256": host["archive_sha256"]}
        ],
        "double_collection_equal": True,
        "password_fallback_verified": True,
    }
