#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Inspect an Apple BiometricKit Catacomb without exposing IDs by default."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import plistlib
from pathlib import Path
from typing import Any


APPLE_EPOCH = dt.datetime(2001, 1, 1, tzinfo=dt.timezone.utc)


class CatacombError(ValueError):
    pass


class Archive:
    def __init__(self, value: Any) -> None:
        if not isinstance(value, dict) or value.get("$archiver") != "NSKeyedArchiver":
            raise CatacombError("not an NSKeyedArchiver Catacomb")
        self.objects = value.get("$objects")
        self.top = value.get("$top")
        if not isinstance(self.objects, list) or not isinstance(self.top, dict):
            raise CatacombError("malformed keyed archive")

    def get(self, value: Any) -> Any:
        if not isinstance(value, plistlib.UID):
            return value
        index = value.data
        if index >= len(self.objects):
            raise CatacombError(f"object reference {index} is out of range")
        return self.objects[index]

    def class_name(self, value: Any) -> str:
        value = self.get(value)
        if not isinstance(value, dict) or "$class" not in value:
            raise CatacombError("expected archived object")
        record = self.get(value["$class"])
        if not isinstance(record, dict) or not isinstance(record.get("$classname"), str):
            raise CatacombError("archived object has no class name")
        return record["$classname"]

    def uuid(self, value: Any) -> str:
        value = self.get(value)
        if isinstance(value, bytes):
            raw = value
        else:
            if self.class_name(value) != "NSUUID":
                raise CatacombError("expected UUID bytes or NSUUID")
            raw = value.get("NS.uuidbytes")
        if not isinstance(raw, bytes) or len(raw) != 16:
            raise CatacombError("invalid NSUUID bytes")
        import uuid

        return str(uuid.UUID(bytes=raw)).upper()

    def date(self, value: Any) -> str:
        value = self.get(value)
        if self.class_name(value) != "NSDate":
            raise CatacombError("expected NSDate")
        seconds = value.get("NS.time")
        if not isinstance(seconds, (int, float)):
            raise CatacombError("invalid NSDate value")
        return (APPLE_EPOCH + dt.timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")

    def scalar(self, value: Any) -> Any:
        value = self.get(value)
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        raise CatacombError("expected archived scalar value")


def inspect(path: Path, include_identifiers: bool = False) -> dict[str, Any]:
    try:
        value = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as error:
        raise CatacombError(str(error)) from error
    archive = Archive(value)
    top = archive.top

    if "CatacombIdentityList" not in top:
        if "CatacombEnrollmentCount" in top:
            return {
                "component": "master",
                "catacomb_version": top.get("CatacombVersion"),
                "enrollment_generation_hint": top.get("CatacombEnrollmentCount"),
            }
        if "BioLockoutRecordVersion" in top:
            return {
                "component": "biolockout",
                "record_version": top.get("BioLockoutRecordVersion"),
            }
        raise CatacombError("unrecognized Catacomb component")

    array = archive.get(top["CatacombIdentityList"])
    if archive.class_name(array) != "NSMutableArray" or not isinstance(array.get("NS.objects"), list):
        raise CatacombError("invalid identity list")

    identities = []
    for reference in array["NS.objects"]:
        identity = archive.get(reference)
        if archive.class_name(identity) != "BiometricKitIdentity":
            raise CatacombError("identity list contains an unexpected object")
        record = {
            "name": archive.scalar(identity.get("BKIdentityName")),
            "type": archive.scalar(identity.get("BKIdentityType")),
            "user_id": archive.scalar(identity.get("BKIdentityUserID")),
            "entity_number": archive.scalar(identity.get("BKIdentityEntityNumber")),
            "attribute": archive.scalar(identity.get("BKIdentityAttribute")),
            "flags": archive.scalar(identity.get("BKIdentityFlags")),
            "match_count": archive.scalar(identity.get("BKIdentityMatchCount")),
            "continuous_match_count": archive.scalar(identity.get("BKIdentityMatchCountContinuous")),
            "update_count": archive.scalar(identity.get("BKIdentityUpdateCount")),
            "created": archive.date(identity["BKIdentityCreationTime"]),
        }
        if include_identifiers:
            record["identity_uuid"] = archive.uuid(identity["BKIdentityUUID"])
        identities.append(record)

    result = {
        "component": "user",
        "catacomb_version": top.get("CatacombVersion"),
        "user_id": top.get("CatacombUserID"),
        "identity_count": len(identities),
        "identities": identities,
        "anatomical_finger_positions_present": False,
    }
    if include_identifiers:
        result["user_uuid"] = archive.uuid(top["CatacombUserUUID"])
        result["keybag_uuid"] = archive.uuid(top["CatacombUserKeybagUUID"])
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catacomb", type=Path, help="master.cat, user_*.cat, or biolockout.cat")
    parser.add_argument(
        "--include-identifiers",
        action="store_true",
        help="print private account, keybag, and biometric UUIDs",
    )
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(args.catacomb, args.include_identifiers), indent=2, sort_keys=True))
    except CatacombError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
