#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Independent strict semantic reader for Linux-emitted Catacomb archives.

This module intentionally shares no traversal or validation code with the
writer in :mod:`t2_catacomb_codec`.  The writer uses it as a read-back oracle.
"""

from __future__ import annotations

import hashlib
import math
import plistlib
import uuid
from typing import Any


class OracleError(ValueError):
    pass


CHAINS = {
    "NSMutableData": ["NSMutableData", "NSData", "NSObject"],
    "NSMutableArray": ["NSMutableArray", "NSArray", "NSObject"],
    "BiometricKitIdentity": ["BiometricKitIdentity", "NSObject"],
    "NSDate": ["NSDate", "NSObject"],
    "BiometricKitAccessory": ["BiometricKitAccessory", "NSObject"],
    "BiometricKitAccessoryGroup": ["BiometricKitAccessoryGroup", "NSObject"],
    "NSUUID": ["NSUUID", "NSObject"],
}


class Graph:
    def __init__(self, data: bytes) -> None:
        if not isinstance(data, bytes) or not 0 < len(data) <= 1024 * 1024 or not data.startswith(b"bplist00"):
            raise OracleError("not a bounded binary plist")
        try:
            root = plistlib.loads(data)
        except (plistlib.InvalidFileException, ValueError, OverflowError) as error:
            raise OracleError("invalid binary plist") from error
        if (
            not isinstance(root, dict)
            or set(root) != {"$version", "$archiver", "$top", "$objects"}
            or root["$version"] != 100000
            or root["$archiver"] != "NSKeyedArchiver"
            or not isinstance(root["$top"], dict)
            or not isinstance(root["$objects"], list)
            or not 1 <= len(root["$objects"]) <= 256
            or root["$objects"][0] != "$null"
        ):
            raise OracleError("unknown keyed-archive root")
        self.top = root["$top"]
        self.objects = root["$objects"]
        self._reachable()

    def index(self, value: Any, field: str) -> int:
        if not isinstance(value, plistlib.UID) or not 0 <= value.data < len(self.objects):
            raise OracleError(f"invalid {field} reference")
        return value.data

    def get(self, value: Any, field: str) -> Any:
        return self.objects[self.index(value, field)]

    def classed(self, value: Any, class_name: str, keys: set[str], field: str) -> dict[str, Any]:
        item = self.get(value, field) if isinstance(value, plistlib.UID) else value
        if not isinstance(item, dict) or set(item) != keys | {"$class"}:
            raise OracleError(f"invalid {field} schema")
        descriptor = self.get(item["$class"], f"{field} class")
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != {"$classname", "$classes"}
            or descriptor.get("$classname") != class_name
            or descriptor.get("$classes") != CHAINS[class_name]
        ):
            raise OracleError(f"invalid {field} class")
        return item

    def text(self, reference: Any, field: str) -> str:
        value = self.get(reference, field)
        if not isinstance(value, str) or len(value.encode("utf-8")) > 1024:
            raise OracleError(f"invalid {field}")
        return value

    def integer(self, value: Any, field: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF:
            raise OracleError(f"invalid {field}")
        return value

    def raw_uuid(self, value: Any, field: str) -> str:
        if not isinstance(value, bytes) or len(value) != 16:
            raise OracleError(f"invalid {field}")
        return str(uuid.UUID(bytes=value))

    def archived_uuid(self, value: Any, field: str) -> str:
        item = self.classed(value, "NSUUID", {"NS.uuidbytes"}, field)
        return self.raw_uuid(item["NS.uuidbytes"], field)

    def data(self, value: Any, magic: bytes, field: str) -> bytes:
        item = self.classed(value, "NSMutableData", {"NS.data"}, field)
        data = item["NS.data"]
        if not isinstance(data, bytes) or not 16 <= len(data) <= 1024 * 1024 or data[:4] != magic:
            raise OracleError(f"invalid {field} envelope")
        return data

    def date(self, value: Any, field: str) -> float:
        item = self.classed(value, "NSDate", {"NS.time"}, field)
        result = item["NS.time"]
        if not isinstance(result, (int, float)) or isinstance(result, bool) or not math.isfinite(result):
            raise OracleError(f"invalid {field}")
        return float(result)

    def _reachable(self) -> None:
        reached: set[int] = set()
        active: set[int] = set()

        def visit(value: Any) -> None:
            if isinstance(value, plistlib.UID):
                index = self.index(value, "graph")
                if index == 0:
                    return
                if index in active:
                    raise OracleError("cyclic object graph")
                if index in reached:
                    return
                active.add(index)
                visit(self.objects[index])
                active.remove(index)
                reached.add(index)
            elif isinstance(value, dict):
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(self.top)
        if reached != set(range(1, len(self.objects))):
            raise OracleError("unreachable object")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_master(data: bytes) -> dict[str, Any]:
    graph = Graph(data)
    expected = {
        "CatacombVersion",
        "CatacombSecureData",
        "CatacombCurrentDate",
        "CatacombUserID",
        "CatacombEnrollmentCount",
    }
    if set(graph.top) != expected or graph.top["CatacombVersion"] != 0x30000 or graph.top["CatacombUserID"] != -1:
        raise OracleError("invalid master top")
    secure = graph.data(graph.top["CatacombSecureData"], b"LTFC", "master secure data")
    return {
        "component": "master",
        "secure_sha256": _digest(secure),
        "secure_length": len(secure),
        "enrollment_count": graph.integer(graph.top["CatacombEnrollmentCount"], "enrollment count"),
        "current_time": graph.date(graph.top["CatacombCurrentDate"], "master date"),
    }


def read_biolockout(data: bytes) -> dict[str, Any]:
    graph = Graph(data)
    if set(graph.top) != {"BioLockoutRecordSecureData", "BioLockoutRecordVersion"} or graph.top["BioLockoutRecordVersion"] != 0x10000:
        raise OracleError("invalid bio-lockout top")
    secure = graph.data(
        graph.top["BioLockoutRecordSecureData"], b"HRLB", "bio-lockout secure data"
    )
    return {
        "component": "biolockout",
        "secure_sha256": _digest(secure),
        "secure_length": len(secure),
    }


def read_user(data: bytes, expected_user_id: int) -> dict[str, Any]:
    graph = Graph(data)
    expected = {
        "CatacombVersion",
        "CatacombSecureData",
        "CatacombUserKeybagUUID",
        "CatacombUserID",
        "CatacombIdentityList",
        "CatacombUserUUID",
    }
    if set(graph.top) != expected or graph.top["CatacombVersion"] != 0x30000 or graph.top["CatacombUserID"] != expected_user_id:
        raise OracleError("invalid user top")
    secure = graph.data(graph.top["CatacombSecureData"], b"LTFC", "user secure data")
    array = graph.classed(
        graph.top["CatacombIdentityList"], "NSMutableArray", {"NS.objects"}, "identity list"
    )
    references = array["NS.objects"]
    if not isinstance(references, list) or len(references) > 10:
        raise OracleError("invalid identity array")
    identities = []
    accessories = []
    for reference in references:
        item = graph.classed(
            reference,
            "BiometricKitIdentity",
            {
                "BKIdentityMatchCount",
                "BKIdentityCreationTime",
                "BKIdentityEntityNumber",
                "BKIdentityUUID",
                "BKIdentityFlags",
                "BKIdentityMatchCountContinuous",
                "BKIdentityName",
                "BKIdentityType",
                "BKIdentityAccessory",
                "BKIdentityUpdateCount",
                "BKIdentityUserID",
                "BKIdentityAttribute",
            },
            "identity",
        )
        user_id = graph.integer(item["BKIdentityUserID"], "identity user ID")
        if user_id != expected_user_id:
            raise OracleError("foreign identity user")
        accessory = graph.classed(
            item["BKIdentityAccessory"],
            "BiometricKitAccessory",
            {"BKAccessoryUUID", "BKAccessoryFlags", "BKAccessoryName", "BKAccessoryType", "BKAccessoryGroup"},
            "accessory",
        )
        group = graph.classed(
            accessory["BKAccessoryGroup"],
            "BiometricKitAccessoryGroup",
            {"BKAccessoryGroupName", "BKAccessoryGroupType", "BKAccessoryGroupUUID"},
            "accessory group",
        )
        accessory_model = {
            "uuid": graph.raw_uuid(accessory["BKAccessoryUUID"], "accessory UUID"),
            "flags": graph.integer(accessory["BKAccessoryFlags"], "accessory flags"),
            "name": graph.text(accessory["BKAccessoryName"], "accessory name"),
            "type": graph.integer(accessory["BKAccessoryType"], "accessory type"),
            "group_uuid": graph.raw_uuid(group["BKAccessoryGroupUUID"], "group UUID"),
            "group_name": graph.text(group["BKAccessoryGroupName"], "group name"),
            "group_type": graph.integer(group["BKAccessoryGroupType"], "group type"),
        }
        accessories.append((graph.index(item["BKIdentityAccessory"], "accessory"), accessory_model))
        identities.append(
            {
                "uuid": graph.raw_uuid(item["BKIdentityUUID"], "identity UUID"),
                "user_id": user_id,
                "entity": graph.integer(item["BKIdentityEntityNumber"], "identity entity"),
                "name": graph.text(item["BKIdentityName"], "identity name"),
                "identity_type": graph.integer(item["BKIdentityType"], "identity type"),
                "flags": graph.integer(item["BKIdentityFlags"], "identity flags"),
                "attribute": graph.integer(item["BKIdentityAttribute"], "identity attribute"),
                "match_count": graph.integer(item["BKIdentityMatchCount"], "match count"),
                "continuous_match_count": graph.integer(
                    item["BKIdentityMatchCountContinuous"], "continuous match count"
                ),
                "update_count": graph.integer(item["BKIdentityUpdateCount"], "update count"),
                "creation_time": graph.date(item["BKIdentityCreationTime"], "creation time"),
            }
        )
    if len({item["uuid"] for item in identities}) != len(identities) or len(
        {item["entity"] for item in identities}
    ) != len(identities):
        raise OracleError("duplicate identity UUID/entity")
    if len({index for index, _model in accessories}) > 1 or any(
        model
        != {
            "uuid": str(uuid.UUID(int=0)),
            "flags": 6,
            "name": "Builtin",
            "type": 1,
            "group_uuid": str(uuid.UUID(int=0)),
            "group_name": "Builtin",
            "group_type": 1,
        }
        for _index, model in accessories
    ):
        raise OracleError("unsupported accessory model")
    return {
        "component": "user",
        "user_id": expected_user_id,
        "account_uuid": graph.archived_uuid(graph.top["CatacombUserUUID"], "account UUID"),
        "keybag_uuid": graph.archived_uuid(graph.top["CatacombUserKeybagUUID"], "keybag UUID"),
        "secure_sha256": _digest(secure),
        "secure_length": len(secure),
        "identities": identities,
    }
