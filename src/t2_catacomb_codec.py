#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Strict primitive-only codec for version-3 BiometricKit user Catacombs.

The codec never instantiates archived Objective-C classes.  It validates the
known NSKeyedArchiver graph as plist primitives and UID references, preserves
the opaque secure envelope, and exposes narrowly typed identity edits.
"""

from __future__ import annotations

import datetime as dt
import dataclasses
import hashlib
import math
import plistlib
import uuid
from dataclasses import dataclass
from typing import Any

from t2_catacomb_oracle import read_biolockout, read_master, read_user


MAX_FILE_BYTES = 1024 * 1024
MAX_OBJECTS = 256
MAX_IDENTITIES = 10
MAX_STRING_BYTES = 1024
APPLE_EPOCH = dt.datetime(2001, 1, 1, tzinfo=dt.timezone.utc)

ROOT_KEYS = {"$version", "$archiver", "$top", "$objects"}
TOP_KEYS = {
    "CatacombVersion",
    "CatacombSecureData",
    "CatacombUserKeybagUUID",
    "CatacombUserID",
    "CatacombIdentityList",
    "CatacombUserUUID",
}
IDENTITY_KEYS = {
    "$class",
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
}
ACCESSORY_KEYS = {
    "$class",
    "BKAccessoryUUID",
    "BKAccessoryFlags",
    "BKAccessoryName",
    "BKAccessoryType",
    "BKAccessoryGroup",
}
GROUP_KEYS = {
    "$class",
    "BKAccessoryGroupName",
    "BKAccessoryGroupType",
    "BKAccessoryGroupUUID",
}
ALLOWED_CLASSES = {
    "NSMutableData",
    "NSMutableArray",
    "BiometricKitIdentity",
    "NSDate",
    "BiometricKitAccessory",
    "BiometricKitAccessoryGroup",
    "NSUUID",
}
CLASS_CHAINS = {
    "NSMutableData": ["NSMutableData", "NSData", "NSObject"],
    "NSMutableArray": ["NSMutableArray", "NSArray", "NSObject"],
    "BiometricKitIdentity": ["BiometricKitIdentity", "NSObject"],
    "NSDate": ["NSDate", "NSObject"],
    "BiometricKitAccessory": ["BiometricKitAccessory", "NSObject"],
    "BiometricKitAccessoryGroup": ["BiometricKitAccessoryGroup", "NSObject"],
    "NSUUID": ["NSUUID", "NSObject"],
}


class CatacombCodecError(ValueError):
    pass


@dataclass(frozen=True)
class Identity:
    uuid: str
    user_id: int
    entity: int
    name: str
    identity_type: int
    flags: int
    attribute: int
    match_count: int
    continuous_match_count: int
    update_count: int
    creation_time: float


def _bounded_int(value: Any, field: str, maximum: int = 0xFFFFFFFF) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        raise CatacombCodecError(f"{field} is not a bounded non-negative integer")
    return value


def _uuid(raw: Any, field: str) -> str:
    if not isinstance(raw, bytes) or len(raw) != 16:
        raise CatacombCodecError(f"{field} is not a 16-byte UUID")
    return str(uuid.UUID(bytes=raw))


def _secure_envelope(data: Any, magic: bytes, field: str) -> bytes:
    if (
        not isinstance(data, bytes)
        or not 16 <= len(data) <= MAX_FILE_BYTES
        or data[:4] != magic
    ):
        raise CatacombCodecError(f"{field} has an invalid secure envelope")
    return data


class UserCatacomb:
    def __init__(self, data: bytes, expected_user_id: int) -> None:
        if not isinstance(data, bytes) or not 0 < len(data) <= MAX_FILE_BYTES:
            raise CatacombCodecError("Catacomb file size is outside policy")
        if not data.startswith(b"bplist00"):
            raise CatacombCodecError("Catacomb must be a binary plist")
        try:
            root = plistlib.loads(data)
        except (plistlib.InvalidFileException, ValueError, OverflowError) as error:
            raise CatacombCodecError("Catacomb is not a valid binary plist") from error
        if not isinstance(root, dict) or set(root) != ROOT_KEYS:
            raise CatacombCodecError("Catacomb root schema is unknown")
        if root["$version"] != 100000 or root["$archiver"] != "NSKeyedArchiver":
            raise CatacombCodecError("unsupported keyed-archive version")
        if not isinstance(root["$top"], dict) or set(root["$top"]) != TOP_KEYS:
            raise CatacombCodecError("user Catacomb top schema is unknown")
        if not isinstance(root["$objects"], list) or not 1 <= len(root["$objects"]) <= MAX_OBJECTS:
            raise CatacombCodecError("keyed-archive object count is outside policy")
        self.root = root
        self.top = root["$top"]
        self.objects = root["$objects"]
        self.expected_user_id = _bounded_int(expected_user_id, "expected user ID")
        if self.top["CatacombVersion"] != 0x30000:
            raise CatacombCodecError("unsupported Catacomb version")
        if self.top["CatacombUserID"] != self.expected_user_id:
            raise CatacombCodecError("Catacomb user ID does not match pinned user")
        self._validate_all_objects()
        self._validate_reachability()
        self.secure_data = self._secure_data()
        self.account_uuid = self._archived_uuid(self.top["CatacombUserUUID"], "account UUID")
        self.keybag_uuid = self._archived_uuid(
            self.top["CatacombUserKeybagUUID"], "keybag UUID"
        )
        self.array_index, self.identity_indices = self._identity_array()
        self.identities = tuple(self._identity(index) for index in self.identity_indices)
        if len({item.uuid for item in self.identities}) != len(self.identities):
            raise CatacombCodecError("identity UUIDs are not unique")
        if len({item.entity for item in self.identities}) != len(self.identities):
            raise CatacombCodecError("identity entity numbers are not unique")
        accessory_indices = {
            self._index(self.objects[index]["BKIdentityAccessory"], "identity accessory")
            for index in self.identity_indices
        }
        if len(accessory_indices) > 1:
            raise CatacombCodecError("built-in identities do not share one accessory")

    def _index(self, value: Any, field: str) -> int:
        if not isinstance(value, plistlib.UID) or not 0 <= value.data < len(self.objects):
            raise CatacombCodecError(f"{field} is not an in-range object reference")
        return value.data

    def _object(self, value: Any, field: str) -> Any:
        return self.objects[self._index(value, field)]

    def _class_name(self, value: dict[str, Any], field: str) -> str:
        descriptor = self._object(value.get("$class"), f"{field} class")
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != {"$classname", "$classes"}
            or not isinstance(descriptor.get("$classname"), str)
            or not isinstance(descriptor.get("$classes"), list)
            or not descriptor["$classes"]
            or descriptor["$classes"][0] != descriptor["$classname"]
            or descriptor["$classes"] != CLASS_CHAINS.get(descriptor["$classname"])
        ):
            raise CatacombCodecError(f"{field} has an invalid class descriptor")
        name = descriptor["$classname"]
        if name not in ALLOWED_CLASSES:
            raise CatacombCodecError(f"{field} uses disallowed class {name}")
        return name

    def _validate_all_objects(self) -> None:
        if self.objects[0] != "$null":
            raise CatacombCodecError("keyed archive has no null sentinel")
        aggregate = 0
        for index, value in enumerate(self.objects):
            if isinstance(value, str):
                aggregate += len(value.encode("utf-8"))
                if len(value.encode("utf-8")) > MAX_STRING_BYTES:
                    raise CatacombCodecError(f"object {index} string exceeds policy")
            elif isinstance(value, bytes):
                aggregate += len(value)
            elif isinstance(value, dict):
                if "$class" in value:
                    self._class_name(value, f"object {index}")
                elif set(value) != {"$classname", "$classes"}:
                    raise CatacombCodecError(f"object {index} is an unknown dictionary")
            elif not isinstance(value, (int, float, bool)):
                raise CatacombCodecError(f"object {index} has an unsupported primitive")
        if aggregate > MAX_FILE_BYTES:
            raise CatacombCodecError("aggregate decoded data exceeds policy")

    def _validate_reachability(self) -> None:
        reached: set[int] = set()
        active: set[int] = set()

        def visit(value: Any) -> None:
            if isinstance(value, plistlib.UID):
                index = self._index(value, "object graph")
                if index == 0:
                    return
                if index in active:
                    raise CatacombCodecError("keyed-archive object graph contains a cycle")
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
        expected = set(range(1, len(self.objects)))
        if reached != expected:
            raise CatacombCodecError("keyed archive contains unreachable objects")

    def _secure_data(self) -> bytes:
        value = self._object(self.top["CatacombSecureData"], "secure data")
        if (
            not isinstance(value, dict)
            or set(value) != {"$class", "NS.data"}
            or self._class_name(value, "secure data") != "NSMutableData"
            or not isinstance(value["NS.data"], bytes)
            or not 16 <= len(value["NS.data"]) <= MAX_FILE_BYTES
        ):
            raise CatacombCodecError("secure data object is malformed")
        return _secure_envelope(value["NS.data"], b"LTFC", "Catacomb secure data")

    def _archived_uuid(self, reference: Any, field: str) -> str:
        value = self._object(reference, field)
        if (
            not isinstance(value, dict)
            or set(value) != {"$class", "NS.uuidbytes"}
            or self._class_name(value, field) != "NSUUID"
        ):
            raise CatacombCodecError(f"{field} object is malformed")
        return _uuid(value["NS.uuidbytes"], field)

    def _identity_array(self) -> tuple[int, list[int]]:
        index = self._index(self.top["CatacombIdentityList"], "identity list")
        value = self.objects[index]
        if (
            not isinstance(value, dict)
            or set(value) != {"$class", "NS.objects"}
            or self._class_name(value, "identity list") != "NSMutableArray"
            or not isinstance(value["NS.objects"], list)
            or len(value["NS.objects"]) > MAX_IDENTITIES
        ):
            raise CatacombCodecError("identity list is malformed")
        return index, [self._index(item, "identity") for item in value["NS.objects"]]

    def _string(self, reference: Any, field: str) -> str:
        value = self._object(reference, field)
        if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise CatacombCodecError(f"{field} is not a bounded string")
        return value

    def _date(self, reference: Any) -> float:
        value = self._object(reference, "identity creation time")
        if (
            not isinstance(value, dict)
            or set(value) != {"$class", "NS.time"}
            or self._class_name(value, "identity creation time") != "NSDate"
            or not isinstance(value["NS.time"], (int, float))
            or isinstance(value["NS.time"], bool)
            or not math.isfinite(value["NS.time"])
        ):
            raise CatacombCodecError("identity creation time is malformed")
        return float(value["NS.time"])

    def _validate_accessory(self, reference: Any) -> None:
        accessory = self._object(reference, "identity accessory")
        if (
            not isinstance(accessory, dict)
            or set(accessory) != ACCESSORY_KEYS
            or self._class_name(accessory, "identity accessory") != "BiometricKitAccessory"
        ):
            raise CatacombCodecError("identity accessory is malformed")
        _uuid(accessory["BKAccessoryUUID"], "accessory UUID")
        _bounded_int(accessory["BKAccessoryFlags"], "accessory flags")
        _bounded_int(accessory["BKAccessoryType"], "accessory type")
        self._string(accessory["BKAccessoryName"], "accessory name")
        group = self._object(accessory["BKAccessoryGroup"], "accessory group")
        if (
            not isinstance(group, dict)
            or set(group) != GROUP_KEYS
            or self._class_name(group, "accessory group") != "BiometricKitAccessoryGroup"
        ):
            raise CatacombCodecError("accessory group is malformed")
        _uuid(group["BKAccessoryGroupUUID"], "accessory group UUID")
        _bounded_int(group["BKAccessoryGroupType"], "accessory group type")
        self._string(group["BKAccessoryGroupName"], "accessory group name")
        if not (
            accessory["BKAccessoryUUID"] == b"\0" * 16
            and accessory["BKAccessoryFlags"] == 6
            and accessory["BKAccessoryType"] == 1
            and self._string(accessory["BKAccessoryName"], "accessory name") == "Builtin"
            and group["BKAccessoryGroupUUID"] == b"\0" * 16
            and group["BKAccessoryGroupType"] == 1
            and self._string(group["BKAccessoryGroupName"], "accessory group name") == "Builtin"
        ):
            raise CatacombCodecError("unsupported non-built-in accessory metadata")

    def _identity(self, index: int) -> Identity:
        value = self.objects[index]
        if (
            not isinstance(value, dict)
            or set(value) != IDENTITY_KEYS
            or self._class_name(value, "identity") != "BiometricKitIdentity"
        ):
            raise CatacombCodecError("identity object has an unknown schema")
        user_id = _bounded_int(value["BKIdentityUserID"], "identity user ID")
        if user_id != self.expected_user_id:
            raise CatacombCodecError("identity belongs to another user")
        self._validate_accessory(value["BKIdentityAccessory"])
        return Identity(
            uuid=_uuid(value["BKIdentityUUID"], "identity UUID"),
            user_id=user_id,
            entity=_bounded_int(value["BKIdentityEntityNumber"], "identity entity"),
            name=self._string(value["BKIdentityName"], "identity name"),
            identity_type=_bounded_int(value["BKIdentityType"], "identity type"),
            flags=_bounded_int(value["BKIdentityFlags"], "identity flags"),
            attribute=_bounded_int(value["BKIdentityAttribute"], "identity attribute"),
            match_count=_bounded_int(value["BKIdentityMatchCount"], "identity match count"),
            continuous_match_count=_bounded_int(
                value["BKIdentityMatchCountContinuous"], "continuous match count"
            ),
            update_count=_bounded_int(value["BKIdentityUpdateCount"], "identity update count"),
            creation_time=self._date(value["BKIdentityCreationTime"]),
        )

    def _identity_index(self, identity_uuid: str) -> int:
        target = str(uuid.UUID(identity_uuid))
        matches = [
            index
            for index, identity in zip(self.identity_indices, self.identities)
            if identity.uuid == target
        ]
        if len(matches) != 1:
            raise CatacombCodecError("target identity is not uniquely present")
        return matches[0]

    def rename(self, identity_uuid: str, name: str) -> bytes:
        if not isinstance(name, str) or not name or len(name.encode("utf-8")) > MAX_STRING_BYTES:
            raise CatacombCodecError("new identity name is invalid")
        index = self._identity_index(identity_uuid)
        position = self.identity_indices.index(index)
        identities = list(self.identities)
        identities[position] = dataclasses.replace(identities[position], name=name)
        return self._encode_and_verify(self._build_root(identities), identities)

    def delete(self, identity_uuid: str) -> bytes:
        if len(self.identities) <= 1:
            raise CatacombCodecError(
                "refusing to encode an unverified zero-identity user component"
            )
        target = self._identity_index(identity_uuid)
        identities = [
            identity
            for index, identity in zip(self.identity_indices, self.identities)
            if index != target
        ]
        return self._encode_and_verify(self._build_root(identities), identities)

    def add(
        self,
        *,
        identity_uuid: str,
        entity: int,
        name: str,
        created: dt.datetime | None = None,
    ) -> bytes:
        if not self.identities:
            raise CatacombCodecError("cannot derive built-in sensor metadata from an empty fixture")
        if len(self.identities) >= MAX_IDENTITIES:
            raise CatacombCodecError("identity capacity policy reached")
        new_uuid = str(uuid.UUID(identity_uuid))
        if new_uuid in {item.uuid for item in self.identities}:
            raise CatacombCodecError("identity UUID already exists")
        entity = _bounded_int(entity, "identity entity")
        if entity in {item.entity for item in self.identities}:
            raise CatacombCodecError("identity entity already exists")
        if not isinstance(name, str) or not name or len(name.encode("utf-8")) > MAX_STRING_BYTES:
            raise CatacombCodecError("new identity name is invalid")
        created = created or dt.datetime.now(dt.timezone.utc)
        if created.tzinfo is None:
            raise CatacombCodecError("creation time must be timezone-aware")
        seconds = (created.astimezone(dt.timezone.utc) - APPLE_EPOCH).total_seconds()
        if not math.isfinite(seconds):
            raise CatacombCodecError("creation time is invalid")

        prototype = self.identities[0]
        identities = [
            *self.identities,
            dataclasses.replace(
                prototype,
                uuid=new_uuid,
                user_id=self.expected_user_id,
                entity=entity,
                name=name,
                match_count=0,
                continuous_match_count=0,
                update_count=1,
                creation_time=seconds,
            ),
        ]
        return self._encode_and_verify(self._build_root(identities), identities)

    def replace_secure_data(self, secure_data: bytes) -> bytes:
        secure_data = _secure_envelope(
            secure_data, b"LTFC", "replacement Catacomb secure data"
        )
        return self._encode_and_verify(
            self._build_root(self.identities, secure_data=secure_data),
            self.identities,
            expected_secure_data=secure_data,
        )

    def _build_root(
        self,
        identities: list[Identity] | tuple[Identity, ...],
        *,
        secure_data: bytes | None = None,
    ) -> dict[str, Any]:
        """Build the recovered built-in user graph deterministically from semantics."""
        objects: list[Any] = [
            "$null",
            {"NS.data": self.secure_data if secure_data is None else secure_data, "$class": plistlib.UID(2)},
            {"$classname": "NSMutableData", "$classes": CLASS_CHAINS["NSMutableData"]},
            {"NS.objects": [], "$class": plistlib.UID(4)},
            {"$classname": "NSMutableArray", "$classes": CLASS_CHAINS["NSMutableArray"]},
            {"$classname": "BiometricKitIdentity", "$classes": CLASS_CHAINS["BiometricKitIdentity"]},
            {"$classname": "NSDate", "$classes": CLASS_CHAINS["NSDate"]},
            {"$classname": "BiometricKitAccessory", "$classes": CLASS_CHAINS["BiometricKitAccessory"]},
            {"$classname": "BiometricKitAccessoryGroup", "$classes": CLASS_CHAINS["BiometricKitAccessoryGroup"]},
            {"$classname": "NSUUID", "$classes": CLASS_CHAINS["NSUUID"]},
            "Builtin",
            {
                "BKAccessoryGroupName": plistlib.UID(10),
                "BKAccessoryGroupType": 1,
                "BKAccessoryGroupUUID": b"\0" * 16,
                "$class": plistlib.UID(8),
            },
            {
                "BKAccessoryUUID": b"\0" * 16,
                "BKAccessoryFlags": 6,
                "BKAccessoryName": plistlib.UID(10),
                "BKAccessoryType": 1,
                "BKAccessoryGroup": plistlib.UID(11),
                "$class": plistlib.UID(7),
            },
            {"NS.uuidbytes": uuid.UUID(self.account_uuid).bytes, "$class": plistlib.UID(9)},
            {"NS.uuidbytes": uuid.UUID(self.keybag_uuid).bytes, "$class": plistlib.UID(9)},
        ]
        references = objects[3]["NS.objects"]
        for identity in identities:
            name_index = len(objects)
            objects.append(identity.name)
            date_index = len(objects)
            objects.append({"NS.time": identity.creation_time, "$class": plistlib.UID(6)})
            identity_index = len(objects)
            objects.append(
                {
                    "BKIdentityMatchCount": identity.match_count,
                    "BKIdentityCreationTime": plistlib.UID(date_index),
                    "BKIdentityEntityNumber": identity.entity,
                    "BKIdentityUUID": uuid.UUID(identity.uuid).bytes,
                    "BKIdentityFlags": identity.flags,
                    "BKIdentityMatchCountContinuous": identity.continuous_match_count,
                    "BKIdentityName": plistlib.UID(name_index),
                    "BKIdentityType": identity.identity_type,
                    "BKIdentityAccessory": plistlib.UID(12),
                    "BKIdentityUpdateCount": identity.update_count,
                    "BKIdentityUserID": identity.user_id,
                    "BKIdentityAttribute": identity.attribute,
                    "$class": plistlib.UID(5),
                }
            )
            references.append(plistlib.UID(identity_index))
        return {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {
                "CatacombVersion": 0x30000,
                "CatacombSecureData": plistlib.UID(1),
                "CatacombUserKeybagUUID": plistlib.UID(14),
                "CatacombUserID": self.expected_user_id,
                "CatacombIdentityList": plistlib.UID(3),
                "CatacombUserUUID": plistlib.UID(13),
            },
            "$objects": objects,
        }

    def _encode_and_verify(
        self,
        root: dict[str, Any],
        expected_identities: list[Identity] | tuple[Identity, ...],
        *,
        expected_secure_data: bytes | None = None,
    ) -> bytes:
        data = plistlib.dumps(root, fmt=plistlib.FMT_BINARY, sort_keys=False)
        # Independent parse from emitted bytes proves references and schema,
        # while the opaque secure envelope must remain byte-for-byte unchanged.
        decoded = UserCatacomb(data, self.expected_user_id)
        expected_secure_data = self.secure_data if expected_secure_data is None else expected_secure_data
        if decoded.secure_data != expected_secure_data:
            raise CatacombCodecError("encoder changed opaque secure data")
        if decoded.account_uuid != self.account_uuid or decoded.keybag_uuid != self.keybag_uuid:
            raise CatacombCodecError("encoder changed account or keybag binding")
        oracle = read_user(data, self.expected_user_id)
        expected_model = [dataclasses.asdict(identity) for identity in expected_identities]
        if (
            oracle["account_uuid"] != self.account_uuid
            or oracle["keybag_uuid"] != self.keybag_uuid
            or oracle["secure_sha256"] != hashlib.sha256(expected_secure_data).hexdigest()
            or oracle["secure_length"] != len(expected_secure_data)
            or oracle["identities"] != expected_model
        ):
            raise CatacombCodecError("independent user read-back mismatch")
        return data


def decode_user_catacomb(data: bytes, expected_user_id: int) -> UserCatacomb:
    return UserCatacomb(data, expected_user_id)


class MasterCatacomb:
    TOP_KEYS = {
        "CatacombVersion",
        "CatacombSecureData",
        "CatacombCurrentDate",
        "CatacombUserID",
        "CatacombEnrollmentCount",
    }

    def __init__(self, data: bytes) -> None:
        root = _load_component_root(data, self.TOP_KEYS, 5)
        self.root = root
        objects = root["$objects"]
        top = root["$top"]
        if top["CatacombVersion"] != 0x30000 or top["CatacombUserID"] != -1:
            raise CatacombCodecError("unsupported master Catacomb identity/version")
        self.enrollment_count = _bounded_int(
            top["CatacombEnrollmentCount"], "master enrollment count"
        )
        self.secure_data = _component_data(objects, top["CatacombSecureData"], b"LTFC")
        date = _component_object(objects, top["CatacombCurrentDate"], "master date")
        if (
            not isinstance(date, dict)
            or set(date) != {"NS.time", "$class"}
            or _component_class(objects, date, "master date") != "NSDate"
            or not isinstance(date["NS.time"], (int, float))
            or isinstance(date["NS.time"], bool)
            or not math.isfinite(date["NS.time"])
        ):
            raise CatacombCodecError("master date is malformed")
        self.current_time = float(date["NS.time"])
        _require_component_reachability(root)

    def encode(
        self,
        *,
        secure_data: bytes | None = None,
        enrollment_count: int | None = None,
        current_time: float | None = None,
    ) -> bytes:
        secure_data = self.secure_data if secure_data is None else _secure_envelope(
            secure_data, b"LTFC", "replacement master secure data"
        )
        enrollment_count = self.enrollment_count if enrollment_count is None else _bounded_int(
            enrollment_count, "master enrollment count"
        )
        current_time = self.current_time if current_time is None else current_time
        if (
            not isinstance(current_time, (int, float))
            or isinstance(current_time, bool)
            or not math.isfinite(current_time)
        ):
            raise CatacombCodecError("master date is invalid")
        root = {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {
                "CatacombVersion": 0x30000,
                "CatacombSecureData": plistlib.UID(1),
                "CatacombCurrentDate": plistlib.UID(3),
                "CatacombUserID": -1,
                "CatacombEnrollmentCount": enrollment_count,
            },
            "$objects": [
                "$null",
                {"NS.data": secure_data, "$class": plistlib.UID(2)},
                {"$classname": "NSMutableData", "$classes": CLASS_CHAINS["NSMutableData"]},
                {"NS.time": float(current_time), "$class": plistlib.UID(4)},
                {"$classname": "NSDate", "$classes": CLASS_CHAINS["NSDate"]},
            ],
        }
        output = plistlib.dumps(root, fmt=plistlib.FMT_BINARY, sort_keys=False)
        decoded = MasterCatacomb(output)
        if (
            decoded.secure_data != secure_data
            or decoded.enrollment_count != enrollment_count
            or decoded.current_time != float(current_time)
        ):
            raise CatacombCodecError("master encoder read-back mismatch")
        oracle = read_master(output)
        if oracle != {
            "component": "master",
            "secure_sha256": hashlib.sha256(secure_data).hexdigest(),
            "secure_length": len(secure_data),
            "enrollment_count": enrollment_count,
            "current_time": float(current_time),
        }:
            raise CatacombCodecError("independent master read-back mismatch")
        return output


class BioLockoutCatacomb:
    TOP_KEYS = {"BioLockoutRecordSecureData", "BioLockoutRecordVersion"}

    def __init__(self, data: bytes) -> None:
        root = _load_component_root(data, self.TOP_KEYS, 3)
        if root["$top"]["BioLockoutRecordVersion"] != 0x10000:
            raise CatacombCodecError("unsupported bio-lockout version")
        self.secure_data = _component_data(
            root["$objects"], root["$top"]["BioLockoutRecordSecureData"], b"HRLB"
        )
        _require_component_reachability(root)

    def encode(self, *, secure_data: bytes | None = None) -> bytes:
        secure_data = self.secure_data if secure_data is None else _secure_envelope(
            secure_data, b"HRLB", "replacement bio-lockout secure data"
        )
        root = {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {
                "BioLockoutRecordSecureData": plistlib.UID(1),
                "BioLockoutRecordVersion": 0x10000,
            },
            "$objects": [
                "$null",
                {"NS.data": secure_data, "$class": plistlib.UID(2)},
                {"$classname": "NSMutableData", "$classes": CLASS_CHAINS["NSMutableData"]},
            ],
        }
        output = plistlib.dumps(root, fmt=plistlib.FMT_BINARY, sort_keys=False)
        if BioLockoutCatacomb(output).secure_data != secure_data:
            raise CatacombCodecError("bio-lockout encoder read-back mismatch")
        if read_biolockout(output) != {
            "component": "biolockout",
            "secure_sha256": hashlib.sha256(secure_data).hexdigest(),
            "secure_length": len(secure_data),
        }:
            raise CatacombCodecError("independent bio-lockout read-back mismatch")
        return output


def _load_component_root(data: bytes, top_keys: set[str], object_count: int) -> dict[str, Any]:
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_FILE_BYTES or not data.startswith(b"bplist00"):
        raise CatacombCodecError("component is not a bounded binary plist")
    try:
        root = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, OverflowError) as error:
        raise CatacombCodecError("component is not a valid binary plist") from error
    if (
        not isinstance(root, dict)
        or set(root) != ROOT_KEYS
        or root["$version"] != 100000
        or root["$archiver"] != "NSKeyedArchiver"
        or not isinstance(root["$top"], dict)
        or set(root["$top"]) != top_keys
        or not isinstance(root["$objects"], list)
        or len(root["$objects"]) != object_count
        or root["$objects"][0] != "$null"
    ):
        raise CatacombCodecError("component keyed-archive schema is unknown")
    return root


def _component_index(objects: list[Any], value: Any, field: str) -> int:
    if not isinstance(value, plistlib.UID) or not 0 <= value.data < len(objects):
        raise CatacombCodecError(f"{field} reference is invalid")
    return value.data


def _component_object(objects: list[Any], value: Any, field: str) -> Any:
    return objects[_component_index(objects, value, field)]


def _component_class(objects: list[Any], value: dict[str, Any], field: str) -> str:
    descriptor = _component_object(objects, value.get("$class"), f"{field} class")
    if (
        not isinstance(descriptor, dict)
        or set(descriptor) != {"$classname", "$classes"}
        or descriptor.get("$classes") != CLASS_CHAINS.get(descriptor.get("$classname"))
    ):
        raise CatacombCodecError(f"{field} class descriptor is invalid")
    return descriptor["$classname"]


def _component_data(objects: list[Any], reference: Any, magic: bytes) -> bytes:
    value = _component_object(objects, reference, "secure data")
    if (
        not isinstance(value, dict)
        or set(value) != {"NS.data", "$class"}
        or _component_class(objects, value, "secure data") != "NSMutableData"
    ):
        raise CatacombCodecError("component secure data object is malformed")
    return _secure_envelope(value["NS.data"], magic, "component secure data")


def _require_component_reachability(root: dict[str, Any]) -> None:
    objects = root["$objects"]
    reached: set[int] = set()
    active: set[int] = set()

    def visit(value: Any) -> None:
        if isinstance(value, plistlib.UID):
            index = _component_index(objects, value, "object graph")
            if index == 0:
                return
            if index in active:
                raise CatacombCodecError("component object graph contains a cycle")
            if index in reached:
                return
            active.add(index)
            visit(objects[index])
            active.remove(index)
            reached.add(index)
        elif isinstance(value, dict):
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(root["$top"])
    if reached != set(range(1, len(objects))):
        raise CatacombCodecError("component contains unreachable objects")


def decode_master_catacomb(data: bytes) -> MasterCatacomb:
    return MasterCatacomb(data)


def decode_biolockout_catacomb(data: bytes) -> BioLockoutCatacomb:
    return BioLockoutCatacomb(data)
