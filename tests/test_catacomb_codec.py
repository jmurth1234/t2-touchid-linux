# SPDX-License-Identifier: GPL-2.0-only
import datetime as dt
import plistlib
import sys
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
import t2_catacomb_codec as codec


def descriptor(name, *parents):
    return {"$classname": name, "$classes": [name, *parents]}


def fixture(user_id=501):
    identity_uuid = uuid.UUID(int=1)
    account_uuid = uuid.UUID(int=2)
    bag_uuid = uuid.UUID(int=3)
    objects = [
        "$null",
        {"NS.data": b"LTFC" + b"s" * 28, "$class": plistlib.UID(2)},
        descriptor("NSMutableData", "NSData", "NSObject"),
        {"NS.objects": [plistlib.UID(4)], "$class": plistlib.UID(14)},
        {
            "BKIdentityMatchCount": 0,
            "BKIdentityCreationTime": plistlib.UID(6),
            "BKIdentityEntityNumber": 0,
            "BKIdentityUUID": identity_uuid.bytes,
            "BKIdentityFlags": 0,
            "BKIdentityMatchCountContinuous": 0,
            "BKIdentityName": plistlib.UID(5),
            "BKIdentityType": 1,
            "BKIdentityAccessory": plistlib.UID(8),
            "BKIdentityUpdateCount": 1,
            "BKIdentityUserID": user_id,
            "BKIdentityAttribute": 0,
            "$class": plistlib.UID(12),
        },
        "Right index finger",
        {"NS.time": 700000000.0, "$class": plistlib.UID(7)},
        descriptor("NSDate", "NSObject"),
        {
            "BKAccessoryUUID": b"\0" * 16,
            "BKAccessoryFlags": 6,
            "BKAccessoryName": plistlib.UID(9),
            "BKAccessoryType": 1,
            "BKAccessoryGroup": plistlib.UID(10),
            "$class": plistlib.UID(11),
        },
        "Builtin",
        {
            "BKAccessoryGroupName": plistlib.UID(9),
            "BKAccessoryGroupType": 1,
            "BKAccessoryGroupUUID": b"\0" * 16,
            "$class": plistlib.UID(13),
        },
        descriptor("BiometricKitAccessory", "NSObject"),
        descriptor("BiometricKitIdentity", "NSObject"),
        descriptor("BiometricKitAccessoryGroup", "NSObject"),
        descriptor("NSMutableArray", "NSArray", "NSObject"),
        {"NS.uuidbytes": account_uuid.bytes, "$class": plistlib.UID(16)},
        descriptor("NSUUID", "NSObject"),
        {"NS.uuidbytes": bag_uuid.bytes, "$class": plistlib.UID(16)},
    ]
    root = {
        "$version": 100000,
        "$archiver": "NSKeyedArchiver",
        "$top": {
            "CatacombVersion": 0x30000,
            "CatacombSecureData": plistlib.UID(1),
            "CatacombUserKeybagUUID": plistlib.UID(17),
            "CatacombUserID": user_id,
            "CatacombIdentityList": plistlib.UID(3),
            "CatacombUserUUID": plistlib.UID(15),
        },
        "$objects": objects,
    }
    return plistlib.dumps(root, fmt=plistlib.FMT_BINARY, sort_keys=False)


def master_fixture():
    return plistlib.dumps(
        {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {
                "CatacombVersion": 0x30000,
                "CatacombSecureData": plistlib.UID(1),
                "CatacombCurrentDate": plistlib.UID(3),
                "CatacombUserID": -1,
                "CatacombEnrollmentCount": 2,
            },
            "$objects": [
                "$null",
                {"NS.data": b"LTFC" + b"m" * 28, "$class": plistlib.UID(2)},
                descriptor("NSMutableData", "NSData", "NSObject"),
                {"NS.time": 700000000.0, "$class": plistlib.UID(4)},
                descriptor("NSDate", "NSObject"),
            ],
        },
        fmt=plistlib.FMT_BINARY,
        sort_keys=False,
    )


def biolockout_fixture():
    return plistlib.dumps(
        {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {
                "BioLockoutRecordSecureData": plistlib.UID(1),
                "BioLockoutRecordVersion": 0x10000,
            },
            "$objects": [
                "$null",
                {"NS.data": b"HRLB" + b"b" * 28, "$class": plistlib.UID(2)},
                descriptor("NSMutableData", "NSData", "NSObject"),
            ],
        },
        fmt=plistlib.FMT_BINARY,
        sort_keys=False,
    )


class CatacombCodecTests(unittest.TestCase):
    def test_master_round_trip_and_typed_replacement(self):
        before = codec.decode_master_catacomb(master_fixture())
        replacement = b"LTFC" + b"n" * 28
        output = before.encode(
            secure_data=replacement,
            enrollment_count=3,
            current_time=710000000.0,
        )
        after = codec.decode_master_catacomb(output)
        self.assertEqual(after.secure_data, replacement)
        self.assertEqual(after.enrollment_count, 3)
        self.assertEqual(after.current_time, 710000000.0)

    def test_biolockout_round_trip_and_typed_replacement(self):
        before = codec.decode_biolockout_catacomb(biolockout_fixture())
        replacement = b"HRLB" + b"n" * 28
        output = before.encode(secure_data=replacement)
        self.assertEqual(
            codec.decode_biolockout_catacomb(output).secure_data,
            replacement,
        )

    def test_secure_envelope_type_cannot_cross_components(self):
        with self.assertRaisesRegex(codec.CatacombCodecError, "secure envelope"):
            codec.decode_master_catacomb(master_fixture()).encode(
                secure_data=b"HRLB" + b"x" * 28
            )
        with self.assertRaisesRegex(codec.CatacombCodecError, "secure envelope"):
            codec.decode_biolockout_catacomb(biolockout_fixture()).encode(
                secure_data=b"LTFC" + b"x" * 28
            )

    def test_decodes_strict_known_schema(self):
        decoded = codec.decode_user_catacomb(fixture(), 501)
        self.assertEqual(decoded.account_uuid, str(uuid.UUID(int=2)))
        self.assertEqual(decoded.keybag_uuid, str(uuid.UUID(int=3)))
        self.assertEqual(len(decoded.identities), 1)
        self.assertEqual(decoded.identities[0].uuid, str(uuid.UUID(int=1)))

    def test_rename_round_trip_preserves_bindings_and_secure_data(self):
        before = codec.decode_user_catacomb(fixture(), 501)
        output = before.rename(str(uuid.UUID(int=1)), "Renamed finger")
        after = codec.decode_user_catacomb(output, 501)
        self.assertEqual(after.identities[0].name, "Renamed finger")
        self.assertEqual(after.secure_data, before.secure_data)
        self.assertEqual(after.account_uuid, before.account_uuid)
        self.assertEqual(after.keybag_uuid, before.keybag_uuid)

    def test_delete_round_trip_removes_only_target_identity(self):
        before = codec.decode_user_catacomb(fixture(), 501)
        with_two = codec.decode_user_catacomb(
            before.add(
                identity_uuid=str(uuid.UUID(int=4)),
                entity=1,
                name="Second finger",
                created=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc),
            ),
            501,
        )
        output = with_two.delete(str(uuid.UUID(int=4)))
        after = codec.decode_user_catacomb(output, 501)
        self.assertEqual(len(after.identities), 1)
        self.assertEqual(after.identities[0].uuid, str(uuid.UUID(int=1)))
        self.assertEqual(after.secure_data, before.secure_data)

    def test_refuses_unverified_zero_identity_encoding(self):
        decoded = codec.decode_user_catacomb(fixture(), 501)
        with self.assertRaisesRegex(codec.CatacombCodecError, "zero-identity"):
            decoded.delete(str(uuid.UUID(int=1)))

    def test_absent_sep_replacement_preserves_one_identity_schema(self):
        before = codec.decode_user_catacomb(fixture(), 501)
        replacement_uuid = str(uuid.UUID(int=9))
        output = before.replace_only_for_absent_sep(
            identity_uuid=replacement_uuid,
            entity=0,
            name="right-index-finger",
            created=dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc),
            absent_sep_attested=True,
        )
        after = codec.decode_user_catacomb(output, 501)
        self.assertEqual(len(after.identities), 1)
        self.assertEqual(after.identities[0].uuid, replacement_uuid)
        self.assertEqual(after.identities[0].name, "right-index-finger")
        self.assertEqual(after.secure_data, before.secure_data)

    def test_add_round_trip_uses_pinned_user_and_unique_entity(self):
        before = codec.decode_user_catacomb(fixture(), 501)
        new_uuid = str(uuid.UUID(int=4))
        output = before.add(
            identity_uuid=new_uuid,
            entity=1,
            name="Left index finger",
            created=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc),
        )
        after = codec.decode_user_catacomb(output, 501)
        self.assertEqual(len(after.identities), 2)
        added = next(item for item in after.identities if item.uuid == new_uuid)
        self.assertEqual(added.user_id, 501)
        self.assertEqual(added.entity, 1)
        self.assertEqual(added.name, "Left index finger")
        self.assertEqual(after.secure_data, before.secure_data)

    def test_rejects_unknown_identity_field(self):
        root = plistlib.loads(fixture())
        root["$objects"][4]["Unexpected"] = 1
        data = plistlib.dumps(root, fmt=plistlib.FMT_BINARY)
        with self.assertRaisesRegex(codec.CatacombCodecError, "unknown schema"):
            codec.decode_user_catacomb(data, 501)

    def test_rejects_foreign_user_identity(self):
        root = plistlib.loads(fixture())
        root["$objects"][4]["BKIdentityUserID"] = 502
        data = plistlib.dumps(root, fmt=plistlib.FMT_BINARY)
        with self.assertRaisesRegex(codec.CatacombCodecError, "another user"):
            codec.decode_user_catacomb(data, 501)

    def test_rejects_duplicate_entity_on_add(self):
        decoded = codec.decode_user_catacomb(fixture(), 501)
        with self.assertRaisesRegex(codec.CatacombCodecError, "entity already exists"):
            decoded.add(identity_uuid=str(uuid.UUID(int=5)), entity=0, name="Duplicate")

    def test_rejects_wrong_class_inheritance_chain(self):
        root = plistlib.loads(fixture())
        root["$objects"][12]["$classes"] = ["BiometricKitIdentity", "NSData", "NSObject"]
        data = plistlib.dumps(root, fmt=plistlib.FMT_BINARY)
        with self.assertRaisesRegex(codec.CatacombCodecError, "invalid class descriptor"):
            codec.decode_user_catacomb(data, 501)

    def test_rejects_unreachable_allowed_object(self):
        root = plistlib.loads(fixture())
        root["$objects"].append("orphan")
        data = plistlib.dumps(root, fmt=plistlib.FMT_BINARY)
        with self.assertRaisesRegex(codec.CatacombCodecError, "unreachable"):
            codec.decode_user_catacomb(data, 501)


if __name__ == "__main__":
    unittest.main()
