# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
import plistlib
import tempfile
import unittest
import uuid
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "enrollment_research/scripts/inspect-catacomb.py"
SPEC = importlib.util.spec_from_file_location("inspect_catacomb", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def uid(value):
    return plistlib.UID(value)


def user_fixture():
    objects = [
        "$null",
        {"NS.objects": [uid(2)], "$class": uid(3)},
        {
            "BKIdentityName": uid(11),
            "BKIdentityType": 1,
            "BKIdentityUserID": 501,
            "BKIdentityEntityNumber": 0,
            "BKIdentityAttribute": 0,
            "BKIdentityFlags": 0,
            "BKIdentityMatchCount": 4,
            "BKIdentityMatchCountContinuous": 1,
            "BKIdentityUpdateCount": 2,
            "BKIdentityCreationTime": uid(4),
            "BKIdentityUUID": uuid.UUID(int=1).bytes,
            "$class": uid(5),
        },
        {"$classname": "NSMutableArray", "$classes": ["NSMutableArray", "NSArray", "NSObject"]},
        {"NS.time": 0.0, "$class": uid(7)},
        {"$classname": "BiometricKitIdentity", "$classes": ["BiometricKitIdentity", "NSObject"]},
        {"NS.uuidbytes": uuid.UUID(int=1).bytes, "$class": uid(8)},
        {"$classname": "NSDate", "$classes": ["NSDate", "NSObject"]},
        {"$classname": "NSUUID", "$classes": ["NSUUID", "NSObject"]},
        {"NS.uuidbytes": uuid.UUID(int=2).bytes, "$class": uid(8)},
        {"NS.uuidbytes": uuid.UUID(int=3).bytes, "$class": uid(8)},
        "Finger 1",
    ]
    return {
        "$archiver": "NSKeyedArchiver",
        "$version": 100000,
        "$objects": objects,
        "$top": {
            "CatacombVersion": 196608,
            "CatacombUserID": 501,
            "CatacombIdentityList": uid(1),
            "CatacombUserUUID": uid(9),
            "CatacombUserKeybagUUID": uid(10),
        },
    }


class InspectCatacombTests(unittest.TestCase):
    def inspect_fixture(self, include_identifiers=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "user.cat"
            path.write_bytes(plistlib.dumps(user_fixture(), fmt=plistlib.FMT_BINARY, sort_keys=False))
            return MODULE.inspect(path, include_identifiers)

    def test_default_inventory_redacts_all_uuids(self):
        result = self.inspect_fixture()
        self.assertEqual(result["identity_count"], 1)
        self.assertEqual(result["identities"][0]["name"], "Finger 1")
        self.assertFalse(result["anatomical_finger_positions_present"])
        self.assertNotIn("user_uuid", result)
        self.assertNotIn("identity_uuid", result["identities"][0])

    def test_identifier_output_requires_explicit_option(self):
        result = self.inspect_fixture(True)
        self.assertEqual(result["user_uuid"], "00000000-0000-0000-0000-000000000002")
        self.assertEqual(
            result["identities"][0]["identity_uuid"],
            "00000000-0000-0000-0000-000000000001",
        )

    def test_rejects_non_keyed_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.plist"
            path.write_bytes(plistlib.dumps({"not": "a catacomb"}))
            with self.assertRaises(MODULE.CatacombError):
                MODULE.inspect(path)


if __name__ == "__main__":
    unittest.main()
