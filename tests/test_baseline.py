# SPDX-License-Identifier: GPL-2.0-only
import io
import plistlib
import tarfile
import tempfile
import unittest
import uuid
from pathlib import Path

from src import t2_baseline
from src import t2_mutation_journal


def uid(value):
    return plistlib.UID(value)


IDENTITY_UUID = "00000000-0000-0000-0000-000000000010"
ACCOUNT_UUID = "00000000-0000-0000-0000-000000000011"
BAG_UUID = "00000000-0000-0000-0000-000000000012"
CATACOMB_UUID = "00000000-0000-0000-0000-000000000013"


def keyed(top, objects):
    return plistlib.dumps(
        {
            "$archiver": "NSKeyedArchiver",
            "$version": 100000,
            "$top": top,
            "$objects": objects,
        },
        fmt=plistlib.FMT_BINARY,
        sort_keys=False,
    )


def user_component():
    objects = [
        "$null",
        {"NS.objects": [uid(2)]},
        {
            "BKIdentityUserID": 501,
            "BKIdentityEntityNumber": 0,
            "BKIdentityUUID": uuid.UUID(IDENTITY_UUID).bytes,
        },
        {"NS.uuidbytes": uuid.UUID(ACCOUNT_UUID).bytes},
        {"NS.uuidbytes": uuid.UUID(BAG_UUID).bytes},
    ]
    return keyed(
        {
            "CatacombVersion": 0x30000,
            "CatacombUserID": 501,
            "CatacombIdentityList": uid(1),
            "CatacombUserUUID": uid(3),
            "CatacombUserKeybagUUID": uid(4),
        },
        objects,
    )


def write_archive(path):
    components = {
        "master.cat": keyed(
            {"CatacombVersion": 0x30000, "CatacombEnrollmentCount": 2},
            ["$null"],
        ),
        "user_000001f5.cat": user_component(),
        "biolockout.cat": keyed({"BioLockoutRecordVersion": 0x10000}, ["$null"]),
        "source-stat.txt": (
            b"-rw-r--r-- root:wheel 100 1 /Library/Catacomb/TEST/master.cat\n"
            b"-rw-r--r-- root:wheel 100 1 /Library/Catacomb/TEST/user_000001f5.cat\n"
            b"-rw-r--r-- root:wheel 100 1 /Library/Catacomb/TEST/biolockout.cat\n"
        ),
    }
    with tarfile.open(path, "w:gz") as archive:
        for name, data in components.items():
            info = tarfile.TarInfo(f"capture/{name}")
            info.size = len(data)
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            archive.addfile(info, io.BytesIO(data))


def live_inventory(identity_uuid=IDENTITY_UUID):
    return {
        "schema_version": 1,
        "connection_generation": "00000000-0000-0000-0000-000000000020",
        "bridge_boot_uuid": None,
        "biometric_protocol_version": 2,
        "apple_uid": 501,
        "per_user_identity_records": [
            {"user_id": 501, "identity_uuid": identity_uuid}
        ],
        "global_identity_records": [],
        "maximum_capacity": 5,
        "configured_user_free_capacity": 2,
        "catacomb": {
            "uuid": CATACOMB_UUID,
            "present": True,
            "hash": "a" * 64,
            "global_state": "00" * 16,
        },
        "sks_lock_state_raw": 0,
        "double_collection_equal": True,
    }


class BaselineTests(unittest.TestCase):
    def test_archive_and_live_inventory_build_valid_journal_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.tar.gz"
            write_archive(path)
            host = t2_baseline.read_host_archive(path, 501)
            baseline = t2_baseline.build_baseline(
                host=host,
                live=live_inventory(),
                caller_linux_uid=1000,
                target_linux_uid=1000,
                linux_boot_uuid="00000000-0000-0000-0000-000000000021",
                mapping_generation="b" * 64,
                backup_reference="backup-1",
                password_fallback_verified=True,
            )
            t2_mutation_journal.validate_baseline(baseline)
            self.assertEqual(baseline["identity_records"][0]["uuid"], IDENTITY_UUID)

    def test_rejects_live_host_identity_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.tar.gz"
            write_archive(path)
            host = t2_baseline.read_host_archive(path, 501)
            with self.assertRaises(t2_baseline.BaselineError):
                t2_baseline.build_baseline(
                    host=host,
                    live=live_inventory("00000000-0000-0000-0000-000000000099"),
                    caller_linux_uid=1000,
                    target_linux_uid=1000,
                    linux_boot_uuid="00000000-0000-0000-0000-000000000021",
                    mapping_generation="b" * 64,
                    backup_reference="backup-1",
                    password_fallback_verified=True,
                )

    def test_rejects_wrong_archive_user(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.tar.gz"
            write_archive(path)
            with self.assertRaises(t2_baseline.BaselineError):
                t2_baseline.read_host_archive(path, 502)


if __name__ == "__main__":
    unittest.main()
