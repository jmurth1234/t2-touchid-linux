# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_user_mapping as mapping


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


def entry(linux_uid: int = 1000, apple_uid: int = 501) -> dict[str, object]:
    return {
        "linux_uid": linux_uid,
        "linux_account_generation": "a" * 64,
        "apple_uid": apple_uid,
        "account_uuid": identifier(apple_uid),
        "bag_uuid": identifier(apple_uid + 1000),
        "keybag_path": f"/var/lib/t2-touchid/users/{linux_uid}/user.kb",
        "keybag_sha256": "b" * 64,
        "unlock_mode": "password-on-demand",
        "capabilities": ["enroll", "verify"],
        "enabled": True,
    }


def encoded(entries: list[dict[str, object]]) -> bytes:
    return json.dumps(
        {"schema_version": 1, "mappings": entries},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


class UserMappingTests(unittest.TestCase):
    def test_parses_distinct_users_and_derives_special_alias(self):
        result = mapping.parse(encoded([entry(), entry(1001, 502)]))
        selected = result.resolve(1001, "enroll")
        self.assertEqual(selected.apple_uid, 502)
        self.assertEqual(selected.special_bag_alias, -502)
        self.assertTrue(selected.permits("verify"))
        self.assertEqual(len(result.generation), 64)

    def test_resolution_requires_enabled_explicit_capability(self):
        value = entry()
        value["enabled"] = False
        result = mapping.parse(encoded([value]))
        with self.assertRaisesRegex(mapping.UserMappingError, "does not permit"):
            result.resolve(1000, "verify")
        with self.assertRaisesRegex(mapping.UserMappingError, "unknown"):
            result.resolve(1000, "raw-sep")

    def test_summary_discloses_no_mapping_identifiers(self):
        value = entry()
        value["unlock_mode"] = "host-encrypted-credential"
        result = mapping.parse(encoded([value]))
        self.assertEqual(
            result.redacted_summary(),
            {
                "schema_version": 1,
                "mapping_count": 1,
                "enabled_mapping_count": 1,
                "password_on_demand_count": 0,
                "host_encrypted_credential_count": 1,
                "identifiers_redacted": True,
            },
        )

    def test_canonical_serialization_sorts_and_round_trips(self):
        parsed = mapping.parse(encoded([entry(1001, 502), entry()]))
        canonical = mapping.serialize(parsed.mappings)
        reparsed = mapping.parse(canonical)
        self.assertEqual(
            [item.linux_uid for item in reparsed.mappings], [1000, 1001]
        )
        self.assertEqual(reparsed, mapping.parse(mapping.serialize(reparsed.mappings)))
        self.assertTrue(canonical.endswith(b"\n"))
        with self.assertRaises(mapping.UserMappingError):
            mapping.serialize([parsed.mappings[0]])
        malformed = mapping.UserMapping(
            **{**parsed.mappings[0].__dict__, "capabilities": frozenset({1})}
        )
        # The serializer accepts typed UserMapping objects only, so malformed
        # direct construction cannot escape as a raw sorting/JSON exception.
        with self.assertRaises(mapping.UserMappingError):
            mapping.serialize((malformed,))

    def test_rejects_duplicate_authority_across_users(self):
        first = entry()
        second = entry(1001, 502)
        for field in ("apple_uid", "account_uuid", "bag_uuid"):
            with self.subTest(field=field):
                duplicate = dict(second)
                duplicate[field] = first[field]
                with self.assertRaisesRegex(mapping.UserMappingError, "more than once"):
                    mapping.parse(encoded([first, duplicate]))

    def test_rejects_noncanonical_or_unsafe_entry_fields(self):
        cases = {
            "low Apple UID": ("apple_uid", 9),
            "Boolean UID": ("linux_uid", True),
            "uppercase digest": ("keybag_sha256", "A" * 64),
            "zero UUID": ("account_uuid", str(uuid.UUID(int=0))),
            "wrong keybag path": ("keybag_path", "/tmp/user.kb"),
            "shared unlock mode": ("unlock_mode", "shared-password"),
            "unsorted capabilities": ("capabilities", ["verify", "enroll"]),
            "unknown capability": ("capabilities", ["raw-sep"]),
            "non-string capability": ("capabilities", [["verify"]]),
            "integer enabled": ("enabled", 1),
        }
        for label, (field, replacement) in cases.items():
            with self.subTest(label=label):
                value = entry()
                value[field] = replacement
                with self.assertRaises(mapping.UserMappingError):
                    mapping.parse(encoded([value]))

    def test_rejects_unknown_and_duplicate_json_fields(self):
        value = json.loads(encoded([entry()]))
        value["extra"] = True
        with self.assertRaises(mapping.UserMappingError):
            mapping.parse(json.dumps(value).encode())
        with self.assertRaisesRegex(mapping.UserMappingError, "duplicate key"):
            mapping.parse(b'{"schema_version":1,"schema_version":1,"mappings":[]}')

    def test_private_file_loader_rejects_unsafe_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "users.json"
            path.write_bytes(encoded([entry()]))
            path.chmod(0o644)
            with self.assertRaisesRegex(mapping.UserMappingError, "private"):
                mapping.load(path)

    def test_private_file_loader_accepts_root_owned_mode_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "users.json"
            content = encoded([entry()])
            path.write_bytes(content)
            path.chmod(0o600)
            descriptor = os.open(path, os.O_RDONLY)
            secure = SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600,
                st_uid=0,
                st_gid=0,
                st_nlink=1,
                st_size=len(content),
                st_dev=1,
                st_ino=2,
                st_mtime_ns=3,
                st_ctime_ns=4,
            )
            with (
                mock.patch.object(mapping.os, "open", return_value=descriptor),
                mock.patch.object(mapping.os, "fstat", return_value=secure),
            ):
                self.assertEqual(
                    mapping.load(path).resolve(1000, "verify").apple_uid, 501
                )

    def test_directory_relative_loader_rejects_unsafe_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "users.json"
            content = encoded([entry()])
            path.write_bytes(content)
            path.chmod(0o600)
            directory_descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            descriptor = os.open(path, os.O_RDONLY)
            secure = SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600,
                st_uid=0,
                st_gid=0,
                st_nlink=1,
                st_size=len(content),
                st_dev=1,
                st_ino=2,
                st_mtime_ns=3,
                st_ctime_ns=4,
            )
            try:
                with (
                    mock.patch.object(mapping.os, "open", return_value=descriptor),
                    mock.patch.object(mapping.os, "fstat", return_value=secure),
                ):
                    self.assertEqual(
                        mapping.load_at(directory_descriptor, "users.json")
                        .resolve(1000, "verify")
                        .apple_uid,
                        501,
                    )
                for name in ("../users.json", "/users.json", ".", ""):
                    with self.subTest(name=name):
                        with self.assertRaises(mapping.UserMappingError):
                            mapping.load_at(directory_descriptor, name)
            finally:
                os.close(directory_descriptor)

    def test_descriptor_loader_detects_same_length_metadata_change(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "users.json"
            content = encoded([entry()])
            path.write_bytes(content)
            path.chmod(0o600)
            descriptor = os.open(path, os.O_RDONLY)
            common = {
                "st_mode": stat.S_IFREG | 0o600,
                "st_uid": 0,
                "st_gid": 0,
                "st_nlink": 1,
                "st_size": len(content),
                "st_dev": 1,
                "st_ino": 2,
                "st_mtime_ns": 3,
            }
            try:
                with mock.patch.object(
                    mapping.os,
                    "fstat",
                    side_effect=(
                        SimpleNamespace(**common, st_ctime_ns=4),
                        SimpleNamespace(**common, st_ctime_ns=5),
                    ),
                ):
                    with self.assertRaisesRegex(mapping.UserMappingError, "changed"):
                        mapping._load_descriptor(descriptor)
            finally:
                os.close(descriptor)


if __name__ == "__main__":
    unittest.main()
