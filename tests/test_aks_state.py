# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_aks_observer as observer
import t2_aks_state as state


def length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + length(len(content)) + content


def integer(value: int) -> bytes:
    if value >= 0:
        encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
        if encoded[0] & 0x80:
            encoded = b"\0" + encoded
    else:
        size = 1
        while value < -(1 << (size * 8 - 1)):
            size += 1
        encoded = value.to_bytes(size, "big", signed=True)
        while len(encoded) > 1 and encoded[0] == 0xFF and encoded[1] & 0x80:
            encoded = encoded[1:]
    return tlv(0x02, encoded)


def item(key: str, value: int | bytes, tag: int | None = None) -> bytes:
    encoded_key = tlv(0x0C, key.encode())
    if tag is None:
        encoded_value = integer(value) if isinstance(value, int) else tlv(0x04, value)
    else:
        encoded_value = tlv(tag, value if isinstance(value, bytes) else bytes([value]))
    return tlv(0x30, encoded_key + encoded_value)


def state_blob(handle: int = -501, lock_state: int = 0) -> bytes:
    fields: dict[str, int | bytes] = {
        "bh": handle,
        "mua": 11,
        "sb": 0,
        "sfa": 0,
        "sgs": 0,
        "sls": lock_state,
        "sms": 0,
        "srcd": 0,
        "ss": 0x06000004,
        "uuuid": uuid.UUID(int=7).bytes,
    }
    members = sorted(item(key, value) for key, value in fields.items())
    return tlv(0x31, b"".join(members))


class FakeRunner:
    def __init__(self, uuids, blob=None, *, state_mode=0o600):
        self.uuids = list(uuids)
        self.blob = blob or state_blob()
        self.state_mode = state_mode
        self.calls = []

    def __call__(self, command):
        self.calls.append(command)
        output = Path(command[-1])
        if command[1] == "copy-keybag-uuid":
            value = self.uuids.pop(0)
            if isinstance(value, BaseException):
                raise value
            if value is None:
                return subprocess.CompletedProcess(command, 3, "present=false\n", "")
            output.write_bytes(uuid.UUID(value).bytes)
            output.chmod(0o600)
            return subprocess.CompletedProcess(command, 0, "present=true\n", "")
        if command[1] == "get-device-state-v1":
            output.write_bytes(self.blob)
            output.chmod(self.state_mode)
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(command)


class AKSStateTests(unittest.TestCase):
    def test_decodes_exact_proven_dictionary(self):
        decoded = state.decode(state_blob())
        self.assertEqual(decoded.handle, -501)
        self.assertEqual(decoded.maximum_unlock_attempts, 11)
        self.assertEqual(decoded.lock_state, 0)
        self.assertEqual(decoded.state, 0x06000004)
        self.assertEqual(decoded.user_uuid, str(uuid.UUID(int=7)))
        self.assertNotIn(decoded.user_uuid, str(decoded.redacted()))

    def test_rejects_trailing_missing_unknown_duplicate_and_unsorted_fields(self):
        valid = state_blob()
        with self.assertRaises(state.AKSStateError):
            state.decode(valid + b"\0")
        root, _ = state._tlv(valid, 0, 0x31)
        members = []
        offset = 0
        while offset < len(root):
            start = offset
            _, offset = state._tlv(root, offset, 0x30)
            members.append(root[start:offset])
        for content in (
            b"".join(members[:-1]),
            b"".join(sorted(members + [item("wat", 1)])),
            b"".join(sorted(members + [members[0]])),
            b"".join(reversed(members)),
        ):
            with self.subTest(length=len(content)):
                with self.assertRaises(state.AKSStateError):
                    state.decode(tlv(0x31, content))

    def test_rejects_noncanonical_integer_wrong_type_and_zero_uuid(self):
        fields = {
            "bh": item("bh", b"\0\x01", 0x02),
            "mua": item("mua", 11),
            "sb": item("sb", 0),
            "sfa": item("sfa", 0),
            "sgs": item("sgs", 0),
            "sls": item("sls", 0),
            "sms": item("sms", 0),
            "srcd": item("srcd", 0),
            "ss": item("ss", 1),
            "uuuid": item("uuuid", uuid.UUID(int=7).bytes),
        }
        with self.assertRaises(state.AKSStateError):
            state.decode(tlv(0x31, b"".join(sorted(fields.values()))))
        fields["bh"] = item("bh", -501)
        fields["sls"] = item("sls", b"x")
        with self.assertRaises(state.AKSStateError):
            state.decode(tlv(0x31, b"".join(sorted(fields.values()))))
        fields["sls"] = item("sls", 0)
        fields["uuuid"] = item("uuuid", bytes(16))
        with self.assertRaises(state.AKSStateError):
            state.decode(tlv(0x31, b"".join(sorted(fields.values()))))

    def test_rejects_nonminimal_lengths_and_out_of_range_lock_state(self):
        valid = state_blob()
        self.assertLess(valid[1], 0x80)
        nonminimal = bytes([valid[0], 0x81, valid[1]]) + valid[2:]
        with self.assertRaises(state.AKSStateError):
            state.decode(nonminimal)
        with self.assertRaises(state.AKSStateError):
            state.decode(state_blob(lock_state=1 << 16))


class AKSAliasObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bag = str(uuid.UUID(int=9))

    def tearDown(self):
        self.temp.cleanup()

    def make(self, runner):
        return observer.AKSAliasObserver(
            tool=Path("/test/t2-aks-tool"),
            runtime_root=self.root,
            runtime_generation=str(uuid.UUID(int=10)),
            runner=runner,
            expected_owner_uid=os.geteuid(),
        )

    def test_double_absence_returns_structural_absent_evidence(self):
        runner = FakeRunner([None, None])
        result = self.make(runner).observe_alias(-501)
        self.assertFalse(result.present)
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_present_alias_requires_uuid_state_uuid_stability(self):
        runner = FakeRunner([self.bag, self.bag], state_blob(-501, 1))
        result = self.make(runner).observe_alias(-501)
        self.assertTrue(result.present)
        self.assertEqual(result.special_alias, -501)
        self.assertEqual(result.bag_uuid, self.bag)
        self.assertEqual(result.lock_state, 1)
        self.assertEqual(len(runner.calls), 3)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_presence_uuid_or_handle_race_fails_closed(self):
        cases = (
            FakeRunner([None, self.bag]),
            FakeRunner([self.bag, None]),
            FakeRunner([self.bag, str(uuid.UUID(int=11))]),
            FakeRunner([self.bag, self.bag], state_blob(-502)),
        )
        for runner in cases:
            with self.subTest(calls=len(runner.uuids)):
                with self.assertRaises(observer.AKSAliasObservationError):
                    self.make(runner).observe_alias(-501)

    def test_command_malformed_state_and_insecure_file_fail_closed(self):
        cases = (
            FakeRunner([OSError("offline")]),
            FakeRunner([self.bag, self.bag], b"not DER"),
            FakeRunner([self.bag, self.bag], state_mode=0o644),
        )
        for runner in cases:
            with self.subTest(runner=runner):
                with self.assertRaises(observer.AKSAliasObservationError):
                    self.make(runner).observe_alias(-501)

    def test_rejects_unproven_session_paths_generation_and_alias(self):
        with self.assertRaises(observer.AKSAliasObservationError):
            observer.AKSAliasObserver(
                tool=Path("relative"), runtime_root=self.root
            )
        with self.assertRaises(observer.AKSAliasObservationError):
            observer.AKSAliasObserver(
                tool=Path("/tool"), runtime_root=self.root, session=2
            )
        with self.assertRaises(observer.AKSAliasObservationError):
            observer.AKSAliasObserver(
                tool=Path("/tool"),
                runtime_root=self.root,
                runtime_generation="bad",
            )
        with self.assertRaises(observer.AKSAliasObservationError):
            self.make(FakeRunner([])).observe_alias(-3)

    def test_positive_handle_uuid_is_double_read(self):
        runner = FakeRunner([self.bag, self.bag])
        self.assertEqual(self.make(runner).observe_handle_uuid(9), self.bag)
        self.assertEqual(len(runner.calls), 2)
        with self.assertRaises(observer.AKSAliasObservationError):
            self.make(FakeRunner([self.bag, None])).observe_handle_uuid(9)
        with self.assertRaises(observer.AKSAliasObservationError):
            self.make(FakeRunner([])).observe_handle_uuid(-501)


if __name__ == "__main__":
    unittest.main()
