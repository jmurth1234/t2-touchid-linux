import struct
import sys
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_bridge_inventory as inventory
import t2_bridge_wire as wire


GENERATION = str(uuid.UUID(int=41))
BOOT = str(uuid.UUID(int=42))


class FakeLease:
    def __init__(self, snapshots: list[dict[int, list[object]]]) -> None:
        self._generation = GENERATION
        self.peer_boot_uuid = BOOT
        self.snapshots = snapshots
        self.snapshot = 0
        self.seen: list[tuple[int, int, bytes, int]] = []
        self.invalidated = False

    @property
    def connection_generation(self) -> str:
        return self._generation

    def biometric_command(
        self,
        command: int,
        *,
        version: int,
        value: int,
        data: bytes | memoryview,
        output_capacity: int,
    ) -> tuple[object, list[object]]:
        self.seen.append((command, version, bytes(data), output_capacity))
        result = self.snapshots[self.snapshot][command]
        if command == 0x27:
            self.snapshot += 1
        return result, []

    def invalidate(self) -> None:
        self.invalidated = True


def snapshot(hash_byte: bytes = b"h") -> dict[int, list[object]]:
    identity = struct.pack("<I", 501) + uuid.UUID(int=43).bytes
    group = struct.pack("<I", 1) + uuid.UUID(int=44).bytes
    return {
        0x01: [0, struct.pack("<I", 2)],
        0x51: [0, identity + group],
        0x0F: [0, struct.pack("<I", 5)],
        0x42: [0, identity],
        0x41: [0, struct.pack("<I", 2)],
        0x38: [0, uuid.UUID(int=45).bytes],
        0x3A: [0, b"\x01" + hash_byte * 32],
        0x3C: [
            0,
            struct.pack("<II", 0xFFFFFFFF, 0)
            + struct.pack("<II", 501, 0),
        ],
        0x27: [0, struct.pack("<I", 552)],
    }


class BridgeInventoryTests(unittest.TestCase):
    def test_stable_double_collection_returns_private_inventory(self):
        lease = FakeLease([snapshot(), snapshot()])
        result = inventory.collect_stable_private_inventory(lease, 501)
        self.assertEqual(result["connection_generation"], GENERATION)
        self.assertEqual(result["bridge_boot_uuid"], BOOT)
        self.assertEqual(result["maximum_capacity"], 5)
        self.assertEqual(result["configured_user_free_capacity"], 2)
        self.assertEqual(len(result["per_user_identity_records"]), 1)
        self.assertEqual(
            result["catacomb"]["user_states"],
            [
                {
                    "kind": "master",
                    "user_id": 0xFFFFFFFF,
                    "state": 0,
                    "needs_save": False,
                },
                {
                    "kind": "user",
                    "user_id": 501,
                    "state": 0,
                    "needs_save": False,
                },
            ],
        )
        self.assertTrue(result["double_collection_equal"])
        self.assertFalse(lease.invalidated)
        self.assertEqual(len(lease.seen), 18)
        self.assertTrue(all(call[1] == 1 for call in lease.seen))

    def test_nil_identity_outputs_are_successful_empty_lists(self):
        first = snapshot()
        second = snapshot()
        for current in (first, second):
            current[0x51] = [0, wire.BIOMETRIC_NIL_OUTPUT_SENTINEL]
            current[0x42] = [0, wire.BIOMETRIC_NIL_OUTPUT_SENTINEL]
            current[0x38] = [0, bytes(16)]
            current[0x3A] = [0, bytes(33)]
        lease = FakeLease([first, second])
        result = inventory.collect_stable_private_inventory(lease, 501)
        self.assertEqual(result["global_identity_records"], [])
        self.assertEqual(result["per_user_identity_records"], [])
        self.assertFalse(lease.invalidated)

    def test_zero_catacomb_uuid_requires_empty_absent_inventory(self):
        for mutation in ("identity", "present"):
            first = snapshot()
            second = snapshot()
            for current in (first, second):
                current[0x38] = [0, bytes(16)]
                if mutation == "present":
                    current[0x3A] = [0, b"\x01" + bytes(32)]
            lease = FakeLease([first, second])
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(
                    inventory.BridgeInventoryError, "Catacomb UUID reply is inconsistent"
                ):
                    inventory.collect_stable_private_inventory(lease, 501)
                self.assertTrue(lease.invalidated)

    def test_enoent_catacomb_metadata_is_valid_only_for_empty_absent_state(self):
        first = snapshot()
        second = snapshot()
        for current in (first, second):
            current[0x51] = [0, wire.BIOMETRIC_NIL_OUTPUT_SENTINEL]
            current[0x42] = [0, wire.BIOMETRIC_NIL_OUTPUT_SENTINEL]
            current[0x38] = [22, bytes(16)]
            current[0x3A] = [22, bytes(33)]
            current[0x3C] = [0, struct.pack("<II", 0xFFFFFFFF, 3)]
        lease = FakeLease([first, second])
        result = inventory.collect_stable_private_inventory(lease, 501)
        self.assertFalse(result["catacomb"]["present"])
        self.assertFalse(lease.invalidated)

    def test_nil_output_is_rejected_for_nonidentity_commands(self):
        first = snapshot()
        first[0x0F] = [0, wire.BIOMETRIC_NIL_OUTPUT_SENTINEL]
        lease = FakeLease([first, snapshot()])
        with self.assertRaisesRegex(inventory.BridgeInventoryError, "maximum_capacity"):
            inventory.collect_stable_private_inventory(lease, 501)
        self.assertTrue(lease.invalidated)

    def test_arbitrary_string_is_not_an_empty_identity_list(self):
        first = snapshot()
        first[0x51] = [0, "not-the-nil-sentinel"]
        lease = FakeLease([first, snapshot()])
        with self.assertRaisesRegex(inventory.BridgeInventoryError, "global_identities"):
            inventory.collect_stable_private_inventory(lease, 501)
        self.assertTrue(lease.invalidated)

    def test_changed_second_snapshot_invalidates_generation(self):
        lease = FakeLease([snapshot(), snapshot(b"x")])
        with self.assertRaisesRegex(inventory.BridgeInventoryError, "changed"):
            inventory.collect_stable_private_inventory(lease, 501)
        self.assertTrue(lease.invalidated)

    def test_unexpected_event_or_malformed_reply_invalidates(self):
        class EventLease(FakeLease):
            def biometric_command(self, *args, **kwargs):
                reply, _events = super().biometric_command(*args, **kwargs)
                return reply, [[9, 0, b"event", None, None]]

        for lease in (
            EventLease([snapshot(), snapshot()]),
            FakeLease([{**snapshot(), 0x0F: [0, b"bad"]}, snapshot()]),
        ):
            with self.subTest(lease=type(lease).__name__):
                with self.assertRaises(inventory.BridgeInventoryError):
                    inventory.collect_stable_private_inventory(lease, 501)
                self.assertTrue(lease.invalidated)

    def test_v2_global_command_attests_rejected_protocol_query(self):
        first = snapshot()
        second = snapshot()
        first[0x01] = [-536870206, bytes(4)]
        second[0x01] = [-536870206, bytes(4)]
        lease = FakeLease([first, second])
        result = inventory.collect_stable_private_inventory(lease, 501)
        self.assertEqual(result["biometric_protocol_version"], 2)

    def test_invalid_uid_never_dispatches_or_invalidates(self):
        lease = FakeLease([snapshot(), snapshot()])
        with self.assertRaises(inventory.BridgeInventoryError):
            inventory.collect_stable_private_inventory(lease, -1)
        self.assertEqual(lease.seen, [])
        self.assertFalse(lease.invalidated)

    def test_catacomb_state_requires_unique_master_and_selected_user(self):
        for state in (
            struct.pack("<II", 501, 0),
            struct.pack("<II", 0xFFFFFFFF, 0),
            struct.pack("<II", 0xFFFFFFFF, 0) * 2
            + struct.pack("<II", 501, 0),
        ):
            first = snapshot()
            second = snapshot()
            first[0x3C] = [0, state]
            second[0x3C] = [0, state]
            lease = FakeLease([first, second])
            with self.subTest(state=state):
                with self.assertRaises(inventory.BridgeInventoryError):
                    inventory.collect_stable_private_inventory(lease, 501)
                self.assertTrue(lease.invalidated)


if __name__ == "__main__":
    unittest.main()
