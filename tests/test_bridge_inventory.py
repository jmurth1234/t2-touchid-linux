import struct
import sys
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_bridge_inventory as inventory


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
        0x41: [0, struct.pack("<I", 4)],
        0x38: [0, uuid.UUID(int=45).bytes],
        0x3A: [0, b"\x01" + hash_byte * 32],
        0x3C: [0, bytes(16)],
        0x27: [0, struct.pack("<I", 552)],
    }


class BridgeInventoryTests(unittest.TestCase):
    def test_stable_double_collection_returns_private_inventory(self):
        lease = FakeLease([snapshot(), snapshot()])
        result = inventory.collect_stable_private_inventory(lease, 501)
        self.assertEqual(result["connection_generation"], GENERATION)
        self.assertEqual(result["bridge_boot_uuid"], BOOT)
        self.assertEqual(result["maximum_capacity"], 5)
        self.assertEqual(result["configured_user_free_capacity"], 4)
        self.assertEqual(len(result["per_user_identity_records"]), 1)
        self.assertTrue(result["double_collection_equal"])
        self.assertFalse(lease.invalidated)
        self.assertEqual(len(lease.seen), 18)
        self.assertTrue(all(call[1] == 2 for call in lease.seen))

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


if __name__ == "__main__":
    unittest.main()
