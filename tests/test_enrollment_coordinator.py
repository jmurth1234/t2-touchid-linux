import struct
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_acm_protocol as acm_protocol
import t2_enrollment_coordinator as coordinator
import t2_enrollment_journal as enrollment_journal
import t2_enrollment_protocol as enrollment_protocol
from tests.test_acm_device import FakeDevice as FakeACMDevice


GENERATION = str(uuid.UUID(int=51))
BOOT = str(uuid.UUID(int=52))
IDENTITY = str(uuid.UUID(int=53))
GROUP = str(uuid.UUID(int=54))
CATACOMB = str(uuid.UUID(int=55))


def inventory_reply(command: int) -> list[object]:
    identity = struct.pack("<I", 501) + uuid.UUID(IDENTITY).bytes
    group = struct.pack("<I", 1) + uuid.UUID(GROUP).bytes
    replies = {
        0x01: [0, struct.pack("<I", 2)],
        0x51: [0, identity + group],
        0x0F: [0, struct.pack("<I", 5)],
        0x42: [0, identity],
        0x41: [0, struct.pack("<I", 2)],
        0x38: [0, uuid.UUID(CATACOMB).bytes],
        0x3A: [0, b"\x01" + b"h" * 32],
        0x3C: [
            0,
            struct.pack("<II", 0xFFFFFFFF, 0)
            + struct.pack("<II", 501, 0),
        ],
        0x27: [0, struct.pack("<I", 552)],
    }
    return replies[command]


class FakeLease:
    def __init__(self) -> None:
        self.connection_generation = GENERATION
        self.peer_boot_uuid = BOOT
        self.invalidated = False
        self.inventory_commands = 0
        self.enrollment_commands: list[int] = []

    def invalidate(self) -> None:
        self.invalidated = True

    def biometric_command(
        self,
        command: int,
        *,
        version: int,
        value: int,
        data: bytes | memoryview,
        output_capacity: int,
    ) -> tuple[object, list[object]]:
        if self.inventory_commands < 18:
            self.inventory_commands += 1
            return inventory_reply(command), []
        self.enrollment_commands.append(command)
        if command == enrollment_protocol.COMMAND_ENROLL_START:
            progress = enrollment_protocol.SERVICE_HEADER.pack(
                1, enrollment_protocol.SERVICE_STATUS, 1, 263
            )
            return [0, None], [[9, 0, progress, None, None]]
        if command == enrollment_protocol.COMMAND_ENROLL_CONTINUE:
            result = enrollment_protocol.SERVICE_HEADER.pack(
                2, enrollment_protocol.SERVICE_ENROLLMENT_RESULT, 2, 0
            )
            result += (501).to_bytes(4, "little") + uuid.UUID(int=56).bytes + bytes(20)
            return [0, None], [[9, 0, result, None, None]]
        raise AssertionError(f"unexpected command {command}")

    def next_service_event(self) -> object:
        raise AssertionError("all events are interleaved in this fixture")


def host_inventory() -> dict[str, object]:
    return {
        "account_uuid": str(uuid.UUID(int=57)),
        "bag_uuid": str(uuid.UUID(int=58)),
        "identity_records": [{"user_id": 501, "uuid": IDENTITY, "entity": 0}],
        "master_enrollment_count": 1,
        "host_components": [
            {"name": "master.cat", "sha256": "a" * 64, "mode": 0o600, "uid": 0, "gid": 0},
            {"name": "biolockout.cat", "sha256": "b" * 64, "mode": 0o600, "uid": 0, "gid": 0},
            {"name": "user_000001f5.cat", "sha256": "c" * 64, "mode": 0o600, "uid": 0, "gid": 0},
        ],
        "archive_sha256": "d" * 64,
    }


def acm_device() -> FakeACMDevice:
    context = bytes(range(16))
    initial = (
        b"\x00\x00\x00\x00"
        + b"\x01\x00\x00\x00"
        + b"\x01\x00\x00\x00"
        + b"\x01\x00\x00\x00"
        + bytes(4)
    )
    final = b"\x01\x00\x00\x00"
    return FakeACMDevice(
        context + bytes(4) + b"\x01", policy_response=[initial, final]
    )


class EnrollmentCoordinatorTests(unittest.TestCase):
    def run_coordinator(self, directory: str, finalizer):
        lease = FakeLease()
        device = acm_device()
        self.last_lease = lease
        self.last_device = device
        bound: list[bytes] = []
        path = Path(directory) / "operation.jsonl"
        operation_id = str(uuid.UUID(int=59))
        result = coordinator.run(
            lease=lease,
            acm_device=device,
            apple_user_id=501,
            host_inventory=host_inventory(),
            journal_path=path,
            operation_id=operation_id,
            caller_linux_uid=1000,
            target_linux_uid=1000,
            linux_boot_uuid=str(uuid.UUID(int=60)),
            mapping_generation="e" * 64,
            backup_reference="backup.tar.gz",
            password_fallback_verified=True,
            password_binder=bound.append,
            finalizer=finalizer,
        )
        return result, lease, device, bound, path

    def test_full_fake_flow_keeps_one_generation_through_finalizer(self):
        finalized = []

        def finalize(result):
            finalized.append(result.outcome)
            return coordinator.FinalizationAttestation(GENERATION, True, True)

        with tempfile.TemporaryDirectory() as directory:
            result, lease, device, bound, path = self.run_coordinator(
                directory, finalize
            )
            history = enrollment_journal.read(path)
        self.assertEqual(result.outcome, "identity-observed")
        self.assertTrue(result.policy_satisfied)
        self.assertTrue(result.persistence_ready)
        self.assertEqual(finalized, ["identity-observed"])
        self.assertEqual(bound, [bytes(range(16))])
        self.assertEqual(
            [command[0] for command in device.commands[-2:]],
            [acm_protocol.OP_VERIFY_POLICY, acm_protocol.OP_CONTEXT_DELETE],
        )
        self.assertEqual(lease.inventory_commands, 18)
        self.assertEqual(
            lease.enrollment_commands,
            [
                enrollment_protocol.COMMAND_ENROLL_START,
                enrollment_protocol.COMMAND_ENROLL_CONTINUE,
            ],
        )
        self.assertEqual(history.phase, enrollment_journal.EnrollmentPhase.TERMINAL_IDENTITY)

    def test_identity_cannot_complete_without_persistence_attestation(self):
        def finalize(_result):
            return coordinator.FinalizationAttestation(GENERATION, False, True)

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                coordinator.EnrollmentCoordinatorError, "persistence"
            ):
                self.run_coordinator(directory, finalize)
        self.assertTrue(self.last_lease.invalidated)
        self.assertEqual(
            self.last_device.commands[-1][0], acm_protocol.OP_CONTEXT_DELETE
        )

    def test_finalizer_cannot_switch_bridge_generation(self):
        def finalize(_result):
            return coordinator.FinalizationAttestation(
                str(uuid.UUID(int=99)), True, True
            )

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(
                coordinator.EnrollmentCoordinatorError, "another Bridge generation"
            ):
                self.run_coordinator(directory, finalize)
        self.assertTrue(self.last_lease.invalidated)
        self.assertEqual(
            self.last_device.commands[-1][0], acm_protocol.OP_CONTEXT_DELETE
        )


if __name__ == "__main__":
    unittest.main()
