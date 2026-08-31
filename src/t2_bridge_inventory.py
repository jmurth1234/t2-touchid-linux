# SPDX-License-Identifier: GPL-2.0-only
"""Stable private E0 inventory over one already-owned Bridge connection."""

from __future__ import annotations

import struct
import uuid
from typing import Protocol


class BridgeInventoryError(RuntimeError):
    """Raised when a same-connection E0 snapshot cannot be trusted."""


class InventoryLease(Protocol):
    connection_generation: str
    peer_boot_uuid: str | None

    def biometric_command(
        self,
        command: int,
        *,
        version: int,
        value: int,
        data: bytes | memoryview,
        output_capacity: int,
    ) -> tuple[object, list[object]]: ...

    def invalidate(self) -> None: ...


COMMANDS = (
    ("protocol", 0x01, b"", 4),
    ("global_identities", 0x51, b"", 40 * 10),
    ("maximum_capacity", 0x0F, b"", 4),
    ("per_user_identities", 0x42, None, 20 * 10),
    ("free_capacity", 0x41, None, 4),
    ("catacomb_uuid", 0x38, None, 16),
    ("catacomb_hash", 0x3A, None, 33),
    ("catacomb_state", 0x3C, b"", 4096),
    ("sks_lock_state", 0x27, None, 4),
)


def _reply_output(reply: object, name: str, *, allow_nonzero: bool = False) -> bytes:
    if type(reply) is not list or len(reply) != 2:
        raise BridgeInventoryError(f"{name} reply is malformed")
    status, output = reply
    if (
        type(status) is not int
        or isinstance(status, bool)
        or not -(2**31) <= status < 2**32
        or (status != 0 and not allow_nonzero)
        or type(output) is not bytes
    ):
        raise BridgeInventoryError(f"{name} reply is invalid")
    return output


def _collect_once(
    lease: InventoryLease, apple_user_id: int, generation: str
) -> dict[str, tuple[int, bytes]]:
    uid = struct.pack("<I", apple_user_id)
    snapshot: dict[str, tuple[int, bytes]] = {}
    for name, command, static_data, capacity in COMMANDS:
        data = uid if static_data is None else static_data
        reply, events = lease.biometric_command(
            command,
            # These inventory codecs retain command-wrapper version 1 even
            # when command 0x51 attests biometric protocol version 2.
            version=1,
            value=0,
            data=data,
            output_capacity=capacity,
        )
        if lease.connection_generation != generation:
            raise BridgeInventoryError("Bridge generation changed during E0")
        if type(events) is not list or events:
            raise BridgeInventoryError(f"{name} emitted an unexpected service event")
        output = _reply_output(reply, name, allow_nonzero=name == "protocol")
        status = reply[0]
        if name == "protocol" and len(output) != 4:
            for _attempt in range(2):
                retry, retry_events = lease.biometric_command(
                    command,
                    version=1,
                    value=0,
                    data=data,
                    output_capacity=capacity,
                )
                if lease.connection_generation != generation:
                    raise BridgeInventoryError("Bridge generation changed during E0")
                if type(retry_events) is not list or retry_events:
                    raise BridgeInventoryError(
                        "protocol retry emitted an unexpected service event"
                    )
                output = _reply_output(retry, name, allow_nonzero=True)
                status = retry[0]
                if len(output) == 4:
                    break
        snapshot[name] = (status, output)
    return snapshot


def _records(output: bytes, size: int, name: str) -> tuple[bytes, ...]:
    if len(output) % size:
        raise BridgeInventoryError(f"{name} record bytes are malformed")
    return tuple(output[offset : offset + size] for offset in range(0, len(output), size))


def collect_stable_private_inventory(
    lease: InventoryLease, apple_user_id: int
) -> dict[str, object]:
    """Collect and validate two complete snapshots without releasing the lease."""
    if type(apple_user_id) is not int or not 0 <= apple_user_id <= 0xFFFFFFFF:
        raise BridgeInventoryError("Apple user ID is outside uint32 range")
    try:
        generation = lease.connection_generation
        parsed_generation = uuid.UUID(generation)
        if str(parsed_generation) != generation:
            raise BridgeInventoryError("Bridge generation is not canonical")
    except (AttributeError, TypeError, ValueError) as error:
        raise BridgeInventoryError("Bridge generation is invalid") from error
    dispatched = False
    try:
        dispatched = True
        first = _collect_once(lease, apple_user_id, generation)
        second = _collect_once(lease, apple_user_id, generation)
        if first != second:
            raise BridgeInventoryError("E0 inventory changed between collections")

        protocol_status, protocol_output = first["protocol"]
        global_records = _records(first["global_identities"][1], 40, "global identity")
        user_records = _records(first["per_user_identities"][1], 20, "per-user identity")
        configured_global = {
            record[:20]
            for record in global_records
            if struct.unpack_from("<I", record)[0] == apple_user_id
        }
        if configured_global != set(user_records):
            raise BridgeInventoryError("global and per-user identities disagree")
        if any(struct.unpack_from("<I", record)[0] != apple_user_id for record in user_records):
            raise BridgeInventoryError("per-user inventory contains another Apple user")
        explicit_v2 = (
            protocol_status == 0
            and len(protocol_output) == 4
            and struct.unpack("<I", protocol_output)[0] == 2
        )
        if not explicit_v2:
            # Successful, structurally valid command 0x51 is protocol-v2-only.
            if first["global_identities"][0] != 0:
                raise BridgeInventoryError("biometric protocol v2 is not attested")

        maximum_output = first["maximum_capacity"][1]
        free_output = first["free_capacity"][1]
        catacomb_uuid = first["catacomb_uuid"][1]
        catacomb_hash = first["catacomb_hash"][1]
        catacomb_state = first["catacomb_state"][1]
        sks_state = first["sks_lock_state"][1]
        if len(maximum_output) != 4 or len(free_output) != 4:
            raise BridgeInventoryError("capacity reply length is invalid")
        if len(catacomb_uuid) != 16 or not any(catacomb_uuid):
            raise BridgeInventoryError("Catacomb UUID reply is invalid")
        if len(catacomb_hash) != 33:
            raise BridgeInventoryError("Catacomb hash reply is invalid")
        if len(catacomb_state) not in (8, 16):
            raise BridgeInventoryError("Catacomb state reply is invalid")
        if len(sks_state) != 4:
            raise BridgeInventoryError("SKS state reply is invalid")
        maximum = struct.unpack("<I", maximum_output)[0]
        free = struct.unpack("<I", free_output)[0]
        # Command 0x0f is device maximum while 0x41 is scoped to the selected
        # user/accessory group. Live hardware confirms they are bounded but do
        # not satisfy a simple per-user used + free == device maximum equation.
        if maximum > 64 or free > maximum or len(user_records) > maximum:
            raise BridgeInventoryError("identity capacity is inconsistent")

        boot_uuid = lease.peer_boot_uuid
        if boot_uuid is not None:
            try:
                if str(uuid.UUID(boot_uuid)) != boot_uuid:
                    raise BridgeInventoryError("Bridge boot UUID is not canonical")
            except (AttributeError, TypeError, ValueError) as error:
                raise BridgeInventoryError("Bridge boot UUID is invalid") from error
        return {
            "schema_version": 1,
            "connection_generation": generation,
            "bridge_boot_uuid": boot_uuid,
            "biometric_protocol_version": 2,
            "apple_uid": apple_user_id,
            "per_user_identity_records": [
                {
                    "user_id": struct.unpack_from("<I", record)[0],
                    "identity_uuid": str(uuid.UUID(bytes=record[4:20])),
                }
                for record in user_records
            ],
            "global_identity_records": [
                {
                    "user_id": struct.unpack_from("<I", record)[0],
                    "identity_uuid": str(uuid.UUID(bytes=record[4:20])),
                    "group_type": struct.unpack_from("<I", record, 20)[0],
                    "group_uuid": str(uuid.UUID(bytes=record[24:40])),
                }
                for record in global_records
            ],
            "maximum_capacity": maximum,
            "configured_user_free_capacity": free,
            "catacomb": {
                "uuid": str(uuid.UUID(bytes=catacomb_uuid)),
                "present": bool(catacomb_hash[0]),
                "hash": catacomb_hash[1:].hex(),
                "global_state": catacomb_state.hex(),
            },
            "sks_lock_state_raw": struct.unpack("<I", sks_state)[0],
            "double_collection_equal": True,
        }
    except BaseException as error:
        if dispatched:
            try:
                lease.invalidate()
            except BaseException:
                pass
        if isinstance(error, BridgeInventoryError):
            raise
        raise BridgeInventoryError("same-connection E0 collection failed") from error
