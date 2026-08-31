# SPDX-License-Identifier: GPL-2.0-only
"""Pure, fail-closed Catacomb persistence command primitives.

This module models only the statically recovered BiometricKit command
contract.  It opens no device or socket and deliberately does not implement a
BridgeXPC transport.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum


COMMAND_PREPARE_SAVE_CATACOMB = 0x3D
COMMAND_COMPLETE_SAVE_CATACOMB = 0x3E
COMMAND_CONFIRM_SAVE_CATACOMB = 0x3F
PREPARE_REPLY = struct.Struct("<I")
MAX_SECURE_BLOB_SIZE = 1024 * 1024
UINT32_MAX = 0xFFFFFFFF
ZERO_UUID = bytes(16)
COMPONENT_DESCRIPTOR = struct.Struct("<II16s")
USER_STATE_RECORD = struct.Struct("<II")
GROUP_STATE_RECORD = struct.Struct("<II16sI")
CATACOMB_STATE_NEEDS_SAVE = 0x04


class CatacombProtocolError(ValueError):
    """Raised when a persistence request or reply is not exact."""


class ComponentKind(Enum):
    MASTER = "master"
    USER = "user"
    GROUP = "group"


@dataclass(frozen=True, repr=False)
class CatacombComponent:
    """Exact protocol-v2 ``CatacombComponent`` value copied by BiometricKit."""

    user_id: int
    group_type: int
    group_uuid: bytes

    def __post_init__(self) -> None:
        for value, field in (
            (self.user_id, "component user ID"),
            (self.group_type, "component group type"),
        ):
            if type(value) is not int or not 0 <= value <= UINT32_MAX:
                raise CatacombProtocolError(f"{field} is outside uint32")
        if type(self.group_uuid) is not bytes or len(self.group_uuid) != 16:
            raise CatacombProtocolError("component group UUID must be exactly 16 bytes")
        if self.group_type == 0:
            if self.group_uuid != ZERO_UUID:
                raise CatacombProtocolError(
                    "user/master component has a nonzero group UUID"
                )
        elif self.user_id == UINT32_MAX:
            raise CatacombProtocolError("group component identity is not canonical")

    @classmethod
    def user(cls, user_id: int) -> "CatacombComponent":
        if type(user_id) is not int or not 0 <= user_id < UINT32_MAX:
            raise CatacombProtocolError("user component ID is outside canonical range")
        return cls(user_id, 0, ZERO_UUID)

    @classmethod
    def master(cls) -> "CatacombComponent":
        return cls(UINT32_MAX, 0, ZERO_UUID)

    @classmethod
    def group(
        cls, user_id: int, group_type: int, group_uuid: bytes
    ) -> "CatacombComponent":
        if type(group_type) is not int or not 0 < group_type <= UINT32_MAX:
            raise CatacombProtocolError("group component type must be nonzero")
        return cls(user_id, group_type, group_uuid)

    @classmethod
    def parse(cls, descriptor: bytes) -> "CatacombComponent":
        if type(descriptor) is not bytes or len(descriptor) != COMPONENT_DESCRIPTOR.size:
            raise CatacombProtocolError("component descriptor must be exactly 24 bytes")
        return cls(*COMPONENT_DESCRIPTOR.unpack(descriptor))

    @property
    def descriptor(self) -> bytes:
        return COMPONENT_DESCRIPTOR.pack(
            self.user_id, self.group_type, self.group_uuid
        )

    @property
    def kind(self) -> ComponentKind:
        if self.user_id == UINT32_MAX:
            return ComponentKind.MASTER
        if self.group_type == 0:
            return ComponentKind.USER
        return ComponentKind.GROUP

    def __repr__(self) -> str:
        return (
            "CatacombComponent(kind="
            f"{self.kind.value!r}, user_id={self.user_id}, descriptor=<redacted>)"
        )


@dataclass(frozen=True, repr=False)
class CatacombState:
    component: CatacombComponent
    state: int

    def __post_init__(self) -> None:
        if not isinstance(self.component, CatacombComponent):
            raise CatacombProtocolError("Catacomb state component is invalid")
        if type(self.state) is not int or not 0 <= self.state <= UINT32_MAX:
            raise CatacombProtocolError("Catacomb state is outside uint32")

    @property
    def needs_save(self) -> bool:
        return bool(self.state & CATACOMB_STATE_NEEDS_SAVE)

    def __repr__(self) -> str:
        return (
            "CatacombState(component="
            f"{self.component!r}, state=0x{self.state:08x})"
        )


def _unique_states(states: list[CatacombState]) -> tuple[CatacombState, ...]:
    descriptors = [record.component.descriptor for record in states]
    if len(set(descriptors)) != len(descriptors):
        raise CatacombProtocolError("Catacomb state contains a duplicate component")
    return tuple(states)


def parse_user_states(output: bytes) -> tuple[CatacombState, ...]:
    """Parse command 0x3c records: ``userID:u32, state:u32``."""
    if type(output) is not bytes or not output or len(output) % USER_STATE_RECORD.size:
        raise CatacombProtocolError("user Catacomb state bytes are malformed")
    states: list[CatacombState] = []
    for offset in range(0, len(output), USER_STATE_RECORD.size):
        user_id, state = USER_STATE_RECORD.unpack_from(output, offset)
        component = (
            CatacombComponent.master()
            if user_id == UINT32_MAX
            else CatacombComponent.user(user_id)
        )
        states.append(CatacombState(component, state))
    return _unique_states(states)


def parse_group_states(output: bytes) -> tuple[CatacombState, ...]:
    """Parse command 0x50 records: 24-byte component followed by ``state:u32``."""
    if type(output) is not bytes or len(output) % GROUP_STATE_RECORD.size:
        raise CatacombProtocolError("group Catacomb state bytes are malformed")
    states: list[CatacombState] = []
    for offset in range(0, len(output), GROUP_STATE_RECORD.size):
        user_id, group_type, group_uuid, state = GROUP_STATE_RECORD.unpack_from(
            output, offset
        )
        component = CatacombComponent(user_id, group_type, group_uuid)
        if component.kind is not ComponentKind.GROUP:
            raise CatacombProtocolError(
                "group Catacomb state contains a non-group component"
            )
        states.append(CatacombState(component, state))
    return _unique_states(states)


def plan_builtin_enrollment_save(
    user_states: tuple[CatacombState, ...],
    apple_user_id: int,
    *,
    group_states: tuple[CatacombState, ...] = (),
) -> tuple[CatacombComponent, ...]:
    """Derive the exact built-in enrollment save list, with master last."""
    if type(apple_user_id) is not int or not 0 <= apple_user_id < UINT32_MAX:
        raise CatacombProtocolError("selected Apple user ID is invalid")
    if type(user_states) is not tuple or type(group_states) is not tuple:
        raise CatacombProtocolError("Catacomb state collections must be tuples")
    combined = user_states + group_states
    if not combined or any(not isinstance(record, CatacombState) for record in combined):
        raise CatacombProtocolError("Catacomb save planning has invalid state")
    descriptors = [record.component.descriptor for record in combined]
    if len(set(descriptors)) != len(descriptors):
        raise CatacombProtocolError("Catacomb state repeats a component")

    master = CatacombComponent.master()
    selected = CatacombComponent.user(apple_user_id)
    if sum(record.component == master for record in user_states) != 1:
        raise CatacombProtocolError("Catacomb state has no unique master component")
    selected_records = [record for record in user_states if record.component == selected]
    if len(selected_records) != 1 or not selected_records[0].needs_save:
        raise CatacombProtocolError("selected user component is not marked for save")
    dirty_non_master = [
        record.component
        for record in combined
        if record.needs_save and record.component.kind is not ComponentKind.MASTER
    ]
    if dirty_non_master != [selected]:
        raise CatacombProtocolError(
            "built-in enrollment dirtied an unexpected Catacomb component"
        )
    return selected, master


@dataclass(frozen=True, repr=False)
class CatacombRequest:
    command: int
    protocol_version: int
    descriptor: bytes
    output_capacity: int

    def __post_init__(self) -> None:
        _validate_descriptor(self.protocol_version, self.descriptor)
        if self.command not in {
            COMMAND_PREPARE_SAVE_CATACOMB,
            COMMAND_COMPLETE_SAVE_CATACOMB,
            COMMAND_CONFIRM_SAVE_CATACOMB,
        }:
            raise CatacombProtocolError("unsupported Catacomb persistence command")
        if type(self.output_capacity) is not int or not (
            0 <= self.output_capacity <= MAX_SECURE_BLOB_SIZE
        ):
            raise CatacombProtocolError("output capacity is invalid or unbounded")
        if (
            self.command == COMMAND_PREPARE_SAVE_CATACOMB
            and self.output_capacity != PREPARE_REPLY.size
        ):
            raise CatacombProtocolError("Catacomb prepare output capacity must be 4")
        if (
            self.command == COMMAND_COMPLETE_SAVE_CATACOMB
            and self.output_capacity == 0
        ):
            raise CatacombProtocolError("Catacomb complete output capacity is empty")
        if (
            self.command == COMMAND_CONFIRM_SAVE_CATACOMB
            and self.output_capacity != 0
        ):
            raise CatacombProtocolError("Catacomb confirm output capacity must be zero")

    def __repr__(self) -> str:
        return (
            "CatacombRequest(command="
            f"0x{self.command:02x}, protocol_version={self.protocol_version}, "
            "descriptor=<redacted>, output_capacity="
            f"{self.output_capacity})"
        )


def _validate_descriptor(protocol_version: int, descriptor: bytes) -> None:
    if type(protocol_version) is not int or protocol_version not in (1, 2):
        raise CatacombProtocolError("Catacomb protocol must be version 1 or 2")
    expected = 4 if protocol_version == 1 else 24
    if type(descriptor) is not bytes or len(descriptor) != expected:
        raise CatacombProtocolError(
            f"protocol-{protocol_version} descriptor must be exactly {expected} bytes"
        )


def _require_success(status: int, operation: str) -> None:
    if type(status) is not int:
        raise CatacombProtocolError(f"{operation} status is not an integer")
    if status != 0:
        raise CatacombProtocolError(f"{operation} returned nonzero status")


def build_prepare_request(protocol_version: int, descriptor: bytes) -> CatacombRequest:
    return CatacombRequest(
        COMMAND_PREPARE_SAVE_CATACOMB,
        protocol_version,
        descriptor,
        PREPARE_REPLY.size,
    )


def parse_prepare_reply(status: int, output: bytes) -> int:
    _require_success(status, "Catacomb prepare")
    if type(output) is not bytes or len(output) != PREPARE_REPLY.size:
        raise CatacombProtocolError("Catacomb prepare output must be exactly 4 bytes")
    expected_length = PREPARE_REPLY.unpack(output)[0]
    if not 0 < expected_length <= MAX_SECURE_BLOB_SIZE:
        raise CatacombProtocolError("prepared secure-blob length is invalid or unbounded")
    return expected_length


def build_complete_request(
    protocol_version: int, descriptor: bytes, expected_length: int
) -> CatacombRequest:
    if type(expected_length) is not int or not (
        0 < expected_length <= MAX_SECURE_BLOB_SIZE
    ):
        raise CatacombProtocolError("expected secure-blob length is invalid or unbounded")
    return CatacombRequest(
        COMMAND_COMPLETE_SAVE_CATACOMB,
        protocol_version,
        descriptor,
        expected_length,
    )


def parse_complete_reply(
    status: int, output: bytearray, expected_length: int
) -> bytearray:
    _require_success(status, "Catacomb complete")
    if type(expected_length) is not int or not (
        0 < expected_length <= MAX_SECURE_BLOB_SIZE
    ):
        raise CatacombProtocolError("expected secure-blob length is invalid or unbounded")
    if type(output) is not bytearray or len(output) != expected_length:
        raise CatacombProtocolError(
            "Catacomb complete output differs from the prepared length"
        )
    return output


def build_confirm_request(protocol_version: int, descriptor: bytes) -> CatacombRequest:
    return CatacombRequest(
        COMMAND_CONFIRM_SAVE_CATACOMB,
        protocol_version,
        descriptor,
        0,
    )


def parse_confirm_reply(status: int, output: bytes) -> None:
    _require_success(status, "Catacomb confirm")
    if type(output) is not bytes or output:
        raise CatacombProtocolError("Catacomb confirm must not return output")
