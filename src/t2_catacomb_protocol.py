# SPDX-License-Identifier: GPL-2.0-only
"""Pure, fail-closed Catacomb persistence command primitives.

This module models only the statically recovered BiometricKit command
contract.  It opens no device or socket and deliberately does not implement a
BridgeXPC transport.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


COMMAND_PREPARE_SAVE_CATACOMB = 0x3D
COMMAND_COMPLETE_SAVE_CATACOMB = 0x3E
COMMAND_CONFIRM_SAVE_CATACOMB = 0x3F
PREPARE_REPLY = struct.Struct("<I")
MAX_SECURE_BLOB_SIZE = 1024 * 1024


class CatacombProtocolError(ValueError):
    """Raised when a persistence request or reply is not exact."""


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
