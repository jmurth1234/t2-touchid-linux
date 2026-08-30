"""Strict framing helpers for the Apple Credential Manager SEP protocol.

This module only constructs the small, independently understood context
lifecycle subset.  It deliberately has no generic "raw command" builder.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


MAGIC = b"DRCS"
VERSION = 1
HEADER_SIZE = 8
CONTEXT_SIZE = 16

OP_CONTEXT_CREATE = 0x01
OP_CONTEXT_DELETE = 0x02
OP_CONTEXT_CREATE_TRACKING = 0x24


class ACMProtocolError(ValueError):
    """Raised when an ACM request or response violates the known schema."""


@dataclass(frozen=True)
class ContextHandle:
    context: bytes
    payload: int
    tracking: bool
    response_flag: bool

    def __post_init__(self) -> None:
        if type(self.context) is not bytes or len(self.context) != CONTEXT_SIZE:
            raise ACMProtocolError("context must be exactly 16 bytes")
        if not 0 <= self.payload <= 0xFFFFFFFF:
            raise ACMProtocolError("context payload is outside uint32 range")
        if type(self.tracking) is not bool:
            raise ACMProtocolError("tracking must be boolean")
        if type(self.response_flag) is not bool:
            raise ACMProtocolError("response_flag must be boolean")


def _header(opcode: int) -> bytes:
    if opcode not in {
        OP_CONTEXT_CREATE,
        OP_CONTEXT_DELETE,
        OP_CONTEXT_CREATE_TRACKING,
    }:
        raise ACMProtocolError("opcode is outside the lifecycle allowlist")
    return MAGIC + bytes((opcode, 0, 0, VERSION))


def build_create(*, user_id: int, tracking: bool = True) -> bytes:
    """Build the exact command passed to SEP after the kext's UID append."""
    if not 0 <= user_id <= 0xFFFFFFFF:
        raise ACMProtocolError("user_id is outside uint32 range")
    opcode = OP_CONTEXT_CREATE_TRACKING if tracking else OP_CONTEXT_CREATE
    return _header(opcode) + struct.pack("<I", user_id)


def parse_create_response(response: bytes, *, tracking: bool) -> ContextHandle:
    expected = 21 if tracking else 17
    if type(response) is not bytes or len(response) != expected:
        raise ACMProtocolError(f"create response must be exactly {expected} bytes")
    flag_offset = CONTEXT_SIZE + (4 if tracking else 0)
    response_flag = response[flag_offset]
    if response_flag not in (0, 1):
        raise ACMProtocolError("create response flag is not boolean")
    payload = (
        struct.unpack_from("<I", response, CONTEXT_SIZE)[0] if tracking else 0
    )
    return ContextHandle(response[:CONTEXT_SIZE], payload, tracking, bool(response_flag))


def build_delete(handle: ContextHandle) -> bytes:
    """Build a delete command; the payload/tracking metadata is not serialized."""
    if not isinstance(handle, ContextHandle):
        raise ACMProtocolError("handle must be a ContextHandle")
    return _header(OP_CONTEXT_DELETE) + handle.context


def validate_command(command: bytes) -> int:
    """Validate and return the opcode for this narrow lifecycle subset."""
    if type(command) is not bytes or len(command) < HEADER_SIZE:
        raise ACMProtocolError("command is shorter than the ACM header")
    if command[:4] != MAGIC or command[5:8] != b"\x00\x00\x01":
        raise ACMProtocolError("command header is invalid")
    opcode = command[4]
    expected = {
        OP_CONTEXT_CREATE: 12,
        OP_CONTEXT_CREATE_TRACKING: 12,
        OP_CONTEXT_DELETE: 24,
    }.get(opcode)
    if expected is None or len(command) != expected:
        raise ACMProtocolError("command opcode or length is not allowed")
    return opcode
