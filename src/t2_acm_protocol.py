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
OP_VERIFY_POLICY = 0x03
OP_CONTEXT_EXTERNALIZE = 0x13
OP_CONTEXT_CREATE_TRACKING = 0x24
ENROLLMENT_POLICY = b"TouchIdEnrollment"
POLICY_RESPONSE_CAPACITY = 0x1000
SIMPLE_REQUIREMENT_TYPES = frozenset(
    {1, 2, 3, 6, *range(8, 16), *range(18, 29)}
)


class ACMProtocolError(ValueError):
    """Raised when an ACM request or response violates the known schema."""


@dataclass(frozen=True)
class ContextHandle:
    context: bytes
    payload: int
    tracking: bool
    response_byte: int

    def __post_init__(self) -> None:
        if type(self.context) is not bytes or len(self.context) != CONTEXT_SIZE:
            raise ACMProtocolError("context must be exactly 16 bytes")
        if not 0 <= self.payload <= 0xFFFFFFFF:
            raise ACMProtocolError("context payload is outside uint32 range")
        if type(self.tracking) is not bool:
            raise ACMProtocolError("tracking must be boolean")
        if not 0 <= self.response_byte <= 0xFF:
            raise ACMProtocolError("response_byte is outside uint8 range")
        if self.tracking and self.response_byte not in (0, 1):
            raise ACMProtocolError("tracking response flag is not boolean")

    @property
    def response_flag(self) -> bool | None:
        return bool(self.response_byte) if self.tracking else None


@dataclass(frozen=True)
class PolicyResult:
    satisfied: bool
    requirement_present: bool
    requirement_length: int
    requirement_type: int | None
    requirement_state: int | None
    requirement_flags: int | None
    requirement_payload_length: int | None


def _header(opcode: int) -> bytes:
    if opcode not in {
        OP_CONTEXT_CREATE,
        OP_CONTEXT_DELETE,
        OP_VERIFY_POLICY,
        OP_CONTEXT_EXTERNALIZE,
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
    response_byte = response[flag_offset]
    if tracking and response_byte not in (0, 1):
        raise ACMProtocolError("tracking create response flag is not boolean")
    payload = (
        struct.unpack_from("<I", response, CONTEXT_SIZE)[0] if tracking else 0
    )
    return ContextHandle(response[:CONTEXT_SIZE], payload, tracking, response_byte)


def build_delete(handle: ContextHandle) -> bytes:
    """Build a delete command; the payload/tracking metadata is not serialized."""
    if not isinstance(handle, ContextHandle):
        raise ACMProtocolError("handle must be a ContextHandle")
    return _header(OP_CONTEXT_DELETE) + handle.context


def build_externalize(handle: ContextHandle) -> bytes:
    """Register and return the existing 16-byte context as an external form."""
    if not isinstance(handle, ContextHandle):
        raise ACMProtocolError("handle must be a ContextHandle")
    return _header(OP_CONTEXT_EXTERNALIZE) + handle.context


def build_enrollment_policy(handle: ContextHandle, *, preflight: bool) -> bytes:
    """Build policy 1007's exact empty-parameter request."""
    if not isinstance(handle, ContextHandle):
        raise ACMProtocolError("handle must be a ContextHandle")
    return (
        _header(OP_VERIFY_POLICY)
        + handle.context
        + ENROLLMENT_POLICY
        + b"\x00"
        + bytes((int(preflight),))
        + struct.pack("<I", 0)  # absent maxGlobalCredentialAge option
        + struct.pack("<I", 0)  # empty ACM parameter array
    )


def build_enrollment_policy_preflight(handle: ContextHandle) -> bytes:
    return build_enrollment_policy(handle, preflight=True)


def parse_policy_response(response: bytes) -> PolicyResult:
    if (
        type(response) is not bytes
        or not 4 <= len(response) <= POLICY_RESPONSE_CAPACITY
    ):
        raise ACMProtocolError("policy response length is invalid")
    raw_result = struct.unpack_from("<I", response)[0]
    if raw_result not in (0, 1):
        raise ACMProtocolError("policy result is not boolean")
    requirement = response[4:]
    if not requirement:
        return PolicyResult(bool(raw_result), False, 0, None, None, None, None)
    if len(requirement) < 16:
        raise ACMProtocolError("policy requirement is shorter than its header")
    req_type, state, flags, payload_length = struct.unpack_from(
        "<IIII", requirement
    )
    if req_type not in SIMPLE_REQUIREMENT_TYPES:
        raise ACMProtocolError("policy returned an unsupported requirement type")
    if payload_length != len(requirement) - 16:
        raise ACMProtocolError("policy requirement payload length is inconsistent")
    return PolicyResult(
        bool(raw_result),
        True,
        len(requirement),
        req_type,
        state,
        flags,
        payload_length,
    )


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
        OP_CONTEXT_EXTERNALIZE: 24,
        OP_VERIFY_POLICY: 51,
    }.get(opcode)
    if expected is None or len(command) != expected:
        raise ACMProtocolError("command opcode or length is not allowed")
    if opcode == OP_VERIFY_POLICY:
        fixed = command[24:]
        if (
            fixed[:18] != ENROLLMENT_POLICY + b"\x00"
            or fixed[18] not in (0, 1)
            or fixed[19:] != b"\x00" * 8
        ):
            raise ACMProtocolError("policy command is not the fixed enrollment policy")
    return opcode
