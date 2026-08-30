"""Narrow userspace client for the root-only T2 ACM lifecycle ioctl."""

from __future__ import annotations

import ctypes
import fcntl
import os
import struct
from pathlib import Path
from collections.abc import Callable

import t2_acm_protocol as protocol


DEVICE = Path("/dev/t2-acm")
INFO_FORMAT = "=QII"
EXCHANGE_FORMAT = "=B3xIIIIIQQQ"
INFO_SIZE = struct.calcsize(INFO_FORMAT)
EXCHANGE_SIZE = struct.calcsize(EXCHANGE_FORMAT)


class ACMDeviceError(RuntimeError):
    pass


def _ioc(direction: int, kind: int, number: int, size: int) -> int:
    if not 0 <= direction < 4 or not 0 <= kind < 256 or not 0 <= number < 256:
        raise ValueError("invalid ioctl field")
    if not 0 <= size < (1 << 14):
        raise ValueError("invalid ioctl size")
    return (direction << 30) | (size << 16) | (kind << 8) | number


T2_ACM_IOC_EXCHANGE = _ioc(3, 0xAC, 0, EXCHANGE_SIZE)
T2_ACM_IOC_GET_INFO = _ioc(2, 0xAC, 1, INFO_SIZE)
T2_ACM_INFO_F_POISONED = 1 << 0


def _address(buffer: bytearray) -> int:
    return ctypes.addressof((ctypes.c_ubyte * len(buffer)).from_buffer(buffer))


def _zero(buffer: bytearray) -> None:
    if buffer:
        ctypes.memset(_address(buffer), 0, len(buffer))


def _signed_u32(value: int) -> int:
    return value if value < 0x80000000 else value - 0x100000000


def _registration_generation(info: bytes | bytearray) -> int:
    if len(info) != INFO_SIZE:
        raise ACMDeviceError("invalid endpoint-10 registration metadata")
    generation, capacity, flags = struct.unpack(INFO_FORMAT, info)
    if (
        generation == 0
        or capacity != 16384
        or flags & ~T2_ACM_INFO_F_POISONED
    ):
        raise ACMDeviceError("invalid endpoint-10 registration metadata")
    if flags & T2_ACM_INFO_F_POISONED:
        raise ACMDeviceError(
            "endpoint-10 has an ambiguous late reply; reboot required"
        )
    return generation


class ACMDevice:
    def __init__(self, path: Path = DEVICE) -> None:
        self.fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            info = bytearray(INFO_SIZE)
            fcntl.ioctl(self.fd, T2_ACM_IOC_GET_INFO, info, True)
            self.generation = _registration_generation(info)
        except BaseException:
            os.close(self.fd)
            self.fd = -1
            raise

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> "ACMDevice":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def exchange(self, command: bytes, response_capacity: int) -> bytes:
        if self.fd < 0:
            raise ACMDeviceError("ACM device is closed")
        protocol.validate_command(command)
        if not 0 <= response_capacity <= 16384:
            raise ACMDeviceError("invalid response capacity")
        request = bytearray(command)
        response = bytearray(response_capacity)
        request_address = _address(request)
        response_address = _address(response) if response else 0
        exchange = bytearray(
            struct.pack(
                EXCHANGE_FORMAT,
                1,
                len(request),
                response_capacity,
                0,
                0,
                0,
                self.generation,
                request_address,
                response_address,
            )
        )
        try:
            fcntl.ioctl(self.fd, T2_ACM_IOC_EXCHANGE, exchange, True)
            (
                request_code,
                request_length,
                returned_capacity,
                response_length,
                request_info,
                response_info,
                generation,
                returned_request,
                returned_response,
            ) = struct.unpack(EXCHANGE_FORMAT, exchange)
            if (
                request_code != 1
                or request_length != len(request)
                or returned_capacity != response_capacity
                or request_info != 0
                or generation != self.generation
                or returned_request != request_address
                or returned_response != response_address
            ):
                raise ACMDeviceError("kernel altered immutable exchange metadata")
            if response_info != 0:
                raise ACMDeviceError(
                    f"SEP rejected ACM command with status {_signed_u32(response_info)}"
                )
            if response_length > response_capacity:
                raise ACMDeviceError("kernel returned an oversized ACM response")
            return bytes(response[:response_length])
        finally:
            _zero(exchange)
            _zero(response)
            _zero(request)


def lifecycle_test(device: ACMDevice, user_id: int) -> dict[str, object]:
    """Create one tracked context and guarantee a delete attempt before return."""
    response = device.exchange(
        protocol.build_create(user_id=user_id, tracking=True), 21
    )
    if len(response) < protocol.CONTEXT_SIZE:
        raise ACMDeviceError(
            "create response omitted the context required for mandatory cleanup"
        )
    cleanup_handle = protocol.ContextHandle(
        response[: protocol.CONTEXT_SIZE], 0, True, False
    )
    parsed = None
    primary_error: BaseException | None = None
    response_shape = (
        f"length={len(response)}, "
        f"terminal_flag_boolean={response[-1] in (0, 1)}"
    )
    try:
        parsed = protocol.parse_create_response(response, tracking=True)
    except BaseException as error:
        primary_error = error
    try:
        delete_response = device.exchange(protocol.build_delete(cleanup_handle), 0)
        if delete_response:
            raise ACMDeviceError("delete returned an unexpected response body")
    except BaseException as cleanup_error:
        if primary_error is not None:
            raise ACMDeviceError(
                f"create response was invalid and cleanup failed: {cleanup_error}"
            ) from primary_error
        raise ACMDeviceError(
            f"mandatory context cleanup failed: {cleanup_error}"
        ) from cleanup_error
    if primary_error is not None:
        raise ACMDeviceError(
            f"create response was invalid ({response_shape}); context was cleaned up"
        ) from primary_error
    assert parsed is not None
    return {
        "schema_version": 1,
        "create_succeeded": True,
        "tracking_response": parsed.tracking,
        "response_flag_boolean": type(parsed.response_flag) is bool,
        "delete_succeeded": True,
        "context_identifier_redacted": True,
        "mutation_reconciled": True,
    }


def policy_preflight_test(device: ACMDevice, user_id: int) -> dict[str, object]:
    """Observe policy 1007's requirement and guarantee context deletion."""
    response = device.exchange(
        protocol.build_create(user_id=user_id, tracking=True), 21
    )
    if len(response) < protocol.CONTEXT_SIZE:
        raise ACMDeviceError(
            "create response omitted the context required for mandatory cleanup"
        )
    cleanup_handle = protocol.ContextHandle(
        response[: protocol.CONTEXT_SIZE], 0, True, False
    )
    result = None
    primary_error: BaseException | None = None
    try:
        handle = protocol.parse_create_response(response, tracking=True)
        policy_response = device.exchange(
            protocol.build_enrollment_policy_preflight(handle),
            protocol.POLICY_RESPONSE_CAPACITY,
        )
        result = protocol.parse_policy_response(policy_response)
    except BaseException as error:
        primary_error = error
    try:
        delete_response = device.exchange(protocol.build_delete(cleanup_handle), 0)
        if delete_response:
            raise ACMDeviceError("delete returned an unexpected response body")
    except BaseException as cleanup_error:
        if primary_error is not None:
            raise ACMDeviceError(
                f"policy preflight failed and mandatory cleanup failed: {cleanup_error}"
            ) from primary_error
        raise ACMDeviceError(f"mandatory context cleanup failed: {cleanup_error}") from cleanup_error
    if primary_error is not None:
        raise ACMDeviceError(
            "policy preflight failed; context was cleaned up"
        ) from primary_error
    assert result is not None
    return {
        "schema_version": 1,
        "policy": 1007,
        "preflight_only": True,
        "policy_satisfied": result.satisfied,
        "requirement_present": result.requirement_present,
        "requirement_length": result.requirement_length,
        "requirement_type": result.requirement_type,
        "requirement_state": result.requirement_state,
        "requirement_flags": result.requirement_flags,
        "requirement_payload_length": result.requirement_payload_length,
        "context_identifier_redacted": True,
        "delete_succeeded": True,
        "mutation_reconciled": True,
    }


def authorization_test(
    device: ACMDevice,
    user_id: int,
    password_binder: Callable[[bytes], None],
    *,
    tracking: bool = True,
) -> dict[str, object]:
    """Bind a password, evaluate policy 1007, and always destroy the context."""
    response_capacity = 21 if tracking else 17
    response = device.exchange(
        protocol.build_create(user_id=user_id, tracking=tracking),
        response_capacity,
    )
    if len(response) < protocol.CONTEXT_SIZE:
        raise ACMDeviceError(
            "create response omitted the context required for mandatory cleanup"
        )
    cleanup_handle = protocol.ContextHandle(
        response[: protocol.CONTEXT_SIZE], 0, tracking, False
    )
    initial = final = None
    primary_error: BaseException | None = None
    try:
        handle = protocol.parse_create_response(response, tracking=tracking)
        initial = protocol.parse_policy_response(
            device.exchange(
                protocol.build_enrollment_policy(handle, preflight=True),
                protocol.POLICY_RESPONSE_CAPACITY,
            )
        )
        if initial.satisfied or initial.requirement_type != 1:
            raise ACMDeviceError("initial policy state is not the passcode requirement")
        password_binder(handle.context)
        final = protocol.parse_policy_response(
            device.exchange(
                protocol.build_enrollment_policy(handle, preflight=False),
                protocol.POLICY_RESPONSE_CAPACITY,
            )
        )
        if not final.satisfied:
            raise ACMDeviceError("policy 1007 remained unsatisfied after password binding")
    except BaseException as error:
        primary_error = error
    try:
        delete_response = device.exchange(protocol.build_delete(cleanup_handle), 0)
        if delete_response:
            raise ACMDeviceError("delete returned an unexpected response body")
    except BaseException as cleanup_error:
        if primary_error is not None:
            raise ACMDeviceError(
                f"authorization failed and mandatory cleanup failed: {cleanup_error}"
            ) from primary_error
        raise ACMDeviceError(f"mandatory context cleanup failed: {cleanup_error}") from cleanup_error
    if primary_error is not None:
        raise ACMDeviceError("authorization failed; context was cleaned up") from primary_error
    assert initial is not None and final is not None
    return {
        "schema_version": 1,
        "policy": 1007,
        "initial_requirement_type": initial.requirement_type,
        "context_create_tracking": tracking,
        "password_bound": True,
        "policy_satisfied": final.satisfied,
        "context_identifier_redacted": True,
        "delete_succeeded": True,
        "mutation_reconciled": True,
        "fingerprint_mutation_performed": False,
    }
