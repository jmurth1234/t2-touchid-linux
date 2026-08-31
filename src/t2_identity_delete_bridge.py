# SPDX-License-Identifier: GPL-2.0-only
"""One-shot, generation-pinned Bridge adapter for identity command 0x0d."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

import t2_bridge_wire


class IdentityDeleteBridgeError(RuntimeError):
    pass


class DeleteLease(Protocol):
    connection_generation: str

    def biometric_command(
        self,
        command: int,
        *,
        version: int,
        value: int,
        data: bytes,
        output_capacity: int,
    ) -> tuple[object, list[object]]: ...

    def invalidate(self) -> None: ...


class DeleteBridgeState(Enum):
    READY = "ready"
    DISPATCHED = "dispatched"
    POISONED = "poisoned"


@dataclass(frozen=True)
class IdentityDeleteCommandResult:
    status: int
    output_length: int = 0
    service_event_count: int = 0


class IdentityDeleteBridge:
    def __init__(self, lease: DeleteLease, *, connection_generation: str) -> None:
        try:
            parsed = uuid.UUID(connection_generation)
        except (AttributeError, TypeError, ValueError) as error:
            raise IdentityDeleteBridgeError("connection generation is invalid") from error
        if (
            str(parsed) != connection_generation
            or lease.connection_generation != connection_generation
        ):
            raise IdentityDeleteBridgeError("delete Bridge generation changed")
        self._lease = lease
        self.connection_generation = connection_generation
        self._state = DeleteBridgeState.READY

    @property
    def state(self) -> DeleteBridgeState:
        return self._state

    def __repr__(self) -> str:
        return (
            "IdentityDeleteBridge(connection_generation="
            f"{self.connection_generation!r}, state={self._state.value!r})"
        )

    def _poison(self) -> None:
        self._state = DeleteBridgeState.POISONED
        try:
            self._lease.invalidate()
        except BaseException:
            pass

    def delete(self, request: bytes) -> IdentityDeleteCommandResult:
        if self._state is not DeleteBridgeState.READY:
            raise IdentityDeleteBridgeError("identity delete Bridge is not reusable")
        if type(request) is not bytes or len(request) != 20:
            raise IdentityDeleteBridgeError("identity delete request must be 20 bytes")
        try:
            reply, events = self._lease.biometric_command(
                0x0D,
                version=0,
                value=0,
                data=request,
                output_capacity=0,
            )
            self._state = DeleteBridgeState.DISPATCHED
            if (
                self._lease.connection_generation != self.connection_generation
                or type(reply) is not list
                or len(reply) != 2
                or type(reply[0]) is not int
                or isinstance(reply[0], bool)
                or not -(2**31) <= reply[0] < 2**32
                or type(events) is not list
                or events
            ):
                raise IdentityDeleteBridgeError("identity delete reply is malformed")
            output = reply[1]
            if t2_bridge_wire.is_biometric_nil_output(output):
                output = b""
            if type(output) is not bytes or output:
                raise IdentityDeleteBridgeError("identity delete returned unexpected data")
            return IdentityDeleteCommandResult(reply[0])
        except BaseException as error:
            self._poison()
            if isinstance(error, IdentityDeleteBridgeError):
                raise
            raise IdentityDeleteBridgeError(
                "identity delete transport is ambiguous"
            ) from error
