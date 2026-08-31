# SPDX-License-Identifier: GPL-2.0-only
"""Generation-pinned, one-shot Bridge adapter for bio-lockout export."""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Protocol

import t2_biolockout_protocol as protocol


class BioLockoutBridgeError(RuntimeError):
    """Raised when the bio-lockout export outcome cannot be trusted."""


class BridgeLease(Protocol):
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


class BioLockoutBridgeState(Enum):
    READY = "ready"
    CAPTURED = "captured"
    POISONED = "poisoned"


def _wipe(value: bytearray) -> None:
    value[:] = b"\x00" * len(value)


class BioLockoutBridgeTransport:
    """Export one record from one initialized Bridge connection generation."""

    def __init__(self, lease: BridgeLease, *, connection_generation: str) -> None:
        try:
            parsed = uuid.UUID(connection_generation)
        except (AttributeError, TypeError, ValueError) as error:
            raise BioLockoutBridgeError(
                "connection generation must be a UUID"
            ) from error
        if str(parsed) != connection_generation:
            raise BioLockoutBridgeError("connection generation is not canonical")
        if lease.connection_generation != connection_generation:
            raise BioLockoutBridgeError("Bridge lease belongs to another generation")
        self._lease = lease
        self.connection_generation = connection_generation
        self._state = BioLockoutBridgeState.READY

    @property
    def state(self) -> BioLockoutBridgeState:
        return self._state

    def __repr__(self) -> str:
        return (
            "BioLockoutBridgeTransport(connection_generation="
            f"{self.connection_generation!r}, state={self._state.value!r})"
        )

    def _poison(self) -> None:
        self._state = BioLockoutBridgeState.POISONED
        try:
            self._lease.invalidate()
        except BaseException:
            pass

    def capture(self) -> bytearray:
        if self._state is BioLockoutBridgeState.POISONED:
            raise BioLockoutBridgeError(
                "bio-lockout Bridge generation is poisoned; reconciliation is required"
            )
        if self._state is not BioLockoutBridgeState.READY:
            raise BioLockoutBridgeError("bio-lockout record was already captured")
        request = protocol.build_save_request()
        dispatched = False
        output: bytearray | None = None
        try:
            if self._lease.connection_generation != self.connection_generation:
                raise BioLockoutBridgeError("Bridge connection generation changed")
            dispatched = True
            result = self._lease.biometric_command(
                request.command,
                version=request.version,
                value=request.value,
                data=request.data,
                output_capacity=request.output_capacity,
            )
            if self._lease.connection_generation != self.connection_generation:
                raise BioLockoutBridgeError("Bridge connection generation changed")
            if type(result) is not tuple or len(result) != 2:
                raise BioLockoutBridgeError("bio-lockout Bridge result is malformed")
            reply, events = result
            if type(events) is not list or events:
                raise BioLockoutBridgeError(
                    "bio-lockout save emitted an unexpected service event"
                )
            if type(reply) is not list or len(reply) != 2:
                raise BioLockoutBridgeError("bio-lockout save reply is malformed")
            output = protocol.parse_save_reply(reply[0], reply[1])
            self._state = BioLockoutBridgeState.CAPTURED
            return output
        except BaseException as error:
            if output is not None:
                _wipe(output)
            if dispatched:
                self._poison()
            if isinstance(error, BioLockoutBridgeError):
                raise
            if isinstance(error, protocol.BioLockoutProtocolError):
                raise BioLockoutBridgeError(
                    "bio-lockout save reply is invalid; reconciliation is required"
                ) from error
            raise BioLockoutBridgeError(
                "bio-lockout save failed; reconciliation is required"
            ) from error
