# SPDX-License-Identifier: GPL-2.0-only
"""Pinned, fail-closed adapter from Bridge replies to Catacomb persistence.

The adapter owns no socket and exposes no command-line entry point.  A future
broker must inject an already-open, exclusively leased Bridge connection.  The
adapter validates the exact recovered command contract and makes any ambiguous
post-dispatch condition terminal for its lifetime.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Protocol

import t2_catacomb_protocol as protocol
import t2_bridge_wire as wire


class CatacombBridgeError(RuntimeError):
    """Raised when a Catacomb Bridge transaction cannot be trusted."""


class BridgeLease(Protocol):
    """Exclusive same-connection command lease supplied by a future broker."""

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


class TransactionState(Enum):
    IDLE = "idle"
    PREPARED = "prepared"
    COMPLETED = "completed"
    POISONED = "poisoned"


def _wipe(value: bytearray) -> None:
    value[:] = b"\x00" * len(value)


def collect_builtin_save_components(
    lease: BridgeLease,
    *,
    apple_user_id: int,
    connection_generation: str,
) -> tuple[protocol.CatacombComponent, ...]:
    """Double-read post-E2 state and derive one exact built-in save list."""
    try:
        parsed_generation = uuid.UUID(connection_generation)
        if str(parsed_generation) != connection_generation:
            raise CatacombBridgeError("connection generation is not canonical")
        if lease.connection_generation != connection_generation:
            raise CatacombBridgeError("Bridge lease belongs to another generation")
        protocol.CatacombComponent.user(apple_user_id)
    except (AttributeError, TypeError, ValueError, protocol.CatacombProtocolError) as error:
        if isinstance(error, CatacombBridgeError):
            raise
        raise CatacombBridgeError("Catacomb save-state request is invalid") from error

    dispatched = False
    try:
        outputs: list[bytes] = []
        for _attempt in range(2):
            dispatched = True
            reply, events = lease.biometric_command(
                0x3C,
                # The command wrapper remains version 1 under biometric protocol 2.
                version=1,
                value=0,
                data=b"",
                output_capacity=4096,
            )
            if lease.connection_generation != connection_generation:
                raise CatacombBridgeError("Bridge connection generation changed")
            if type(events) is not list or events:
                raise CatacombBridgeError(
                    "Catacomb save-state query emitted an unexpected event"
                )
            if (
                type(reply) is not list
                or len(reply) != 2
                or type(reply[0]) is not int
                or isinstance(reply[0], bool)
                or reply[0] != 0
                or type(reply[1]) is not bytes
                or len(reply[1]) > 4096
            ):
                raise CatacombBridgeError("Catacomb save-state reply is malformed")
            outputs.append(reply[1])
        if outputs[0] != outputs[1]:
            raise CatacombBridgeError("Catacomb save state changed between reads")
        states = protocol.parse_user_states(outputs[0])
        return protocol.plan_builtin_enrollment_save(states, apple_user_id)
    except BaseException as error:
        if dispatched:
            try:
                lease.invalidate()
            except BaseException:
                pass
        if isinstance(error, CatacombBridgeError):
            raise
        if isinstance(error, protocol.CatacombProtocolError):
            raise CatacombBridgeError("Catacomb save state is unsafe") from error
        raise CatacombBridgeError(
            "Catacomb save-state collection failed; reconciliation is required"
        ) from error


class CatacombBridgeTransport:
    """One exclusive, generation-pinned Catacomb persistence transport."""

    def __init__(
        self,
        lease: BridgeLease,
        *,
        protocol_version: int,
        connection_generation: str,
    ) -> None:
        if type(protocol_version) is not int or protocol_version not in (1, 2):
            raise CatacombBridgeError("Catacomb protocol must be version 1 or 2")
        try:
            parsed_generation = uuid.UUID(connection_generation)
        except (TypeError, ValueError, AttributeError) as error:
            raise CatacombBridgeError("connection generation must be a UUID") from error
        if str(parsed_generation) != connection_generation:
            raise CatacombBridgeError("connection generation is not canonical")
        if lease.connection_generation != connection_generation:
            raise CatacombBridgeError("Bridge lease belongs to another generation")
        self._lease = lease
        self.protocol_version = protocol_version
        self.connection_generation = connection_generation
        self._state = TransactionState.IDLE
        self._descriptor: bytes | None = None
        self._expected_length: int | None = None

    @property
    def state(self) -> TransactionState:
        return self._state

    def __repr__(self) -> str:
        return (
            "CatacombBridgeTransport(protocol_version="
            f"{self.protocol_version}, connection_generation="
            f"{self.connection_generation!r}, state={self._state.value!r}, "
            "descriptor=<redacted>)"
        )

    def _require_state(self, expected: TransactionState, operation: str) -> None:
        if self._state is TransactionState.POISONED:
            raise CatacombBridgeError(
                "Catacomb Bridge generation is poisoned; reconciliation is required"
            )
        if self._state is not expected:
            raise CatacombBridgeError(f"Catacomb {operation} is out of order")

    def _require_descriptor(self, descriptor: bytes) -> None:
        if type(descriptor) is not bytes or descriptor != self._descriptor:
            raise CatacombBridgeError(
                "Catacomb component changed during the persistence transaction"
            )

    def _poison(self) -> None:
        self._state = TransactionState.POISONED

    def _dispatch(
        self, request: protocol.CatacombRequest
    ) -> tuple[int, bytes]:
        try:
            if self._lease.connection_generation != self.connection_generation:
                raise CatacombBridgeError("Bridge connection generation changed")
            result = self._lease.biometric_command(
                request.command,
                version=request.protocol_version,
                value=0,
                data=request.descriptor,
                output_capacity=request.output_capacity,
            )
            if self._lease.connection_generation != self.connection_generation:
                raise CatacombBridgeError("Bridge connection generation changed")
            if type(result) is not tuple or len(result) != 2:
                raise CatacombBridgeError("Bridge command result is malformed")
            reply, events = result
            if type(events) is not list or events:
                raise CatacombBridgeError(
                    "Catacomb command emitted an unexpected service event"
                )
            if type(reply) is not list or len(reply) != 2:
                raise CatacombBridgeError("Bridge command reply is malformed")
            status, output = reply
            if type(status) is not int or not -(2**31) <= status < 2**32:
                raise CatacombBridgeError("Bridge command status is malformed")
            if request.output_capacity == 0 and wire.is_biometric_nil_output(output):
                output = b""
            if type(output) is not bytes:
                raise CatacombBridgeError("Bridge command output is not byte data")
            if len(output) > request.output_capacity:
                raise CatacombBridgeError("Bridge command exceeded its output capacity")
            return status, output
        except BaseException as error:
            # Entry into _dispatch follows all local request checks. Even a
            # failed generation read means this lease can no longer prove
            # whether it is the same connection, so it is never reusable.
            self._poison()
            if isinstance(error, CatacombBridgeError):
                raise
            raise CatacombBridgeError(
                "Catacomb Bridge dispatch failed; reconciliation is required"
            ) from error

    def prepare(self, descriptor: bytes) -> tuple[int, int]:
        self._require_state(TransactionState.IDLE, "prepare")
        try:
            request = protocol.build_prepare_request(
                self.protocol_version, descriptor
            )
        except protocol.CatacombProtocolError as error:
            raise CatacombBridgeError("Catacomb prepare descriptor is invalid") from error
        status, output = self._dispatch(request)
        try:
            expected_length = protocol.parse_prepare_reply(status, output)
        except protocol.CatacombProtocolError as error:
            self._poison()
            raise CatacombBridgeError("Catacomb prepare reply is invalid") from error
        self._descriptor = descriptor
        self._expected_length = expected_length
        self._state = TransactionState.PREPARED
        return 0, expected_length

    def complete(self, descriptor: bytes) -> tuple[int, bytearray]:
        self._require_state(TransactionState.PREPARED, "complete")
        self._require_descriptor(descriptor)
        assert self._expected_length is not None
        request = protocol.build_complete_request(
            self.protocol_version, descriptor, self._expected_length
        )
        status, immutable_output = self._dispatch(request)
        output = bytearray(immutable_output)
        try:
            parsed = protocol.parse_complete_reply(
                status, output, self._expected_length
            )
        except protocol.CatacombProtocolError as error:
            _wipe(output)
            self._poison()
            raise CatacombBridgeError("Catacomb complete reply is invalid") from error
        self._state = TransactionState.COMPLETED
        return 0, parsed

    def confirm(self, descriptor: bytes) -> int:
        self._require_state(TransactionState.COMPLETED, "confirm")
        self._require_descriptor(descriptor)
        request = protocol.build_confirm_request(
            self.protocol_version, descriptor
        )
        status, output = self._dispatch(request)
        try:
            protocol.parse_confirm_reply(status, output)
        except protocol.CatacombProtocolError as error:
            self._poison()
            raise CatacombBridgeError("Catacomb confirm reply is invalid") from error
        self._descriptor = None
        self._expected_length = None
        self._state = TransactionState.IDLE
        return 0
