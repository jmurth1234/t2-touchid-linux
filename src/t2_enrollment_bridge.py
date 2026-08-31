# SPDX-License-Identifier: GPL-2.0-only
"""Generation-pinned Bridge adapter for one enrollment operation.

This module opens no socket and exposes no command-line entry point.  A future
privileged broker must inject an already-open exclusive Bridge lease whose
baseline was collected on the same connection.  Any ambiguous condition after
dispatch permanently poisons this adapter so the typed journal can require
reconciliation rather than retrying enrollment.
"""

from __future__ import annotations

import uuid
from collections import deque
from enum import Enum
from typing import Protocol

import t2_enrollment_protocol as protocol
import t2_bridge_wire as wire


COMMAND_CANCEL = 0x0C
PAYLOADLESS_COMMAND_VERSION = 1


class EnrollmentBridgeError(RuntimeError):
    """Raised when an enrollment Bridge operation cannot be trusted."""


class EnrollmentBridgeLease(Protocol):
    """Exclusive same-connection lease supplied by a future broker."""

    connection_generation: str

    def biometric_command(
        self,
        command: int,
        *,
        version: int,
        value: int,
        data: bytes | memoryview,
        output_capacity: int,
    ) -> tuple[object, list[object]]: ...

    def wait_service_event(self, timeout: float) -> object | None: ...


class EnrollmentBridgeState(Enum):
    IDLE = "idle"
    ACTIVE = "active"
    CANCEL_REQUESTED = "cancel-requested"
    START_REJECTED = "start-rejected"
    POISONED = "poisoned"


class EnrollmentBridgeTransport:
    """One exact, synchronous enrollment transport over a pinned lease."""

    def __init__(
        self,
        lease: EnrollmentBridgeLease,
        *,
        protocol_version: int,
        connection_generation: str,
    ) -> None:
        if type(protocol_version) is not int or protocol_version not in (1, 2):
            raise EnrollmentBridgeError("enrollment protocol must be version 1 or 2")
        try:
            parsed_generation = uuid.UUID(connection_generation)
        except (AttributeError, TypeError, ValueError) as error:
            raise EnrollmentBridgeError("connection generation must be a UUID") from error
        if str(parsed_generation) != connection_generation:
            raise EnrollmentBridgeError("connection generation is not canonical")
        if lease.connection_generation != connection_generation:
            raise EnrollmentBridgeError("Bridge lease belongs to another generation")
        self._lease = lease
        self.protocol_version = protocol_version
        self.connection_generation = connection_generation
        self._state = EnrollmentBridgeState.IDLE
        self._events: deque[bytes] = deque()

    @property
    def state(self) -> EnrollmentBridgeState:
        return self._state

    def __repr__(self) -> str:
        return (
            "EnrollmentBridgeTransport(protocol_version="
            f"{self.protocol_version}, connection_generation="
            f"{self.connection_generation!r}, state={self._state.value!r}, "
            f"queued_events={len(self._events)})"
        )

    def _poison(self) -> None:
        self._state = EnrollmentBridgeState.POISONED
        self._events.clear()

    def _require_state(
        self, allowed: tuple[EnrollmentBridgeState, ...], operation: str
    ) -> None:
        if self._state is EnrollmentBridgeState.POISONED:
            raise EnrollmentBridgeError(
                "enrollment Bridge generation is poisoned; reconciliation is required"
            )
        if self._state not in allowed:
            raise EnrollmentBridgeError(f"enrollment {operation} is out of order")

    @staticmethod
    def _event_data(value: object) -> bytes:
        if (
            type(value) is not list
            or len(value) != 5
            or value[0] != 9
            or value[1] != protocol.BRIDGE_SERVICE_STATUS
            or type(value[2]) is not bytes
            or not protocol.SERVICE_HEADER.size
            <= len(value[2])
            <= protocol.SERVICE_HEADER.size + protocol.MAX_EVENT_PAYLOAD
        ):
            raise EnrollmentBridgeError("Bridge service event is malformed")
        return value[2]

    def _check_generation(self) -> None:
        if self._lease.connection_generation != self.connection_generation:
            raise EnrollmentBridgeError("Bridge connection generation changed")

    def _dispatch(
        self,
        command: int,
        data: bytes | memoryview,
        *,
        poison_nonzero: bool,
        status_authoritative: bool = True,
        wire_version: int | None = None,
    ) -> int:
        selected_version = (
            self.protocol_version if wire_version is None else wire_version
        )
        if type(selected_version) is not int or selected_version not in (1, 2):
            raise EnrollmentBridgeError("enrollment command wire version is invalid")
        try:
            self._check_generation()
            result = self._lease.biometric_command(
                command,
                version=selected_version,
                value=0,
                data=data,
                output_capacity=0,
            )
            self._check_generation()
            if type(result) is not tuple or len(result) != 2:
                raise EnrollmentBridgeError("Bridge command result is malformed")
            reply, events = result
            if type(reply) is not list or len(reply) not in (1, 2):
                raise EnrollmentBridgeError("Bridge command reply is malformed")
            status = reply[0]
            output = reply[1] if len(reply) == 2 else None
            if (
                type(status) is not int
                or isinstance(status, bool)
                or not -(2**31) <= status < 2**32
            ):
                raise EnrollmentBridgeError("Bridge command status is malformed")
            # bkremoted substitutes one fixed CFString sentinel when the
            # Objective-C output pointer is nil.  Depending on the decoder or
            # bridge build, the same zero-capacity result can instead omit the
            # second item, decode it as null, or materialize empty NSData.
            # Never accept a different UUID/string as equivalent to nil.
            empty_output = (
                output is None
                or (type(output) is bytes and len(output) == 0)
                or wire.is_biometric_nil_output(output)
            )
            if not empty_output:
                raise EnrollmentBridgeError("enrollment command returned unexpected data")
            if type(events) is not list:
                raise EnrollmentBridgeError("Bridge command events are malformed")
            staged_events = [self._event_data(event) for event in events]
            if status_authoritative and status != 0 and staged_events:
                raise EnrollmentBridgeError(
                    "rejected enrollment command also emitted service events"
                )
            self._events.extend(staged_events)
            if status_authoritative and status != 0 and poison_nonzero:
                self._poison()
            return status
        except BaseException as error:
            self._poison()
            if isinstance(error, EnrollmentBridgeError):
                raise
            raise EnrollmentBridgeError(
                "enrollment Bridge dispatch failed; reconciliation is required"
            ) from error

    def start(self, payload: memoryview) -> int:
        self._require_state((EnrollmentBridgeState.IDLE,), "start")
        expected_length = 48 if self.protocol_version == 1 else 68
        if (
            type(payload) is not memoryview
            or payload.ndim != 1
            or payload.itemsize != 1
            or payload.nbytes != expected_length
            or not payload.readonly
        ):
            raise EnrollmentBridgeError("enrollment start payload is invalid")
        status = self._dispatch(
            protocol.COMMAND_ENROLL_START, payload, poison_nonzero=False
        )
        self._state = (
            EnrollmentBridgeState.ACTIVE
            if status == 0
            else EnrollmentBridgeState.START_REJECTED
        )
        return status

    def continue_enrollment(self) -> int:
        self._require_state((EnrollmentBridgeState.ACTIVE,), "continue")
        # The exact daemon's payload-less wrapper calls
        # performCommand:inValue:... and hardcodes wire version 1.  Only the
        # initial enrollment request selects biometric protocol version 1/2.
        return self._dispatch(
            protocol.COMMAND_ENROLL_CONTINUE,
            protocol.build_continue_payload(),
            poison_nonzero=False,
            status_authoritative=False,
            wire_version=PAYLOADLESS_COMMAND_VERSION,
        )

    def cancel(self) -> int:
        self._require_state((EnrollmentBridgeState.ACTIVE,), "cancel")
        status = self._dispatch(
            COMMAND_CANCEL,
            b"",
            poison_nonzero=True,
            wire_version=PAYLOADLESS_COMMAND_VERSION,
        )
        if status == 0:
            self._state = EnrollmentBridgeState.CANCEL_REQUESTED
        return status

    def next_event(self, *, timeout: float = 1.0) -> bytes | None:
        self._require_state(
            (
                EnrollmentBridgeState.ACTIVE,
                EnrollmentBridgeState.CANCEL_REQUESTED,
            ),
            "event receive",
        )
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 0 < timeout <= 5
        ):
            raise EnrollmentBridgeError("enrollment event poll timeout is invalid")
        if self._events:
            return self._events.popleft()
        try:
            self._check_generation()
            value = self._lease.wait_service_event(float(timeout))
            self._check_generation()
            if value is None:
                return None
            return self._event_data(value)
        except BaseException as error:
            self._poison()
            if isinstance(error, EnrollmentBridgeError):
                raise
            raise EnrollmentBridgeError(
                "enrollment service-event receive failed; reconciliation is required"
            ) from error
