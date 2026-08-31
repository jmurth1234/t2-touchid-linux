# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed, transport-independent T2 enrollment protocol primitives.

Nothing in this module opens BridgeXPC or sends a biometric command.  It makes
the statically recovered request layout and asynchronous event rules testable
before a mutating transport consumer exists.
"""

from __future__ import annotations

import hashlib
import struct
from collections import deque
from dataclasses import dataclass
from enum import Enum


COMMAND_ENROLL_START = 0x03
COMMAND_ENROLL_CONTINUE = 0x0E
BRIDGE_SERVICE_STATUS = 0xE3FF8000
SERVICE_STATUS = 0xE3FF8001
SERVICE_ENROLLMENT_RESULT = 0xE3FF8003
SERVICE_STATISTICS = 0xE3FF8004
SERVICE_SKS_LOCK_STATE = 0xE3FF800A
SERVICE_ACCESSORY_AUTHORIZATION = 0xE3FF800E
SERVICE_HEADER = struct.Struct("<QIIQ")
STATUS_PAYLOAD_HEADER = struct.Struct("<I4xQ")
SKS_LOCK_STATE_PAYLOAD = struct.Struct("<IH")
STATISTICS_MIN_PAYLOAD_SIZE = 12
AUTH_DATA_SIZE = 40
ACM_EXTERNAL_FORM_SIZE = 16
BUILTIN_GROUPS = frozenset((bytes(20), struct.pack("<I16x", 1)))
MAX_EVENT_PAYLOAD = 1024 * 1024
MAX_EVENT_FINGERPRINTS = 64
EXACT_NOOP_PHASE_STATUSES = frozenset((55, 72, 90))


class EnrollmentProtocolError(ValueError):
    """Raised when enrollment framing or sequencing is ambiguous."""


class EnrollmentState(Enum):
    ACTIVE = "active"
    CANCEL_REQUESTED = "cancel-requested"
    SEP_IDENTITY_OBSERVED = "sep-identity-observed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    FROZEN = "frozen"


class EnrollmentAction(Enum):
    IGNORE_TELEMETRY = "ignore-telemetry"
    IGNORE_AUXILIARY = "ignore-auxiliary"
    IGNORE_PHASE = "ignore-phase"
    FINGER_PRESENT = "finger-present"
    FINGER_REMOVED = "finger-removed"
    CONTINUE = "continue"
    PROGRESS = "progress"
    REMOVE_AND_RETRY = "remove-and-retry"
    RETRY_SCAN = "retry-scan"
    RETRY_SMALL_COVERAGE = "retry-small-coverage"
    DIRTY_SENSOR = "dirty-sensor"
    CANCELLED = "cancelled"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    IDENTITY_OBSERVED = "identity-observed"


@dataclass(frozen=True, repr=False)
class EnrollmentIdentity:
    user_id: int
    identity_uuid: bytes
    group_type: int
    group_uuid: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.user_id <= 0xFFFFFFFF:
            raise EnrollmentProtocolError("identity user ID is outside uint32 range")
        if type(self.identity_uuid) is not bytes or len(self.identity_uuid) != 16:
            raise EnrollmentProtocolError("identity UUID must be exactly 16 bytes")
        if not any(self.identity_uuid):
            raise EnrollmentProtocolError("identity UUID must not be zero")
        if not 0 <= self.group_type <= 0xFFFFFFFF:
            raise EnrollmentProtocolError("group type is outside uint32 range")
        if type(self.group_uuid) is not bytes or len(self.group_uuid) != 16:
            raise EnrollmentProtocolError("group UUID must be exactly 16 bytes")

    def __repr__(self) -> str:
        return (
            "EnrollmentIdentity(user_id="
            f"{self.user_id}, identity_uuid=<redacted>, group_type={self.group_type}, "
            "group_uuid=<redacted>)"
        )


@dataclass(frozen=True, repr=False)
class ServiceEvent:
    sequence: int
    envelope_type: int
    version: int
    ordinal: int
    payload: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.sequence <= 0xFFFFFFFFFFFFFFFF:
            raise EnrollmentProtocolError("event sequence is outside uint64 range")
        if not 0 <= self.envelope_type <= 0xFFFFFFFF:
            raise EnrollmentProtocolError("event type is outside uint32 range")
        if not 0 <= self.version <= 0xFFFFFFFF:
            raise EnrollmentProtocolError("event version is outside uint32 range")
        if not 0 <= self.ordinal <= 0xFFFFFFFFFFFFFFFF:
            raise EnrollmentProtocolError("event ordinal is outside uint64 range")
        if type(self.payload) is not bytes or len(self.payload) > MAX_EVENT_PAYLOAD:
            raise EnrollmentProtocolError("event payload is invalid or unbounded")


@dataclass(frozen=True, repr=False)
class EnrollmentTransition:
    action: EnrollmentAction
    state: EnrollmentState
    continue_required: bool = False
    progress_percent: int | None = None
    identity: EnrollmentIdentity | None = None


class SensitiveEnrollmentRequest:
    """Operation-local start request whose backing storage can be wiped."""

    __slots__ = ("_buffer", "_wiped", "protocol_version")

    def __init__(self, protocol_version: int, user_id: int, acm_external_form: bytes):
        if protocol_version not in (1, 2):
            raise EnrollmentProtocolError("enrollment protocol must be version 1 or 2")
        if not 0 <= user_id <= 0xFFFFFFFF:
            raise EnrollmentProtocolError("user ID is outside uint32 range")
        if (
            type(acm_external_form) is not bytes
            or len(acm_external_form) != ACM_EXTERNAL_FORM_SIZE
        ):
            raise EnrollmentProtocolError(
                "ACM external form must be exactly 16 bytes"
            )
        size = 48 if protocol_version == 1 else 68
        self._buffer = bytearray(size)
        self._wiped = False
        self.protocol_version = protocol_version
        struct.pack_into("<IIII", self._buffer, 0, 0, user_id, 0, 16)
        self._buffer[16:32] = acm_external_form
        # The mode-0 credential container's remaining 16 bytes stay zero.  A
        # protocol-v2 built-in request likewise has an all-zero device group.

    def __repr__(self) -> str:
        return (
            "SensitiveEnrollmentRequest(protocol_version="
            f"{self.protocol_version}, payload=<redacted>)"
        )

    @property
    def command(self) -> int:
        return COMMAND_ENROLL_START

    @property
    def buffer(self) -> memoryview:
        if self._wiped:
            raise EnrollmentProtocolError("enrollment request has been wiped")
        return memoryview(self._buffer).toreadonly()

    def wipe(self) -> None:
        for offset in range(len(self._buffer)):
            self._buffer[offset] = 0
        self._wiped = True

    def __enter__(self) -> SensitiveEnrollmentRequest:
        return self

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        self.wipe()

    def __del__(self) -> None:
        if hasattr(self, "_buffer"):
            self.wipe()


def build_continue_payload() -> bytes:
    """Command 0x0e has no payload."""
    return b""


def parse_service_event(data: bytes) -> ServiceEvent:
    if type(data) is not bytes or not SERVICE_HEADER.size <= len(data) <= (
        SERVICE_HEADER.size + MAX_EVENT_PAYLOAD
    ):
        raise EnrollmentProtocolError("service event length is invalid")
    reserved, envelope_type, version, event_timestamp = SERVICE_HEADER.unpack_from(data)
    payload = data[SERVICE_HEADER.size :]
    if reserved != 0 or event_timestamp == 0:
        raise EnrollmentProtocolError("service event header is invalid")
    # The final qword in the common header is a monotonic event timestamp, not
    # the generic biometric status.  Status messages carry their 32-bit
    # ordinal at byte 24, followed by padding and a 64-bit detail length.
    # Use the timestamp as the operation-local monotonic sequence key.
    ordinal = 0
    if envelope_type == SERVICE_STATUS:
        if len(payload) < STATUS_PAYLOAD_HEADER.size:
            raise EnrollmentProtocolError("generic status payload is truncated")
        ordinal, _detail_length = STATUS_PAYLOAD_HEADER.unpack_from(payload)
    return ServiceEvent(event_timestamp, envelope_type, version, ordinal, payload)


def parse_enrollment_identity(
    event: ServiceEvent, *, expected_user_id: int
) -> EnrollmentIdentity:
    if event.envelope_type != SERVICE_ENROLLMENT_RESULT:
        raise EnrollmentProtocolError("event is not an enrollment result")
    if event.version == 1:
        if len(event.payload) != 20:
            raise EnrollmentProtocolError("version-1 enrollment result must be 20 bytes")
        record = event.payload + struct.pack("<I16x", 1)
    elif event.version == 2:
        if len(event.payload) < 40:
            raise EnrollmentProtocolError(
                "version-2 enrollment result must contain at least 40 bytes"
            )
        record = event.payload[:40]
    else:
        raise EnrollmentProtocolError("unsupported enrollment-result version")
    user_id, identity_uuid, group_type, group_uuid = struct.unpack("<I16sI16s", record)
    if user_id != expected_user_id:
        raise EnrollmentProtocolError("enrollment result belongs to another Apple user")
    if record[20:40] not in BUILTIN_GROUPS:
        raise EnrollmentProtocolError("accessory enrollment result is unsupported")
    return EnrollmentIdentity(user_id, identity_uuid, group_type, group_uuid)


def validate_status_payload(event: ServiceEvent) -> None:
    """Validate the optional message-status record without retaining its data."""
    if not event.payload:
        return
    if len(event.payload) < 16:
        raise EnrollmentProtocolError("generic status payload is truncated")
    payload_status = struct.unpack_from("<I", event.payload)[0]
    payload_length = struct.unpack_from("<Q", event.payload, 8)[0]
    if payload_status != event.ordinal:
        raise EnrollmentProtocolError("status payload disagrees with its ordinal")
    if payload_length != len(event.payload) - 16:
        raise EnrollmentProtocolError("status payload length is inconsistent")


def validate_sks_lock_state_payload(event: ServiceEvent) -> None:
    """Validate an SKS host-side event without retaining its user or state."""
    if event.version != 1:
        raise EnrollmentProtocolError("unsupported SKS lock-state event version")
    if len(event.payload) < SKS_LOCK_STATE_PAYLOAD.size:
        raise EnrollmentProtocolError("SKS lock-state payload is truncated")
    # The exact daemon deliberately routes this auxiliary notification using
    # the user ID carried by the event; it does not bind that ID to the active
    # biometric operation. Decode only to prove the recovered field layout.
    # Neither value is allowed to select or advance an enrollment identity.
    SKS_LOCK_STATE_PAYLOAD.unpack_from(event.payload)


class EnrollmentStateMachine:
    """Conservative one-operation enrollment event reducer."""

    def __init__(
        self, *, expected_user_id: int, connection_generation: str, operation_id: str
    ) -> None:
        if not 0 <= expected_user_id <= 0xFFFFFFFF:
            raise EnrollmentProtocolError("expected user ID is outside uint32 range")
        if not connection_generation or not operation_id:
            raise EnrollmentProtocolError("generation and operation IDs are required")
        self.expected_user_id = expected_user_id
        self.connection_generation = connection_generation
        self.operation_id = operation_id
        self.state = EnrollmentState.ACTIVE
        self._last_sequence: int | None = None
        self._fingerprints: deque[bytes] = deque(maxlen=MAX_EVENT_FINGERPRINTS)

    def request_cancel(self) -> None:
        if self.state is not EnrollmentState.ACTIVE:
            self._freeze("cancel requested outside an active operation")
        self.state = EnrollmentState.CANCEL_REQUESTED

    def accept(
        self,
        event: ServiceEvent,
        *,
        connection_generation: str,
        operation_id: str,
    ) -> EnrollmentTransition:
        if self.state not in (EnrollmentState.ACTIVE, EnrollmentState.CANCEL_REQUESTED):
            self._freeze("event arrived after the operation became terminal")
        if connection_generation != self.connection_generation:
            self._freeze("event belongs to another connection generation")
        if operation_id != self.operation_id:
            self._freeze("event belongs to another enrollment operation")
        fingerprint = hashlib.sha256(
            SERVICE_HEADER.pack(
                event.sequence, event.envelope_type, event.version, event.ordinal
            )
            + event.payload
        ).digest()
        if fingerprint in self._fingerprints:
            self._freeze("duplicate enrollment event")
        if self._last_sequence is not None and event.sequence <= self._last_sequence:
            self._freeze("enrollment event sequence is not increasing")
        self._last_sequence = event.sequence
        self._fingerprints.append(fingerprint)

        if event.envelope_type == SERVICE_ENROLLMENT_RESULT:
            try:
                identity = parse_enrollment_identity(
                    event, expected_user_id=self.expected_user_id
                )
            except EnrollmentProtocolError as error:
                self.state = EnrollmentState.FROZEN
                raise EnrollmentProtocolError(
                    "invalid enrollment-result event"
                ) from error
            self.state = EnrollmentState.SEP_IDENTITY_OBSERVED
            return EnrollmentTransition(
                EnrollmentAction.IDENTITY_OBSERVED, self.state, identity=identity
            )
        if event.envelope_type == SERVICE_ACCESSORY_AUTHORIZATION or (
            event.envelope_type == SERVICE_STATUS and event.ordinal == 501
        ):
            self._freeze("accessory authorization is unsupported")
        # Statistics are ambient operation telemetry.  The exact T2 emits
        # these on the same callback stream during a normal match, and they do
        # not advance, complete, or select an enrollment identity.
        if event.envelope_type == SERVICE_STATISTICS and event.version == 1:
            if len(event.payload) < STATISTICS_MIN_PAYLOAD_SIZE:
                self._freeze("statistics telemetry payload is truncated")
            return EnrollmentTransition(EnrollmentAction.IGNORE_TELEMETRY, self.state)
        # Matching macOS accepts a version-1 record containing at least a
        # uint32 Apple user ID and uint16 SKS state. It can synchronize the
        # template list, save the bio-lockout record, cancel a tokenless unlock
        # match, notify observers, and log. None of those side effects advances
        # or terminates enrollment. The daemon routes this ambient notification
        # by the user ID inside the record, which may differ from the active
        # operation. Leave persistence to the finalizer; malformed records
        # remain fail-closed and this event can never select an identity.
        if event.envelope_type == SERVICE_SKS_LOCK_STATE:
            try:
                validate_sks_lock_state_payload(event)
            except EnrollmentProtocolError as error:
                self.state = EnrollmentState.FROZEN
                raise EnrollmentProtocolError(
                    "invalid SKS lock-state auxiliary event"
                ) from error
            return EnrollmentTransition(EnrollmentAction.IGNORE_AUXILIARY, self.state)
        if event.envelope_type != SERVICE_STATUS or event.version not in (1, 2):
            self._freeze(
                "unknown enrollment envelope "
                f"0x{event.envelope_type:08x} version {event.version}"
            )
        try:
            validate_status_payload(event)
        except EnrollmentProtocolError as error:
            self.state = EnrollmentState.FROZEN
            raise EnrollmentProtocolError("invalid generic status event") from error

        status = event.ordinal
        # The exact bridge wrapper uses the same ordinal/detail-length record
        # for both versions. Matching host dispatch normalizes version 2 and
        # forwards the same ordinal/details to BiometricKit, whose recovered
        # state transitions do not receive the envelope version. Linux discards
        # the opaque details and still fails closed on every unknown ordinal.
        if status == 66:
            self.state = EnrollmentState.CANCELLED
            return EnrollmentTransition(EnrollmentAction.CANCELLED, self.state)
        if status == 67:
            self.state = EnrollmentState.FAILED
            return EnrollmentTransition(EnrollmentAction.FAILED, self.state)
        if status == 68:
            self.state = EnrollmentState.TIMED_OUT
            return EnrollmentTransition(EnrollmentAction.TIMED_OUT, self.state)
        if self.state is EnrollmentState.CANCEL_REQUESTED:
            self._freeze("nonterminal event arrived after cancellation was requested")
        # Exact macOS 15.7 / 24G830 BKOperation dispatches these two statuses
        # through operation:presenceStateChanged:. Status 63 supplies true;
        # status 64 supplies false and returns the host operation to its
        # waiting state. Neither path sends enrollContinue or completes.
        if status == 63:
            return EnrollmentTransition(EnrollmentAction.FINGER_PRESENT, self.state)
        if status == 64:
            return EnrollmentTransition(EnrollmentAction.FINGER_REMOVED, self.state)
        if status == 70:
            return EnrollmentTransition(
                EnrollmentAction.CONTINUE,
                self.state,
                continue_required=True,
            )
        if status == 74:
            return EnrollmentTransition(EnrollmentAction.REMOVE_AND_RETRY, self.state)
        if status in (78, 85, 87, 88, 98):
            return EnrollmentTransition(EnrollmentAction.RETRY_SCAN, self.state)
        if status == 86:
            return EnrollmentTransition(
                EnrollmentAction.RETRY_SMALL_COVERAGE, self.state
            )
        if status == 93:
            return EnrollmentTransition(EnrollmentAction.DIRTY_SENSOR, self.state)
        # Exact macOS 15.7 / 24G830 BiometricKit forwards statuses 55, 72, and
        # 90 through BKEnrollTouchIDOperation and BKEnrollOperation without a
        # capture error, progress update, terminal result, or enrollContinue.
        # The generic BKOperation jump-table sends all three directly to its
        # common return path. Preserve only these recovered no-ops while
        # retaining fail-closed handling for every other unknown status.
        if status in EXACT_NOOP_PHASE_STATUSES:
            return EnrollmentTransition(EnrollmentAction.IGNORE_PHASE, self.state)
        if 100 <= status <= 355:
            return EnrollmentTransition(
                EnrollmentAction.PROGRESS,
                self.state,
                continue_required=True,
                progress_percent=100 * (status - 100) // 255,
            )
        self._freeze(f"unknown enrollment status {status}")

    def _freeze(self, message: str) -> None:
        self.state = EnrollmentState.FROZEN
        raise EnrollmentProtocolError(message)
