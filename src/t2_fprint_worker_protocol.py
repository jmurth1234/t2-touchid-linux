# SPDX-License-Identifier: GPL-2.0-only
"""Bounded pidfd-bearing protocol for the credential-scoped fprint worker."""

from __future__ import annotations

import array
import json
import os
import socket
from dataclasses import dataclass, field

import t2_dbus_identity
import t2_fprint_enrollment_runtime
import t2_fprint_projection
import t2_ipc_session
import t2_linux_account
import t2_polkit_grant


MAX_PACKET_BYTES = 4096
START_KEYS = frozenset(
    {
        "schema_version",
        "message",
        "finger_name",
        "caller",
        "account",
        "session",
    }
)
CALLER_KEYS = frozenset({"pid", "uid", "start_time_ticks"})
ACCOUNT_KEYS = frozenset(
    {
        "linux_uid",
        "generation",
        "source",
        "protected_password_record",
        "home_object_bound",
    }
)
SESSION_KEYS = frozenset(
    {
        "binding",
        "session_id",
        "session_type",
        "session_class",
        "seat_attached",
        "session_start_time_usec",
        "active_local_session",
    }
)
UPDATE_KEYS = frozenset(
    {
        "schema_version",
        "message",
        "status",
        "done",
        "finger_present",
        "finger_needed",
    }
)
CANCEL_PACKET = b'{"message":"cancel","schema_version":1}'
ALLOWED_STATUSES = frozenset(
    {
        "enroll-stage-passed",
        "enroll-retry-scan",
        "enroll-swipe-too-short",
        "enroll-finger-not-centered",
        "enroll-remove-and-retry",
        "enroll-completed",
        "enroll-failed",
        "enroll-data-full",
        "enroll-disconnected",
        "enroll-unknown-error",
    }
)
TERMINAL_STATUSES = frozenset(
    {
        "enroll-completed",
        "enroll-failed",
        "enroll-data-full",
        "enroll-disconnected",
        "enroll-unknown-error",
    }
)


class FprintWorkerProtocolError(ValueError):
    pass


class FprintWorkerPeerClosed(FprintWorkerProtocolError):
    pass


@dataclass(frozen=True, repr=False)
class StartRequest:
    finger_name: str
    caller: t2_polkit_grant.ProcessSubject = field(repr=False)
    account: t2_linux_account.AccountEvidence = field(repr=False)
    session: t2_ipc_session.SessionEvidence = field(repr=False)

    def public(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "message": "start",
            "finger_name": self.finger_name,
            "caller": {
                "pid": self.caller.pid,
                "uid": self.caller.uid,
                "start_time_ticks": self.caller.start_time_ticks,
            },
            "account": {
                "linux_uid": self.account.linux_uid,
                "generation": self.account.generation,
                "source": self.account.source,
                "protected_password_record": (
                    self.account.protected_password_record
                ),
                "home_object_bound": self.account.home_object_bound,
            },
            "session": {
                "binding": self.session.binding,
                "session_id": self.session.session_id,
                "session_type": self.session.session_type,
                "session_class": self.session.session_class,
                "seat_attached": self.session.seat_attached,
                "session_start_time_usec": (
                    self.session.session_start_time_usec
                ),
                "active_local_session": self.session.active_local_session,
            },
        }


def _duplicate_safe_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise FprintWorkerProtocolError(
                "worker protocol object has a duplicate key"
            )
        value[key] = item
    return value


def _decode(data: bytes) -> dict[str, object]:
    if type(data) is not bytes or not 1 <= len(data) <= MAX_PACKET_BYTES or b"\0" in data:
        raise FprintWorkerProtocolError("worker packet size is invalid")
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicate_safe_object,
            parse_constant=lambda _constant: (_ for _ in ()).throw(
                FprintWorkerProtocolError("non-finite JSON is forbidden")
            ),
        )
    except FprintWorkerProtocolError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise FprintWorkerProtocolError(
            "worker packet is not strict JSON"
        ) from error
    if not isinstance(value, dict):
        raise FprintWorkerProtocolError("worker packet is not an object")
    return value


def _encode(value: dict[str, object]) -> bytes:
    try:
        data = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise FprintWorkerProtocolError("worker packet cannot be encoded") from error
    if not 1 <= len(data) <= MAX_PACKET_BYTES:
        raise FprintWorkerProtocolError("worker packet size is invalid")
    return data


def _require_seqpacket(connection: socket.socket) -> None:
    if not isinstance(connection, socket.socket):
        raise FprintWorkerProtocolError("worker connection has the wrong type")
    try:
        domain = connection.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN)
        kind = connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
    except OSError as error:
        raise FprintWorkerProtocolError(
            "worker socket metadata is unavailable"
        ) from error
    if domain != socket.AF_UNIX or kind != socket.SOCK_SEQPACKET:
        raise FprintWorkerProtocolError(
            "worker connection must be a Unix seqpacket socket"
        )


def _validate_request(request: StartRequest) -> None:
    if not isinstance(request, StartRequest):
        raise FprintWorkerProtocolError("worker start request has the wrong type")
    caller = request.caller
    account = request.account
    session = request.session
    try:
        t2_ipc_session.validate_account(account, caller.uid)
    except t2_ipc_session.IPCSessionError as error:
        raise FprintWorkerProtocolError(
            "worker caller/account evidence is invalid"
        ) from error
    if (
        not isinstance(caller, t2_polkit_grant.ProcessSubject)
        or type(caller.pid) is not int
        or not 1 <= caller.pid <= t2_polkit_grant.MAX_PID
        or type(caller.uid) is not int
        or not 1 <= caller.uid < (1 << 32) - 1
        or type(caller.start_time_ticks) is not int
        or not 1 <= caller.start_time_ticks < 1 << 64
        or request.finger_name not in t2_fprint_projection.FINGER_NAME_SET
        or account.linux_uid != caller.uid
        or account.source != "local-files-v1"
        or account.protected_password_record is not True
        or account.home_object_bound is not True
        or session.binding not in {"pidfd-session", "uid-active-session"}
        or not t2_ipc_session.SESSION_ID.fullmatch(session.session_id)
        or session.session_type not in t2_ipc_session.ALLOWED_SESSION_TYPES
        or session.session_class not in t2_ipc_session.ALLOWED_SESSION_CLASSES
        or type(session.seat_attached) is not bool
        or type(session.session_start_time_usec) is not int
        or session.session_start_time_usec <= 0
        or session.active_local_session is not True
    ):
        raise FprintWorkerProtocolError(
            "worker start request evidence is inconsistent"
        )


def encode_start(request: StartRequest) -> bytes:
    _validate_request(request)
    return _encode(request.public())


def decode_start(data: bytes) -> StartRequest:
    value = _decode(data)
    caller = value.get("caller")
    account = value.get("account")
    session = value.get("session")
    if (
        set(value) != START_KEYS
        or value.get("schema_version") != 1
        or type(value.get("schema_version")) is not int
        or value.get("message") != "start"
        or not isinstance(value.get("finger_name"), str)
        or not isinstance(caller, dict)
        or set(caller) != CALLER_KEYS
        or not isinstance(account, dict)
        or set(account) != ACCOUNT_KEYS
        or not isinstance(session, dict)
        or set(session) != SESSION_KEYS
    ):
        raise FprintWorkerProtocolError("worker start request schema is invalid")
    request = StartRequest(
        value["finger_name"],
        t2_polkit_grant.ProcessSubject(
            caller.get("pid"), caller.get("uid"), caller.get("start_time_ticks")
        ),
        t2_linux_account.AccountEvidence(
            account.get("linux_uid"),
            account.get("generation"),
            account.get("source"),
            account.get("protected_password_record"),
            account.get("home_object_bound"),
        ),
        t2_ipc_session.SessionEvidence(
            session.get("binding"),
            session.get("session_id"),
            session.get("session_type"),
            session.get("session_class"),
            session.get("seat_attached"),
            session.get("session_start_time_usec"),
            session.get("active_local_session"),
        ),
    )
    _validate_request(request)
    if encode_start(request) != data:
        raise FprintWorkerProtocolError(
            "worker start request is not canonical"
        )
    return request


def _close_descriptors(descriptors: list[int]) -> None:
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except OSError:
            pass


def send_start(
    connection: socket.socket,
    request: StartRequest,
    pidfd: int,
) -> None:
    _require_seqpacket(connection)
    encoded = encode_start(request)
    if type(pidfd) is not int or pidfd < 0:
        raise FprintWorkerProtocolError("worker caller pidfd is invalid")
    try:
        t2_dbus_identity._pidfd_matches(pidfd, request.caller.pid)
        sent = connection.sendmsg(
            [encoded],
            [
                (
                    socket.SOL_SOCKET,
                    socket.SCM_RIGHTS,
                    array.array("i", [pidfd]),
                )
            ],
        )
    except (OSError, t2_dbus_identity.DBusIdentityError) as error:
        raise FprintWorkerProtocolError("worker start send failed") from error
    if sent != len(encoded):
        raise FprintWorkerProtocolError("worker start send was incomplete")


def receive_start(connection: socket.socket) -> tuple[StartRequest, int]:
    _require_seqpacket(connection)
    descriptors: list[int] = []
    try:
        data, ancillary, flags, _address = connection.recvmsg(
            MAX_PACKET_BYTES,
            socket.CMSG_SPACE(array.array("i").itemsize * 2),
        )
        for level, kind, payload in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                raise FprintWorkerProtocolError(
                    "worker start contains unsupported ancillary data"
                )
            received = array.array("i")
            received.frombytes(
                payload[: len(payload) - (len(payload) % received.itemsize)]
            )
            descriptors.extend(received.tolist())
    except FprintWorkerProtocolError:
        _close_descriptors(descriptors)
        raise
    except OSError as error:
        _close_descriptors(descriptors)
        raise FprintWorkerProtocolError("worker start receive failed") from error
    if not data:
        _close_descriptors(descriptors)
        raise FprintWorkerPeerClosed("worker facade closed before start")
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(descriptors) != 1:
        _close_descriptors(descriptors)
        raise FprintWorkerProtocolError(
            "worker start must contain exactly one complete pidfd"
        )
    descriptor = descriptors[0]
    try:
        request = decode_start(data)
        t2_dbus_identity._pidfd_matches(descriptor, request.caller.pid)
        current = t2_polkit_grant.read_process_subject(
            request.caller.pid,
            request.caller.uid,
            allow_root=False,
        )
        if current != request.caller:
            raise FprintWorkerProtocolError(
                "worker pidfd caller changed before receipt"
            )
        return request, descriptor
    except BaseException:
        _close_descriptors([descriptor])
        raise


def send_cancel(connection: socket.socket) -> None:
    _require_seqpacket(connection)
    try:
        sent = connection.send(CANCEL_PACKET)
    except OSError as error:
        raise FprintWorkerProtocolError("worker cancellation send failed") from error
    if sent != len(CANCEL_PACKET):
        raise FprintWorkerProtocolError(
            "worker cancellation send was incomplete"
        )


def receive_cancel(connection: socket.socket) -> None:
    _require_seqpacket(connection)
    try:
        data, ancillary, flags, _address = connection.recvmsg(
            MAX_PACKET_BYTES, 0
        )
    except OSError as error:
        raise FprintWorkerProtocolError(
            "worker cancellation receive failed"
        ) from error
    if not data:
        raise FprintWorkerPeerClosed("worker facade closed during enrollment")
    if ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise FprintWorkerProtocolError(
            "worker cancellation is truncated or contains ancillary data"
        )
    if data != CANCEL_PACKET:
        raise FprintWorkerProtocolError("worker cancellation packet is invalid")


def _validate_update(
    update: t2_fprint_enrollment_runtime.EnrollmentUpdate,
) -> None:
    if not isinstance(
        update, t2_fprint_enrollment_runtime.EnrollmentUpdate
    ):
        raise FprintWorkerProtocolError("worker update has the wrong type")
    if (
        update.status is not None
        and update.status not in ALLOWED_STATUSES
    ):
        raise FprintWorkerProtocolError("worker update status is invalid")
    if (
        type(update.done) is not bool
        or type(update.finger_present) is not bool
        or type(update.finger_needed) is not bool
        or update.finger_present and update.finger_needed
        or update.done != (update.status in TERMINAL_STATUSES)
        or update.done and (update.finger_present or update.finger_needed)
    ):
        raise FprintWorkerProtocolError("worker update state is inconsistent")


def encode_update(
    update: t2_fprint_enrollment_runtime.EnrollmentUpdate,
) -> bytes:
    _validate_update(update)
    return _encode(
        {
            "schema_version": 1,
            "message": "update",
            "status": update.status,
            "done": update.done,
            "finger_present": update.finger_present,
            "finger_needed": update.finger_needed,
        }
    )


def decode_update(data: bytes) -> t2_fprint_enrollment_runtime.EnrollmentUpdate:
    value = _decode(data)
    if (
        set(value) != UPDATE_KEYS
        or value.get("schema_version") != 1
        or type(value.get("schema_version")) is not int
        or value.get("message") != "update"
    ):
        raise FprintWorkerProtocolError("worker update schema is invalid")
    update = t2_fprint_enrollment_runtime.EnrollmentUpdate(
        value.get("status"),
        value.get("done"),
        value.get("finger_present"),
        value.get("finger_needed"),
    )
    _validate_update(update)
    if encode_update(update) != data:
        raise FprintWorkerProtocolError("worker update is not canonical")
    return update


def send_update(
    connection: socket.socket,
    update: t2_fprint_enrollment_runtime.EnrollmentUpdate,
) -> None:
    _require_seqpacket(connection)
    data = encode_update(update)
    try:
        sent = connection.send(data)
    except OSError as error:
        raise FprintWorkerProtocolError("worker update send failed") from error
    if sent != len(data):
        raise FprintWorkerProtocolError("worker update send was incomplete")


def receive_update(
    connection: socket.socket,
) -> t2_fprint_enrollment_runtime.EnrollmentUpdate:
    _require_seqpacket(connection)
    try:
        data, ancillary, flags, _address = connection.recvmsg(
            MAX_PACKET_BYTES, 0
        )
    except OSError as error:
        raise FprintWorkerProtocolError("worker update receive failed") from error
    if not data:
        raise FprintWorkerPeerClosed("worker closed without terminal update")
    if ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise FprintWorkerProtocolError(
            "worker update is truncated or contains ancillary data"
        )
    return decode_update(data)
