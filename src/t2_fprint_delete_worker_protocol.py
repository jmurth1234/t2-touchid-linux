# SPDX-License-Identifier: GPL-2.0-only
"""Bounded pidfd-bearing protocol for the single-deletion worker."""

from __future__ import annotations

import array
import os
import socket
from dataclasses import dataclass, field

import t2_dbus_identity
import t2_fprint_deletion_runtime
import t2_fprint_worker_protocol as common
import t2_ipc_session
import t2_linux_account
import t2_polkit_grant


REQUEST_KEYS = common.START_KEYS
COMPLETION_KEYS = frozenset(
    {
        "schema_version",
        "message",
        "finger_name",
        "deleted",
        "reconciled",
        "post_reboot_pending",
        "mutation_performed",
    }
)
FAILURE_PACKET = b'{"message":"delete-failed","schema_version":1}'


class FprintDeleteWorkerProtocolError(ValueError):
    pass


class FprintDeleteWorkerPeerClosed(FprintDeleteWorkerProtocolError):
    pass


class FprintDeleteWorkerFailed(FprintDeleteWorkerProtocolError):
    pass


@dataclass(frozen=True, repr=False)
class DeleteRequest:
    finger_name: str
    caller: t2_polkit_grant.ProcessSubject = field(repr=False)
    account: t2_linux_account.AccountEvidence = field(repr=False)
    session: t2_ipc_session.SessionEvidence = field(repr=False)

    def public(self) -> dict[str, object]:
        value = common.StartRequest(
            self.finger_name,
            self.caller,
            self.account,
            self.session,
        ).public()
        value["message"] = "delete-one"
        return value


def _as_start(request: DeleteRequest) -> common.StartRequest:
    if not isinstance(request, DeleteRequest):
        raise FprintDeleteWorkerProtocolError(
            "delete worker request has the wrong type"
        )
    return common.StartRequest(
        request.finger_name,
        request.caller,
        request.account,
        request.session,
    )


def encode_request(request: DeleteRequest) -> bytes:
    try:
        common._validate_request(_as_start(request))
        return common._encode(request.public())
    except common.FprintWorkerProtocolError as error:
        raise FprintDeleteWorkerProtocolError(
            "delete worker request is invalid"
        ) from error


def decode_request(data: bytes) -> DeleteRequest:
    try:
        value = common._decode(data)
        if value.get("message") != "delete-one":
            raise FprintDeleteWorkerProtocolError(
                "delete worker request message is invalid"
            )
        translated = dict(value)
        translated["message"] = "start"
        start = common.decode_start(common._encode(translated))
        request = DeleteRequest(
            start.finger_name,
            start.caller,
            start.account,
            start.session,
        )
    except FprintDeleteWorkerProtocolError:
        raise
    except common.FprintWorkerProtocolError as error:
        raise FprintDeleteWorkerProtocolError(
            "delete worker request schema is invalid"
        ) from error
    if set(value) != REQUEST_KEYS or encode_request(request) != data:
        raise FprintDeleteWorkerProtocolError(
            "delete worker request is not canonical"
        )
    return request


def _require_connection(connection: socket.socket) -> None:
    try:
        common._require_seqpacket(connection)
    except common.FprintWorkerProtocolError as error:
        raise FprintDeleteWorkerProtocolError(str(error)) from error


def send_request(
    connection: socket.socket,
    request: DeleteRequest,
    pidfd: int,
) -> None:
    _require_connection(connection)
    encoded = encode_request(request)
    if type(pidfd) is not int or pidfd < 0:
        raise FprintDeleteWorkerProtocolError(
            "delete worker caller pidfd is invalid"
        )
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
        raise FprintDeleteWorkerProtocolError(
            "delete worker request send failed"
        ) from error
    if sent != len(encoded):
        raise FprintDeleteWorkerProtocolError(
            "delete worker request send was incomplete"
        )


def receive_request(connection: socket.socket) -> tuple[DeleteRequest, int]:
    _require_connection(connection)
    descriptors: list[int] = []
    try:
        data, ancillary, flags, _address = connection.recvmsg(
            common.MAX_PACKET_BYTES,
            socket.CMSG_SPACE(array.array("i").itemsize * 2),
        )
        for level, kind, payload in ancillary:
            if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
                raise FprintDeleteWorkerProtocolError(
                    "delete worker request contains unsupported ancillary data"
                )
            received = array.array("i")
            received.frombytes(
                payload[: len(payload) - (len(payload) % received.itemsize)]
            )
            descriptors.extend(received.tolist())
    except FprintDeleteWorkerProtocolError:
        common._close_descriptors(descriptors)
        raise
    except OSError as error:
        common._close_descriptors(descriptors)
        raise FprintDeleteWorkerProtocolError(
            "delete worker request receive failed"
        ) from error
    if not data:
        common._close_descriptors(descriptors)
        raise FprintDeleteWorkerPeerClosed(
            "delete worker facade closed before request"
        )
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(descriptors) != 1:
        common._close_descriptors(descriptors)
        raise FprintDeleteWorkerProtocolError(
            "delete worker request requires exactly one complete pidfd"
        )
    descriptor = descriptors[0]
    try:
        request = decode_request(data)
        t2_dbus_identity._pidfd_matches(descriptor, request.caller.pid)
        current = t2_polkit_grant.read_process_subject(
            request.caller.pid,
            request.caller.uid,
            allow_root=False,
        )
        if current != request.caller:
            raise FprintDeleteWorkerProtocolError(
                "delete worker caller changed before receipt"
            )
        return request, descriptor
    except BaseException:
        common._close_descriptors([descriptor])
        raise


def encode_completion(
    value: t2_fprint_deletion_runtime.DeletionCompletion,
) -> bytes:
    if type(value) is not t2_fprint_deletion_runtime.DeletionCompletion:
        raise FprintDeleteWorkerProtocolError(
            "delete worker completion has the wrong type"
        )
    try:
        return common._encode(
            {
                "schema_version": 1,
                "message": "delete-completed",
                "finger_name": value.finger_name,
                "deleted": value.deleted,
                "reconciled": value.reconciled,
                "post_reboot_pending": value.post_reboot_pending,
                "mutation_performed": value.mutation_performed,
            }
        )
    except common.FprintWorkerProtocolError as error:
        raise FprintDeleteWorkerProtocolError(
            "delete worker completion cannot be encoded"
        ) from error


def decode_completion(
    data: bytes,
) -> t2_fprint_deletion_runtime.DeletionCompletion:
    if data == FAILURE_PACKET:
        raise FprintDeleteWorkerFailed("delete worker reported failure")
    try:
        value = common._decode(data)
        if (
            set(value) != COMPLETION_KEYS
            or value.get("schema_version") != 1
            or type(value.get("schema_version")) is not int
            or value.get("message") != "delete-completed"
        ):
            raise FprintDeleteWorkerProtocolError(
                "delete worker completion schema is invalid"
            )
        result = t2_fprint_deletion_runtime.DeletionCompletion(
            value.get("finger_name"),
            value.get("deleted"),
            value.get("reconciled"),
            value.get("post_reboot_pending"),
            value.get("mutation_performed"),
        )
    except FprintDeleteWorkerProtocolError:
        raise
    except (
        common.FprintWorkerProtocolError,
        t2_fprint_deletion_runtime.FprintDeletionRuntimeError,
    ) as error:
        raise FprintDeleteWorkerProtocolError(
            "delete worker completion is invalid"
        ) from error
    if encode_completion(result) != data:
        raise FprintDeleteWorkerProtocolError(
            "delete worker completion is not canonical"
        )
    return result


def _send_packet(connection: socket.socket, data: bytes) -> None:
    _require_connection(connection)
    try:
        sent = connection.send(data)
    except OSError as error:
        raise FprintDeleteWorkerProtocolError(
            "delete worker response send failed"
        ) from error
    if sent != len(data):
        raise FprintDeleteWorkerProtocolError(
            "delete worker response send was incomplete"
        )


def send_completion(
    connection: socket.socket,
    value: t2_fprint_deletion_runtime.DeletionCompletion,
) -> None:
    _send_packet(connection, encode_completion(value))


def send_failure(connection: socket.socket) -> None:
    _send_packet(connection, FAILURE_PACKET)


def receive_completion(
    connection: socket.socket,
) -> t2_fprint_deletion_runtime.DeletionCompletion:
    _require_connection(connection)
    try:
        data, ancillary, flags, _address = connection.recvmsg(
            common.MAX_PACKET_BYTES, 0
        )
    except OSError as error:
        raise FprintDeleteWorkerProtocolError(
            "delete worker response receive failed"
        ) from error
    if not data:
        raise FprintDeleteWorkerPeerClosed(
            "delete worker closed without a reconciled response"
        )
    if ancillary or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
        raise FprintDeleteWorkerProtocolError(
            "delete worker response is truncated or contains ancillary data"
        )
    return decode_completion(data)
