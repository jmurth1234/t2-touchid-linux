# SPDX-License-Identifier: GPL-2.0-only
"""Credential-free worker core for one caller-bound fprint deletion."""

from __future__ import annotations

import os
import socket
import stat
import uuid
from pathlib import Path

import t2_fprint_delete_worker_protocol
import t2_fprint_deletion_consumer
import t2_fprint_deletion_runtime
import t2_ipc_session
import t2_user_broker


WORKER_ROOT = Path("/run/t2-touchid/workers")


class FprintDeleteWorkerError(RuntimeError):
    pass


def serve_once(
    connection: socket.socket,
    *,
    authorization_factory=t2_ipc_session.AuthorizationSession.from_peer,
    broker_runner=t2_user_broker.run_self_service,
    deletion_consumer_factory=t2_fprint_deletion_consumer.DeletionConsumer,
) -> t2_fprint_deletion_runtime.DeletionCompletion:
    """Run exactly one deletion and emit only a reconciled completion."""

    if any(
        not callable(value)
        for value in (
            authorization_factory,
            broker_runner,
            deletion_consumer_factory,
        )
    ):
        raise FprintDeleteWorkerError("delete worker dependency is unavailable")
    authorization = None
    response_sent = False
    mutation_completed = False
    try:
        request, pidfd = t2_fprint_delete_worker_protocol.receive_request(
            connection
        )
        peer = t2_ipc_session.PinnedPeer.from_process_fd(
            pidfd,
            request.caller.pid,
            request.caller.uid,
        )
        if peer.subject != request.caller:
            peer.close()
            raise FprintDeleteWorkerError(
                "delete worker caller changed after transfer"
            )
        authorization = authorization_factory(
            peer,
            expected_uid=request.caller.uid,
            expected_session=request.session,
            expected_account=request.account,
        )

        def consume(authority, live):
            deletion = deletion_consumer_factory(
                request.finger_name,
            )
            return deletion(authority, live)

        result = broker_runner(
            None,
            operation="delete-one",
            modification_allowed=True,
            consumer=consume,
            allow_user_interaction=True,
            collect_activation_authority=False,
            authorization_manager=authorization,
        )
        if (
            not isinstance(result, t2_user_broker.BrokerResult)
            or result.consumer_invoked is not True
            or type(result.value)
            is not t2_fprint_deletion_runtime.DeletionCompletion
            or result.value.finger_name != request.finger_name
        ):
            raise FprintDeleteWorkerError(
                "delete worker broker returned no reconciled result"
            )
        mutation_completed = True
        t2_fprint_delete_worker_protocol.send_completion(
            connection, result.value
        )
        response_sent = True
        return result.value
    except BaseException as error:
        if not response_sent and not mutation_completed:
            try:
                t2_fprint_delete_worker_protocol.send_failure(connection)
            except BaseException:
                pass
        if isinstance(error, FprintDeleteWorkerError):
            raise
        raise FprintDeleteWorkerError(
            "caller-bound deletion stopped"
        ) from error
    finally:
        if authorization is not None:
            try:
                authorization.close()
            except BaseException:
                pass


def connect_endpoint(path: Path) -> socket.socket:
    """Connect only to the facade's operation-scoped private seqpacket path."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise FprintDeleteWorkerError("delete worker endpoint path is invalid")
    try:
        relative = path.relative_to(WORKER_ROOT)
        operation_id = relative.stem
        parsed = uuid.UUID(operation_id)
        root = WORKER_ROOT.stat(follow_symlinks=False)
    except (OSError, ValueError, AttributeError) as error:
        raise FprintDeleteWorkerError(
            "delete worker endpoint path is invalid"
        ) from error
    if (
        len(relative.parts) != 1
        or relative.suffix != ".sock"
        or str(parsed) != operation_id
        or parsed.int == 0
        or not stat.S_ISDIR(root.st_mode)
        or root.st_uid != os.geteuid()
        or root.st_mode & 0o077
    ):
        raise FprintDeleteWorkerError("delete worker endpoint path is unsafe")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        connection.settimeout(30)
        connection.connect(str(path))
        connection.settimeout(None)
        return connection
    except BaseException:
        connection.close()
        raise
