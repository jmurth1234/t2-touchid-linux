# SPDX-License-Identifier: GPL-2.0-only
"""Credential-scoped worker core for one caller-bound fprint enrollment."""

from __future__ import annotations

import os
import socket
import stat
import threading
import uuid
from pathlib import Path

import t2_enrollment_coordinator
import t2_fprint_enrollment_consumer
import t2_fprint_enrollment_runtime
import t2_fprint_worker_protocol
import t2_ipc_session
import t2_system_credential
import t2_user_broker


WORKER_ROOT = Path("/run/t2-touchid/workers")


class FprintWorkerError(RuntimeError):
    pass


def _capacity_exhausted(error: BaseException) -> bool:
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        if isinstance(
            current,
            t2_fprint_enrollment_consumer.FprintEnrollmentDataFullError,
        ):
            return True
        seen.add(id(current))
        cause = current.__cause__
        current = cause if isinstance(cause, BaseException) else None
    return False


def _cancel_listener(
    connection: socket.socket,
    cancel_event: threading.Event,
    completed_event: threading.Event,
) -> None:
    try:
        t2_fprint_worker_protocol.receive_cancel(connection)
    except (
        t2_fprint_worker_protocol.FprintWorkerPeerClosed,
        t2_fprint_worker_protocol.FprintWorkerProtocolError,
    ):
        pass
    finally:
        if not completed_event.is_set():
            cancel_event.set()


def serve_once(
    connection: socket.socket,
    *,
    authorization_factory=t2_ipc_session.AuthorizationSession.from_peer,
    binder_factory=t2_system_credential.CredentialPasswordBinder,
    broker_runner=t2_user_broker.run_self_service,
    enrollment_consumer_factory=(
        t2_fprint_enrollment_consumer.EnrollmentConsumer
    ),
) -> t2_enrollment_coordinator.EnrollmentCoordinatorResult:
    """Run exactly one enrollment; every failure emits at most one terminal."""

    if (
        not callable(authorization_factory)
        or not callable(binder_factory)
        or not callable(broker_runner)
        or not callable(enrollment_consumer_factory)
    ):
        raise FprintWorkerError("worker dependency is unavailable")
    runtime = t2_fprint_enrollment_runtime.EnrollmentRuntime()
    cancel_event = threading.Event()
    completed_event = threading.Event()
    listener: threading.Thread | None = None
    authorization = None
    terminal_sent = False
    try:
        request, pidfd = t2_fprint_worker_protocol.receive_start(connection)
        peer = t2_ipc_session.PinnedPeer.from_process_fd(
            pidfd,
            request.caller.pid,
            request.caller.uid,
        )
        if peer.subject != request.caller:
            peer.close()
            raise FprintWorkerError("worker caller changed after transfer")
        authorization = authorization_factory(
            peer,
            expected_uid=request.caller.uid,
            expected_session=request.session,
            expected_account=request.account,
        )
        listener = threading.Thread(
            target=_cancel_listener,
            args=(connection, cancel_event, completed_event),
            name="t2-fprint-worker-cancel",
            daemon=True,
        )
        listener.start()

        def consume(authority, live):
            if cancel_event.is_set():
                raise FprintWorkerError(
                    "worker enrollment was cancelled before credential use"
                )
            if authority.selected.unlock_mode != "host-encrypted-credential":
                raise FprintWorkerError(
                    "mapped user has no worker-scoped credential authority"
                )
            binder = binder_factory(authority.selected.special_bag_alias)
            fallback_verified = binder.verify_password_fallback()
            t2_fprint_worker_protocol.send_update(
                connection, runtime.initial()
            )
            enrollment = enrollment_consumer_factory(
                request.finger_name,
                binder.bind,
                cancel_event.is_set,
                lambda transition: t2_fprint_worker_protocol.send_update(
                    connection, runtime.accept(transition)
                ),
                fallback_verified,
            )
            return enrollment(authority, live)

        result = broker_runner(
            None,
            operation="enroll",
            modification_allowed=True,
            consumer=consume,
            allow_user_interaction=True,
            collect_activation_authority=False,
            authorization_manager=authorization,
        )
        if (
            not isinstance(result, t2_user_broker.BrokerResult)
            or result.consumer_invoked is not True
            or not isinstance(
                result.value,
                t2_enrollment_coordinator.EnrollmentCoordinatorResult,
            )
        ):
            raise FprintWorkerError(
                "worker broker returned no enrollment result"
            )
        final = runtime.finish(result.value)
        t2_fprint_worker_protocol.send_update(connection, final)
        terminal_sent = True
        return result.value
    except BaseException as error:
        if not terminal_sent:
            try:
                update = (
                    runtime.refuse_pre_dispatch("capacity-exhausted")
                    if _capacity_exhausted(error)
                    else runtime.fail_unknown()
                )
                t2_fprint_worker_protocol.send_update(
                    connection, update
                )
            except BaseException:
                pass
        if isinstance(error, FprintWorkerError):
            raise
        raise FprintWorkerError("credential-scoped enrollment stopped") from error
    finally:
        completed_event.set()
        cancel_event.set()
        if authorization is not None:
            try:
                authorization.close()
            except BaseException:
                pass
        try:
            connection.shutdown(socket.SHUT_RD)
        except OSError:
            pass
        if listener is not None:
            listener.join(timeout=5)


def connect_endpoint(path: Path) -> socket.socket:
    """Connect only to the facade's operation-scoped private seqpacket path."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise FprintWorkerError("worker endpoint path is invalid")
    try:
        relative = path.relative_to(WORKER_ROOT)
        operation_id = relative.stem
        parsed = uuid.UUID(operation_id)
        root = WORKER_ROOT.stat(follow_symlinks=False)
    except (OSError, ValueError, AttributeError) as error:
        raise FprintWorkerError("worker endpoint path is invalid") from error
    if (
        len(relative.parts) != 1
        or relative.suffix != ".sock"
        or str(parsed) != operation_id
        or parsed.int == 0
        or not stat.S_ISDIR(root.st_mode)
        or root.st_uid != os.geteuid()
        or root.st_mode & 0o077
    ):
        raise FprintWorkerError("worker endpoint path is unsafe")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        connection.settimeout(30)
        connection.connect(str(path))
        connection.settimeout(None)
        return connection
    except BaseException:
        connection.close()
        raise
