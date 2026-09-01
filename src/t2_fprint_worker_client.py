# SPDX-License-Identifier: GPL-2.0-only
"""Async facade-side lifecycle for the detached credential worker."""

from __future__ import annotations

import asyncio
import inspect
import threading
from collections.abc import Callable

import t2_dbus_identity
import t2_fprint_claim
import t2_fprint_enrollment_runtime
import t2_fprint_projection
import t2_fprint_worker_launcher
import t2_fprint_worker_protocol


class FprintWorkerClientError(RuntimeError):
    pass


UpdateConsumer = Callable[
    [t2_fprint_enrollment_runtime.EnrollmentUpdate], None
]


class EnrollmentWorkerClient:
    """Own one worker connection until its reconciled terminal update."""

    def __init__(
        self,
        *,
        launcher=t2_fprint_worker_launcher.launch,
    ) -> None:
        if not callable(launcher):
            raise FprintWorkerClientError("worker launcher is unavailable")
        self._launcher = launcher
        self.task: asyncio.Task | None = None
        self.session: t2_fprint_worker_launcher.WorkerConnection | None = None
        self.cancel_event: threading.Event | None = None
        self._request_sent = False
        self._cancel_sent = False

    @staticmethod
    def _deliver(
        consumer: UpdateConsumer,
        update: t2_fprint_enrollment_runtime.EnrollmentUpdate,
    ) -> None:
        result = consumer(update)
        if inspect.isawaitable(result):
            close = getattr(result, "close", None)
            if callable(close):
                close()
            raise FprintWorkerClientError(
                "worker update consumer must be synchronous"
            )
        if result is not None:
            raise FprintWorkerClientError(
                "worker update consumer must return None"
            )

    def start(
        self,
        finger_name: object,
        caller: t2_dbus_identity.PinnedDBusCaller,
        evidence: t2_fprint_claim.ClaimEvidence,
        on_update: UpdateConsumer,
    ) -> asyncio.Task:
        if self.task is not None:
            raise FprintWorkerClientError(
                "an enrollment worker is already active"
            )
        if finger_name not in t2_fprint_projection.FINGER_NAME_SET:
            raise FprintWorkerClientError(
                "worker enrollment requires a canonical finger name"
            )
        if (
            not isinstance(caller, t2_dbus_identity.PinnedDBusCaller)
            or not isinstance(evidence, t2_fprint_claim.ClaimEvidence)
            or not callable(on_update)
            or caller.subject.uid != evidence.linux_uid
            or evidence.account.linux_uid != evidence.linux_uid
        ):
            raise FprintWorkerClientError(
                "worker enrollment claim is invalid or cross-user"
            )
        cancel_event = threading.Event()
        self.cancel_event = cancel_event
        self._request_sent = False
        self._cancel_sent = False
        self.task = asyncio.create_task(
            self._supervise(
                finger_name, caller, evidence, on_update, cancel_event
            )
        )
        return self.task

    async def _send_cancel_if_ready(self) -> None:
        session = self.session
        if (
            session is None
            or not self._request_sent
            or self._cancel_sent
        ):
            return
        self._cancel_sent = True
        try:
            await asyncio.to_thread(
                t2_fprint_worker_protocol.send_cancel,
                session.connection,
            )
        except t2_fprint_worker_protocol.FprintWorkerProtocolError:
            pass

    async def _supervise(
        self,
        finger_name: str,
        caller: t2_dbus_identity.PinnedDBusCaller,
        evidence: t2_fprint_claim.ClaimEvidence,
        on_update: UpdateConsumer,
        cancel_event: threading.Event,
    ) -> t2_fprint_enrollment_runtime.EnrollmentUpdate:
        operation = asyncio.create_task(
            self._run(
                finger_name, caller, evidence, on_update, cancel_event
            )
        )
        try:
            return await asyncio.shield(operation)
        except asyncio.CancelledError:
            cancel_event.set()
            await self._send_cancel_if_ready()
            return await operation

    async def _run(
        self,
        finger_name: str,
        caller: t2_dbus_identity.PinnedDBusCaller,
        evidence: t2_fprint_claim.ClaimEvidence,
        on_update: UpdateConsumer,
        cancel_event: threading.Event,
    ) -> t2_fprint_enrollment_runtime.EnrollmentUpdate:
        terminal: t2_fprint_enrollment_runtime.EnrollmentUpdate | None = None
        session = None
        try:
            await asyncio.to_thread(evidence.revalidate, caller)
            session = await asyncio.to_thread(self._launcher)
            if not isinstance(
                session, t2_fprint_worker_launcher.WorkerConnection
            ):
                raise FprintWorkerClientError(
                    "worker launcher returned no typed connection"
                )
            self.session = session
            await asyncio.to_thread(evidence.revalidate, caller)
            request = t2_fprint_worker_protocol.StartRequest(
                finger_name,
                caller.subject,
                evidence.account,
                evidence.session,
            )
            await asyncio.to_thread(
                t2_fprint_worker_protocol.send_start,
                session.connection,
                request,
                caller.pidfd,
            )
            self._request_sent = True
            if cancel_event.is_set():
                await self._send_cancel_if_ready()
            while terminal is None:
                update = await asyncio.to_thread(
                    t2_fprint_worker_protocol.receive_update,
                    session.connection,
                )
                self._deliver(on_update, update)
                if update.done:
                    terminal = update
            return terminal
        except BaseException:
            unknown = t2_fprint_enrollment_runtime.EnrollmentUpdate(
                "enroll-unknown-error", True, False, False
            )
            try:
                self._deliver(on_update, unknown)
            except BaseException:
                pass
            return unknown
        finally:
            if session is not None:
                session.close()
            self.session = None
            self._request_sent = False

    async def stop(
        self,
    ) -> t2_fprint_enrollment_runtime.EnrollmentUpdate:
        task = self.task
        cancel_event = self.cancel_event
        if task is None or cancel_event is None:
            raise FprintWorkerClientError("no enrollment worker is active")
        if not task.done():
            cancel_event.set()
            await self._send_cancel_if_ready()
        try:
            return await asyncio.shield(task)
        finally:
            self.task = None
            self.cancel_event = None
            self._request_sent = False
            self._cancel_sent = False

    async def release(self) -> None:
        if self.task is not None:
            await self.stop()
