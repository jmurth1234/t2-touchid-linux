# SPDX-License-Identifier: GPL-2.0-only
"""Async fprint lifecycle around one synchronous journaled T2 enrollment."""

from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
import threading
from collections.abc import Callable

import t2_enrollment_coordinator
import t2_fprint_enrollment_runtime
import t2_fprint_projection


class FprintEnrollmentControllerError(RuntimeError):
    pass


EnrollmentWorker = Callable[
    [str, Callable[[], bool], Callable[[object], None]],
    t2_enrollment_coordinator.EnrollmentCoordinatorResult,
]
UpdateConsumer = Callable[
    [t2_fprint_enrollment_runtime.EnrollmentUpdate], None
]


class EnrollmentController:
    """Own one operation task and cooperative cancellation event."""

    def __init__(self) -> None:
        self.task: asyncio.Task | None = None
        self.cancel_event: threading.Event | None = None

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
            raise FprintEnrollmentControllerError(
                "enrollment update consumer must be synchronous"
            )
        if result is not None:
            raise FprintEnrollmentControllerError(
                "enrollment update consumer must return None"
            )

    def start(
        self,
        finger_name: object,
        worker: EnrollmentWorker,
        on_update: UpdateConsumer,
    ) -> asyncio.Task:
        if self.task is not None:
            raise FprintEnrollmentControllerError(
                "an enrollment transaction is already active"
            )
        if finger_name not in t2_fprint_projection.FINGER_NAME_SET:
            raise FprintEnrollmentControllerError(
                "enrollment requires one canonical finger name"
            )
        if not callable(worker) or not callable(on_update):
            raise FprintEnrollmentControllerError(
                "enrollment worker or update consumer is unavailable"
            )
        operation_cancel = threading.Event()
        runtime = t2_fprint_enrollment_runtime.EnrollmentRuntime()
        self._deliver(on_update, runtime.initial())
        self.cancel_event = operation_cancel
        self.task = asyncio.create_task(
            self._run(
                finger_name,
                worker,
                on_update,
                operation_cancel,
                runtime,
            )
        )
        return self.task

    async def _run(
        self,
        finger_name: str,
        worker: EnrollmentWorker,
        on_update: UpdateConsumer,
        operation_cancel: threading.Event,
        runtime: t2_fprint_enrollment_runtime.EnrollmentRuntime,
    ) -> t2_fprint_enrollment_runtime.EnrollmentUpdate:
        loop = asyncio.get_running_loop()

        async def deliver(
            update: t2_fprint_enrollment_runtime.EnrollmentUpdate,
        ) -> None:
            self._deliver(on_update, update)

        def feedback(transition: object) -> None:
            update = runtime.accept(transition)
            delivery = asyncio.run_coroutine_threadsafe(
                deliver(update), loop
            )
            try:
                delivery.result(timeout=5)
            except concurrent.futures.TimeoutError as error:
                delivery.cancel()
                raise FprintEnrollmentControllerError(
                    "enrollment feedback delivery timed out"
                ) from error

        worker_task = asyncio.create_task(
            asyncio.to_thread(
                worker,
                finger_name,
                operation_cancel.is_set,
                feedback,
            )
        )
        try:
            try:
                result = await asyncio.shield(worker_task)
            except asyncio.CancelledError:
                # An accidental asyncio cancellation must become the worker's
                # journaled cooperative cancel path, never an abandoned thread.
                operation_cancel.set()
                result = await worker_task
            final = runtime.finish(result)
        except BaseException:
            final = runtime.fail_unknown()
        await deliver(final)
        return final

    async def stop(self) -> t2_fprint_enrollment_runtime.EnrollmentUpdate:
        task = self.task
        if task is None or self.cancel_event is None:
            raise FprintEnrollmentControllerError(
                "no enrollment transaction is active"
            )
        if not task.done():
            self.cancel_event.set()
        try:
            result = await asyncio.shield(task)
        finally:
            self.task = None
            self.cancel_event = None
        return result

    async def release(self) -> None:
        if self.task is not None:
            await self.stop()
