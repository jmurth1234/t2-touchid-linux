# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import asyncio
import sys
import threading
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_enrollment_coordinator as coordinator
import t2_enrollment_protocol as protocol
import t2_fprint_enrollment_controller as controller


def transition(action, *, progress=None):
    return protocol.EnrollmentTransition(
        action, protocol.EnrollmentState.ACTIVE, progress_percent=progress
    )


class FprintEnrollmentControllerTests(unittest.IsolatedAsyncioTestCase):
    async def test_success_feedback_is_ordered_before_reconciled_completion(self):
        updates = []

        def worker(finger_name, cancel_requested, feedback):
            self.assertEqual(finger_name, "left-thumb")
            self.assertFalse(cancel_requested())
            feedback(transition(protocol.EnrollmentAction.FINGER_PRESENT))
            feedback(
                transition(protocol.EnrollmentAction.PROGRESS, progress=25)
            )
            return coordinator.EnrollmentCoordinatorResult(
                "identity-observed", True, True, True
            )

        lifecycle = controller.EnrollmentController()
        task = lifecycle.start("left-thumb", worker, updates.append)
        final = await task
        self.assertEqual(final.status, "enroll-completed")
        self.assertEqual(
            [item.status for item in updates],
            [None, None, "enroll-stage-passed", "enroll-completed"],
        )
        self.assertIs(lifecycle.task, task)
        self.assertEqual((await lifecycle.stop()).status, "enroll-completed")
        self.assertIsNone(lifecycle.task)

    async def test_stop_requests_cooperative_cancel_without_task_kill(self):
        entered = threading.Event()
        updates = []

        def worker(_finger_name, cancel_requested, _feedback):
            entered.set()
            while not cancel_requested():
                pass
            return coordinator.EnrollmentCoordinatorResult(
                "cancelled", True, False, True
            )

        lifecycle = controller.EnrollmentController()
        task = lifecycle.start("right-thumb", worker, updates.append)
        await asyncio.to_thread(entered.wait)
        final = await lifecycle.stop()
        self.assertIs(task.cancelled(), False)
        self.assertEqual(final.status, "enroll-failed")
        self.assertEqual(updates[-1].status, "enroll-failed")

    async def test_worker_or_feedback_failure_is_terminal_unknown(self):
        for worker in (
            lambda _finger, _cancel, _feedback: (_ for _ in ()).throw(
                RuntimeError("worker failed")
            ),
            lambda _finger, _cancel, feedback: feedback(
                transition(protocol.EnrollmentAction.PROGRESS, progress=None)
            ),
        ):
            updates = []
            lifecycle = controller.EnrollmentController()
            task = lifecycle.start("left-index-finger", worker, updates.append)
            final = await task
            self.assertEqual(final.status, "enroll-unknown-error")
            await lifecycle.stop()

    async def test_async_task_cancellation_becomes_cooperative_worker_cancel(self):
        entered = threading.Event()
        updates = []

        def worker(_finger_name, cancel_requested, _feedback):
            entered.set()
            while not cancel_requested():
                pass
            return coordinator.EnrollmentCoordinatorResult(
                "cancelled", True, False, True
            )

        lifecycle = controller.EnrollmentController()
        task = lifecycle.start("left-thumb", worker, updates.append)
        await asyncio.to_thread(entered.wait)
        task.cancel()
        final = await task
        self.assertFalse(task.cancelled())
        self.assertEqual(final.status, "enroll-failed")
        await lifecycle.stop()

    async def test_invalid_or_concurrent_start_fails_before_new_worker(self):
        release = asyncio.Event()
        loop = asyncio.get_running_loop()

        def worker(_finger, _cancel, _feedback):
            future = asyncio.run_coroutine_threadsafe(release.wait(), loop)
            future.result(timeout=2)
            return coordinator.EnrollmentCoordinatorResult(
                "cancelled", True, False, True
            )

        lifecycle = controller.EnrollmentController()
        with self.assertRaises(controller.FprintEnrollmentControllerError):
            lifecycle.start("any", worker, lambda _update: None)
        lifecycle.start("right-index-finger", worker, lambda _update: None)
        with self.assertRaises(controller.FprintEnrollmentControllerError):
            lifecycle.start("right-thumb", worker, lambda _update: None)
        release.set()
        await lifecycle.stop()


if __name__ == "__main__":
    unittest.main()
