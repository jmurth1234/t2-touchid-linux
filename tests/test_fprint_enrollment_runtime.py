# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_enrollment_coordinator as coordinator
import t2_enrollment_protocol as protocol
import t2_fprint_enrollment_runtime as runtime


def transition(action, *, progress=None):
    return protocol.EnrollmentTransition(
        action, protocol.EnrollmentState.ACTIVE, progress_percent=progress
    )


class FprintEnrollmentRuntimeTests(unittest.TestCase):
    def test_presence_progress_and_duplicate_progress_are_truthful(self):
        state = runtime.EnrollmentRuntime()
        present = state.accept(
            transition(protocol.EnrollmentAction.FINGER_PRESENT)
        )
        self.assertEqual((present.status, present.finger_present), (None, True))
        progress = state.accept(
            transition(protocol.EnrollmentAction.PROGRESS, progress=23)
        )
        self.assertEqual(
            (progress.status, progress.done), ("enroll-stage-passed", False)
        )
        duplicate = state.accept(
            transition(protocol.EnrollmentAction.PROGRESS, progress=23)
        )
        self.assertIsNone(duplicate.status)
        removed = state.accept(
            transition(protocol.EnrollmentAction.FINGER_REMOVED)
        )
        self.assertEqual(
            (removed.finger_present, removed.finger_needed), (False, True)
        )

    def test_quality_feedback_uses_only_documented_statuses(self):
        expected = {
            protocol.EnrollmentAction.REMOVE_AND_RETRY: (
                "enroll-remove-and-retry"
            ),
            protocol.EnrollmentAction.RETRY_SCAN: "enroll-retry-scan",
            protocol.EnrollmentAction.RETRY_SMALL_COVERAGE: (
                "enroll-finger-not-centered"
            ),
            protocol.EnrollmentAction.DIRTY_SENSOR: "enroll-retry-scan",
        }
        for action, status in expected.items():
            with self.subTest(action=action):
                state = runtime.EnrollmentRuntime()
                self.assertEqual(state.accept(transition(action)).status, status)

    def test_only_reconciled_success_is_completed(self):
        state = runtime.EnrollmentRuntime()
        success = coordinator.EnrollmentCoordinatorResult(
            "identity-observed", True, True, True
        )
        self.assertEqual(
            state.finish(success),
            runtime.EnrollmentUpdate("enroll-completed", True, False, False),
        )
        with self.assertRaises(runtime.FprintEnrollmentRuntimeError):
            state.fail_unknown()

    def test_reconciled_terminal_failures_and_ambiguity_are_distinct(self):
        for outcome in ("cancelled", "failed", "timed-out"):
            state = runtime.EnrollmentRuntime()
            result = coordinator.EnrollmentCoordinatorResult(
                outcome, True, False, True
            )
            self.assertEqual(state.finish(result).status, "enroll-failed")

    def test_capacity_refusal_is_typed_and_strictly_pre_dispatch(self):
        state = runtime.EnrollmentRuntime()
        self.assertEqual(
            state.refuse_pre_dispatch("capacity-exhausted"),
            runtime.EnrollmentUpdate("enroll-data-full", True, False, False),
        )
        with self.assertRaises(runtime.FprintEnrollmentRuntimeError):
            state.refuse_pre_dispatch("capacity-exhausted")

        for reason in ("duplicate", None):
            with self.subTest(reason=reason), self.assertRaises(
                runtime.FprintEnrollmentRuntimeError
            ):
                runtime.EnrollmentRuntime().refuse_pre_dispatch(reason)

        progressed = runtime.EnrollmentRuntime()
        progressed.accept(
            protocol.EnrollmentTransition(
                protocol.EnrollmentAction.PROGRESS,
                protocol.EnrollmentState.ACTIVE,
                progress_percent=10,
            )
        )
        with self.assertRaises(runtime.FprintEnrollmentRuntimeError):
            progressed.refuse_pre_dispatch("capacity-exhausted")
        state = runtime.EnrollmentRuntime()
        ambiguous = coordinator.EnrollmentCoordinatorResult(
            "identity-observed", True, True, False
        )
        self.assertEqual(state.finish(ambiguous).status, "enroll-unknown-error")

    def test_regression_malformed_and_terminal_feedback_fail_closed(self):
        state = runtime.EnrollmentRuntime()
        state.accept(transition(protocol.EnrollmentAction.PROGRESS, progress=50))
        for value in (49, None, True, 101):
            with self.subTest(value=value), self.assertRaises(
                runtime.FprintEnrollmentRuntimeError
            ):
                state.accept(
                    transition(protocol.EnrollmentAction.PROGRESS, progress=value)
                )
        for action in (
            protocol.EnrollmentAction.CANCELLED,
            protocol.EnrollmentAction.IDENTITY_OBSERVED,
        ):
            with self.subTest(action=action), self.assertRaises(
                runtime.FprintEnrollmentRuntimeError
            ):
                runtime.EnrollmentRuntime().accept(transition(action))


if __name__ == "__main__":
    unittest.main()
