# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed translation from T2 enrollment state to the fprint ABI."""

from __future__ import annotations

from dataclasses import dataclass

import t2_enrollment_coordinator
import t2_enrollment_protocol


class FprintEnrollmentRuntimeError(RuntimeError):
    pass


@dataclass(frozen=True)
class EnrollmentUpdate:
    status: str | None
    done: bool
    finger_present: bool
    finger_needed: bool


class EnrollmentRuntime:
    """Reduce trusted coordinator feedback into documented fprint statuses."""

    def __init__(self) -> None:
        self.finger_present = False
        self.finger_needed = True
        self.last_progress = -1
        self.finished = False

    def _update(self, status: str | None = None) -> EnrollmentUpdate:
        return EnrollmentUpdate(
            status,
            False,
            self.finger_present,
            self.finger_needed,
        )

    def initial(self) -> EnrollmentUpdate:
        if self.finished or self.last_progress != -1:
            raise FprintEnrollmentRuntimeError(
                "initial enrollment state is no longer available"
            )
        return self._update()

    def accept(self, transition: object) -> EnrollmentUpdate:
        if self.finished:
            raise FprintEnrollmentRuntimeError(
                "enrollment feedback arrived after completion"
            )
        if not isinstance(
            transition, t2_enrollment_protocol.EnrollmentTransition
        ):
            raise FprintEnrollmentRuntimeError(
                "enrollment feedback has the wrong type"
            )
        action = transition.action
        if action is t2_enrollment_protocol.EnrollmentAction.FINGER_PRESENT:
            self.finger_present = True
            self.finger_needed = False
            return self._update()
        if action is t2_enrollment_protocol.EnrollmentAction.FINGER_REMOVED:
            self.finger_present = False
            self.finger_needed = True
            return self._update()
        if action is t2_enrollment_protocol.EnrollmentAction.PROGRESS:
            progress = transition.progress_percent
            if (
                type(progress) is not int
                or not 0 <= progress <= 100
                or progress < self.last_progress
            ):
                raise FprintEnrollmentRuntimeError(
                    "enrollment progress is invalid or regressed"
                )
            if progress == self.last_progress:
                return self._update()
            self.last_progress = progress
            self.finger_needed = False
            return self._update("enroll-stage-passed")
        statuses = {
            t2_enrollment_protocol.EnrollmentAction.REMOVE_AND_RETRY: (
                "enroll-remove-and-retry"
            ),
            t2_enrollment_protocol.EnrollmentAction.RETRY_SCAN: (
                "enroll-retry-scan"
            ),
            t2_enrollment_protocol.EnrollmentAction.RETRY_SMALL_COVERAGE: (
                "enroll-finger-not-centered"
            ),
            t2_enrollment_protocol.EnrollmentAction.DIRTY_SENSOR: (
                "enroll-retry-scan"
            ),
        }
        if action in statuses:
            self.finger_needed = action is not (
                t2_enrollment_protocol.EnrollmentAction.REMOVE_AND_RETRY
            )
            return self._update(statuses[action])
        if action in {
            t2_enrollment_protocol.EnrollmentAction.CONTINUE,
            t2_enrollment_protocol.EnrollmentAction.IGNORE_TELEMETRY,
            t2_enrollment_protocol.EnrollmentAction.IGNORE_AUXILIARY,
            t2_enrollment_protocol.EnrollmentAction.IGNORE_PHASE,
        }:
            return self._update()
        raise FprintEnrollmentRuntimeError(
            "terminal or identity feedback bypassed final reconciliation"
        )

    def finish(self, result: object) -> EnrollmentUpdate:
        if self.finished:
            raise FprintEnrollmentRuntimeError(
                "enrollment completed more than once"
            )
        if not isinstance(
            result, t2_enrollment_coordinator.EnrollmentCoordinatorResult
        ):
            raise FprintEnrollmentRuntimeError(
                "enrollment result has the wrong type"
            )
        successful = (
            result.outcome == "identity-observed"
            and result.policy_satisfied is True
            and result.persistence_ready is True
            and result.reconciliation_complete is True
        )
        reconciled_failure = (
            result.outcome in {"cancelled", "failed", "timed-out"}
            and result.persistence_ready is False
            and result.reconciliation_complete is True
        )
        status = (
            "enroll-completed"
            if successful
            else "enroll-failed"
            if reconciled_failure
            else "enroll-unknown-error"
        )
        self.finished = True
        self.finger_present = False
        self.finger_needed = False
        return EnrollmentUpdate(status, True, False, False)

    def fail_unknown(self) -> EnrollmentUpdate:
        if self.finished:
            raise FprintEnrollmentRuntimeError(
                "enrollment completed more than once"
            )
        self.finished = True
        self.finger_present = False
        self.finger_needed = False
        return EnrollmentUpdate("enroll-unknown-error", True, False, False)
