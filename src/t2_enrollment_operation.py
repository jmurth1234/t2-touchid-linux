# SPDX-License-Identifier: GPL-2.0-only
"""Journaled enrollment operation core with no live transport implementation."""

from __future__ import annotations

import hashlib
import inspect
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import t2_enrollment_journal as enrollment_journal
import t2_enrollment_protocol as protocol


class EnrollmentOperationError(RuntimeError):
    pass


class EnrollmentPreDispatchCancelled(EnrollmentOperationError):
    """The live safety guard stopped enrollment before any SEP dispatch."""


class EnrollmentTransport(Protocol):
    """Synchronous same-connection transport supplied by a future broker."""

    connection_generation: str
    protocol_version: int

    def start(self, payload: memoryview) -> int: ...

    def continue_enrollment(self) -> int: ...

    def cancel(self) -> int: ...

    def next_event(self) -> bytes: ...


@dataclass(frozen=True, repr=False)
class EnrollmentOperationResult:
    outcome: str
    transition: protocol.EnrollmentTransition | None
    reconciliation_required: bool


class EnrollmentOperation:
    """Drive E1 through E2 synchronously under one authorization callback."""

    def __init__(
        self,
        *,
        journal_path: Path,
        operation_id: str,
        transport: EnrollmentTransport,
        linux_boot_uuid: str,
        mapping_generation: str,
        caller_linux_uid: int,
        target_linux_uid: int,
    ) -> None:
        history = enrollment_journal.read(journal_path)
        enrollment_journal.require_start_ready(
            history,
            linux_boot_uuid=linux_boot_uuid,
            connection_generation=transport.connection_generation,
            mapping_generation=mapping_generation,
            caller_linux_uid=caller_linux_uid,
            target_linux_uid=target_linux_uid,
            protocol_version=transport.protocol_version,
        )
        if operation_id != history.operation_id:
            raise EnrollmentOperationError("operation ID does not match E0 journal")
        self.journal_path = journal_path
        self.operation_id = operation_id
        self.transport = transport
        self.history = history
        self.apple_user_id = history.baseline["apple_uid"]

    def run(
        self,
        acm_external_form: bytes,
        *,
        dispatch_allowed: Callable[[], bool] = lambda: True,
        cancel_requested: Callable[[], bool] = lambda: False,
        on_feedback: Callable[[protocol.EnrollmentTransition], None] = lambda _transition: None,
        event_limit: int = 512,
    ) -> EnrollmentOperationResult:
        if not isinstance(event_limit, int) or isinstance(event_limit, bool) or not 1 <= event_limit <= 1024:
            raise EnrollmentOperationError("event limit is outside policy")
        machine = protocol.EnrollmentStateMachine(
            expected_user_id=self.apple_user_id,
            connection_generation=self.transport.connection_generation,
            operation_id=self.operation_id,
        )
        try:
            try:
                allowed = dispatch_allowed()
                if inspect.isawaitable(allowed):
                    close = getattr(allowed, "close", None)
                    if callable(close):
                        close()
                    allowed = False
            except BaseException:
                allowed = False
            if allowed is not True:
                self._append(
                    "ENROLL_ABORTED_BEFORE_START",
                    {
                        "connection_generation": self.transport.connection_generation,
                        "reason": "safety-guard-unavailable",
                        "mutation_possible": False,
                    },
                )
                raise EnrollmentPreDispatchCancelled(
                    "enrollment cancelled before start dispatch"
                )
            with protocol.SensitiveEnrollmentRequest(
                self.transport.protocol_version,
                self.apple_user_id,
                acm_external_form,
            ) as request:
                request_bytes = request.buffer
                self._append(
                    "ENROLL_START_INTENT",
                    {
                        "apple_uid": self.apple_user_id,
                        "protocol_version": self.transport.protocol_version,
                        "connection_generation": self.transport.connection_generation,
                        "request_length": len(request_bytes),
                        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
                    },
                )
                try:
                    start_status = self._transport_status(
                        self.transport.start(request_bytes), "start"
                    )
                except BaseException as error:
                    self._outcome_unknown("start", "transport-error", error)
                if start_status != 0:
                    self._append_during_active_operation(
                        "ENROLL_START_REJECTED",
                        {"status": start_status},
                        stage="start",
                    )
                    return EnrollmentOperationResult(
                        "start-rejected", None, reconciliation_required=True
                    )
                self._append_during_active_operation(
                    "ENROLL_START_OBSERVED", {"status": 0}, stage="start"
                )

            cancel_sent = False
            for _event_index in range(event_limit):
                try:
                    should_cancel = not cancel_sent and cancel_requested()
                except BaseException as error:
                    self._outcome_unknown("active", "protocol-error", error)
                if should_cancel:
                    self._append_during_active_operation(
                        "ENROLL_CANCEL_INTENT",
                        {
                            "connection_generation": self.transport.connection_generation,
                            "reason": "caller-requested",
                        },
                        stage="cancel",
                    )
                    machine.request_cancel()
                    try:
                        cancel_status = self._transport_status(
                            self.transport.cancel(), "cancel"
                        )
                    except BaseException as error:
                        self._outcome_unknown("cancel", "transport-error", error)
                    if cancel_status != 0:
                        self._outcome_unknown(
                            "cancel",
                            "transport-error",
                            EnrollmentOperationError(
                                f"cancel returned status {cancel_status}"
                            ),
                        )
                    self._append_during_active_operation(
                        "ENROLL_CANCEL_DISPATCH_OBSERVED",
                        {"status": 0},
                        stage="cancel",
                    )
                    cancel_sent = True

                try:
                    raw_event = self.transport.next_event()
                except BaseException as error:
                    self._outcome_unknown("active", "connection-lost", error)
                try:
                    event = protocol.parse_service_event(raw_event)
                    transition = machine.accept(
                        event,
                        connection_generation=self.transport.connection_generation,
                        operation_id=self.operation_id,
                    )
                except (protocol.EnrollmentProtocolError, TypeError) as error:
                    self._outcome_unknown("terminal", "protocol-error", error)

                if transition.action not in {
                    protocol.EnrollmentAction.IGNORE_TELEMETRY,
                    protocol.EnrollmentAction.IGNORE_AUXILIARY,
                    protocol.EnrollmentAction.IGNORE_PHASE,
                    protocol.EnrollmentAction.IDENTITY_OBSERVED,
                    protocol.EnrollmentAction.CANCELLED,
                    protocol.EnrollmentAction.FAILED,
                    protocol.EnrollmentAction.TIMED_OUT,
                }:
                    try:
                        feedback_result = on_feedback(transition)
                        if inspect.isawaitable(feedback_result):
                            close = getattr(feedback_result, "close", None)
                            if callable(close):
                                close()
                            raise EnrollmentOperationError(
                                "enrollment feedback callback must be synchronous"
                            )
                        if feedback_result is not None:
                            raise EnrollmentOperationError(
                                "enrollment feedback callback must return None"
                            )
                    except BaseException as error:
                        self._outcome_unknown("active", "protocol-error", error)

                if transition.continue_required:
                    self._append_during_active_operation(
                        "ENROLL_CONTINUE_INTENT",
                        {
                            "connection_generation": self.transport.connection_generation,
                            "event_sequence": event.sequence,
                            "event_ordinal": event.ordinal,
                            "event_sha256": hashlib.sha256(raw_event).hexdigest(),
                        },
                        stage="continue",
                    )
                    try:
                        continue_status = self._transport_status(
                            self.transport.continue_enrollment(), "continue"
                        )
                    except BaseException as error:
                        self._outcome_unknown("continue", "transport-error", error)
                    if continue_status != 0:
                        self._outcome_unknown(
                            "continue",
                            "transport-error",
                            EnrollmentOperationError(
                                f"continue returned status {continue_status}"
                            ),
                        )
                    self._append_during_active_operation(
                        "ENROLL_CONTINUE_OBSERVED",
                        {"event_sequence": event.sequence, "status": 0},
                        stage="continue",
                    )
                    continue

                if transition.action is protocol.EnrollmentAction.IDENTITY_OBSERVED:
                    assert transition.identity is not None
                    self._append_during_active_operation(
                        "E2_TERMINAL_IDENTITY_OBSERVED",
                        {
                            "connection_generation": self.transport.connection_generation,
                            "event_sequence": event.sequence,
                            "envelope_type": event.envelope_type,
                            "event_version": event.version,
                            "user_id": transition.identity.user_id,
                            "identity_uuid": str(
                                uuid.UUID(bytes=transition.identity.identity_uuid)
                            ),
                        },
                        stage="terminal",
                    )
                    return EnrollmentOperationResult(
                        "identity-observed",
                        transition,
                        reconciliation_required=True,
                    )

                terminal_status = {
                    protocol.EnrollmentAction.CANCELLED: 66,
                    protocol.EnrollmentAction.FAILED: 67,
                    protocol.EnrollmentAction.TIMED_OUT: 68,
                }.get(transition.action)
                if terminal_status is not None:
                    self._append_during_active_operation(
                        "ENROLL_TERMINAL_FAILURE_OBSERVED",
                        {
                            "connection_generation": self.transport.connection_generation,
                            "event_sequence": event.sequence,
                            "envelope_type": event.envelope_type,
                            "status": terminal_status,
                        },
                        stage="terminal",
                    )
                    return EnrollmentOperationResult(
                        transition.action.value,
                        transition,
                        reconciliation_required=True,
                    )

            self._outcome_unknown(
                "active",
                "protocol-error",
                EnrollmentOperationError("enrollment event limit reached"),
            )
        except EnrollmentOperationError:
            raise
        except BaseException as error:
            if self.history.phase in {
                enrollment_journal.EnrollmentPhase.ACTIVE,
                enrollment_journal.EnrollmentPhase.CONTINUE_INTENT,
                enrollment_journal.EnrollmentPhase.CANCEL_INTENT,
                enrollment_journal.EnrollmentPhase.CANCEL_REQUESTED,
            }:
                self._outcome_unknown("active", "protocol-error", error)
            raise EnrollmentOperationError("enrollment operation failed locally") from error
        raise AssertionError("unreachable enrollment operation state")

    def _append(self, milestone: str, evidence: dict[str, object]) -> None:
        try:
            self.history = enrollment_journal.append_checked(
                self.journal_path, self.operation_id, milestone, evidence
            )
        except enrollment_journal.EnrollmentJournalError as error:
            raise EnrollmentOperationError(
                f"durable enrollment milestone {milestone} failed"
            ) from error

    def _outcome_unknown(
        self, stage: str, reason: str, cause: BaseException
    ) -> None:
        try:
            self._append(
                "ENROLL_OUTCOME_UNKNOWN",
                {
                    "connection_generation": self.transport.connection_generation,
                    "stage": stage,
                    "reason": reason,
                    "mutation_possible": True,
                },
            )
        except EnrollmentOperationError as journal_error:
            raise EnrollmentOperationError(
                "enrollment outcome is unknown and could not be journaled"
            ) from journal_error
        raise EnrollmentOperationError(
            "enrollment outcome is unknown; reconciliation is required"
        ) from cause

    def _append_during_active_operation(
        self,
        milestone: str,
        evidence: dict[str, object],
        *,
        stage: str,
    ) -> None:
        try:
            self._append(milestone, evidence)
        except EnrollmentOperationError as error:
            self._outcome_unknown(stage, "journal-error", error)

    @staticmethod
    def _transport_status(value: object, operation: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or not -(2**31) <= value < 2**32:
            raise EnrollmentOperationError(
                f"{operation} transport returned an invalid status"
            )
        return value
