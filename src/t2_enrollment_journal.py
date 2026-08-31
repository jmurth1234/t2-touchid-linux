# SPDX-License-Identifier: GPL-2.0-only
"""Typed transition rules above the generic durable mutation journal."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import t2_mutation_journal as journal


SERVICE_STATUS = 0xE3FF8001
SERVICE_ENROLLMENT_RESULT = 0xE3FF8003


class EnrollmentJournalError(journal.JournalError):
    pass


class EnrollmentPhase(Enum):
    BASELINE = "baseline-reconciled"
    START_INTENT = "start-intent"
    ACTIVE = "active"
    CONTINUE_INTENT = "continue-intent"
    CANCEL_INTENT = "cancel-intent"
    CANCEL_REQUESTED = "cancel-requested"
    TERMINAL_IDENTITY = "terminal-identity"
    TERMINAL_FAILURE = "terminal-failure"
    OUTCOME_UNKNOWN = "outcome-unknown"


@dataclass(frozen=True)
class EnrollmentHistory:
    operation_id: str
    phase: EnrollmentPhase
    baseline: dict[str, Any]
    last_event_sequence: int | None
    pending_event_sequence: int | None
    record_count: int
    head_hash: str


def _exact(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise EnrollmentJournalError(f"{field} evidence does not match its schema")
    return value


def _uint(value: Any, field: str, maximum: int = 0xFFFFFFFFFFFFFFFF) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= maximum
    ):
        raise EnrollmentJournalError(f"{field} is not a bounded unsigned integer")
    return value


def _status(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not -(2**31) <= value < 2**32:
        raise EnrollmentJournalError(f"{field} is not a bounded status value")
    return value


def _uuid(value: Any, field: str) -> None:
    try:
        journal.require_uuid(value, field)
    except journal.JournalError as error:
        raise EnrollmentJournalError(str(error)) from error


def _sha256(value: Any, field: str) -> None:
    try:
        journal.require_sha256(value, field)
    except journal.JournalError as error:
        raise EnrollmentJournalError(str(error)) from error


def _same_generation(evidence: dict[str, Any], baseline: dict[str, Any]) -> None:
    if evidence["connection_generation"] != baseline["connection_generation"]:
        raise EnrollmentJournalError("enrollment connection generation changed")


def validate_history(records: list[dict[str, Any]]) -> EnrollmentHistory:
    if not records:
        raise EnrollmentJournalError("enrollment journal is empty")
    first = records[0]
    if first.get("milestone") != "BASELINE_RECONCILED":
        raise EnrollmentJournalError("enrollment journal has no reconciled baseline")
    initial = _exact(
        first.get("evidence"), {"operation_kind", "baseline"}, "baseline"
    )
    if initial["operation_kind"] != "enroll":
        raise EnrollmentJournalError("journal is not an enrollment operation")
    baseline = initial["baseline"]
    try:
        journal.validate_baseline(baseline)
    except journal.JournalError as error:
        raise EnrollmentJournalError(str(error)) from error
    operation_id = first.get("operation_id")
    _uuid(operation_id, "operation_id")
    phase = EnrollmentPhase.BASELINE
    last_event: int | None = None
    pending_event: int | None = None

    for record in records[1:]:
        if record.get("operation_id") != operation_id:
            raise EnrollmentJournalError("operation ID changed inside enrollment journal")
        milestone = record.get("milestone")
        evidence = record.get("evidence")

        if milestone == "ENROLL_START_INTENT":
            if phase is not EnrollmentPhase.BASELINE:
                raise EnrollmentJournalError("enrollment start intent is out of order")
            evidence = _exact(
                evidence,
                {
                    "apple_uid",
                    "protocol_version",
                    "connection_generation",
                    "request_length",
                    "request_sha256",
                },
                milestone,
            )
            if (
                evidence["apple_uid"] != baseline["apple_uid"]
                or evidence["protocol_version"] != baseline["protocol_version"]
                or evidence["request_length"]
                != (48 if baseline["protocol_version"] == 1 else 68)
            ):
                raise EnrollmentJournalError("start intent disagrees with baseline")
            _same_generation(evidence, baseline)
            _sha256(evidence["request_sha256"], "request_sha256")
            phase = EnrollmentPhase.START_INTENT
            continue

        if milestone == "ENROLL_START_OBSERVED":
            if phase is not EnrollmentPhase.START_INTENT:
                raise EnrollmentJournalError("enrollment start observation is out of order")
            evidence = _exact(evidence, {"status"}, milestone)
            if _status(evidence["status"], "start status") != 0:
                raise EnrollmentJournalError("accepted enrollment start status is not zero")
            phase = EnrollmentPhase.ACTIVE
            continue

        if milestone == "ENROLL_START_REJECTED":
            if phase is not EnrollmentPhase.START_INTENT:
                raise EnrollmentJournalError("enrollment start rejection is out of order")
            evidence = _exact(evidence, {"status"}, milestone)
            if _status(evidence["status"], "start status") == 0:
                raise EnrollmentJournalError("rejected enrollment start has status zero")
            phase = EnrollmentPhase.TERMINAL_FAILURE
            continue

        if milestone == "ENROLL_CONTINUE_INTENT":
            if phase is not EnrollmentPhase.ACTIVE:
                raise EnrollmentJournalError("enrollment continue intent is out of order")
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "event_sequence",
                    "event_ordinal",
                    "event_sha256",
                },
                milestone,
            )
            _same_generation(evidence, baseline)
            sequence = _uint(evidence["event_sequence"], "event sequence")
            ordinal = _uint(evidence["event_ordinal"], "event ordinal")
            if ordinal != 70 and not 100 <= ordinal <= 355:
                raise EnrollmentJournalError("continue intent does not follow a continue event")
            if last_event is not None and sequence <= last_event:
                raise EnrollmentJournalError("continue event sequence is not increasing")
            _sha256(evidence["event_sha256"], "event_sha256")
            pending_event = sequence
            phase = EnrollmentPhase.CONTINUE_INTENT
            continue

        if milestone == "ENROLL_CONTINUE_OBSERVED":
            if phase is not EnrollmentPhase.CONTINUE_INTENT:
                raise EnrollmentJournalError("enrollment continue observation is out of order")
            evidence = _exact(evidence, {"event_sequence", "status"}, milestone)
            if (
                _uint(evidence["event_sequence"], "event sequence") != pending_event
                or _status(evidence["status"], "continue status") != 0
            ):
                raise EnrollmentJournalError("continue observation disagrees with its intent")
            last_event = pending_event
            pending_event = None
            phase = EnrollmentPhase.ACTIVE
            continue

        if milestone == "ENROLL_CANCEL_INTENT":
            if phase is not EnrollmentPhase.ACTIVE:
                raise EnrollmentJournalError("enrollment cancel intent is out of order")
            evidence = _exact(
                evidence, {"connection_generation", "reason"}, milestone
            )
            _same_generation(evidence, baseline)
            if evidence["reason"] != "caller-requested":
                raise EnrollmentJournalError("unsupported enrollment cancel reason")
            phase = EnrollmentPhase.CANCEL_INTENT
            continue

        if milestone == "ENROLL_CANCEL_DISPATCH_OBSERVED":
            if phase is not EnrollmentPhase.CANCEL_INTENT:
                raise EnrollmentJournalError("cancel dispatch observation is out of order")
            evidence = _exact(evidence, {"status"}, milestone)
            if _status(evidence["status"], "cancel status") != 0:
                raise EnrollmentJournalError("accepted cancel dispatch status is not zero")
            phase = EnrollmentPhase.CANCEL_REQUESTED
            continue

        if milestone == "E2_TERMINAL_IDENTITY_OBSERVED":
            if phase not in (EnrollmentPhase.ACTIVE, EnrollmentPhase.CANCEL_REQUESTED):
                raise EnrollmentJournalError("terminal identity is out of order")
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "event_sequence",
                    "envelope_type",
                    "event_version",
                    "user_id",
                    "identity_uuid",
                },
                milestone,
            )
            _same_generation(evidence, baseline)
            sequence = _uint(evidence["event_sequence"], "event sequence")
            if last_event is not None and sequence <= last_event:
                raise EnrollmentJournalError("terminal event sequence is not increasing")
            if (
                evidence["envelope_type"] != SERVICE_ENROLLMENT_RESULT
                or evidence["event_version"] not in (1, 2)
                or evidence["user_id"] != baseline["apple_uid"]
            ):
                raise EnrollmentJournalError("terminal identity framing is invalid")
            _uuid(evidence["identity_uuid"], "identity_uuid")
            last_event = sequence
            phase = EnrollmentPhase.TERMINAL_IDENTITY
            continue

        if milestone == "ENROLL_TERMINAL_FAILURE_OBSERVED":
            if phase not in (EnrollmentPhase.ACTIVE, EnrollmentPhase.CANCEL_REQUESTED):
                raise EnrollmentJournalError("terminal failure is out of order")
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "event_sequence",
                    "envelope_type",
                    "status",
                },
                milestone,
            )
            _same_generation(evidence, baseline)
            sequence = _uint(evidence["event_sequence"], "event sequence")
            if last_event is not None and sequence <= last_event:
                raise EnrollmentJournalError("terminal event sequence is not increasing")
            if (
                evidence["envelope_type"] != SERVICE_STATUS
                or evidence["status"] not in (66, 67, 68)
            ):
                raise EnrollmentJournalError("terminal failure status is invalid")
            last_event = sequence
            phase = EnrollmentPhase.TERMINAL_FAILURE
            continue

        if milestone == "ENROLL_OUTCOME_UNKNOWN":
            if phase not in (
                EnrollmentPhase.START_INTENT,
                EnrollmentPhase.ACTIVE,
                EnrollmentPhase.CONTINUE_INTENT,
                EnrollmentPhase.CANCEL_INTENT,
                EnrollmentPhase.CANCEL_REQUESTED,
            ):
                raise EnrollmentJournalError("outcome-unknown marker is out of order")
            evidence = _exact(
                evidence,
                {"connection_generation", "stage", "reason", "mutation_possible"},
                milestone,
            )
            _same_generation(evidence, baseline)
            if evidence["stage"] not in {
                "start",
                "active",
                "continue",
                "cancel",
                "terminal",
            }:
                raise EnrollmentJournalError("outcome-unknown stage is invalid")
            if (
                not isinstance(evidence["reason"], str)
                or evidence["reason"] not in {
                    "transport-error",
                    "connection-lost",
                    "journal-error",
                    "protocol-error",
                }
                or evidence["mutation_possible"] is not True
            ):
                raise EnrollmentJournalError("outcome-unknown evidence is invalid")
            phase = EnrollmentPhase.OUTCOME_UNKNOWN
            continue

        raise EnrollmentJournalError(f"unsupported enrollment milestone {milestone!r}")

    head_hash = records[-1].get("record_hash")
    _sha256(head_hash, "journal head hash")
    return EnrollmentHistory(
        operation_id,
        phase,
        baseline,
        last_event,
        pending_event,
        len(records),
        head_hash,
    )


def read(path: Path) -> EnrollmentHistory:
    return validate_history(journal.read(path))


def require_start_ready(
    history: EnrollmentHistory,
    *,
    linux_boot_uuid: str,
    connection_generation: str,
    mapping_generation: str,
    caller_linux_uid: int,
    target_linux_uid: int,
    protocol_version: int,
) -> None:
    """Bind an E0 baseline to the exact live operation lease before E1."""
    if history.phase is not EnrollmentPhase.BASELINE:
        raise EnrollmentJournalError("journal is not at the E0 baseline")
    baseline = history.baseline
    if baseline["linux_boot_uuid"] != linux_boot_uuid:
        raise EnrollmentJournalError("baseline belongs to another Linux boot")
    if baseline["connection_generation"] != connection_generation:
        raise EnrollmentJournalError(
            "baseline was not collected on the enrollment connection"
        )
    if baseline["mapping_generation"] != mapping_generation:
        raise EnrollmentJournalError("protected mapping changed after baseline")
    if (
        baseline["caller_linux_uid"] != caller_linux_uid
        or baseline["target_linux_uid"] != target_linux_uid
    ):
        raise EnrollmentJournalError("Linux caller or target differs from baseline")
    if baseline["protocol_version"] != protocol_version or protocol_version not in (1, 2):
        raise EnrollmentJournalError("biometric protocol differs from baseline")
    capacity = baseline["capacity"]
    if capacity["used"] >= capacity["maximum"]:
        raise EnrollmentJournalError("enrollment capacity is exhausted")


def append_checked(
    path: Path, operation_id: str, milestone: str, evidence: dict[str, Any]
) -> EnrollmentHistory:
    records = journal.read(path)
    current = validate_history(records)
    if operation_id != current.operation_id:
        raise EnrollmentJournalError("operation ID does not match enrollment journal")
    candidate = {
        "operation_id": operation_id,
        "milestone": milestone,
        "evidence": evidence,
        "record_hash": "0" * 64,
    }
    validate_history([*records, candidate])
    journal.append(
        path,
        operation_id,
        milestone,
        evidence,
        expected_record_count=current.record_count,
        expected_previous_hash=current.head_hash,
    )
    return read(path)
