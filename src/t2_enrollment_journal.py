# SPDX-License-Identifier: GPL-2.0-only
"""Typed transition rules above the generic durable mutation journal."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import t2_mutation_journal as journal
import t2_enrollment_persistence_journal as persistence_journal


SERVICE_STATUS = 0xE3FF8001
SERVICE_ENROLLMENT_RESULT = 0xE3FF8003


class EnrollmentJournalError(journal.JournalError):
    pass


class EnrollmentPhase(Enum):
    BASELINE = "baseline-reconciled"
    ABORTED_BEFORE_START = "aborted-before-start"
    START_INTENT = "start-intent"
    ACTIVE = "active"
    CONTINUE_INTENT = "continue-intent"
    CANCEL_INTENT = "cancel-intent"
    CANCEL_REQUESTED = "cancel-requested"
    TERMINAL_WITNESS = "terminal-result-witness"
    TERMINAL_IDENTITY = "terminal-identity"
    TERMINAL_FAILURE = "terminal-failure"
    PERSISTING = "persisting"
    PERSISTENCE_READY = "persistence-ready"
    RECONCILED = "reconciled"
    POST_REBOOT_VERIFIED = "post-reboot-verified"
    OUTCOME_UNKNOWN = "outcome-unknown"


@dataclass(frozen=True, repr=False)
class EnrollmentHistory:
    operation_id: str
    phase: EnrollmentPhase
    baseline: dict[str, Any]
    last_event_sequence: int | None
    pending_event_sequence: int | None
    record_count: int
    head_hash: str
    terminal_identity_uuid: str | None
    terminal_status: int | None
    persistence: persistence_journal.PersistenceHistory
    reconciled_snapshot_sha256: str | None
    post_reboot_linux_boot_uuid: str | None
    outcome_unknown_stage: str | None
    persistence_connection_generation: str


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
    if baseline["password_fallback_verified"] is not True:
        raise EnrollmentJournalError(
            "enrollment password fallback is not verified"
        )
    operation_id = first.get("operation_id")
    _uuid(operation_id, "operation_id")
    phase = EnrollmentPhase.BASELINE
    last_event: int | None = None
    pending_event: int | None = None
    terminal_identity_uuid: str | None = None
    terminal_status: int | None = None
    persistence = persistence_journal.PersistenceTracker(baseline)
    reconciled_snapshot_sha256: str | None = None
    post_reboot_linux_boot_uuid: str | None = None
    outcome_unknown_stage: str | None = None
    persistence_connection_generation = baseline["connection_generation"]

    for record in records[1:]:
        if record.get("operation_id") != operation_id:
            raise EnrollmentJournalError("operation ID changed inside enrollment journal")
        milestone = record.get("milestone")
        evidence = record.get("evidence")

        if milestone == "ENROLL_ABORTED_BEFORE_START":
            if phase is not EnrollmentPhase.BASELINE:
                raise EnrollmentJournalError(
                    "pre-dispatch enrollment abort is out of order"
                )
            evidence = _exact(
                evidence,
                {"connection_generation", "reason", "mutation_possible"},
                milestone,
            )
            _same_generation(evidence, baseline)
            if (
                evidence["reason"] != "safety-guard-unavailable"
                or evidence["mutation_possible"] is not False
            ):
                raise EnrollmentJournalError(
                    "pre-dispatch enrollment abort evidence is invalid"
                )
            phase = EnrollmentPhase.ABORTED_BEFORE_START
            continue

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
            terminal_status = evidence["status"]
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
            if isinstance(evidence, dict) and set(evidence) == {
                "event_sequence",
                "status",
            }:
                # Compatibility with journals written before exact 24G830
                # return-value handling was recovered.
                legacy = True
            else:
                evidence = _exact(
                    evidence,
                    {
                        "event_sequence",
                        "status",
                        "return_status_authoritative",
                    },
                    milestone,
                )
                legacy = False
            sequence = _uint(evidence["event_sequence"], "event sequence")
            status = _status(evidence["status"], "continue status")
            if sequence != pending_event:
                raise EnrollmentJournalError("continue observation disagrees with its intent")
            if legacy:
                if status != 0:
                    raise EnrollmentJournalError(
                        "legacy continue observation has nonzero status"
                    )
            elif evidence["return_status_authoritative"] is not False:
                raise EnrollmentJournalError(
                    "continue return status was incorrectly treated as authoritative"
                )
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
            terminal_identity_uuid = evidence["identity_uuid"]
            last_event = sequence
            phase = EnrollmentPhase.TERMINAL_IDENTITY
            continue

        if milestone == "E2_TERMINAL_RESULT_WITNESSED":
            if phase not in (EnrollmentPhase.ACTIVE, EnrollmentPhase.CANCEL_REQUESTED):
                raise EnrollmentJournalError("terminal result witness is out of order")
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "event_sequence",
                    "envelope_type",
                    "event_version",
                    "payload_length",
                    "event_sha256",
                    "embedded_user_matches",
                },
                milestone,
            )
            _same_generation(evidence, baseline)
            sequence = _uint(evidence["event_sequence"], "event sequence")
            if last_event is not None and sequence <= last_event:
                raise EnrollmentJournalError("terminal event sequence is not increasing")
            version = _uint(evidence["event_version"], "event version", 2)
            payload_length = _uint(
                evidence["payload_length"], "payload length", 1024 * 1024
            )
            length_valid = (
                payload_length == 20
                if version == 1
                else version == 2 and payload_length >= 40
            )
            if (
                evidence["envelope_type"] != SERVICE_ENROLLMENT_RESULT
                or version not in (1, 2)
                or not length_valid
                or evidence["embedded_user_matches"] is not False
            ):
                raise EnrollmentJournalError("terminal result witness framing is invalid")
            _sha256(evidence["event_sha256"], "event_sha256")
            last_event = sequence
            phase = EnrollmentPhase.TERMINAL_WITNESS
            continue

        if milestone == "E2_WITNESS_IDENTITY_READBACK_OBSERVED":
            if phase is not EnrollmentPhase.TERMINAL_WITNESS:
                raise EnrollmentJournalError("witness identity read-back is out of order")
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "user_id",
                    "identity_uuid",
                    "source",
                    "single_identity_added",
                    "host_unchanged",
                    "sep_catacomb_advanced",
                    "per_user_global_equal",
                    "mapping_generation",
                },
                milestone,
            )
            _same_generation(evidence, baseline)
            _uuid(evidence["identity_uuid"], "identity_uuid")
            _sha256(evidence["mapping_generation"], "mapping_generation")
            if (
                evidence["user_id"] != baseline["apple_uid"]
                or evidence["source"] != "stable-readback"
                or evidence["mapping_generation"] != baseline["mapping_generation"]
            ):
                raise EnrollmentJournalError("witness identity read-back binding is invalid")
            for field in (
                "single_identity_added",
                "host_unchanged",
                "sep_catacomb_advanced",
                "per_user_global_equal",
            ):
                if evidence[field] is not True:
                    raise EnrollmentJournalError(
                        f"witness identity read-back field {field} is not true"
                    )
            terminal_identity_uuid = evidence["identity_uuid"]
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
            terminal_status = evidence["status"]
            phase = EnrollmentPhase.TERMINAL_FAILURE
            continue

        if milestone == "E2_IDENTITY_READBACK_OBSERVED":
            if phase is not EnrollmentPhase.TERMINAL_FAILURE:
                raise EnrollmentJournalError(
                    "post-failure identity read-back is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "user_id",
                    "identity_uuid",
                    "source",
                },
                milestone,
            )
            _same_generation(evidence, baseline)
            if (
                evidence["user_id"] != baseline["apple_uid"]
                or evidence["source"] != "stable-readback"
            ):
                raise EnrollmentJournalError(
                    "post-failure identity read-back is invalid"
                )
            _uuid(evidence["identity_uuid"], "identity_uuid")
            terminal_identity_uuid = evidence["identity_uuid"]
            phase = EnrollmentPhase.TERMINAL_IDENTITY
            continue

        if milestone == "E2_RECOVERY_IDENTITY_READBACK_OBSERVED":
            if (
                phase is not EnrollmentPhase.OUTCOME_UNKNOWN
                or outcome_unknown_stage != "terminal"
            ):
                raise EnrollmentJournalError(
                    "terminal identity recovery is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "user_id",
                    "identity_uuid",
                    "source",
                    "single_identity_added",
                    "host_unchanged",
                    "sep_catacomb_advanced",
                    "per_user_global_equal",
                    "mapping_generation",
                },
                milestone,
            )
            _uuid(
                evidence["connection_generation"],
                "recovery connection generation",
            )
            _uuid(evidence["identity_uuid"], "identity_uuid")
            _sha256(evidence["mapping_generation"], "mapping_generation")
            if (
                evidence["connection_generation"]
                == baseline["connection_generation"]
                or evidence["user_id"] != baseline["apple_uid"]
                or evidence["source"] != "stable-readback"
                or evidence["mapping_generation"]
                != baseline["mapping_generation"]
            ):
                raise EnrollmentJournalError(
                    "terminal identity recovery binding is invalid"
                )
            for field in (
                "single_identity_added",
                "host_unchanged",
                "sep_catacomb_advanced",
                "per_user_global_equal",
            ):
                if evidence[field] is not True:
                    raise EnrollmentJournalError(
                        f"terminal identity recovery field {field} is not true"
                    )
            terminal_identity_uuid = evidence["identity_uuid"]
            persistence_connection_generation = evidence[
                "connection_generation"
            ]
            persistence.use_recovery_generation(
                persistence_connection_generation
            )
            phase = EnrollmentPhase.TERMINAL_IDENTITY
            continue

        if isinstance(milestone, str) and milestone.startswith("CATACOMB_"):
            identity_persistence = terminal_identity_uuid is not None
            failure_biolockout_persistence = (
                terminal_identity_uuid is None and terminal_status is not None
            )
            early_confirm_recovery = (
                milestone == "CATACOMB_EARLY_CONFIRM_RECOVERED"
                and phase is EnrollmentPhase.OUTCOME_UNKNOWN
                and identity_persistence
            )
            if (
                not identity_persistence
                and not failure_biolockout_persistence
            ) or (
                not early_confirm_recovery
                and phase not in (
                    EnrollmentPhase.TERMINAL_IDENTITY,
                    EnrollmentPhase.TERMINAL_FAILURE,
                    EnrollmentPhase.PERSISTING,
                )
            ):
                raise EnrollmentJournalError(
                    "Catacomb persistence has no terminal identity or failure"
                )
            try:
                persistence.consume(
                    milestone,
                    evidence,
                    allow_biolockout_only=failure_biolockout_persistence,
                )
            except persistence_journal.PersistenceJournalError as error:
                raise EnrollmentJournalError(str(error)) from error
            if early_confirm_recovery:
                persistence_connection_generation = evidence[
                    "connection_generation"
                ]
            phase = (
                EnrollmentPhase.PERSISTENCE_READY
                if persistence.phase is persistence_journal.PersistencePhase.COMPLETE
                else (
                    EnrollmentPhase.OUTCOME_UNKNOWN
                    if persistence.phase
                    is persistence_journal.PersistencePhase.OUTCOME_UNKNOWN
                    else (
                        EnrollmentPhase.TERMINAL_IDENTITY
                        if early_confirm_recovery
                        else EnrollmentPhase.PERSISTING
                    )
                )
            )
            continue

        if milestone == "E3_RECONCILED":
            if phase not in (
                EnrollmentPhase.PERSISTENCE_READY,
                EnrollmentPhase.TERMINAL_FAILURE,
            ):
                raise EnrollmentJournalError("E3 reconciliation is out of order")
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "snapshot_sha256",
                    "identity_uuid",
                    "identity_present",
                    "host_sep_identity_equal",
                    "catacomb_reconciled",
                    "bindings_preserved",
                    "mapping_generation",
                    "capacity_used",
                    "capacity_maximum",
                    "master_enrollment_count",
                },
                milestone,
            )
            if (
                evidence["connection_generation"]
                != persistence_connection_generation
            ):
                raise EnrollmentJournalError(
                    "E3 used another persistence connection generation"
                )
            _sha256(evidence["snapshot_sha256"], "snapshot_sha256")
            _sha256(evidence["mapping_generation"], "mapping_generation")
            if evidence["mapping_generation"] != baseline["mapping_generation"]:
                raise EnrollmentJournalError("mapping changed before E3")
            for field in (
                "host_sep_identity_equal",
                "catacomb_reconciled",
                "bindings_preserved",
            ):
                if evidence[field] is not True:
                    raise EnrollmentJournalError(f"E3 field {field} is not true")
            used = _uint(evidence["capacity_used"], "capacity used", 0xFFFFFFFF)
            maximum = _uint(
                evidence["capacity_maximum"], "capacity maximum", 0xFFFFFFFF
            )
            _uint(
                evidence["master_enrollment_count"],
                "master enrollment count",
                0xFFFFFFFF,
            )
            if used > maximum or maximum != baseline["capacity"]["maximum"]:
                raise EnrollmentJournalError("E3 capacity is inconsistent")
            if (
                phase is EnrollmentPhase.PERSISTENCE_READY
                and terminal_identity_uuid is not None
            ):
                _uuid(evidence["identity_uuid"], "identity_uuid")
                if (
                    evidence["identity_uuid"] != terminal_identity_uuid
                    or evidence["identity_present"] is not True
                    or used != baseline["capacity"]["used"] + 1
                ):
                    raise EnrollmentJournalError(
                        "E3 identity or capacity does not match E2"
                    )
            else:
                if (
                    evidence["identity_uuid"] is not None
                    or evidence["identity_present"] is not False
                    or used != baseline["capacity"]["used"]
                ):
                    raise EnrollmentJournalError(
                        "failure reconciliation observed an unexpected identity"
                    )
            reconciled_snapshot_sha256 = evidence["snapshot_sha256"]
            phase = EnrollmentPhase.RECONCILED
            continue

        if milestone in {
            "E3_RECOVERY_NO_CHANGE_RECONCILED",
            "E3_PERSISTENCE_READBACK_RECOVERED",
        }:
            if phase is not EnrollmentPhase.OUTCOME_UNKNOWN:
                raise EnrollmentJournalError(
                    "outcome-unknown recovery reconciliation is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "snapshot_sha256",
                    "identity_uuid",
                    "identity_present",
                    "host_sep_identity_equal",
                    "catacomb_reconciled",
                    "bindings_preserved",
                    "mapping_generation",
                    "capacity_used",
                    "capacity_maximum",
                    "master_enrollment_count",
                },
                milestone,
            )
            _uuid(
                evidence["connection_generation"],
                "recovery connection generation",
            )
            if evidence["connection_generation"] == baseline["connection_generation"]:
                raise EnrollmentJournalError(
                    "outcome-unknown recovery did not use a fresh Bridge generation"
                )
            _sha256(evidence["snapshot_sha256"], "snapshot_sha256")
            _sha256(evidence["mapping_generation"], "mapping_generation")
            if evidence["mapping_generation"] != baseline["mapping_generation"]:
                raise EnrollmentJournalError(
                    "mapping changed before recovery reconciliation"
                )
            for field in (
                "host_sep_identity_equal",
                "catacomb_reconciled",
                "bindings_preserved",
            ):
                if evidence[field] is not True:
                    raise EnrollmentJournalError(
                        f"recovery reconciliation field {field} is not true"
                    )
            used = _uint(evidence["capacity_used"], "capacity used", 0xFFFFFFFF)
            maximum = _uint(
                evidence["capacity_maximum"], "capacity maximum", 0xFFFFFFFF
            )
            _uint(
                evidence["master_enrollment_count"],
                "master enrollment count",
                0xFFFFFFFF,
            )
            if milestone == "E3_PERSISTENCE_READBACK_RECOVERED":
                if (
                    persistence.phase
                    is not persistence_journal.PersistencePhase.OUTCOME_UNKNOWN
                    or persistence._outcome_unknown_stage != "readback"
                    or persistence._outcome_unknown_host_commit_possible is not True
                    or terminal_identity_uuid is None
                    or evidence["identity_uuid"] != terminal_identity_uuid
                    or evidence["identity_present"] is not True
                    or used
                    != (
                        baseline["capacity"]["used"]
                        if baseline["sep_catacomb"]["present"] is False
                        else baseline["capacity"]["used"] + 1
                    )
                    or maximum != baseline["capacity"]["maximum"]
                ):
                    raise EnrollmentJournalError(
                        "persistence readback recovery evidence is inconsistent"
                    )
            elif (
                evidence["identity_uuid"] is not None
                or evidence["identity_present"] is not False
                or used != baseline["capacity"]["used"]
                or maximum != baseline["capacity"]["maximum"]
            ):
                raise EnrollmentJournalError(
                    "outcome-unknown recovery observed a persistent identity delta"
                )
            reconciled_snapshot_sha256 = evidence["snapshot_sha256"]
            phase = EnrollmentPhase.RECONCILED
            continue

        if milestone == "E4_POST_REBOOT_VERIFIED":
            if (
                phase is not EnrollmentPhase.RECONCILED
                or terminal_identity_uuid is None
            ):
                raise EnrollmentJournalError("E4 verification is out of order")
            evidence = _exact(
                evidence,
                {
                    "linux_boot_uuid",
                    "connection_generation",
                    "bridge_boot_uuid",
                    "protocol_version",
                    "mapping_generation",
                    "account_uuid",
                    "bag_uuid",
                    "identity_uuid",
                    "snapshot_sha256",
                    "double_collection_equal",
                    "host_sep_identity_equal",
                    "bindings_preserved",
                    "keybag_runtime_revalidated",
                },
                milestone,
            )
            for field in (
                "linux_boot_uuid",
                "connection_generation",
                "account_uuid",
                "bag_uuid",
                "identity_uuid",
            ):
                _uuid(evidence[field], field)
            if evidence["bridge_boot_uuid"] is not None:
                _uuid(evidence["bridge_boot_uuid"], "bridge_boot_uuid")
            _sha256(evidence["mapping_generation"], "mapping_generation")
            _sha256(evidence["snapshot_sha256"], "snapshot_sha256")
            if (
                evidence["linux_boot_uuid"] == baseline["linux_boot_uuid"]
                or evidence["connection_generation"]
                == baseline["connection_generation"]
            ):
                raise EnrollmentJournalError(
                    "E4 did not cross a boot and connection boundary"
                )
            if (
                evidence["protocol_version"] != baseline["protocol_version"]
                or evidence["mapping_generation"] != baseline["mapping_generation"]
                or evidence["account_uuid"] != baseline["account_uuid"]
                or evidence["bag_uuid"] != baseline["bag_uuid"]
                or evidence["identity_uuid"] != terminal_identity_uuid
                or evidence["snapshot_sha256"] != reconciled_snapshot_sha256
            ):
                raise EnrollmentJournalError("E4 state differs from reconciled E3")
            for field in (
                "double_collection_equal",
                "host_sep_identity_equal",
                "bindings_preserved",
                "keybag_runtime_revalidated",
            ):
                if evidence[field] is not True:
                    raise EnrollmentJournalError(f"E4 field {field} is not true")
            post_reboot_linux_boot_uuid = evidence["linux_boot_uuid"]
            phase = EnrollmentPhase.POST_REBOOT_VERIFIED
            continue

        if milestone == "ENROLL_OUTCOME_UNKNOWN":
            if phase not in (
                EnrollmentPhase.START_INTENT,
                EnrollmentPhase.ACTIVE,
                EnrollmentPhase.CONTINUE_INTENT,
                EnrollmentPhase.CANCEL_INTENT,
                EnrollmentPhase.CANCEL_REQUESTED,
                EnrollmentPhase.TERMINAL_WITNESS,
                EnrollmentPhase.PERSISTING,
            ):
                raise EnrollmentJournalError("outcome-unknown marker is out of order")
            evidence = _exact(
                evidence,
                {"connection_generation", "stage", "reason", "mutation_possible"},
                milestone,
            )
            _same_generation(evidence, baseline)
            persistence_interruption = phase is EnrollmentPhase.PERSISTING
            stage_options = (
                {
                    "local-prepare-discarded",
                    "local-commit-rolled-forward",
                }
                if persistence_interruption
                else {"start", "active", "continue", "cancel", "terminal"}
            )
            reason_options = (
                {"process-interrupted"}
                if persistence_interruption
                else {
                    "transport-error",
                    "connection-lost",
                    "journal-error",
                    "protocol-error",
                }
            )
            stage_valid = (
                isinstance(evidence["stage"], str)
                and evidence["stage"] in stage_options
            )
            reason_valid = (
                isinstance(evidence["reason"], str)
                and evidence["reason"] in reason_options
            )
            if (
                not stage_valid
                or not reason_valid
                or evidence["mutation_possible"] is not True
            ):
                raise EnrollmentJournalError("outcome-unknown evidence is invalid")
            outcome_unknown_stage = evidence["stage"]
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
        terminal_identity_uuid,
        terminal_status,
        persistence.snapshot(),
        reconciled_snapshot_sha256,
        post_reboot_linux_boot_uuid,
        outcome_unknown_stage,
        persistence_connection_generation,
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
