# SPDX-License-Identifier: GPL-2.0-only
"""Typed journal state machine for one SEP-first identity deletion."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import t2_enrollment_persistence_journal as persistence_journal
import t2_mutation_journal as journal


class IdentityDeleteJournalError(journal.JournalError):
    pass


class IdentityDeletePhase(Enum):
    BASELINE = "baseline-reconciled"
    INTENT = "delete-intent"
    DISPATCH_INTENT = "delete-dispatch-intent"
    COMMAND_OBSERVED = "delete-command-observed"
    SEP_DELETED = "sep-deletion-observed"
    ABORTED = "aborted-not-deleted"
    PERSISTING = "persisting"
    PERSISTENCE_READY = "persistence-ready"
    RECONCILED = "reconciled"
    POST_REBOOT_VERIFIED = "post-reboot-verified"
    OUTCOME_UNKNOWN = "outcome-unknown"


@dataclass(frozen=True, repr=False)
class IdentityDeleteHistory:
    operation_id: str
    phase: IdentityDeletePhase
    baseline: dict[str, Any]
    target_identity_uuid: str | None
    target_entity: int | None
    target_name_sha256: str | None
    request_sha256: str | None
    survivor_snapshot_sha256: str | None
    command_status: int | None
    persistence: persistence_journal.PersistenceHistory
    reconciled_snapshot_sha256: str | None
    outcome_unknown_stage: str | None
    record_count: int
    head_hash: str


def _exact(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IdentityDeleteJournalError(f"{field} evidence does not match its schema")
    return value


def _sha256(value: Any, field: str) -> None:
    try:
        journal.require_sha256(value, field)
    except journal.JournalError as error:
        raise IdentityDeleteJournalError(str(error)) from error


def _uuid(value: Any, field: str) -> None:
    try:
        journal.require_uuid(value, field)
    except journal.JournalError as error:
        raise IdentityDeleteJournalError(str(error)) from error


def validate_history(records: list[dict[str, Any]]) -> IdentityDeleteHistory:
    if not records:
        raise IdentityDeleteJournalError("delete journal is empty")
    first = records[0]
    if first.get("milestone") != "BASELINE_RECONCILED":
        raise IdentityDeleteJournalError("delete journal has no baseline")
    initial = _exact(
        first.get("evidence"), {"operation_kind", "baseline"}, "baseline"
    )
    if initial["operation_kind"] != "delete-one":
        raise IdentityDeleteJournalError("journal is not a single identity deletion")
    baseline = initial["baseline"]
    try:
        journal.validate_baseline(baseline)
    except journal.JournalError as error:
        raise IdentityDeleteJournalError(str(error)) from error
    operation_id = first.get("operation_id")
    _uuid(operation_id, "operation ID")
    phase = IdentityDeletePhase.BASELINE
    target_uuid = None
    target_entity = None
    target_name_hash = None
    request_hash = None
    survivor_hash = None
    command_status = None
    reconciled_hash = None
    outcome_stage = None
    persistence = persistence_journal.PersistenceTracker(
        baseline, plan_kind="identity-metadata"
    )

    for record in records[1:]:
        if record.get("operation_id") != operation_id:
            raise IdentityDeleteJournalError("operation ID changed inside delete journal")
        milestone = record.get("milestone")
        evidence = record.get("evidence")

        if milestone == "DELETE_INTENT":
            if phase is not IdentityDeletePhase.BASELINE:
                raise IdentityDeleteJournalError("delete intent is out of order")
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "user_id",
                    "identity_uuid",
                    "entity",
                    "target_name_sha256",
                    "request_sha256",
                    "request_length",
                    "survivor_snapshot_sha256",
                    "survivor_count",
                    "mapping_generation",
                },
                milestone,
            )
            _uuid(evidence["identity_uuid"], "identity UUID")
            for field in (
                "target_name_sha256",
                "request_sha256",
                "survivor_snapshot_sha256",
                "mapping_generation",
            ):
                _sha256(evidence[field], field)
            matches = [
                identity
                for identity in baseline["identity_records"]
                if identity["uuid"] == evidence["identity_uuid"]
                and identity["entity"] == evidence["entity"]
            ]
            if (
                len(baseline["identity_records"]) <= 1
                or len(matches) != 1
                or evidence["connection_generation"]
                != baseline["connection_generation"]
                or evidence["user_id"] != baseline["apple_uid"]
                or evidence["request_length"] != 20
                or evidence["survivor_count"]
                != len(baseline["identity_records"]) - 1
                or evidence["mapping_generation"] != baseline["mapping_generation"]
            ):
                raise IdentityDeleteJournalError("delete intent binding is invalid")
            target_uuid = evidence["identity_uuid"]
            target_entity = evidence["entity"]
            target_name_hash = evidence["target_name_sha256"]
            request_hash = evidence["request_sha256"]
            survivor_hash = evidence["survivor_snapshot_sha256"]
            phase = IdentityDeletePhase.INTENT
            continue

        if milestone == "DELETE_DISPATCH_INTENT":
            if phase is not IdentityDeletePhase.INTENT:
                raise IdentityDeleteJournalError("delete dispatch intent is out of order")
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "identity_uuid",
                    "request_sha256",
                    "command",
                    "protocol_version",
                },
                milestone,
            )
            if (
                evidence["connection_generation"]
                != baseline["connection_generation"]
                or evidence["identity_uuid"] != target_uuid
                or evidence["request_sha256"] != request_hash
                or evidence["command"] != 0x0D
                or evidence["protocol_version"] != 0
            ):
                raise IdentityDeleteJournalError("delete dispatch binding is invalid")
            phase = IdentityDeletePhase.DISPATCH_INTENT
            continue

        if milestone == "DELETE_COMMAND_OBSERVED":
            if phase is not IdentityDeletePhase.DISPATCH_INTENT:
                raise IdentityDeleteJournalError("delete command result is out of order")
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "identity_uuid",
                    "status",
                    "output_length",
                    "service_event_count",
                },
                milestone,
            )
            status = evidence["status"]
            if (
                evidence["connection_generation"]
                != baseline["connection_generation"]
                or evidence["identity_uuid"] != target_uuid
                or type(status) is not int
                or not -(2**31) <= status < 2**32
                or evidence["output_length"] != 0
                or evidence["service_event_count"] != 0
            ):
                raise IdentityDeleteJournalError("delete command result is invalid")
            command_status = status
            phase = IdentityDeletePhase.COMMAND_OBSERVED
            continue

        if milestone == "DELETE_SEP_ABSENCE_OBSERVED":
            if phase is not IdentityDeletePhase.COMMAND_OBSERVED:
                raise IdentityDeleteJournalError("SEP deletion evidence is out of order")
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "identity_uuid",
                    "survivor_snapshot_sha256",
                    "survivor_count",
                    "stable_double_read",
                    "per_user_global_equal",
                    "target_absent",
                },
                milestone,
            )
            _sha256(evidence["survivor_snapshot_sha256"], "survivor snapshot")
            if (
                evidence["connection_generation"]
                != baseline["connection_generation"]
                or evidence["identity_uuid"] != target_uuid
                or evidence["survivor_snapshot_sha256"] != survivor_hash
                or evidence["survivor_count"]
                != len(baseline["identity_records"]) - 1
                or evidence["stable_double_read"] is not True
                or evidence["per_user_global_equal"] is not True
                or evidence["target_absent"] is not True
            ):
                raise IdentityDeleteJournalError("SEP deletion evidence is invalid")
            phase = IdentityDeletePhase.SEP_DELETED
            continue

        if milestone == "DELETE_NOT_PERFORMED":
            if phase is not IdentityDeletePhase.COMMAND_OBSERVED:
                raise IdentityDeleteJournalError("delete abort evidence is out of order")
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "identity_uuid",
                    "command_failed",
                    "target_present",
                    "baseline_identity_set_equal",
                    "sep_catacomb_unchanged",
                    "stable_double_read",
                },
                milestone,
            )
            if (
                command_status == 0
                or evidence["connection_generation"]
                != baseline["connection_generation"]
                or evidence["identity_uuid"] != target_uuid
                or any(
                    evidence[field] is not True
                    for field in (
                        "command_failed",
                        "target_present",
                        "baseline_identity_set_equal",
                        "sep_catacomb_unchanged",
                        "stable_double_read",
                    )
                )
            ):
                raise IdentityDeleteJournalError("delete abort evidence is invalid")
            phase = IdentityDeletePhase.ABORTED
            continue

        if milestone == "DELETE_OUTCOME_UNKNOWN":
            if phase not in {
                IdentityDeletePhase.DISPATCH_INTENT,
                IdentityDeletePhase.COMMAND_OBSERVED,
                IdentityDeletePhase.SEP_DELETED,
                IdentityDeletePhase.PERSISTING,
                IdentityDeletePhase.PERSISTENCE_READY,
            }:
                raise IdentityDeleteJournalError("delete ambiguity is out of order")
            evidence = _exact(
                evidence,
                {"connection_generation", "stage", "reason", "mutation_possible"},
                milestone,
            )
            if (
                evidence["connection_generation"]
                != baseline["connection_generation"]
                or evidence["stage"]
                not in {"dispatch", "readback", "persistence", "reconciliation"}
                or evidence["reason"]
                not in {
                    "transport-error",
                    "protocol-error",
                    "inventory-error",
                    "host-store-error",
                    "readback-error",
                    "process-interrupted",
                }
                or evidence["mutation_possible"] is not True
            ):
                raise IdentityDeleteJournalError("delete ambiguity evidence is invalid")
            outcome_stage = evidence["stage"]
            phase = IdentityDeletePhase.OUTCOME_UNKNOWN
            continue

        if isinstance(milestone, str) and milestone.startswith("CATACOMB_"):
            if phase not in {IdentityDeletePhase.SEP_DELETED, IdentityDeletePhase.PERSISTING}:
                raise IdentityDeleteJournalError("delete persistence is out of order")
            try:
                persistence.consume(milestone, evidence)
            except persistence_journal.PersistenceJournalError as error:
                raise IdentityDeleteJournalError(str(error)) from error
            if persistence.phase is persistence_journal.PersistencePhase.COMPLETE:
                phase = IdentityDeletePhase.PERSISTENCE_READY
            elif persistence.phase is persistence_journal.PersistencePhase.OUTCOME_UNKNOWN:
                phase = IdentityDeletePhase.OUTCOME_UNKNOWN
                outcome_stage = persistence.snapshot().outcome_unknown_stage
            else:
                phase = IdentityDeletePhase.PERSISTING
            continue

        if milestone == "DELETE_RECONCILED":
            if phase is not IdentityDeletePhase.PERSISTENCE_READY:
                raise IdentityDeleteJournalError("delete reconciliation is out of order")
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "identity_uuid",
                    "survivor_snapshot_sha256",
                    "snapshot_sha256",
                    "mapping_generation",
                    "identity_count",
                    "target_absent",
                    "local_live_equal",
                    "host_reconciled",
                    "sep_clean",
                },
                milestone,
            )
            _uuid(evidence["identity_uuid"], "identity UUID")
            for field in (
                "survivor_snapshot_sha256",
                "snapshot_sha256",
                "mapping_generation",
            ):
                _sha256(evidence[field], field)
            if (
                evidence["connection_generation"]
                != baseline["connection_generation"]
                or evidence["identity_uuid"] != target_uuid
                or evidence["survivor_snapshot_sha256"] != survivor_hash
                or evidence["mapping_generation"] != baseline["mapping_generation"]
                or evidence["identity_count"]
                != len(baseline["identity_records"]) - 1
                or any(
                    evidence[field] is not True
                    for field in (
                        "target_absent",
                        "local_live_equal",
                        "host_reconciled",
                        "sep_clean",
                    )
                )
            ):
                raise IdentityDeleteJournalError("delete reconciliation is invalid")
            reconciled_hash = evidence["snapshot_sha256"]
            phase = IdentityDeletePhase.RECONCILED
            continue

        if milestone == "DELETE_POST_REBOOT_VERIFIED":
            if phase is not IdentityDeletePhase.RECONCILED:
                raise IdentityDeleteJournalError("delete post-reboot proof is out of order")
            evidence = _exact(
                evidence,
                {
                    "linux_boot_uuid",
                    "connection_generation",
                    "identity_uuid",
                    "survivor_snapshot_sha256",
                    "snapshot_sha256",
                    "mapping_generation",
                    "target_absent",
                    "local_live_equal",
                    "sep_clean",
                },
                milestone,
            )
            for field in ("linux_boot_uuid", "connection_generation", "identity_uuid"):
                _uuid(evidence[field], field)
            for field in (
                "survivor_snapshot_sha256",
                "snapshot_sha256",
                "mapping_generation",
            ):
                _sha256(evidence[field], field)
            if (
                evidence["linux_boot_uuid"] == baseline["linux_boot_uuid"]
                or evidence["connection_generation"]
                == baseline["connection_generation"]
                or evidence["identity_uuid"] != target_uuid
                or evidence["survivor_snapshot_sha256"] != survivor_hash
                or evidence["snapshot_sha256"] != reconciled_hash
                or evidence["mapping_generation"] != baseline["mapping_generation"]
                or evidence["target_absent"] is not True
                or evidence["local_live_equal"] is not True
                or evidence["sep_clean"] is not True
            ):
                raise IdentityDeleteJournalError("delete post-reboot proof is invalid")
            phase = IdentityDeletePhase.POST_REBOOT_VERIFIED
            continue

        raise IdentityDeleteJournalError(f"unsupported delete milestone {milestone!r}")

    head_hash = records[-1].get("record_hash")
    _sha256(head_hash, "journal head hash")
    return IdentityDeleteHistory(
        operation_id,
        phase,
        baseline,
        target_uuid,
        target_entity,
        target_name_hash,
        request_hash,
        survivor_hash,
        command_status,
        persistence.snapshot(),
        reconciled_hash,
        outcome_stage,
        len(records),
        head_hash,
    )


def read(path: Path) -> IdentityDeleteHistory:
    return validate_history(journal.read(path))


def append_checked(
    path: Path, operation_id: str, milestone: str, evidence: dict[str, Any]
) -> IdentityDeleteHistory:
    records = journal.read(path)
    current = validate_history(records)
    if current.operation_id != operation_id:
        raise IdentityDeleteJournalError("operation ID does not match delete journal")
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
