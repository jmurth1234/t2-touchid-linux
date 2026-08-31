# SPDX-License-Identifier: GPL-2.0-only
"""Typed journal state machine for one identity-label Catacomb transaction."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import t2_enrollment_persistence_journal as persistence_journal
import t2_mutation_journal as journal


class IdentityRenameJournalError(journal.JournalError):
    pass


class IdentityRenamePhase(Enum):
    BASELINE = "baseline-reconciled"
    INTENT = "rename-intent"
    ABORTED = "aborted-before-persistence"
    PERSISTING = "persisting"
    PERSISTENCE_READY = "persistence-ready"
    RECONCILED = "reconciled"
    POST_REBOOT_VERIFIED = "post-reboot-verified"
    OUTCOME_UNKNOWN = "outcome-unknown"


@dataclass(frozen=True, repr=False)
class IdentityRenameHistory:
    operation_id: str
    phase: IdentityRenamePhase
    baseline: dict[str, Any]
    target_identity_uuid: str | None
    target_entity: int | None
    previous_name_sha256: str | None
    new_name_sha256: str | None
    persistence: persistence_journal.PersistenceHistory
    reconciled_snapshot_sha256: str | None
    recovery_action: str | None
    record_count: int
    head_hash: str


def _exact(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise IdentityRenameJournalError(f"{field} evidence does not match its schema")
    return value


def _sha256(value: Any, field: str) -> None:
    try:
        journal.require_sha256(value, field)
    except journal.JournalError as error:
        raise IdentityRenameJournalError(str(error)) from error


def _uuid(value: Any, field: str) -> None:
    try:
        journal.require_uuid(value, field)
    except journal.JournalError as error:
        raise IdentityRenameJournalError(str(error)) from error


def validate_history(records: list[dict[str, Any]]) -> IdentityRenameHistory:
    if not records:
        raise IdentityRenameJournalError("rename journal is empty")
    first = records[0]
    if first.get("milestone") != "BASELINE_RECONCILED":
        raise IdentityRenameJournalError("rename journal has no baseline")
    initial = _exact(
        first.get("evidence"), {"operation_kind", "baseline"}, "baseline"
    )
    if initial["operation_kind"] != "rename":
        raise IdentityRenameJournalError("journal is not an identity rename")
    baseline = initial["baseline"]
    try:
        journal.validate_baseline(baseline)
    except journal.JournalError as error:
        raise IdentityRenameJournalError(str(error)) from error
    operation_id = first.get("operation_id")
    _uuid(operation_id, "operation ID")
    phase = IdentityRenamePhase.BASELINE
    target_uuid: str | None = None
    target_entity: int | None = None
    old_name_hash: str | None = None
    new_name_hash: str | None = None
    reconciled_hash: str | None = None
    recovery_action: str | None = None
    persistence = persistence_journal.PersistenceTracker(
        baseline, plan_kind="identity-metadata"
    )

    for record in records[1:]:
        if record.get("operation_id") != operation_id:
            raise IdentityRenameJournalError("operation ID changed inside rename journal")
        milestone = record.get("milestone")
        evidence = record.get("evidence")

        if milestone == "RENAME_INTENT":
            if phase is not IdentityRenamePhase.BASELINE:
                raise IdentityRenameJournalError("rename intent is out of order")
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "user_id",
                    "identity_uuid",
                    "entity",
                    "previous_name_sha256",
                    "new_name_sha256",
                    "mapping_generation",
                },
                milestone,
            )
            _uuid(evidence["identity_uuid"], "identity UUID")
            _sha256(evidence["previous_name_sha256"], "previous name SHA-256")
            _sha256(evidence["new_name_sha256"], "new name SHA-256")
            _sha256(evidence["mapping_generation"], "mapping generation")
            if (
                evidence["connection_generation"] != baseline["connection_generation"]
                or evidence["user_id"] != baseline["apple_uid"]
                or evidence["mapping_generation"] != baseline["mapping_generation"]
                or not isinstance(evidence["entity"], int)
                or isinstance(evidence["entity"], bool)
                or evidence["entity"] < 0
                or evidence["previous_name_sha256"] == evidence["new_name_sha256"]
            ):
                raise IdentityRenameJournalError("rename intent binding is invalid")
            matches = [
                identity
                for identity in baseline["identity_records"]
                if identity["uuid"] == evidence["identity_uuid"]
                and identity["entity"] == evidence["entity"]
            ]
            if len(matches) != 1:
                raise IdentityRenameJournalError("rename target is not in the baseline")
            target_uuid = evidence["identity_uuid"]
            target_entity = evidence["entity"]
            old_name_hash = evidence["previous_name_sha256"]
            new_name_hash = evidence["new_name_sha256"]
            phase = IdentityRenamePhase.INTENT
            continue

        if milestone == "RENAME_ABORTED_BEFORE_PERSISTENCE":
            if (
                phase is not IdentityRenamePhase.PERSISTING
                or persistence.phase
                is not persistence_journal.PersistencePhase.COMPONENT_READY
            ):
                raise IdentityRenameJournalError("rename abort is out of order")
            evidence = _exact(
                evidence, {"reason", "mutation_possible"}, milestone
            )
            if (
                evidence["reason"] != "host-store-unavailable"
                or evidence["mutation_possible"] is not False
            ):
                raise IdentityRenameJournalError("rename abort evidence is invalid")
            phase = IdentityRenamePhase.ABORTED
            continue

        if isinstance(milestone, str) and milestone.startswith("CATACOMB_"):
            if phase not in (
                IdentityRenamePhase.INTENT,
                IdentityRenamePhase.PERSISTING,
            ):
                raise IdentityRenameJournalError("rename persistence is out of order")
            try:
                persistence.consume(milestone, evidence)
            except persistence_journal.PersistenceJournalError as error:
                raise IdentityRenameJournalError(str(error)) from error
            if persistence.phase is persistence_journal.PersistencePhase.COMPLETE:
                phase = IdentityRenamePhase.PERSISTENCE_READY
            elif persistence.phase is persistence_journal.PersistencePhase.OUTCOME_UNKNOWN:
                phase = IdentityRenamePhase.OUTCOME_UNKNOWN
            else:
                phase = IdentityRenamePhase.PERSISTING
            continue

        if milestone == "RENAME_RECONCILED":
            if phase is not IdentityRenamePhase.PERSISTENCE_READY:
                raise IdentityRenameJournalError("rename reconciliation is out of order")
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "identity_uuid",
                    "new_name_sha256",
                    "snapshot_sha256",
                    "mapping_generation",
                    "identity_count",
                    "identity_set_unchanged",
                    "label_updated",
                    "local_live_equal",
                },
                milestone,
            )
            _uuid(evidence["identity_uuid"], "identity UUID")
            for field in ("new_name_sha256", "snapshot_sha256", "mapping_generation"):
                _sha256(evidence[field], field)
            if (
                evidence["connection_generation"] != baseline["connection_generation"]
                or evidence["identity_uuid"] != target_uuid
                or evidence["new_name_sha256"] != new_name_hash
                or evidence["mapping_generation"] != baseline["mapping_generation"]
                or evidence["identity_count"] != len(baseline["identity_records"])
                or evidence["identity_set_unchanged"] is not True
                or evidence["label_updated"] is not True
                or evidence["local_live_equal"] is not True
            ):
                raise IdentityRenameJournalError("rename reconciliation is invalid")
            reconciled_hash = evidence["snapshot_sha256"]
            phase = IdentityRenamePhase.RECONCILED
            continue

        if milestone == "RENAME_RECOVERY_INTENT":
            if phase not in {
                IdentityRenamePhase.INTENT,
                IdentityRenamePhase.PERSISTING,
                IdentityRenamePhase.PERSISTENCE_READY,
                IdentityRenamePhase.OUTCOME_UNKNOWN,
            } or recovery_action is not None:
                raise IdentityRenameJournalError("rename recovery intent is out of order")
            evidence = _exact(
                evidence,
                {
                    "action",
                    "mapping_generation",
                    "host_commit_possible",
                    "mutation_possible",
                },
                milestone,
            )
            action = evidence["action"]
            if action not in {
                "prepare-discarded",
                "commit-rolled-forward",
                "no-local-transaction",
            }:
                raise IdentityRenameJournalError("rename recovery action is invalid")
            _sha256(evidence["mapping_generation"], "mapping generation")
            if (
                evidence["mapping_generation"] != baseline["mapping_generation"]
                or evidence["mutation_possible"] is not True
                or evidence["host_commit_possible"]
                != (action != "prepare-discarded")
            ):
                raise IdentityRenameJournalError("rename recovery binding is invalid")
            recovery_action = action
            phase = IdentityRenamePhase.OUTCOME_UNKNOWN
            continue

        if milestone in {
            "RENAME_RECOVERY_RECONCILED_NO_CHANGE",
            "RENAME_RECOVERY_RECONCILED_COMMITTED",
        }:
            if (
                phase is not IdentityRenamePhase.OUTCOME_UNKNOWN
                or recovery_action is None
                or target_uuid is None
            ):
                raise IdentityRenameJournalError(
                    "rename recovery reconciliation is out of order"
                )
            evidence = _exact(
                evidence,
                {
                    "connection_generation",
                    "identity_uuid",
                    "name_sha256",
                    "snapshot_sha256",
                    "mapping_generation",
                    "identity_count",
                    "identity_set_unchanged",
                    "local_live_equal",
                    "sep_clean",
                    "host_reconciled",
                    "recovery_action",
                },
                milestone,
            )
            for field in ("connection_generation", "identity_uuid"):
                _uuid(evidence[field], field)
            for field in ("name_sha256", "snapshot_sha256", "mapping_generation"):
                _sha256(evidence[field], field)
            committed = milestone.endswith("COMMITTED")
            expected_name = new_name_hash if committed else old_name_hash
            if (
                evidence["connection_generation"]
                == baseline["connection_generation"]
                or evidence["identity_uuid"] != target_uuid
                or evidence["name_sha256"] != expected_name
                or evidence["mapping_generation"] != baseline["mapping_generation"]
                or evidence["identity_count"] != len(baseline["identity_records"])
                or evidence["identity_set_unchanged"] is not True
                or evidence["local_live_equal"] is not True
                or evidence["sep_clean"] is not True
                or evidence["host_reconciled"] is not True
                or evidence["recovery_action"] != recovery_action
            ):
                raise IdentityRenameJournalError(
                    "rename recovery reconciliation is invalid"
                )
            if not committed and recovery_action == "commit-rolled-forward":
                raise IdentityRenameJournalError(
                    "rolled-forward rename cannot reconcile as unchanged"
                )
            reconciled_hash = evidence["snapshot_sha256"]
            phase = (
                IdentityRenamePhase.RECONCILED
                if committed
                else IdentityRenamePhase.ABORTED
            )
            continue

        if milestone == "RENAME_POST_REBOOT_VERIFIED":
            if phase is not IdentityRenamePhase.RECONCILED:
                raise IdentityRenameJournalError("rename post-reboot proof is out of order")
            evidence = _exact(
                evidence,
                {
                    "linux_boot_uuid",
                    "connection_generation",
                    "identity_uuid",
                    "new_name_sha256",
                    "snapshot_sha256",
                    "mapping_generation",
                    "identity_set_unchanged",
                    "label_preserved",
                    "local_live_equal",
                },
                milestone,
            )
            for field in ("linux_boot_uuid", "connection_generation", "identity_uuid"):
                _uuid(evidence[field], field)
            for field in ("new_name_sha256", "snapshot_sha256", "mapping_generation"):
                _sha256(evidence[field], field)
            if (
                evidence["linux_boot_uuid"] == baseline["linux_boot_uuid"]
                or evidence["connection_generation"] == baseline["connection_generation"]
                or evidence["identity_uuid"] != target_uuid
                or evidence["new_name_sha256"] != new_name_hash
                or evidence["snapshot_sha256"] != reconciled_hash
                or evidence["mapping_generation"] != baseline["mapping_generation"]
                or evidence["identity_set_unchanged"] is not True
                or evidence["label_preserved"] is not True
                or evidence["local_live_equal"] is not True
            ):
                raise IdentityRenameJournalError("rename post-reboot proof is invalid")
            phase = IdentityRenamePhase.POST_REBOOT_VERIFIED
            continue

        raise IdentityRenameJournalError(f"unsupported rename milestone {milestone!r}")

    head_hash = records[-1].get("record_hash")
    _sha256(head_hash, "journal head hash")
    return IdentityRenameHistory(
        operation_id,
        phase,
        baseline,
        target_uuid,
        target_entity,
        old_name_hash,
        new_name_hash,
        persistence.snapshot(),
        reconciled_hash,
        recovery_action,
        len(records),
        head_hash,
    )


def read(path: Path) -> IdentityRenameHistory:
    return validate_history(journal.read(path))


def append_checked(
    path: Path, operation_id: str, milestone: str, evidence: dict[str, Any]
) -> IdentityRenameHistory:
    records = journal.read(path)
    current = validate_history(records)
    if current.operation_id != operation_id:
        raise IdentityRenameJournalError("operation ID does not match rename journal")
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
