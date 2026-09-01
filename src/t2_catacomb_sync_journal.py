# SPDX-License-Identifier: GPL-2.0-only
"""Typed journal for persisting an already-dirty user Catacomb."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import t2_mutation_journal


class CatacombSyncJournalError(RuntimeError):
    pass


class CatacombSyncPhase(Enum):
    BASELINE = "baseline"
    INTENT = "intent"
    HOST_COMMITTED = "host-committed"
    RECONCILED = "reconciled"
    ABORTED = "aborted"
    OUTCOME_UNKNOWN = "outcome-unknown"


@dataclass(frozen=True, repr=False)
class CatacombSyncHistory:
    operation_id: str
    phase: CatacombSyncPhase
    baseline: dict[str, Any]
    record_count: int
    head_hash: str


def _sha(value: Any, field: str) -> None:
    try:
        t2_mutation_journal.require_sha256(value, field)
    except t2_mutation_journal.JournalError as error:
        raise CatacombSyncJournalError(str(error)) from error


def _uuid(value: Any, field: str) -> None:
    try:
        t2_mutation_journal.require_uuid(value, field)
    except t2_mutation_journal.JournalError as error:
        raise CatacombSyncJournalError(str(error)) from error


def validate_history(records: list[dict[str, Any]]) -> CatacombSyncHistory:
    if not isinstance(records, list) or not records:
        raise CatacombSyncJournalError("Catacomb sync journal is empty")
    first = records[0]
    evidence = first.get("evidence")
    if (
        first.get("milestone") != "BASELINE_RECONCILED"
        or not isinstance(evidence, dict)
        or set(evidence) != {"operation_kind", "baseline"}
        or evidence.get("operation_kind") != "sync-user-catacomb"
    ):
        raise CatacombSyncJournalError("Catacomb sync baseline is invalid")
    try:
        t2_mutation_journal.validate_baseline(evidence["baseline"])
    except t2_mutation_journal.JournalError as error:
        raise CatacombSyncJournalError("Catacomb sync baseline is invalid") from error
    operation_id = first.get("operation_id")
    phase = CatacombSyncPhase.BASELINE
    intent: dict[str, Any] | None = None
    host_commit: dict[str, Any] | None = None
    for index, record in enumerate(records[1:], 1):
        item = record.get("evidence")
        milestone = record.get("milestone")
        if not isinstance(item, dict):
            raise CatacombSyncJournalError("Catacomb sync evidence is invalid")
        if milestone == "CATACOMB_SYNC_INTENT" and phase is CatacombSyncPhase.BASELINE:
            if set(item) != {
                "connection_generation",
                "mapping_generation",
                "descriptor_snapshot_sha256",
                "initial_component_snapshot_sha256",
                "initial_sep_catacomb_hash",
                "identity_snapshot_sha256",
            }:
                raise CatacombSyncJournalError("Catacomb sync intent is invalid")
            _uuid(item["connection_generation"], "connection generation")
            for field in set(item) - {"connection_generation"}:
                _sha(item[field], field)
            if (
                item["connection_generation"]
                != evidence["baseline"]["connection_generation"]
                or item["mapping_generation"]
                != evidence["baseline"]["mapping_generation"]
            ):
                raise CatacombSyncJournalError("Catacomb sync intent binding changed")
            intent = item
            phase = CatacombSyncPhase.INTENT
        elif milestone == "CATACOMB_SYNC_HOST_COMMITTED" and phase is CatacombSyncPhase.INTENT:
            if set(item) != {
                "connection_generation",
                "final_component_snapshot_sha256",
                "secure_blob_snapshot_sha256",
            }:
                raise CatacombSyncJournalError("Catacomb sync host commit is invalid")
            _uuid(item["connection_generation"], "connection generation")
            _sha(item["final_component_snapshot_sha256"], "final component snapshot")
            _sha(item["secure_blob_snapshot_sha256"], "secure blob snapshot")
            if intent is None or item["connection_generation"] != intent["connection_generation"]:
                raise CatacombSyncJournalError("Catacomb sync host binding changed")
            host_commit = item
            phase = CatacombSyncPhase.HOST_COMMITTED
        elif milestone == "CATACOMB_SYNC_RECONCILED" and phase is CatacombSyncPhase.HOST_COMMITTED:
            if set(item) != {
                "connection_generation",
                "final_component_snapshot_sha256",
                "final_sep_catacomb_hash",
                "identity_snapshot_sha256",
                "sep_clean",
                "local_live_equal",
            }:
                raise CatacombSyncJournalError("Catacomb sync proof is invalid")
            _uuid(item["connection_generation"], "connection generation")
            for field in (
                "final_component_snapshot_sha256",
                "final_sep_catacomb_hash",
                "identity_snapshot_sha256",
            ):
                _sha(item[field], field)
            if item["sep_clean"] is not True or item["local_live_equal"] is not True:
                raise CatacombSyncJournalError("Catacomb sync proof is incomplete")
            if (
                intent is None
                or host_commit is None
                or item["connection_generation"] != intent["connection_generation"]
                or item["final_component_snapshot_sha256"]
                != host_commit["final_component_snapshot_sha256"]
                or item["identity_snapshot_sha256"]
                != intent["identity_snapshot_sha256"]
            ):
                raise CatacombSyncJournalError("Catacomb sync proof binding changed")
            phase = CatacombSyncPhase.RECONCILED
        elif milestone == "CATACOMB_SYNC_ABORTED_BEFORE_DISPATCH" and phase is CatacombSyncPhase.INTENT:
            if set(item) != {"reason", "mutation_possible"} or (
                not isinstance(item["reason"], str)
                or not item["reason"]
                or item["mutation_possible"] is not False
            ):
                raise CatacombSyncJournalError("Catacomb sync abort is invalid")
            phase = CatacombSyncPhase.ABORTED
        elif milestone == "CATACOMB_SYNC_OUTCOME_UNKNOWN" and phase in {
            CatacombSyncPhase.INTENT,
            CatacombSyncPhase.HOST_COMMITTED,
        }:
            if set(item) != {
                "stage",
                "reason",
                "mutation_possible",
                "host_commit_possible",
            } or (
                not isinstance(item["stage"], str)
                or not item["stage"]
                or not isinstance(item["reason"], str)
                or not item["reason"]
                or item["mutation_possible"] is not True
                or type(item["host_commit_possible"]) is not bool
            ):
                raise CatacombSyncJournalError("Catacomb sync ambiguity is invalid")
            phase = CatacombSyncPhase.OUTCOME_UNKNOWN
        else:
            raise CatacombSyncJournalError(
                f"Catacomb sync milestone is out of order at record {index}"
            )
    return CatacombSyncHistory(
        operation_id,
        phase,
        evidence["baseline"],
        len(records),
        records[-1]["record_hash"],
    )


def read(path: Path) -> CatacombSyncHistory:
    try:
        return validate_history(t2_mutation_journal.read(path))
    except t2_mutation_journal.JournalError as error:
        raise CatacombSyncJournalError("Catacomb sync journal is invalid") from error


def append_checked(
    path: Path,
    operation_id: str,
    milestone: str,
    evidence: dict[str, Any],
) -> CatacombSyncHistory:
    before = read(path)
    if before.operation_id != operation_id:
        raise CatacombSyncJournalError("Catacomb sync operation ID changed")
    try:
        t2_mutation_journal.append(
            path,
            operation_id,
            milestone,
            evidence,
            expected_record_count=before.record_count,
            expected_previous_hash=before.head_hash,
        )
        return read(path)
    except t2_mutation_journal.JournalError as error:
        raise CatacombSyncJournalError("Catacomb sync append failed") from error
