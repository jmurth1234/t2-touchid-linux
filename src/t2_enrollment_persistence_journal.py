# SPDX-License-Identifier: GPL-2.0-only
"""Typed Catacomb persistence milestones for an enrollment journal.

This module validates records only.  It never sends a biometric command,
handles a secure blob, or writes a Catacomb component.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any

import t2_mutation_journal as journal


class PersistenceJournalError(journal.JournalError):
    pass


class PersistencePhase(Enum):
    NOT_STARTED = "not-started"
    COMPONENT_READY = "component-ready"
    PREPARE_INTENT = "prepare-intent"
    PREPARED = "prepared"
    COMPLETE_INTENT = "complete-intent"
    SECURE_BLOB_CAPTURED = "secure-blob-captured"
    HOST_STAGED = "host-staged"
    CONFIRM_INTENT = "confirm-intent"
    BATCH_COMMIT_INTENT = "batch-commit-intent"
    BATCH_COMMITTED = "batch-committed"
    FINAL_CONFIRM_INTENT = "final-confirm-intent"
    ATTESTATION_READY = "attestation-ready"
    COMPLETE = "complete"
    OUTCOME_UNKNOWN = "outcome-unknown"


@dataclass(frozen=True, repr=False)
class PersistenceHistory:
    phase: PersistencePhase
    batches: tuple[tuple[tuple[str, str], ...], ...]
    batch_index: int | None
    component_index: int | None
    staged_files: tuple[tuple[str, str], ...]
    reconciliation_snapshot_sha256: str | None
    sep_host_generation_equal: bool
    independent_archive_readback: bool
    outcome_unknown_stage: str | None
    outcome_unknown_host_commit_possible: bool | None


def _exact(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise PersistenceJournalError(f"{field} evidence does not match its schema")
    return value


def _uint(value: Any, field: str, maximum: int = 0xFFFFFFFF) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= maximum
    ):
        raise PersistenceJournalError(f"{field} is not a bounded unsigned integer")
    return value


def _sha256(value: Any, field: str) -> None:
    try:
        journal.require_sha256(value, field)
    except journal.JournalError as error:
        raise PersistenceJournalError(str(error)) from error


def _status_zero(value: Any, field: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value != 0:
        raise PersistenceJournalError(f"{field} is not successful")


def _allowed_names(apple_uid: int) -> set[str]:
    return {
        "master.cat",
        "biolockout.cat",
        f"user_{apple_uid:08x}.cat",
    }


class PersistenceTracker:
    """Reconstruct and validate one immutable multi-batch save sequence."""

    def __init__(
        self, baseline: dict[str, Any], *, plan_kind: str = "enrollment"
    ) -> None:
        if plan_kind not in {"enrollment", "identity-metadata"}:
            raise PersistenceJournalError("unsupported Catacomb persistence plan kind")
        self._baseline = baseline
        self._plan_kind = plan_kind
        self._connection_generation = baseline["connection_generation"]
        self.phase = PersistencePhase.NOT_STARTED
        self.batches: tuple[tuple[tuple[str, str], ...], ...] = ()
        self.batch_index: int | None = None
        self.component_index: int | None = None
        self._captured_blob_sha256: str | None = None
        self._expected_blob_length: int | None = None
        self._staged: dict[str, str] = {}
        self.reconciliation_snapshot_sha256: str | None = None
        self.sep_host_generation_equal = False
        self.independent_archive_readback = False
        self._outcome_unknown_stage: str | None = None
        self._outcome_unknown_host_commit_possible: bool | None = None

    def snapshot(self) -> PersistenceHistory:
        return PersistenceHistory(
            self.phase,
            self.batches,
            self.batch_index,
            self.component_index,
            tuple(sorted(self._staged.items())),
            self.reconciliation_snapshot_sha256,
            self.sep_host_generation_equal,
            self.independent_archive_readback,
            self._outcome_unknown_stage,
            self._outcome_unknown_host_commit_possible,
        )

    def _same_generation(self, evidence: dict[str, Any]) -> None:
        if (
            evidence["connection_generation"]
            != self._connection_generation
        ):
            raise PersistenceJournalError(
                "Catacomb persistence connection generation changed"
            )

    def use_recovery_generation(self, connection_generation: str) -> None:
        """Bind not-yet-started persistence to a fresh recovery lease."""
        if self.phase is not PersistencePhase.NOT_STARTED:
            raise PersistenceJournalError(
                "Catacomb persistence generation changed after planning"
            )
        try:
            journal.require_uuid(
                connection_generation, "recovery connection generation"
            )
        except journal.JournalError as error:
            raise PersistenceJournalError(str(error)) from error
        if connection_generation == self._baseline["connection_generation"]:
            raise PersistenceJournalError(
                "Catacomb recovery did not use a fresh connection generation"
            )
        self._connection_generation = connection_generation

    def _current(self) -> tuple[str, str]:
        if self.batch_index is None or self.component_index is None:
            raise PersistenceJournalError("Catacomb persistence has no component")
        return self.batches[self.batch_index][self.component_index]

    def _component_evidence(
        self, value: Any, milestone: str, extra: set[str] | None = None
    ) -> dict[str, Any]:
        keys = {
            "connection_generation",
            "batch_index",
            "component_index",
            "name",
            "descriptor_sha256",
        }
        evidence = _exact(value, keys | (extra or set()), milestone)
        self._same_generation(evidence)
        batch_index = _uint(evidence["batch_index"], "batch index")
        component_index = _uint(evidence["component_index"], "component index")
        name, descriptor_sha256 = self._current()
        if (
            batch_index != self.batch_index
            or component_index != self.component_index
            or evidence["name"] != name
            or evidence["descriptor_sha256"] != descriptor_sha256
        ):
            raise PersistenceJournalError(
                "Catacomb persistence milestone targets another component"
            )
        return evidence

    def _batch_evidence(self, value: Any, milestone: str) -> dict[str, Any]:
        evidence = _exact(
            value,
            {
                "connection_generation",
                "batch_index",
                "staged_snapshot_sha256",
            },
            milestone,
        )
        self._same_generation(evidence)
        if _uint(evidence["batch_index"], "batch index") != self.batch_index:
            raise PersistenceJournalError("Catacomb batch index changed")
        _sha256(evidence["staged_snapshot_sha256"], "staged snapshot SHA-256")
        expected = hashlib.sha256(
            journal.canonical(
                [
                    {"name": name, "final_file_sha256": self._staged[name]}
                    for name, _descriptor in self.batches[self.batch_index]
                ]
            )
        ).hexdigest()
        if evidence["staged_snapshot_sha256"] != expected:
            raise PersistenceJournalError("staged Catacomb snapshot digest differs")
        return evidence

    def _plan(
        self, value: Any, milestone: str, *, allow_biolockout_only: bool
    ) -> None:
        if self.phase is not PersistencePhase.NOT_STARTED:
            raise PersistenceJournalError("Catacomb persistence plan is out of order")
        evidence = _exact(value, {"connection_generation", "batches"}, milestone)
        self._same_generation(evidence)
        batches = evidence["batches"]
        if not isinstance(batches, list) or not 1 <= len(batches) <= 2:
            raise PersistenceJournalError("Catacomb persistence batches are invalid")
        allowed = _allowed_names(self._baseline["apple_uid"])
        required = {
            "master.cat",
            f'user_{self._baseline["apple_uid"]:08x}.cat',
        }
        seen: set[str] = set()
        seen_descriptors: set[str] = set()
        normalized = []
        for batch_index, batch in enumerate(batches):
            if not isinstance(batch, list) or not batch:
                raise PersistenceJournalError("Catacomb persistence batch is empty")
            normalized_batch = []
            for component_index, component in enumerate(batch):
                component = _exact(
                    component,
                    {"name", "descriptor_sha256"},
                    f"{milestone} batch {batch_index} component {component_index}",
                )
                name = component["name"]
                if name not in allowed or name in seen:
                    raise PersistenceJournalError(
                        "Catacomb persistence component is invalid or duplicated"
                    )
                _sha256(
                    component["descriptor_sha256"], "component descriptor SHA-256"
                )
                if component["descriptor_sha256"] in seen_descriptors:
                    raise PersistenceJournalError(
                        "Catacomb component descriptor digest is duplicated"
                    )
                seen.add(name)
                seen_descriptors.add(component["descriptor_sha256"])
                normalized_batch.append((name, component["descriptor_sha256"]))
            if any(name == "master.cat" for name, _digest in normalized_batch) and (
                normalized_batch[-1][0] != "master.cat"
            ):
                raise PersistenceJournalError(
                    "master Catacomb must be last in its batch"
                )
            normalized.append(tuple(normalized_batch))
        if self._plan_kind == "identity-metadata":
            if allow_biolockout_only or (
                len(normalized) != 1
                or [name for name, _digest in normalized[0]]
                != [f'user_{self._baseline["apple_uid"]:08x}.cat']
            ):
                raise PersistenceJournalError(
                    "identity metadata persistence must contain only its user Catacomb"
                )
        elif allow_biolockout_only:
            if (
                len(normalized) != 1
                or [name for name, _digest in normalized[0]]
                != ["biolockout.cat"]
            ):
                raise PersistenceJournalError(
                    "failure persistence must contain only bio-lockout Catacomb"
                )
        elif not required <= seen:
            raise PersistenceJournalError(
                "enrollment persistence omits the user or master Catacomb"
            )
        user_name = f'user_{self._baseline["apple_uid"]:08x}.cat'
        primary_names = [name for name, _digest in normalized[0]]
        if (
            self._plan_kind == "enrollment"
            and not allow_biolockout_only
            and primary_names != [user_name, "master.cat"]
        ):
            raise PersistenceJournalError(
                "primary enrollment batch must contain user then master Catacomb"
            )
        if self._plan_kind == "enrollment" and not allow_biolockout_only and (
            len(normalized) != 2
            or [name for name, _digest in normalized[1]] != ["biolockout.cat"]
        ):
            raise PersistenceJournalError(
                "secondary enrollment batch must contain only bio-lockout Catacomb"
            )
        self.batches = tuple(normalized)
        self.batch_index = 0
        self.component_index = 0
        self.phase = PersistencePhase.COMPONENT_READY

    def consume(
        self,
        milestone: str,
        value: Any,
        *,
        allow_biolockout_only: bool = False,
    ) -> bool:
        if not isinstance(milestone, str) or not milestone.startswith("CATACOMB_"):
            return False
        if milestone == "CATACOMB_EARLY_CONFIRM_RECOVERED":
            if (
                self.phase is not PersistencePhase.OUTCOME_UNKNOWN
                or self._outcome_unknown_stage != "early-confirm"
                or self._outcome_unknown_host_commit_possible is not False
            ):
                raise PersistenceJournalError(
                    "early Catacomb confirm recovery is out of order"
                )
            evidence = _exact(
                value,
                {
                    "connection_generation",
                    "batch_index",
                    "component_index",
                    "name",
                    "descriptor_sha256",
                    "sep_component_clean",
                    "staged_file_sha256",
                },
                milestone,
            )
            connection_generation = evidence["connection_generation"]
            try:
                journal.require_uuid(
                    connection_generation, "recovery connection generation"
                )
            except journal.JournalError as error:
                raise PersistenceJournalError(str(error)) from error
            if connection_generation == self._connection_generation:
                raise PersistenceJournalError(
                    "early confirm recovery reused the ambiguous connection"
                )
            batch_index = _uint(evidence["batch_index"], "batch index")
            component_index = _uint(
                evidence["component_index"], "component index"
            )
            name, descriptor_sha256 = self._current()
            if (
                batch_index != self.batch_index
                or component_index != self.component_index
                or evidence["name"] != name
                or evidence["descriptor_sha256"] != descriptor_sha256
                or evidence["sep_component_clean"] is not True
                or evidence["staged_file_sha256"] != self._staged.get(name)
            ):
                raise PersistenceJournalError(
                    "early confirm recovery evidence differs from the journal"
                )
            self._connection_generation = connection_generation
            self.component_index += 1
            if self.component_index >= len(self.batches[self.batch_index]):
                raise PersistenceJournalError(
                    "early confirm recovery has no following component"
                )
            self._captured_blob_sha256 = None
            self._expected_blob_length = None
            self._outcome_unknown_stage = None
            self._outcome_unknown_host_commit_possible = None
            self.phase = PersistencePhase.COMPONENT_READY
            return True
        if milestone == "CATACOMB_PERSISTENCE_PLAN":
            self._plan(
                value,
                milestone,
                allow_biolockout_only=allow_biolockout_only,
            )
            return True
        if self.phase is PersistencePhase.NOT_STARTED:
            raise PersistenceJournalError("Catacomb persistence has no immutable plan")

        if milestone == "CATACOMB_PERSISTENCE_OUTCOME_UNKNOWN":
            if self.phase in (
                PersistencePhase.COMPONENT_READY,
                PersistencePhase.COMPLETE,
                PersistencePhase.OUTCOME_UNKNOWN,
            ):
                raise PersistenceJournalError(
                    "persistence outcome-unknown marker is out of order"
                )
            evidence = self._component_evidence(
                value,
                milestone,
                {
                    "stage",
                    "reason",
                    "sep_mutation_possible",
                    "host_commit_possible",
                },
            )
            if evidence["stage"] not in {
                "prepare",
                "complete",
                "encode",
                "host-stage",
                "early-confirm",
                "host-commit",
                "final-confirm",
                "readback",
            }:
                raise PersistenceJournalError("persistence failure stage is invalid")
            if evidence["reason"] not in {
                "transport-error",
                "journal-error",
                "codec-error",
                "host-store-error",
                "readback-error",
            }:
                raise PersistenceJournalError("persistence failure reason is invalid")
            if (
                evidence["sep_mutation_possible"] is not True
                or not isinstance(evidence["host_commit_possible"], bool)
            ):
                raise PersistenceJournalError(
                    "persistence ambiguity flags are invalid"
                )
            self._outcome_unknown_stage = evidence["stage"]
            self._outcome_unknown_host_commit_possible = evidence[
                "host_commit_possible"
            ]
            self.phase = PersistencePhase.OUTCOME_UNKNOWN
            return True

        if milestone == "CATACOMB_PREPARE_INTENT":
            if self.phase is not PersistencePhase.COMPONENT_READY:
                raise PersistenceJournalError("Catacomb prepare intent is out of order")
            self._component_evidence(value, milestone)
            self.phase = PersistencePhase.PREPARE_INTENT
            return True

        if milestone == "CATACOMB_PREPARED":
            if self.phase is not PersistencePhase.PREPARE_INTENT:
                raise PersistenceJournalError(
                    "Catacomb prepare observation is out of order"
                )
            evidence = self._component_evidence(
                value, milestone, {"status", "expected_blob_length"}
            )
            _status_zero(evidence["status"], "Catacomb prepare status")
            expected_blob_length = _uint(
                evidence["expected_blob_length"],
                "expected secure blob length",
                1024 * 1024,
            )
            if expected_blob_length == 0:
                raise PersistenceJournalError("expected secure blob is empty")
            self._expected_blob_length = expected_blob_length
            self.phase = PersistencePhase.PREPARED
            return True

        if milestone == "CATACOMB_COMPLETE_INTENT":
            if self.phase is not PersistencePhase.PREPARED:
                raise PersistenceJournalError("Catacomb complete intent is out of order")
            self._component_evidence(value, milestone)
            self.phase = PersistencePhase.COMPLETE_INTENT
            return True

        if milestone == "CATACOMB_SECURE_BLOB_CAPTURED":
            if self.phase is not PersistencePhase.COMPLETE_INTENT:
                raise PersistenceJournalError("secure blob observation is out of order")
            evidence = self._component_evidence(
                value, milestone, {"status", "blob_length", "secure_blob_sha256"}
            )
            _status_zero(evidence["status"], "Catacomb complete status")
            blob_length = _uint(
                evidence["blob_length"], "secure blob length", 1024 * 1024
            )
            name, _descriptor = self._current()
            length_valid = (
                16 <= blob_length <= self._expected_blob_length
                if name == "biolockout.cat"
                else blob_length == self._expected_blob_length
            )
            if not length_valid:
                raise PersistenceJournalError(
                    "secure blob length differs from prepare response"
                )
            _sha256(evidence["secure_blob_sha256"], "secure blob SHA-256")
            self._captured_blob_sha256 = evidence["secure_blob_sha256"]
            self.phase = PersistencePhase.SECURE_BLOB_CAPTURED
            return True

        if milestone == "CATACOMB_HOST_STAGED":
            if self.phase is not PersistencePhase.SECURE_BLOB_CAPTURED:
                raise PersistenceJournalError("host staging observation is out of order")
            evidence = self._component_evidence(
                value,
                milestone,
                {"secure_blob_sha256", "final_file_sha256"},
            )
            _sha256(evidence["secure_blob_sha256"], "secure blob SHA-256")
            _sha256(evidence["final_file_sha256"], "final file SHA-256")
            if evidence["secure_blob_sha256"] != self._captured_blob_sha256:
                raise PersistenceJournalError("staged host file uses another secure blob")
            name, _descriptor = self._current()
            self._staged[name] = evidence["final_file_sha256"]
            self.phase = PersistencePhase.HOST_STAGED
            return True

        final_component = (
            self.component_index == len(self.batches[self.batch_index]) - 1
        )
        if milestone == "CATACOMB_CONFIRM_INTENT":
            if self.phase is not PersistencePhase.HOST_STAGED or final_component:
                raise PersistenceJournalError(
                    "early Catacomb confirm intent is out of order"
                )
            self._component_evidence(value, milestone)
            self.phase = PersistencePhase.CONFIRM_INTENT
            return True

        if milestone == "CATACOMB_CONFIRMED":
            if self.phase is not PersistencePhase.CONFIRM_INTENT:
                raise PersistenceJournalError("early Catacomb confirm is out of order")
            evidence = self._component_evidence(
                value, milestone, {"status"}
            )
            _status_zero(evidence["status"], "Catacomb confirm status")
            self.component_index += 1
            self._captured_blob_sha256 = None
            self._expected_blob_length = None
            self.phase = PersistencePhase.COMPONENT_READY
            return True

        if milestone == "CATACOMB_HOST_BATCH_COMMIT_INTENT":
            if self.phase is not PersistencePhase.HOST_STAGED or not final_component:
                raise PersistenceJournalError(
                    "host batch commit intent is out of order"
                )
            self._batch_evidence(value, milestone)
            self.phase = PersistencePhase.BATCH_COMMIT_INTENT
            return True

        if milestone == "CATACOMB_HOST_BATCH_COMMITTED":
            if self.phase is not PersistencePhase.BATCH_COMMIT_INTENT:
                raise PersistenceJournalError("host batch commit is out of order")
            self._batch_evidence(value, milestone)
            self.phase = PersistencePhase.BATCH_COMMITTED
            return True

        if milestone == "CATACOMB_FINAL_CONFIRM_INTENT":
            if self.phase is not PersistencePhase.BATCH_COMMITTED:
                raise PersistenceJournalError(
                    "final Catacomb confirm intent is out of order"
                )
            self._component_evidence(value, milestone)
            self.phase = PersistencePhase.FINAL_CONFIRM_INTENT
            return True

        if milestone == "CATACOMB_FINAL_CONFIRMED":
            if self.phase is not PersistencePhase.FINAL_CONFIRM_INTENT:
                raise PersistenceJournalError("final Catacomb confirm is out of order")
            evidence = self._component_evidence(
                value, milestone, {"status"}
            )
            _status_zero(evidence["status"], "final Catacomb confirm status")
            self._captured_blob_sha256 = None
            self._expected_blob_length = None
            if self.batch_index + 1 < len(self.batches):
                self.batch_index += 1
                self.component_index = 0
                self._staged = {}
                self.phase = PersistencePhase.COMPONENT_READY
            else:
                self.phase = PersistencePhase.ATTESTATION_READY
            return True

        if milestone == "CATACOMB_PERSISTENCE_ATTESTED":
            if self.phase is not PersistencePhase.ATTESTATION_READY:
                raise PersistenceJournalError("persistence attestation is out of order")
            evidence = _exact(
                value,
                {
                    "connection_generation",
                    "batch_count",
                    "reconciliation_snapshot_sha256",
                    "sep_host_generation_equal",
                    "independent_archive_readback",
                },
                milestone,
            )
            self._same_generation(evidence)
            if _uint(evidence["batch_count"], "batch count") != len(self.batches):
                raise PersistenceJournalError("persistence batch count changed")
            _sha256(
                evidence["reconciliation_snapshot_sha256"],
                "reconciliation snapshot SHA-256",
            )
            if (
                evidence["sep_host_generation_equal"] is not True
                or evidence["independent_archive_readback"] is not True
            ):
                raise PersistenceJournalError("persistence attestation is incomplete")
            self.reconciliation_snapshot_sha256 = evidence[
                "reconciliation_snapshot_sha256"
            ]
            self.sep_host_generation_equal = True
            self.independent_archive_readback = True
            self.phase = PersistencePhase.COMPLETE
            return True

        raise PersistenceJournalError(
            f"unsupported Catacomb persistence milestone {milestone!r}"
        )
