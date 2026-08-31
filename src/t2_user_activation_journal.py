# SPDX-License-Identifier: GPL-2.0-only
"""Typed durable journal for one runtime Apple-user alias activation."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import t2_mutation_journal as journal
import t2_user_mapping
import t2_user_readiness


class UserActivationJournalError(journal.JournalError):
    pass


class UserActivationPhase(Enum):
    BASELINE = "baseline"
    LOAD_INTENT = "load-intent"
    HANDLE_OBSERVED = "handle-observed"
    BIND_INTENT = "bind-intent"
    ALIAS_OBSERVED = "alias-observed"
    UNLOCK_INTENT = "unlock-intent"
    READY = "ready"
    STOPPED = "stopped"
    OUTCOME_UNKNOWN = "outcome-unknown"


@dataclass(frozen=True, repr=False)
class UserActivationHistory:
    operation_id: str
    phase: UserActivationPhase
    baseline: dict[str, Any]
    temporary_handle: int | None
    record_count: int
    head_hash: str


def _exact(value: Any, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise UserActivationJournalError(f"{field} evidence does not match its schema")
    return value


def _uuid(value: Any, field: str) -> None:
    try:
        journal.require_uuid(value, field)
    except journal.JournalError as error:
        raise UserActivationJournalError(str(error)) from error


def _sha256(value: Any, field: str) -> None:
    try:
        journal.require_sha256(value, field)
    except journal.JournalError as error:
        raise UserActivationJournalError(str(error)) from error


def _uint(value: Any, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= 0xFFFFFFFF:
        raise UserActivationJournalError(f"{field} is not a bounded integer")
    return value


def _status(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not -(1 << 31) <= value < (1 << 32):
        raise UserActivationJournalError(f"{field} is not a bounded status")
    return value


def _validate_baseline(value: Any) -> dict[str, Any]:
    baseline = _exact(
        value,
        {
            "mapping_generation",
            "linux_boot_uuid",
            "runtime_generation",
            "target_linux_uid",
            "apple_uid",
            "account_uuid",
            "bag_uuid",
            "keybag_sha256",
            "special_alias",
            "capability",
            "initial_state",
            "alias_preexisting",
        },
        "activation baseline",
    )
    for field in ("mapping_generation", "keybag_sha256"):
        _sha256(baseline[field], field)
    for field in ("linux_boot_uuid", "runtime_generation", "account_uuid", "bag_uuid"):
        _uuid(baseline[field], field)
    _uint(baseline["target_linux_uid"], "target Linux UID", minimum=1)
    apple_uid = _uint(baseline["apple_uid"], "Apple UID", minimum=10)
    if baseline["special_alias"] != -apple_uid:
        raise UserActivationJournalError("special alias is not derived from Apple UID")
    if baseline["capability"] not in t2_user_mapping.CAPABILITIES:
        raise UserActivationJournalError("activation capability is unsupported")
    if baseline["initial_state"] not in {
        "alias-absent",
        "device-locked",
        "before-first-unlock",
    }:
        raise UserActivationJournalError("activation baseline is not actionable")
    if type(baseline["alias_preexisting"]) is not bool or baseline[
        "alias_preexisting"
    ] != (baseline["initial_state"] != "alias-absent"):
        raise UserActivationJournalError("activation alias provenance is inconsistent")
    return baseline


def validate_history(records: list[dict[str, Any]]) -> UserActivationHistory:
    if not records:
        raise UserActivationJournalError("activation journal is empty")
    first = records[0]
    if first.get("milestone") != "USER_ACTIVATION_BASELINE":
        raise UserActivationJournalError("activation journal has no baseline")
    initial = _exact(
        first.get("evidence"), {"operation_kind", "baseline"}, "baseline"
    )
    if initial["operation_kind"] != "user-activation":
        raise UserActivationJournalError("journal is not a user activation")
    baseline = _validate_baseline(initial["baseline"])
    operation_id = first.get("operation_id")
    _uuid(operation_id, "operation ID")
    phase = UserActivationPhase.BASELINE
    temporary_handle: int | None = None

    for record in records[1:]:
        if record.get("operation_id") != operation_id:
            raise UserActivationJournalError("operation ID changed in activation journal")
        milestone = record.get("milestone")
        evidence = record.get("evidence")
        if milestone == "USER_KEYBAG_LOAD_INTENT":
            if phase is not UserActivationPhase.BASELINE or baseline["alias_preexisting"]:
                raise UserActivationJournalError("keybag load intent is out of order")
            evidence = _exact(
                evidence,
                {"runtime_generation", "keybag_sha256", "mutation_possible"},
                milestone,
            )
            if (
                evidence["runtime_generation"] != baseline["runtime_generation"]
                or evidence["keybag_sha256"] != baseline["keybag_sha256"]
                or evidence["mutation_possible"] is not True
            ):
                raise UserActivationJournalError("keybag load intent is not bound")
            phase = UserActivationPhase.LOAD_INTENT
            continue
        if milestone == "USER_KEYBAG_HANDLE_OBSERVED":
            if phase is not UserActivationPhase.LOAD_INTENT:
                raise UserActivationJournalError("keybag handle observation is out of order")
            evidence = _exact(
                evidence,
                {"runtime_generation", "handle", "bag_uuid_matches"},
                milestone,
            )
            temporary_handle = _uint(evidence["handle"], "temporary handle", minimum=1)
            if (
                evidence["runtime_generation"] != baseline["runtime_generation"]
                or evidence["bag_uuid_matches"] is not True
            ):
                raise UserActivationJournalError("loaded handle did not reconcile")
            phase = UserActivationPhase.HANDLE_OBSERVED
            continue
        if milestone == "USER_ALIAS_BIND_INTENT":
            if phase is not UserActivationPhase.HANDLE_OBSERVED:
                raise UserActivationJournalError("alias bind intent is out of order")
            evidence = _exact(
                evidence,
                {"runtime_generation", "handle", "special_alias", "mutation_possible"},
                milestone,
            )
            if (
                evidence["runtime_generation"] != baseline["runtime_generation"]
                or evidence["handle"] != temporary_handle
                or evidence["special_alias"] != baseline["special_alias"]
                or evidence["mutation_possible"] is not True
            ):
                raise UserActivationJournalError("alias bind intent is not bound")
            phase = UserActivationPhase.BIND_INTENT
            continue
        if milestone == "USER_ALIAS_OBSERVED":
            if phase is not UserActivationPhase.BIND_INTENT:
                raise UserActivationJournalError("alias observation is out of order")
            evidence = _exact(
                evidence,
                {
                    "runtime_generation",
                    "special_alias",
                    "bag_uuid_matches",
                    "command_status",
                    "command_raised",
                },
                milestone,
            )
            _status(evidence["command_status"], "alias command status")
            if (
                evidence["runtime_generation"] != baseline["runtime_generation"]
                or evidence["special_alias"] != baseline["special_alias"]
                or evidence["bag_uuid_matches"] is not True
                or type(evidence["command_raised"]) is not bool
                or (evidence["command_raised"] and evidence["command_status"] is not None)
            ):
                raise UserActivationJournalError("alias observation did not reconcile")
            phase = UserActivationPhase.ALIAS_OBSERVED
            continue
        if milestone == "USER_ALIAS_UNLOCK_INTENT":
            if phase not in {UserActivationPhase.BASELINE, UserActivationPhase.ALIAS_OBSERVED}:
                raise UserActivationJournalError("alias unlock intent is out of order")
            if phase is UserActivationPhase.BASELINE and not baseline["alias_preexisting"]:
                raise UserActivationJournalError("absent alias cannot be unlocked")
            evidence = _exact(
                evidence,
                {"runtime_generation", "special_alias", "mutation_possible"},
                milestone,
            )
            if (
                evidence["runtime_generation"] != baseline["runtime_generation"]
                or evidence["special_alias"] != baseline["special_alias"]
                or evidence["mutation_possible"] is not True
            ):
                raise UserActivationJournalError("alias unlock intent is not bound")
            phase = UserActivationPhase.UNLOCK_INTENT
            continue
        if milestone == "USER_ACTIVATION_READY":
            if phase not in {
                UserActivationPhase.ALIAS_OBSERVED,
                UserActivationPhase.UNLOCK_INTENT,
            }:
                raise UserActivationJournalError("ready observation is out of order")
            evidence = _exact(
                evidence,
                {
                    "runtime_generation",
                    "special_alias",
                    "bag_uuid_matches",
                    "readiness_state",
                    "source",
                    "command_status",
                    "command_raised",
                },
                milestone,
            )
            _status(evidence["command_status"], "unlock command status")
            if (
                evidence["runtime_generation"] != baseline["runtime_generation"]
                or evidence["special_alias"] != baseline["special_alias"]
                or evidence["bag_uuid_matches"] is not True
                or evidence["readiness_state"] != "ready"
                or evidence["source"]
                != (
                    "bind-readback"
                    if phase is UserActivationPhase.ALIAS_OBSERVED
                    else "unlock-readback"
                )
                or type(evidence["command_raised"]) is not bool
                or (evidence["command_raised"] and evidence["command_status"] is not None)
            ):
                raise UserActivationJournalError("ready observation is invalid")
            phase = UserActivationPhase.READY
            continue
        if milestone in {"USER_ACTIVATION_STOPPED", "USER_ACTIVATION_OUTCOME_UNKNOWN"}:
            if phase not in {
                UserActivationPhase.LOAD_INTENT,
                UserActivationPhase.HANDLE_OBSERVED,
                UserActivationPhase.BIND_INTENT,
                UserActivationPhase.ALIAS_OBSERVED,
                UserActivationPhase.UNLOCK_INTENT,
            }:
                raise UserActivationJournalError("activation stop is out of order")
            evidence = _exact(
                evidence,
                {"runtime_generation", "stage", "reason", "mutation_possible"},
                milestone,
            )
            stages = {
                UserActivationPhase.LOAD_INTENT: {"load", "handle"},
                UserActivationPhase.HANDLE_OBSERVED: {"handle", "bind"},
                UserActivationPhase.BIND_INTENT: {"bind", "readback"},
                UserActivationPhase.ALIAS_OBSERVED: {"bind", "unlock", "readback"},
                UserActivationPhase.UNLOCK_INTENT: {"unlock", "readback"},
            }
            if (
                evidence["runtime_generation"] != baseline["runtime_generation"]
                or evidence["stage"] not in stages[phase]
                or not isinstance(evidence["reason"], str)
                or not evidence["reason"]
                or evidence["mutation_possible"] is not True
            ):
                raise UserActivationJournalError("activation stop evidence is invalid")
            phase = (
                UserActivationPhase.STOPPED
                if milestone == "USER_ACTIVATION_STOPPED"
                else UserActivationPhase.OUTCOME_UNKNOWN
            )
            continue
        raise UserActivationJournalError("unknown activation journal milestone")

    return UserActivationHistory(
        operation_id,
        phase,
        baseline,
        temporary_handle,
        len(records),
        records[-1].get("record_hash", ""),
    )


def create(
    path: Path,
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    capability: str,
    persistent: t2_user_readiness.PersistentEvidence,
    alias: t2_user_readiness.AliasEvidence,
    *,
    linux_boot_uuid: str,
    runtime_generation: str,
) -> UserActivationHistory:
    decision = t2_user_readiness.assess(selected, capability, persistent, alias)
    if decision.state not in {
        "alias-absent",
        "device-locked",
        "before-first-unlock",
    }:
        raise UserActivationJournalError("mapping is not safely actionable")
    if selected not in mapping_set.mappings or mapping_set.generation == "":
        raise UserActivationJournalError("selected mapping is not in the mapping set")
    baseline = {
        "mapping_generation": mapping_set.generation,
        "linux_boot_uuid": linux_boot_uuid,
        "runtime_generation": runtime_generation,
        "target_linux_uid": selected.linux_uid,
        "apple_uid": selected.apple_uid,
        "account_uuid": selected.account_uuid,
        "bag_uuid": selected.bag_uuid,
        "keybag_sha256": selected.keybag_sha256,
        "special_alias": selected.special_bag_alias,
        "capability": capability,
        "initial_state": decision.state,
        "alias_preexisting": alias.present,
    }
    _validate_baseline(baseline)
    operation_id = str(uuid.uuid4())
    journal.append(
        path,
        operation_id,
        "USER_ACTIVATION_BASELINE",
        {"operation_kind": "user-activation", "baseline": baseline},
        exclusive=True,
    )
    return read(path)


def read(path: Path) -> UserActivationHistory:
    return validate_history(journal.read(path))


def append_checked(
    path: Path, operation_id: str, milestone: str, evidence: dict[str, Any]
) -> UserActivationHistory:
    records = journal.read(path)
    current = validate_history(records)
    if current.operation_id != operation_id:
        raise UserActivationJournalError("operation ID does not match activation journal")
    validate_history(
        [
            *records,
            {
                "operation_id": operation_id,
                "milestone": milestone,
                "evidence": evidence,
                "record_hash": "0" * 64,
            },
        ]
    )
    journal.append(
        path,
        operation_id,
        milestone,
        evidence,
        expected_record_count=current.record_count,
        expected_previous_hash=current.head_hash,
    )
    return read(path)
