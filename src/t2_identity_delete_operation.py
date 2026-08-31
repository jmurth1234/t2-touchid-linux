# SPDX-License-Identifier: GPL-2.0-only
"""Journaled SEP-first execution boundary for one identity deletion."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import t2_catacomb_codec
import t2_identity_delete
import t2_identity_delete_bridge
import t2_identity_delete_journal as delete_journal
import t2_identity_inventory


class IdentityDeleteOperationError(RuntimeError):
    pass


@dataclass(frozen=True)
class IdentityDeleteOperationResult:
    outcome: str
    command_status: int


InventoryCollector = Callable[[], dict[str, object]]


def _append(path, operation_id, milestone, evidence):
    return delete_journal.append_checked(path, operation_id, milestone, evidence)


def _freeze(
    path: Path,
    operation_id: str,
    generation: str,
    *,
    stage: str,
    reason: str,
    cause: BaseException | None = None,
) -> None:
    try:
        _append(
            path,
            operation_id,
            "DELETE_OUTCOME_UNKNOWN",
            {
                "connection_generation": generation,
                "stage": stage,
                "reason": reason,
                "mutation_possible": True,
            },
        )
    except BaseException:
        pass
    error = IdentityDeleteOperationError(
        f"identity deletion stopped at {stage}; reconciliation is required"
    )
    if cause is None:
        raise error
    raise error from cause


def run(
    path: Path,
    operation_id: str,
    *,
    plan: t2_identity_delete.IdentityDeletePlan,
    local: t2_catacomb_codec.UserCatacomb,
    bridge: t2_identity_delete_bridge.IdentityDeleteBridge,
    collect_inventory: InventoryCollector,
) -> IdentityDeleteOperationResult:
    history = delete_journal.read(path)
    generation = history.baseline["connection_generation"]
    if (
        history.operation_id != operation_id
        or history.phase is not delete_journal.IdentityDeletePhase.INTENT
        or history.target_identity_uuid != plan.identity_uuid
        or history.target_entity != plan.entity
        or history.request_sha256 != hashlib.sha256(plan.request).hexdigest()
        or history.survivor_snapshot_sha256 != plan.survivor_snapshot_sha256
        or history.baseline["apple_uid"] != plan.apple_user_id
        or bridge.connection_generation != generation
        or local.expected_user_id != plan.apple_user_id
    ):
        raise IdentityDeleteOperationError("identity delete plan differs from durable intent")
    _append(
        path,
        operation_id,
        "DELETE_DISPATCH_INTENT",
        {
            "connection_generation": generation,
            "identity_uuid": plan.identity_uuid,
            "request_sha256": history.request_sha256,
            "command": 0x0D,
            "protocol_version": 0,
        },
    )
    try:
        command = bridge.delete(plan.request)
    except BaseException as error:
        _freeze(
            path,
            operation_id,
            generation,
            stage="dispatch",
            reason="transport-error",
            cause=error,
        )
    _append(
        path,
        operation_id,
        "DELETE_COMMAND_OBSERVED",
        {
            "connection_generation": generation,
            "identity_uuid": plan.identity_uuid,
            "status": command.status,
            "output_length": command.output_length,
            "service_event_count": command.service_event_count,
        },
    )
    try:
        live = collect_inventory()
    except BaseException as error:
        _freeze(
            path,
            operation_id,
            generation,
            stage="readback",
            reason="inventory-error",
            cause=error,
        )
    if live.get("connection_generation") != generation:
        _freeze(
            path,
            operation_id,
            generation,
            stage="readback",
            reason="inventory-error",
        )

    planned_local = t2_catacomb_codec.decode_user_catacomb(
        plan.archive, plan.apple_user_id
    )
    try:
        survivor_summary = t2_identity_inventory.summarize(planned_local, live)
    except t2_identity_inventory.IdentityInventoryError:
        survivor_summary = None
    if survivor_summary is not None:
        _append(
            path,
            operation_id,
            "DELETE_SEP_ABSENCE_OBSERVED",
            {
                "connection_generation": generation,
                "identity_uuid": plan.identity_uuid,
                "survivor_snapshot_sha256": plan.survivor_snapshot_sha256,
                "survivor_count": survivor_summary["identity_count"],
                "stable_double_read": True,
                "per_user_global_equal": True,
                "target_absent": True,
            },
        )
        return IdentityDeleteOperationResult("sep-deleted", command.status)

    try:
        original_summary = t2_identity_inventory.summarize(local, live)
    except t2_identity_inventory.IdentityInventoryError:
        original_summary = None
    catacomb = live.get("catacomb")
    exact_no_change = (
        original_summary is not None
        and original_summary["identity_count"]
        == len(history.baseline["identity_records"])
        and isinstance(catacomb, dict)
        and catacomb.get("uuid") == history.baseline["sep_catacomb"]["uuid"]
        and catacomb.get("hash") == history.baseline["sep_catacomb"]["hash"]
    )
    if command.status != 0 and exact_no_change:
        _append(
            path,
            operation_id,
            "DELETE_NOT_PERFORMED",
            {
                "connection_generation": generation,
                "identity_uuid": plan.identity_uuid,
                "command_failed": True,
                "target_present": True,
                "baseline_identity_set_equal": True,
                "sep_catacomb_unchanged": True,
                "stable_double_read": True,
            },
        )
        return IdentityDeleteOperationResult("not-deleted", command.status)
    _freeze(
        path,
        operation_id,
        generation,
        stage="readback",
        reason="readback-error",
    )
