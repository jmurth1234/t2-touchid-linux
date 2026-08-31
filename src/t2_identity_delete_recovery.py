# SPDX-License-Identifier: GPL-2.0-only
"""Fresh-state classifier for an interrupted SEP-first identity deletion."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import t2_catacomb_codec
import t2_identity_delete
import t2_identity_delete_journal as delete_journal
import t2_identity_inventory
import t2_mutation_journal


class IdentityDeleteRecoveryError(ValueError):
    pass


@dataclass(frozen=True)
class IdentityDeleteRecovery:
    outcome: str
    archive_state: str
    connection_generation: str
    snapshot_sha256: str
    identity_count: int


def _components(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        raise IdentityDeleteRecoveryError("host component inventory is absent")
    result = {}
    for record in value:
        if not isinstance(record, dict) or set(record) != {
            "name",
            "sha256",
            "mode",
            "uid",
            "gid",
        }:
            raise IdentityDeleteRecoveryError(
                "host component inventory is malformed"
            )
        if record["name"] in result:
            raise IdentityDeleteRecoveryError(
                "host component inventory is duplicated"
            )
        try:
            t2_mutation_journal.require_sha256(
                record["sha256"], "component hash"
            )
        except t2_mutation_journal.JournalError as error:
            raise IdentityDeleteRecoveryError(str(error)) from error
        result[record["name"]] = record
    return result


def _catacomb_state(
    live: dict[str, Any], baseline: dict[str, Any]
) -> tuple[dict[str, Any], bool]:
    catacomb = live.get("catacomb")
    states = catacomb.get("user_states") if isinstance(catacomb, dict) else None
    if (
        not isinstance(catacomb, dict)
        or catacomb.get("present") is not True
        or catacomb.get("uuid") != baseline["sep_catacomb"]["uuid"]
        or not isinstance(states, list)
    ):
        raise IdentityDeleteRecoveryError("SEP Catacomb binding changed")
    try:
        t2_mutation_journal.require_sha256(
            catacomb.get("hash"), "SEP Catacomb hash"
        )
    except t2_mutation_journal.JournalError as error:
        raise IdentityDeleteRecoveryError(str(error)) from error
    selected = [
        state
        for state in states
        if isinstance(state, dict)
        and state.get("kind") == "user"
        and state.get("user_id") == baseline["apple_uid"]
    ]
    masters = [
        state
        for state in states
        if isinstance(state, dict) and state.get("kind") == "master"
    ]
    if (
        len(selected) != 1
        or len(masters) != 1
        or masters[0].get("needs_save") is not False
        or not isinstance(selected[0].get("needs_save"), bool)
    ):
        raise IdentityDeleteRecoveryError("SEP Catacomb state is unsafe")
    return catacomb, selected[0]["needs_save"]


def _summarize_or_none(
    local: t2_catacomb_codec.UserCatacomb, live: dict[str, Any]
) -> dict[str, Any] | None:
    try:
        return t2_identity_inventory.summarize(local, live)
    except t2_identity_inventory.IdentityInventoryError:
        return None


def classify(
    history: delete_journal.IdentityDeleteHistory,
    *,
    local: t2_catacomb_codec.UserCatacomb,
    host: dict[str, Any],
    live: dict[str, Any],
    mapping_generation: str,
) -> IdentityDeleteRecovery:
    if (
        not isinstance(history, delete_journal.IdentityDeleteHistory)
        or history.phase is not delete_journal.IdentityDeletePhase.OUTCOME_UNKNOWN
        or history.recovery_action is None
        or history.target_identity_uuid is None
        or history.target_entity is None
        or history.target_name_sha256 is None
        or history.survivor_snapshot_sha256 is None
    ):
        raise IdentityDeleteRecoveryError("delete journal is not recoverable")
    baseline = history.baseline
    generation = live.get("connection_generation")
    if (
        generation == baseline["connection_generation"]
        or mapping_generation != baseline["mapping_generation"]
        or local.expected_user_id != baseline["apple_uid"]
    ):
        raise IdentityDeleteRecoveryError(
            "delete recovery binding did not advance"
        )
    try:
        t2_mutation_journal.require_uuid(
            generation, "recovery connection generation"
        )
    except t2_mutation_journal.JournalError as error:
        raise IdentityDeleteRecoveryError(str(error)) from error
    if (
        host.get("account_uuid") != baseline["account_uuid"]
        or host.get("bag_uuid") != baseline["bag_uuid"]
        or host.get("master_enrollment_count")
        != baseline["master_enrollment_count"]
    ):
        raise IdentityDeleteRecoveryError(
            "delete changed account, keybag, or master enrollment count"
        )

    baseline_pairs = {
        (record["user_id"], record["uuid"], record["entity"])
        for record in baseline["identity_records"]
    }
    survivor_pairs = {
        pair for pair in baseline_pairs if pair[1] != history.target_identity_uuid
    }
    if len(survivor_pairs) != len(baseline_pairs) - 1:
        raise IdentityDeleteRecoveryError("delete target is not unique in baseline")
    local_pairs = {
        (identity.user_id, identity.uuid, identity.entity)
        for identity in local.identities
    }
    host_records = host.get("identity_records")
    if not isinstance(host_records, list) or any(
        not isinstance(record, dict)
        or set(record) != {"user_id", "uuid", "entity"}
        for record in host_records
    ):
        raise IdentityDeleteRecoveryError("host identity inventory is malformed")
    host_pairs = {
        (record["user_id"], record["uuid"], record["entity"])
        for record in host_records
    }
    if host_pairs != local_pairs:
        raise IdentityDeleteRecoveryError(
            "host identity inventory differs from the committed archive"
        )

    before = _components(baseline["host_components"])
    after = _components(host.get("host_components"))
    if set(before) != set(after):
        raise IdentityDeleteRecoveryError("delete changed the component set")
    for name in before:
        if any(
            before[name][field] != after[name][field]
            for field in ("mode", "uid", "gid")
        ):
            raise IdentityDeleteRecoveryError(
                "delete changed component ownership or mode"
            )
    catacomb, user_needs_save = _catacomb_state(live, baseline)
    user_name = f'user_{baseline["apple_uid"]:08x}.cat'
    staged = dict(history.persistence.staged_files)
    forward_persistence = (
        history.persistence_connection_generation
        != baseline["connection_generation"]
        and set(staged) == {user_name}
    )

    plan = None
    if local_pairs == baseline_pairs:
        try:
            plan = t2_identity_delete.plan_target(
                local, history.target_identity_uuid
            )
        except t2_identity_delete.IdentityDeleteError as error:
            raise IdentityDeleteRecoveryError(
                "baseline archive cannot reconstruct the delete plan"
            ) from error
        if (
            plan.entity != history.target_entity
            or hashlib.sha256(plan.name.encode("utf-8")).hexdigest()
            != history.target_name_sha256
            or plan.survivor_snapshot_sha256
            != history.survivor_snapshot_sha256
        ):
            raise IdentityDeleteRecoveryError(
                "reconstructed delete plan differs from the journal"
            )

    host_baseline_equal = all(
        after[name]["sha256"] == before[name]["sha256"] for name in before
    )
    unchanged_summary = (
        _summarize_or_none(local, live)
        if local_pairs == baseline_pairs
        else None
    )
    unchanged = (
        unchanged_summary is not None
        and host_baseline_equal
        and catacomb["hash"] == baseline["sep_catacomb"]["hash"]
        and user_needs_save is False
        and history.recovery_action != "commit-rolled-forward"
    )

    committed_summary = (
        _summarize_or_none(local, live)
        if local_pairs == survivor_pairs
        else None
    )
    committed = (
        committed_summary is not None
        and t2_identity_delete.survivor_snapshot_sha256(local.identities)
        == history.survivor_snapshot_sha256
        and set(staged) == {user_name}
        and after[user_name]["sha256"] == staged[user_name]
        and all(
            after[name]["sha256"] == before[name]["sha256"]
            for name in before
            if name != user_name
        )
        and user_needs_save is False
        and (
            history.recovery_action != "prepare-discarded"
            or forward_persistence
        )
    )

    baseline_forward_summary = None
    if plan is not None:
        try:
            planned_local = t2_catacomb_codec.decode_user_catacomb(
                plan.archive, plan.apple_user_id
            )
        except t2_catacomb_codec.CatacombCodecError as error:
            raise IdentityDeleteRecoveryError(
                "reconstructed survivor archive is invalid"
            ) from error
        baseline_forward_summary = _summarize_or_none(planned_local, live)
    baseline_forward = (
        baseline_forward_summary is not None
        and host_baseline_equal
        and user_needs_save is True
        and history.recovery_action != "commit-rolled-forward"
    )
    survivor_forward = (
        committed_summary is not None
        and t2_identity_delete.survivor_snapshot_sha256(local.identities)
        == history.survivor_snapshot_sha256
        and set(staged) == {user_name}
        and after[user_name]["sha256"] == staged[user_name]
        and all(
            after[name]["sha256"] == before[name]["sha256"]
            for name in before
            if name != user_name
        )
        and user_needs_save is True
        and (
            history.recovery_action != "prepare-discarded"
            or forward_persistence
        )
    )
    forward = baseline_forward or survivor_forward
    outcomes = [unchanged, committed, forward]
    if sum(outcomes) != 1:
        raise IdentityDeleteRecoveryError(
            "fresh state is not a unique unchanged, committed, or forward-repair state"
        )
    outcome = (
        "no-change" if unchanged else "committed" if committed else "forward-required"
    )
    archive_state = "baseline" if unchanged or baseline_forward else "survivors"
    summary = (
        unchanged_summary
        or committed_summary
        or baseline_forward_summary
    )
    snapshot = {
        "outcome": outcome,
        "connection_generation": generation,
        "account_uuid": host["account_uuid"],
        "bag_uuid": host["bag_uuid"],
        "survivor_snapshot_sha256": history.survivor_snapshot_sha256,
        "host_components": [after[name] for name in sorted(after)],
        "sep_catacomb_uuid": catacomb["uuid"],
        "sep_catacomb_hash": catacomb["hash"],
        "mapping_generation": mapping_generation,
        "recovery_action": history.recovery_action,
    }
    return IdentityDeleteRecovery(
        outcome,
        archive_state,
        generation,
        hashlib.sha256(t2_mutation_journal.canonical(snapshot)).hexdigest(),
        summary["identity_count"],
    )


def append_observed(
    path: Path,
    operation_id: str,
    recovery: IdentityDeleteRecovery,
    *,
    mapping_generation: str,
) -> delete_journal.IdentityDeleteHistory:
    history = delete_journal.read(path)
    if history.operation_id != operation_id or not isinstance(
        recovery, IdentityDeleteRecovery
    ):
        raise IdentityDeleteRecoveryError(
            "delete recovery append binding changed"
        )
    expected_archive_states = (
        {"baseline"}
        if recovery.outcome == "no-change"
        else {"survivors"}
        if recovery.outcome == "committed"
        else {"baseline", "survivors"}
        if recovery.outcome == "forward-required"
        else set()
    )
    if recovery.archive_state not in expected_archive_states:
        raise IdentityDeleteRecoveryError(
            "delete recovery archive state differs from its outcome"
        )
    common = {
        "connection_generation": recovery.connection_generation,
        "identity_uuid": history.target_identity_uuid,
        "mapping_generation": mapping_generation,
        "recovery_action": history.recovery_action,
    }
    if recovery.outcome == "forward-required":
        return delete_journal.append_checked(
            path,
            operation_id,
            "DELETE_RECOVERY_SEP_ABSENCE_OBSERVED",
            {
                **common,
                "survivor_snapshot_sha256": history.survivor_snapshot_sha256,
                "survivor_count": recovery.identity_count,
                "target_absent": True,
                "local_archive_state": recovery.archive_state,
                "host_archive_state": recovery.archive_state,
                "sep_user_needs_save": True,
                "sep_master_clean": True,
                "stable_double_read": True,
            },
        )
    if recovery.outcome not in {"no-change", "committed"}:
        raise IdentityDeleteRecoveryError("delete recovery outcome is invalid")
    committed = recovery.outcome == "committed"
    return delete_journal.append_checked(
        path,
        operation_id,
        (
            "DELETE_RECOVERY_RECONCILED_COMMITTED"
            if committed
            else "DELETE_RECOVERY_RECONCILED_NO_CHANGE"
        ),
        {
            **common,
            "snapshot_sha256": recovery.snapshot_sha256,
            "identity_count": recovery.identity_count,
            "target_absent": committed,
            "local_live_equal": True,
            "host_reconciled": True,
            "sep_clean": True,
        },
    )
