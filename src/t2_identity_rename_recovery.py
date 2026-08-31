# SPDX-License-Identifier: GPL-2.0-only
"""Fresh-observation classifier for an interrupted identity-label transaction."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import t2_catacomb_codec
import t2_identity_inventory
import t2_identity_rename_journal as rename_journal
import t2_mutation_journal


class IdentityRenameRecoveryError(ValueError):
    pass


@dataclass(frozen=True)
class IdentityRenameRecovery:
    outcome: str
    connection_generation: str
    name_sha256: str
    snapshot_sha256: str
    identity_count: int


def _components(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        raise IdentityRenameRecoveryError("host component inventory is absent")
    result = {}
    for record in value:
        if not isinstance(record, dict) or set(record) != {
            "name",
            "sha256",
            "mode",
            "uid",
            "gid",
        }:
            raise IdentityRenameRecoveryError("host component inventory is malformed")
        if record["name"] in result:
            raise IdentityRenameRecoveryError("host component inventory is duplicated")
        try:
            t2_mutation_journal.require_sha256(record["sha256"], "component hash")
        except t2_mutation_journal.JournalError as error:
            raise IdentityRenameRecoveryError(str(error)) from error
        result[record["name"]] = record
    return result


def classify(
    history: rename_journal.IdentityRenameHistory,
    *,
    local: t2_catacomb_codec.UserCatacomb,
    host: dict[str, Any],
    live: dict[str, Any],
    mapping_generation: str,
) -> IdentityRenameRecovery:
    if (
        not isinstance(history, rename_journal.IdentityRenameHistory)
        or history.phase is not rename_journal.IdentityRenamePhase.OUTCOME_UNKNOWN
        or history.recovery_action is None
        or history.target_identity_uuid is None
        or history.previous_name_sha256 is None
        or history.new_name_sha256 is None
    ):
        raise IdentityRenameRecoveryError("rename journal is not recoverable")
    baseline = history.baseline
    generation = live.get("connection_generation")
    if (
        generation == baseline["connection_generation"]
        or mapping_generation != baseline["mapping_generation"]
        or local.expected_user_id != baseline["apple_uid"]
    ):
        raise IdentityRenameRecoveryError("rename recovery binding did not advance")
    try:
        t2_mutation_journal.require_uuid(generation, "recovery connection generation")
        public = t2_identity_inventory.summarize(local, live)
    except (
        t2_mutation_journal.JournalError,
        t2_identity_inventory.IdentityInventoryError,
    ) as error:
        raise IdentityRenameRecoveryError(
            "rename recovery inventory does not reconcile"
        ) from error

    baseline_pairs = {
        (record["user_id"], record["uuid"], record["entity"])
        for record in baseline["identity_records"]
    }
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
        raise IdentityRenameRecoveryError("host identity inventory is malformed")
    host_pairs = {
        (record["user_id"], record["uuid"], record["entity"])
        for record in host_records
    }
    if baseline_pairs != local_pairs or local_pairs != host_pairs:
        raise IdentityRenameRecoveryError("rename changed the identity set")
    targets = [
        identity
        for identity in local.identities
        if identity.uuid == history.target_identity_uuid
        and identity.entity == history.target_entity
    ]
    if len(targets) != 1:
        raise IdentityRenameRecoveryError("rename target is no longer unique")
    name_hash = hashlib.sha256(targets[0].name.encode("utf-8")).hexdigest()

    if (
        host.get("account_uuid") != baseline["account_uuid"]
        or host.get("bag_uuid") != baseline["bag_uuid"]
        or host.get("master_enrollment_count")
        != baseline["master_enrollment_count"]
    ):
        raise IdentityRenameRecoveryError(
            "rename changed account, keybag, or enrollment count"
        )
    before = _components(baseline["host_components"])
    after = _components(host.get("host_components"))
    if set(before) != set(after):
        raise IdentityRenameRecoveryError("rename changed the component set")
    for name in before:
        if any(before[name][field] != after[name][field] for field in ("mode", "uid", "gid")):
            raise IdentityRenameRecoveryError("rename changed component metadata")

    catacomb = live.get("catacomb")
    states = catacomb.get("user_states") if isinstance(catacomb, dict) else None
    if (
        not isinstance(catacomb, dict)
        or catacomb.get("present") is not True
        or catacomb.get("uuid") != baseline["sep_catacomb"]["uuid"]
        or not isinstance(states, list)
    ):
        raise IdentityRenameRecoveryError("SEP Catacomb binding changed")
    try:
        t2_mutation_journal.require_sha256(catacomb.get("hash"), "SEP Catacomb hash")
    except t2_mutation_journal.JournalError as error:
        raise IdentityRenameRecoveryError(str(error)) from error
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
        or selected[0].get("needs_save") is not False
        or masters[0].get("needs_save") is not False
    ):
        raise IdentityRenameRecoveryError("SEP Catacomb is not clean")

    user_name = f'user_{baseline["apple_uid"]:08x}.cat'
    staged = dict(history.persistence.staged_files)
    unchanged = (
        name_hash == history.previous_name_sha256
        and all(after[name]["sha256"] == before[name]["sha256"] for name in before)
        and catacomb["hash"] == baseline["sep_catacomb"]["hash"]
        and history.recovery_action != "commit-rolled-forward"
    )
    committed = (
        name_hash == history.new_name_sha256
        and set(staged) == {user_name}
        and after[user_name]["sha256"] == staged[user_name]
        and all(
            after[name]["sha256"] == before[name]["sha256"]
            for name in before
            if name != user_name
        )
        and history.recovery_action != "prepare-discarded"
    )
    if unchanged == committed:
        raise IdentityRenameRecoveryError(
            "fresh state is neither uniquely unchanged nor committed"
        )
    labels = [
        {
            "user_id": identity.user_id,
            "identity_uuid": identity.uuid,
            "entity": identity.entity,
            "name_sha256": hashlib.sha256(identity.name.encode("utf-8")).hexdigest(),
        }
        for identity in sorted(local.identities, key=lambda value: value.entity)
    ]
    snapshot = {
        "connection_generation": generation,
        "account_uuid": host["account_uuid"],
        "bag_uuid": host["bag_uuid"],
        "labels": labels,
        "host_components": [after[name] for name in sorted(after)],
        "sep_catacomb_uuid": catacomb["uuid"],
        "sep_catacomb_hash": catacomb["hash"],
        "mapping_generation": mapping_generation,
        "recovery_action": history.recovery_action,
    }
    return IdentityRenameRecovery(
        "committed" if committed else "no-change",
        generation,
        name_hash,
        hashlib.sha256(t2_mutation_journal.canonical(snapshot)).hexdigest(),
        public["identity_count"],
    )


def append_reconciled(
    path,
    operation_id: str,
    recovery: IdentityRenameRecovery,
    *,
    mapping_generation: str,
) -> rename_journal.IdentityRenameHistory:
    history = rename_journal.read(path)
    if history.operation_id != operation_id or not isinstance(
        recovery, IdentityRenameRecovery
    ):
        raise IdentityRenameRecoveryError("rename recovery append binding changed")
    milestone = (
        "RENAME_RECOVERY_RECONCILED_COMMITTED"
        if recovery.outcome == "committed"
        else "RENAME_RECOVERY_RECONCILED_NO_CHANGE"
    )
    return rename_journal.append_checked(
        path,
        operation_id,
        milestone,
        {
            "connection_generation": recovery.connection_generation,
            "identity_uuid": history.target_identity_uuid,
            "name_sha256": recovery.name_sha256,
            "snapshot_sha256": recovery.snapshot_sha256,
            "mapping_generation": mapping_generation,
            "identity_count": recovery.identity_count,
            "identity_set_unchanged": True,
            "local_live_equal": True,
            "sep_clean": True,
            "host_reconciled": True,
            "recovery_action": history.recovery_action,
        },
    )
