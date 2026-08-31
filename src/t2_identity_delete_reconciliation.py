# SPDX-License-Identifier: GPL-2.0-only
"""Independent read-back classifier for a persisted identity deletion."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import t2_catacomb_codec
import t2_enrollment_persistence_journal
import t2_identity_delete
import t2_identity_delete_journal as delete_journal
import t2_identity_inventory
import t2_mutation_journal


class IdentityDeleteReconciliationError(ValueError):
    pass


@dataclass(frozen=True)
class IdentityDeleteReconciliation:
    connection_generation: str
    snapshot_sha256: str
    identity_count: int


def _component_map(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        raise IdentityDeleteReconciliationError("host component inventory is absent")
    result = {}
    for record in value:
        if not isinstance(record, dict) or set(record) != {
            "name",
            "sha256",
            "mode",
            "uid",
            "gid",
        }:
            raise IdentityDeleteReconciliationError(
                "host component inventory is malformed"
            )
        if record["name"] in result:
            raise IdentityDeleteReconciliationError(
                "host component inventory is duplicated"
            )
        try:
            t2_mutation_journal.require_sha256(record["sha256"], "component hash")
        except t2_mutation_journal.JournalError as error:
            raise IdentityDeleteReconciliationError(str(error)) from error
        result[record["name"]] = record
    return result


def classify(
    history: delete_journal.IdentityDeleteHistory,
    plan: t2_identity_delete.IdentityDeletePlan,
    *,
    local: t2_catacomb_codec.UserCatacomb,
    host: dict[str, Any],
    live: dict[str, Any],
    mapping_generation: str,
) -> IdentityDeleteReconciliation:
    if (
        not isinstance(history, delete_journal.IdentityDeleteHistory)
        or history.phase is not delete_journal.IdentityDeletePhase.PERSISTING
        or history.persistence.phase
        is not t2_enrollment_persistence_journal.PersistencePhase.ATTESTATION_READY
    ):
        raise IdentityDeleteReconciliationError(
            "delete journal is not ready for read-back"
        )
    baseline = history.baseline
    if (
        history.target_identity_uuid != plan.identity_uuid
        or history.target_entity != plan.entity
        or history.survivor_snapshot_sha256 != plan.survivor_snapshot_sha256
        or baseline["apple_uid"] != plan.apple_user_id
        or live.get("connection_generation") != baseline["connection_generation"]
        or mapping_generation != baseline["mapping_generation"]
    ):
        raise IdentityDeleteReconciliationError("delete read-back binding changed")
    if (
        host.get("account_uuid") != baseline["account_uuid"]
        or host.get("bag_uuid") != baseline["bag_uuid"]
        or host.get("master_enrollment_count")
        != baseline["master_enrollment_count"]
    ):
        raise IdentityDeleteReconciliationError(
            "delete changed account, keybag, or master enrollment count"
        )
    try:
        expected = t2_catacomb_codec.decode_user_catacomb(
            plan.archive, plan.apple_user_id
        )
        public = t2_identity_inventory.summarize(local, live)
    except (
        t2_catacomb_codec.CatacombCodecError,
        t2_identity_inventory.IdentityInventoryError,
    ) as error:
        raise IdentityDeleteReconciliationError(
            "deleted local and live identities do not reconcile"
        ) from error
    if (
        local.identities != expected.identities
        or plan.identity_uuid in {identity.uuid for identity in local.identities}
        or t2_identity_delete.survivor_snapshot_sha256(local.identities)
        != plan.survivor_snapshot_sha256
    ):
        raise IdentityDeleteReconciliationError(
            "committed archive differs from the deletion plan"
        )

    expected_pairs = {
        (identity.user_id, identity.uuid, identity.entity)
        for identity in expected.identities
    }
    host_records = host.get("identity_records")
    if not isinstance(host_records, list) or any(
        not isinstance(record, dict)
        or set(record) != {"user_id", "uuid", "entity"}
        for record in host_records
    ):
        raise IdentityDeleteReconciliationError("host identity inventory is malformed")
    host_pairs = {
        (record["user_id"], record["uuid"], record["entity"])
        for record in host_records
    }
    if host_pairs != expected_pairs:
        raise IdentityDeleteReconciliationError("host survivor set differs")

    before = _component_map(baseline["host_components"])
    after = _component_map(host.get("host_components"))
    if set(before) != set(after):
        raise IdentityDeleteReconciliationError("delete changed the component set")
    user_name = f'user_{plan.apple_user_id:08x}.cat'
    for name in before:
        if any(before[name][field] != after[name][field] for field in ("mode", "uid", "gid")):
            raise IdentityDeleteReconciliationError(
                "delete changed component ownership or mode"
            )
        if name != user_name and before[name]["sha256"] != after[name]["sha256"]:
            raise IdentityDeleteReconciliationError(
                "delete changed an unrelated Catacomb component"
            )
    staged = dict(history.persistence.staged_files)
    if (
        set(staged) != {user_name}
        or staged[user_name] != after[user_name]["sha256"]
        or before[user_name]["sha256"] == after[user_name]["sha256"]
    ):
        raise IdentityDeleteReconciliationError(
            "committed user Catacomb differs from the journaled deletion"
        )

    catacomb = live.get("catacomb")
    states = catacomb.get("user_states") if isinstance(catacomb, dict) else None
    if (
        not isinstance(catacomb, dict)
        or catacomb.get("present") is not True
        or catacomb.get("uuid") != baseline["sep_catacomb"]["uuid"]
        or not isinstance(states, list)
    ):
        raise IdentityDeleteReconciliationError("delete rebound the SEP Catacomb")
    try:
        t2_mutation_journal.require_sha256(catacomb.get("hash"), "SEP Catacomb hash")
    except t2_mutation_journal.JournalError as error:
        raise IdentityDeleteReconciliationError(str(error)) from error
    selected = [
        state
        for state in states
        if isinstance(state, dict)
        and state.get("kind") == "user"
        and state.get("user_id") == plan.apple_user_id
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
        raise IdentityDeleteReconciliationError(
            "SEP Catacomb is not clean after deletion"
        )
    snapshot = {
        "connection_generation": live["connection_generation"],
        "account_uuid": host["account_uuid"],
        "bag_uuid": host["bag_uuid"],
        "survivor_snapshot_sha256": plan.survivor_snapshot_sha256,
        "host_components": [after[name] for name in sorted(after)],
        "sep_catacomb_uuid": catacomb["uuid"],
        "sep_catacomb_hash": catacomb["hash"],
        "mapping_generation": mapping_generation,
    }
    return IdentityDeleteReconciliation(
        live["connection_generation"],
        hashlib.sha256(t2_mutation_journal.canonical(snapshot)).hexdigest(),
        public["identity_count"],
    )
