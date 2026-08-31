# SPDX-License-Identifier: GPL-2.0-only
"""Independent read-back classifier for a completed identity-label rename."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import t2_catacomb_codec
import t2_enrollment_persistence_journal
import t2_identity_inventory
import t2_identity_rename
import t2_identity_rename_journal as rename_journal
import t2_mutation_journal


class IdentityRenameReconciliationError(ValueError):
    pass


@dataclass(frozen=True)
class IdentityRenameReconciliation:
    connection_generation: str
    snapshot_sha256: str
    identity_count: int
    identity_set_unchanged: bool = True
    label_updated: bool = True
    local_live_equal: bool = True


def _component_map(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list):
        raise IdentityRenameReconciliationError("host component inventory is absent")
    result = {}
    for record in value:
        if not isinstance(record, dict) or set(record) != {
            "name",
            "sha256",
            "mode",
            "uid",
            "gid",
        }:
            raise IdentityRenameReconciliationError(
                "host component inventory is malformed"
            )
        if record["name"] in result:
            raise IdentityRenameReconciliationError(
                "host component inventory is duplicated"
            )
        try:
            t2_mutation_journal.require_sha256(record["sha256"], "component hash")
        except t2_mutation_journal.JournalError as error:
            raise IdentityRenameReconciliationError(str(error)) from error
        result[record["name"]] = record
    return result


def classify(
    history: rename_journal.IdentityRenameHistory,
    plan: t2_identity_rename.IdentityRenamePlan,
    *,
    local: t2_catacomb_codec.UserCatacomb,
    host: dict[str, Any],
    live: dict[str, Any],
    mapping_generation: str,
) -> IdentityRenameReconciliation:
    if (
        not isinstance(history, rename_journal.IdentityRenameHistory)
        or history.phase is not rename_journal.IdentityRenamePhase.PERSISTING
        or history.persistence.phase
        is not t2_enrollment_persistence_journal.PersistencePhase.ATTESTATION_READY
    ):
        raise IdentityRenameReconciliationError(
            "rename journal is not ready for read-back"
        )
    baseline = history.baseline
    if (
        history.target_identity_uuid != plan.identity_uuid
        or history.target_entity != plan.entity
        or baseline["apple_uid"] != plan.apple_user_id
        or live.get("connection_generation") != baseline["connection_generation"]
        or mapping_generation != baseline["mapping_generation"]
    ):
        raise IdentityRenameReconciliationError("rename read-back binding changed")
    if (
        host.get("account_uuid") != baseline["account_uuid"]
        or host.get("bag_uuid") != baseline["bag_uuid"]
        or host.get("master_enrollment_count")
        != baseline["master_enrollment_count"]
    ):
        raise IdentityRenameReconciliationError(
            "rename changed account, keybag, or enrollment count"
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
        raise IdentityRenameReconciliationError(
            "renamed local and live identities do not reconcile"
        ) from error
    if local.identities != expected.identities:
        raise IdentityRenameReconciliationError(
            "committed archive differs from the rename plan"
        )

    baseline_pairs = {
        (record["user_id"], record["uuid"], record["entity"])
        for record in baseline["identity_records"]
    }
    host_pairs = {
        (record["user_id"], record["uuid"], record["entity"])
        for record in host.get("identity_records", [])
        if isinstance(record, dict)
        and set(record) == {"user_id", "uuid", "entity"}
    }
    local_pairs = {
        (identity.user_id, identity.uuid, identity.entity)
        for identity in local.identities
    }
    if baseline_pairs != host_pairs or host_pairs != local_pairs:
        raise IdentityRenameReconciliationError("rename changed the identity set")

    before_components = _component_map(baseline["host_components"])
    after_components = _component_map(host.get("host_components"))
    if set(before_components) != set(after_components):
        raise IdentityRenameReconciliationError("rename changed the component set")
    user_name = f'user_{plan.apple_user_id:08x}.cat'
    for name in before_components:
        before = before_components[name]
        after = after_components[name]
        if any(before[field] != after[field] for field in ("mode", "uid", "gid")):
            raise IdentityRenameReconciliationError(
                "rename changed component ownership or mode"
            )
        if name != user_name and before["sha256"] != after["sha256"]:
            raise IdentityRenameReconciliationError(
                "rename changed an unrelated Catacomb component"
            )
    if before_components[user_name]["sha256"] == after_components[user_name]["sha256"]:
        raise IdentityRenameReconciliationError(
            "rename did not change the user Catacomb"
        )

    catacomb = live.get("catacomb")
    if (
        not isinstance(catacomb, dict)
        or catacomb.get("present") is not True
        or catacomb.get("uuid") != baseline["sep_catacomb"]["uuid"]
    ):
        raise IdentityRenameReconciliationError("rename rebound the SEP Catacomb")
    try:
        t2_mutation_journal.require_sha256(
            catacomb.get("hash"), "SEP Catacomb hash"
        )
    except t2_mutation_journal.JournalError as error:
        raise IdentityRenameReconciliationError(str(error)) from error
    states = catacomb.get("user_states")
    if not isinstance(states, list):
        raise IdentityRenameReconciliationError("SEP Catacomb states are absent")
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
        raise IdentityRenameReconciliationError(
            "SEP Catacomb is not clean after rename"
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
        "connection_generation": live["connection_generation"],
        "account_uuid": host["account_uuid"],
        "bag_uuid": host["bag_uuid"],
        "labels": labels,
        "host_components": [after_components[name] for name in sorted(after_components)],
        "sep_catacomb_uuid": catacomb["uuid"],
        "sep_catacomb_hash": catacomb["hash"],
        "mapping_generation": mapping_generation,
    }
    return IdentityRenameReconciliation(
        live["connection_generation"],
        hashlib.sha256(t2_mutation_journal.canonical(snapshot)).hexdigest(),
        public["identity_count"],
    )
