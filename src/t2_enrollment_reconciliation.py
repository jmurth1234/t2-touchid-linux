# SPDX-License-Identifier: GPL-2.0-only
"""Strict E3 classifier for stable post-enrollment host and SEP snapshots."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import t2_enrollment_journal as enrollment_journal
import t2_enrollment_persistence_journal as persistence_journal
import t2_mutation_journal as mutation_journal


class EnrollmentReconciliationError(ValueError):
    pass


@dataclass(frozen=True, repr=False)
class ReconciliationPlan:
    evidence: dict[str, Any] | None
    readback_identity_uuid: str | None


def _identity_pairs(
    records: Any,
    uuid_key: str,
    apple_uid: int,
    *,
    expected_keys: set[str],
    require_entity: bool = False,
) -> set[tuple[int, str]]:
    if not isinstance(records, list):
        raise EnrollmentReconciliationError("identity inventory is not a list")
    result: set[tuple[int, str]] = set()
    entities: set[int] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != expected_keys:
            raise EnrollmentReconciliationError("identity inventory row is malformed")
        user_id = record.get("user_id")
        identity_uuid = record.get(uuid_key)
        if user_id != apple_uid:
            raise EnrollmentReconciliationError("identity belongs to another Apple user")
        try:
            mutation_journal.require_uuid(identity_uuid, "identity UUID")
        except mutation_journal.JournalError as error:
            raise EnrollmentReconciliationError(str(error)) from error
        pair = (user_id, identity_uuid)
        if pair in result:
            raise EnrollmentReconciliationError("identity inventory contains a duplicate")
        result.add(pair)
        if require_entity:
            entity = record.get("entity")
            if (
                not isinstance(entity, int)
                or isinstance(entity, bool)
                or entity < 0
                or entity in entities
            ):
                raise EnrollmentReconciliationError(
                    "host identity entity is invalid or duplicated"
                )
            entities.add(entity)
    return result


def _configured_global_pairs(records: Any, apple_uid: int) -> set[tuple[int, str]]:
    if not isinstance(records, list):
        raise EnrollmentReconciliationError("global identity inventory is missing")
    selected = []
    seen: set[tuple[int, str, int, str]] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "user_id",
            "identity_uuid",
            "group_type",
            "group_uuid",
        }:
            raise EnrollmentReconciliationError("global identity row is malformed")
        user_id = record["user_id"]
        group_type = record["group_type"]
        if (
            not isinstance(user_id, int)
            or isinstance(user_id, bool)
            or user_id < 0
            or not isinstance(group_type, int)
            or isinstance(group_type, bool)
            or group_type < 0
        ):
            raise EnrollmentReconciliationError("global identity row is malformed")
        try:
            mutation_journal.require_uuid(record["identity_uuid"], "identity UUID")
            mutation_journal.require_uuid(record["group_uuid"], "group UUID")
        except mutation_journal.JournalError as error:
            raise EnrollmentReconciliationError(str(error)) from error
        key = (user_id, record["identity_uuid"], group_type, record["group_uuid"])
        if key in seen:
            raise EnrollmentReconciliationError(
                "global identity inventory contains a duplicate"
            )
        seen.add(key)
        if user_id == apple_uid:
            if group_type not in (0, 1) or uuid.UUID(
                record["group_uuid"]
            ).int != 0:
                raise EnrollmentReconciliationError(
                    "configured identity belongs to an unsupported accessory"
                )
            selected.append(
                {
                    "user_id": user_id,
                    "identity_uuid": record["identity_uuid"],
                }
            )
    return _identity_pairs(
        selected,
        "identity_uuid",
        apple_uid,
        expected_keys={"user_id", "identity_uuid"},
    )


def _components(records: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(records, list):
        raise EnrollmentReconciliationError("host component inventory is not a list")
    result = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "name",
            "sha256",
            "mode",
            "uid",
            "gid",
        }:
            raise EnrollmentReconciliationError("host component row is malformed")
        if record["name"] in result:
            raise EnrollmentReconciliationError("host component inventory has a duplicate")
        try:
            mutation_journal.require_sha256(record["sha256"], "component SHA-256")
        except mutation_journal.JournalError as error:
            raise EnrollmentReconciliationError(str(error)) from error
        for field in ("mode", "uid", "gid"):
            if (
                not isinstance(record[field], int)
                or isinstance(record[field], bool)
                or record[field] < 0
            ):
                raise EnrollmentReconciliationError(
                    "host component metadata is invalid"
                )
        result[record["name"]] = record
    return result


def classify(
    history: enrollment_journal.EnrollmentHistory,
    *,
    host: dict[str, Any],
    live: dict[str, Any],
    mapping_generation: str,
) -> ReconciliationPlan:
    if not isinstance(host, dict) or not isinstance(live, dict):
        raise EnrollmentReconciliationError("E3 snapshots are not mappings")
    persistence_readback = (
        history.phase is enrollment_journal.EnrollmentPhase.PERSISTING
        and history.persistence.phase is persistence_journal.PersistencePhase.ATTESTATION_READY
    )
    if history.phase not in (
        enrollment_journal.EnrollmentPhase.PERSISTENCE_READY,
        enrollment_journal.EnrollmentPhase.TERMINAL_FAILURE,
    ) and not persistence_readback:
        raise EnrollmentReconciliationError("journal is not ready for E3")
    baseline = history.baseline
    apple_uid = baseline["apple_uid"]
    if (
        live.get("double_collection_equal") is not True
        or live.get("connection_generation") != baseline["connection_generation"]
        or live.get("apple_uid") != apple_uid
        or live.get("biometric_protocol_version") != baseline["protocol_version"]
    ):
        raise EnrollmentReconciliationError("live E3 inventory is stale or unstable")
    if mapping_generation != baseline["mapping_generation"]:
        raise EnrollmentReconciliationError("protected mapping changed before E3")
    if host.get("account_uuid") != baseline["account_uuid"] or host.get(
        "bag_uuid"
    ) != baseline["bag_uuid"]:
        raise EnrollmentReconciliationError("account or keybag binding changed")

    before = _identity_pairs(
        baseline["identity_records"],
        "uuid",
        apple_uid,
        expected_keys={"user_id", "uuid", "entity"},
        require_entity=True,
    )
    host_after = _identity_pairs(
        host.get("identity_records"),
        "uuid",
        apple_uid,
        expected_keys={"user_id", "uuid", "entity"},
        require_entity=True,
    )
    live_after = _identity_pairs(
        live.get("per_user_identity_records"),
        "identity_uuid",
        apple_uid,
        expected_keys={"user_id", "identity_uuid"},
    )
    configured_global = _configured_global_pairs(
        live.get("global_identity_records"), apple_uid
    )
    if host_after != live_after or configured_global != live_after:
        raise EnrollmentReconciliationError("host and SEP identity inventories diverge")
    before_entities = {
        (record["user_id"], record["uuid"]): record["entity"]
        for record in baseline["identity_records"]
    }
    after_entities = {
        (record["user_id"], record["uuid"]): record["entity"]
        for record in host["identity_records"]
    }
    if any(after_entities.get(pair) != entity for pair, entity in before_entities.items()):
        raise EnrollmentReconciliationError("existing host identity entity changed")
    removed = before - live_after
    added = live_after - before
    if removed or len(added) > 1:
        raise EnrollmentReconciliationError("post-enrollment identity delta is unsafe")

    maximum = live.get("maximum_capacity")
    free_capacity = live.get("configured_user_free_capacity")
    if (
        not isinstance(maximum, int)
        or isinstance(maximum, bool)
        or maximum != baseline["capacity"]["maximum"]
        or not isinstance(free_capacity, int)
        or isinstance(free_capacity, bool)
        or not 0 <= free_capacity <= maximum
    ):
        raise EnrollmentReconciliationError("identity capacity changed before E3")
    catacomb = live.get("catacomb")
    if (
        not isinstance(catacomb, dict)
        or catacomb.get("present") is not True
        or not isinstance(catacomb.get("uuid"), str)
        or not isinstance(catacomb.get("hash"), str)
    ):
        raise EnrollmentReconciliationError("SEP Catacomb state is incomplete")
    try:
        mutation_journal.require_uuid(catacomb["uuid"], "SEP Catacomb UUID")
        mutation_journal.require_sha256(catacomb["hash"], "SEP Catacomb hash")
    except mutation_journal.JournalError as error:
        raise EnrollmentReconciliationError(str(error)) from error
    before_components = _components(baseline["host_components"])
    after_components = _components(host.get("host_components"))
    if set(before_components) != set(after_components):
        raise EnrollmentReconciliationError("host component set changed")
    if any(
        after_components[name][field] != before_components[name][field]
        for name in before_components
        for field in ("mode", "uid", "gid")
    ):
        raise EnrollmentReconciliationError("host component metadata changed")
    if catacomb["uuid"] != baseline["sep_catacomb"]["uuid"]:
        raise EnrollmentReconciliationError("SEP Catacomb UUID changed")

    master_enrollment_count = host.get("master_enrollment_count")
    if (
        not isinstance(master_enrollment_count, int)
        or isinstance(master_enrollment_count, bool)
        or master_enrollment_count < 0
    ):
        raise EnrollmentReconciliationError("master enrollment count is invalid")
    identity_uuid = next(iter(added))[1] if added else None
    persistence_success = history.phase is enrollment_journal.EnrollmentPhase.PERSISTENCE_READY or persistence_readback
    if persistence_success:
        if identity_uuid != history.terminal_identity_uuid:
            raise EnrollmentReconciliationError(
                "E2 identity does not match stable read-back"
            )
        user_name = f"user_{apple_uid:08x}.cat"
        if user_name not in after_components or "master.cat" not in after_components:
            raise EnrollmentReconciliationError("required Catacomb components are absent")
        if (
            after_components[user_name]["sha256"]
            == before_components[user_name]["sha256"]
            or after_components["master.cat"]["sha256"]
            == before_components["master.cat"]["sha256"]
            or catacomb["hash"] == baseline["sep_catacomb"]["hash"]
            or master_enrollment_count
            <= baseline["master_enrollment_count"]
        ):
            raise EnrollmentReconciliationError(
                "successful enrollment did not advance durable Catacomb state"
            )
    else:
        if identity_uuid is not None:
            return ReconciliationPlan(None, identity_uuid)
        if (
            after_components != before_components
            or catacomb.get("uuid") != baseline["sep_catacomb"]["uuid"]
            or catacomb.get("hash") != baseline["sep_catacomb"]["hash"]
            or master_enrollment_count
            != baseline["master_enrollment_count"]
        ):
            raise EnrollmentReconciliationError(
                "failed enrollment changed persistent state"
            )

    snapshot_model = {
        "account_uuid": host["account_uuid"],
        "bag_uuid": host["bag_uuid"],
        "identity_records": sorted(live_after),
        "catacomb": {"uuid": catacomb["uuid"], "hash": catacomb["hash"]},
        "host_components": [after_components[name] for name in sorted(after_components)],
        "master_enrollment_count": master_enrollment_count,
        "mapping_generation": mapping_generation,
    }
    snapshot_sha256 = hashlib.sha256(
        mutation_journal.canonical(snapshot_model)
    ).hexdigest()
    if (
        history.phase is enrollment_journal.EnrollmentPhase.PERSISTENCE_READY
        and history.persistence.reconciliation_snapshot_sha256 != snapshot_sha256
    ):
        raise EnrollmentReconciliationError(
            "journaled persistence snapshot does not match E3 read-back"
        )
    return ReconciliationPlan(
        {
            "connection_generation": baseline["connection_generation"],
            "snapshot_sha256": snapshot_sha256,
            "identity_uuid": identity_uuid,
            "identity_present": identity_uuid is not None,
            "host_sep_identity_equal": True,
            "catacomb_reconciled": True,
            "bindings_preserved": True,
            "mapping_generation": mapping_generation,
            "capacity_used": len(live_after),
            "capacity_maximum": maximum,
            "master_enrollment_count": master_enrollment_count,
        },
        None,
    )


def append_reconciled(
    path: Path,
    operation_id: str,
    *,
    host: dict[str, Any],
    live: dict[str, Any],
    mapping_generation: str,
) -> enrollment_journal.EnrollmentHistory:
    history = enrollment_journal.read(path)
    plan = classify(
        history,
        host=host,
        live=live,
        mapping_generation=mapping_generation,
    )
    if plan.readback_identity_uuid is not None:
        return enrollment_journal.append_checked(
            path,
            operation_id,
            "E2_IDENTITY_READBACK_OBSERVED",
            {
                "connection_generation": history.baseline["connection_generation"],
                "user_id": history.baseline["apple_uid"],
                "identity_uuid": plan.readback_identity_uuid,
                "source": "stable-readback",
            },
        )
    if plan.evidence is None:
        raise EnrollmentReconciliationError("E3 evidence is incomplete")
    return enrollment_journal.append_checked(
        path, operation_id, "E3_RECONCILED", plan.evidence
    )
