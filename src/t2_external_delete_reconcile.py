# SPDX-License-Identifier: GPL-2.0-only
"""Reconcile one externally removed SEP identity into the Linux Catacomb.

This module sends no biometric or Catacomb command.  It accepts only the
strict shape produced when a stable live SEP inventory is an exact subset of
the validated Linux-local archive by one identity.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import stat
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import t2_catacomb_codec
import t2_identity_delete
import t2_identity_inventory
import t2_mutation_journal


class ExternalDeleteReconcileError(RuntimeError):
    pass


@dataclass(frozen=True, repr=False)
class ExternalDeletePlan:
    apple_user_id: int
    stale_identity_uuid: str
    stale_entity: int
    stale_name_sha256: str
    local_identity_count: int
    live_identity_count: int
    local_snapshot_sha256: str
    live_snapshot_sha256: str
    survivor_snapshot_sha256: str
    archive: bytes

    def __repr__(self) -> str:
        return (
            "ExternalDeletePlan(apple_user_id="
            f"{self.apple_user_id}, stale_identity_uuid=<redacted>, "
            f"stale_entity={self.stale_entity}, stale_name_sha256=<redacted>, "
            f"local_identity_count={self.local_identity_count}, "
            f"live_identity_count={self.live_identity_count}, "
            "local_snapshot_sha256=<redacted>, "
            "live_snapshot_sha256=<redacted>, "
            "survivor_snapshot_sha256=<redacted>, archive=<redacted>)"
        )


@dataclass(frozen=True)
class BackupAttestation:
    reference: str
    snapshot_sha256: str
    component_hashes: tuple[tuple[str, str], ...]


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _identity_snapshot(identities: tuple[t2_catacomb_codec.Identity, ...]) -> str:
    records = [
        dataclasses.asdict(identity)
        for identity in sorted(identities, key=lambda item: item.entity)
    ]
    return _sha256(t2_mutation_journal.canonical(records))


def _canonical_uuid(value: object, field: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise ExternalDeleteReconcileError(f"{field} is not a UUID") from error
    if str(parsed) != value:
        raise ExternalDeleteReconcileError(f"{field} is not canonical")
    return value


def _per_user_pairs(records: object, apple_uid: int) -> set[tuple[int, str]]:
    if not isinstance(records, list):
        raise ExternalDeleteReconcileError("per-user SEP inventory is absent")
    result: set[tuple[int, str]] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "user_id",
            "identity_uuid",
        }:
            raise ExternalDeleteReconcileError("per-user SEP inventory is malformed")
        pair = (
            record["user_id"],
            _canonical_uuid(record["identity_uuid"], "SEP identity UUID"),
        )
        if pair[0] != apple_uid or pair in result:
            raise ExternalDeleteReconcileError("per-user SEP inventory is ambiguous")
        result.add(pair)
    return result


def _global_pairs(records: object, apple_uid: int) -> set[tuple[int, str]]:
    if not isinstance(records, list):
        raise ExternalDeleteReconcileError("global SEP inventory is absent")
    result: set[tuple[int, str]] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {
            "user_id",
            "identity_uuid",
            "group_type",
            "group_uuid",
        }:
            raise ExternalDeleteReconcileError("global SEP inventory is malformed")
        if record["user_id"] != apple_uid:
            continue
        if record["group_type"] not in (0, 1) or record["group_uuid"] != str(
            uuid.UUID(int=0)
        ):
            raise ExternalDeleteReconcileError("SEP identity is not built-in")
        pair = (
            record["user_id"],
            _canonical_uuid(record["identity_uuid"], "global identity UUID"),
        )
        if pair in result:
            raise ExternalDeleteReconcileError("global SEP inventory is ambiguous")
        result.add(pair)
    return result


def _require_clean_catacomb(live: dict[str, Any], apple_uid: int) -> None:
    catacomb = live.get("catacomb")
    states = catacomb.get("user_states") if isinstance(catacomb, dict) else None
    if catacomb is None or not isinstance(states, list):
        raise ExternalDeleteReconcileError("SEP Catacomb state is unavailable")
    users = [
        item
        for item in states
        if isinstance(item, dict)
        and item.get("kind") == "user"
        and item.get("user_id") == apple_uid
    ]
    masters = [
        item
        for item in states
        if isinstance(item, dict) and item.get("kind") == "master"
    ]
    if (
        catacomb.get("present") is not True
        or len(users) != 1
        or len(masters) != 1
        or users[0].get("needs_save") is not False
        or masters[0].get("needs_save") is not False
    ):
        raise ExternalDeleteReconcileError(
            "SEP Catacomb is not clean after the external deletion"
        )


def plan(
    local: t2_catacomb_codec.UserCatacomb,
    live: dict[str, Any],
) -> ExternalDeletePlan:
    """Prove exactly one local-only identity and encode its local removal."""

    if not isinstance(local, t2_catacomb_codec.UserCatacomb):
        raise ExternalDeleteReconcileError("local Catacomb is not validated")
    if not isinstance(live, dict):
        raise ExternalDeleteReconcileError("live SEP inventory is not a mapping")
    apple_uid = local.expected_user_id
    if (
        live.get("double_collection_equal") is not True
        or live.get("apple_uid") != apple_uid
        or live.get("biometric_protocol_version") != 2
    ):
        raise ExternalDeleteReconcileError("live SEP inventory is stale or unstable")
    _require_clean_catacomb(live, apple_uid)
    per_user = _per_user_pairs(live.get("per_user_identity_records"), apple_uid)
    global_pairs = _global_pairs(live.get("global_identity_records"), apple_uid)
    if per_user != global_pairs:
        raise ExternalDeleteReconcileError(
            "per-user and global SEP inventories disagree"
        )
    local_by_pair = {
        (identity.user_id, identity.uuid): identity for identity in local.identities
    }
    local_pairs = set(local_by_pair)
    stale_pairs = local_pairs - per_user
    if (
        not per_user
        or per_user - local_pairs
        or len(stale_pairs) != 1
        or len(local_pairs) != len(per_user) + 1
    ):
        raise ExternalDeleteReconcileError(
            "external reconciliation requires exactly one local-only identity"
        )
    stale = local_by_pair[next(iter(stale_pairs))]
    try:
        archive = local.delete(stale.uuid)
        survivor = t2_catacomb_codec.decode_user_catacomb(archive, apple_uid)
        t2_identity_inventory.summarize(survivor, live)
    except (
        t2_catacomb_codec.CatacombCodecError,
        t2_identity_inventory.IdentityInventoryError,
    ) as error:
        raise ExternalDeleteReconcileError(
            "external deletion survivor archive did not reconcile"
        ) from error
    before = {identity.uuid: identity for identity in local.identities}
    after = {identity.uuid: identity for identity in survivor.identities}
    if (
        stale.uuid in after
        or set(after) != set(before) - {stale.uuid}
        or any(after[key] != before[key] for key in after)
        or survivor.account_uuid != local.account_uuid
        or survivor.keybag_uuid != local.keybag_uuid
        or survivor.secure_data != local.secure_data
    ):
        raise ExternalDeleteReconcileError(
            "external reconciliation changed survivor or account metadata"
        )
    live_records = [
        {"user_id": user_id, "identity_uuid": identity_uuid}
        for user_id, identity_uuid in sorted(per_user)
    ]
    return ExternalDeletePlan(
        apple_uid,
        stale.uuid,
        stale.entity,
        _sha256(stale.name.encode("utf-8")),
        len(local.identities),
        len(survivor.identities),
        _identity_snapshot(local.identities),
        _sha256(t2_mutation_journal.canonical(live_records)),
        t2_identity_delete.survivor_snapshot_sha256(survivor.identities),
        archive,
    )


def verify(
    value: ExternalDeletePlan,
    local: t2_catacomb_codec.UserCatacomb,
    live: dict[str, Any],
) -> None:
    """Independently prove a committed host-only reconciliation."""

    if not isinstance(value, ExternalDeletePlan):
        raise ExternalDeleteReconcileError("external reconciliation plan is invalid")
    try:
        public = t2_identity_inventory.summarize(local, live)
    except t2_identity_inventory.IdentityInventoryError as error:
        raise ExternalDeleteReconcileError(
            "committed external reconciliation is not local/live equal"
        ) from error
    if (
        local.expected_user_id != value.apple_user_id
        or public["identity_count"] != value.live_identity_count
        or value.stale_identity_uuid in {item.uuid for item in local.identities}
        or t2_identity_delete.survivor_snapshot_sha256(local.identities)
        != value.survivor_snapshot_sha256
    ):
        raise ExternalDeleteReconcileError(
            "committed external reconciliation changed its survivor binding"
        )


def _private_directory(path: Path) -> None:
    info = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise ExternalDeleteReconcileError("backup directory is unsafe")


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_private(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        offset = 0
        while offset < len(value):
            written = os.write(descriptor, value[offset:])
            if written <= 0:
                raise ExternalDeleteReconcileError("backup write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_backup(
    root: Path,
    operation_id: str,
    components: dict[str, bytes],
) -> BackupAttestation:
    """Create an exclusive private full-component recovery snapshot."""

    if not isinstance(root, Path) or not isinstance(components, dict):
        raise ExternalDeleteReconcileError("backup input is invalid")
    _private_directory(root)
    try:
        parsed = uuid.UUID(operation_id)
    except (TypeError, ValueError) as error:
        raise ExternalDeleteReconcileError("backup operation ID is invalid") from error
    if str(parsed) != operation_id or not components or any(
        not isinstance(name, str)
        or not isinstance(data, bytes)
        or not data
        or len(data) > t2_catacomb_codec.MAX_FILE_BYTES
        for name, data in components.items()
    ):
        raise ExternalDeleteReconcileError("backup component set is invalid")
    target = root / operation_id
    temporary = root / f".{operation_id}.prepare"
    if os.path.lexists(target) or os.path.lexists(temporary):
        raise ExternalDeleteReconcileError("backup operation already exists")
    temporary.mkdir(mode=0o700)
    promoted = False
    try:
        hashes = []
        for name in sorted(components):
            if "/" in name or name in {"", ".", ".."}:
                raise ExternalDeleteReconcileError("backup component name is unsafe")
            _write_private(temporary / name, components[name])
            hashes.append((name, _sha256(components[name])))
        _sync_directory(temporary)
        os.rename(temporary, target)
        promoted = True
        _sync_directory(root)
    finally:
        if not promoted and temporary.exists():
            for entry in temporary.iterdir():
                if entry.is_file() and not entry.is_symlink():
                    entry.unlink()
            temporary.rmdir()
    snapshot = _sha256(
        t2_mutation_journal.canonical(
            [{"name": name, "sha256": digest} for name, digest in hashes]
        )
    )
    return BackupAttestation(operation_id, snapshot, tuple(hashes))


class ExternalDeletePhase(Enum):
    BASELINE = "external-delete-baseline"
    INTENT = "external-delete-intent"
    HOST_COMMITTED = "external-delete-host-committed"
    RECONCILED = "external-delete-reconciled"
    ABORTED = "external-delete-aborted"
    OUTCOME_UNKNOWN = "external-delete-outcome-unknown"


@dataclass(frozen=True, repr=False)
class ExternalDeleteHistory:
    operation_id: str
    phase: ExternalDeletePhase
    baseline: dict[str, Any]
    intent: dict[str, Any] | None
    record_count: int
    head_hash: str

    def __repr__(self) -> str:
        return (
            "ExternalDeleteHistory(operation_id=<redacted>, "
            f"phase={self.phase.value!r}, baseline=<redacted>, "
            f"intent={'<redacted>' if self.intent else None}, "
            f"record_count={self.record_count}, head_hash=<redacted>)"
        )


def _exact(value: object, keys: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ExternalDeleteReconcileError(f"{field} evidence is invalid")
    return value


def _require_hash(value: object, field: str) -> None:
    try:
        t2_mutation_journal.require_sha256(value, field)
    except t2_mutation_journal.JournalError as error:
        raise ExternalDeleteReconcileError(str(error)) from error


def validate_history(records: list[dict[str, Any]]) -> ExternalDeleteHistory:
    if not records or records[0].get("milestone") != "EXTERNAL_DELETE_BASELINE":
        raise ExternalDeleteReconcileError("external-delete journal has no baseline")
    operation_id = records[0].get("operation_id")
    try:
        t2_mutation_journal.require_uuid(operation_id, "operation ID")
    except t2_mutation_journal.JournalError as error:
        raise ExternalDeleteReconcileError(str(error)) from error
    baseline = _exact(
        records[0].get("evidence"),
        {
            "operation_kind",
            "apple_uid",
            "linux_boot_uuid",
            "connection_generation",
            "mapping_generation",
            "local_identity_count",
            "live_identity_count",
            "stale_identity_uuid",
            "stale_entity",
            "stale_name_sha256",
            "local_snapshot_sha256",
            "live_snapshot_sha256",
            "survivor_snapshot_sha256",
            "before_user_sha256",
            "other_components_snapshot_sha256",
            "backup_reference",
            "backup_snapshot_sha256",
            "sep_mutation_performed",
        },
        "baseline",
    )
    for field in (
        "linux_boot_uuid",
        "connection_generation",
        "stale_identity_uuid",
        "backup_reference",
    ):
        try:
            t2_mutation_journal.require_uuid(baseline[field], field)
        except t2_mutation_journal.JournalError as error:
            raise ExternalDeleteReconcileError(str(error)) from error
    for field in (
        "mapping_generation",
        "stale_name_sha256",
        "local_snapshot_sha256",
        "live_snapshot_sha256",
        "survivor_snapshot_sha256",
        "before_user_sha256",
        "other_components_snapshot_sha256",
        "backup_snapshot_sha256",
    ):
        _require_hash(baseline[field], field)
    if (
        baseline["operation_kind"] != "reconcile-external-delete"
        or type(baseline["apple_uid"]) is not int
        or type(baseline["stale_entity"]) is not int
        or type(baseline["local_identity_count"]) is not int
        or type(baseline["live_identity_count"]) is not int
        or baseline["live_identity_count"] < 1
        or baseline["local_identity_count"] != baseline["live_identity_count"] + 1
        or baseline["sep_mutation_performed"] is not False
    ):
        raise ExternalDeleteReconcileError("external-delete baseline binding is invalid")
    phase = ExternalDeletePhase.BASELINE
    intent = None
    for record in records[1:]:
        if record.get("operation_id") != operation_id:
            raise ExternalDeleteReconcileError("external-delete operation ID changed")
        milestone = record.get("milestone")
        evidence = record.get("evidence")
        if milestone == "EXTERNAL_DELETE_INTENT":
            if phase is not ExternalDeletePhase.BASELINE:
                raise ExternalDeleteReconcileError("external-delete intent is out of order")
            intent = _exact(
                evidence,
                {
                    "connection_generation",
                    "staged_user_sha256",
                    "survivor_snapshot_sha256",
                    "identity_count",
                    "sep_mutation_performed",
                },
                "intent",
            )
            _require_hash(intent["staged_user_sha256"], "staged user component")
            if (
                intent["connection_generation"] != baseline["connection_generation"]
                or intent["survivor_snapshot_sha256"]
                != baseline["survivor_snapshot_sha256"]
                or intent["identity_count"] != baseline["live_identity_count"]
                or intent["sep_mutation_performed"] is not False
            ):
                raise ExternalDeleteReconcileError("external-delete intent binding changed")
            phase = ExternalDeletePhase.INTENT
        elif milestone == "EXTERNAL_DELETE_HOST_COMMITTED":
            if phase not in {ExternalDeletePhase.INTENT, ExternalDeletePhase.OUTCOME_UNKNOWN}:
                raise ExternalDeleteReconcileError("external-delete commit is out of order")
            value = _exact(
                evidence,
                {"staged_user_sha256", "recovery_action", "sep_mutation_performed"},
                "host commit",
            )
            if (
                intent is None
                or value["staged_user_sha256"] != intent["staged_user_sha256"]
                or value["recovery_action"] not in {"direct", "commit-rolled-forward"}
                or value["sep_mutation_performed"] is not False
            ):
                raise ExternalDeleteReconcileError("external-delete commit binding changed")
            phase = ExternalDeletePhase.HOST_COMMITTED
        elif milestone == "EXTERNAL_DELETE_RECONCILED":
            if phase is not ExternalDeletePhase.HOST_COMMITTED:
                raise ExternalDeleteReconcileError("external-delete proof is out of order")
            value = _exact(
                evidence,
                {
                    "connection_generation",
                    "staged_user_sha256",
                    "identity_count",
                    "local_live_equal",
                    "target_absent",
                    "other_components_unchanged",
                    "sep_mutation_performed",
                },
                "reconciliation",
            )
            try:
                t2_mutation_journal.require_uuid(
                    value["connection_generation"], "reconciled connection generation"
                )
            except t2_mutation_journal.JournalError as error:
                raise ExternalDeleteReconcileError(str(error)) from error
            if (
                intent is None
                or value["staged_user_sha256"] != intent["staged_user_sha256"]
                or value["identity_count"] != baseline["live_identity_count"]
                or value["local_live_equal"] is not True
                or value["target_absent"] is not True
                or value["other_components_unchanged"] is not True
                or value["sep_mutation_performed"] is not False
            ):
                raise ExternalDeleteReconcileError("external-delete proof is incomplete")
            phase = ExternalDeletePhase.RECONCILED
        elif milestone == "EXTERNAL_DELETE_ABORTED":
            if phase not in {
                ExternalDeletePhase.BASELINE,
                ExternalDeletePhase.INTENT,
                ExternalDeletePhase.OUTCOME_UNKNOWN,
            }:
                raise ExternalDeleteReconcileError("external-delete abort is out of order")
            value = _exact(
                evidence,
                {"reason", "host_commit_possible", "sep_mutation_performed"},
                "abort",
            )
            if (
                value["reason"] not in {"before-host-stage", "prepare-discarded"}
                or value["host_commit_possible"] is not False
                or value["sep_mutation_performed"] is not False
            ):
                raise ExternalDeleteReconcileError("external-delete abort is invalid")
            phase = ExternalDeletePhase.ABORTED
        elif milestone == "EXTERNAL_DELETE_OUTCOME_UNKNOWN":
            if phase not in {ExternalDeletePhase.INTENT, ExternalDeletePhase.HOST_COMMITTED}:
                raise ExternalDeleteReconcileError("external-delete ambiguity is out of order")
            value = _exact(
                evidence,
                {"stage", "host_commit_possible", "sep_mutation_performed"},
                "ambiguity",
            )
            if (
                value["stage"] not in {"host-stage", "host-commit", "readback"}
                or type(value["host_commit_possible"]) is not bool
                or value["sep_mutation_performed"] is not False
            ):
                raise ExternalDeleteReconcileError("external-delete ambiguity is invalid")
            phase = ExternalDeletePhase.OUTCOME_UNKNOWN
        else:
            raise ExternalDeleteReconcileError("unknown external-delete milestone")
    return ExternalDeleteHistory(
        operation_id,
        phase,
        baseline,
        intent,
        len(records),
        records[-1]["record_hash"],
    )


def create_journal(
    path: Path,
    operation_id: str,
    evidence: dict[str, Any],
) -> ExternalDeleteHistory:
    t2_mutation_journal.append(
        path,
        operation_id,
        "EXTERNAL_DELETE_BASELINE",
        evidence,
        exclusive=True,
    )
    return validate_history(t2_mutation_journal.read(path))


def append_checked(
    path: Path,
    operation_id: str,
    milestone: str,
    evidence: dict[str, Any],
) -> ExternalDeleteHistory:
    history = validate_history(t2_mutation_journal.read(path))
    if history.operation_id != operation_id:
        raise ExternalDeleteReconcileError("external-delete operation ID changed")
    t2_mutation_journal.append(
        path,
        operation_id,
        milestone,
        evidence,
        expected_record_count=history.record_count,
        expected_previous_hash=history.head_hash,
    )
    return validate_history(t2_mutation_journal.read(path))
