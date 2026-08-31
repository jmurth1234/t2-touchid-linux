# SPDX-License-Identifier: GPL-2.0-only
"""Journaled one-component Catacomb transaction for an identity-label rename."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

import t2_catacomb_protocol
import t2_identity_rename
import t2_identity_rename_journal as rename_journal
import t2_mutation_journal


class IdentityRenameOperationError(RuntimeError):
    pass


class RenameTransport(Protocol):
    def prepare(self, descriptor: bytes) -> tuple[int, int]: ...

    def complete(self, descriptor: bytes) -> tuple[int, bytearray]: ...

    def confirm(self, descriptor: bytes) -> int: ...


class RenameStore(Protocol):
    def begin_stage(self, expected_names: set[str]) -> None: ...

    def stage_component(
        self, name: str, data: bytearray, expected_names: set[str]
    ) -> str: ...

    def cross_commit_boundary(self, expected: dict[str, str]) -> None: ...


@dataclass(frozen=True)
class RenameReadbackAttestation:
    connection_generation: str
    snapshot_sha256: str
    identity_count: int
    identity_set_unchanged: bool
    label_updated: bool
    local_live_equal: bool


Readback = Callable[[], RenameReadbackAttestation]


def _wipe(value: object) -> None:
    if isinstance(value, bytearray):
        value[:] = b"\x00" * len(value)


def _name_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _append(
    path: Path,
    operation_id: str,
    milestone: str,
    evidence: dict[str, object],
) -> rename_journal.IdentityRenameHistory:
    return rename_journal.append_checked(path, operation_id, milestone, evidence)


def _freeze(
    path: Path,
    operation_id: str,
    reference: dict[str, object],
    *,
    stage: str,
    reason: str,
    host_commit_possible: bool,
    cause: BaseException | None = None,
) -> None:
    try:
        _append(
            path,
            operation_id,
            "CATACOMB_PERSISTENCE_OUTCOME_UNKNOWN",
            {
                **reference,
                "stage": stage,
                "reason": reason,
                "sep_mutation_possible": True,
                "host_commit_possible": host_commit_possible,
            },
        )
    except BaseException:
        pass
    error = IdentityRenameOperationError(
        f"identity rename stopped at {stage}; reconciliation is required"
    )
    if cause is None:
        raise error
    raise error from cause


def run(
    path: Path,
    operation_id: str,
    *,
    plan: t2_identity_rename.IdentityRenamePlan,
    transport: RenameTransport,
    store: RenameStore,
    mapping_generation: str,
    readback: Readback,
) -> rename_journal.IdentityRenameHistory:
    """Persist one already-planned label update without exposing its UUID."""
    history = rename_journal.read(path)
    if history.operation_id != operation_id or history.phase is not (
        rename_journal.IdentityRenamePhase.INTENT
    ):
        raise IdentityRenameOperationError("rename journal is not startable")
    if (
        history.target_identity_uuid != plan.identity_uuid
        or history.target_entity != plan.entity
        or history.previous_name_sha256 != _name_hash(plan.previous_name)
        or history.new_name_sha256 != _name_hash(plan.new_name)
        or history.baseline["apple_uid"] != plan.apple_user_id
        or history.baseline["mapping_generation"] != mapping_generation
    ):
        raise IdentityRenameOperationError("rename plan differs from durable intent")

    user_name = f"user_{plan.apple_user_id:08x}.cat"
    component = t2_catacomb_protocol.CatacombComponent.user(plan.apple_user_id)
    descriptor = component.descriptor
    descriptor_hash = hashlib.sha256(descriptor).hexdigest()
    generation = history.baseline["connection_generation"]
    reference: dict[str, object] = {
        "connection_generation": generation,
        "batch_index": 0,
        "component_index": 0,
        "name": user_name,
        "descriptor_sha256": descriptor_hash,
    }
    expected_names = {user_name}

    _append(
        path,
        operation_id,
        "CATACOMB_PERSISTENCE_PLAN",
        {
            "connection_generation": generation,
            "batches": [
                [{"name": user_name, "descriptor_sha256": descriptor_hash}]
            ],
        },
    )
    try:
        store.begin_stage(expected_names)
    except BaseException as error:
        try:
            _append(
                path,
                operation_id,
                "RENAME_ABORTED_BEFORE_PERSISTENCE",
                {"reason": "host-store-unavailable", "mutation_possible": False},
            )
        except BaseException:
            pass
        raise IdentityRenameOperationError(
            "identity rename could not create a local transaction"
        ) from error
    _append(path, operation_id, "CATACOMB_PREPARE_INTENT", reference)
    try:
        prepare_status, expected_length = transport.prepare(descriptor)
    except BaseException as error:
        _freeze(
            path,
            operation_id,
            reference,
            stage="prepare",
            reason="transport-error",
            host_commit_possible=False,
            cause=error,
        )
    if (
        type(prepare_status) is not int
        or prepare_status != 0
        or type(expected_length) is not int
        or not 0 < expected_length <= 1024 * 1024
    ):
        _freeze(
            path,
            operation_id,
            reference,
            stage="prepare",
            reason="transport-error",
            host_commit_possible=False,
        )
    _append(
        path,
        operation_id,
        "CATACOMB_PREPARED",
        {**reference, "status": 0, "expected_blob_length": expected_length},
    )
    _append(path, operation_id, "CATACOMB_COMPLETE_INTENT", reference)

    secure_blob: bytearray | None = None
    encoded: bytearray | None = None
    try:
        try:
            complete_status, secure_blob = transport.complete(descriptor)
        except BaseException as error:
            _freeze(
                path,
                operation_id,
                reference,
                stage="complete",
                reason="transport-error",
                host_commit_possible=False,
                cause=error,
            )
        if (
            type(complete_status) is not int
            or complete_status != 0
            or not isinstance(secure_blob, bytearray)
            or len(secure_blob) != expected_length
        ):
            _freeze(
                path,
                operation_id,
                reference,
                stage="complete",
                reason="transport-error",
                host_commit_possible=False,
            )
        blob_hash = hashlib.sha256(secure_blob).hexdigest()
        _append(
            path,
            operation_id,
            "CATACOMB_SECURE_BLOB_CAPTURED",
            {
                **reference,
                "status": 0,
                "blob_length": len(secure_blob),
                "secure_blob_sha256": blob_hash,
            },
        )
        try:
            encoded = t2_identity_rename.bind_secure_blob(plan, secure_blob)
        except t2_identity_rename.IdentityRenameError as error:
            _freeze(
                path,
                operation_id,
                reference,
                stage="encode",
                reason="codec-error",
                host_commit_possible=False,
                cause=error,
            )
        try:
            file_hash = store.stage_component(user_name, encoded, expected_names)
        except BaseException as error:
            _freeze(
                path,
                operation_id,
                reference,
                stage="host-stage",
                reason="host-store-error",
                host_commit_possible=False,
                cause=error,
            )
        if file_hash != hashlib.sha256(encoded).hexdigest():
            _freeze(
                path,
                operation_id,
                reference,
                stage="host-stage",
                reason="host-store-error",
                host_commit_possible=False,
            )
        _append(
            path,
            operation_id,
            "CATACOMB_HOST_STAGED",
            {
                **reference,
                "secure_blob_sha256": blob_hash,
                "final_file_sha256": file_hash,
            },
        )
    finally:
        _wipe(encoded)
        _wipe(secure_blob)

    staged_snapshot = hashlib.sha256(
        t2_mutation_journal.canonical(
            [{"name": user_name, "final_file_sha256": file_hash}]
        )
    ).hexdigest()
    batch = {
        "connection_generation": generation,
        "batch_index": 0,
        "staged_snapshot_sha256": staged_snapshot,
    }
    _append(path, operation_id, "CATACOMB_HOST_BATCH_COMMIT_INTENT", batch)
    try:
        store.cross_commit_boundary({user_name: file_hash})
    except BaseException as error:
        _freeze(
            path,
            operation_id,
            reference,
            stage="host-commit",
            reason="host-store-error",
            host_commit_possible=True,
            cause=error,
        )
    _append(path, operation_id, "CATACOMB_HOST_BATCH_COMMITTED", batch)
    _append(path, operation_id, "CATACOMB_FINAL_CONFIRM_INTENT", reference)
    try:
        confirm_status = transport.confirm(descriptor)
    except BaseException as error:
        _freeze(
            path,
            operation_id,
            reference,
            stage="final-confirm",
            reason="transport-error",
            host_commit_possible=True,
            cause=error,
        )
    if type(confirm_status) is not int or confirm_status != 0:
        _freeze(
            path,
            operation_id,
            reference,
            stage="final-confirm",
            reason="transport-error",
            host_commit_possible=True,
        )
    _append(
        path,
        operation_id,
        "CATACOMB_FINAL_CONFIRMED",
        {**reference, "status": 0},
    )
    try:
        attestation = readback()
    except BaseException as error:
        _freeze(
            path,
            operation_id,
            reference,
            stage="readback",
            reason="readback-error",
            host_commit_possible=True,
            cause=error,
        )
    if (
        not isinstance(attestation, RenameReadbackAttestation)
        or attestation.connection_generation != generation
        or attestation.identity_count != len(history.baseline["identity_records"])
        or attestation.identity_set_unchanged is not True
        or attestation.label_updated is not True
        or attestation.local_live_equal is not True
    ):
        _freeze(
            path,
            operation_id,
            reference,
            stage="readback",
            reason="readback-error",
            host_commit_possible=True,
        )
    try:
        t2_mutation_journal.require_sha256(
            attestation.snapshot_sha256, "rename snapshot SHA-256"
        )
    except t2_mutation_journal.JournalError as error:
        _freeze(
            path,
            operation_id,
            reference,
            stage="readback",
            reason="readback-error",
            host_commit_possible=True,
            cause=error,
        )
    _append(
        path,
        operation_id,
        "CATACOMB_PERSISTENCE_ATTESTED",
        {
            "connection_generation": generation,
            "batch_count": 1,
            "reconciliation_snapshot_sha256": attestation.snapshot_sha256,
            "sep_host_generation_equal": True,
            "independent_archive_readback": True,
        },
    )
    return _append(
        path,
        operation_id,
        "RENAME_RECONCILED",
        {
            "connection_generation": generation,
            "identity_uuid": plan.identity_uuid,
            "new_name_sha256": _name_hash(plan.new_name),
            "snapshot_sha256": attestation.snapshot_sha256,
            "mapping_generation": mapping_generation,
            "identity_count": attestation.identity_count,
            "identity_set_unchanged": True,
            "label_updated": True,
            "local_live_equal": True,
        },
    )
