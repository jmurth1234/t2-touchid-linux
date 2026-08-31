# SPDX-License-Identifier: GPL-2.0-only
"""Dependency-injected E2-to-E3 Catacomb persistence operation core."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

import t2_enrollment_journal as enrollment_journal
import t2_mutation_journal as mutation_journal
import t2_catacomb_protocol as catacomb_protocol


class PersistenceOperationError(RuntimeError):
    pass


@dataclass(frozen=True, repr=False)
class ComponentSpec:
    name: str
    descriptor: bytes

    @property
    def descriptor_sha256(self) -> str:
        return hashlib.sha256(self.descriptor).hexdigest()


@dataclass(frozen=True)
class ReadbackAttestation:
    reconciliation_snapshot_sha256: str
    sep_host_generation_equal: bool
    independent_archive_readback: bool


class PersistenceTransport(Protocol):
    def prepare(self, descriptor: bytes) -> tuple[int, int]: ...

    def complete(self, descriptor: bytes) -> tuple[int, bytearray]: ...

    def confirm(self, descriptor: bytes) -> int: ...


class HostStore(Protocol):
    def begin_stage(self, expected_names: set[str]) -> None: ...

    def stage_component(
        self, name: str, data: bytearray, expected_names: set[str]
    ) -> str: ...

    def cross_commit_boundary(self, expected: dict[str, str]) -> None: ...


Encoder = Callable[[str, bytearray], bytearray]
Readback = Callable[[], ReadbackAttestation]


def _wipe(value: object) -> None:
    if isinstance(value, bytearray):
        value[:] = b"\x00" * len(value)


def _reference(
    history: enrollment_journal.EnrollmentHistory,
    batch_index: int,
    component_index: int,
    component: ComponentSpec,
) -> dict[str, object]:
    return {
        "connection_generation": history.baseline["connection_generation"],
        "batch_index": batch_index,
        "component_index": component_index,
        "name": component.name,
        "descriptor_sha256": component.descriptor_sha256,
    }


def _append(
    path: Path,
    operation_id: str,
    milestone: str,
    evidence: dict[str, object],
) -> enrollment_journal.EnrollmentHistory:
    return enrollment_journal.append_checked(
        path, operation_id, milestone, evidence
    )


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
    except Exception:
        pass
    error = PersistenceOperationError(
        f"Catacomb persistence stopped at {stage}; reconciliation is required"
    )
    if cause is None:
        raise error
    raise error from cause


def _validate_components(
    history: enrollment_journal.EnrollmentHistory,
    batches: tuple[tuple[ComponentSpec, ...], ...],
) -> None:
    if history.phase is not enrollment_journal.EnrollmentPhase.TERMINAL_IDENTITY:
        raise PersistenceOperationError(
            "persistence requires one provisional enrollment identity"
        )
    if not batches:
        raise PersistenceOperationError("persistence has no component batches")
    apple_user_id = history.baseline["apple_uid"]
    expected_user_name = f"user_{apple_user_id:08x}.cat"
    for batch in batches:
        if not batch:
            raise PersistenceOperationError("persistence has an empty batch")
        for component in batch:
            if (
                not isinstance(component, ComponentSpec)
                or not isinstance(component.name, str)
                or not isinstance(component.descriptor, bytes)
                or len(component.descriptor) != 24
            ):
                raise PersistenceOperationError(
                    "persistence component descriptor is invalid"
                )
            if component.name in {expected_user_name, "master.cat"}:
                try:
                    parsed = catacomb_protocol.CatacombComponent.parse(
                        component.descriptor
                    )
                except catacomb_protocol.CatacombProtocolError as error:
                    raise PersistenceOperationError(
                        "persistence component descriptor is invalid"
                    ) from error
                expected = (
                    catacomb_protocol.CatacombComponent.user(apple_user_id)
                    if component.name == expected_user_name
                    else catacomb_protocol.CatacombComponent.master()
                )
                if parsed != expected:
                    raise PersistenceOperationError(
                        "persistence component descriptor is bound to another target"
                    )


def run(
    path: Path,
    operation_id: str,
    *,
    batches: tuple[tuple[ComponentSpec, ...], ...],
    transport: PersistenceTransport,
    encoder: Encoder,
    store: HostStore,
    readback: Readback,
) -> enrollment_journal.EnrollmentHistory:
    """Persist a provisional identity without exposing a concrete transport."""
    history = enrollment_journal.read(path)
    if history.operation_id != operation_id:
        raise PersistenceOperationError("operation ID differs from journal")
    _validate_components(history, batches)
    generation = history.baseline["connection_generation"]
    _append(
        path,
        operation_id,
        "CATACOMB_PERSISTENCE_PLAN",
        {
            "connection_generation": generation,
            "batches": [
                [
                    {
                        "name": component.name,
                        "descriptor_sha256": component.descriptor_sha256,
                    }
                    for component in batch
                ]
                for batch in batches
            ],
        },
    )

    final_reference: dict[str, object] | None = None
    for batch_index, batch in enumerate(batches):
        expected_names = {component.name for component in batch}
        store.begin_stage(expected_names)
        staged: dict[str, str] = {}
        for component_index, component in enumerate(batch):
            reference = _reference(
                history, batch_index, component_index, component
            )
            final_reference = reference
            _append(path, operation_id, "CATACOMB_PREPARE_INTENT", reference)
            try:
                prepare_status, expected_blob_length = transport.prepare(
                    component.descriptor
                )
            except Exception as error:
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
                or not isinstance(expected_blob_length, int)
                or isinstance(expected_blob_length, bool)
                or not 0 < expected_blob_length <= 1024 * 1024
            ):
                _freeze(
                    path,
                    operation_id,
                    reference,
                    stage="prepare",
                    reason="transport-error",
                    host_commit_possible=False,
                )
            try:
                _append(
                    path,
                    operation_id,
                    "CATACOMB_PREPARED",
                    {
                        **reference,
                        "status": prepare_status,
                        "expected_blob_length": expected_blob_length,
                    },
                )
            except Exception as error:
                _freeze(
                    path,
                    operation_id,
                    reference,
                    stage="prepare",
                    reason="journal-error",
                    host_commit_possible=False,
                    cause=error,
                )

            _append(path, operation_id, "CATACOMB_COMPLETE_INTENT", reference)
            secure_blob: bytearray | None = None
            encoded: bytearray | None = None
            try:
                try:
                    complete_status, secure_blob = transport.complete(
                        component.descriptor
                    )
                except Exception as error:
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
                    or not secure_blob
                    or len(secure_blob) != expected_blob_length
                ):
                    _freeze(
                        path,
                        operation_id,
                        reference,
                        stage="complete",
                        reason="transport-error",
                        host_commit_possible=False,
                    )
                blob_sha256 = hashlib.sha256(secure_blob).hexdigest()
                try:
                    _append(
                        path,
                        operation_id,
                        "CATACOMB_SECURE_BLOB_CAPTURED",
                        {
                            **reference,
                            "status": complete_status,
                            "blob_length": len(secure_blob),
                            "secure_blob_sha256": blob_sha256,
                        },
                    )
                except Exception as error:
                    _freeze(
                        path,
                        operation_id,
                        reference,
                        stage="complete",
                        reason="journal-error",
                        host_commit_possible=False,
                        cause=error,
                    )
                try:
                    encoded = encoder(component.name, secure_blob)
                except Exception as error:
                    _freeze(
                        path,
                        operation_id,
                        reference,
                        stage="encode",
                        reason="codec-error",
                        host_commit_possible=False,
                        cause=error,
                    )
                if not isinstance(encoded, bytearray) or not encoded:
                    _freeze(
                        path,
                        operation_id,
                        reference,
                        stage="encode",
                        reason="codec-error",
                        host_commit_possible=False,
                    )
                try:
                    final_file_sha256 = store.stage_component(
                        component.name, encoded, expected_names
                    )
                except Exception as error:
                    _freeze(
                        path,
                        operation_id,
                        reference,
                        stage="host-stage",
                        reason="host-store-error",
                        host_commit_possible=False,
                        cause=error,
                    )
                expected_file_sha256 = hashlib.sha256(encoded).hexdigest()
                if final_file_sha256 != expected_file_sha256:
                    _freeze(
                        path,
                        operation_id,
                        reference,
                        stage="host-stage",
                        reason="host-store-error",
                        host_commit_possible=False,
                    )
                staged[component.name] = final_file_sha256
                try:
                    _append(
                        path,
                        operation_id,
                        "CATACOMB_HOST_STAGED",
                        {
                            **reference,
                            "secure_blob_sha256": blob_sha256,
                            "final_file_sha256": final_file_sha256,
                        },
                    )
                except Exception as error:
                    _freeze(
                        path,
                        operation_id,
                        reference,
                        stage="host-stage",
                        reason="journal-error",
                        host_commit_possible=False,
                        cause=error,
                    )
            finally:
                _wipe(encoded)
                _wipe(secure_blob)

            if component_index + 1 < len(batch):
                _append(path, operation_id, "CATACOMB_CONFIRM_INTENT", reference)
                try:
                    confirm_status = transport.confirm(component.descriptor)
                except Exception as error:
                    _freeze(
                        path,
                        operation_id,
                        reference,
                        stage="early-confirm",
                        reason="transport-error",
                        host_commit_possible=False,
                        cause=error,
                    )
                if type(confirm_status) is not int or confirm_status != 0:
                    _freeze(
                        path,
                        operation_id,
                        reference,
                        stage="early-confirm",
                        reason="transport-error",
                        host_commit_possible=False,
                    )
                try:
                    _append(
                        path,
                        operation_id,
                        "CATACOMB_CONFIRMED",
                        {
                            **reference,
                            "status": confirm_status,
                        },
                    )
                except Exception as error:
                    _freeze(
                        path,
                        operation_id,
                        reference,
                        stage="early-confirm",
                        reason="journal-error",
                        host_commit_possible=False,
                        cause=error,
                    )

        staged_snapshot_sha256 = hashlib.sha256(
            mutation_journal.canonical(
                [
                    {"name": component.name, "final_file_sha256": staged[component.name]}
                    for component in batch
                ]
            )
        ).hexdigest()
        batch_evidence = {
            "connection_generation": generation,
            "batch_index": batch_index,
            "staged_snapshot_sha256": staged_snapshot_sha256,
        }
        _append(
            path,
            operation_id,
            "CATACOMB_HOST_BATCH_COMMIT_INTENT",
            batch_evidence,
        )
        try:
            store.cross_commit_boundary(staged)
        except Exception as error:
            _freeze(
                path,
                operation_id,
                final_reference,
                stage="host-commit",
                reason="host-store-error",
                host_commit_possible=True,
                cause=error,
            )
        try:
            _append(
                path,
                operation_id,
                "CATACOMB_HOST_BATCH_COMMITTED",
                batch_evidence,
            )
        except Exception as error:
            _freeze(
                path,
                operation_id,
                final_reference,
                stage="host-commit",
                reason="journal-error",
                host_commit_possible=True,
                cause=error,
            )
        _append(
            path, operation_id, "CATACOMB_FINAL_CONFIRM_INTENT", final_reference
        )
        try:
            confirm_status = transport.confirm(batch[-1].descriptor)
        except Exception as error:
            _freeze(
                path,
                operation_id,
                final_reference,
                stage="final-confirm",
                reason="transport-error",
                host_commit_possible=True,
                cause=error,
            )
        if type(confirm_status) is not int or confirm_status != 0:
            _freeze(
                path,
                operation_id,
                final_reference,
                stage="final-confirm",
                reason="transport-error",
                host_commit_possible=True,
            )
        try:
            _append(
                path,
                operation_id,
                "CATACOMB_FINAL_CONFIRMED",
                {
                    **final_reference,
                    "status": confirm_status,
                },
            )
        except Exception as error:
            _freeze(
                path,
                operation_id,
                final_reference,
                stage="final-confirm",
                reason="journal-error",
                host_commit_possible=True,
                cause=error,
            )

    try:
        attestation = readback()
    except Exception as error:
        _freeze(
            path,
            operation_id,
            final_reference,
            stage="readback",
            reason="readback-error",
            host_commit_possible=True,
            cause=error,
        )
    if (
        not isinstance(attestation, ReadbackAttestation)
        or attestation.sep_host_generation_equal is not True
        or attestation.independent_archive_readback is not True
    ):
        _freeze(
            path,
            operation_id,
            final_reference,
            stage="readback",
            reason="readback-error",
            host_commit_possible=True,
        )
    return _append(
        path,
        operation_id,
        "CATACOMB_PERSISTENCE_ATTESTED",
        {
            "connection_generation": generation,
            "batch_count": len(batches),
            "reconciliation_snapshot_sha256": (
                attestation.reconciliation_snapshot_sha256
            ),
            "sep_host_generation_equal": True,
            "independent_archive_readback": True,
        },
    )
