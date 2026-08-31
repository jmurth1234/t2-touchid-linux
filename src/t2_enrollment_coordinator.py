# SPDX-License-Identifier: GPL-2.0-only
"""No-CLI composition of E0, ACM authorization, E1/E2, and finalization."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import t2_acm_device
import t2_baseline
import t2_bridge_inventory
import t2_enrollment_bridge
import t2_enrollment_operation
import t2_enrollment_protocol
import t2_mutation_journal


class EnrollmentCoordinatorError(RuntimeError):
    """Raised when a composed enrollment cannot prove its final state."""


def _safe_stop_detail(error: BaseException) -> str | None:
    """Expose only controlled adapter diagnostics, never arbitrary text."""
    current: BaseException | None = error
    seen: set[int] = set()
    detail: str | None = None
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, t2_enrollment_bridge.EnrollmentBridgeError):
            detail = str(current)
        elif isinstance(current, t2_enrollment_protocol.EnrollmentProtocolError):
            detail = str(current)
        elif isinstance(
            current, t2_enrollment_operation.EnrollmentPreDispatchCancelled
        ):
            detail = "enrollment cancelled before start dispatch"
        cause = current.__cause__
        current = cause if isinstance(cause, BaseException) else None
    return detail


def _stopped(error: BaseException) -> EnrollmentCoordinatorError:
    detail = _safe_stop_detail(error)
    suffix = f": {detail}" if detail else ""
    return EnrollmentCoordinatorError(f"same-connection enrollment stopped{suffix}")


@dataclass(frozen=True)
class FinalizationAttestation:
    connection_generation: str
    persistence_ready: bool
    reconciliation_complete: bool


@dataclass(frozen=True, repr=False)
class EnrollmentCoordinatorResult:
    outcome: str
    policy_satisfied: bool
    persistence_ready: bool
    reconciliation_complete: bool

    def __repr__(self) -> str:
        return (
            "EnrollmentCoordinatorResult(outcome="
            f"{self.outcome!r}, policy_satisfied={self.policy_satisfied}, "
            f"persistence_ready={self.persistence_ready}, "
            f"reconciliation_complete={self.reconciliation_complete})"
        )


Finalizer = Callable[
    [t2_enrollment_operation.EnrollmentOperationResult], FinalizationAttestation
]


def run(
    *,
    lease: t2_bridge_inventory.InventoryLease,
    acm_device: t2_acm_device.ACMDevice,
    apple_user_id: int,
    host_inventory: dict[str, object],
    journal_path: Path,
    operation_id: str,
    caller_linux_uid: int,
    target_linux_uid: int,
    linux_boot_uuid: str,
    mapping_generation: str,
    backup_reference: str,
    password_fallback_verified: bool,
    password_binder: Callable[[bytes], None],
    finalizer: Finalizer,
    dispatch_allowed: Callable[[], bool],
    cancel_requested: Callable[[], bool] = lambda: False,
    on_feedback: Callable[[object], None] = lambda _transition: None,
) -> EnrollmentCoordinatorResult:
    """Run one operation while retaining the E0 Bridge lease and ACM context."""
    if not callable(password_binder) or not callable(finalizer):
        raise EnrollmentCoordinatorError("password binder and finalizer are required")
    try:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, apple_user_id
        )
        baseline = t2_baseline.build_baseline(
            host=host_inventory,
            live=live,
            caller_linux_uid=caller_linux_uid,
            target_linux_uid=target_linux_uid,
            linux_boot_uuid=linux_boot_uuid,
            mapping_generation=mapping_generation,
            backup_reference=backup_reference,
            password_fallback_verified=password_fallback_verified,
        )
        t2_mutation_journal.create(
            journal_path, "enroll", baseline, operation_id=operation_id
        )
        generation = live["connection_generation"]
        transport = t2_enrollment_bridge.EnrollmentBridgeTransport(
            lease,
            protocol_version=baseline["protocol_version"],
            connection_generation=generation,
        )
        enrollment = t2_enrollment_operation.EnrollmentOperation(
            journal_path=journal_path,
            operation_id=operation_id,
            transport=transport,
            linux_boot_uuid=linux_boot_uuid,
            mapping_generation=mapping_generation,
            caller_linux_uid=caller_linux_uid,
            target_linux_uid=target_linux_uid,
        )

        def consume(external_form: bytes) -> tuple[
            t2_enrollment_operation.EnrollmentOperationResult,
            FinalizationAttestation,
        ]:
            result = enrollment.run(
                external_form,
                dispatch_allowed=dispatch_allowed,
                cancel_requested=cancel_requested,
                on_feedback=on_feedback,
            )
            try:
                attestation = finalizer(result)
                if inspect.isawaitable(attestation):
                    close = getattr(attestation, "close", None)
                    if callable(close):
                        close()
                    raise EnrollmentCoordinatorError("finalizer must be synchronous")
                if not isinstance(attestation, FinalizationAttestation):
                    raise EnrollmentCoordinatorError(
                        "finalizer returned no typed attestation"
                    )
                if attestation.connection_generation != generation:
                    raise EnrollmentCoordinatorError(
                        "finalizer used another Bridge generation"
                    )
                if lease.connection_generation != generation:
                    raise EnrollmentCoordinatorError(
                        "Bridge generation changed during finalization"
                    )
                if not attestation.reconciliation_complete:
                    raise EnrollmentCoordinatorError("final reconciliation is incomplete")
                identity_observed = result.outcome == "identity-observed"
                if attestation.persistence_ready is not identity_observed:
                    raise EnrollmentCoordinatorError(
                        "persistence attestation disagrees with enrollment outcome"
                    )
            except BaseException:
                try:
                    lease.invalidate()
                except BaseException:
                    pass
                raise
            return result, attestation

        _initial, final_policy, consumed = t2_acm_device.with_authorized_context(
            acm_device,
            apple_user_id,
            password_binder,
            consume,
        )
        enrollment_result, attestation = consumed
        return EnrollmentCoordinatorResult(
            outcome=enrollment_result.outcome,
            policy_satisfied=final_policy.satisfied,
            persistence_ready=attestation.persistence_ready,
            reconciliation_complete=attestation.reconciliation_complete,
        )
    except EnrollmentCoordinatorError:
        raise
    except t2_acm_device.ACMDeviceError as error:
        if isinstance(error.__cause__, EnrollmentCoordinatorError):
            raise error.__cause__ from error
        raise _stopped(error) from error
    except (
        t2_baseline.BaselineError,
        t2_bridge_inventory.BridgeInventoryError,
        t2_enrollment_bridge.EnrollmentBridgeError,
        t2_enrollment_operation.EnrollmentOperationError,
        t2_mutation_journal.JournalError,
    ) as error:
        raise _stopped(error) from error
