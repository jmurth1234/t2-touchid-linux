# SPDX-License-Identifier: GPL-2.0-only
"""Authorized same-generation enrollment consumer for the fprint worker."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import t2_acm_device
import t2_enrollment_coordinator
import t2_enrollment_finalizer
import t2_fprint_projection
import t2_user_broker
import t2_user_policy
import t2_user_reconciliation_live


MUTATION_ROOT = Path("/var/lib/t2-touchid/mutations")


class FprintEnrollmentConsumerError(RuntimeError):
    """Raised before or during an authorized fprint enrollment handoff."""


@dataclass(frozen=True, repr=False)
class EnrollmentConsumer:
    finger_name: str
    password_binder: Callable[[bytes], None] = field(repr=False)
    cancel_requested: Callable[[], bool] = field(repr=False)
    on_feedback: Callable[[object], None] = field(repr=False)
    password_fallback_verified: bool
    acm_device_factory: Callable[[], object] = field(
        default=t2_acm_device.ACMDevice, repr=False
    )
    finalizer_factory: Callable[..., object] = field(
        default=t2_enrollment_finalizer.BuiltinEnrollmentFinalizer,
        repr=False,
    )
    coordinator: Callable[..., object] = field(
        default=t2_enrollment_coordinator.run, repr=False
    )

    def __post_init__(self) -> None:
        if self.finger_name not in t2_fprint_projection.FINGER_NAME_SET:
            raise FprintEnrollmentConsumerError(
                "enrollment consumer requires a canonical finger name"
            )
        if (
            not callable(self.password_binder)
            or not callable(self.cancel_requested)
            or not callable(self.on_feedback)
            or not callable(self.acm_device_factory)
            or not callable(self.finalizer_factory)
            or not callable(self.coordinator)
        ):
            raise FprintEnrollmentConsumerError(
                "enrollment consumer dependency is unavailable"
            )
        if self.password_fallback_verified is not True:
            raise FprintEnrollmentConsumerError(
                "password fallback must be independently verified"
            )

    def __repr__(self) -> str:
        return (
            "EnrollmentConsumer(finger_name="
            f"{self.finger_name!r}, credential=<operation-scoped>, private=True)"
        )

    @staticmethod
    def _validate_authority(
        authority: t2_user_broker.BrokerAuthority,
        live: object,
    ) -> None:
        if not isinstance(authority, t2_user_broker.BrokerAuthority):
            raise FprintEnrollmentConsumerError(
                "enrollment consumer authority has the wrong type"
            )
        selected = authority.selected
        binding = authority.decision.binding
        if (
            authority.stage != "operate"
            or authority.decision.state != "authorized"
            or authority.decision.operation != "enroll"
            or authority.decision.operation_permitted is not True
            or authority.decision.selected_mapping != selected
            or not selected.permits("enroll")
            or not isinstance(binding, t2_user_policy.PolicyBinding)
            or binding.operation_id != authority.operation_id
            or binding.mapping_generation != authority.mapping_set.generation
            or binding.linux_account_generation
            != selected.linux_account_generation
            or binding.caller_linux_uid != selected.linux_uid
            or binding.target_linux_uid != selected.linux_uid
            or binding.capability != "enroll"
            or binding.linux_boot_uuid != authority.linux_boot_uuid
            or binding.runtime_generation != authority.runtime_generation
            or not callable(authority.dispatch_allowed)
        ):
            raise FprintEnrollmentConsumerError(
                "enrollment consumer authority is not exactly bound"
            )
        try:
            live_generation = live.runtime_generation
        except Exception as error:
            raise FprintEnrollmentConsumerError(
                "live enrollment generation is unavailable"
            ) from error
        if live_generation != authority.runtime_generation:
            raise FprintEnrollmentConsumerError(
                "live enrollment generation changed"
            )

    def __call__(
        self,
        authority: t2_user_broker.BrokerAuthority,
        live: object,
    ) -> t2_enrollment_coordinator.EnrollmentCoordinatorResult:
        self._validate_authority(authority, live)
        prepare = getattr(live, "prepare_enrollment_material", None)
        if not callable(prepare):
            raise FprintEnrollmentConsumerError(
                "live enrollment material provider is unavailable"
            )
        try:
            material = prepare(authority.selected, authority.operation_id)
        except Exception as error:
            raise FprintEnrollmentConsumerError(
                "same-generation enrollment material preparation failed"
            ) from error
        if (
            not isinstance(
                material, t2_user_reconciliation_live.EnrollmentMaterial
            )
            or material.apple_uid != authority.selected.apple_uid
            or material.connection_generation != authority.runtime_generation
            or material.lease.connection_generation
            != authority.runtime_generation
            or material.anchor.host_inventory.get("archive_sha256")
            != material.anchor.sha256
            or material.anchor.reference
            != f"recovery-anchors/{authority.operation_id}.tar"
            or material.anchor.path
            != (
                t2_user_reconciliation_live.RECOVERY_ANCHOR_ROOT
                / f"{authority.operation_id}.tar"
            )
            or material.catacomb_root
            != t2_user_reconciliation_live.STORE_ROOT
        ):
            raise FprintEnrollmentConsumerError(
                "same-generation enrollment material is inconsistent"
            )
        journal_path = MUTATION_ROOT / f"{authority.operation_id}.jsonl"
        try:
            acm_manager = self.acm_device_factory()
            if not hasattr(acm_manager, "__enter__") or not hasattr(
                acm_manager, "__exit__"
            ):
                raise FprintEnrollmentConsumerError(
                    "ACM device manager has the wrong type"
                )
            with acm_manager as acm_device:
                finalizer = self.finalizer_factory(
                    lease=material.lease,
                    apple_user_id=material.apple_uid,
                    connection_generation=material.connection_generation,
                    journal_path=journal_path,
                    operation_id=authority.operation_id,
                    catacomb_root=material.catacomb_root,
                    mapping_generation=authority.mapping_set.generation,
                    identity_name=self.finger_name,
                )
                result = self.coordinator(
                    lease=material.lease,
                    acm_device=acm_device,
                    apple_user_id=material.apple_uid,
                    host_inventory=material.anchor.host_inventory,
                    journal_path=journal_path,
                    operation_id=authority.operation_id,
                    caller_linux_uid=authority.selected.linux_uid,
                    target_linux_uid=authority.selected.linux_uid,
                    linux_boot_uuid=authority.linux_boot_uuid,
                    mapping_generation=authority.mapping_set.generation,
                    backup_reference=material.anchor.reference,
                    password_fallback_verified=(
                        self.password_fallback_verified
                    ),
                    password_binder=self.password_binder,
                    finalizer=finalizer,
                    dispatch_allowed=authority.dispatch_allowed,
                    cancel_requested=self.cancel_requested,
                    on_feedback=self.on_feedback,
                )
        except FprintEnrollmentConsumerError:
            raise
        except Exception as error:
            raise FprintEnrollmentConsumerError(
                "journaled enrollment consumer stopped"
            ) from error
        if not isinstance(
            result, t2_enrollment_coordinator.EnrollmentCoordinatorResult
        ):
            raise FprintEnrollmentConsumerError(
                "enrollment coordinator returned no typed result"
            )
        try:
            if live.runtime_generation != authority.runtime_generation:
                raise FprintEnrollmentConsumerError(
                    "live enrollment generation changed after reconciliation"
                )
        except FprintEnrollmentConsumerError:
            raise
        except Exception as error:
            raise FprintEnrollmentConsumerError(
                "live enrollment generation is unavailable after reconciliation"
            ) from error
        return result
