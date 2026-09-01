# SPDX-License-Identifier: GPL-2.0-only
"""Authorized same-generation single-deletion consumer for the fprint worker."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import t2_baseline
import t2_bridge_inventory
import t2_catacomb_store
import t2_fprint_deletion_runtime
import t2_fprint_projection
import t2_identity_delete
import t2_identity_delete_bridge
import t2_identity_delete_journal as delete_journal
import t2_identity_delete_operation
import t2_identity_delete_pipeline
import t2_mutation_journal
import t2_mutation_registry
import t2_user_broker
import t2_user_policy
import t2_user_reconciliation_live


MUTATION_ROOT = Path("/var/lib/t2-touchid/mutations")


class FprintDeletionConsumerError(RuntimeError):
    """Raised before or during an authorized fprint single deletion."""


@dataclass(frozen=True, repr=False)
class DeletionConsumer:
    finger_name: str
    password_fallback_verified: bool
    mutation_root: Path = field(default=MUTATION_ROOT, repr=False)
    mutation_blocked: Callable[[Path], bool] = field(
        default=t2_mutation_registry.blocks_new_mutation, repr=False
    )
    store_factory: Callable[[Path, int], object] = field(
        default=t2_catacomb_store.CatacombStore, repr=False
    )
    bridge_factory: Callable[..., object] = field(
        default=t2_identity_delete_bridge.IdentityDeleteBridge, repr=False
    )
    operation_runner: Callable[..., object] = field(
        default=t2_identity_delete_operation.run, repr=False
    )
    persistence_runner: Callable[..., object] = field(
        default=t2_identity_delete_pipeline.persist, repr=False
    )
    inventory_collector: Callable[..., object] = field(
        default=t2_bridge_inventory.collect_stable_private_inventory,
        repr=False,
    )

    def __post_init__(self) -> None:
        if self.finger_name not in t2_fprint_projection.FINGER_NAME_SET:
            raise FprintDeletionConsumerError(
                "deletion consumer requires a canonical finger name"
            )
        if self.password_fallback_verified is not True:
            raise FprintDeletionConsumerError(
                "password fallback must be independently verified"
            )
        if not isinstance(self.mutation_root, Path) or any(
            not callable(value)
            for value in (
                self.mutation_blocked,
                self.store_factory,
                self.bridge_factory,
                self.operation_runner,
                self.persistence_runner,
                self.inventory_collector,
            )
        ):
            raise FprintDeletionConsumerError(
                "deletion consumer dependency is unavailable"
            )

    def __repr__(self) -> str:
        return (
            "DeletionConsumer(finger_name="
            f"{self.finger_name!r}, private=True)"
        )

    @staticmethod
    def _validate_authority(
        authority: t2_user_broker.BrokerAuthority,
        live: object,
    ) -> None:
        if not isinstance(authority, t2_user_broker.BrokerAuthority):
            raise FprintDeletionConsumerError(
                "deletion consumer authority has the wrong type"
            )
        selected = authority.selected
        binding = authority.decision.binding
        if (
            authority.stage != "operate"
            or authority.decision.state != "authorized"
            or authority.decision.operation != "delete-one"
            or authority.decision.operation_permitted is not True
            or authority.decision.selected_mapping != selected
            or not selected.permits("identity-management")
            or not isinstance(binding, t2_user_policy.PolicyBinding)
            or binding.operation_id != authority.operation_id
            or binding.mapping_generation != authority.mapping_set.generation
            or binding.linux_account_generation
            != selected.linux_account_generation
            or binding.caller_linux_uid != selected.linux_uid
            or binding.target_linux_uid != selected.linux_uid
            or binding.capability != "identity-management"
            or binding.linux_boot_uuid != authority.linux_boot_uuid
            or binding.runtime_generation != authority.runtime_generation
            or not callable(authority.dispatch_allowed)
        ):
            raise FprintDeletionConsumerError(
                "deletion consumer authority is not exactly bound"
            )
        try:
            generation = live.runtime_generation
        except Exception as error:
            raise FprintDeletionConsumerError(
                "live deletion generation is unavailable"
            ) from error
        if generation != authority.runtime_generation:
            raise FprintDeletionConsumerError(
                "live deletion generation changed"
            )

    def __call__(
        self,
        authority: t2_user_broker.BrokerAuthority,
        live: object,
    ) -> t2_fprint_deletion_runtime.DeletionCompletion:
        self._validate_authority(authority, live)
        inventory = getattr(live, "public_identity_inventory", None)
        prepare = getattr(live, "prepare_deletion_material", None)
        if not callable(inventory) or not callable(prepare):
            raise FprintDeletionConsumerError(
                "live deletion material provider is unavailable"
            )
        try:
            if self.mutation_blocked(self.mutation_root):
                raise FprintDeletionConsumerError(
                    "an earlier biometric mutation requires reconciliation"
                )
            projection = t2_fprint_projection.project(
                inventory(authority.selected)
            )
        except FprintDeletionConsumerError:
            raise
        except Exception as error:
            raise FprintDeletionConsumerError(
                "same-generation fprint projection failed"
            ) from error
        if not projection.complete:
            raise FprintDeletionConsumerError(
                "existing fingerprint labels require migration"
            )
        if self.finger_name not in projection.finger_names:
            raise FprintDeletionConsumerError(
                "finger name is not currently enrolled"
            )
        if len(projection.finger_names) <= 1:
            raise FprintDeletionConsumerError(
                "refusing to delete the final fingerprint"
            )
        try:
            material = prepare(authority.selected, authority.operation_id)
        except Exception as error:
            raise FprintDeletionConsumerError(
                "same-generation deletion material preparation failed"
            ) from error
        if (
            not isinstance(
                material, t2_user_reconciliation_live.DeletionMaterial
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
            raise FprintDeletionConsumerError(
                "same-generation deletion material is inconsistent"
            )
        try:
            plan = t2_identity_delete.plan_named(
                material.local,
                material.live,
                finger_name=self.finger_name,
            )
            if (
                plan.name != self.finger_name
                or plan.apple_user_id != material.apple_uid
            ):
                raise FprintDeletionConsumerError(
                    "private deletion target changed"
                )
            baseline = t2_baseline.build_baseline(
                host=material.anchor.host_inventory,
                live=material.live,
                caller_linux_uid=authority.selected.linux_uid,
                target_linux_uid=authority.selected.linux_uid,
                linux_boot_uuid=authority.linux_boot_uuid,
                mapping_generation=authority.mapping_set.generation,
                backup_reference=material.anchor.reference,
                password_fallback_verified=self.password_fallback_verified,
            )
            if not authority.dispatch_allowed():
                raise FprintDeletionConsumerError(
                    "deletion authority expired before durable intent"
                )
            journal_path = (
                self.mutation_root / f"{authority.operation_id}.jsonl"
            )
            t2_mutation_journal.create(
                journal_path,
                "delete-one",
                baseline,
                operation_id=authority.operation_id,
            )
            delete_journal.append_checked(
                journal_path,
                authority.operation_id,
                "DELETE_INTENT",
                {
                    "connection_generation": material.connection_generation,
                    "user_id": material.apple_uid,
                    "identity_uuid": plan.identity_uuid,
                    "entity": plan.entity,
                    "target_name_sha256": hashlib.sha256(
                        plan.name.encode("utf-8")
                    ).hexdigest(),
                    "request_sha256": hashlib.sha256(plan.request).hexdigest(),
                    "request_length": len(plan.request),
                    "survivor_snapshot_sha256": plan.survivor_snapshot_sha256,
                    "survivor_count": len(material.local.identities) - 1,
                    "mapping_generation": authority.mapping_set.generation,
                },
            )
            store = self.store_factory(
                material.catacomb_root, material.apple_uid
            )
            bridge = self.bridge_factory(
                material.lease,
                connection_generation=material.connection_generation,
            )
            result = self.operation_runner(
                journal_path,
                authority.operation_id,
                plan=plan,
                local=material.local,
                bridge=bridge,
                collect_inventory=lambda: self.inventory_collector(
                    material.lease, material.apple_uid
                ),
            )
            if (
                not isinstance(
                    result,
                    t2_identity_delete_operation.IdentityDeleteOperationResult,
                )
                or result.outcome != "sep-deleted"
            ):
                raise FprintDeletionConsumerError(
                    "SEP did not perform the requested deletion"
                )
            final = self.persistence_runner(
                lease=material.lease,
                store=store,
                journal_path=journal_path,
                operation_id=authority.operation_id,
                plan=plan,
                apple_uid=material.apple_uid,
                mapping_generation=authority.mapping_set.generation,
            )
        except FprintDeletionConsumerError:
            raise
        except Exception as error:
            raise FprintDeletionConsumerError(
                "journaled deletion consumer stopped"
            ) from error
        if (
            not isinstance(final, delete_journal.IdentityDeleteHistory)
            or final.phase is not delete_journal.IdentityDeletePhase.RECONCILED
        ):
            raise FprintDeletionConsumerError(
                "identity deletion did not reach reconciled state"
            )
        return t2_fprint_deletion_runtime.DeletionCompletion(
            self.finger_name,
            True,
            True,
            True,
            True,
        )
