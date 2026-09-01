# SPDX-License-Identifier: GPL-2.0-only
"""Shared reconciled persistence tail for one SEP-observed identity deletion."""

from __future__ import annotations

from pathlib import Path

import t2_bridge_inventory
import t2_catacomb_bridge
import t2_catacomb_codec
import t2_catacomb_store
import t2_enrollment_finalizer
import t2_identity_delete
import t2_identity_delete_journal as delete_journal
import t2_identity_delete_persistence
import t2_identity_delete_reconciliation


class IdentityDeletePipelineError(RuntimeError):
    pass


def persist(
    *,
    lease: object,
    store: t2_catacomb_store.CatacombStore,
    journal_path: Path,
    operation_id: str,
    plan: t2_identity_delete.IdentityDeletePlan,
    apple_uid: int,
    mapping_generation: str,
) -> delete_journal.IdentityDeleteHistory:
    """Persist and independently reconcile one already-observed SEP deletion."""

    if (
        not isinstance(store, t2_catacomb_store.CatacombStore)
        or not isinstance(journal_path, Path)
        or not isinstance(plan, t2_identity_delete.IdentityDeletePlan)
        or type(apple_uid) is not int
        or apple_uid != plan.apple_user_id
        or getattr(lease, "connection_generation", None) is None
    ):
        raise IdentityDeletePipelineError("delete persistence input is invalid")
    transport = t2_catacomb_bridge.CatacombBridgeTransport(
        lease,
        protocol_version=2,
        connection_generation=lease.connection_generation,
    )

    def readback() -> t2_identity_delete_persistence.DeleteReadbackAttestation:
        observed_live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, apple_uid
        )
        history = delete_journal.read(journal_path)
        observed_host = t2_enrollment_finalizer.read_local_host_snapshot(
            store, history.baseline
        )
        components = store.read_committed_components()
        observed_local = t2_catacomb_codec.decode_user_catacomb(
            components[f"user_{apple_uid:08x}.cat"], apple_uid
        )
        attestation = t2_identity_delete_reconciliation.classify(
            history,
            plan,
            local=observed_local,
            host=observed_host,
            live=observed_live,
            mapping_generation=mapping_generation,
        )
        return t2_identity_delete_persistence.DeleteReadbackAttestation(
            attestation.connection_generation,
            attestation.snapshot_sha256,
            attestation.identity_count,
        )

    try:
        return t2_identity_delete_persistence.run(
            journal_path,
            operation_id,
            plan=plan,
            transport=transport,
            store=store,
            mapping_generation=mapping_generation,
            readback=readback,
        )
    except IdentityDeletePipelineError:
        raise
    except Exception as error:
        raise IdentityDeletePipelineError(
            "delete persistence or reconciliation stopped"
        ) from error
