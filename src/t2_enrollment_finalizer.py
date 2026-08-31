# SPDX-License-Identifier: GPL-2.0-only
"""Concrete same-generation built-in enrollment persistence finalizer.

This module deliberately has no CLI.  A privileged broker must supply the
already-owned Bridge lease, protected local Catacomb directory, journal, and
immutable account mapping.  The finalizer never retries an ambiguous mutation.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path
from typing import Callable

import t2_bridge_inventory
import t2_biolockout_protocol
import t2_catacomb_bridge
import t2_catacomb_codec
import t2_catacomb_store
import t2_enrollment_coordinator
import t2_enrollment_journal
import t2_enrollment_operation
import t2_enrollment_persistence_bridge
import t2_enrollment_persistence_operation
import t2_enrollment_reconciliation


class EnrollmentFinalizerError(RuntimeError):
    """Raised when persistence or its independent read-back is not provable."""


Clock = Callable[[], dt.datetime]


def _apple_time(value: dt.datetime) -> float:
    if not isinstance(value, dt.datetime) or value.tzinfo is None:
        raise EnrollmentFinalizerError("finalizer clock is not timezone-aware")
    return (
        value.astimezone(dt.timezone.utc) - t2_catacomb_codec.APPLE_EPOCH
    ).total_seconds()


def _next_entity(entities: set[int]) -> int:
    for candidate in range(t2_catacomb_codec.MAX_IDENTITIES):
        if candidate not in entities:
            return candidate
    raise EnrollmentFinalizerError("no unused built-in identity entity remains")


def read_local_host_snapshot(
    store: t2_catacomb_store.CatacombStore,
    baseline: dict[str, object],
) -> dict[str, object]:
    """Read the Linux-local store through both strict codecs and pinned metadata."""
    components = store.read_committed_components()
    apple_user_id = baseline.get("apple_uid")
    if type(apple_user_id) is not int:
        raise EnrollmentFinalizerError("baseline Apple user ID is invalid")
    user_name = f"user_{apple_user_id:08x}.cat"
    user = t2_catacomb_codec.decode_user_catacomb(
        components[user_name], apple_user_id
    )
    master = t2_catacomb_codec.decode_master_catacomb(components["master.cat"])
    t2_catacomb_codec.decode_biolockout_catacomb(components["biolockout.cat"])

    source_metadata = baseline.get("host_components")
    if not isinstance(source_metadata, list):
        raise EnrollmentFinalizerError("baseline component metadata is absent")
    metadata: dict[str, dict[str, object]] = {}
    for record in source_metadata:
        if not isinstance(record, dict) or set(record) != {
            "name",
            "sha256",
            "mode",
            "uid",
            "gid",
        }:
            raise EnrollmentFinalizerError("baseline component metadata is malformed")
        name = record["name"]
        if not isinstance(name, str) or name in metadata:
            raise EnrollmentFinalizerError("baseline component metadata is duplicated")
        metadata[name] = record
    if set(metadata) != set(components):
        raise EnrollmentFinalizerError("local and baseline component sets differ")

    return {
        "account_uuid": user.account_uuid,
        "bag_uuid": user.keybag_uuid,
        "identity_records": [
            {
                "user_id": identity.user_id,
                "uuid": identity.uuid,
                "entity": identity.entity,
            }
            for identity in user.identities
        ],
        "host_components": [
            {
                "name": name,
                "sha256": hashlib.sha256(components[name]).hexdigest(),
                "mode": metadata[name]["mode"],
                "uid": metadata[name]["uid"],
                "gid": metadata[name]["gid"],
            }
            for name in sorted(components)
        ],
        "master_enrollment_count": master.enrollment_count,
    }


class BuiltinEnrollmentFinalizer:
    """Persist and reconcile one built-in identity on the enrollment generation."""

    def __init__(
        self,
        *,
        lease: t2_bridge_inventory.InventoryLease,
        apple_user_id: int,
        connection_generation: str,
        journal_path: Path,
        operation_id: str,
        catacomb_root: Path,
        mapping_generation: str,
        identity_name: str,
        clock: Clock = lambda: dt.datetime.now(dt.timezone.utc),
    ) -> None:
        if not isinstance(journal_path, Path) or not isinstance(catacomb_root, Path):
            raise EnrollmentFinalizerError("finalizer paths must be typed Paths")
        if (
            not isinstance(identity_name, str)
            or not identity_name
            or "\x00" in identity_name
            or len(identity_name.encode("utf-8"))
            > t2_catacomb_codec.MAX_STRING_BYTES
        ):
            raise EnrollmentFinalizerError("identity name is invalid")
        if not callable(clock):
            raise EnrollmentFinalizerError("finalizer clock is not callable")
        self.lease = lease
        self.apple_user_id = apple_user_id
        self.connection_generation = connection_generation
        self.journal_path = journal_path
        self.operation_id = operation_id
        self.store = t2_catacomb_store.CatacombStore(
            catacomb_root, apple_user_id
        )
        self.mapping_generation = mapping_generation
        self.identity_name = identity_name
        self.clock = clock

    def _stable_readback(
        self, baseline: dict[str, object]
    ) -> tuple[dict[str, object], dict[str, object]]:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            self.lease, self.apple_user_id
        )
        host = read_local_host_snapshot(self.store, baseline)
        return host, live

    def __call__(
        self, result: t2_enrollment_operation.EnrollmentOperationResult
    ) -> t2_enrollment_coordinator.FinalizationAttestation:
        if not isinstance(result, t2_enrollment_operation.EnrollmentOperationResult):
            raise EnrollmentFinalizerError("finalizer received no typed outcome")
        history = t2_enrollment_journal.read(self.journal_path)
        if history.operation_id != self.operation_id:
            raise EnrollmentFinalizerError("finalizer operation ID differs from journal")
        baseline = history.baseline
        if (
            baseline["apple_uid"] != self.apple_user_id
            or baseline["connection_generation"] != self.connection_generation
            or baseline["mapping_generation"] != self.mapping_generation
            or self.lease.connection_generation != self.connection_generation
        ):
            raise EnrollmentFinalizerError("finalizer binding changed")

        if result.outcome != "identity-observed":
            committed = self.store.read_committed_components()
            old_biolockout = t2_catacomb_codec.decode_biolockout_catacomb(
                committed["biolockout.cat"]
            )
            batches = (
                (
                    t2_enrollment_persistence_operation.ComponentSpec(
                        "biolockout.cat",
                        t2_biolockout_protocol.PERSISTENCE_DESCRIPTOR,
                    ),
                ),
            )

            def encode_failure_biolockout(
                name: str, secure_blob: bytearray
            ) -> bytearray:
                if name != "biolockout.cat":
                    raise EnrollmentFinalizerError(
                        "unexpected failure persistence component"
                    )
                return bytearray(
                    old_biolockout.encode(secure_data=bytes(secure_blob))
                )

            cached: dict[str, dict[str, object]] = {}

            def readback_failure() -> (
                t2_enrollment_persistence_operation.ReadbackAttestation
            ):
                host, live = self._stable_readback(baseline)
                current = t2_enrollment_journal.read(self.journal_path)
                plan = t2_enrollment_reconciliation.classify(
                    current,
                    host=host,
                    live=live,
                    mapping_generation=self.mapping_generation,
                )
                if (
                    plan.evidence is None
                    or plan.readback_identity_uuid is not None
                    or plan.evidence["identity_uuid"] is not None
                ):
                    raise EnrollmentFinalizerError(
                        "failure bio-lockout read-back is incomplete"
                    )
                cached["host"] = host
                cached["live"] = live
                return t2_enrollment_persistence_operation.ReadbackAttestation(
                    plan.evidence["snapshot_sha256"], True, True
                )

            transport = (
                t2_enrollment_persistence_bridge.EnrollmentPersistenceBridgeTransport(
                    self.lease,
                    protocol_version=2,
                    connection_generation=self.connection_generation,
                )
            )
            persisted = t2_enrollment_persistence_operation.run(
                self.journal_path,
                self.operation_id,
                batches=batches,
                transport=transport,
                encoder=encode_failure_biolockout,
                store=self.store,
                readback=readback_failure,
            )
            if persisted.phase is not t2_enrollment_journal.EnrollmentPhase.PERSISTENCE_READY:
                raise EnrollmentFinalizerError(
                    "failure bio-lockout sync did not reach its attested state"
                )
            if set(cached) != {"host", "live"}:
                raise EnrollmentFinalizerError(
                    "failure bio-lockout read-back snapshots are absent"
                )
            reconciled = t2_enrollment_reconciliation.append_reconciled(
                self.journal_path,
                self.operation_id,
                host=cached["host"],
                live=cached["live"],
                mapping_generation=self.mapping_generation,
            )
            if reconciled.phase is not t2_enrollment_journal.EnrollmentPhase.RECONCILED:
                raise EnrollmentFinalizerError("failed enrollment did not reconcile")
            return t2_enrollment_coordinator.FinalizationAttestation(
                self.connection_generation, False, True
            )

        if history.phase is not t2_enrollment_journal.EnrollmentPhase.TERMINAL_IDENTITY:
            raise EnrollmentFinalizerError("identity outcome has no provisional journal state")
        identity_uuid = history.terminal_identity_uuid
        if identity_uuid is None:
            raise EnrollmentFinalizerError("provisional identity UUID is absent")
        components = t2_catacomb_bridge.collect_builtin_save_components(
            self.lease,
            apple_user_id=self.apple_user_id,
            connection_generation=self.connection_generation,
        )
        batches = (
            (
                t2_enrollment_persistence_operation.ComponentSpec(
                    f"user_{self.apple_user_id:08x}.cat", components[0].descriptor
                ),
                t2_enrollment_persistence_operation.ComponentSpec(
                    "master.cat", components[1].descriptor
                ),
            ),
            (
                t2_enrollment_persistence_operation.ComponentSpec(
                    "biolockout.cat",
                    t2_biolockout_protocol.PERSISTENCE_DESCRIPTOR,
                ),
            ),
        )

        committed = self.store.read_committed_components()
        user_name = f"user_{self.apple_user_id:08x}.cat"
        old_user = t2_catacomb_codec.decode_user_catacomb(
            committed[user_name], self.apple_user_id
        )
        old_master = t2_catacomb_codec.decode_master_catacomb(
            committed["master.cat"]
        )
        old_biolockout = t2_catacomb_codec.decode_biolockout_catacomb(
            committed["biolockout.cat"]
        )
        timestamp = self.clock()
        apple_time = _apple_time(timestamp)
        if apple_time <= old_master.current_time:
            raise EnrollmentFinalizerError("finalizer clock did not advance master time")
        entity = _next_entity({identity.entity for identity in old_user.identities})
        user_with_identity = t2_catacomb_codec.decode_user_catacomb(
            old_user.add(
                identity_uuid=identity_uuid,
                entity=entity,
                name=self.identity_name,
                created=timestamp,
            ),
            self.apple_user_id,
        )

        def encode(name: str, secure_blob: bytearray) -> bytearray:
            if name == user_name:
                output = user_with_identity.replace_secure_data(bytes(secure_blob))
            elif name == "master.cat":
                output = old_master.encode(
                    secure_data=bytes(secure_blob),
                    enrollment_count=old_master.enrollment_count + 1,
                    current_time=apple_time,
                )
            elif name == "biolockout.cat":
                output = old_biolockout.encode(secure_data=bytes(secure_blob))
            else:
                raise EnrollmentFinalizerError("unexpected persistence component")
            return bytearray(output)

        cached: dict[str, dict[str, object]] = {}

        def readback() -> t2_enrollment_persistence_operation.ReadbackAttestation:
            host, live = self._stable_readback(baseline)
            current = t2_enrollment_journal.read(self.journal_path)
            plan = t2_enrollment_reconciliation.classify(
                current,
                host=host,
                live=live,
                mapping_generation=self.mapping_generation,
            )
            if (
                plan.evidence is None
                or plan.readback_identity_uuid is not None
                or plan.evidence["identity_uuid"] != identity_uuid
            ):
                raise EnrollmentFinalizerError("persistence read-back is incomplete")
            cached["host"] = host
            cached["live"] = live
            return t2_enrollment_persistence_operation.ReadbackAttestation(
                plan.evidence["snapshot_sha256"], True, True
            )

        transport = (
            t2_enrollment_persistence_bridge.EnrollmentPersistenceBridgeTransport(
                self.lease,
                protocol_version=2,
                connection_generation=self.connection_generation,
            )
        )
        persisted = t2_enrollment_persistence_operation.run(
            self.journal_path,
            self.operation_id,
            batches=batches,
            transport=transport,
            encoder=encode,
            store=self.store,
            readback=readback,
        )
        if persisted.phase is not t2_enrollment_journal.EnrollmentPhase.PERSISTENCE_READY:
            raise EnrollmentFinalizerError("persistence did not reach its attested state")
        if set(cached) != {"host", "live"}:
            raise EnrollmentFinalizerError("persistence read-back snapshots are absent")
        reconciled = t2_enrollment_reconciliation.append_reconciled(
            self.journal_path,
            self.operation_id,
            host=cached["host"],
            live=cached["live"],
            mapping_generation=self.mapping_generation,
        )
        if reconciled.phase is not t2_enrollment_journal.EnrollmentPhase.RECONCILED:
            raise EnrollmentFinalizerError("persisted identity did not reach E3")
        return t2_enrollment_coordinator.FinalizationAttestation(
            self.connection_generation, True, True
        )
