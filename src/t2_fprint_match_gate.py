# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed inventory gate around one named fprint match."""

from __future__ import annotations

import hashlib
import struct
import uuid
from dataclasses import dataclass, field

import t2_catacomb_codec
import t2_fprint_match_selection


class FprintMatchGateError(ValueError):
    pass


def _component_hashes(components: object) -> tuple[tuple[str, str], ...]:
    if type(components) is not dict or not components:
        raise FprintMatchGateError("local Catacomb component set is invalid")
    result: list[tuple[str, str]] = []
    for name, data in sorted(components.items()):
        if type(name) is not str or type(data) is not bytes or not data:
            raise FprintMatchGateError("local Catacomb component is invalid")
        result.append((name, hashlib.sha256(data).hexdigest()))
    return tuple(result)


def _per_user_records(value: object, apple_user_id: int) -> tuple[bytes, ...]:
    if type(value) is not tuple:
        raise FprintMatchGateError("per-user identity inventory is invalid")
    seen: set[bytes] = set()
    for record in value:
        if type(record) is not bytes or len(record) != 20:
            raise FprintMatchGateError("per-user identity record is malformed")
        if struct.unpack_from("<I", record)[0] != apple_user_id:
            raise FprintMatchGateError(
                "per-user identity record belongs to another Apple user"
            )
        identity_uuid = uuid.UUID(bytes=record[4:20])
        if identity_uuid.int == 0 or record in seen:
            raise FprintMatchGateError(
                "per-user identity inventory is empty-authority or duplicated"
            )
        seen.add(record)
    return value


def _global_records(
    value: object, apple_user_id: int
) -> tuple[tuple[bytes, ...], set[bytes]]:
    if type(value) is not tuple:
        raise FprintMatchGateError("global identity inventory is invalid")
    configured: set[bytes] = set()
    seen: set[bytes] = set()
    for record in value:
        if type(record) is not bytes or len(record) != 40:
            raise FprintMatchGateError("global identity record is malformed")
        identity = record[:20]
        user_id = struct.unpack_from("<I", identity)[0]
        identity_uuid = uuid.UUID(bytes=identity[4:20])
        if identity_uuid.int == 0 or identity in seen:
            raise FprintMatchGateError(
                "global identity inventory is empty-authority or duplicated"
            )
        seen.add(identity)
        if user_id == apple_user_id:
            group_type = struct.unpack_from("<I", record, 20)[0]
            group_uuid = uuid.UUID(bytes=record[24:40])
            if group_type not in (0, 1) or group_uuid.int != 0:
                raise FprintMatchGateError(
                    "configured global identity is not built-in"
                )
            configured.add(identity)
    return value, configured


@dataclass(frozen=True, repr=False)
class TargetedMatchGate:
    finger_name: str
    identity_record: bytes = field(repr=False)
    per_user_records: tuple[bytes, ...] = field(repr=False)
    global_records: tuple[bytes, ...] = field(repr=False)
    component_hashes: tuple[tuple[str, str], ...] = field(repr=False)

    def public(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "finger_name": self.finger_name,
            "single_identity_selected": True,
            "same_connection_inventory_stable": True,
            "local_live_reconciled": True,
            "identifiers_redacted": True,
        }


def prepare(
    local: object,
    components: object,
    first_per_user: object,
    first_global: object,
    second_per_user: object,
    second_global: object,
    finger_name: object,
) -> TargetedMatchGate:
    """Select one identity only after exact repeated local/live agreement."""

    if not isinstance(local, t2_catacomb_codec.UserCatacomb):
        raise FprintMatchGateError("local Catacomb has the wrong type")
    apple_user_id = local.expected_user_id
    first_user = _per_user_records(first_per_user, apple_user_id)
    second_user = _per_user_records(second_per_user, apple_user_id)
    first_all, first_configured = _global_records(first_global, apple_user_id)
    second_all, second_configured = _global_records(second_global, apple_user_id)
    if first_user != second_user or first_all != second_all:
        raise FprintMatchGateError("live identity inventory is unstable")
    if first_configured != set(first_user) or second_configured != set(first_user):
        raise FprintMatchGateError(
            "global and per-user identity inventories disagree"
        )
    try:
        selected = t2_fprint_match_selection.select(
            local, first_user, finger_name
        )
    except t2_fprint_match_selection.FprintMatchSelectionError as error:
        raise FprintMatchGateError("named identity selection failed") from error
    return TargetedMatchGate(
        selected.finger_name,
        selected.identity_record,
        first_user,
        first_all,
        _component_hashes(components),
    )


def attest_unchanged(
    gate: object,
    components: object,
    per_user_records: object,
    global_records: object,
) -> dict[str, object]:
    """Prove the read-only named match did not change identity state."""

    if not isinstance(gate, TargetedMatchGate):
        raise FprintMatchGateError("targeted match gate has the wrong type")
    if (
        _component_hashes(components) != gate.component_hashes
        or per_user_records != gate.per_user_records
        or global_records != gate.global_records
    ):
        raise FprintMatchGateError("identity state changed during named match")
    return {
        "schema_version": 1,
        "identity_state_unchanged": True,
        "local_components_unchanged": True,
        "per_user_inventory_unchanged": True,
        "global_inventory_unchanged": True,
        "identifiers_redacted": True,
    }
